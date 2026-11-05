"""Pure-Python Multi-Threaded Socket Port Scanner & Banner Grabber.

Provides fast, native TCP port scanning and protocol banner grabbing without
external tool dependencies (inspired by Mastering Python Networking & Security):
1. Scope authorization check before sending any SYN probe.
2. ThreadPoolExecutor concurrent socket connect scanning.
3. Protocol-specific banner extraction (SSH, HTTP/HTTPS, FTP, SMTP, MySQL).
4. Direct integration into DiscoveredHostObservation and AssetInventoryService.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.asset_inventory import (
    AssetInventoryService,
    DiscoveredHostObservation,
    DiscoveredPortObservation,
)
from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import AssetNode, Project, TargetScope

logger = logging.getLogger(__name__)


# Standard top ports for rapid penetration-testing enumeration
TOP_PENTEST_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPC
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    5985,  # WinRM
    6379,  # Redis
    8000,  # HTTP Alt
    8080,  # HTTP Proxy / Web
    8443,  # HTTPS Alt
    8888,  # HTTP Alt
    9000,  # SonarQube / FastCGI
    27017, # MongoDB
]

SERVICE_PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5985: "wsman",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    27017: "mongodb",
}


class SocketPortScanner:
    """Pure-Python multi-threaded TCP connect scanner with active banner grabber."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def scan_host(
        self,
        target_ip: str,
        ports: Optional[List[int]] = None,
        project: Optional[Project] = None,
        scopes: Optional[List[TargetScope]] = None,
        timeout: float = 0.8,
        max_workers: int = 25,
        on_progress: Optional[Callable[[int, int, int], None]] = None,
    ) -> DiscoveredHostObservation:
        """Executes authorized TCP connect scan on target IP and captures service banners."""
        clean_ip = target_ip.strip()
        target_ports = ports if ports is not None else TOP_PENTEST_PORTS

        # 1. Scope Boundary Enforcement
        if scopes:
            scope_check = ScopeAuthorizationService.is_target_authorized(clean_ip, scopes, project)
            if not scope_check.is_allowed:
                raise PermissionError(f"Target {clean_ip} rejected by Scope Guard: {scope_check.reason}")

        open_ports: List[DiscoveredPortObservation] = []
        total = len(target_ports)
        scanned = 0

        # Resolve hostname if available
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(clean_ip)[0]
        except Exception:
            hostname = ""

        # Worker for individual port probe
        def _probe_port(port: int) -> Optional[DiscoveredPortObservation]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                result = s.connect_ex((clean_ip, port))
                if result == 0:
                    banner = self._grab_banner(clean_ip, port, s, timeout)
                    service_name = SERVICE_PORT_NAMES.get(port, "unknown")
                    product = ""
                    version = ""

                    # Parse product/version from common banners
                    if banner:
                        if port in (80, 8080, 8000, 8443, 8888, 9000):
                            m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
                            if m:
                                product = m.group(1).strip()
                        elif port == 22:
                            m = re.search(r"SSH-[\d\.]+-([^\r\n]+)", banner)
                            if m:
                                product = "OpenSSH"
                                version = m.group(1).strip()
                        elif port == 21:
                            m = re.search(r"220[- ]([^\r\n]+)", banner)
                            if m:
                                product = m.group(1).strip()
                        elif port == 3306:
                            product = "MySQL"
                            # MySQL handshake often starts with protocol version byte + version string
                            clean_str = "".join(c for c in banner if 32 <= ord(c) < 127)
                            m = re.search(r"(\d+\.\d+\.\d+[\w\.-]*)", clean_str)
                            if m:
                                version = m.group(1)

                    return DiscoveredPortObservation(
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        product=product,
                        version=version,
                        state="open",
                    )
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            return None

        # Execute concurrent scans
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(_probe_port, p): p for p in target_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                scanned += 1
                res = future.result()
                if res:
                    open_ports.append(res)
                if on_progress:
                    on_progress(scanned, total, len(open_ports))

        # Sort ports ascending
        open_ports.sort(key=lambda x: x.port)

        host_obs = DiscoveredHostObservation(
            ip=clean_ip,
            hostname=hostname,
            status="up" if open_ports else "up",
            confidence=1.0 if open_ports else 0.8,
            discovery_source="socket_scanner",
            ports=open_ports,
            metadata={"scanned_ports_count": len(target_ports), "open_ports_count": len(open_ports)},
        )
        return host_obs

    def _grab_banner(self, ip: str, port: int, sock: socket.socket, timeout: float) -> str:
        """Captures service identification banner using protocol-aware probes."""
        banner = ""
        try:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000, 8888, 9000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="ignore")
            elif port in (443, 8443):
                # TLS wrap
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    raw = ssock.recv(1024)
                    banner = raw.decode("utf-8", errors="ignore")
            elif port == 25:
                # Read greeting and send HELO
                raw = sock.recv(512)
                banner = raw.decode("utf-8", errors="ignore")
                sock.sendall(b"HELO pentest.local\r\n")
                raw2 = sock.recv(512)
                banner += "\n" + raw2.decode("utf-8", errors="ignore")
            else:
                raw = sock.recv(512)
                banner = raw.decode("utf-8", errors="ignore")
        except Exception:
            pass
        return banner.strip()

    def scan_and_sync(
        self,
        project_id: int,
        target_ip: str,
        ports: Optional[List[int]] = None,
        scopes: Optional[List[TargetScope]] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[DiscoveredHostObservation, List[AssetNode]]:
        """Scans target and synchronizes discovered hosts and open ports to AssetInventoryService."""
        if not self.db:
            raise ValueError("Database instance required for scan_and_sync.")

        project = self.db.get_project(project_id)
        scope_list = scopes if scopes is not None else self.db.list_scopes(project_id)

        host_obs = self.scan_host(
            target_ip=target_ip,
            ports=ports,
            project=project,
            scopes=scope_list,
        )

        inventory = AssetInventoryService(self.db)
        synced_nodes, _ = inventory.sync_host_observations(
            project_id=project_id,
            observations=[host_obs],
            scopes=scope_list,
            session_id=session_id,
            source_tool="socket_scanner",
        )
        return host_obs, synced_nodes

