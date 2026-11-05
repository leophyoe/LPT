"""Internal Network Footprinting and Initial Discovery module for CyberSecuritySuite.

Collects and parses local network interfaces, routing tables, default gateways,
and passive ARP/neighbour caches. Accurately distinguishes passive observations
from active live discovery, correlates discovered subnets against authorized
project scopes fail-closed, and generates cryptographic SHA-256 evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import (
    Evidence,
    Project,
    TargetScope,
    ValidationStatus,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NetworkInterfaceInfo:
    """Represents a discovered local network interface."""

    name: str
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = None
    is_up: bool = True
    is_loopback: bool = False
    mtu: Optional[int] = None
    flags: List[str] = field(default_factory=list)
    scope_status: str = "UNKNOWN"  # "IN_SCOPE", "OUT_OF_SCOPE", "NOT_CONFIGURED"


@dataclass
class RouteInfo:
    """Represents an entry in the system routing table."""

    destination: str
    gateway: Optional[str] = None
    interface: str = ""
    metric: Optional[int] = None
    protocol: str = ""
    is_default_gateway: bool = False
    scope_status: str = "UNKNOWN"


@dataclass
class NeighborEntry:
    """Represents an ARP / Neighbour cache observation.

    CRITICAL METHODOLOGY NOTE:
    ARP/neighbour cache entries represent passive historical observations, NEVER
    proof of currently active hosts or completed subnet sweeps. They are assigned
    confidence=0.7 and validation_status=ValidationStatus.OBSERVED.
    """

    ip_address: str
    mac_address: str = "Unknown"
    interface: str = ""
    state: str = "STALE"  # REACHABLE, STALE, DELAY, PERMANENT, FAILED
    collection_method: str = "passive_arp_cache"
    confidence: float = 0.7  # Passive historical cache = 0.7 vs active probe = 1.0
    validation_status: ValidationStatus = ValidationStatus.OBSERVED
    observed_at: str = field(default_factory=_utc_now_iso)
    scope_status: str = "UNKNOWN"
    hostname: Optional[str] = None


@dataclass
class InternalFootprintResult:
    """Complete structured footprinting telemetry and scope analysis."""

    timestamp: str = field(default_factory=_utc_now_iso)
    hostname: str = ""
    interfaces: List[NetworkInterfaceInfo] = field(default_factory=list)
    routes: List[RouteInfo] = field(default_factory=list)
    neighbors: List[NeighborEntry] = field(default_factory=list)
    default_gateway: Optional[str] = None
    discovered_subnets: List[str] = field(default_factory=list)
    in_scope_subnets: List[str] = field(default_factory=list)
    out_of_scope_subnets: List[str] = field(default_factory=list)
    raw_data: Dict[str, str] = field(default_factory=dict)
    evidence_hash: str = ""
    project_id: Optional[int] = None


class InternalFootprintCollector:
    """Collects and analyzes local network configuration and passive neighbor data."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def collect_footprint(
        self,
        project: Optional[Project] = None,
        scopes: Optional[List[TargetScope]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> InternalFootprintResult:
        """Executes passive local network collection and evaluates target scope boundaries."""
        raw_data: Dict[str, str] = {}
        hostname = socket.gethostname()

        # 1. Collect Interfaces: try 'ip -j addr', then fallback 'ip addr'
        ip_addr_json = self._run_command(["ip", "-j", "addr"])
        if ip_addr_json:
            raw_data["ip_addr_json"] = ip_addr_json
            interfaces = self.parse_interfaces(raw_json=ip_addr_json)
        else:
            ip_addr_text = self._run_command(["ip", "addr"])
            raw_data["ip_addr_text"] = ip_addr_text or ""
            interfaces = self.parse_interfaces(raw_text=ip_addr_text)

        # Fallback if no interfaces detected (e.g. non-Linux / restricted)
        if not interfaces:
            interfaces = self._fallback_interfaces()

        # 2. Collect Routes: try 'ip -j route', then 'ip route'
        ip_route_json = self._run_command(["ip", "-j", "route"])
        if ip_route_json:
            raw_data["ip_route_json"] = ip_route_json
            routes = self.parse_routes(raw_json=ip_route_json)
        else:
            ip_route_text = self._run_command(["ip", "route"])
            raw_data["ip_route_text"] = ip_route_text or ""
            routes = self.parse_routes(raw_text=ip_route_text)

        # 3. Collect Neighbors (ARP): try 'ip -j neigh', then 'ip neigh', then '/proc/net/arp'
        ip_neigh_json = self._run_command(["ip", "-j", "neigh"])
        if ip_neigh_json:
            raw_data["ip_neigh_json"] = ip_neigh_json
            neighbors = self.parse_neighbors(raw_json=ip_neigh_json)
        else:
            ip_neigh_text = self._run_command(["ip", "neigh"])
            if ip_neigh_text:
                raw_data["ip_neigh_text"] = ip_neigh_text
                neighbors = self.parse_neighbors(raw_text=ip_neigh_text)
            else:
                proc_arp = self._read_proc_arp()
                raw_data["proc_arp"] = proc_arp
                neighbors = self.parse_neighbors(proc_arp_text=proc_arp)

        # Identify default gateway
        default_gw: Optional[str] = None
        for r in routes:
            if r.is_default_gateway and r.gateway:
                default_gw = r.gateway
                break

        # Calculate discovered subnets
        discovered_subnets = self._extract_subnets(interfaces, routes)

        # Compute SHA-256 evidence hash of all raw telemetry
        payload_to_hash = json.dumps(raw_data, sort_keys=True).encode("utf-8")
        evidence_hash = hashlib.sha256(payload_to_hash).hexdigest()

        result = InternalFootprintResult(
            timestamp=_utc_now_iso(),
            hostname=hostname,
            interfaces=interfaces,
            routes=routes,
            neighbors=neighbors,
            default_gateway=default_gw,
            discovered_subnets=discovered_subnets,
            raw_data=raw_data,
            evidence_hash=evidence_hash,
            project_id=project.id if project else None,
        )

        # Correlate with authorized scopes if available
        if scopes:
            self.correlate_scopes(result, scopes=scopes, project=project)

        # Persist evidence record if database and project available
        if self.db and project and project.id:
            self._persist_evidence(result, project.id, evidence_dir)

        return result

    def parse_interfaces(
        self,
        raw_json: Optional[str] = None,
        raw_text: Optional[str] = None,
    ) -> List[NetworkInterfaceInfo]:
        """Parses interface data from JSON or standard text output."""
        interfaces: List[NetworkInterfaceInfo] = []

        if raw_json:
            try:
                data = json.loads(raw_json)
                if isinstance(data, list):
                    for item in data:
                        ifname = item.get("ifname", "")
                        flags = item.get("flags", [])
                        is_loopback = "LOOPBACK" in flags or ifname == "lo"
                        is_up = "UP" in flags or item.get("operstate") == "UP"
                        mac = item.get("address")
                        mtu = item.get("mtu")

                        ipv4s: List[str] = []
                        ipv6s: List[str] = []
                        for addr in item.get("addr_info", []):
                            family = addr.get("family")
                            local = addr.get("local")
                            prefixlen = addr.get("prefixlen")
                            if local and prefixlen is not None:
                                cidr = f"{local}/{prefixlen}"
                                if family == "inet":
                                    ipv4s.append(cidr)
                                elif family == "inet6":
                                    ipv6s.append(cidr)

                        interfaces.append(
                            NetworkInterfaceInfo(
                                name=ifname,
                                ipv4_addresses=ipv4s,
                                ipv6_addresses=ipv6s,
                                mac_address=mac if mac and mac != "00:00:00:00:00:00" else None,
                                is_up=is_up,
                                is_loopback=is_loopback,
                                mtu=mtu,
                                flags=flags,
                            )
                        )
                    return interfaces
            except Exception:
                pass

        if raw_text:
            current_iface: Optional[NetworkInterfaceInfo] = None
            for line in raw_text.splitlines():
                # Line like: "1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ..."
                iface_match = re.match(r"^\d+:\s+([a-zA-Z0-9_\-\.]+):?\s+<([^>]+)>\s+mtu\s+(\d+)", line)
                if iface_match:
                    name = iface_match.group(1)
                    flags = iface_match.group(2).split(",")
                    mtu = int(iface_match.group(3))
                    current_iface = NetworkInterfaceInfo(
                        name=name,
                        flags=flags,
                        mtu=mtu,
                        is_up="UP" in flags,
                        is_loopback="LOOPBACK" in flags or name == "lo",
                    )
                    interfaces.append(current_iface)
                    continue

                if current_iface:
                    # MAC link: "link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"
                    link_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
                    if link_match:
                        current_iface.mac_address = link_match.group(1)

                    # IPv4: "inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0"
                    inet_match = re.search(r"inet\s+([0-9\.]+/\d+)", line)
                    if inet_match:
                        current_iface.ipv4_addresses.append(inet_match.group(1))

                    # IPv6: "inet6 fe80::1/64 scope link"
                    inet6_match = re.search(r"inet6\s+([0-9a-fA-F:]+/\d+)", line)
                    if inet6_match:
                        current_iface.ipv6_addresses.append(inet6_match.group(1))

        return interfaces

    def parse_routes(
        self,
        raw_json: Optional[str] = None,
        raw_text: Optional[str] = None,
    ) -> List[RouteInfo]:
        """Parses routing table data from JSON or standard text output."""
        routes: List[RouteInfo] = []

        if raw_json:
            try:
                data = json.loads(raw_json)
                if isinstance(data, list):
                    for item in data:
                        dst = item.get("dst", "default")
                        gw = item.get("gateway")
                        dev = item.get("dev", "")
                        metric = item.get("metric")
                        proto = item.get("protocol", "")
                        is_def = dst in ("default", "0.0.0.0/0", "::/0") or gw is not None and dst == "default"

                        routes.append(
                            RouteInfo(
                                destination=dst,
                                gateway=gw,
                                interface=dev,
                                metric=metric,
                                protocol=proto,
                                is_default_gateway=is_def,
                            )
                        )
                    return routes
            except Exception:
                pass

        if raw_text:
            for line in raw_text.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue

                is_default = parts[0] == "default"
                dst = parts[0]
                gw: Optional[str] = None
                dev = ""
                proto = ""
                metric: Optional[int] = None

                i = 1
                while i < len(parts):
                    if parts[i] == "via" and i + 1 < len(parts):
                        gw = parts[i + 1]
                        i += 2
                    elif parts[i] == "dev" and i + 1 < len(parts):
                        dev = parts[i + 1]
                        i += 2
                    elif parts[i] == "proto" and i + 1 < len(parts):
                        proto = parts[i + 1]
                        i += 2
                    elif parts[i] == "metric" and i + 1 < len(parts):
                        try:
                            metric = int(parts[i + 1])
                        except ValueError:
                            pass
                        i += 2
                    else:
                        i += 1

                routes.append(
                    RouteInfo(
                        destination=dst,
                        gateway=gw,
                        interface=dev,
                        metric=metric,
                        protocol=proto,
                        is_default_gateway=is_default,
                    )
                )

        return routes

    def parse_neighbors(
        self,
        raw_json: Optional[str] = None,
        raw_text: Optional[str] = None,
        proc_arp_text: Optional[str] = None,
    ) -> List[NeighborEntry]:
        """Parses ARP/neighbor cache observations with passive confidence assignment (0.7)."""
        neighbors: List[NeighborEntry] = []

        if raw_json:
            try:
                data = json.loads(raw_json)
                if isinstance(data, list):
                    for item in data:
                        dst = item.get("dst", "")
                        lladdr = item.get("lladdr", "Unknown")
                        dev = item.get("dev", "")
                        state_raw = item.get("state", ["STALE"])
                        state = state_raw[0] if isinstance(state_raw, list) and state_raw else str(state_raw)

                        if dst:
                            neighbors.append(
                                NeighborEntry(
                                    ip_address=dst,
                                    mac_address=lladdr or "Unknown",
                                    interface=dev,
                                    state=state.upper(),
                                    collection_method="passive_arp_cache",
                                    confidence=0.7,
                                    validation_status=ValidationStatus.OBSERVED,
                                )
                            )
                    return neighbors
            except Exception:
                pass

        if raw_text:
            for line in raw_text.splitlines():
                # Format: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip = parts[0]
                    dev = ""
                    mac = "Unknown"
                    state = parts[-1]

                    i = 1
                    while i < len(parts) - 1:
                        if parts[i] == "dev":
                            dev = parts[i + 1]
                            i += 2
                        elif parts[i] == "lladdr":
                            mac = parts[i + 1]
                            i += 2
                        else:
                            i += 1

                    neighbors.append(
                        NeighborEntry(
                            ip_address=ip,
                            mac_address=mac,
                            interface=dev,
                            state=state.upper(),
                            collection_method="passive_arp_cache",
                            confidence=0.7,
                            validation_status=ValidationStatus.OBSERVED,
                        )
                    )
            if neighbors:
                return neighbors

        if proc_arp_text:
            lines = proc_arp_text.strip().splitlines()
            if len(lines) > 1:
                # First line is header: IP address HW type Flags HW address Mask Device
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        dev = parts[5]
                        neighbors.append(
                            NeighborEntry(
                                ip_address=ip,
                                mac_address=mac if mac != "00:00:00:00:00:00" else "Unknown",
                                interface=dev,
                                state="STALE",
                                collection_method="passive_arp_cache",
                                confidence=0.7,
                                validation_status=ValidationStatus.OBSERVED,
                            )
                        )

        return neighbors

    def correlate_scopes(
        self,
        footprint: InternalFootprintResult,
        scopes: List[TargetScope],
        project: Optional[Project] = None,
    ) -> None:
        """Evaluates discovered interfaces, subnets, and neighbor IPs against project scope boundaries."""
        in_scope_subnets: List[str] = []
        out_of_scope_subnets: List[str] = []

        # 1. Correlate Interfaces
        for iface in footprint.interfaces:
            any_in_scope = False
            for cidr in iface.ipv4_addresses:
                res = ScopeAuthorizationService.is_target_authorized(cidr, scopes, project)
                if res.is_allowed:
                    any_in_scope = True
                    break
            iface.scope_status = "IN_SCOPE" if any_in_scope else "OUT_OF_SCOPE"

        # 2. Correlate Subnets
        for subnet in footprint.discovered_subnets:
            res = ScopeAuthorizationService.is_target_authorized(subnet, scopes, project)
            if res.is_allowed:
                in_scope_subnets.append(subnet)
            else:
                out_of_scope_subnets.append(subnet)

        footprint.in_scope_subnets = sorted(list(set(in_scope_subnets)))
        footprint.out_of_scope_subnets = sorted(list(set(out_of_scope_subnets)))

        # 3. Correlate Neighbor Entries
        for neighbor in footprint.neighbors:
            res = ScopeAuthorizationService.is_target_authorized(neighbor.ip_address, scopes, project)
            neighbor.scope_status = "IN_SCOPE" if res.is_allowed else "OUT_OF_SCOPE"

        # 4. Correlate Routes
        for route in footprint.routes:
            target_to_check = route.gateway if route.gateway else route.destination
            if target_to_check and target_to_check != "default":
                res = ScopeAuthorizationService.is_target_authorized(target_to_check, scopes, project)
                route.scope_status = "IN_SCOPE" if res.is_allowed else "OUT_OF_SCOPE"
            else:
                route.scope_status = "NOT_CONFIGURED"

    def _extract_subnets(
        self,
        interfaces: List[NetworkInterfaceInfo],
        routes: List[RouteInfo],
    ) -> List[str]:
        """Calculates unique network subnets from local interfaces and routing destinations."""
        subnets = set()
        for iface in interfaces:
            if iface.is_loopback:
                continue
            for cidr in iface.ipv4_addresses:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    subnets.add(str(net))
                except ValueError:
                    pass

        for route in routes:
            if route.destination and route.destination != "default" and "/" in route.destination:
                try:
                    net = ipaddress.ip_network(route.destination, strict=False)
                    if not net.is_loopback and not net.is_multicast:
                        subnets.add(str(net))
                except ValueError:
                    pass

        return sorted(list(subnets))

    def _fallback_interfaces(self) -> List[NetworkInterfaceInfo]:
        """Provides minimal loopback and local host discovery via python socket when tools are missing."""
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"

        return [
            NetworkInterfaceInfo(
                name="lo",
                ipv4_addresses=["127.0.0.1/8"],
                ipv6_addresses=["::1/128"],
                is_up=True,
                is_loopback=True,
                flags=["LOOPBACK", "UP"],
            ),
            NetworkInterfaceInfo(
                name="eth0 (fallback)",
                ipv4_addresses=[f"{local_ip}/24"],
                is_up=True,
                is_loopback=False,
                flags=["UP"],
            ),
        ]

    def _run_command(self, cmd: List[str]) -> Optional[str]:
        """Executes a local command safely with bounded timeout."""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
        except Exception:
            pass
        return None

    def _read_proc_arp(self) -> str:
        """Directly reads /proc/net/arp on Linux systems."""
        try:
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    def _persist_evidence(
        self,
        footprint: InternalFootprintResult,
        project_id: int,
        evidence_dir: Optional[Path] = None,
    ) -> None:
        """Stores evidence hash and file artifact in storage/evidence."""
        try:
            target_dir = evidence_dir or Path("storage/evidence")
            target_dir.mkdir(parents=True, exist_ok=True)
            filename = f"footprint_{project_id}_{int(datetime.now(timezone.utc).timestamp())}.json"
            file_path = target_dir / filename

            payload = {
                "timestamp": footprint.timestamp,
                "hostname": footprint.hostname,
                "default_gateway": footprint.default_gateway,
                "discovered_subnets": footprint.discovered_subnets,
                "in_scope_subnets": footprint.in_scope_subnets,
                "out_of_scope_subnets": footprint.out_of_scope_subnets,
                "raw_data": footprint.raw_data,
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            if self.db:
                self.db.add_evidence(
                    Evidence(
                        project_id=project_id,
                        file_path=str(file_path),
                        sha256_hash=footprint.evidence_hash,
                        file_hash=footprint.evidence_hash,
                        mime_type="application/json",
                        description=f"Internal network footprinting telemetry for project {project_id}",
                    )
                )
        except Exception:
            pass
