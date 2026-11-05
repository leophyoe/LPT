"""Offline PCAP Network Protocol Dissector & Anomaly Analyzer.

Pure-Python implementation for offline traffic analysis without external dependencies.
Dissects:
1. DNS Traffic (Queries, Record Types, Tunneling / Exfiltration entropy detection).
2. HTTP Traffic (Methods, URIs, User-Agents, Cleartext Auth, Web Attack Payloads).
3. TLS Traffic (Client Hello, SNI extraction, Deprecated TLS 1.0/1.1 detection).
4. ARP Traffic (IP-to-MAC resolution, ARP Poisoning / Spoofing detection).
5. Normalized Finding generation, Scope Authorization Guard, and SHA-256 evidence hashing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import math
from pathlib import Path
import re
import socket
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService
from modules.wireless.wireless_analyzer import PurePythonPCAPReader
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    ValidationStatus,
)


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def _shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string to detect encrypted or base64 data."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


@dataclass
class DNSQueryRecord:
    timestamp: float
    client_ip: str
    server_ip: str
    query_name: str
    query_type: str
    entropy: float = 0.0
    is_suspicious_tunnel: bool = False


@dataclass
class HTTPTransaction:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    host: str
    user_agent: str = ""
    auth_header: str = ""
    attack_tags: List[str] = field(default_factory=list)


@dataclass
class TLSSession:
    timestamp: float
    client_ip: str
    server_ip: str
    server_port: int
    sni: str = ""
    tls_version_str: str = ""
    is_deprecated_version: bool = False


@dataclass
class ARPMapping:
    ip: str
    mac: str
    is_duplicate_poison: bool = False


@dataclass
class PCAPAnalysisResult:
    source_file: str
    total_packets: int
    ip_packets: int
    dns_queries: List[DNSQueryRecord] = field(default_factory=list)
    http_transactions: List[HTTPTransaction] = field(default_factory=list)
    tls_sessions: List[TLSSession] = field(default_factory=list)
    arp_anomalies: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence_id: Optional[int] = None
    evidence_hash: str = ""
    is_authorized: bool = True
    scope_reason: str = "Authorized"


class OfflinePCAPAnalyzer:
    """Pure-Python offline network packet and protocol analyzer."""

    DNS_TYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
    }

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def analyze_pcap(
        self,
        pcap_path: Path,
        project_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
        evidence_dir: Optional[Path] = None,
    ) -> PCAPAnalysisResult:
        """Dissects an offline PCAP capture file across DNS, HTTP, TLS, and ARP protocols."""
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        raw_bytes = pcap_path.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        reader = PurePythonPCAPReader(pcap_path)
        total_packets = 0
        ip_packets = 0

        dns_queries: List[DNSQueryRecord] = []
        http_txs: List[HTTPTransaction] = []
        tls_sessions: List[TLSSession] = []
        arp_cache: Dict[str, Set[str]] = {}  # IP -> Set[MAC]
        arp_anomalies: List[str] = []

        for ts, link_type, pkt in reader:
            total_packets += 1
            # Check Link-Layer
            if link_type == PurePythonPCAPReader.DLT_EN10MB:
                if len(pkt) < 14:
                    continue
                eth_type = struct.unpack("!H", pkt[12:14])[0]
                l3_payload = pkt[14:]

                # 1. ARP Protocol (0x0806)
                if eth_type == 0x0806 and len(l3_payload) >= 28:
                    self._handle_arp(l3_payload, arp_cache, arp_anomalies)

                # 2. IPv4 Protocol (0x0800)
                elif eth_type == 0x0800 and len(l3_payload) >= 20:
                    ip_packets += 1
                    self._handle_ipv4(ts, l3_payload, dns_queries, http_txs, tls_sessions)

            elif link_type in (PurePythonPCAPReader.DLT_IEEE802_11, PurePythonPCAPReader.DLT_IEEE802_11_RADIO):
                # 802.11 frames - strip to LLC/IP if present
                # Look for IPv4 EtherType 0x0800 in LLC/SNAP
                idx = pkt.find(b"\xaa\xaa\x03\x00\x00\x00\x08\x00")
                if idx != -1 and len(pkt) >= idx + 8 + 20:
                    ip_packets += 1
                    self._handle_ipv4(ts, pkt[idx + 8 :], dns_queries, http_txs, tls_sessions)

        # Build Normalized Findings
        findings: List[Finding] = []
        if project_id:
            findings = self._generate_findings(
                project_id=project_id,
                dns_queries=dns_queries,
                http_txs=http_txs,
                tls_sessions=tls_sessions,
                arp_anomalies=arp_anomalies,
                source_file=pcap_path.name,
                assessment_id=assessment_id,
            )

        # Scope Check
        is_authorized = True
        scope_reason = "PCAP endpoints within authorized scope"
        authorized_findings = findings

        if project_id and self.db:
            scopes = self.db.list_scopes(project_id)
            project = self.db.get_project(project_id)
            if scopes:
                in_scope_findings = []
                for f in findings:
                    chk = ScopeAuthorizationService.is_target_authorized(
                        f.affected_asset, scopes, project=project
                    )
                    if chk.is_allowed:
                        in_scope_findings.append(f)
                    else:
                        is_authorized = False
                        scope_reason = f"Endpoint '{f.affected_asset}' outside authorized scope"
                authorized_findings = in_scope_findings

        # Evidence Vault Registration
        evidence_entry = None
        if project_id and self.db:
            dest_file = pcap_path
            if evidence_dir:
                evidence_dir.mkdir(parents=True, exist_ok=True)
                dest_file = evidence_dir / f"pcap_{project_id}_{pcap_path.name}"
                if dest_file != pcap_path:
                    dest_file.write_bytes(raw_bytes)

            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    file_path=str(dest_file),
                    sha256_hash=sha256,
                    description=f"PCAP Network Protocol Capture: {pcap_path.name} ({total_packets} pkts, {len(dns_queries)} DNS, {len(http_txs)} HTTP)",
                    mime_type="application/vnd.tcpdump.pcap",
                    assessment_id=assessment_id,
                )
            )

            for f in authorized_findings:
                self.db.upsert_finding_deduplicated(f)

            ActivityLogger(self.db).log(
                project_id=project_id,
                action="pcap_network_analysis_completed",
                outcome="completed",
                details={
                    "source_file": pcap_path.name,
                    "packets": total_packets,
                    "dns_count": len(dns_queries),
                    "http_count": len(http_txs),
                    "findings_count": len(authorized_findings),
                    "sha256": sha256,
                },
            )

        return PCAPAnalysisResult(
            source_file=str(pcap_path),
            total_packets=total_packets,
            ip_packets=ip_packets,
            dns_queries=dns_queries,
            http_transactions=http_txs,
            tls_sessions=tls_sessions,
            arp_anomalies=arp_anomalies,
            findings=authorized_findings,
            evidence_id=evidence_entry.id if evidence_entry else None,
            evidence_hash=sha256,
            is_authorized=is_authorized,
            scope_reason=scope_reason,
        )

    def _handle_arp(
        self,
        arp_raw: bytes,
        arp_cache: Dict[str, Set[str]],
        arp_anomalies: List[str],
    ):
        """Dissects ARP packets and flags ARP Poisoning / duplicate MAC anomalies."""
        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", arp_raw[0:8])
        if hw_type == 1 and proto_type == 0x0800 and hw_size == 6 and proto_size == 4:
            src_mac = _mac_to_str(arp_raw[8:14])
            src_ip = socket.inet_ntoa(arp_raw[14:18])

            # Ignore 0.0.0.0 or broadcast
            if src_ip != "0.0.0.0":
                if src_ip not in arp_cache:
                    arp_cache[src_ip] = set()
                arp_cache[src_ip].add(src_mac)

                if len(arp_cache[src_ip]) > 1:
                    mac_list = ", ".join(sorted(arp_cache[src_ip]))
                    msg = f"ARP Poisoning / IP Conflict Detected: IP '{src_ip}' claimed by multiple MACs: [{mac_list}]"
                    if msg not in arp_anomalies:
                        arp_anomalies.append(msg)

    def _handle_ipv4(
        self,
        ts: float,
        ip_raw: bytes,
        dns_queries: List[DNSQueryRecord],
        http_txs: List[HTTPTransaction],
        tls_sessions: List[TLSSession],
    ):
        """Parses IPv4 Header and dispatches to TCP/UDP payload decoders."""
        ihl = (ip_raw[0] & 0x0F) * 4
        if len(ip_raw) < ihl:
            return

        proto = ip_raw[9]
        src_ip = socket.inet_ntoa(ip_raw[12:16])
        dst_ip = socket.inet_ntoa(ip_raw[16:20])
        l4_payload = ip_raw[ihl:]

        # UDP (Protocol 17)
        if proto == 17 and len(l4_payload) >= 8:
            src_port, dst_port, udp_len = struct.unpack("!HHH", l4_payload[0:6])
            udp_data = l4_payload[8:udp_len]

            # DNS (Port 53)
            if src_port == 53 or dst_port == 53:
                self._handle_dns(ts, src_ip, dst_ip, udp_data, dns_queries)

        # TCP (Protocol 6)
        elif proto == 6 and len(l4_payload) >= 20:
            src_port, dst_port, _seq, _ack, data_offset = struct.unpack("!HHIIB", l4_payload[0:13])
            tcp_hdr_len = (data_offset >> 4) * 4
            tcp_data = l4_payload[tcp_hdr_len:]
            if not tcp_data:
                return

            # HTTP Inspection (Port 80, 8080, 3000, 5000...)
            if dst_port in (80, 8080, 8000, 8888, 3000, 5000) or src_port in (80, 8080, 8000, 8888, 3000, 5000):
                self._handle_http(ts, src_ip, dst_ip, dst_port, tcp_data, http_txs)

            # TLS Inspection (Port 443, 8443)
            if dst_port in (443, 8443) or src_port in (443, 8443):
                self._handle_tls(ts, src_ip, dst_ip, dst_port, tcp_data, tls_sessions)

    def _handle_dns(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dns_raw: bytes,
        dns_queries: List[DNSQueryRecord],
    ):
        """Parses standard DNS queries and checks for tunneling anomalies."""
        if len(dns_raw) < 12:
            return

        _trans_id, flags, q_count = struct.unpack("!HHH", dns_raw[0:6])
        is_response = bool(flags & 0x8000)
        if is_response or q_count < 1:
            return

        # Parse Question Name
        offset = 12
        labels = []
        while offset < len(dns_raw):
            length = dns_raw[offset]
            if length == 0:
                offset += 1
                break
            if length > 63:  # Compression pointer
                offset += 2
                break
            offset += 1
            if offset + length > len(dns_raw):
                break
            labels.append(dns_raw[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

        if not labels:
            return

        domain = ".".join(labels)
        q_type_str = "A"
        if offset + 2 <= len(dns_raw):
            q_type = struct.unpack("!H", dns_raw[offset : offset + 2])[0]
            q_type_str = self.DNS_TYPES.get(q_type, f"TYPE_{q_type}")

        # Check for DNS Tunneling (long subdomain or high entropy)
        subdomain = labels[0] if len(labels) > 2 else ""
        ent = _shannon_entropy(subdomain) if subdomain else 0.0
        is_tunnel = len(subdomain) > 40 or (len(subdomain) > 20 and ent > 3.8)

        dns_queries.append(
            DNSQueryRecord(
                timestamp=ts,
                client_ip=src_ip,
                server_ip=dst_ip,
                query_name=domain,
                query_type=q_type_str,
                entropy=round(ent, 2),
                is_suspicious_tunnel=is_tunnel,
            )
        )

    def _handle_http(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        data: bytes,
        http_txs: List[HTTPTransaction],
    ):
        """Parses HTTP request line, headers, and flags web attack payloads."""
        try:
            head = data[: min(len(data), 2048)].decode("latin1")
            first_line = head.split("\r\n", 1)[0]
            parts = first_line.split(" ")
            if len(parts) >= 3 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
                method, uri, _proto = parts[0], parts[1], parts[2]
                host = ""
                ua = ""
                auth = ""

                for line in head.split("\r\n")[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("user-agent:"):
                        ua = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("authorization:"):
                        auth = line.split(":", 1)[1].strip()

                # Flag Web Attack Payloads in URI
                attack_tags = []
                if any(p in uri for p in ("../", "..\\", "%2e%2e")):
                    attack_tags.append("Path Traversal (CWE-22)")
                if any(x in uri.lower() for x in ("<script>", "%3cscript%3e", "javascript:")):
                    attack_tags.append("Cross-Site Scripting (CWE-79)")
                if any(s in uri.lower() for s in ("union+select", "union%20select", "' or '1'='1", "select+from")):
                    attack_tags.append("SQL Injection (CWE-89)")

                http_txs.append(
                    HTTPTransaction(
                        timestamp=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        method=method,
                        uri=uri,
                        host=host or dst_ip,
                        user_agent=ua,
                        auth_header=auth,
                        attack_tags=attack_tags,
                    )
                )
        except Exception:
            pass

    def _handle_tls(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        data: bytes,
        tls_sessions: List[TLSSession],
    ):
        """Extracts SNI and TLS version from Client Hello packets."""
        if len(data) < 43 or data[0] != 22:  # ContentType: Handshake (22)
            return

        legacy_ver = struct.unpack("!H", data[1:3])[0]
        # Handshake Type: Client Hello (1)
        if data[5] != 1:
            return

        client_ver = struct.unpack("!H", data[9:11])[0]
        ver_map = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }
        ver_str = ver_map.get(client_ver, f"0x{client_ver:04x}")
        is_deprecated = client_ver in (0x0300, 0x0301, 0x0302)

        # Search for Server Name Indication (SNI) extension
        sni = ""
        sni_idx = data.find(b"\x00\x00")  # Extension type 0 (Server Name)
        if sni_idx != -1 and len(data) >= sni_idx + 9:
            try:
                name_len = struct.unpack("!H", data[sni_idx + 7 : sni_idx + 9])[0]
                if len(data) >= sni_idx + 9 + name_len:
                    sni = data[sni_idx + 9 : sni_idx + 9 + name_len].decode("ascii", errors="replace")
            except Exception:
                pass

        if sni or is_deprecated:
            tls_sessions.append(
                TLSSession(
                    timestamp=ts,
                    client_ip=src_ip,
                    server_ip=dst_ip,
                    server_port=dst_port,
                    sni=sni,
                    tls_version_str=ver_str,
                    is_deprecated_version=is_deprecated,
                )
            )

    def _generate_findings(
        self,
        project_id: int,
        dns_queries: List[DNSQueryRecord],
        http_txs: List[HTTPTransaction],
        tls_sessions: List[TLSSession],
        arp_anomalies: List[str],
        source_file: str,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Translates detected traffic anomalies into structured Finding records."""
        findings: List[Finding] = []

        # 1. ARP Poisoning Findings
        for anomaly in arp_anomalies:
            ip_match = re.search(r"IP '([^']+)'", anomaly)
            affected = ip_match.group(1) if ip_match else source_file
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"ARP Cache Poisoning / Spoofing Anomaly on {affected}",
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.4,
                    affected_asset=affected,
                    affected_port_service="arp/ethernet",
                    description=anomaly,
                    reproduction_steps=f"Observed during passive offline capture analysis of '{source_file}'.",
                    remediation="Enable Dynamic ARP Inspection (DAI) and 802.1X Port Security on network switches.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="pcap_analyzer",
                    assessment_id=assessment_id,
                )
            )

        # 2. DNS Tunneling Findings
        for q in dns_queries:
            if q.is_suspicious_tunnel:
                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Potential DNS Tunneling / Exfiltration Query: {q.query_name}",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.2,
                        affected_asset=q.client_ip,
                        affected_port_service="53/dns",
                        description=(
                            f"Client {q.client_ip} dispatched a high-entropy ({q.entropy}) DNS query for '{q.query_name}'. "
                            "This pattern is characteristic of DNS tunneling tools (e.g. dnscat2, iodine) or data exfiltration."
                        ),
                        reproduction_steps=f"Client: {q.client_ip} -> DNS Server: {q.server_ip}\nQuery: {q.query_name} ({q.query_type})",
                        remediation="Deploy DNS firewall / RPZ to block suspicious high-entropy subdomains and monitor TXT query volume.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="pcap_analyzer",
                        assessment_id=assessment_id,
                    )
                )

        # 3. HTTP Cleartext Auth & Attack Payloads
        for tx in http_txs:
            if tx.attack_tags:
                tag_str = ", ".join(tx.attack_tags)
                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Web Attack Payload in Network Traffic ({tag_str})",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.5,
                        affected_asset=tx.dst_ip,
                        affected_port_service=f"{tx.dst_port}/http",
                        description=f"Observed malicious attack request from {tx.src_ip} targeting {tx.host}: {tx.method} {tx.uri}",
                        reproduction_steps=f"Request:\n{tx.method} {tx.uri}\nHost: {tx.host}\nUser-Agent: {tx.user_agent}",
                        remediation="Filter inputs with a Web Application Firewall (WAF) and sanitize request parameters.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="pcap_analyzer",
                        assessment_id=assessment_id,
                    )
                )
            elif tx.auth_header and tx.auth_header.lower().startswith("basic "):
                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Cleartext HTTP Basic Authentication Transmitted to {tx.host}",
                        severity=FindingSeverity.MEDIUM,
                        cvss_score=5.3,
                        affected_asset=tx.dst_ip,
                        affected_port_service=f"{tx.dst_port}/http",
                        description=f"Client {tx.src_ip} transmitted unencrypted Basic Authentication credentials to {tx.host}.",
                        reproduction_steps=f"Endpoint: http://{tx.host}:{tx.dst_port}{tx.uri}\nAuth Header: {tx.auth_header[:20]}...",
                        remediation="Enforce HTTPS via TLS/SSL and disable plaintext HTTP authentication.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="pcap_analyzer",
                        assessment_id=assessment_id,
                    )
                )

        # 4. Deprecated TLS 1.0/1.1
        for s in tls_sessions:
            if s.is_deprecated_version:
                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Deprecated Insecure TLS Version ({s.tls_version_str}) Used by {s.client_ip}",
                        severity=FindingSeverity.MEDIUM,
                        cvss_score=4.3,
                        affected_asset=s.server_ip,
                        affected_port_service=f"{s.server_port}/tls",
                        description=f"Connection negotiated obsolete protocol {s.tls_version_str} for destination '{s.sni or s.server_ip}'.",
                        reproduction_steps=f"Client: {s.client_ip} -> Server: {s.server_ip}:{s.server_port} ({s.sni})\nVersion: {s.tls_version_str}",
                        remediation="Disable SSL 3.0, TLS 1.0, and TLS 1.1; enforce TLS 1.2 or TLS 1.3.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="pcap_analyzer",
                        assessment_id=assessment_id,
                    )
                )

        return findings

