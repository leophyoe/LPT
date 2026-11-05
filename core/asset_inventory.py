"""Asset inventory normalization, deduplication, and observation preservation.

Normalizes asset identifiers (IPv4, IPv6, Hostnames, URLs), associates assets
with assessment sessions, deduplicates asset nodes in the database, and preserves
complete historical scan observation records across time without destructive overwriting.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService
from modules.network.nmap_parser import HostResult, NmapScanResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    TargetScope,
    _utc_now_iso,
)


def normalize_asset_value(node_type: str, value: str) -> str:
    """Standardizes asset identifiers for deduplication."""
    if not value or not isinstance(value, str):
        return ""
    val = value.strip()
    ntype = node_type.strip().lower()

    if ntype in ("ip", "ip_address"):
        try:
            return ipaddress.ip_address(val).compressed
        except ValueError:
            return val
    elif ntype in ("hostname", "domain", "subdomain"):
        return val.lower().rstrip(".")
    elif ntype == "url":
        try:
            p = urlparse(val)
            scheme = (p.scheme or "http").lower()
            netloc = p.netloc.lower()
            path = p.path.rstrip("/")
            return f"{scheme}://{netloc}{path}"
        except Exception:
            return val
    elif ntype == "mac":
        return val.lower().replace("-", ":")
    return val


@dataclass
class DiscoveredPortObservation:
    """Represents a discovered open or filtered service port."""
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class DiscoveredHostObservation:
    """Unified normalized host observation from any network or security tool provider."""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_match: Optional[str] = None
    os_accuracy: Optional[int] = None
    device_type: Optional[str] = None
    latency_ms: Optional[float] = None
    status: str = "up"
    confidence: float = 1.0  # 1.0 for active verified probe, 0.7 for passive cache
    discovery_source: str = "nmap"  # nmap, arp_scan, netdiscover, local_footprint, zap, burp, pcap
    session_id: str = ""
    evidence_id: Optional[int] = None
    ports: List[DiscoveredPortObservation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AssetInventoryService:
    """Manages asset normalization, deduplication, and historical observation tracking."""

    def __init__(self, db: Database):
        self.db = db

    def sync_host_observations(
        self,
        project_id: int,
        observations: Optional[List[DiscoveredHostObservation]] = None,
        scopes: Optional[List[TargetScope]] = None,
        source_tool: str = "discovery",
        evidence_id: Optional[int] = None,
        session_id: Optional[str] = None,
        hosts: Optional[List[DiscoveredHostObservation]] = None,
    ) -> Tuple[List[AssetNode], List[Observation]]:
        """Unified multi-tool asset synchronization engine.

        Enforces strict scope authorization, non-destructive telemetry merging,
        multi-tool provenance tracking, and observation preservation.
        """
        synced_nodes: List[AssetNode] = []
        recorded_observations: List[Observation] = []
        target_observations = observations if observations is not None else (hosts or [])
        scope_list = scopes if scopes is not None else self.db.list_scopes(project_id)
        existing_nodes = {n.value: n for n in self.db.list_asset_nodes(project_id) if n.node_type == "ip"}

        for host in target_observations:
            if host.status != "up":
                continue

            # Scope Authorization Guard: Only record authorized assets as active inventory nodes
            scope_check = ScopeAuthorizationService.is_target_authorized(host.ip, scope_list)
            if not scope_check.is_allowed:
                continue

            norm_ip = normalize_asset_value("ip", host.ip)
            open_ports = [p for p in host.ports if p.state == "open"]

            existing_meta: Dict[str, Any] = {}
            existing_node = existing_nodes.get(norm_ip)
            if existing_node and existing_node.metadata_json:
                try:
                    existing_meta = json.loads(existing_node.metadata_json)
                except Exception:
                    existing_meta = {}

            # Multi-tool provenance tracking
            tool_name = host.discovery_source or source_tool or "discovery"
            existing_sources = existing_meta.get("sources", [])
            if not existing_sources and existing_node:
                existing_sources = [existing_node.source_tool or "unknown"]
            if tool_name not in existing_sources:
                existing_sources.append(tool_name)

            # If current scan probed open ports, use them as current port state.
            # If current scan is a host-discovery / ping sweep / passive ARP with no port scan, preserve existing open ports!
            if open_ports:
                final_open_ports = [p.port for p in open_ports]
                final_services = [
                    {
                        "port": p.port,
                        "proto": p.protocol,
                        "service": p.service_name,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in open_ports
                ]
            elif existing_meta.get("open_ports"):
                final_open_ports = existing_meta.get("open_ports", [])
                final_services = existing_meta.get("services", [])
            else:
                final_open_ports = []
                final_services = []

            metadata: Dict[str, Any] = {
                "os_match": host.os_match or existing_meta.get("os_match"),
                "os_accuracy": host.os_accuracy or existing_meta.get("os_accuracy"),
                "mac_address": host.mac_address or existing_meta.get("mac_address"),
                "vendor": host.vendor or existing_meta.get("vendor"),
                "device_type": host.device_type or existing_meta.get("device_type"),
                "latency_ms": host.latency_ms if host.latency_ms is not None else existing_meta.get("latency_ms"),
                "open_ports": final_open_ports,
                "services": final_services,
                "session_id": session_id or host.session_id or existing_meta.get("session_id", ""),
                "discovery_source": tool_name,
                "sources": existing_sources,
                "confidence": max(host.confidence, existing_meta.get("confidence", 0.0)),
                "last_seen": _utc_now_iso(),
            }
            if host.metadata:
                for k, v in host.metadata.items():
                    if k not in metadata or not metadata[k]:
                        metadata[k] = v

            final_label = host.hostname or (existing_node.label if (existing_node and existing_node.label != norm_ip) else norm_ip)

            # 1. Deduplicate & Upsert IP AssetNode
            ip_node = self.db.upsert_asset_node(
                AssetNode(
                    project_id=project_id,
                    node_type="ip",
                    value=norm_ip,
                    label=final_label,
                    source_tool=tool_name,
                    confidence=metadata["confidence"],
                    metadata_json=json.dumps(metadata),
                )
            )
            synced_nodes.append(ip_node)
            existing_nodes[norm_ip] = ip_node

            # 2. Preserve Historical Scan Observation Record (Non-destructive)
            obs_payload = {
                "session_id": session_id or host.session_id or "",
                "timestamp": _utc_now_iso(),
                "scanner": tool_name,
                "ports": metadata["services"],
                "os_fingerprint": metadata.get("os_match"),
                "mac_address": metadata.get("mac_address"),
                "vendor": metadata.get("vendor"),
                "latency_ms": metadata.get("latency_ms"),
                "confidence": host.confidence,
            }
            method_type = "active_scan" if host.confidence >= 0.9 else "passive_observation"
            obs = Observation(
                project_id=project_id,
                title=f"Observation for {norm_ip} via {tool_name.upper()} ({len(final_open_ports)} open port(s))",
                asset_id=ip_node.id,
                source_tool=tool_name,
                method=method_type,
                raw_data=json.dumps(obs_payload),
                confidence=host.confidence,
                verification_status="observed" if host.confidence >= 0.9 else "unverified",
                evidence_id=evidence_id or host.evidence_id,
            )
            recorded_obs = self.db.create_observation(obs)
            recorded_observations.append(recorded_obs)

            # 3. Hostname normalization, upsert, and relationship edge
            if host.hostname:
                norm_hn = normalize_asset_value("hostname", host.hostname)
                hn_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type="hostname",
                        value=norm_hn,
                        label=norm_hn,
                        source_tool=tool_name,
                        confidence=host.confidence,
                        metadata_json=json.dumps({"ip": norm_ip, "session_id": session_id or ""}),
                    )
                )
                synced_nodes.append(hn_node)

                self.db.add_asset_edge(
                    AssetEdge(
                        project_id=project_id,
                        source_node_id=hn_node.id,
                        target_node_id=ip_node.id,
                        relation_type="RESOLVES_TO",
                        source_tool=tool_name,
                    )
                )

        return synced_nodes, recorded_observations

    def sync_scan_assets(
        self,
        project_id: int,
        scan_result: NmapScanResult,
        scopes: List[TargetScope],
        session_id: Optional[str] = None,
        source_tool: str = "nmap",
        evidence_id: Optional[int] = None,
    ) -> Tuple[List[AssetNode], List[Observation]]:
        """Converts NmapScanResult into unified DiscoveredHostObservation objects and syncs."""
        host_obs: List[DiscoveredHostObservation] = []
        for h in scan_result.hosts:
            ports = [
                DiscoveredPortObservation(
                    port=p.port_id,
                    protocol=p.protocol,
                    service_name=p.service_name,
                    product=p.product,
                    version=p.version,
                    state=p.state,
                )
                for p in h.ports
            ]
            host_obs.append(
                DiscoveredHostObservation(
                    ip=h.ip,
                    hostname=h.hostname,
                    mac_address=h.mac_address,
                    vendor=h.vendor,
                    os_match=h.os_match or h.os_summary,
                    os_accuracy=h.os_accuracy,
                    device_type=h.device_type,
                    latency_ms=h.latency_ms,
                    status=h.status,
                    confidence=1.0,
                    discovery_source=source_tool or "nmap",
                    session_id=session_id or "",
                    evidence_id=evidence_id,
                    ports=ports,
                )
            )
        return self.sync_host_observations(
            project_id=project_id,
            observations=host_obs,
            scopes=scopes,
            source_tool=source_tool,
            evidence_id=evidence_id,
            session_id=session_id,
        )

    def sync_footprint_assets(
        self,
        project_id: int,
        footprint: Any,
        scopes: List[TargetScope],
        evidence_id: Optional[int] = None,
        source_tool: str = "local_footprint",
    ) -> Tuple[List[AssetNode], List[Observation]]:
        """Converts local network footprint (passive ARP cache, interfaces) into DiscoveredHostObservation."""
        host_obs: List[DiscoveredHostObservation] = []

        # 1. Process passive neighbor cache
        for n in getattr(footprint, "neighbors", []):
            if not n.ip_address:
                continue
            host_obs.append(
                DiscoveredHostObservation(
                    ip=n.ip_address,
                    hostname=getattr(n, "hostname", None),
                    mac_address=n.mac_address if n.mac_address != "Unknown" else None,
                    status="up" if n.state != "FAILED" else "down",
                    confidence=getattr(n, "confidence", 0.7),
                    discovery_source="passive_arp",
                    evidence_id=evidence_id,
                    metadata={"interface": n.interface, "state": n.state, "method": n.collection_method},
                )
            )

        # 2. Process local interfaces
        for iface in getattr(footprint, "interfaces", []):
            if not iface.is_up or iface.is_loopback:
                continue
            for ip_str in iface.ipv4_addresses:
                clean_ip = ip_str.split("/")[0].strip()
                if clean_ip and not clean_ip.startswith("127."):
                    host_obs.append(
                        DiscoveredHostObservation(
                            ip=clean_ip,
                            mac_address=iface.mac_address,
                            status="up",
                            confidence=1.0,
                            discovery_source="local_interface",
                            evidence_id=evidence_id,
                            metadata={"interface": iface.name},
                        )
                    )

        # 3. Process default gateway if present
        gateway = getattr(footprint, "default_gateway", None)
        if gateway and not gateway.startswith("127."):
            host_obs.append(
                DiscoveredHostObservation(
                    ip=gateway,
                    status="up",
                    confidence=0.9,
                    discovery_source="default_gateway",
                    evidence_id=evidence_id,
                    metadata={"role": "gateway"},
                )
            )

        return self.sync_host_observations(
            project_id=project_id,
            observations=host_obs,
            scopes=scopes,
            source_tool=source_tool,
            evidence_id=evidence_id,
        )

    def get_asset_history(self, project_id: int, asset_id: int) -> List[Observation]:
        """Retrieves complete timeline of observations for the given asset."""
        return self.db.list_observations_for_asset(project_id, asset_id)

    def sync_pcap_relationships(
        self,
        project_id: int,
        pcap_result: Any,
        scopes: Optional[List[TargetScope]] = None,
        evidence_id: Optional[int] = None,
        session_id: Optional[str] = None,
        admit_ordinary_flows: bool = False,
        admitted_service_ports: Optional[Any] = None,
        project: Optional[Project] = None,
    ) -> Tuple[List[AssetEdge], List[Observation]]:
        """Selectively ingests evidence-backed network communication relationships from PCAP analysis.

        Enforces:
        - Strict scope boundary checks on both source and destination endpoints.
        - Security-anomaly flow admission based on genuine analyzer findings.
        - Ordinary service flow admission restricted to Nmap-confirmed open ports or explicit configuration.
        - Non-destructive edge upserts preserving created_at and aggregating evidence identifiers.
        - Generation of supporting Observation records linked to capture evidence.
        """
        synced_edges: List[AssetEdge] = []
        recorded_observations: List[Observation] = []

        scope_list = scopes if scopes is not None else self.db.list_scopes(project_id)
        if project is None:
            try:
                project = self.db.get_project(project_id)
            except Exception:
                project = None

        existing_nodes = {n.value: n for n in self.db.list_asset_nodes(project_id) if n.node_type == "ip"}

        def _get_verified_ports(ip_str: str) -> set:
            verified = set()
            node = existing_nodes.get(ip_str)
            if node and node.metadata_json:
                try:
                    meta = json.loads(node.metadata_json)
                    for p in meta.get("open_ports", []):
                        verified.add(("tcp", int(p)))
                        verified.add(("udp", int(p)))
                    for s in meta.get("services", []):
                        p_num = s.get("port")
                        p_proto = (s.get("proto") or "tcp").lower()
                        if p_num is not None:
                            verified.add((p_proto, int(p_num)))
                except Exception:
                    pass
            return verified

        flows: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}

        def _accumulate_flow(src: str, dst: str, proto: str, port: int, is_anomaly: bool, tags: List[str]):
            if not src or not dst or port <= 0 or port > 65535:
                return
            if any(ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::1") for ip in (src, dst)):
                return
            if src.startswith("224.") or dst.startswith("224.") or src.startswith("239.") or dst.startswith("239."):
                return

            key = (src, dst, proto.lower(), port)
            if key not in flows:
                flows[key] = {
                    "src": src,
                    "dst": dst,
                    "proto": proto.lower(),
                    "port": port,
                    "is_anomaly": False,
                    "attack_tags": set(),
                    "packet_count": 0,
                }
            flows[key]["packet_count"] += 1
            if is_anomaly:
                flows[key]["is_anomaly"] = True
                flows[key]["attack_tags"].update(tags)

        # 1. Harvest flows from DNS
        for q in getattr(pcap_result, "dns_queries", []):
            is_anomaly = bool(
                getattr(q, "is_suspicious_tunnel", False)
                or getattr(q, "is_anomaly", False)
                or getattr(q, "entropy", 0.0) > 4.2
            )
            tags = ["DNS Exfiltration / Tunneling"] if is_anomaly else []
            _accumulate_flow(q.client_ip, q.server_ip, "udp", 53, is_anomaly, tags)

        # 2. Harvest flows from HTTP
        for h in getattr(pcap_result, "http_transactions", []):
            attacks = list(getattr(h, "attack_tags", []))
            cleartext_auth = bool(getattr(h, "auth_header", ""))
            is_anomaly = bool(attacks or cleartext_auth)
            tags = list(attacks)
            if cleartext_auth:
                tags.append("Cleartext Authentication")
            _accumulate_flow(h.src_ip, h.dst_ip, "tcp", h.dst_port, is_anomaly, tags)

        # 3. Harvest flows from TLS
        for s in getattr(pcap_result, "tls_sessions", []):
            is_anomaly = bool(getattr(s, "is_deprecated_version", False))
            tls_ver = getattr(s, "tls_version_str", "Unknown")
            tags = [f"Deprecated TLS Version ({tls_ver})"] if is_anomaly else []
            _accumulate_flow(s.client_ip, s.server_ip, "tcp", s.server_port, is_anomaly, tags)

        # Helper for activity logging of scope rejections
        def _log_scope_exclusion(src_ip: str, dst_ip: str, proto: str, port: int, reason: str):
            try:
                act_logger = ActivityLogger(self.db)
                act_logger.log(
                    project_id=project_id,
                    action="pcap_scope_exclusion",
                    outcome="rejected",
                    session_id=session_id,
                    details={
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "protocol": proto,
                        "port": port,
                        "reason": reason,
                    },
                )
            except Exception:
                pass

        for (src_ip, dst_ip, proto, dst_port), flow_info in flows.items():
            src_check = ScopeAuthorizationService.is_target_authorized(src_ip, scope_list, project)
            if not src_check.is_allowed:
                _log_scope_exclusion(src_ip, dst_ip, proto, dst_port, f"Source IP {src_ip} unauthorized: {src_check.reason}")
                continue

            dst_check = ScopeAuthorizationService.is_target_authorized(dst_ip, scope_list, project)
            if not dst_check.is_allowed:
                _log_scope_exclusion(src_ip, dst_ip, proto, dst_port, f"Target IP {dst_ip} unauthorized: {dst_check.reason}")
                continue

            is_anomaly = flow_info["is_anomaly"]
            verified_ports = _get_verified_ports(dst_ip)
            is_nmap_verified = (proto, dst_port) in verified_ports or ("tcp", dst_port) in verified_ports

            is_explicitly_admitted = False
            if admit_ordinary_flows:
                is_explicitly_admitted = True
            elif admitted_service_ports and ((proto, dst_port) in admitted_service_ports or ("*", dst_port) in admitted_service_ports):
                is_explicitly_admitted = True

            if not is_anomaly and not is_nmap_verified and not is_explicitly_admitted:
                continue

            norm_src = normalize_asset_value("ip", src_ip)
            norm_dst = normalize_asset_value("ip", dst_ip)

            src_node = existing_nodes.get(norm_src)
            if not src_node:
                src_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type="ip",
                        value=norm_src,
                        label=norm_src,
                        source_tool="pcap_analyzer",
                        confidence=0.85,
                    )
                )
                existing_nodes[norm_src] = src_node

            dst_node = existing_nodes.get(norm_dst)
            if not dst_node:
                dst_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type="ip",
                        value=norm_dst,
                        label=norm_dst,
                        source_tool="pcap_analyzer",
                        confidence=0.85,
                    )
                )
                existing_nodes[norm_dst] = dst_node

            relation_type = f"COMMUNICATES_WITH:{proto}/{dst_port}"
            now_iso = _utc_now_iso()
            attack_tags = sorted(list(flow_info["attack_tags"]))

            edge_meta: Dict[str, Any] = {
                "protocol": proto,
                "destination_port": dst_port,
                "packet_count": flow_info["packet_count"],
                "is_anomaly": is_anomaly,
                "attack_tags": attack_tags,
                "nmap_confirmed": is_nmap_verified,
                "session_id": session_id or "",
                "evidence_ids": [evidence_id] if evidence_id else [],
            }

            edge = AssetEdge(
                project_id=project_id,
                source_node_id=src_node.id,
                target_node_id=dst_node.id,
                relation_type=relation_type,
                source_tool="pcap_analyzer",
                verification_state="observed",
                confidence=0.9 if is_nmap_verified else 0.85,
                evidence_id=evidence_id,
                last_seen=now_iso,
                metadata_json=json.dumps(edge_meta),
            )
            saved_edge = self.db.upsert_asset_edge(edge)
            synced_edges.append(saved_edge)

            obs_title = f"Observed flow {norm_src} -> {norm_dst} ({proto.upper()}/{dst_port})"
            if is_anomaly:
                obs_title += f" [ANOMALY: {', '.join(attack_tags)}]"

            obs = Observation(
                project_id=project_id,
                title=obs_title,
                asset_id=dst_node.id,
                source_tool="pcap_analyzer",
                method="pcap_flow_dissection",
                raw_data=json.dumps(edge_meta),
                confidence=saved_edge.confidence,
                verification_status="verified" if is_nmap_verified else "observed",
                evidence_id=evidence_id,
            )
            saved_obs = self.db.create_observation(obs)
            recorded_observations.append(saved_obs)

        return synced_edges, recorded_observations

