"""Asset and Service Correlation Engine.

Normalizes, deduplicates, and correlates network hosts, open ports, and services
discovered across heterogeneous security tools (Nmap, Nikto, Gobuster, SQLMap, etc.).
Preserves historical observations, tracks multi-tool provenance, and strictly
enforces project boundaries.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.asset_inventory import (
    AssetInventoryService,
    DiscoveredHostObservation,
    DiscoveredPortObservation,
    normalize_asset_value,
)
from core.parsers.normalized_models import NormalizedFinding, NormalizedService
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    TargetScope,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


@dataclass
class AssetCorrelationSummary:
    """Consolidated outcome of asset and service correlation."""
    project_id: int
    hosts_updated: int = 0
    services_correlated: int = 0
    nodes: List[AssetNode] = field(default_factory=list)
    edges: List[AssetEdge] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)


class AssetServiceCorrelator:
    """Correlates normalized services, endpoints, and findings into persistent asset topology."""

    def __init__(self, db: Database):
        self.db = db
        self.inventory_service = AssetInventoryService(db)

    def correlate_services(
        self,
        project_id: int,
        services: List[NormalizedService],
        source_tool: str = "discovery",
        evidence_id: Optional[int] = None,
        session_id: Optional[str] = None,
        scopes: Optional[List[TargetScope]] = None,
    ) -> AssetCorrelationSummary:
        """Correlates a batch of normalized services into the project asset inventory."""
        summary = AssetCorrelationSummary(project_id=project_id)
        if not services:
            return summary

        # Group services by target host
        services_by_host: Dict[str, List[NormalizedService]] = {}
        for s in services:
            h = s.host.strip()
            if h:
                services_by_host.setdefault(h, []).append(s)

        host_observations: List[DiscoveredHostObservation] = []
        for host_str, host_services in services_by_host.items():
            parsed_ip, parsed_hostname = self._resolve_host_identity(host_str)

            port_obs: List[DiscoveredPortObservation] = []
            for s in host_services:
                port_obs.append(
                    DiscoveredPortObservation(
                        port=s.port,
                        protocol=s.protocol,
                        service_name=s.service_name,
                        product=s.product,
                        version=s.version,
                        state=s.state or "open",
                    )
                )

            obs = DiscoveredHostObservation(
                ip=parsed_ip or host_str,
                hostname=parsed_hostname,
                ports=port_obs,
                confidence=max((s.confidence for s in host_services), default=1.0),
                discovery_source=source_tool or "discovery",
                session_id=session_id or "",
                evidence_id=evidence_id,
            )
            host_observations.append(obs)

        nodes, observations = self.inventory_service.sync_host_observations(
            project_id=project_id,
            observations=host_observations,
            scopes=scopes,
            source_tool=source_tool,
            evidence_id=evidence_id,
            session_id=session_id,
        )

        summary.nodes = nodes
        summary.observations = observations
        summary.hosts_updated = len(nodes)
        summary.services_correlated = len(services)

        # Retrieve any generated edges for the project
        summary.edges = self.db.list_asset_edges(project_id)
        return summary

    def correlate_finding_targets(
        self,
        project_id: int,
        findings: List[NormalizedFinding],
        source_tool: str = "security_tool",
        evidence_id: Optional[int] = None,
    ) -> List[AssetNode]:
        """Ensures that assets mentioned in findings exist as nodes in the project inventory."""
        created_or_found: List[AssetNode] = []
        existing_nodes = {n.value: n for n in self.db.list_asset_nodes(project_id)}

        for f in findings:
            raw_target = f.affected_asset or ""
            if not raw_target:
                continue

            # Strip port or URL path if present to find core asset
            core_host = self._extract_core_host(raw_target)
            if not core_host:
                continue

            node_type = "ip" if self._is_ip(core_host) else "hostname"
            norm_val = normalize_asset_value(node_type, core_host)

            if norm_val in existing_nodes:
                created_or_found.append(existing_nodes[norm_val])
            else:
                new_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type=node_type,
                        value=norm_val,
                        label=norm_val,
                        source_tool=f.source_tool or source_tool,
                        confidence=f.confidence,
                        metadata_json=json.dumps({"first_seen_in_finding": f.title}),
                    )
                )
                existing_nodes[norm_val] = new_node
                created_or_found.append(new_node)

        return created_or_found

    @staticmethod
    def _is_ip(val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    @classmethod
    def _resolve_host_identity(cls, host_str: str) -> Tuple[Optional[str], Optional[str]]:
        """Splits host_str into (ip, hostname) if possible."""
        clean = cls._extract_core_host(host_str)
        if cls._is_ip(clean):
            return clean, None
        return None, clean

    @classmethod
    def _extract_core_host(cls, target_str: str) -> str:
        """Extracts bare hostname or IP from target string or URL."""
        if not target_str:
            return ""
        s = target_str.strip()
        if "://" in s:
            try:
                parsed = urlparse(s)
                return parsed.hostname or parsed.netloc.split(":")[0]
            except Exception:
                pass
        # Handle host:port
        if ":" in s and not s.startswith("[") and s.count(":") == 1:
            return s.split(":")[0]
        # Handle host/path
        if "/" in s:
            return s.split("/")[0]
        return s

