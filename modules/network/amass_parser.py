"""OWASP Amass Output Parser & Asset Relationship Normalizer.

Parses Amass JSON-lines and standard text enumeration streams into normalized
asset records, performs scope quarantine for out-of-scope discoveries, and maps
discoveries into graph entities (Domains, Subdomains, IPs, ASNs).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.scope import ScopeAuthorizationService
from storage.models import (
    AssetEdge,
    AssetNode,
    Finding,
    FindingSeverity,
    TargetScope,
    ValidationStatus,
)


@dataclass
class AmassAddress:
    ip: str
    cidr: str = ""
    asn: int = 0
    desc: str = ""


@dataclass
class AmassRecord:
    name: str
    domain: str = ""
    addresses: List[AmassAddress] = field(default_factory=list)
    tag: str = ""
    sources: List[str] = field(default_factory=list)
    is_in_scope: bool = True
    quarantine_reason: str = ""


@dataclass
class AmassResult:
    records: List[AmassRecord] = field(default_factory=list)
    quarantined: List[AmassRecord] = field(default_factory=list)
    target_domains: List[str] = field(default_factory=list)


class AmassParser:
    """Parses OWASP Amass OSINT reconnaissance outputs."""

    @classmethod
    def parse_json_lines(
        cls,
        text_content: str,
        scopes: Optional[List[TargetScope]] = None,
    ) -> AmassResult:
        """Parses Amass JSON output stream (one JSON object per line)."""
        result = AmassResult()
        domains_seen = set()

        for line in text_content.splitlines():
            line_str = line.strip()
            if not line_str or not line_str.startswith("{"):
                continue

            try:
                data = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            name = data.get("name", "").strip()
            domain = data.get("domain", "").strip()
            if not name:
                continue

            if domain:
                domains_seen.add(domain)

            addrs: List[AmassAddress] = []
            for a in data.get("addresses", []):
                ip_str = a.get("ip", "")
                if ip_str:
                    addrs.append(
                        AmassAddress(
                            ip=ip_str,
                            cidr=a.get("cidr", ""),
                            asn=int(a.get("asn", 0) or 0),
                            desc=a.get("desc", ""),
                        )
                    )

            rec = AmassRecord(
                name=name,
                domain=domain,
                addresses=addrs,
                tag=data.get("tag", "dns"),
                sources=data.get("sources", []),
            )

            # Scope Validation & Quarantine Check
            if scopes is not None:
                scope_check = ScopeAuthorizationService.is_target_authorized(name, scopes)
                if not scope_check.is_allowed:
                    rec.is_in_scope = False
                    rec.quarantine_reason = scope_check.reason
                    result.quarantined.append(rec)
                    continue

            result.records.append(rec)

        result.target_domains = sorted(list(domains_seen))
        return result

    @classmethod
    def parse_text(
        cls,
        text_content: str,
        scopes: Optional[List[TargetScope]] = None,
    ) -> AmassResult:
        """Parses plain-text Amass enumeration output lines."""
        result = AmassResult()
        domains_seen = set()

        for line in text_content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("OWASP") or clean.startswith("Starting"):
                continue

            # Strip ANSI color codes
            clean = re.sub(r"\x1b\[[0-9;]*m", "", clean)

            # Pattern: [TAG] hostname IP
            m = re.match(r"(?:\[([A-Za-z0-9_-]+)\]\s+)?([a-zA-Z0-9.\-_]+)(?:\s+([0-9a-fA-F:.]+))?", clean)
            if not m:
                continue

            tag, name, ip_val = m.groups()
            if not name or "." not in name:
                continue

            parts = name.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else name
            domains_seen.add(domain)

            addrs = [AmassAddress(ip=ip_val)] if ip_val else []
            rec = AmassRecord(
                name=name,
                domain=domain,
                addresses=addrs,
                tag=tag or "dns",
                sources=["amass_cli"],
            )

            if scopes is not None:
                scope_check = ScopeAuthorizationService.is_target_authorized(name, scopes)
                if not scope_check.is_allowed:
                    rec.is_in_scope = False
                    rec.quarantine_reason = scope_check.reason
                    result.quarantined.append(rec)
                    continue

            result.records.append(rec)

        result.target_domains = sorted(list(domains_seen))
        return result

    @staticmethod
    def to_findings(
        result: AmassResult,
        project_id: int,
        execution_id: Optional[int] = None,
    ) -> List[Finding]:
        """Converts in-scope discovered assets into findings for assessment reports."""
        findings: List[Finding] = []

        # 1. Summary finding for discovered subdomains
        if result.records:
            subdomain_list = sorted(list({r.name for r in result.records}))
            preview = "\n".join(f"- {sub}" for sub in subdomain_list[:25])
            if len(subdomain_list) > 25:
                preview += f"\n... and {len(subdomain_list) - 25} more subdomains."

            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"OWASP Amass: Discovered {len(subdomain_list)} In-Scope Subdomains",
                    description=(
                        f"Automated OSINT and DNS enumeration mapped {len(subdomain_list)} subdomains "
                        f"across target domains ({', '.join(result.target_domains)}).\n\n"
                        f"Discovered Assets Preview:\n{preview}"
                    ),
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=", ".join(result.target_domains) or "Target Domain",
                    remediation="Maintain an up-to-date attack surface asset inventory and decommission unused subdomains.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="amass",
                )
            )

        # 2. Informational finding for quarantined (out-of-scope) discoveries
        if result.quarantined:
            quarantined_names = sorted(list({r.name for r in result.quarantined}))
            preview = "\n".join(f"- {name}" for name in quarantined_names[:15])
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"Scope Quarantine: {len(quarantined_names)} Out-of-Scope Assets Filtered",
                    description=(
                        f"Amass identified {len(quarantined_names)} related hostnames that are outside authorized scope "
                        f"or explicitly excluded. These targets are quarantined and prohibited from active probing.\n\n"
                        f"Quarantined Targets:\n{preview}"
                    ),
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset="Scope Boundary Guard",
                    remediation="Confirm scope authorization with the client before expanding testing boundaries.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="amass",
                )
            )

        return findings

    @staticmethod
    def to_asset_graph(
        result: AmassResult,
        project_id: int,
    ) -> Tuple[List[AssetNode], List[AssetEdge]]:
        """Converts Amass discovery topology into Maltego-compatible graph nodes and edges."""
        nodes: List[AssetNode] = []
        edges: List[AssetEdge] = []
        node_id_map: Dict[Tuple[str, str], int] = {}  # (type, value) -> temp index

        def _get_or_create_node(node_type: str, value: str, label: str = "") -> int:
            key = (node_type, value)
            if key in node_id_map:
                return node_id_map[key]
            idx = len(nodes)
            node = AssetNode(
                project_id=project_id,
                node_type=node_type,
                value=value,
                label=label or value,
                source_tool="amass",
                confidence=1.0,
            )
            nodes.append(node)
            node_id_map[key] = idx
            return idx

        # Process each discovered record
        for rec in result.records:
            # 1. Domain Node
            if rec.domain:
                dom_idx = _get_or_create_node("domain", rec.domain, rec.domain)
            else:
                dom_idx = None

            # 2. Subdomain Node
            sub_idx = _get_or_create_node("subdomain", rec.name, rec.name)
            if dom_idx is not None and dom_idx != sub_idx:
                edges.append(
                    AssetEdge(
                        project_id=project_id,
                        source_node_id=sub_idx,
                        target_node_id=dom_idx,
                        relation_type="SUBDOMAIN_OF",
                        source_tool="amass",
                    )
                )

            # 3. IP Addresses & ASNs
            for addr in rec.addresses:
                if addr.ip:
                    ip_idx = _get_or_create_node("ip", addr.ip, addr.ip)
                    edges.append(
                        AssetEdge(
                            project_id=project_id,
                            source_node_id=sub_idx,
                            target_node_id=ip_idx,
                            relation_type="RESOLVES_TO",
                            source_tool="amass",
                        )
                    )

                    if addr.asn:
                        asn_label = f"AS{addr.asn} ({addr.desc or 'ASN'})"
                        asn_idx = _get_or_create_node("asn", str(addr.asn), asn_label)
                        edges.append(
                            AssetEdge(
                                project_id=project_id,
                                source_node_id=ip_idx,
                                target_node_id=asn_idx,
                                relation_type="BELONGS_TO_ASN",
                                source_tool="amass",
                            )
                        )

        return nodes, edges

