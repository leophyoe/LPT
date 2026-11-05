"""Pure-Python Passive OSINT & Web Technology Profiling Adapter.

Provides zero-dependency passive reconnaissance:
1. Pure-Python DNS Wire Protocol Resolution & Reverse DNS Lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR).
2. Pure-Python RDAP Domain Registration & Subnet Attribution (RFC 7480-7484).
3. Certificate Transparency Subdomain Enumeration (via crt.sh JSON API).
4. Web Server & Technology Stack Profiling (Server, X-Powered-By, Session Cookies, CMS/WAF indicators).
5. Comprehensive Topology Asset & Relationship Ingestion (RESOLVES_TO, MX_RECORD_FOR, NS_FOR, ANNOUNCED_BY_ASN, SUBDOMAIN_OF).
6. Strict Scope Guard enforcement, AssetNode deduplication, and Observation preservation.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.scope import ScopeAuthorizationService
from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from modules.osint.dns_resolver import DNSSummary, PurePythonDNSResolver
from modules.osint.rdap_client import PurePythonRDAPClient, RDAPDomainResult, RDAPIPResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    TargetScope,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


def resolve_ip_asn(ip_str: str) -> Dict[str, str]:
    """Resolves BGP Autonomous System Number (ASN) and Organization via native DNS / Cymru."""
    asn_data: Dict[str, str] = {}
    try:
        parts = ip_str.strip().split(".")
        if len(parts) == 4 and not (
            ip_str.startswith("10.")
            or ip_str.startswith("192.168.")
            or ip_str.startswith("127.")
            or ip_str.startswith("172.")
        ):
            rev_ip = ".".join(reversed(parts))
            res = subprocess.run(
                ["host", "-t", "txt", f"{rev_ip}.origin.asn.cymru.com"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            if res.returncode == 0 and "descriptive text" in res.stdout:
                m = re.search(r'"([^"]+)"', res.stdout)
                if m:
                    fields = [f.strip() for f in m.group(1).split("|")]
                    if len(fields) >= 2:
                        asn_data["asn"] = f"AS{fields[0]}"
                        asn_data["bgp_prefix"] = fields[1]
    except Exception:
        pass
    return asn_data


class PassiveReconAdapter(BaseOSINTAdapter):
    """Pure-Python passive intelligence, DNS wire resolver, RDAP and technology fingerprinting adapter."""

    def __init__(self, db: Database):
        super().__init__(db)
        self.dns_resolver = PurePythonDNSResolver()
        self.rdap_client = PurePythonRDAPClient()

    @property
    def name(self) -> str:
        return "passive_recon"

    @property
    def display_name(self) -> str:
        return "Pure-Python Passive OSINT & Tech Profiler"

    @property
    def is_passive_capable(self) -> bool:
        return True

    @property
    def requires_api_key(self) -> bool:
        return False

    def is_available(self) -> bool:
        return True

    def check_availability(self) -> Tuple[bool, str]:
        """Passive recon uses pure Python standard libraries (socket, ssl, urllib, struct). Always available."""
        return True, "Pure-Python standard library engines active (DNS Wire Resolver & RDAP RFC 7480-7484)"

    def run_discovery(
        self,
        target_domain: str,
        project: Project,
        scopes: List[TargetScope],
        case_id: Optional[str] = None,
        timeout: float = 30.0,
        passive_only: bool = True,
        on_output: Optional[Callable[[str, str], None]] = None,
    ) -> OSINTDiscoveryResult:
        """Executes full passive reconnaissance against target_domain within approved scope."""
        self._is_cancelled = False
        start_time = time.time()
        result = OSINTDiscoveryResult(
            source_tool=self.name,
            target=target_domain,
            status="running",
        )

        def emit(msg: str, stream: str = "stdout"):
            if on_output:
                on_output(msg, stream)

        clean_target = target_domain.strip().lower()
        if clean_target.startswith("http://"):
            clean_target = clean_target[7:]
        elif clean_target.startswith("https://"):
            clean_target = clean_target[8:]
        clean_target = clean_target.split("/")[0].split(":")[0]

        # -------------------------------------------------------------
        # 1. Scope Boundary Enforcement
        # -------------------------------------------------------------
        scope_check = ScopeAuthorizationService.is_target_authorized(clean_target, scopes, project)
        if not scope_check.is_allowed:
            emit(f"[-] Target {clean_target} rejected by Scope Guard: {scope_check.reason}\n", "stderr")
            result.status = "scope_rejected"
            result.error_message = scope_check.reason
            return result

        emit(f"[*] Starting Pure-Python Passive Reconnaissance targeting: {clean_target}\n")

        # Create/upsert root domain/host node
        is_ip_target = False
        try:
            socket.inet_aton(clean_target)
            is_ip_target = True
        except socket.error:
            pass

        root_node_type = "ip" if is_ip_target else "domain"
        root_node = self.db.upsert_asset_node(
            AssetNode(
                project_id=project.id,
                node_type=root_node_type,
                value=clean_target,
                label=clean_target,
                source_tool=self.name,
                confidence=1.0,
                metadata_json=json.dumps({"target": clean_target, "case_id": case_id}),
            )
        )
        result.discovered_assets.append(root_node)

        discovered_ips: Set[str] = set()
        discovered_subdomains: Set[str] = set()
        discovered_mx: List[Dict[str, Any]] = []
        discovered_ns: Set[str] = set()
        tech_profile: Dict[str, Any] = {}
        dns_records_data: Dict[str, Any] = {}
        rdap_profile: Dict[str, Any] = {}

        # -------------------------------------------------------------
        # 2. Pure-Python DNS Wire Protocol Resolution (RFC 1035 / RFC 3596)
        # -------------------------------------------------------------
        emit("[+] Resolving DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR)...\n")
        try:
            dns_summary: DNSSummary = self.dns_resolver.resolve_all_records(
                clean_target, timeout=min(timeout, 5.0)
            )
            dns_records_data = dns_summary.to_dict()

            for ip_val in dns_summary.a:
                discovered_ips.add(ip_val)
                emit(f"    [DNS A] {ip_val}\n")

            for ip6_val in dns_summary.aaaa:
                discovered_ips.add(ip6_val)
                emit(f"    [DNS AAAA] {ip6_val}\n")

            for cname in dns_summary.cname:
                discovered_subdomains.add(cname.lower())
                emit(f"    [DNS CNAME] {cname}\n")

            for mx_entry in dns_summary.mx:
                discovered_mx.append(mx_entry)
                emit(f"    [DNS MX] {mx_entry.get('exchange')} (Priority: {mx_entry.get('preference')})\n")

            for ns_entry in dns_summary.ns:
                discovered_ns.add(ns_entry.lower())
                emit(f"    [DNS NS] {ns_entry}\n")

            for txt_val in dns_summary.txt:
                emit(f"    [DNS TXT] {txt_val[:80]}{'...' if len(txt_val) > 80 else ''}\n")

            if dns_summary.soa:
                soa_mname = dns_summary.soa.get("mname", "unknown")
                emit(f"    [DNS SOA] Primary NS: {soa_mname}\n")

            for ptr_val in dns_summary.ptr:
                emit(f"    [DNS PTR] {ptr_val}\n")

        except Exception as exc:
            emit(f"    [!] DNS wire resolution notice: {exc}\n", "system")

        # -------------------------------------------------------------
        # 3. Pure-Python RDAP Domain & Registration Metadata (RFC 7480-7484)
        # -------------------------------------------------------------
        if not is_ip_target:
            emit("[+] Querying Registration Data Access Protocol (RDAP) registry...\n")
            try:
                rdap_dom: RDAPDomainResult = self.rdap_client.lookup_domain(
                    clean_target, timeout=min(timeout, 6.0)
                )
                if rdap_dom.is_successful:
                    rdap_profile = rdap_dom.to_dict()
                    if rdap_dom.registrar:
                        emit(f"    [RDAP Registrar] {rdap_dom.registrar}\n")
                    if rdap_dom.created_date:
                        emit(f"    [RDAP Created] {rdap_dom.created_date}\n")
                    if rdap_dom.expiration_date:
                        emit(f"    [RDAP Expiration] {rdap_dom.expiration_date}\n")
                    if rdap_dom.status:
                        emit(f"    [RDAP Status] {', '.join(rdap_dom.status[:3])}\n")

                    for ns in rdap_dom.nameservers:
                        discovered_ns.add(ns.lower())

                    # Enrich root domain node metadata with RDAP data
                    try:
                        curr_meta = json.loads(root_node.metadata_json or "{}")
                    except Exception:
                        curr_meta = {}
                    curr_meta["rdap"] = {
                        "registrar": rdap_dom.registrar,
                        "created_date": rdap_dom.created_date,
                        "expiration_date": rdap_dom.expiration_date,
                        "status": rdap_dom.status,
                        "entities": rdap_dom.entities,
                    }
                    root_node.metadata_json = json.dumps(curr_meta)
                    self.db.upsert_asset_node(root_node)
            except Exception as exc:
                emit(f"    [!] RDAP domain lookup notice: {exc}\n", "system")

        # -------------------------------------------------------------
        # 4. Certificate Transparency Subdomain Enumeration (crt.sh)
        # -------------------------------------------------------------
        if not is_ip_target:
            emit("[+] Querying Certificate Transparency logs (crt.sh)...\n")
            ct_url = f"https://crt.sh/?q=%25.{urllib.parse.quote(clean_target)}&output=json"
            req = urllib.request.Request(
                ct_url,
                headers={"User-Agent": "Mozilla/5.0 (CyberSecuritySuite Passive Recon/1.0)"},
            )
            try:
                with urllib.request.urlopen(req, timeout=min(timeout, 15.0)) as resp:
                    if resp.status == 200:
                        raw_data = resp.read().decode("utf-8", errors="ignore")
                        entries = json.loads(raw_data)
                        for item in entries:
                            name_val = item.get("name_value", "")
                            for candidate in name_val.split("\n"):
                                cand = candidate.strip().lower()
                                if cand.startswith("*."):
                                    cand = cand[2:]
                                if cand and cand.endswith(clean_target) and cand != clean_target:
                                    discovered_subdomains.add(cand)
                        emit(f"    [*] Found {len(discovered_subdomains)} subdomains from CT logs.\n")
            except Exception as exc:
                emit(f"    [!] CT log query notice (offline/throttled): {exc}\n", "system")

        # -------------------------------------------------------------
        # 5. Web Server & Technology Stack Profiling (HTTP & HTTPS)
        # -------------------------------------------------------------
        emit("[+] Fingerprinting HTTP/HTTPS response headers and web technology stack...\n")
        schemes = ["https", "http"]
        for scheme in schemes:
            target_url = f"{scheme}://{clean_target}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                http_req = urllib.request.Request(
                    target_url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecuritySuite/1.0"},
                    method="HEAD",
                )
                with urllib.request.urlopen(http_req, timeout=5.0, context=ctx) as h_resp:
                    hdrs = {k.lower(): v for k, v in h_resp.headers.items()}
                    server = hdrs.get("server")
                    powered_by = hdrs.get("x-powered-by")
                    cookies = hdrs.get("set-cookie", "")

                    if server:
                        tech_profile["server"] = server
                        emit(f"    [Server Banner] {server}\n")
                    if powered_by:
                        tech_profile["powered_by"] = powered_by
                        emit(f"    [X-Powered-By] {powered_by}\n")

                    # Identify technologies by cookies and headers
                    detected_frameworks = []
                    if "phpsessid" in cookies.lower():
                        detected_frameworks.append("PHP")
                    if "jsessionid" in cookies.lower():
                        detected_frameworks.append("Java / JSP")
                    if "asp.net" in cookies.lower() or (powered_by and "aspnet" in powered_by.lower()):
                        detected_frameworks.append("Microsoft ASP.NET")
                    if "laravel" in cookies.lower():
                        detected_frameworks.append("Laravel (PHP)")
                    if "connect.sid" in cookies.lower():
                        detected_frameworks.append("Express / Node.js")

                    # WAF Detection
                    if "cf-ray" in hdrs:
                        tech_profile["waf"] = "Cloudflare CDN/WAF"
                        emit("    [WAF / CDN Detected] Cloudflare (cf-ray)\n")
                    elif "x-amz-cf-id" in hdrs:
                        tech_profile["waf"] = "AWS CloudFront CDN"
                        emit("    [WAF / CDN Detected] Amazon CloudFront\n")
                    elif "x-akamai-transformed" in hdrs:
                        tech_profile["waf"] = "Akamai CDN"
                        emit("    [WAF / CDN Detected] Akamai\n")

                    if detected_frameworks:
                        tech_profile["frameworks"] = list(set(detected_frameworks))
                        emit(f"    [Identified Frameworks] {', '.join(detected_frameworks)}\n")
                    break  # HTTPS succeeded, no need to probe HTTP
            except Exception:
                continue

        # -------------------------------------------------------------
        # 6. Ingest Discovered Subdomains into Asset Topology
        # -------------------------------------------------------------
        for sub in sorted(list(discovered_subdomains))[:50]:  # Cap at top 50 in passive run
            sub_check = ScopeAuthorizationService.is_target_authorized(sub, scopes, project)
            if sub_check.is_allowed:
                sub_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project.id,
                        node_type="subdomain",
                        value=sub,
                        label=sub,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata_json=json.dumps({"domain": clean_target}),
                    )
                )
                result.discovered_assets.append(sub_node)

                # Edge: subdomain -> root domain
                edge = self.db.upsert_asset_edge(
                    AssetEdge(
                        project_id=project.id,
                        source_node_id=sub_node.id,
                        target_node_id=root_node.id,
                        relation_type="SUBDOMAIN_OF",
                        source_tool=self.name,
                        verification_state="observed",
                        confidence=0.85,
                    )
                )
                result.relationships.append(edge)
            else:
                result.quarantined_assets.append({"target": sub, "reason": sub_check.reason})

        # -------------------------------------------------------------
        # 7. Ingest Nameservers (NS) into Asset Topology
        # -------------------------------------------------------------
        for ns_val in sorted(list(discovered_ns)):
            ns_check = ScopeAuthorizationService.is_target_authorized(ns_val, scopes, project)
            if ns_check.is_allowed:
                ns_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project.id,
                        node_type="nameserver",
                        value=ns_val,
                        label=f"NS: {ns_val}",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata_json=json.dumps({"domain": clean_target}),
                    )
                )
                result.discovered_assets.append(ns_node)

                edge = self.db.upsert_asset_edge(
                    AssetEdge(
                        project_id=project.id,
                        source_node_id=ns_node.id,
                        target_node_id=root_node.id,
                        relation_type="NS_FOR",
                        source_tool=self.name,
                        verification_state="observed",
                        confidence=0.9,
                    )
                )
                result.relationships.append(edge)
            else:
                result.quarantined_assets.append({"target": ns_val, "reason": ns_check.reason})

        # -------------------------------------------------------------
        # 8. Ingest Mail Exchanges (MX) into Asset Topology
        # -------------------------------------------------------------
        for mx_item in discovered_mx:
            mx_exchange = mx_item.get("exchange", "")
            if not mx_exchange:
                continue
            mx_check = ScopeAuthorizationService.is_target_authorized(mx_exchange, scopes, project)
            if mx_check.is_allowed:
                mx_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project.id,
                        node_type="mail_exchange",
                        value=mx_exchange,
                        label=f"MX: {mx_exchange}",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata_json=json.dumps({"priority": mx_item.get("preference", 10), "domain": clean_target}),
                    )
                )
                result.discovered_assets.append(mx_node)

                edge = self.db.upsert_asset_edge(
                    AssetEdge(
                        project_id=project.id,
                        source_node_id=mx_node.id,
                        target_node_id=root_node.id,
                        relation_type="MX_RECORD_FOR",
                        source_tool=self.name,
                        verification_state="observed",
                        confidence=0.9,
                    )
                )
                result.relationships.append(edge)
            else:
                result.quarantined_assets.append({"target": mx_exchange, "reason": mx_check.reason})

        # -------------------------------------------------------------
        # 9. Ingest Discovered IPs & RDAP Subnet / ASN BGP Attribution
        # -------------------------------------------------------------
        for ip_val in sorted(list(discovered_ips)):
            ip_check = ScopeAuthorizationService.is_target_authorized(ip_val, scopes, project)
            if ip_check.is_allowed:
                # Query RDAP for IP allocation / BGP network
                rdap_ip: Optional[RDAPIPResult] = None
                try:
                    rdap_ip = self.rdap_client.lookup_ip(ip_val, timeout=min(timeout, 5.0))
                except Exception:
                    pass

                asn_info = resolve_ip_asn(ip_val)
                ip_meta: Dict[str, Any] = {"tech_profile": tech_profile}

                net_cidr = rdap_ip.cidr if rdap_ip and rdap_ip.cidr else ""
                net_org = rdap_ip.organization if rdap_ip and rdap_ip.organization else ""
                net_country = rdap_ip.country if rdap_ip and rdap_ip.country else ""
                asn_str = (rdap_ip.asn if rdap_ip and rdap_ip.asn else "") or asn_info.get("asn", "")

                if net_cidr:
                    ip_meta["netblock"] = net_cidr
                if net_org:
                    ip_meta["organization"] = net_org
                if net_country:
                    ip_meta["country"] = net_country
                if asn_str:
                    ip_meta["asn"] = asn_str
                if asn_info.get("bgp_prefix"):
                    ip_meta["bgp_prefix"] = asn_info["bgp_prefix"]

                ip_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project.id,
                        node_type="ip",
                        value=ip_val,
                        label=ip_val,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata_json=json.dumps(ip_meta),
                    )
                )
                result.discovered_assets.append(ip_node)

                edge = self.db.upsert_asset_edge(
                    AssetEdge(
                        project_id=project.id,
                        source_node_id=root_node.id,
                        target_node_id=ip_node.id,
                        relation_type="RESOLVES_TO",
                        source_tool=self.name,
                        verification_state="observed",
                        confidence=0.9,
                    )
                )
                result.relationships.append(edge)

                # If ASN is identified, upsert ASN node and ANNOUNCED_BY_ASN edge
                if asn_str:
                    asn_label = f"{asn_str}"
                    if net_org:
                        asn_label += f" ({net_org})"
                    asn_node = self.db.upsert_asset_node(
                        AssetNode(
                            project_id=project.id,
                            node_type="asn",
                            value=asn_str,
                            label=asn_label,
                            source_tool=self.name,
                            confidence=0.95,
                            metadata_json=json.dumps({
                                "asn": asn_str,
                                "organization": net_org,
                                "country": net_country,
                                "cidr": net_cidr,
                            }),
                        )
                    )
                    result.discovered_assets.append(asn_node)

                    asn_edge = self.db.upsert_asset_edge(
                        AssetEdge(
                            project_id=project.id,
                            source_node_id=ip_node.id,
                            target_node_id=asn_node.id,
                            relation_type="ANNOUNCED_BY_ASN",
                            source_tool=self.name,
                            verification_state="observed",
                            confidence=0.95,
                        )
                    )
                    result.relationships.append(asn_edge)

            else:
                result.quarantined_assets.append({"target": ip_val, "reason": ip_check.reason})

        # -------------------------------------------------------------
        # 10. Record Consolidated Recon Observation Record
        # -------------------------------------------------------------
        summary_payload = {
            "target": clean_target,
            "resolved_ips": list(discovered_ips),
            "subdomain_count": len(discovered_subdomains),
            "nameservers": list(discovered_ns),
            "mail_exchangers": discovered_mx,
            "dns_summary": dns_records_data,
            "rdap_summary": rdap_profile,
            "technology_profile": tech_profile,
            "timestamp": _utc_now_iso(),
        }
        obs = self.db.create_observation(
            Observation(
                project_id=project.id,
                case_id=case_id,
                asset_id=root_node.id,
                title=f"Passive Recon & Tech Profile for {clean_target}",
                source_tool=self.name,
                method="passive_recon",
                raw_data=json.dumps(summary_payload, indent=2),
                confidence=0.9,
                verification_status="observed",
            )
        )
        result.observations.append(obs)

        duration = time.time() - start_time
        result.duration_seconds = duration
        result.status = "completed"
        emit(f"[✓] Passive Reconnaissance completed in {duration:.2f}s ({len(result.discovered_assets)} assets, {len(result.relationships)} edges recorded).\n")
        return result
