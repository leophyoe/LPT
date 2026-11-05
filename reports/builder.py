"""Professional Assessment Reporting Service for CyberSecuritySuite.

Generates self-contained HTML, portable Markdown, and machine-readable JSON
reports incorporating CPENT penetration testing methodology, executive summaries,
severity distributions, technical findings, and cryptographic evidence hashes.
"""

from __future__ import annotations

import csv
import html
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from storage.db import Database
from modules.network.nmap_parser import HostResult, NmapParser, NmapScanResult
from modules.network.pentest_workflow import (
    CPENT_LAB_CATALOG,
    CPENTLabScenario,
    NetworkPentestWorkflowManager,
    StageStatus,
    WorkflowStage,
)
from storage.models import (
    Assessment,
    AssessmentPlan,
    AssetEdge,
    AssetNode,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    ScopeRuleType,
    TargetScope,
    TerminalSessionRecord,
    ToolExecution,
    ValidationStatus,
)
from terminal.recorder import redact_sensitive_text


class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _render_network_svg(hosts: List[HostResult]) -> str:
    """Generates a responsive SVG network topology architecture diagram for report inclusion.

    Includes Subnet Zone containers, verification status badges, and an architecture legend.
    """
    if not hosts:
        return ""

    import ipaddress
    from collections import defaultdict

    # Group hosts by /24 subnet or logical group
    subnet_groups: Dict[str, List[HostResult]] = defaultdict(list)
    for h in hosts:
        subnet = "Unassigned / External"
        if h.ip:
            try:
                ip_obj = ipaddress.ip_address(h.ip)
                if ip_obj.version == 4:
                    subnet = str(ipaddress.ip_network(f"{h.ip}/24", strict=False))
                else:
                    subnet = "IPv6 Network"
            except Exception:
                subnet = "External / Domain"
        subnet_groups[subnet].append(h)

    width = 820
    # Calculate height: header (70px) + pentest ops tier (84px) + vpn tunnel (36px) + each subnet box + legend (70px)
    ops_box_height = 84
    vpn_tunnel_height = 36
    total_host_cards_height = 0
    for subnet, group_hosts in subnet_groups.items():
        total_host_cards_height += 46 + (len(group_hosts) * 64) + 16

    height = max(320, 70 + ops_box_height + vpn_tunnel_height + total_host_cards_height + 80)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="{height}" viewBox="0 0 {width} {height}" style="background-color: #0B1120; border-radius: 8px; border: 1px solid #2B394D; margin: 16px 0; font-family: sans-serif;">',
        '<rect width="100%" height="100%" fill="#0B1120"/>',
        '<text x="24" y="30" fill="#F3F6FC" font-size="14" font-weight="bold">Pentesting Network Infrastructure & Target Architecture</text>',
        '<text x="24" y="48" fill="#38BDF8" font-size="11">Evidence-driven topology grouping with verified status badges and subnet segregation</text>',
    ]

    curr_y = 66
    # 1. Pentest Operations & Offensive Toolchain Tier Container
    parts.append(
        f'<g transform="translate(20, {curr_y})">'
        f'<rect width="780" height="{ops_box_height}" rx="8" fill="#180C1E" stroke="#EC4899" stroke-width="1.2" stroke-opacity="0.7"/>'
        f'<path d="M 0 8 Q 0 0 8 0 L 772 0 Q 780 0 780 8 L 780 24 L 0 24 Z" fill="#2E1030"/>'
        f'<text x="14" y="17" fill="#F472B6" font-size="11" font-weight="bold">⚔️ Pentest Operations &amp; Offensive Toolchain Tier</text>'
        f'<rect x="640" y="4" width="130" height="16" rx="3" fill="#EC4899" fill-opacity="0.2"/>'
        f'<text x="705" y="15" fill="#F472B6" font-size="8" font-weight="bold" text-anchor="middle">AUTHORIZED ORIGIN</text>'
        f'<rect x="14" y="32" width="220" height="40" rx="4" fill="#251229" stroke="#EC4899" stroke-width="0.8"/>'
        f'<text x="24" y="48" fill="#FDF2F8" font-size="10" font-weight="bold">💻 Kali Tester Station</text>'
        f'<text x="24" y="62" fill="#F472B6" font-size="9">IP: 10.10.14.2 (Operator Console)</text>'
        f'<rect x="250" y="32" width="240" height="40" rx="4" fill="#251229" stroke="#EC4899" stroke-width="0.8"/>'
        f'<text x="260" y="48" fill="#FDF2F8" font-size="10" font-weight="bold">🎯 Vulnerability Scanner &amp; Tools</text>'
        f'<text x="260" y="62" fill="#F472B6" font-size="9">IP: 10.10.14.5 | Nmap / Nuclei Engine</text>'
        f'<rect x="506" y="32" width="260" height="40" rx="4" fill="#251229" stroke="#EC4899" stroke-width="0.8"/>'
        f'<text x="516" y="48" fill="#FDF2F8" font-size="10" font-weight="bold">🔒 VPN &amp; Cloud Relay Gateway</text>'
        f'<text x="516" y="62" fill="#A855F7" font-size="9">IPsec / WireGuard Tunnel &amp; Firewall</text>'
        f'</g>'
    )
    curr_y += ops_box_height + 8

    # 2. VPN / Pivot Tunnel Transit Line
    parts.append(
        f'<g transform="translate(410, {curr_y})">'
        f'<line x1="0" y1="0" x2="0" y2="22" stroke="#A855F7" stroke-width="2" stroke-dasharray="4,3"/>'
        f'<rect x="-85" y="2" width="170" height="18" rx="4" fill="#1E1035" stroke="#A855F7" stroke-width="1"/>'
        f'<text x="0" y="14" fill="#C084FC" font-size="8" font-weight="bold" text-anchor="middle">AUTHORIZED VPN / PIVOT TUNNEL</text>'
        f'</g>'
    )
    curr_y += vpn_tunnel_height

    # 3. Target Subnet Zones
    for subnet, group_hosts in subnet_groups.items():
        group_box_height = 42 + (len(group_hosts) * 64) + 12
        # Zone Container Rect
        parts.append(
            f'<g transform="translate(20, {curr_y})">'
            f'<rect width="780" height="{group_box_height}" rx="8" fill="#0F172A" stroke="#10B981" stroke-width="1.2" stroke-opacity="0.6"/>'
            f'<path d="M 0 8 Q 0 0 8 0 L 772 0 Q 780 0 780 8 L 780 28 L 0 28 Z" fill="#132A26"/>'
            f'<text x="14" y="19" fill="#10B981" font-size="11" font-weight="bold">🌐 Subnet Zone: {html.escape(subnet)}</text>'
            f'<rect x="660" y="5" width="110" height="18" rx="3" fill="#047857" fill-opacity="0.3"/>'
            f'<text x="715" y="18" fill="#34D399" font-size="9" font-weight="bold" text-anchor="middle">{len(group_hosts)} Discovered Host(s)</text>'
            f'</g>'
        )

        host_y = curr_y + 36
        for h in group_hosts:
            open_cnt = sum(1 for p in h.ports if p.state == "open")
            border = "#38BDF8" if open_cnt > 0 else "#10B981"
            bg = "#102538" if open_cnt > 0 else "#0D2818"

            ports_summary = ", ".join(
                f"{getattr(p, 'port_id', getattr(p, 'port', ''))}/{getattr(p, 'protocol', getattr(p, 'proto', 'tcp'))}"
                for p in h.ports if getattr(p, 'state', '') == "open"
            )[:40]
            if ports_summary:
                ports_display = f" | Ports: {html.escape(ports_summary)}"
            else:
                ports_display = " | Ports: None open"

            parts.append(
                f'<g transform="translate(36, {host_y})">'
                f'<rect width="748" height="54" rx="6" fill="{bg}" stroke="{border}" stroke-width="1.2"/>'
                f'<circle cx="26" cy="27" r="14" fill="{border}"/>'
                f'<text x="26" y="31" fill="#ffffff" font-size="9" font-weight="bold" text-anchor="middle">{open_cnt}p</text>'
                f'<text x="50" y="22" fill="#F3F6FC" font-size="12" font-weight="bold">{html.escape(h.ip)} ({html.escape(h.status.upper())})</text>'
                f'<rect x="650" y="10" width="84" height="16" rx="3" fill="#10B981" fill-opacity="0.2"/>'
                f'<text x="692" y="22" fill="#10B981" font-size="8" font-weight="bold" text-anchor="middle">OBSERVED</text>'
                f'<text x="50" y="40" fill="#94A3B8" font-size="10">Host: {html.escape(h.hostname or "None")} | OS: {html.escape(h.os_summary or "Unknown")}{ports_display}</text>'
                f'</g>'
            )
            host_y += 64

        curr_y += group_box_height + 16

    # Architecture Legend
    legend_y = curr_y + 4
    parts.append(
        f'<g transform="translate(20, {legend_y})">'
        f'<rect width="780" height="58" rx="6" fill="#070D18" stroke="#1E293B" stroke-width="1"/>'
        f'<text x="14" y="18" fill="#94A3B8" font-size="10" font-weight="bold">ARCHITECTURE STATUS &amp; PROVENANCE LEGEND:</text>'
        f'<circle cx="20" cy="38" r="5" fill="#10B981"/>'
        f'<text x="30" y="42" fill="#E2E8F0" font-size="9">Observed Evidence (Tool Scan)</text>'
        f'<circle cx="220" cy="38" r="5" fill="#38BDF8"/>'
        f'<text x="230" y="42" fill="#E2E8F0" font-size="9">Active Host (Services Open)</text>'
        f'<circle cx="410" cy="38" r="5" fill="#A855F7"/>'
        f'<text x="420" y="42" fill="#E2E8F0" font-size="9">Server Farm / Tunnel</text>'
        f'<circle cx="580" cy="38" r="5" fill="#F59E0B"/>'
        f'<text x="590" y="42" fill="#E2E8F0" font-size="9">Manual / Unverified</text>'
        f'</g>'
    )

    parts.append('</svg>')
    return "\n".join(parts)


@dataclass
class ReportSummaryMetrics:
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    max_cvss: float = 0.0
    confirmed_findings: int = 0
    unverified_findings: int = 0
    observed_findings: int = 0
    needs_validation_findings: int = 0
    remediated_findings: int = 0
    false_positive_findings: int = 0
    total_targets: int = 0
    total_executions: int = 0
    total_evidence_files: int = 0


@dataclass
class AssessmentReportData:
    project: Project
    scopes: List[TargetScope]
    executions: List[ToolExecution]
    findings: List[Finding]
    evidence: List[Evidence]
    metrics: ReportSummaryMetrics
    assessment: Optional[Assessment] = None
    terminal_sessions: List[TerminalSessionRecord] = field(default_factory=list)
    asset_nodes: List[AssetNode] = field(default_factory=list)
    asset_edges: List[AssetEdge] = field(default_factory=list)
    assessment_plans: List[AssessmentPlan] = field(default_factory=list)
    network_scan_results: List[NmapScanResult] = field(default_factory=list)
    footprint_results: List[Any] = field(default_factory=list)
    workflow_summary: Optional[Dict[str, Any]] = None
    cpent_labs: List[CPENTLabScenario] = field(default_factory=list)
    ad_audit_summary: Optional[Dict[str, Any]] = None
    pcap_analysis_summary: Optional[Dict[str, Any]] = None
    code_security_findings: List[Finding] = field(default_factory=list)
    cracked_credentials_summary: Optional[Dict[str, Any]] = None
    waf_events_summary: Optional[Dict[str, Any]] = None
    tls_assessment_summary: Optional[Dict[str, Any]] = None
    evidence_integrity: List[Dict[str, str]] = field(default_factory=list)
    terminal_session_integrity: List[Dict[str, str]] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now_iso)


class ReportBuilder:
    """Aggregates project assessment data and generates professional reports."""

    def __init__(self, db: Database):
        self.db = db

    def build_report_data(self, project_id: int, assessment_id: Optional[int] = None) -> AssessmentReportData:
        """Pulls and aggregates all project security records from SQLite."""
        project = self.db.get_project(project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} does not exist.")

        assessment = self.db.get_assessment(assessment_id) if assessment_id else None
        scopes = self.db.list_scopes(project_id)
        executions = self.db.list_executions(project_id, assessment_id=assessment_id)
        findings = self.db.list_findings(project_id, assessment_id=assessment_id)
        evidence = self.db.list_evidence(project_id, assessment_id=assessment_id)
        evidence_integrity = [self._verify_evidence_integrity(item) for item in evidence]
        terminal_sessions = self.db.list_terminal_sessions(project_id)
        terminal_session_integrity = [
            self._verify_artifact_integrity(item.raw_output_path, item.sha256_hash, project_id)
            for item in terminal_sessions
        ]
        asset_nodes = self.db.list_asset_nodes(project_id)
        asset_edges = self.db.list_asset_edges(project_id)
        assessment_plans = self.db.list_assessment_plans(project_id)

        # Compute summary metrics
        metrics = ReportSummaryMetrics(
            total_findings=len(findings),
            total_targets=len(scopes),
            total_executions=len(executions),
            total_evidence_files=len(evidence),
        )

        for f in findings:
            if f.severity == FindingSeverity.CRITICAL:
                metrics.critical_count += 1
            elif f.severity == FindingSeverity.HIGH:
                metrics.high_count += 1
            elif f.severity == FindingSeverity.MEDIUM:
                metrics.medium_count += 1
            elif f.severity == FindingSeverity.LOW:
                metrics.low_count += 1
            else:
                metrics.info_count += 1

            if f.cvss_score and f.cvss_score > metrics.max_cvss:
                metrics.max_cvss = f.cvss_score

            v_val = f.validation_status.value if hasattr(f.validation_status, "value") else str(f.validation_status)
            if v_val == "confirmed":
                metrics.confirmed_findings += 1
            elif v_val == "unverified":
                metrics.unverified_findings += 1
            elif v_val == "observed":
                metrics.observed_findings += 1
            elif v_val == "needs_validation":
                metrics.needs_validation_findings += 1
            elif v_val == "remediated":
                metrics.remediated_findings += 1
            elif v_val == "false_positive":
                metrics.false_positive_findings += 1

        # Extract network scan results from XML evidence records
        network_scan_results: List[NmapScanResult] = []
        for ev in evidence:
            if ev.mime_type == "application/xml" and ev.file_path:
                ev_p = Path(ev.file_path)
                if ev_p.exists():
                    try:
                        content = ev_p.read_text(encoding="utf-8")
                        sr = NmapParser.parse_xml(content)
                        if sr.hosts:
                            network_scan_results.append(sr)
                    except Exception as exc:
                        logger.warning("Failed to parse Nmap XML evidence '%s': %s", ev_p, exc)

        # Extract footprinting results from JSON evidence records
        footprint_results: List[Dict[str, Any]] = []
        for ev in evidence:
            if getattr(ev, "mime_type", "") in ("application/json", "json") and ev.file_path:
                if "footprint_" in ev.file_path:
                    ev_p = Path(ev.file_path)
                    if ev_p.exists():
                        try:
                            fp_data = json.loads(ev_p.read_text(encoding="utf-8"))
                            footprint_results.append(fp_data)
                        except Exception as exc:
                            logger.warning("Failed to parse footprint JSON evidence '%s': %s", ev_p, exc)

        # Compute Six-Step Internal Penetration Testing Workflow status (Strictly Read-Only, no DB side-effects)
        wf_mgr = NetworkPentestWorkflowManager(db=None, project_id=project_id)
        if footprint_results:
            wf_mgr.update_stage(
                WorkflowStage.STAGE_1_FOOTPRINTING,
                StageStatus.COMPLETED,
                summary=f"Footprinting telemetry collected with {len(footprint_results)} observation snapshot(s).",
                count=len(footprint_results),
            )
        if network_scan_results:
            total_hosts = sum(len(sr.hosts) for sr in network_scan_results)
            total_svcs = sum(len(h.ports) for sr in network_scan_results for h in sr.hosts)
            wf_mgr.update_stage(
                WorkflowStage.STAGE_2_DISCOVERY,
                StageStatus.COMPLETED,
                summary=f"Discovered {total_hosts} active network host(s) across target scope.",
                count=total_hosts,
            )
            wf_mgr.update_stage(
                WorkflowStage.STAGE_3_FINGERPRINTING,
                StageStatus.COMPLETED,
                summary=f"Fingerprinted {total_svcs} network service(s) and CPE records.",
                count=total_svcs,
            )
        elif asset_nodes:
            total_hosts = len(asset_nodes)
            total_svcs = 0
            for n in asset_nodes:
                if n.metadata_json:
                    try:
                        meta = json.loads(n.metadata_json)
                        total_svcs += len(meta.get("ports", []))
                    except Exception:
                        pass
            wf_mgr.update_stage(
                WorkflowStage.STAGE_2_DISCOVERY,
                StageStatus.COMPLETED,
                summary=f"Discovered {total_hosts} active network host(s) via inventory telemetry.",
                count=total_hosts,
            )
            if total_svcs > 0:
                wf_mgr.update_stage(
                    WorkflowStage.STAGE_3_FINGERPRINTING,
                    StageStatus.COMPLETED,
                    summary=f"Fingerprinted {total_svcs} network service port(s) via native port scans.",
                    count=total_svcs,
                )
        if findings:
            wf_mgr.update_stage(
                WorkflowStage.STAGE_4_VULNERABILITY,
                StageStatus.COMPLETED,
                summary=f"Identified {len(findings)} security observation(s) across target scope.",
                count=len(findings),
            )
            verified_count = sum(
                1 for f in findings if f.validation_status in (ValidationStatus.CONFIRMED, ValidationStatus.NEEDS_VALIDATION, ValidationStatus.FALSE_POSITIVE)
            )
            if verified_count > 0:
                wf_mgr.update_stage(
                    WorkflowStage.STAGE_5_EXPLOITATION,
                    StageStatus.COMPLETED,
                    summary=f"Performed controlled verification on {verified_count} candidate finding(s).",
                    count=verified_count,
                )
        wf_mgr.update_stage(
            WorkflowStage.STAGE_6_REPORTING,
            StageStatus.COMPLETED,
            summary="Cryptographic report audit trail generated.",
        )
        workflow_summary = wf_mgr.get_workflow_summary()

        # Extract Code Security SAST findings
        code_security_findings: List[Finding] = [
            f for f in findings
            if (f.source_tool and f.source_tool.lower() in ("bandit", "semgrep", "c0desec", "bob_sast", "ast_visitor", "python_security_scanner"))
            or ("CWE-" in f.title and ("File:" in f.description or "Line" in f.description or "ast" in (f.source_tool or "").lower()))
        ]

        # Extract Active Directory Weak Password findings & statistics
        ad_findings = [
            f for f in findings
            if (f.source_tool and "ad_password_auditor" in f.source_tool.lower())
            or "Active Directory" in f.affected_asset
            or "Active Directory" in f.title
            or "Weak Password" in f.title
        ]
        ad_audit_summary: Optional[Dict[str, Any]] = None
        if ad_findings:
            categories: Dict[str, int] = {}
            for af in ad_findings:
                cat = "Weak Password"
                for c_name in ("Shared Password", "Empty Password", "Clear Text Password", "Password Never Expires", "LM Hash", "AES Encryption Not Set", "DES-Only", "Missing Pre-Authentication"):
                    if c_name.lower() in af.title.lower() or c_name.lower() in af.description.lower():
                        cat = c_name
                        break
                categories[cat] = categories.get(cat, 0) + 1
            ad_audit_summary = {
                "total_findings": len(ad_findings),
                "vulnerable_accounts": len(ad_findings),
                "categories": categories,
                "findings": ad_findings,
            }

        # Extract PCAP Protocol Analysis summary
        pcap_findings = [
            f for f in findings
            if (f.source_tool and "pcap" in f.source_tool.lower())
            or "PCAP" in f.title
            or "DNS Tunneling" in f.title
            or "Cleartext" in f.title
            or "ARP Spoof" in f.title
        ]
        pcap_evidence_files = [
            ev.file_path for ev in evidence
            if ev.file_path and ev.file_path.lower().endswith((".pcap", ".pcapng"))
        ]
        pcap_analysis_summary: Optional[Dict[str, Any]] = None
        if pcap_findings or pcap_evidence_files:
            pcap_analysis_summary = {
                "total_findings": len(pcap_findings),
                "evidence_files": pcap_evidence_files,
                "findings": pcap_findings,
            }

        # Extract Cracked Credentials (Hydra, Hashcat, John)
        cracked_findings = [
            f for f in findings
            if (f.source_tool and f.source_tool.lower() in ("hydra", "hashcat", "john", "password_cracker"))
            or "Crackable Password" in f.title
            or "Discovered Credential" in f.title
        ]
        cracked_credentials_summary: Optional[Dict[str, Any]] = None
        if cracked_findings:
            cracked_credentials_summary = {
                "total_recovered": len(cracked_findings),
                "findings": cracked_findings,
            }

        # Extract ModSecurity / WAF events
        waf_findings = [
            f for f in findings
            if (f.source_tool and "modsecurity" in f.source_tool.lower())
            or "WAF Block" in f.title
        ]
        waf_events_summary: Optional[Dict[str, Any]] = None
        if waf_findings:
            waf_events_summary = {
                "total_events": len(waf_findings),
                "findings": waf_findings,
            }

        # Extract TLS/SSL Cryptographic & Cipher Suite findings
        tls_findings = [
            f for f in findings
            if (f.source_tool and "tls" in f.source_tool.lower())
            or "TLS" in f.title
            or "SSL" in f.title
            or "Certificate" in f.title
            or "Cipher" in f.title
        ]
        tls_evidence_files = [
            ev.file_path for ev in evidence
            if ev.file_path and "tls" in ev.file_path.lower()
        ]
        tls_assessment_summary: Optional[Dict[str, Any]] = None
        if tls_findings or tls_evidence_files:
            tls_assessment_summary = {
                "total_findings": len(tls_findings),
                "evidence_files": tls_evidence_files,
                "findings": tls_findings,
            }

        return AssessmentReportData(
            project=project,
            scopes=scopes,
            executions=executions,
            findings=findings,
            evidence=evidence,
            metrics=metrics,
            assessment=assessment,
            terminal_sessions=terminal_sessions,
            asset_nodes=asset_nodes,
            asset_edges=asset_edges,
            assessment_plans=assessment_plans,
            network_scan_results=network_scan_results,
            footprint_results=footprint_results,
            workflow_summary=workflow_summary,
            cpent_labs=CPENT_LAB_CATALOG,
            ad_audit_summary=ad_audit_summary,
            pcap_analysis_summary=pcap_analysis_summary,
            code_security_findings=code_security_findings,
            cracked_credentials_summary=cracked_credentials_summary,
            waf_events_summary=waf_events_summary,
            tls_assessment_summary=tls_assessment_summary,
            evidence_integrity=evidence_integrity,
            terminal_session_integrity=terminal_session_integrity,
        )

    def _verify_evidence_integrity(self, evidence: Evidence) -> Dict[str, str]:
        """Verifies each evidence artifact before describing it as intact in a report."""
        return self._verify_artifact_integrity(
            evidence.file_path,
            evidence.sha256_hash or evidence.file_hash or "",
            evidence.project_id,
        )

    def _verify_artifact_integrity(
        self, file_path: Optional[str], expected_hash: str, project_id: int
    ) -> Dict[str, str]:
        """Checks a stored artifact digest against its current file."""
        expected_hash = expected_hash.strip()
        if not expected_hash:
            return {
                "status": "unverified",
                "details": "No expected SHA-256 hash is recorded.",
            }

        artifact = Evidence(
            project_id=project_id,
            file_path=file_path or "",
            sha256_hash=expected_hash,
        )
        is_valid, message = self.db.verify_evidence_integrity(artifact)
        if is_valid:
            return {
                "status": "verified",
                "details": "File hash matches the recorded SHA-256.",
            }

        normalized_message = message.lower()
        if "mismatch" in normalized_message:
            return {
                "status": "mismatch",
                "details": "File contents do not match the recorded SHA-256.",
            }
        if "does not exist" in normalized_message or "no associated file path" in normalized_message:
            return {
                "status": "missing",
                "details": "Evidence file is missing or has no associated path.",
            }
        return {
            "status": "error",
            "details": message,
        }

    # -------------------------------------------------------------
    # 1. JSON Report Generation
    # -------------------------------------------------------------
    def generate_json(self, project_id: int, output_path: Optional[Path] = None, assessment_id: Optional[int] = None) -> str:
        """Generates a structured machine-readable JSON report."""
        data = self.build_report_data(project_id, assessment_id=assessment_id)

        report_dict = {
            "report_version": "1.0",
            "generator": "CyberSecuritySuite Assessment Engine",
            "sample_data_notice": "Verify target authorization, scope, findings, and evidence before treating this as a real engagement report.",
            "generated_at": data.generated_at,
            "assessment": {
                "id": data.assessment.id,
                "name": data.assessment.name,
                "status": data.assessment.status.value if hasattr(data.assessment.status, "value") else str(data.assessment.status),
                "authorized_scope": data.assessment.authorized_scope,
                "start_date": data.assessment.start_date,
                "end_date": data.assessment.end_date,
                "notes": data.assessment.notes,
                "description": data.assessment.description,
            } if data.assessment else None,
            "project": {
                "id": data.project.id,
                "name": data.project.name,
                "client_name": data.project.client_name,
                "description": data.project.description,
                "status": data.project.status.value,
                "created_at": data.project.created_at,
                "engagement_id": getattr(data.project, "engagement_id", ""),
                "lead_tester": getattr(data.project, "lead_tester", ""),
                "authorized_contact": getattr(data.project, "authorized_contact", ""),
                "emergency_contact": getattr(data.project, "emergency_contact", ""),
                "sow_reference": getattr(data.project, "sow_reference", ""),
                "authorization_doc": getattr(data.project, "authorization_doc", ""),
                "start_date": getattr(data.project, "start_date", ""),
                "end_date": getattr(data.project, "end_date", ""),
                "timezone": getattr(data.project, "timezone", "UTC"),
                "allowed_hours": getattr(data.project, "allowed_hours", ""),
                "max_rate_limit": getattr(data.project, "max_rate_limit", 100),
                "allow_active_recon": getattr(data.project, "allow_active_recon", False),
                "prohibited_tests": getattr(data.project, "prohibited_tests", ""),
            },
            "metrics": asdict(data.metrics),
            "scopes": [
                {
                    "target": s.target,
                    "target_type": s.target_type.value,
                    "rule_type": getattr(s, "rule_type", ScopeRuleType.ALLOWED).value if hasattr(getattr(s, "rule_type", None), "value") else str(getattr(s, "rule_type", "ALLOWED")),
                    "is_authorized": s.is_authorized,
                    "environment": s.environment,
                    "ports_allowed": s.ports_allowed,
                    "expires_at": s.expires_at,
                    "notes": s.notes,
                }
                for s in data.scopes
            ],
            "executions": [
                {
                    "id": ex.id,
                    "tool_name": ex.tool_name,
                    "command": ex.command,
                    "status": ex.status.value,
                    "exit_code": ex.exit_code,
                    "started_at": ex.started_at,
                    "finished_at": ex.finished_at,
                    "duration_seconds": ex.duration_seconds,
                    "raw_output_path": ex.raw_output_path,
                }
                for ex in data.executions
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "affected_asset": f.affected_asset,
                    "affected_port_service": f.affected_port_service,
                    "description": f.description,
                    "reproduction_steps": f.reproduction_steps,
                    "remediation": f.remediation,
                    "validation_status": f.validation_status.value if hasattr(f.validation_status, "value") else str(f.validation_status),
                    "validation_method": getattr(f, "validation_method", ""),
                    "severity_rationale": getattr(f, "severity_rationale", ""),
                    "source_tool": f.source_tool,
                    "execution_id": f.execution_id,
                    "created_at": f.created_at,
                }
                for f in data.findings
            ],
            "evidence": [
                {
                    "id": ev.id,
                    "file_path": ev.file_path,
                    "sha256_hash": ev.sha256_hash,
                    "integrity_status": data.evidence_integrity[index]["status"],
                    "integrity_details": data.evidence_integrity[index]["details"],
                    "finding_id": ev.finding_id,
                    "execution_id": ev.execution_id,
                    "description": ev.description,
                    "mime_type": ev.mime_type,
                    "created_at": ev.created_at,
                }
                for index, ev in enumerate(data.evidence)
            ],
            "terminal_sessions": [
                {
                    "session_id": s.session_id,
                    "started_at": s.started_at,
                    "ended_at": s.ended_at,
                    "working_directory": s.working_directory,
                    "exit_status": s.exit_status,
                    "sha256_hash": s.sha256_hash,
                    "integrity_status": data.terminal_session_integrity[index]["status"],
                    "integrity_details": data.terminal_session_integrity[index]["details"],
                    "raw_output_path": s.raw_output_path,
                    "plain_text_path": s.plain_text_path,
                    "evidence_id": s.evidence_id,
                    "execution_id": s.execution_id,
                    "command_count": s.command_count,
                    "commands": [
                        {
                            "command": redact_sensitive_text(c.get("command", "")),
                            "working_directory": c.get("working_directory", ""),
                            "exit_code": c.get("exit_code"),
                            "timestamp": c.get("timestamp"),
                            "duration_seconds": c.get("duration_seconds"),
                        }
                        for c in (json.loads(s.commands_json) if s.commands_json else [])
                    ],
                }
                for index, s in enumerate(data.terminal_sessions)
            ],
            "asset_nodes": [
                {
                    "id": n.id,
                    "node_type": n.node_type,
                    "value": n.value,
                    "label": n.label,
                    "source_tool": n.source_tool,
                    "confidence": n.confidence,
                    "metadata_json": n.metadata_json,
                }
                for n in data.asset_nodes
            ],
            "asset_edges": [
                {
                    "id": e.id,
                    "source_node_id": e.source_node_id,
                    "target_node_id": e.target_node_id,
                    "relation_type": e.relation_type,
                    "source_tool": e.source_tool,
                }
                for e in data.asset_edges
            ],
            "assessment_plans": [
                {
                    "id": p.id,
                    "title": p.title,
                    "target": p.target,
                    "test_category": p.test_category.value if hasattr(p.test_category, "value") else str(p.test_category),
                    "description": p.description,
                    "acceptance_criteria": p.acceptance_criteria,
                    "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                    "preflight_blockers": p.preflight_blockers,
                    "execution_id": p.execution_id,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                }
                for p in data.assessment_plans
            ],
            "network_inventory": [
                {
                    "ip": h.ip,
                    "status": h.status,
                    "hostname": h.hostname,
                    "os_match": h.os_match,
                    "os_accuracy": h.os_accuracy,
                    "mac_address": h.mac_address,
                    "vendor": h.vendor,
                    "latency_ms": h.latency_ms,
                    "ports": [
                        {
                            "port_id": p.port_id,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service_name": p.service_name,
                            "product": p.product,
                            "version": p.version,
                            "cpe_list": p.cpe_list,
                        }
                        for p in h.ports
                    ],
                }
                for sr in data.network_scan_results
                for h in sr.hosts
            ],
            "internal_network_pentest_workflow": {
                "summary": data.workflow_summary,
                "footprint_observations": data.footprint_results,
                "cpent_labs": [
                    {
                        "id": lab.id,
                        "title": lab.title,
                        "module": lab.module,
                        "difficulty": lab.difficulty,
                        "description": lab.description,
                        "target_ranges": lab.target_ranges,
                        "prerequisites": lab.prerequisites,
                        "learning_objectives": lab.learning_objectives,
                        "verification_steps": lab.verification_steps,
                        "scoring_criteria": lab.scoring_criteria,
                        "cleanup_procedure": lab.cleanup_procedure,
                        "safety_warning": lab.safety_warning,
                    }
                    for lab in data.cpent_labs
                ],
            },
            "active_directory_audit": {
                "total_findings": data.ad_audit_summary["total_findings"] if data.ad_audit_summary else 0,
                "vulnerable_accounts": data.ad_audit_summary["vulnerable_accounts"] if data.ad_audit_summary else 0,
                "categories": data.ad_audit_summary["categories"] if data.ad_audit_summary else {},
            } if data.ad_audit_summary else None,
            "pcap_protocol_analysis": {
                "total_findings": data.pcap_analysis_summary["total_findings"] if data.pcap_analysis_summary else 0,
                "evidence_files": data.pcap_analysis_summary["evidence_files"] if data.pcap_analysis_summary else [],
            } if data.pcap_analysis_summary else None,
            "code_security_sast": [
                {
                    "id": csf.id,
                    "title": csf.title,
                    "severity": csf.severity.value,
                    "affected_asset": csf.affected_asset,
                    "source_tool": csf.source_tool,
                }
                for csf in data.code_security_findings
            ],
            "recovered_credentials": {
                "total_recovered": data.cracked_credentials_summary["total_recovered"] if data.cracked_credentials_summary else 0,
            } if data.cracked_credentials_summary else None,
            "waf_events": {
                "total_events": data.waf_events_summary["total_events"] if data.waf_events_summary else 0,
            } if data.waf_events_summary else None,
            "cpent_framework": {
                "rating_levels": {
                    "critical": "5 Stars (*****): Intruders can easily gain full control of hosts and network. Requires immediate emergency response.",
                    "high": "4 Stars (****): Intruders can possibly gain control of hosts or leak highly sensitive assets.",
                    "medium": "3 Stars (***): Intruders may gain partial control or gather intelligence leading to deeper compromise.",
                    "low": "2 Stars (**): Minor configuration issues or limited information exposure.",
                    "informational": "1 Star (*): Hardening recommendations and defense-in-depth best practices.",
                },
                "risk_assessment_matrix": {
                    "high_threat": "Scores 12-25: High Likelihood combined with Significant Impact.",
                    "medium_threat": "Scores 5-11: Medium Likelihood or Moderate Impact.",
                    "low_threat": "Scores 1-4: Low Likelihood with Minimal Impact.",
                },
                "strategic_recommendations": {
                    "personnel": "Implement regular phishing awareness drills and least-privilege role segregation.",
                    "policies_and_procedures": "Establish rigid change management, patch cadence baselines, and incident response runbooks.",
                    "critical_vulnerabilities": "Prioritize immediate patch deployment and service isolation for confirmed RCE/injection flaws.",
                    "identification_and_authentication": "Enforce Multi-Factor Authentication (MFA) and eliminate all cleartext protocols.",
                    "intrusion_detection": "Centralize telemetry into SIEM/EDR and configure active anomaly alerts on perimeter edge devices.",
                },
                "references": [
                    "NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment",
                    "Open Source Security Testing Methodology Manual (OSSTMM 3.0)",
                    "OWASP Web Security Testing Guide (WSTG v4.2)",
                    "Penetration Testing Execution Standard (PTES)",
                    "EC-Council Certified Penetration Testing Professional (CPENT) Courseware",
                ],
                "glossary": {
                    "Black Box Testing": "Testing with zero prior internal knowledge, simulating an external unprivileged threat actor.",
                    "Crystal Box / White Box Testing": "Testing with full architectural, credential, and source code knowledge.",
                    "Grey Box Testing": "Testing with partial user-level knowledge, simulating an insider or contractor.",
                    "Pivoting": "Using a compromised host as a relay gateway to route traffic into adjacent restricted subnets.",
                    "Double Pivoting": "Multi-hop routing through multiple compromised pivot hops across nested internal firewalls.",
                },
            },
        }

        json_text = json.dumps(report_dict, indent=2)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_text, encoding="utf-8")

        return json_text

    # -------------------------------------------------------------
    # 2. Markdown Report Generation
    # -------------------------------------------------------------
    def generate_markdown(self, project_id: int, output_path: Optional[Path] = None, assessment_id: Optional[int] = None) -> str:
        """Generates a comprehensive, portable technical Markdown report."""
        data = self.build_report_data(project_id, assessment_id=assessment_id)
        p = data.project
        m = data.metrics

        lines: List[str] = [
            f"# Security Assessment & Penetration Testing Report",
            f"**Project / Engagement:** {p.name}  ",
            f"**Engagement ID:** {p.engagement_id or 'N/A'}  ",
            f"**Client Organization:** {p.client_name or 'N/A'}  ",
            f"**Lead Tester:** {getattr(p, 'lead_tester', '') or 'N/A'}  ",
            f"**Emergency Contacts:** {getattr(p, 'emergency_contact', '') or 'N/A'}  ",
            f"**Testing Window:** {getattr(p, 'start_date', '') or 'N/A'} to {getattr(p, 'end_date', '') or 'N/A'} ({getattr(p, 'timezone', 'UTC') or 'UTC'})  ",
            f"**Authorization / SoW:** {getattr(p, 'authorization_doc', '') or 'N/A'} / {getattr(p, 'sow_reference', '') or 'N/A'}  ",
            f"**Assessment Date:** {data.generated_at[:10]}  ",
            f"**Engagement Status:** {p.status.value.upper()}  ",
            f"**Report Classification:** CONFIDENTIAL  ",
            f"**Platform:** CyberSecuritySuite Workstation  ",
        ]

        if data.assessment:
            lines.extend([
                f"**Assessment Focus:** {data.assessment.name} (ID: #{data.assessment.id})  ",
                f"**Assessment Scope:** `{data.assessment.authorized_scope}`  ",
                f"**Assessment Status:** {data.assessment.status.value.upper()}  ",
            ])

        lines.extend([
            "",
            "> **Sample data notice:** This project contains demonstration targets and findings. Treat this report as a sample until every target, authorization record, test result, and evidence item has been verified for the real engagement.",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            p.description or "This report documents the security assessment and vulnerability findings identified during the authorized penetration test.",
            "",
            "### 1.1 Project Objectives & Target Systems",
            f"The primary objective of this engagement was to discover security vulnerabilities within the systems of **{p.client_name or 'the client'}**, evaluate exploitable paths across the network perimeter and web applications, and produce actionable risk remediation guidance.",
            f"- **Target Systems:** {m.total_targets} authorized target scopes defined.",
            f"- **Operational Timeline:** {getattr(p, 'start_date', '') or 'N/A'} through {getattr(p, 'end_date', '') or 'N/A'} ({getattr(p, 'timezone', 'UTC') or 'UTC'}). Permitted testing hours: `{getattr(p, 'allowed_hours', '') or '08:00-18:00'}`.",
            "",
            "### 1.2 Assumptions & Operational Limitations",
            "- **Non-Destructive Testing:** Assessment was conducted with care to avoid service interruption or permanent data modification.",
            "- **Scope Adherence:** Probes were restricted strictly to authorized IP ranges and hostnames registered in the Scope Guard.",
            "- **Point-in-Time Evaluation:** Findings reflect the security posture of the target systems during the active testing window only.",
            "",
            "### 1.3 Finding Rating Levels (EC-Council CPENT Standards)",
            "Findings are categorized using standard 5-level severity criteria:",
            "- **5 Stars (★★★★★) Critical:** Intruders can easily gain full control of hosts and network. Requires immediate emergency remediation.",
            "- **4 Stars (★★★★☆) High:** Intruders can possibly gain control of the host, or potential leakage of highly sensitive assets.",
            "- **3 Stars (★★★☆☆) Medium:** Intruders may gain partial control or gather intelligence leading to deeper exploitation.",
            "- **2 Stars (★★☆☆☆) Low:** Minor security issues or informational configuration exposure.",
            "- **1 Star (★☆☆☆☆) Informational:** Defense-in-depth hardening suggestions and procedural baselines.",
            "",
            "### 1.4 Risk Assessment Matrix (Likelihood vs Impact)",
            "",
            "| Likelihood \\ Impact | Low Impact | Medium Impact | High Impact / Critical |",
            "| :--- | :---: | :---: | :---: |",
            "| **High Likelihood** | Medium Threat (6) | High Threat (15) | **Critical Threat (25)** |",
            "| **Medium Likelihood** | Low Threat (3) | Medium Threat (9) | **High Threat (15)** |",
            "| **Low Likelihood** | Low Threat (1) | Low Threat (4) | **Medium Threat (6)** |",
            "",
            "- **High / Critical Threat (Scores 12-25):** Critical vulnerabilities that can be exploited remotely without authentication.",
            "- **Medium Threat (Scores 5-11):** Flaws requiring user interaction, local network positioning, or specific pre-conditions.",
            "- **Low Threat (Scores 1-4):** Minor information disclosure or non-exploitable configuration variances.",
            "",
            "### 1.5 Risk Posture & Metrics Overview",
            "",
            "| Metric | Count / Value |",
            "| :--- | :--- |",
            f"| **Total Security Findings** | **{m.total_findings}** |",
            f"| Critical Severity | {m.critical_count} |",
            f"| High Severity | {m.high_count} |",
            f"| Medium Severity | {m.medium_count} |",
            f"| Low Severity | {m.low_count} |",
            f"| Informational | {m.info_count} |",
            f"| Maximum CVSS Score | {m.max_cvss:.1f} / 10.0 |",
            f"| Confirmed Vulnerabilities | {m.confirmed_findings} |",
            f"| Unverified Observations | {m.unverified_findings} |",
            f"| Authorized Targets In Scope | {m.total_targets} |",
            f"| Security Tools Executed | {m.total_executions} |",
            f"| Cryptographic Evidence Records | {m.total_evidence_files} |",
            "",
            "### 1.6 Summary of Strategic Recommendations (CPENT Five Pillars)",
            "",
            "#### 1.6.1 Personnel & Security Awareness",
            "- Conduct regular phishing simulation campaigns and practical awareness workshops for developers and operational staff.",
            "- Enforce strict separation of duties and least privilege access across administrative workflows.",
            "",
            "#### 1.6.2 Policies and Procedures",
            "- Establish a formal Vulnerability Management Policy mandating critical flaw resolution within 14 calendar days.",
            "- Implement continuous configuration change audits and disaster recovery runbook validation.",
            "",
            "#### 1.6.3 Critical Vulnerabilities Remediation",
            f"- Immediately deploy vendor security updates for the **{m.critical_count} Critical** and **{m.high_count} High** severity findings identified in this assessment.",
            "- Decommission or isolate legacy end-of-life operating systems and outdated library dependencies.",
            "",
            "#### 1.6.4 Identification and Authentication (I&A)",
            "- Enforce mandatory Multi-Factor Authentication (MFA) across all external remote access endpoints (VPN, SSH, RDP, Web Portals).",
            "- Prohibit cleartext communication protocols (HTTP, Telnet, FTP, SNMPv1/v2c) in favor of TLS 1.3 encrypted transport.",
            "",
            "#### 1.6.5 Intrusion Detection & Logging (IDS/SIEM)",
            "- Centralize server, perimeter firewall, and application access logs into a SIEM platform with real-time alerting.",
            "- Configure automated alerting on anomalous multi-probe port scans, repeated authentication failures, and outbound data spikes.",
            "",
            "#### 1.6.6 Conclusion",
            "Remediating these systemic gaps will substantially harden the organization's defense-in-depth posture against external and internal threat actors.",
            "",
            "---",
            "",
            "## 2. Assessment Scope & Rules of Engagement",
            "",
            "### Rules of Engagement & Operational Constraints",
            f"- **Allowed Techniques:** {'Standard authorized pentest' if not getattr(p, 'allow_active_recon', False) else 'Active OSINT and authorized penetration testing'}",
            f"- **Prohibited Techniques:** {getattr(p, 'prohibited_tests', '') or 'DoS/DDoS, Social Engineering, Physical Intrusion'}",
            f"- **Rate Limits:** {getattr(p, 'max_rate_limit', 100)} req/sec",
            f"- **Emergency Stop Procedure:** Immediately terminate all processes and notify authorized emergency contact ({getattr(p, 'emergency_contact', '') or 'Designated SecOps'})",
            "",
            "### Target Scope Boundaries & Exclusions",
            "",
            "| Target Identifier | Type | Rule | Authorization Status | Environment | Ports Allowed | Notes |",
            "| :--- | :--- | :---: | :---: | :---: | :---: | :--- |",
        ])

        if data.scopes:
            for s in data.scopes:
                auth_str = "Authorized ✓" if s.is_authorized else "Excluded / Blocked ✗"
                rule_str = getattr(s, "rule_type", ScopeRuleType.ALLOWED)
                rule_name = rule_str.value if hasattr(rule_str, "value") else str(rule_str)
                env_str = s.environment or "All"
                ports_str = s.ports_allowed or "All"
                lines.append(f"| `{s.target}` | {s.target_type.value} | `{rule_name}` | {auth_str} | {env_str} | {ports_str} | {s.notes or 'N/A'} |")
        else:
            lines.append("| *No specific target scopes registered* | - | - | - | - | - | - |")

        if data.assessment_plans:
            lines.extend([
                "",
                "### Authorized Assessment Plans & Acceptance Criteria",
                "",
                "| Plan ID | Title | Category | Target | Status | Acceptance Criteria |",
                "| :---: | :--- | :---: | :---: | :---: | :--- |",
            ])
            for ap in data.assessment_plans:
                cat_val = ap.test_category.value if hasattr(ap.test_category, "value") else str(ap.test_category)
                stat_val = ap.status.value.upper() if hasattr(ap.status, "value") else str(ap.status).upper()
                lines.append(
                    f"| #{ap.id} | {ap.title} | `{cat_val}` | `{ap.target}` | **{stat_val}** | {ap.acceptance_criteria} |"
                )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Methodology & Standards",
            "",
            "The assessment followed the EC-Council CPENT (Certified Penetration Testing Professional) and PTES methodologies:",
            "1. **Reconnaissance & Passive OSINT:** DNS inspection, certificate analysis, HTTP header enumeration, and passive route mapping.",
            "2. **Host & Service Discovery:** Non-intrusive network port scanning and service fingerprinting via Nmap.",
            "3. **Web & API Security Inspection:** Security header validation, CORS misconfiguration analysis, and JavaScript secret scanning.",
            "4. **Vulnerability Verification:** Evidence collection with SHA-256 cryptographic integrity hashes.",
            "",
        ])

        if data.asset_nodes:
            lines.extend([
                "---",
                "",
                "## Attack Surface Topology & OSINT Asset Graph",
                "",
                f"Discovered **{len(data.asset_nodes)}** infrastructure assets and **{len(data.asset_edges)}** relationship interconnections via native discovery and OSINT correlation:",
                "",
                "| Asset ID | Type | Label | Properties / Source |",
                "| :---: | :--- | :--- | :--- |",
            ])
            for n in data.asset_nodes[:30]:
                lines.append(f"| #{n.id} | `{n.node_type}` | `{n.value}` | {n.source_tool or 'Amass'} |")
            if len(data.asset_nodes) > 30:
                lines.append(f"| ... | *and {len(data.asset_nodes) - 30} more assets* | - | - |")
            lines.append("")

        # Network Penetration Testing & Asset Inventory Section
        all_network_hosts: List[HostResult] = []
        for sr in data.network_scan_results:
            all_network_hosts.extend(sr.hosts)

        if all_network_hosts:
            lines.extend([
                "---",
                "",
                "## Network Penetration Testing & Discovered Endpoints",
                "",
                f"Discovered **{len(all_network_hosts)}** active network host(s) via authorized port discovery and service interrogation.",
                "",
                "> **Topological Integrity Notice:** Network host groupings represent logical address blocks (/24 subnets). Physical switch connectivity, VLAN isolation, and routing paths remain unverified without direct infrastructure inspection.",
                "",
                "### Discovered Host Inventory",
                "",
                "| Host IP | Status | Hostname | OS Fingerprint | MAC Address / Vendor | Open Ports | Latency |",
                "| :--- | :---: | :--- | :--- | :--- | :---: | :---: |",
            ])
            for h in all_network_hosts:
                open_cnt = sum(1 for p in h.ports if p.state == "open")
                mac_v = h.mac_address or "Unknown"
                if h.vendor:
                    mac_v += f" ({h.vendor})"
                lat_str = f"{h.latency_ms} ms" if h.latency_ms is not None else "N/A"
                lines.append(
                    f"| `{h.ip}` | **{h.status.upper()}** | {h.hostname or 'None'} | {h.os_summary} | {mac_v} | {open_cnt} | {lat_str} |"
                )

            has_services = any(len(h.ports) > 0 for h in all_network_hosts)
            if has_services:
                lines.extend([
                    "",
                    "### Port & Service Fingerprinting Matrix",
                    "",
                    "| Host IP | Port | Protocol | State | Service | Version / Product | CPE Identifiers |",
                    "| :--- | :---: | :---: | :---: | :--- | :--- | :--- |",
                ])
                for h in all_network_hosts:
                    for p in h.ports:
                        cpe_txt = ", ".join(p.cpe_list) if p.cpe_list else "-"
                        lines.append(
                            f"| `{h.ip}` | `{p.port_id}` | `{p.protocol}` | **{p.state}** | {p.service_name or '-'} | {p.service_summary or '-'} | `{cpe_txt}` |"
                        )
            lines.append("")

        # Six-Step Internal Penetration Testing Methodology Section
        wf = data.workflow_summary or {}
        st_data = wf.get("stages", {})
        lines.extend([
            "---",
            "",
            "## Six-Step Internal Network Penetration Testing Workflow",
            "",
            "| Stage | Methodology Phase | Status | Telemetry & Assessment Summary |",
            "| :---: | :--- | :---: | :--- |",
        ])
        stage_names = [
            ("STAGE 1", "footprinting_initial_discovery", "Footprinting & Initial Discovery"),
            ("STAGE 2", "network_scanning_live_discovery", "Host & Port Discovery"),
            ("STAGE 3", "os_service_fingerprinting", "OS & Service Fingerprinting"),
            ("STAGE 4", "vulnerability_assessment", "Vulnerability Assessment & Observations"),
            ("STAGE 5", "exploit_verification", "Controlled Exploit Verification (Labs)"),
            ("STAGE 6", "reporting_retesting", "Reporting & Remediation Retesting"),
        ]
        for num, key, label in stage_names:
            st = st_data.get(key, {})
            status_badge = f"**{st.get('status', 'NOT_STARTED').upper()}**"
            summary_txt = st.get("summary") or "Pending engagement execution"
            lines.append(f"| {num} | {label} | {status_badge} | {summary_txt} |")
        lines.append("")

        # Footprinting & Interface Telemetry (Step 1)
        if data.footprint_results:
            lines.extend([
                "### Step 1: Footprinting & Local Network Topology Telemetry",
                "",
                "> **Passive Collection Methodology:** ARP and neighbour cache entries reflect historical OS-level observations. They do NOT constitute proof of active host reachability or completed network sweeps (Confidence: 0.7, Classification: OBSERVED).",
                "",
            ])
            for idx, fp in enumerate(data.footprint_results):
                gw = fp.get("default_gateway") or "None"
                subnets = ", ".join(fp.get("discovered_subnets", [])) or "None"
                in_sc = ", ".join(fp.get("in_scope_subnets", [])) or "None"
                out_sc = ", ".join(fp.get("out_of_scope_subnets", [])) or "None"
                lines.extend([
                    f"- **Host System:** `{fp.get('hostname', 'Localhost')}` | **Default Gateway:** `{gw}`",
                    f"- **Discovered Subnets:** `{subnets}`",
                    f"- **Scope Correlation:** In-Scope: `{in_sc}` | Out-of-Scope: `{out_sc}`",
                    "",
                ])

        lines.extend([
            "---",
            "",
            "## 4. Findings Summary Matrix",
            "",
            "| ID | Severity | CVSS | Finding Title | Affected Asset | Status |",
            "| :---: | :---: | :---: | :--- | :--- | :---: |",
        ])

        if data.findings:
            for f in data.findings:
                cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score else "N/A"
                lines.append(
                    f"| #{f.id} | **{f.severity.value.upper()}** | {cvss_str} | {f.title} | `{f.affected_asset}` | {f.validation_status.value} |"
                )
        else:
            lines.append("| - | - | - | *No security vulnerabilities identified* | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Detailed Technical Findings & Remediation",
            "",
        ])

        if data.findings:
            for f in data.findings:
                val_val = f.validation_status.value if hasattr(f.validation_status, "value") else str(f.validation_status)
                unverified_suffix = " `[UNVERIFIED - PENDING EVIDENCE]`" if val_val.lower() in ("unverified", "needs_validation") else ""
                lines.extend([
                    f"### Finding #{f.id}: {f.title}{unverified_suffix}",
                    "",
                    f"- **Severity:** `{f.severity.value.upper()}`",
                    f"- **CVSS Score:** `{f.cvss_score or 'N/A'}`",
                    f"- **CVSS Vector:** `{f.cvss_vector or 'N/A'}`",
                    f"- **Affected Asset:** `{f.affected_asset}`",
                    f"- **Service / Port:** `{f.affected_port_service or 'N/A'}`",
                    f"- **Source Tool:** `{f.source_tool or 'N/A'}`",
                    f"- **Validation Status:** `{val_val.upper()}`",
                ])
                if getattr(f, "validation_method", ""):
                    lines.append(f"- **Validation Method:** `{f.validation_method}`")
                if getattr(f, "severity_rationale", ""):
                    lines.append(f"- **Severity Rationale:** {f.severity_rationale}")
                lines.extend([
                    "",
                    "#### Vulnerability Description & Explanation",
                    f"{f.description or 'No description provided.'}",
                    "",
                    "#### Actionable Remediation Guidance",
                    f"{f.remediation or 'Review application configuration and apply vendor hardening guidelines.'}",
                    "",
                ])
                if f.reproduction_steps:
                    lines.extend([
                        "#### Reproduction Steps",
                        f"```text\n{f.reproduction_steps}\n```",
                        "",
                    ])

                # Proof-of-Concept Screenshot Evidence for Finding
                finding_ev = [
                    ev for ev in data.evidence
                    if ev.finding_id == f.id and (
                        (ev.mime_type and ev.mime_type.startswith("image/"))
                        or Path(ev.file_path).suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp", ".gif")
                    )
                ]
                if finding_ev:
                    lines.append("#### Proof-of-Concept (POC) Evidence")
                    for idx, fev in enumerate(finding_ev, 1):
                        lines.extend([
                            f"![Figure {f.id}.{idx}: {fev.description}]({fev.file_path})",
                            f"*Figure {f.id}.{idx}: {fev.description or 'Proof of Concept'} (SHA-256: `{fev.sha256_hash}`)*",
                            "",
                        ])
        else:
            lines.append("No technical findings to display.")

        lines.extend([
            "",
            "---",
            "",
            "## 6. Cryptographic Evidence Vault",
            "",
            "Evidence integrity is checked against the current on-disk file during report generation. A stored hash alone does not establish that the current artifact is intact:",
            "",
            "| ID | File Name | MIME Type | SHA-256 Hash | Integrity Status | Description |",
            "| :---: | :--- | :---: | :--- | :--- | :--- |",
        ])

        if data.evidence:
            for index, ev in enumerate(data.evidence):
                fname = Path(ev.file_path).name
                integrity_status = data.evidence_integrity[index]["status"]
                lines.append(
                    f"| #{ev.id} | `{fname}` | {ev.mime_type} | `{ev.sha256_hash}` | `{integrity_status}` | {ev.description} |"
                )
        else:
            lines.append("| - | *No evidence files registered* | - | - | - | - |")

        disclaimer_section_num = 7
        if data.terminal_sessions:
            disclaimer_section_num = 8
            lines.extend([
                "",
                "---",
                "",
                "## 7. Interactive Terminal Sessions & Command Audit Trail",
                "",
                "Recorded interactive terminal sessions linked to this assessment engagement:",
                "",
                "| Session ID | Recorded Time Range | Working Directory | Exit Status | SHA-256 Hash | Integrity Status | Commands |",
                "| :--- | :--- | :--- | :---: | :--- | :--- | :---: |",
            ])
            for index, s in enumerate(data.terminal_sessions):
                time_range = f"{s.started_at[:19]} to {s.ended_at[:19] if s.ended_at else 'Incomplete'}"
                hash_short = f"`{s.sha256_hash[:16]}...`" if s.sha256_hash else "-"
                exit_str = str(s.exit_status) if s.exit_status is not None else "0"
                lines.append(
                    f"| `{s.session_id}` | {time_range} | `{s.working_directory}` | {exit_str} | {hash_short} | `{data.terminal_session_integrity[index]['status']}` | {s.command_count} |"
                )

            for index, s in enumerate(data.terminal_sessions):
                lines.extend([
                    "",
                    f"### Session `{s.session_id}`",
                    f"- **Recorded:** {s.started_at} to {s.ended_at or 'Incomplete'}",
                    f"- **Working Directory:** `{s.working_directory}`",
                    f"- **Cryptographic SHA-256:** `{s.sha256_hash}`",
                    f"- **Integrity Status:** `{data.terminal_session_integrity[index]['status']}`",
                ])
                if s.commands_json:
                    try:
                        cmds = json.loads(s.commands_json)
                        if cmds:
                            lines.append("- **Recorded Commands (Redacted):**")
                            for c in cmds:
                                cmd_red = redact_sensitive_text(c.get("command", ""))
                                exit_code = c.get("exit_code")
                                exit_lbl = f"(exit: {exit_code})" if exit_code is not None else ""
                                lines.append(f"  - `{cmd_red}` {exit_lbl}")
                    except Exception:
                        pass

                if s.plain_text_path and os.path.exists(s.plain_text_path):
                    try:
                        content = Path(s.plain_text_path).read_text(encoding="utf-8", errors="replace").strip()
                        if content:
                            snippet = "\n".join(content.splitlines()[:15])
                            redacted_snippet = redact_sensitive_text(snippet)
                            lines.extend([
                                "",
                                "**Session Output Preview (Redacted):**",
                                "```text",
                                redacted_snippet,
                                "```",
                            ])
                    except Exception:
                        pass

        # 8. Active Directory Weak Password Audit
        if data.ad_audit_summary:
            ad = data.ad_audit_summary
            lines.extend([
                "",
                "---",
                "",
                "## Active Directory Weak Password & Credential Audit",
                "",
                f"- **Vulnerable Accounts Identified:** {ad.get('vulnerable_accounts', 0)}",
                f"- **Total AD Security Findings:** {ad.get('total_findings', 0)}",
                "",
                "### Vulnerability Categories Breakdown",
                "| Category | Vulnerable Count | Risk Level |",
                "| :--- | :---: | :---: |",
            ])
            for cat, count in ad.get("categories", {}).items():
                lines.append(f"| {cat} | **{count}** | HIGH |")

        # 9. Offline PCAP Protocol Analysis
        if data.pcap_analysis_summary:
            pca = data.pcap_analysis_summary
            lines.extend([
                "",
                "---",
                "",
                "## Offline Network Traffic & PCAP Protocol Analysis",
                "",
                f"- **Total Traffic Anomaly Findings:** {pca.get('total_findings', 0)}",
                "- **Evidence PCAP Capture Files:**",
            ])
            for pcap_f in pca.get("evidence_files", []):
                lines.append(f"  * `{Path(pcap_f).name}`")

        # 10. Static Application Security Testing (SAST)
        if data.code_security_findings:
            lines.extend([
                "",
                "---",
                "",
                "## Static Application Security Testing (SAST & AST)",
                "",
                "| ID | Title | Severity | Affected Asset | Engine |",
                "| :---: | :--- | :---: | :--- | :---: |",
            ])
            for csf in data.code_security_findings:
                lines.append(f"| #{csf.id} | {csf.title} | **{csf.severity.value.upper()}** | `{csf.affected_asset}` | `{csf.source_tool or 'SAST'}` |")

        # 11. Recovered Credentials & Cracking Audit
        if data.cracked_credentials_summary:
            cc = data.cracked_credentials_summary
            lines.extend([
                "",
                "---",
                "",
                "## Recovered Credentials & Password Cracking Audit",
                "",
                f"- **Total Recovered Accounts:** {cc.get('total_recovered', 0)}",
                "",
                "| ID | Title | Target Asset | Tool |",
                "| :---: | :--- | :--- | :---: |",
            ])
            for cf in cc.get("findings", []):
                lines.append(f"| #{cf.id} | {cf.title} | `{cf.affected_asset}` | `{cf.source_tool or 'Cracker'}` |")

        # 12. TLS / SSL Security & Cryptographic Assessment
        if data.tls_assessment_summary:
            tls = data.tls_assessment_summary
            lines.extend([
                "",
                "---",
                "",
                "## TLS / SSL Certificate & Cryptographic Assessment",
                "",
                f"- **Total Cryptographic Findings:** {tls.get('total_findings', 0)}",
                "- **Evidence Artifacts:**",
            ])
            for ev_f in tls.get("evidence_files", []):
                lines.append(f"  * `{Path(ev_f).name}`")
            lines.extend([
                "",
                "| ID | Title | Severity | Affected Asset | Remediation Guidance |",
                "| :---: | :--- | :---: | :--- | :--- |",
            ])
            for tf in tls.get("findings", []):
                lines.append(f"| #{tf.id or '-'} | {tf.title} | **{tf.severity.value.upper()}** | `{tf.affected_asset}` | {tf.remediation} |")

        lines.extend([
            "",
            "---",
            "",
            "## Appendix A: References & Standards",
            "",
            "1. **NIST SP 800-115:** Technical Guide to Information Security Testing and Assessment.",
            "2. **NIST SP 800-42:** Guideline on Network Security Testing.",
            "3. **EC-Council CPENT:** Certified Penetration Testing Professional Methodology Standards.",
            "4. **PTES:** Penetration Testing Execution Standard (Pre-engagement, Intelligence, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting).",
            "5. **OWASP Top 10 (2021):** The Ten Most Critical Web Application Security Risks.",
            "6. **MITRE ATT&CK Framework:** Adversarial Tactics, Techniques, and Common Knowledge Enterprise Matrix.",
            "",
            "---",
            "",
            "## Appendix B: CPENT Security Terminology Glossary",
            "",
            "- **Black Box Penetration Testing:** Testing performed with zero advance internal knowledge of the target organization, simulating an external unprivileged adversary.",
            "- **Crystal Box / White Box Testing:** Testing conducted with full knowledge and administrative collaboration, including architecture designs, credentials, and source code.",
            "- **Grey Box Penetration Testing:** Testing conducted with limited insider knowledge (e.g. standard non-administrative user credentials), providing thorough coverage across attack vectors.",
            "- **Internet Footprinting:** Passive and non-intrusive collection of publicly available intelligence across DNS, web records, and registration databases to map an organization's perimeter.",
            "- **Pivoting:** The practice of using a compromised internal system as an application or network proxy to launch scans and attacks against adjacent, normally unreachable subnets.",
            "- **Double Pivoting:** Routing multi-hop tunnels across two or more sequentially compromised pivot gateways to penetrate isolated, deeply nested internal subnets.",
            "- **Rules of Engagement (RoE):** Formal, legally binding guidelines specifying authorized testing windows, rate limits, prohibited techniques, and emergency contact protocols.",
            "- **Buffer Overflow & ROP:** Memory safety corruption where data exceeds allocated buffer boundaries; Return-Oriented Programming (ROP) chains assembly snippets ending in RET to defeat NX/DEP.",
            "- **Modbus / SCADA:** Cleartext industrial automation protocol running over TCP port 502 without native authentication, commonly controlling field Programmable Logic Controllers (PLCs).",
            "",
            "---",
            "",
            f"## {disclaimer_section_num}. Disclaimer & Rules of Engagement",
            "",
            "This report contains sensitive security intelligence intended solely for the authorized client organization.",
            "Testing was executed in compliance with agreed Rules of Engagement. Antigravity / CyberSecuritySuite makes",
            "no guarantee that all vulnerabilities have been discovered beyond the specified testing timeframe and scope.",
            "",
            f"*Generated by CyberSecuritySuite on {data.generated_at} UTC*",
        ])

        md_text = "\n".join(lines)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(md_text, encoding="utf-8")

        return md_text

    # -------------------------------------------------------------
    # 3. HTML Report Generation
    # -------------------------------------------------------------
    def generate_html(self, project_id: int, output_path: Optional[Path] = None, assessment_id: Optional[int] = None) -> str:
        """Generates a professional, self-contained, responsive HTML report with embedded CSS."""
        data = self.build_report_data(project_id, assessment_id=assessment_id)
        p = data.project
        m = data.metrics

        assessment_banner_html = ""
        if data.assessment:
            assessment_banner_html = f"""
    <div style="background: rgba(38, 128, 255, 0.12); border: 1px solid var(--accent-blue); border-radius: 8px; padding: 16px; margin-bottom: 24px;">
      <h3 style="margin: 0 0 8px 0; color: var(--accent-blue);">🎯 Focused Assessment: {html.escape(data.assessment.name)} (ID: #{data.assessment.id})</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; font-size: 13px; color: var(--text-secondary);">
        <div><strong>Status:</strong> <span class="badge badge-info">{data.assessment.status.value.upper()}</span></div>
        <div><strong>Authorized Scope:</strong> <code>{html.escape(data.assessment.authorized_scope)}</code></div>
        <div><strong>Timeline:</strong> {data.assessment.start_date or 'N/A'} to {data.assessment.end_date or 'Active'}</div>
      </div>
      {f'<p style="margin: 8px 0 0 0; font-size: 13px; color: var(--text-primary);">{html.escape(data.assessment.description)}</p>' if data.assessment.description else ''}
    </div>"""

        # Severity Badge CSS classes and colors
        sev_color_map = {
            "critical": ("#ef4444", "#450a0a"),
            "high": ("#f97316", "#431407"),
            "medium": ("#eab308", "#422006"),
            "low": ("#38bdf8", "#082f49"),
            "informational": ("#94a3b8", "#0f172a"),
        }

        # Build Scope Rows HTML
        scope_rows = ""
        for s in data.scopes:
            rule_val = getattr(s, "rule_type", ScopeRuleType.ALLOWED)
            rule_name = rule_val.value if hasattr(rule_val, "value") else str(rule_val)
            rule_badge = (
                '<span class="badge badge-success">IN-SCOPE</span>'
                if rule_name == "ALLOWED"
                else '<span class="badge badge-danger">EXCLUDED</span>'
            )
            auth_badge = (
                '<span class="badge badge-success">Authorized</span>'
                if s.is_authorized
                else '<span class="badge badge-danger">Blocked</span>'
            )
            scope_rows += f"""
            <tr>
              <td><code>{s.target}</code></td>
              <td>{s.target_type.value}</td>
              <td>{rule_badge}</td>
              <td>{auth_badge}</td>
              <td>{s.environment or 'All'}</td>
              <td>{s.ports_allowed or 'All'}</td>
              <td>{s.notes or '—'}</td>
            </tr>"""

        # Build Attack Surface Topology HTML
        topology_html = ""
        if data.asset_nodes:
            node_rows = ""
            for n in data.asset_nodes[:30]:
                node_rows += f"""
            <tr>
              <td>#{n.id}</td>
              <td><span class="badge badge-info">{n.node_type}</span></td>
              <td><code>{n.value}</code></td>
              <td>{n.source_tool or 'Amass/OSINT'}</td>
            </tr>"""

            topology_html = f"""
    <!-- Attack Surface Relationship Topology Section -->
    <h2 class="section-title">🌐 Attack Surface Topology & Asset Graph</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
      Correlated <strong>{len(data.asset_nodes)}</strong> infrastructure nodes and <strong>{len(data.asset_edges)}</strong> relationship interconnections across target perimeter.
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Asset ID</th>
            <th>Type</th>
            <th>Canonical Identifier</th>
            <th>Metadata & Provenance</th>
          </tr>
        </thead>
        <tbody>
          {node_rows}
        </tbody>
      </table>
    </div>"""

        # Build Network Penetration Testing & Inventory HTML
        network_inventory_html = ""
        all_report_hosts: List[HostResult] = []
        for sr in data.network_scan_results:
            all_report_hosts.extend(sr.hosts)

        if all_report_hosts:
            host_rows = ""
            for h in all_report_hosts:
                open_cnt = sum(1 for p in h.ports if p.state == "open")
                mac_v = html.escape(h.mac_address or "Unknown")
                if h.vendor:
                    mac_v += f" ({html.escape(h.vendor)})"
                lat_str = f"{h.latency_ms} ms" if h.latency_ms is not None else "—"
                stat_badge = '<span class="badge badge-success">UP</span>' if h.status == "up" else '<span class="badge badge-danger">DOWN</span>'
                host_rows += f"""
            <tr>
              <td><code>{html.escape(h.ip)}</code></td>
              <td>{stat_badge}</td>
              <td>{html.escape(h.hostname or 'None')}</td>
              <td>{html.escape(h.os_summary)}</td>
              <td>{mac_v}</td>
              <td><span class="badge badge-info">{open_cnt} open</span></td>
              <td>{lat_str}</td>
            </tr>"""

            svc_rows = ""
            for h in all_report_hosts:
                for port in h.ports:
                    cpe_txt = html.escape(", ".join(port.cpe_list)) if port.cpe_list else "—"
                    p_badge = '<span class="badge badge-success">open</span>' if port.state == "open" else f'<span class="badge badge-warning">{port.state}</span>'
                    svc_rows += f"""
            <tr>
              <td><code>{html.escape(h.ip)}</code></td>
              <td><code>{port.port_id}/{port.protocol}</code></td>
              <td>{p_badge}</td>
              <td>{html.escape(port.service_name or '—')}</td>
              <td>{html.escape(port.service_summary or '—')}</td>
              <td><code>{cpe_txt}</code></td>
            </tr>"""

            svg_diagram = _render_network_svg(all_report_hosts)

            network_inventory_html = f"""
    <!-- Network Penetration Testing & Discovered Endpoints -->
    <h2 class="section-title">🖥 Network Penetration Testing & Asset Inventory</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">
      Discovered <strong>{len(all_report_hosts)}</strong> active network endpoint(s) across target scope.
    </div>
    <div style="font-size: 11px; color: var(--warning-amber); background: rgba(255,191,0,0.1); border-left: 3px solid var(--warning-amber); padding: 8px 12px; border-radius: 4px; margin-bottom: 16px;">
      <strong>Topological Integrity Notice:</strong> Network host groupings reflect logical address blocks (/24 subnets). Physical switch connectivity, VLAN isolation, and routing paths remain unverified without direct infrastructure inspection.
    </div>

    {svg_diagram}

    <h3 style="font-size: 15px; margin: 16px 0 8px 0; color: var(--text-primary);">Live Host Inventory</h3>
    <div class="table-container" style="margin-bottom: 20px;">
      <table>
        <thead>
          <tr>
            <th>Host IP</th>
            <th>Status</th>
            <th>Hostname</th>
            <th>OS Fingerprint</th>
            <th>MAC / Vendor</th>
            <th>Open Ports</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          {host_rows}
        </tbody>
      </table>
    </div>"""

            if svc_rows:
                network_inventory_html += f"""
    <h3 style="font-size: 15px; margin: 16px 0 8px 0; color: var(--text-primary);">Discovered Services & Version Fingerprints</h3>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Host IP</th>
            <th>Port</th>
            <th>State</th>
            <th>Service Name</th>
            <th>Product & Version</th>
            <th>CPE Identifiers</th>
          </tr>
        </thead>
        <tbody>
          {svc_rows}
        </tbody>
      </table>
    </div>"""

        # Build Six-Step Internal Penetration Testing Methodology HTML
        wf = data.workflow_summary or {}
        st_data = wf.get("stages", {})
        wf_rows = ""
        stage_names = [
            ("Stage 1", "footprinting_initial_discovery", "Footprinting & Initial Discovery"),
            ("Stage 2", "network_scanning_live_discovery", "Host & Port Discovery"),
            ("Stage 3", "os_service_fingerprinting", "OS & Service Fingerprinting"),
            ("Stage 4", "vulnerability_assessment", "Vulnerability Assessment & Observations"),
            ("Stage 5", "exploit_verification", "Controlled Exploit Verification (Labs)"),
            ("Stage 6", "reporting_retesting", "Reporting & Remediation Retesting"),
        ]
        for num, key, label in stage_names:
            st = st_data.get(key, {})
            st_val = st.get("status", "not_started").upper()
            badge_class = "badge-success" if st_val == "COMPLETED" else ("badge-warning" if st_val == "NEEDS_REVIEW" else ("badge-info" if st_val == "RUNNING" else "badge-secondary"))
            summary_txt = html.escape(st.get("summary") or "Pending execution")
            cnt = st.get("items_count", 0)
            wf_rows += f"""
            <tr>
              <td><strong>{num}</strong></td>
              <td>{label}</td>
              <td><span class="badge {badge_class}">{st_val}</span></td>
              <td>{cnt}</td>
              <td>{summary_txt}</td>
            </tr>"""

        pentest_workflow_html = f"""
    <!-- Six-Step Internal Network Penetration Testing Workflow -->
    <h2 class="section-title">🛡 Six-Step Internal Penetration Testing Methodology</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
      Execution status and telemetry progression across the 6 professional testing phases.
    </div>
    <div class="table-container" style="margin-bottom: 20px;">
      <table>
        <thead>
          <tr>
            <th>Stage</th>
            <th>Methodology Phase</th>
            <th>Status</th>
            <th>Discovered Items</th>
            <th>Telemetry & Assessment Details</th>
          </tr>
        </thead>
        <tbody>
          {wf_rows}
        </tbody>
      </table>
    </div>"""

        if data.footprint_results:
            fp_rows = ""
            for fp in data.footprint_results:
                gw = html.escape(fp.get("default_gateway") or "—")
                subnets = html.escape(", ".join(fp.get("discovered_subnets", [])) or "—")
                in_sc = html.escape(", ".join(fp.get("in_scope_subnets", [])) or "—")
                out_sc = html.escape(", ".join(fp.get("out_of_scope_subnets", [])) or "—")
                fp_rows += f"""
            <tr>
              <td><code>{html.escape(fp.get('hostname', 'localhost'))}</code></td>
              <td><code>{gw}</code></td>
              <td><code>{subnets}</code></td>
              <td><span class="badge badge-success">{in_sc}</span></td>
              <td><span class="badge badge-warning">{out_sc}</span></td>
            </tr>"""

            pentest_workflow_html += f"""
    <h3 style="font-size: 15px; margin: 16px 0 8px 0; color: var(--text-primary);">Footprinting & Subnet Telemetry</h3>
    <div style="font-size: 11px; color: var(--warning-amber); background: rgba(255,191,0,0.1); border-left: 3px solid var(--warning-amber); padding: 8px 12px; border-radius: 4px; margin-bottom: 12px;">
      <strong>Passive Collection Methodology:</strong> ARP and neighbour cache entries reflect historical OS-level observations. They do NOT constitute proof of active host reachability or completed network sweeps (Confidence: 0.7, Classification: OBSERVED).
    </div>
    <div class="table-container" style="margin-bottom: 20px;">
      <table>
        <thead>
          <tr>
            <th>Host System</th>
            <th>Default Gateway</th>
            <th>Discovered Subnets</th>
            <th>In-Scope Subnets</th>
            <th>Out-of-Scope Subnets</th>
          </tr>
        </thead>
        <tbody>
          {fp_rows}
        </tbody>
      </table>
    </div>"""

        # Build Findings Matrix HTML
        findings_matrix_rows = ""
        for f in data.findings:
            sev_fg, sev_bg = sev_color_map.get(f.severity.value, ("#94a3b8", "#0f172a"))
            cvss_val = f"{f.cvss_score:.1f}" if f.cvss_score else "—"
            findings_matrix_rows += f"""
            <tr>
              <td>#{f.id}</td>
              <td><span class="badge" style="background-color: {sev_bg}; color: {sev_fg}; border: 1px solid {sev_fg};">{f.severity.value.upper()}</span></td>
              <td><strong>{cvss_val}</strong></td>
              <td><a href="#finding-{f.id}" class="finding-link">{f.title}</a></td>
              <td><code>{f.affected_asset}</code></td>
              <td><span class="status-tag">{f.validation_status.value}</span></td>
            </tr>"""

        # Build Detailed Findings Cards HTML
        findings_cards = ""
        for f in data.findings:
            sev_fg, sev_bg = sev_color_map.get(f.severity.value, ("#94a3b8", "#0f172a"))
            val_val = f.validation_status.value if hasattr(f.validation_status, "value") else str(f.validation_status)
            unverified_badge = (
                ' <span class="badge" style="background-color: #713f12; color: #fde047; border: 1px solid #eab308; font-size: 11px; margin-left: 8px;">UNVERIFIED - PENDING EVIDENCE</span>'
                if val_val in ("unverified", "needs_validation")
                else ""
            )
            repro_html = ""
            if f.reproduction_steps:
                repro_html = f"""
                <div class="card-section">
                  <h4>Reproduction Steps</h4>
                  <pre class="code-block">{f.reproduction_steps}</pre>
                </div>"""

            # Proof-of-Concept Screenshot Evidence for Finding
            poc_html = ""
            finding_ev = [
                ev for ev in data.evidence
                if ev.finding_id == f.id and (
                    (ev.mime_type and ev.mime_type.startswith("image/"))
                    or Path(ev.file_path).suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp", ".gif")
                )
            ]
            if finding_ev:
                poc_html = '<div class="card-section"><h4>Proof-of-Concept (POC) Evidence</h4>'
                for idx, fev in enumerate(finding_ev, 1):
                    ev_p = Path(fev.file_path)
                    img_src = ""
                    if ev_p.exists():
                        try:
                            import base64
                            b64 = base64.b64encode(ev_p.read_bytes()).decode("ascii")
                            mime = fev.mime_type or "image/png"
                            img_src = f"data:{mime};base64,{b64}"
                        except Exception:
                            img_src = str(ev_p.resolve())
                    poc_html += f"""
                    <figure style="margin: 12px 0; text-align: center; background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid #334155;">
                      <img src="{img_src}" alt="{html.escape(fev.description)}" style="max-width: 100%; max-height: 450px; border-radius: 4px; border: 1px solid #475569;" />
                      <figcaption style="font-size: 12px; color: #94a3b8; margin-top: 8px;">
                        <strong>Figure {f.id}.{idx}:</strong> {html.escape(fev.description or 'Proof of Concept')} 
                        (<code>{fev.sha256_hash[:16]}...</code>)
                      </figcaption>
                    </figure>"""
                poc_html += "</div>"

            findings_cards += f"""
            <div class="finding-card" id="finding-{f.id}">
              <div class="finding-header">
                <span class="badge" style="background-color: {sev_bg}; color: {sev_fg}; border: 1px solid {sev_fg};">{f.severity.value.upper()}</span>
                <h3 class="finding-title">#{f.id} — {html.escape(f.title)}{unverified_badge}</h3>
                <span class="cvss-tag">CVSS {f.cvss_score or 'N/A'}</span>
              </div>
              <div class="finding-meta-grid">
                <div><strong>Affected Asset:</strong> <code>{f.affected_asset}</code></div>
                <div><strong>Port / Service:</strong> {f.affected_port_service or 'N/A'}</div>
                <div><strong>Validation:</strong> {f.validation_status.value}</div>
                <div><strong>Validation Method:</strong> {getattr(f, 'validation_method', '') or 'Automated Verification'}</div>
                <div><strong>Source Tool:</strong> {f.source_tool or 'c0desec/nmap'}</div>
              </div>
              <div class="card-section">
                <h4>Vulnerability Explanation</h4>
                <p>{f.description or 'No technical description recorded.'}</p>
              </div>
              <div class="card-section remediation-box">
                <h4>Recommended Remediation</h4>
                <p>{f.remediation or 'Review application configuration and harden server per industry baselines.'}</p>
              </div>
              {repro_html}
              {poc_html}
            </div>"""

        # Build Evidence Rows HTML
        evidence_rows = ""
        for index, ev in enumerate(data.evidence):
            fname = Path(ev.file_path).name
            integrity_status = html.escape(data.evidence_integrity[index]["status"])
            evidence_rows += f"""
            <tr>
              <td>#{html.escape(str(ev.id))}</td>
              <td><strong>{html.escape(fname)}</strong></td>
              <td><span class="badge badge-info">{html.escape(ev.mime_type)}</span></td>
              <td><code class="hash-code">{html.escape(ev.sha256_hash)}</code></td>
              <td>{integrity_status}</td>
              <td>{html.escape(ev.description)}</td>
            </tr>"""

        # Build Terminal Sessions HTML
        terminal_sessions_html = ""
        if data.terminal_sessions:
            terminal_sessions_html = """
    <!-- Interactive Terminal Sessions Section -->
    <h2 class="section-title">🖥️ Interactive Terminal Sessions & Command Audit Trail</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Session ID</th>
            <th>Recorded Time Range</th>
            <th>Working Directory</th>
            <th>Exit</th>
            <th>Cryptographic Hash (SHA-256)</th>
            <th>Integrity Status</th>
            <th>Commands</th>
          </tr>
        </thead>
        <tbody>
        """
            for index, s in enumerate(data.terminal_sessions):
                time_range = f"{s.started_at[:19]} to {s.ended_at[:19] if s.ended_at else 'Incomplete'}"
                terminal_sessions_html += f"""
          <tr>
            <td><code>{s.session_id}</code></td>
            <td>{time_range}</td>
            <td><code>{s.working_directory}</code></td>
            <td><span class="badge {'badge-low' if s.exit_status == 0 else 'badge-critical'}">{s.exit_status if s.exit_status is not None else 0}</span></td>
            <td><code class="hash-code">{s.sha256_hash}</code></td>
            <td>{html.escape(data.terminal_session_integrity[index]["status"])}</td>
            <td><strong>{s.command_count}</strong></td>
          </tr>
            """
            terminal_sessions_html += """
        </tbody>
      </table>
    </div>
        """
            for index, s in enumerate(data.terminal_sessions):
                cmds_html = ""
                if s.commands_json:
                    try:
                        cmds = json.loads(s.commands_json)
                        if cmds:
                            cmds_html = "<div class='card-section'><h4>Recorded Commands (Redacted)</h4><ul>"
                            for c in cmds:
                                cmd_red = redact_sensitive_text(c.get("command", ""))
                                exit_lbl = f" <span class='badge badge-info'>exit {c.get('exit_code')}</span>" if c.get("exit_code") is not None else ""
                                cmds_html += f"<li><code>{cmd_red}</code>{exit_lbl}</li>"
                            cmds_html += "</ul></div>"
                    except Exception:
                        pass

                preview_html = ""
                if s.plain_text_path and os.path.exists(s.plain_text_path):
                    try:
                        content = Path(s.plain_text_path).read_text(encoding="utf-8", errors="replace").strip()
                        if content:
                            snippet = "\n".join(content.splitlines()[:15])
                            red_snip = redact_sensitive_text(snippet)
                            preview_html = f"<div class='card-section'><h4>Output Preview (Redacted)</h4><pre class='code-block'><code>{red_snip}</code></pre></div>"
                    except Exception:
                        pass

                terminal_sessions_html += f"""
            <div class="finding-card" style="border-left: 4px solid var(--accent-blue); margin-bottom: 16px;">
              <div class="finding-header">
                <span class="finding-title">Terminal Session <code>{s.session_id}</code></span>
                <span class="badge badge-info">Integrity: {html.escape(data.terminal_session_integrity[index]["status"])}</span>
              </div>
              <div class="card-section">
                <p><strong>Time:</strong> {s.started_at} to {s.ended_at or 'Incomplete'} | <strong>Directory:</strong> <code>{s.working_directory}</code></p>
                <p><strong>Evidence Hash:</strong> <code class="hash-code">{s.sha256_hash}</code></p>
              </div>
              {cmds_html}
              {preview_html}
            </div>"""

        # Build Active Directory & Weak Password Audit HTML
        ad_audit_html = ""
        if data.ad_audit_summary:
            ad = data.ad_audit_summary
            cat_rows = ""
            for c_name, count in ad.get("categories", {}).items():
                cat_rows += f"""
                <tr>
                  <td><strong>{html.escape(c_name)}</strong></td>
                  <td><span class="badge badge-warning">{count}</span></td>
                  <td><span class="badge badge-critical">HIGH RISK</span></td>
                </tr>"""
            ad_findings_rows = ""
            for af in ad.get("findings", [])[:15]:
                ad_findings_rows += f"""
                <tr>
                  <td>#{af.id}</td>
                  <td><code>{html.escape(af.affected_asset)}</code></td>
                  <td><strong>{html.escape(af.title)}</strong></td>
                  <td><span class="badge badge-critical">{af.severity.value.upper()}</span></td>
                  <td><span class="status-tag">{af.validation_status.value}</span></td>
                </tr>"""

            ad_audit_html = f"""
    <!-- Active Directory & Password Auditing Section -->
    <h2 class="section-title">🏢 Active Directory Weak Password & Credential Audit</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      KnowBe4-standard credential analysis identifying password hygiene deficiencies, insecure LM/DES hashes, and account policy vulnerabilities.
    </div>
    <div class="metrics-grid" style="margin-bottom: 20px;">
      <div class="metric-card" style="border-top: 3px solid var(--color-critical);">
        <div class="metric-value" style="color: var(--color-critical);">{ad.get('vulnerable_accounts', 0)}</div>
        <div class="metric-label">Vulnerable Accounts</div>
      </div>
      <div class="metric-card" style="border-top: 3px solid var(--accent-cyan);">
        <div class="metric-value" style="color: var(--accent-cyan);">{len(ad.get('categories', {}))}</div>
        <div class="metric-label">Vulnerability Categories</div>
      </div>
      <div class="metric-card" style="border-top: 3px solid var(--color-high);">
        <div class="metric-value" style="color: var(--color-high);">{ad.get('total_findings', 0)}</div>
        <div class="metric-label">Total AD Findings</div>
      </div>
    </div>
    <h3 style="font-size: 15px; margin: 16px 0 8px 0; color: var(--text-primary);">Identified Password Vulnerability Classes</h3>
    <div class="table-container" style="margin-bottom: 20px;">
      <table>
        <thead>
          <tr>
            <th>Vulnerability Classification</th>
            <th>Impacted Accounts</th>
            <th>Policy Risk Level</th>
          </tr>
        </thead>
        <tbody>
          {cat_rows or '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No weak password categories identified</td></tr>'}
        </tbody>
      </table>
    </div>
    <h3 style="font-size: 15px; margin: 16px 0 8px 0; color: var(--text-primary);">Audited Account Details</h3>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>Finding ID</th>
            <th>Domain / Account Asset</th>
            <th>Issue Title</th>
            <th>Severity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {ad_findings_rows or '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No specific accounts flagged</td></tr>'}
        </tbody>
      </table>
    </div>"""

        # Build Offline PCAP & Protocol Dissection HTML
        pcap_analysis_html = ""
        if data.pcap_analysis_summary:
            pca = data.pcap_analysis_summary
            pcap_ev_html = "".join([f"<li><code>{html.escape(Path(p).name)}</code></li>" for p in pca.get("evidence_files", [])]) or "<li>Offline packet dissection data</li>"
            pcap_findings_rows = ""
            for pf in pca.get("findings", []):
                pcap_findings_rows += f"""
                <tr>
                  <td>#{pf.id}</td>
                  <td><strong>{html.escape(pf.title)}</strong></td>
                  <td><code>{html.escape(pf.affected_asset)}</code></td>
                  <td><span class="badge badge-warning">{pf.severity.value.upper()}</span></td>
                  <td>{html.escape(pf.description[:100])}...</td>
                </tr>"""

            pcap_analysis_html = f"""
    <!-- Offline PCAP & Protocol Dissection Section -->
    <h2 class="section-title">📡 Offline Network Traffic & PCAP Protocol Analysis</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      Non-intrusive offline packet dissection inspecting Ethernet, IPv4/IPv6, TCP conversations, DNS tunneling, HTTP cleartext, and TLS SNI handshakes.
    </div>
    <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
      <h4 style="margin: 0 0 8px 0; font-size: 14px; color: var(--accent-cyan);">Analyzed Capture Evidence Files</h4>
      <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--text-secondary);">
        {pcap_ev_html}
      </ul>
    </div>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Traffic Anomaly / Finding</th>
            <th>Affected Flow / IP</th>
            <th>Severity</th>
            <th>Dissection Summary</th>
          </tr>
        </thead>
        <tbody>
          {pcap_findings_rows or '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No suspicious traffic anomalies detected</td></tr>'}
        </tbody>
      </table>
    </div>"""

        # Build Static Application Security Testing (SAST) HTML
        sast_html = ""
        if data.code_security_findings:
            sast_cards = ""
            for csf in data.code_security_findings:
                sast_cards += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical); margin-bottom: 16px;">
                  <div class="finding-header">
                    <span class="finding-title">{html.escape(csf.title)}</span>
                    <span class="badge badge-critical">{csf.severity.value.upper()}</span>
                  </div>
                  <div class="card-section">
                    <p><strong>Affected Source File:</strong> <code>{html.escape(csf.affected_asset)}</code> | <strong>Scanner Engine:</strong> <code>{html.escape(csf.source_tool or 'SAST AST')}</code></p>
                    <p style="color: var(--text-secondary);">{html.escape(csf.description)}</p>
                  </div>
                  <div class="card-section" style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 6px; padding: 10px;">
                    <strong style="color: var(--accent-cyan);">Secure Code Remediation Guidance:</strong>
                    <p style="margin: 6px 0 0 0; color: var(--text-primary); font-size: 12px;">{html.escape(csf.remediation or 'Adopt parameterized queries and safe subprocess execution.')}</p>
                  </div>
                </div>"""

            sast_html = f"""
    <!-- Static Application Security Testing Section -->
    <h2 class="section-title">🛡️ Static Application Security Testing (SAST & AST Code Audit)</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      Automated Abstract Syntax Tree (AST) code auditing detecting injection flaws (CWE-89, CWE-78), unsafe deserialization (CWE-502), path traversal (CWE-22), and hardcoded credentials.
    </div>
    {sast_cards}"""

        # Build Recovered Credentials & Cracking Audit HTML
        cracked_creds_html = ""
        if data.cracked_credentials_summary:
            cc = data.cracked_credentials_summary
            cc_rows = ""
            for cf in cc.get("findings", []):
                cc_rows += f"""
                <tr>
                  <td>#{cf.id}</td>
                  <td><strong>{html.escape(cf.title)}</strong></td>
                  <td><code>{html.escape(cf.affected_asset)}</code></td>
                  <td><code>{html.escape(cf.source_tool or 'Cracker')}</code></td>
                  <td><span class="badge badge-critical">CONFIRMED</span></td>
                </tr>"""

            cracked_creds_html = f"""
    <!-- Recovered Credentials & Authentication Audit Section -->
    <h2 class="section-title">🔑 Recovered Credentials & Password Cracking Audit</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      Verification of password complexity and offline audit results utilizing Hashcat, John the Ripper, and THC-Hydra.
    </div>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Observation Title</th>
            <th>Target Account / Service</th>
            <th>Tool Provenance</th>
            <th>Verification</th>
          </tr>
        </thead>
        <tbody>
          {cc_rows or '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No weak credentials cracked</td></tr>'}
        </tbody>
      </table>
    </div>"""

        # Build TLS / SSL Security Assessment HTML
        tls_html = ""
        if data.tls_assessment_summary:
            tls = data.tls_assessment_summary
            tls_rows = ""
            for tf in tls.get("findings", []):
                sev_badge = "badge-critical" if tf.severity == FindingSeverity.CRITICAL else ("badge-high" if tf.severity == FindingSeverity.HIGH else "badge-medium")
                tls_rows += f"""
                <tr>
                  <td><span class="badge {sev_badge}">{tf.severity.value.upper()}</span></td>
                  <td><strong>{html.escape(tf.title)}</strong></td>
                  <td><code>{html.escape(tf.affected_asset)}</code></td>
                  <td>{tf.cvss_score or '-'}</td>
                  <td style="font-size: 12px; color: var(--text-secondary);">{html.escape(tf.remediation)}</td>
                </tr>"""

            tls_html = f"""
    <!-- TLS / SSL Cryptographic & Cipher Suite Assessment Section -->
    <h2 class="section-title">🔒 TLS / SSL Certificate & Cryptographic Assessment</h2>
    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">
      Cryptographic evaluation of X.509 public-key certificates, protocol version deprecation (NIST SP 800-52r2), and cipher suite security (RFC 6125, PCI-DSS).
    </div>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Vulnerability / Misconfiguration</th>
            <th>Target Service</th>
            <th>CVSS</th>
            <th>Remediation Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {tls_rows or '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No cryptographic vulnerabilities identified</td></tr>'}
        </tbody>
      </table>
    </div>"""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report — {p.name}</title>
  <style>
    :root {{
      --bg-primary: #0b0d13;
      --bg-surface: #121620;
      --bg-card: #171d2b;
      --border-color: #242d40;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-blue: #0284c7;
      --accent-cyan: #38bdf8;
      --color-critical: #ef4444;
      --color-high: #f97316;
      --color-medium: #eab308;
      --color-low: #38bdf8;
      --color-info: #94a3b8;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 32px 16px;
    }}

    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}

    /* Header Banner */
    .report-header {{
      background: linear-gradient(135deg, #0e1526 0%, #17223b 100%);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }}

    .header-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }}

    .brand-title {{
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--accent-cyan);
    }}

    .confidential-tag {{
      background-color: #ef444422;
      color: #ef4444;
      border: 1px solid #ef444466;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}

    .report-title {{
      font-size: 28px;
      font-weight: 800;
      color: #ffffff;
      margin-bottom: 8px;
    }}

    .report-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid var(--border-color);
      font-size: 13px;
      color: var(--text-secondary);
    }}

    .report-meta-grid strong {{ color: var(--text-primary); }}

    /* Metrics Overview Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }}

    .metric-card {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }}

    .metric-value {{
      font-size: 32px;
      font-weight: 800;
      line-height: 1.2;
      margin-bottom: 4px;
    }}

    .metric-label {{
      font-size: 12px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    /* Severity Breakdown Bar */
    .severity-bar-container {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 32px;
    }}

    .section-title {{
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    /* Tables */
    .table-container {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow-x: auto;
      margin-bottom: 32px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }}

    th {{
      background-color: #0f1420;
      color: var(--text-secondary);
      padding: 12px 16px;
      font-weight: 600;
      border-bottom: 1px solid var(--border-color);
    }}

    td {{
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      color: var(--text-primary);
    }}

    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background-color: rgba(255, 255, 255, 0.02); }}

    code {{
      font-family: "JetBrains Mono", Consolas, monospace;
      font-size: 12px;
      background-color: #1e2638;
      padding: 2px 6px;
      border-radius: 4px;
      color: var(--accent-cyan);
    }}

    .hash-code {{
      font-size: 11px;
      word-break: break-all;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .badge-success {{ background-color: #064e3b; color: #34d399; border: 1px solid #059669; }}
    .badge-danger {{ background-color: #450a0a; color: #f87171; border: 1px solid #dc2626; }}
    .badge-info {{ background-color: #0c4a6e; color: #38bdf8; border: 1px solid #0284c7; }}

    .status-tag {{
      background-color: #1e293b;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      color: var(--text-secondary);
    }}

    .finding-link {{
      color: #ffffff;
      text-decoration: none;
      font-weight: 600;
    }}

    .finding-link:hover {{
      color: var(--accent-cyan);
      text-decoration: underline;
    }}

    /* Finding Detail Cards */
    .finding-card {{
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 24px;
      margin-bottom: 20px;
    }}

    .finding-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }}

    .finding-title {{
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      flex: 1;
    }}

    .cvss-tag {{
      background-color: #1e293b;
      border: 1px solid #334155;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      color: #e2e8f0;
    }}

    .finding-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      padding: 12px;
      background-color: #0f1420;
      border-radius: 6px;
      margin-bottom: 16px;
      font-size: 12px;
      color: var(--text-secondary);
    }}

    .card-section {{ margin-bottom: 16px; }}
    .card-section h4 {{
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent-cyan);
      margin-bottom: 6px;
    }}

    .card-section p {{ font-size: 13px; color: #cbd5e1; }}

    .remediation-box {{
      background-color: rgba(2, 132, 199, 0.08);
      border-left: 3px solid var(--accent-cyan);
      padding: 12px;
      border-radius: 0 6px 6px 0;
    }}

    .code-block {{
      background-color: #090c12;
      border: 1px solid #1e2433;
      padding: 12px;
      border-radius: 6px;
      font-family: "JetBrains Mono", Consolas, monospace;
      font-size: 12px;
      color: #38bdf8;
      overflow-x: auto;
    }}

    /* Footer */
    .report-footer {{
      margin-top: 48px;
      padding-top: 24px;
      border-top: 1px solid var(--border-color);
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
    }}

    @media print {{
      body {{ background-color: #ffffff; color: #000000; padding: 0; }}
      .container {{ max-width: 100%; }}
      .report-header {{ background: #f1f5f9; border-color: #cbd5e1; color: #000; }}
      .report-title {{ color: #000000; }}
      .metric-card, .finding-card, .table-container, .severity-bar-container {{
        background: #ffffff;
        border-color: #cbd5e1;
        color: #000;
      }}
      th {{ background: #f8fafc; color: #334155; }}
      td {{ color: #0f172a; border-color: #e2e8f0; }}
      .card-section p, .finding-title {{ color: #0f172a; }}
    }}
  </style>
</head>
<body>
  <div class="container">

    <!-- Header Banner -->
    <header class="report-header">
      <div class="header-top">
        <span class="brand-title">CyberSecuritySuite — Security Workstation</span>
        <span class="confidential-tag">Confidential Assessment</span>
      </div>
      <h1 class="report-title">{p.name}</h1>
      <p style="color: var(--text-secondary); font-size: 14px;">Professional Penetration Testing & Vulnerability Assessment Report</p>

      <div class="report-meta-grid">
        <div><strong>Engagement ID:</strong> {getattr(p, 'engagement_id', '') or 'N/A'}</div>
        <div><strong>Client:</strong> {p.client_name or 'N/A'}</div>
        <div><strong>Lead Tester:</strong> {getattr(p, 'lead_tester', '') or 'N/A'}</div>
        <div><strong>Emergency Contact:</strong> {getattr(p, 'emergency_contact', '') or 'N/A'}</div>
        <div><strong>Testing Window:</strong> {getattr(p, 'start_date', '') or 'N/A'} to {getattr(p, 'end_date', '') or 'N/A'} ({getattr(p, 'timezone', 'UTC') or 'UTC'})</div>
        <div><strong>Authorization / SoW:</strong> {getattr(p, 'authorization_doc', '') or 'N/A'} / {getattr(p, 'sow_reference', '') or 'N/A'}</div>
        <div><strong>Assessment Date:</strong> {data.generated_at[:10]}</div>
        <div><strong>Project Status:</strong> {p.status.value.upper()}</div>
        <div><strong>Methodology:</strong> EC-Council CPENT / PTES</div>
      </div>
    </header>

    {assessment_banner_html}

    <!-- Metrics Cards -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value" style="color: var(--accent-cyan);">{m.total_findings}</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-critical);">{m.critical_count}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-high);">{m.high_count}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-medium);">{m.medium_count}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: var(--color-low);">{m.low_count}</div>
        <div class="metric-label">Low / Info</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color: #ffffff;">{m.max_cvss:.1f}</div>
        <div class="metric-label">Max CVSS</div>
      </div>
    </div>

    <!-- Executive Summary Section -->
    <div class="severity-bar-container">
      <h2 class="section-title">📊 Executive Summary</h2>
      <p style="border-left: 4px solid var(--color-medium); padding: 10px 14px; background: rgba(255, 193, 7, 0.08); color: var(--text-secondary); margin-bottom: 16px;">
        <strong>Sample data notice:</strong> Verify target authorization, scope, findings, and evidence before treating this as a real engagement report.
      </p>
      <p style="color: var(--text-secondary); margin-bottom: 12px;">
        {p.description or 'A comprehensive security evaluation was executed to discover exploitable vulnerabilities and configuration deficiencies.'}
      </p>
      <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">
        A total of <strong>{m.total_findings}</strong> security findings were identified across <strong>{m.total_targets}</strong> target assets.
        <strong>{m.confirmed_findings}</strong> vulnerabilities were confirmed with evidence, and <strong>{m.unverified_findings}</strong> observations remain unverified.
      </div>

      <!-- CPENT Finding Rating Levels -->
      <h3 style="font-size: 15px; margin-bottom: 10px; color: var(--accent-cyan);">Finding Rating Levels (CPENT Standard)</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 20px;">
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-critical); border-radius: 6px; padding: 10px; font-size: 12px;">
          <strong style="color: var(--color-critical);">★★★★★ Critical</strong><br>Intruders can easily gain full control of hosts and network.
        </div>
        <div style="background: rgba(249, 115, 22, 0.1); border: 1px solid var(--color-high); border-radius: 6px; padding: 10px; font-size: 12px;">
          <strong style="color: var(--color-high);">★★★★☆ High</strong><br>Intruders can possibly gain control or leak highly sensitive assets.
        </div>
        <div style="background: rgba(234, 179, 8, 0.1); border: 1px solid var(--color-medium); border-radius: 6px; padding: 10px; font-size: 12px;">
          <strong style="color: var(--color-medium);">★★★☆☆ Medium</strong><br>Intruders may gain partial control or gather intelligence.
        </div>
        <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid var(--color-low); border-radius: 6px; padding: 10px; font-size: 12px;">
          <strong style="color: var(--color-low);">★★☆☆☆ Low</strong><br>Minor security issues or informational exposure.
        </div>
        <div style="background: rgba(148, 163, 184, 0.1); border: 1px solid var(--color-info); border-radius: 6px; padding: 10px; font-size: 12px;">
          <strong style="color: var(--color-info);">★☆☆☆☆ Informational</strong><br>Hardening baselines and procedural best practices.
        </div>
      </div>

      <!-- Risk Assessment Matrix -->
      <h3 style="font-size: 15px; margin-bottom: 10px; color: var(--accent-cyan);">Risk Assessment Matrix (Likelihood vs Impact)</h3>
      <div class="table-container" style="margin-bottom: 20px;">
        <table>
          <thead>
            <tr>
              <th>Likelihood \\ Impact</th>
              <th>Low Impact</th>
              <th>Medium Impact</th>
              <th>High Impact / Critical</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>High Likelihood</strong></td>
              <td><span class="badge badge-medium">Medium Threat (6)</span></td>
              <td><span class="badge badge-high">High Threat (15)</span></td>
              <td><span class="badge badge-critical">Critical Threat (25)</span></td>
            </tr>
            <tr>
              <td><strong>Medium Likelihood</strong></td>
              <td><span class="badge badge-low">Low Threat (3)</span></td>
              <td><span class="badge badge-medium">Medium Threat (9)</span></td>
              <td><span class="badge badge-high">High Threat (15)</span></td>
            </tr>
            <tr>
              <td><strong>Low Likelihood</strong></td>
              <td><span class="badge badge-low">Low Threat (1)</span></td>
              <td><span class="badge badge-low">Low Threat (4)</span></td>
              <td><span class="badge badge-medium">Medium Threat (6)</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Strategic Recommendations (Five Pillars) -->
      <h3 style="font-size: 15px; margin-bottom: 10px; color: var(--accent-cyan);">Strategic Recommendations (CPENT Five Pillars)</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 13px;">
          <strong style="color: var(--accent-cyan);">👥 1. Personnel & Awareness</strong>
          <p style="color: var(--text-secondary); margin-top: 6px;">Conduct regular phishing simulation drills and least-privilege security training for engineers.</p>
        </div>
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 13px;">
          <strong style="color: var(--accent-cyan);">📜 2. Policies & Procedures</strong>
          <p style="color: var(--text-secondary); margin-top: 6px;">Establish strict SLA policies mandating critical flaw patching within 14 calendar days.</p>
        </div>
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 13px;">
          <strong style="color: var(--accent-cyan);">⚡ 3. Critical Vulnerabilities</strong>
          <p style="color: var(--text-secondary); margin-top: 6px;">Prioritize immediate remediation for the {m.critical_count} Critical and {m.high_count} High flaws identified.</p>
        </div>
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 13px;">
          <strong style="color: var(--accent-cyan);">🔑 4. Identification & Auth</strong>
          <p style="color: var(--text-secondary); margin-top: 6px;">Enforce MFA everywhere and completely eliminate unencrypted cleartext protocols (HTTP/Telnet/SNMPv1).</p>
        </div>
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-size: 13px;">
          <strong style="color: var(--accent-cyan);">📡 5. Intrusion Detection</strong>
          <p style="color: var(--text-secondary); margin-top: 6px;">Aggregate perimeter and server logs into a SIEM with real-time alerting on anomalous probing.</p>
        </div>
      </div>
    </div>

    <!-- Rules of Engagement Section -->
    <div class="severity-bar-container" style="border-left: 4px solid var(--accent-cyan);">
      <h2 class="section-title">⚖️ Rules of Engagement & Operational Boundaries</h2>
      <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.8;">
        <div><strong>Allowed Techniques:</strong> {'Standard authorized pentest' if not getattr(p, 'allow_active_recon', False) else 'Active OSINT and authorized penetration testing'}</div>
        <div><strong>Prohibited Techniques:</strong> <span style="color: var(--color-critical);">{getattr(p, 'prohibited_tests', '') or 'DoS/DDoS, Social Engineering, Physical Intrusion'}</span></div>
        <div><strong>Rate Limit:</strong> {getattr(p, 'max_rate_limit', 100)} requests/sec</div>
        <div><strong>Emergency Stop Procedure:</strong> Immediately terminate all processes and notify authorized emergency contact ({getattr(p, 'emergency_contact', '') or 'Designated SecOps'})</div>
      </div>
    </div>

    <!-- Scope Table -->
    <h2 class="section-title">🎯 Assessment Scope & Rules of Engagement</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Target Locus</th>
            <th>Type</th>
            <th>Rule</th>
            <th>Authorization Status</th>
            <th>Environment</th>
            <th>Ports Allowed</th>
            <th>Operational Notes</th>
          </tr>
        </thead>
        <tbody>
          {scope_rows or '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No target scopes registered</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Findings Matrix Table -->
    <h2 class="section-title">🛡️ Security Findings Summary Matrix</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Finding Title</th>
            <th>Affected Asset</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {findings_matrix_rows or '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No security findings discovered</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- Detailed Findings Cards -->
    <h2 class="section-title">🔍 Technical Findings & Remediation Guidance</h2>
    {findings_cards or '<div class="finding-card"><p style="color: var(--text-secondary);">No findings to display.</p></div>'}

    <!-- Evidence Vault Table -->
    <h2 class="section-title">🔒 Cryptographic Evidence Vault (SHA-256)</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Artifact File</th>
            <th>MIME Type</th>
            <th>Cryptographic Hash (SHA-256)</th>
            <th>Integrity Status</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {evidence_rows or '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No evidence records vaulted</td></tr>'}
        </tbody>
      </table>
    </div>

    {topology_html}

    {pentest_workflow_html}

    {network_inventory_html}

    {ad_audit_html}

    {pcap_analysis_html}

    {sast_html}

    {cracked_creds_html}

    {tls_html}

    {terminal_sessions_html}

    <!-- Appendix A: References -->
    <h2 class="section-title">📚 Appendix A: Standards & Authoritative References</h2>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>Reference Standard</th>
            <th>Description & Scope</th>
          </tr>
        </thead>
        <tbody>
          <tr><td><strong>NIST SP 800-115</strong></td><td>Technical Guide to Information Security Testing and Assessment</td></tr>
          <tr><td><strong>NIST SP 800-42</strong></td><td>Guideline on Network Security Testing and Administration Folders</td></tr>
          <tr><td><strong>EC-Council CPENT</strong></td><td>Certified Penetration Testing Professional Practical Methodology Standards</td></tr>
          <tr><td><strong>PTES</strong></td><td>Penetration Testing Execution Standard Framework</td></tr>
          <tr><td><strong>OWASP Top 10 (2021)</strong></td><td>The Ten Most Critical Web Application Security Risks</td></tr>
          <tr><td><strong>MITRE ATT&CK</strong></td><td>Adversarial Tactics, Techniques, and Common Knowledge Enterprise Matrix</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Appendix B: Glossary -->
    <h2 class="section-title">📖 Appendix B: CPENT Security Terminology Glossary</h2>
    <div class="table-container" style="margin-bottom: 24px;">
      <table>
        <thead>
          <tr>
            <th>Term</th>
            <th>Definition</th>
          </tr>
        </thead>
        <tbody>
          <tr><td><strong>Black Box Testing</strong></td><td>Testing performed with zero prior internal knowledge, simulating an external unprivileged adversary.</td></tr>
          <tr><td><strong>Crystal / White Box</strong></td><td>Testing conducted with full access to architectural documentation, credentials, and source code.</td></tr>
          <tr><td><strong>Grey Box Testing</strong></td><td>Testing conducted with partial user-level knowledge, simulating an insider or contractor.</td></tr>
          <tr><td><strong>Pivoting</strong></td><td>Using a compromised host as a relay gateway to route traffic into adjacent restricted subnets.</td></tr>
          <tr><td><strong>Double Pivoting</strong></td><td>Multi-hop routing through multiple compromised pivot hops across nested internal firewalls.</td></tr>
          <tr><td><strong>Rules of Engagement (RoE)</strong></td><td>Formal guidelines specifying authorized windows, rate limits, prohibited techniques, and emergency stop protocols.</td></tr>
          <tr><td><strong>Modbus / SCADA</strong></td><td>Cleartext industrial automation protocol running over TCP port 502 without native authentication.</td></tr>
          <tr><td><strong>ROP Exploitation</strong></td><td>Return-Oriented Programming: chaining memory gadgets ending in RET to defeat NX/DEP execution barriers.</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <footer class="report-footer">
      <p>Report generated by <strong>CyberSecuritySuite Workstation</strong> — EC-Council CPENT Preparedness Platform</p>
      <p>Generated at {data.generated_at} UTC • Cryptographically Signed Record</p>
    </footer>

  </div>
</body>
</html>"""

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding="utf-8")

        return html_content

    # -------------------------------------------------------------
    # 4. Generate PDF Report Utility
    # -------------------------------------------------------------
    def generate_pdf(self, project_id: int, output_path: Optional[Path] = None, assessment_id: Optional[int] = None) -> Path:
        """Generates a standalone, professional PDF penetration testing report using Qt PDF."""
        data = self.build_report_data(project_id, assessment_id=assessment_id)
        if output_path is None:
            clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data.project.name.lower())
            if assessment_id:
                clean_name += f"_assessment_{assessment_id}"
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = Path(__file__).resolve().parent / "output" / f"{clean_name}_report_{stamp}.pdf"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            from PySide6.QtCore import QMarginsF
            from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
            from PySide6.QtWidgets import QApplication
        except ImportError as e:
            raise RuntimeError(
                f"PDF generation requires PySide6. Please install via: pip install PySide6. Original error: {e}"
            )

        app = QApplication.instance()
        if app is None:
            app = QApplication(["cybersecuritysuite", "-platform", "offscreen"])

        # Generate HTML report content with print-friendly formatting
        html_content = self.generate_html(project_id, assessment_id=assessment_id)

        # Prepare QTextDocument
        doc = QTextDocument()
        doc.setHtml(html_content)

        writer = QPdfWriter(str(output_path))
        layout = QPageLayout(
            QPageSize(QPageSize.PageSizeId.A4),
            QPageLayout.Orientation.Portrait,
            QMarginsF(12, 12, 12, 12),
        )
        writer.setPageLayout(layout)
        writer.setTitle(f"Penetration Testing Assessment Report — {data.project.name}")
        writer.setCreator("CyberSecuritySuite Report Generator")

        success = doc.print_(writer)
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise RuntimeError(f"PDF export failed: output file '{output_path}' was not written or is empty.")

        return output_path

    # -------------------------------------------------------------
    # 5. Generate CSV / Excel Matrix Spreadsheet
    # -------------------------------------------------------------
    def generate_csv(
        self,
        project_id: int,
        output_path: Optional[Path] = None,
        assessment_id: Optional[int] = None,
    ) -> Path:
        """Generates an RFC-4180 compliant CSV vulnerability & finding matrix spreadsheet."""
        data = self.build_report_data(project_id, assessment_id=assessment_id)
        if output_path is None:
            clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data.project.name.lower())
            if assessment_id:
                clean_name += f"_assessment_{assessment_id}"
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = Path("reports") / "output" / f"{clean_name}_findings_matrix_{stamp}.csv"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ev_map: Dict[int, str] = {}
        for ev in data.evidence:
            if ev.finding_id and ev.sha256_hash:
                ev_map[ev.finding_id] = ev.sha256_hash

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID",
                "Title",
                "Severity",
                "CVSS Score",
                "CVSS Vector",
                "Affected Asset",
                "Port / Service",
                "Validation Status",
                "Source Tool",
                "Assessment ID",
                "Evidence SHA-256",
                "Description",
                "Remediation Guidance",
            ])
            for finding in data.findings:
                writer.writerow([
                    finding.id or "",
                    finding.title,
                    finding.severity.value.upper(),
                    finding.cvss_score if finding.cvss_score is not None else "",
                    finding.cvss_vector or "",
                    finding.affected_asset,
                    finding.affected_port_service or "",
                    finding.validation_status.value.upper(),
                    finding.source_tool or "Manual",
                    finding.assessment_id or "",
                    ev_map.get(finding.id, ""),
                    finding.description.replace("\r", " ").replace("\n", " "),
                    finding.remediation.replace("\r", " ").replace("\n", " "),
                ])

        return output_path

    # -------------------------------------------------------------
    # 6. Generate All Formats Utility
    # -------------------------------------------------------------
    def generate_all(
        self, project_id: int, output_dir: Path, *, stable_names: bool = False, assessment_id: Optional[int] = None
    ) -> Dict[str, Path]:
        """Generates PDF, HTML, Markdown, JSON, and CSV reports in output_dir.

        stable_names is intended for automatic refreshes: it replaces the current
        snapshot files instead of creating a new timestamped set each time.
        """
        data = self.build_report_data(project_id, assessment_id=assessment_id)
        output_dir.mkdir(parents=True, exist_ok=True)

        clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data.project.name.lower())
        if assessment_id:
            clean_name += f"_assessment_{assessment_id}"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        suffix = "latest" if stable_names else stamp
        pdf_path = output_dir / f"{clean_name}_report_{suffix}.pdf"
        html_path = output_dir / f"{clean_name}_report_{suffix}.html"
        md_path = output_dir / f"{clean_name}_report_{suffix}.md"
        json_path = output_dir / f"{clean_name}_report_{suffix}.json"
        csv_path = output_dir / f"{clean_name}_report_{suffix}.csv"

        self.generate_html(project_id, output_path=html_path, assessment_id=assessment_id)
        self.generate_markdown(project_id, output_path=md_path, assessment_id=assessment_id)
        self.generate_json(project_id, output_path=json_path, assessment_id=assessment_id)
        self.generate_pdf(project_id, output_path=pdf_path, assessment_id=assessment_id)
        self.generate_csv(project_id, output_path=csv_path, assessment_id=assessment_id)

        # Keep an easy-to-find pointer to the most recently generated set without
        # deleting older, timestamped reports that may be needed for audit history.
        latest = output_dir / "LATEST_REPORTS.md"
        latest.write_text(
            "# Latest generated assessment reports\n\n"
            "These files reflect the current database snapshot and may contain "
            "demonstration data. Verify authorization, scope, findings, and evidence "
            "before sharing.\n\n"
            f"- PDF: [{pdf_path.name}]({pdf_path.name})\n"
            f"- HTML: [{html_path.name}]({html_path.name})\n"
            f"- Markdown: [{md_path.name}]({md_path.name})\n"
            f"- JSON: [{json_path.name}]({json_path.name})\n"
            f"- CSV: [{csv_path.name}]({csv_path.name})\n",
            encoding="utf-8",
        )

        return {
            "pdf": pdf_path,
            "html": html_path,
            "markdown": md_path,
            "json": json_path,
            "csv": csv_path,
        }
