"""Burp Suite integration adapter for CyberSecuritySuite.

Provides tool availability discovery, proxy listener connectivity validation,
target scope verification, and structured Burp Suite XML issue report parsing into
normalized, deduplicated findings and evidence with cryptographic provenance.
"""

from __future__ import annotations

import hashlib
import re
import socket
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.activity_logger import ActivityLogger
from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    ValidationStatus,
    _utc_now_iso,
)


class BurpReportParser:
    """Parses Burp Suite Scanner XML issue exports into normalized Finding objects."""

    SEVERITY_MAP = {
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "information": FindingSeverity.INFORMATIONAL,
        "informational": FindingSeverity.INFORMATIONAL,
        "info": FindingSeverity.INFORMATIONAL,
    }

    CONFIDENCE_MAP = {
        "certain": ValidationStatus.CONFIRMED,
        "firm": ValidationStatus.OBSERVED,
        "tentative": ValidationStatus.NEEDS_VALIDATION,
    }

    @classmethod
    def clean_html_tags(cls, text: str) -> str:
        """Strips HTML formatting common in Burp Suite descriptions and backgrounds."""
        if not text:
            return ""
        clean = re.sub(r"<[^>]+>", " ", text)
        return " ".join(clean.split()).strip()

    @classmethod
    def parse_xml(
        cls,
        xml_content: str,
        project_id: int,
        execution_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parses Burp Suite XML export (<issues><issue>...</issue></issues>) into normalized Findings."""
        findings: List[Finding] = []
        if not xml_content or not xml_content.strip():
            return findings

        root = ET.fromstring(xml_content.strip())

        # If the root itself is an issue or contains issues
        issue_nodes = root.findall(".//issue") if root.tag != "issue" else [root]

        for issue_elem in issue_nodes:
            raw_title = issue_elem.findtext("name") or "Burp Suite Finding"
            
            # Severity
            raw_sev = (issue_elem.findtext("severity") or "information").strip().lower()
            severity = cls.SEVERITY_MAP.get(raw_sev, FindingSeverity.INFORMATIONAL)

            # Confidence -> ValidationStatus
            raw_conf = (issue_elem.findtext("confidence") or "firm").strip().lower()
            val_status = cls.CONFIDENCE_MAP.get(raw_conf, ValidationStatus.OBSERVED)

            # Host and URL extraction
            host_elem = issue_elem.find("host")
            host_str = ""
            ip_attr = ""
            if host_elem is not None:
                host_str = (host_elem.text or "").strip()
                ip_attr = host_elem.attrib.get("ip", "").strip()

            path_str = (issue_elem.findtext("path") or "").strip()
            location = (issue_elem.findtext("location") or "").strip()

            # Clean host string to domain or IP
            parsed_host = host_str
            if "://" in host_str:
                parsed_url = urllib.parse.urlparse(host_str)
                affected_asset = parsed_url.hostname or host_str
                port_service = f"{parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)}/{parsed_url.scheme}"
            else:
                affected_asset = host_str or ip_attr or "unknown_host"
                port_service = "8080/http"

            # Textual sections
            bg = cls.clean_html_tags(issue_elem.findtext("issueBackground") or "")
            detail = cls.clean_html_tags(issue_elem.findtext("issueDetail") or "")
            remediation_bg = cls.clean_html_tags(issue_elem.findtext("remediationBackground") or "")
            remediation_detail = cls.clean_html_tags(issue_elem.findtext("remediationDetail") or "")

            # Look for CWE in classifications
            classifications = issue_elem.findtext("vulnerabilityClassifications") or ""
            cwe_match = re.search(r"CWE-(\d+)", classifications, re.IGNORECASE)
            title = f"CWE-{cwe_match.group(1)}: {raw_title}" if cwe_match else raw_title

            description_parts = []
            if bg:
                description_parts.append(bg)
            if detail:
                description_parts.append(f"Observation: {detail}")
            description = "\n\n".join(description_parts) or raw_title

            remediation_parts = []
            if remediation_bg:
                remediation_parts.append(remediation_bg)
            if remediation_detail:
                remediation_parts.append(remediation_detail)
            remediation = "\n\n".join(remediation_parts) or "Apply relevant security patches and input validation."

            repro = f"Target: {host_str}{path_str}"
            if location:
                repro += f"\nLocation: {location}"
            if ip_attr:
                repro += f"\nTarget IP: {ip_attr}"

            findings.append(
                Finding(
                    project_id=project_id,
                    title=title,
                    severity=severity,
                    affected_asset=affected_asset,
                    affected_port_service=port_service,
                    description=description,
                    reproduction_steps=repro,
                    remediation=remediation,
                    validation_status=val_status,
                    source_tool="burpsuite",
                    execution_id=execution_id,
                    assessment_id=assessment_id,
                )
            )

        return findings


class BurpSuiteAdapter(BaseSecurityAdapter):
    """Execution and reporting adapter for Burp Suite (Community / Professional)."""

    @property
    def tool_name(self) -> str:
        return "burpsuite"

    @property
    def display_name(self) -> str:
        return "Burp Suite Web Proxy & Scanner"

    def check_daemon_health(self, host: str = "127.0.0.1", port: int = 8080, timeout: float = 1.5) -> bool:
        """Tests whether local Burp Suite proxy listener is active and accepting connections."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def import_burp_xml(
        self,
        project_id: int,
        xml_content: str,
        target_override: Optional[str] = None,
        assessment_id: Optional[int] = None,
        source_filename: str = "burp_issues.xml",
        evidence_dir: Optional[Path] = None,
    ) -> SecurityToolResult:
        """Imports Burp Suite XML issue export with scope enforcement, SHA-256 evidence hashing, and deduplication."""
        target_detected = target_override or "web_application"

        # Create ToolExecution
        exec_record = ToolExecution(
            project_id=project_id,
            tool_name="burpsuite",
            command=f"burpsuite report-import --target {target_detected} --file {source_filename}",
            status=ExecutionStatus.RUNNING,
            assessment_id=assessment_id,
        )
        self.db.create_execution(exec_record)

        try:
            findings = BurpReportParser.parse_xml(
                xml_content, project_id=project_id, execution_id=exec_record.id, assessment_id=assessment_id
            )
        except Exception as e:
            exec_record.status = ExecutionStatus.FAILED
            self.db.update_execution(exec_record)
            return SecurityToolResult(
                tool_name="burpsuite",
                target=target_detected,
                is_authorized=True,
                scope_reason="Burp XML parsing failed",
                execution_status=ExecutionStatus.FAILED,
                execution_id=exec_record.id,
                error_message=f"Failed to parse Burp Suite XML report: {e}",
                assessment_id=assessment_id,
            )

        # Enforce scope validation against discovered assets
        scopes = self.db.list_scopes(project_id)
        project = self.db.get_project(project_id)
        authorized_findings: List[Finding] = []

        for f in findings:
            chk = ScopeAuthorizationService.is_target_authorized(f.affected_asset, scopes, project=project)
            if chk.is_allowed:
                authorized_findings.append(f)

        # Save Evidence with SHA-256 integrity hash
        sha256 = hashlib.sha256(xml_content.encode("utf-8")).hexdigest()
        evidence_entry = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"burp_import_{exec_record.id}.xml"
            ev_file.write_text(xml_content, encoding="utf-8")
            exec_record.raw_output_path = str(ev_file)

            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=exec_record.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Burp Suite imported scan issues ({source_filename})",
                    mime_type="application/xml",
                    assessment_id=assessment_id,
                )
            )

        # Save findings with deduplication
        persisted_findings: List[Finding] = []
        for f in authorized_findings:
            saved = self.db.upsert_finding_deduplicated(f)
            persisted_findings.append(saved)

        # Sync discovered web host assets into AssetInventoryService
        try:
            from core.asset_inventory import (
                AssetInventoryService,
                DiscoveredHostObservation,
                DiscoveredPortObservation,
            )
            inventory_service = AssetInventoryService(self.db)
            host_obs_map: Dict[str, DiscoveredHostObservation] = {}
            for f in persisted_findings:
                raw_target = f.affected_asset or ""
                host_str = raw_target
                port_num = None
                proto = "tcp"
                if "://" in raw_target:
                    parsed = urllib.parse.urlparse(raw_target)
                    host_str = parsed.hostname or raw_target
                    port_num = parsed.port or (443 if parsed.scheme == "https" else 80)
                elif ":" in raw_target and not raw_target.startswith("["):
                    parts = raw_target.split(":", 1)
                    host_str = parts[0]
                    try:
                        port_num = int(parts[1].split("/")[0])
                    except ValueError:
                        pass

                if not host_str:
                    continue

                if host_str not in host_obs_map:
                    host_obs_map[host_str] = DiscoveredHostObservation(
                        ip=host_str,
                        hostname="",
                        status="up",
                        ports=[],
                        confidence=1.0,
                        discovery_source="burpsuite",
                    )
                if port_num and not any(p.port == port_num for p in host_obs_map[host_str].ports):
                    host_obs_map[host_str].ports.append(
                        DiscoveredPortObservation(
                            port=port_num,
                            protocol=proto,
                            state="open",
                            service_name="https" if port_num == 443 else "http",
                        )
                    )

            if host_obs_map:
                inventory_service.sync_host_observations(
                    project_id=project_id,
                    observations=list(host_obs_map.values()),
                    scopes=scopes,
                    session_id=None,
                    source_tool="burpsuite",
                    evidence_id=evidence_entry.id if evidence_entry else None,
                )
        except Exception:
            pass

        exec_record.status = ExecutionStatus.COMPLETED
        self.db.update_execution(exec_record)

        ActivityLogger(self.db).log(
            project_id=project_id,
            action="burp_report_imported",
            outcome="completed",
            details={
                "source_file": source_filename,
                "findings_count": len(persisted_findings),
                "assessment_id": assessment_id,
                "evidence_hash": sha256,
            },
        )

        return SecurityToolResult(
            tool_name="burpsuite",
            target=target_detected,
            is_authorized=True,
            scope_reason=f"Parsed {len(findings)} findings ({len(persisted_findings)} authorized)",
            execution_status=ExecutionStatus.COMPLETED,
            execution_id=exec_record.id,
            evidence_id=evidence_entry.id if evidence_entry else None,
            evidence_hash=sha256,
            findings=persisted_findings,
            raw_output=xml_content[:2000],
            assessment_id=assessment_id,
        )
