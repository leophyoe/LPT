"""OWASP ZAP (Zed Attack Proxy) integration adapter for CyberSecuritySuite.

Provides tool availability discovery, proxy daemon connectivity validation,
target scope verification, automated baseline scan execution, and structured
ZAP XML and JSON report parsing into normalized deduplicated findings and evidence.
"""

from __future__ import annotations

import hashlib
import json
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
from terminal.runner import ProcessRunner


class ZAPReportParser:
    """Parses OWASP ZAP XML and JSON alert reports into normalized Finding objects."""

    RISK_MAP = {
        "3": FindingSeverity.HIGH,
        "2": FindingSeverity.MEDIUM,
        "1": FindingSeverity.LOW,
        "0": FindingSeverity.INFORMATIONAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "informational": FindingSeverity.INFORMATIONAL,
        "info": FindingSeverity.INFORMATIONAL,
    }

    @classmethod
    def clean_html_tags(cls, text: str) -> str:
        """Strips HTML formatting common in ZAP descriptions and solutions."""
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
        """Parses ZAP XML export into normalized Finding instances."""
        findings: List[Finding] = []
        if not xml_content or not xml_content.strip():
            return findings

        root = ET.fromstring(xml_content.strip())
        
        # Traverse sites and alerts
        for site_elem in root.findall(".//site"):
            host = site_elem.get("host") or site_elem.get("name") or "unknown_host"
            port = site_elem.get("port") or ""

            for alert_elem in site_elem.findall(".//alertitem"):
                title = alert_elem.findtext("name") or alert_elem.findtext("alert") or "ZAP Finding"
                risk_code = (alert_elem.findtext("riskcode") or "0").strip().lower()
                severity = cls.RISK_MAP.get(risk_code, FindingSeverity.INFORMATIONAL)

                desc = cls.clean_html_tags(alert_elem.findtext("desc") or "")
                solution = cls.clean_html_tags(alert_elem.findtext("solution") or "")
                uri = alert_elem.findtext("uri") or host
                cwe_id = alert_elem.findtext("cweid") or ""
                param = alert_elem.findtext("param") or ""
                evidence_text = alert_elem.findtext("evidence") or ""

                port_service = f"{port}/http" if port else "web"
                repro = f"Target URL: {uri}"
                if param:
                    repro += f"\nVulnerable Parameter: {param}"
                if evidence_text:
                    repro += f"\nMatched Evidence: {evidence_text}"

                if cwe_id and cwe_id != "0":
                    title = f"CWE-{cwe_id}: {title}"

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        severity=severity,
                        affected_asset=host,
                        affected_port_service=port_service,
                        description=desc,
                        reproduction_steps=repro,
                        remediation=solution or "Review and patch the reported web application weakness.",
                        validation_status=ValidationStatus.OBSERVED,
                        source_tool="zaproxy",
                        execution_id=execution_id,
                        assessment_id=assessment_id,
                    )
                )

        return findings

    @classmethod
    def parse_json(
        cls,
        json_content: str,
        project_id: int,
        execution_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parses ZAP JSON export into normalized Finding instances."""
        findings: List[Finding] = []
        if not json_content or not json_content.strip():
            return findings

        data = json.loads(json_content)
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            host = site.get("@host") or site.get("@name") or "unknown_host"
            port = site.get("@port", "")
            alerts = site.get("alerts", [])
            if isinstance(alerts, dict):
                alerts = [alerts]

            for a in alerts:
                title = a.get("name") or a.get("alert") or "ZAP Finding"
                risk_code = str(a.get("riskcode", "0")).lower()
                severity = cls.RISK_MAP.get(risk_code, FindingSeverity.INFORMATIONAL)

                desc = cls.clean_html_tags(a.get("desc", ""))
                solution = cls.clean_html_tags(a.get("solution", ""))
                uri = a.get("uri") or host
                cwe_id = str(a.get("cweid", ""))
                param = a.get("param", "")

                port_service = f"{port}/http" if port else "web"
                repro = f"Target URL: {uri}"
                if param:
                    repro += f"\nVulnerable Parameter: {param}"

                if cwe_id and cwe_id != "0":
                    title = f"CWE-{cwe_id}: {title}"

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        severity=severity,
                        affected_asset=host,
                        affected_port_service=port_service,
                        description=desc,
                        reproduction_steps=repro,
                        remediation=solution or "Apply relevant security patches and secure headers.",
                        validation_status=ValidationStatus.OBSERVED,
                        source_tool="zaproxy",
                        execution_id=execution_id,
                        assessment_id=assessment_id,
                    )
                )

        return findings


class ZAPAdapter(BaseSecurityAdapter):
    """Execution and reporting adapter for OWASP ZAP."""

    @property
    def tool_name(self) -> str:
        return "zaproxy"

    @property
    def display_name(self) -> str:
        return "OWASP ZAP Web Proxy & Scanner"

    def check_daemon_health(self, host: str = "127.0.0.1", port: int = 8090, timeout: float = 1.5) -> bool:
        """Tests whether local ZAP proxy daemon is listening and accepting connections."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def import_zap_report(
        self,
        project_id: int,
        content: str,
        target_override: Optional[str] = None,
        assessment_id: Optional[int] = None,
        source_filename: str = "zap_report.xml",
        evidence_dir: Optional[Path] = None,
    ) -> SecurityToolResult:
        """Imports ZAP XML or JSON report with scope enforcement, SHA-256 evidence hashing, and deduplication."""
        is_json = content.strip().startswith("{") or content.strip().startswith("[")
        target_detected = target_override or "web_application"

        # Create ToolExecution
        exec_record = ToolExecution(
            project_id=project_id,
            tool_name="zaproxy",
            command=f"zaproxy report-import --target {target_detected} --file {source_filename}",
            status=ExecutionStatus.RUNNING,
            assessment_id=assessment_id,
        )
        self.db.create_execution(exec_record)

        try:
            if is_json:
                findings = ZAPReportParser.parse_json(
                    content, project_id=project_id, execution_id=exec_record.id, assessment_id=assessment_id
                )
            else:
                findings = ZAPReportParser.parse_xml(
                    content, project_id=project_id, execution_id=exec_record.id, assessment_id=assessment_id
                )
        except Exception as e:
            exec_record.status = ExecutionStatus.FAILED
            self.db.update_execution(exec_record)
            return SecurityToolResult(
                tool_name="zaproxy",
                target=target_detected,
                is_authorized=True,
                scope_reason="XML/JSON parsing failed",
                execution_status=ExecutionStatus.FAILED,
                execution_id=exec_record.id,
                error_message=f"Failed to parse ZAP report: {e}",
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
        sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        evidence_entry = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ext = "json" if is_json else "xml"
            mime = "application/json" if is_json else "application/xml"
            ev_file = evidence_dir / f"zap_import_{exec_record.id}.{ext}"
            ev_file.write_text(content, encoding="utf-8")
            exec_record.raw_output_path = str(ev_file)

            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=exec_record.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"OWASP ZAP imported scan report ({source_filename})",
                    mime_type=mime,
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
                        discovery_source="zaproxy",
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
                    source_tool="zaproxy",
                    evidence_id=evidence_entry.id if evidence_entry else None,
                )
        except Exception:
            pass

        exec_record.status = ExecutionStatus.COMPLETED
        self.db.update_execution(exec_record)

        ActivityLogger(self.db).log(
            project_id=project_id,
            action="zap_report_imported",
            outcome="completed",
            details={
                "source_file": source_filename,
                "findings_count": len(persisted_findings),
                "assessment_id": assessment_id,
                "evidence_hash": sha256,
            },
        )

        return SecurityToolResult(
            tool_name="zaproxy",
            target=target_detected,
            is_authorized=True,
            scope_reason=f"Parsed {len(findings)} findings ({len(persisted_findings)} authorized)",
            execution_status=ExecutionStatus.COMPLETED,
            execution_id=exec_record.id,
            evidence_id=evidence_entry.id if evidence_entry else None,
            evidence_hash=sha256,
            findings=persisted_findings,
            raw_output=content[:2000],
            assessment_id=assessment_id,
        )
