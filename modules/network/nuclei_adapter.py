"""Nuclei vulnerability scanner execution and JSONL output adapter.

Provides scope-enforced execution, binary availability checks,
JSONL/JSON finding parsing with CVE/CPE correlation, and external
Nuclei result import with SHA-256 evidence hashing.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessRunner


@dataclass
class NucleiScanOptions:
    target: str
    tags: Optional[str] = "cve,misconfig,exposure"
    severity: Optional[str] = "medium,high,critical"
    rate_limit: int = 50
    timeout: float = 300.0


@dataclass
class NucleiExecutionResult:
    is_available: bool
    is_authorized: bool
    status_reason: str
    execution: Optional[ToolExecution] = None
    findings: List[Finding] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class NucleiAdapter:
    """Orchestrates authorized Nuclei vulnerability scanning and evidence extraction."""

    SEVERITY_MAP: Dict[str, FindingSeverity] = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFORMATIONAL,
        "unknown": FindingSeverity.INFORMATIONAL,
    }

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def is_available(self) -> bool:
        """Verifies whether the nuclei binary is installed and executable."""
        meta = self.registry.get_tool("nuclei")
        if meta and meta.binary_path and Path(meta.binary_path).exists():
            return True
        return shutil.which("nuclei") is not None

    def get_binary_path(self) -> Optional[str]:
        meta = self.registry.get_tool("nuclei")
        if meta and meta.binary_path and Path(meta.binary_path).exists():
            return meta.binary_path
        return shutil.which("nuclei")

    @classmethod
    def parse_jsonl(
        cls,
        jsonl_content: str,
        project_id: int,
        execution_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parses Nuclei JSON lines output into structured security findings."""
        findings: List[Finding] = []
        if not jsonl_content or not jsonl_content.strip():
            return findings

        seen_keys = set()

        for line in jsonl_content.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = item.get("template-id", "unknown-template")
            info = item.get("info", {})
            title = info.get("name") or f"Nuclei Detection: {template_id}"
            raw_sev = str(info.get("severity", "info")).lower()
            severity = cls.SEVERITY_MAP.get(raw_sev, FindingSeverity.INFORMATIONAL)

            host = item.get("host", "")
            ip = item.get("ip", "")
            affected_asset = ip or host or "unknown"
            port_svc = item.get("type", "network")

            # Avoid duplicate findings within the same execution
            dedup_key = (affected_asset, template_id)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            classification = info.get("classification", {})
            cve_ids = classification.get("cve-id", [])
            cve_str = f"CVE: {', '.join(cve_ids)}. " if cve_ids else ""
            cvss_score = classification.get("cvss-score", None)
            if cvss_score is not None:
                try:
                    cvss_score = float(cvss_score)
                except (ValueError, TypeError):
                    cvss_score = None

            desc = info.get("description", "") or f"Nuclei template '{template_id}' matched target endpoint {host}."
            remediation = info.get("remediation", "") or "Review endpoint configuration and apply vendor security updates."

            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"[{template_id}] {title}",
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_asset=affected_asset,
                    affected_port_service=port_svc,
                    description=f"{cve_str}{desc}\nMatched at: {item.get('matched-at', host)}",
                    remediation=remediation,
                    validation_status=ValidationStatus.NEEDS_VALIDATION,
                    source_tool=f"nuclei:{template_id}",
                    execution_id=execution_id,
                )
            )

        return findings

    def execute_scan(
        self,
        project_id: int,
        options: NucleiScanOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> NucleiExecutionResult:
        """Validate scope, check executable availability, run Nuclei, and persist findings."""
        if not self.is_available():
            return NucleiExecutionResult(
                is_available=False,
                is_authorized=False,
                status_reason="Nuclei binary not found. Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )

        # 1. Scope Check (Fail-closed)
        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            options.target, scopes
        )
        if not scope_check.is_allowed:
            return NucleiExecutionResult(
                is_available=True,
                is_authorized=False,
                status_reason=scope_check.reason,
            )

        binary = self.get_binary_path() or "nuclei"
        command = [
            binary,
            "-target", options.target,
            "-jsonl",
            "-silent",
            "-rate-limit", str(options.rate_limit),
        ]
        if options.tags:
            command.extend(["-tags", options.tags])
        if options.severity:
            command.extend(["-severity", options.severity])

        cmd_str = " ".join(command)

        # 2. Record execution
        execution = ToolExecution(
            project_id=project_id,
            tool_name="nuclei",
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
        )
        execution = self.db.create_execution(execution)

        # 3. Execute process
        result = self.runner.run(
            command=command,
            timeout=options.timeout,
            on_output=on_output,
        )

        execution.status = result.status
        execution.exit_code = result.exit_code
        execution.started_at = result.started_at
        execution.finished_at = result.finished_at
        execution.duration_seconds = result.duration_seconds

        # 4. Save evidence
        raw_jsonl = result.stdout
        if raw_jsonl.strip() and evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"nuclei_exec_{execution.id}.jsonl"
            ev_file.write_text(raw_jsonl, encoding="utf-8")
            execution.raw_output_path = str(ev_file)

            sha256 = hashlib.sha256(raw_jsonl.encode("utf-8")).hexdigest()
            self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Raw Nuclei JSONL output for execution #{execution.id}",
                    mime_type="application/x-ndjson",
                )
            )

        self.db.update_execution(execution)

        # 5. Parse findings
        findings: List[Finding] = []
        if result.status == ExecutionStatus.COMPLETED and raw_jsonl.strip():
            findings = self.parse_jsonl(raw_jsonl, project_id=project_id, execution_id=execution.id)
            for f in findings:
                self.db.create_finding(f)

        return NucleiExecutionResult(
            is_available=True,
            is_authorized=True,
            status_reason="Nuclei assessment completed successfully.",
            execution=execution,
            findings=findings,
        )

    def import_nuclei_jsonl(
        self,
        project_id: int,
        jsonl_content: str,
        scopes: List[TargetScope],
        source_filename: str = "imported_nuclei.jsonl",
        evidence_dir: Optional[Path] = None,
    ) -> NucleiExecutionResult:
        """Import externally generated Nuclei results with cryptographic hash and scope check."""
        if not jsonl_content or not jsonl_content.strip():
            raise ValueError("Provided Nuclei output content is empty.")

        parsed_findings = self.parse_jsonl(jsonl_content, project_id=project_id)
        if not parsed_findings:
            raise ValueError("No valid Nuclei findings parsed from the provided input.")

        # Re-check scope for each affected asset
        in_scope_findings = []
        out_of_scope_assets = set()

        for f in parsed_findings:
            chk = ScopeAuthorizationService.is_target_authorized(f.affected_asset, scopes)
            if chk.is_allowed:
                in_scope_findings.append(f)
            else:
                out_of_scope_assets.add(f.affected_asset)

        if not in_scope_findings:
            return NucleiExecutionResult(
                is_available=True,
                is_authorized=False,
                status_reason=f"All findings in imported Nuclei output are outside authorized scope: {', '.join(out_of_scope_assets)}",
            )

        # Create execution record
        execution = ToolExecution(
            project_id=project_id,
            tool_name="nuclei_import",
            command=f"import_nuclei_jsonl(source='{Path(source_filename).name}')",
            status=ExecutionStatus.COMPLETED,
        )
        execution = self.db.create_execution(execution)

        # Save evidence
        sha256 = hashlib.sha256(jsonl_content.encode("utf-8")).hexdigest()
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"nuclei_import_{execution.id}_{Path(source_filename).name}"
            ev_file.write_text(jsonl_content, encoding="utf-8")
            execution.raw_output_path = str(ev_file)

            self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Imported Nuclei output from '{Path(source_filename).name}'",
                    mime_type="application/x-ndjson",
                )
            )

        self.db.update_execution(execution)

        for f in in_scope_findings:
            f.execution_id = execution.id
            self.db.create_finding(f)

        reason = f"Successfully imported {len(in_scope_findings)} in-scope finding(s)."
        if out_of_scope_assets:
            reason += f" Quarantined {len(out_of_scope_assets)} out-of-scope asset(s)."

        return NucleiExecutionResult(
            is_available=True,
            is_authorized=True,
            status_reason=reason,
            execution=execution,
            findings=in_scope_findings,
        )

