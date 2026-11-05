"""Nikto Web Vulnerability Scanner Adapter.

Integrates Nikto via bin/nikto wrapper (Method 2) and Adapter & Parser pattern (Method 3),
enforcing Scope Guard authorization before execution, capturing streaming output,
preserving cryptographic evidence with SHA-256, and persisting findings into SQLite.
Enriched with Strix AI automated risk triage (Method 1).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

from core.base_adapter import BaseSecurityAdapter
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.parsers.universal_parser import UniversalParser
from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from core.strix_triage import StrixTriageEngine
from modules.web.nikto_parser import NiktoParser, NiktoScanResult
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
from terminal.runner import ProcessExecutionResult, ProcessRunner


@dataclass
class NiktoScanOptions:
    """Options for configuring a Nikto assessment run."""
    target: str
    port: Optional[int] = None
    ssl: Optional[bool] = None
    tuning: Optional[str] = None         # e.g., "1,2,3,b" (Scan tuning options)
    timeout: float = 120.0               # Maximum timeout for execution
    use_json_output: bool = True
    extra_args: Optional[List[str]] = None


@dataclass
class NiktoExecutionResult:
    """Structured result returned after Nikto execution."""
    is_authorized: bool
    scope_reason: str
    execution: Optional[ToolExecution] = None
    scan_result: Optional[NiktoScanResult] = None
    findings: List[Finding] = field(default_factory=list)
    evidence: Optional[Evidence] = None


class NiktoAdapter(BaseSecurityAdapter):
    """Orchestrates authorized Nikto web vulnerability assessments."""

    @property
    def tool_name(self) -> str:
        return "nikto"

    @property
    def display_name(self) -> str:
        return "Nikto Web Vulnerability Scanner"

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db)
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()
        self.triage_engine = StrixTriageEngine()
        self.execution_service = ToolExecutionService(db=db)

    def cancel(self):
        """Requests cancellation of any running Nikto process."""
        self.runner.cancel()

    def _resolve_binary(self) -> str:
        """Finds the best executable path for Nikto (wrapper script or system PATH)."""
        # 1. Prefer local bin/nikto wrapper
        local_wrapper = Path("bin/nikto").resolve()
        if local_wrapper.exists() and os.access(local_wrapper, os.X_OK):
            return str(local_wrapper)

        # 2. Query registry
        meta = self.registry.get_tool("nikto")
        if meta and meta.binary_path and os.path.exists(meta.binary_path):
            return meta.binary_path

        # 3. System PATH fallback
        host_bin = shutil.which("nikto")
        if host_bin:
            return host_bin

        # 4. Source fallback
        src_nikto = Path("source/web/nikto/program/nikto.pl").resolve()
        if src_nikto.exists():
            return str(src_nikto)

        return "nikto"

    def build_command(self, options: NiktoScanOptions, output_file: Optional[str] = None) -> List[str]:
        """Constructs a validated argument list for Nikto."""
        binary = self._resolve_binary()
        cmd = [binary]

        # Parse target to extract host, port, scheme
        target = options.target.strip()
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        port = options.port or parsed.port or (443 if parsed.scheme == "https" else 80)
        is_ssl = options.ssl if options.ssl is not None else (parsed.scheme == "https" or port == 443)

        cmd.extend(["-host", host, "-port", str(port)])

        if is_ssl:
            cmd.append("-ssl")

        # Non-interactive and no update check flags
        cmd.extend(["-nointeractive", "-nocheck"])

        if options.tuning:
            cmd.extend(["-Tuning", str(options.tuning)])

        if output_file:
            fmt = "json" if options.use_json_output else "txt"
            cmd.extend(["-output", output_file, "-Format", fmt])

        if options.extra_args:
            forbidden = {
                "-update", "-config", "-id", "-host", "-h", "-o",
                "-output", "-format", "-f", "-interactive", "-plugins", "-mutate"
            }
            for arg in options.extra_args:
                arg_clean = arg.strip().lower()
                # Reject shell metacharacters and prohibited prefixes
                if any(c in arg for c in (";", "|", "&", "$", "`", "\n", "\r")):
                    continue
                if not any(arg_clean.startswith(f) for f in forbidden):
                    cmd.append(arg)

        return cmd

    def execute_scan(
        self,
        project_id: int,
        options: NiktoScanOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        assessment_id: Optional[int] = None,
    ) -> NiktoExecutionResult:
        """Executes an authorized Nikto scan under Scope Guard."""
        # 1. Scope Authorization Check with Project Lifecycle
        project = self.db.get_project(project_id) if project_id else None
        scope_target = options.target
        if "://" in scope_target:
            scope_target = urlparse(scope_target).hostname or scope_target

        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            scope_target, scopes, project=project
        )
        if not scope_check.is_allowed:
            return NiktoExecutionResult(
                is_authorized=False,
                scope_reason=scope_check.reason,
            )

        # 2. Setup output temp file for structured capture
        temp_dir = tempfile.mkdtemp(prefix="nikto_run_")
        output_json_path = os.path.join(temp_dir, "nikto_output.json")

        try:
            command = self.build_command(options, output_file=output_json_path)

            parsed_scan_result: List[Optional[NiktoScanResult]] = [None]
            parsed_findings: List[Finding] = []

            def custom_parser(job: ExecutionJob) -> List[Finding]:
                scan_res = None
                if os.path.exists(output_json_path) and os.path.getsize(output_json_path) > 0:
                    try:
                        with open(output_json_path, "r", encoding="utf-8", errors="replace") as f:
                            raw_json = f.read()
                        job.custom_evidence_payload = raw_json
                        job.custom_evidence_mime = "application/json"
                        job.custom_evidence_ext = "json"
                        scan_res = NiktoParser.parse_json(raw_json)
                    except Exception:
                        scan_res = None
                elif job.stdout.strip().startswith("{") or job.stdout.strip().startswith("["):
                    try:
                        scan_res = NiktoParser.parse_json(job.stdout)
                    except Exception:
                        scan_res = None

                if not scan_res and job.stdout.strip():
                    try:
                        scan_res = NiktoParser.parse_text(job.stdout)
                    except Exception:
                        scan_res = None

                parsed_scan_result[0] = scan_res
                if scan_res and scan_res.items:
                    f_list = NiktoParser.to_findings(
                        scan_res,
                        project_id=project_id,
                        execution_id=job.execution_record_id,
                        assessment_id=assessment_id,
                    )
                    for f in f_list:
                        try:
                            triaged = self.triage_engine.triage(f)
                            f.cvss_score = triaged.cvss_score
                            f.cvss_vector = triaged.cvss_vector
                        except Exception:
                            pass
                        parsed_findings.append(f)
                    return f_list

                # Fallback to UniversalParser if NiktoParser found no findings
                raw_to_parse = raw_json if ("raw_json" in locals() and raw_json) else job.stdout
                if raw_to_parse.strip():
                    norm_findings, _ = UniversalParser.parse(
                        raw_output=raw_to_parse,
                        tool_hint="nikto",
                        target_url=options.target,
                        execution_id=job.execution_record_id,
                    )
                    if norm_findings:
                        f_list = [nf.to_finding(project_id=project_id) for nf in norm_findings]
                        for f in f_list:
                            if assessment_id:
                                f.assessment_id = assessment_id
                            parsed_findings.append(f)
                        return f_list

                return []

            job = ExecutionJob(
                tool_name="nikto",
                display_name="Nikto Web Server Scanner",
                target=scope_target,
                command=command,
                project_id=project_id,
                scopes=scopes,
                assessment_id=assessment_id,
                timeout=options.timeout,
                evidence_dir=evidence_dir,
                runner=self.runner,
                custom_parser=custom_parser,
            )

            finished_job = self.execution_service.execute_job_sync(
                job=job,
                on_output=on_output,
            )

            db_execution = finished_job.execution_record or (self.db.get_execution(finished_job.execution_record_id, project_id=project_id) if (self.db and finished_job.execution_record_id) else None)
            db_evidence = self.db.get_evidence(finished_job.evidence_id, project_id=project_id) if (self.db and finished_job.evidence_id) else None

            # Retrieve findings from DB to get populated IDs
            persisted_findings = self.db.list_findings(project_id, assessment_id=assessment_id) if (self.db and project_id) else parsed_findings

            return NiktoExecutionResult(
                is_authorized=True,
                scope_reason=scope_check.reason,
                execution=db_execution,
                scan_result=parsed_scan_result[0],
                findings=persisted_findings if persisted_findings else parsed_findings,
                evidence=db_evidence,
            )

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
