"""WAFW00F Web Application Firewall Fingerprinting Adapter.

Safely invokes the open-source WAFW00F engine (from source/web/wafw00f or host PATH),
enforces pre-execution target scope authorization, streams output in real time,
and records detected WAF products as structured security findings and cryptographic evidence.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse

from core.base_adapter import BaseSecurityAdapter
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.parsers.universal_parser import UniversalParser
from core.registry import ToolRegistry
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
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


@dataclass
class WAFW00FOptions:
    target_url: str
    find_all: bool = False
    timeout: float = 45.0


@dataclass
class WAFDetectionResult:
    target_url: str
    waf_detected: bool
    waf_name: Optional[str]
    num_requests: int
    raw_output: str


class WAFW00FAdapter(BaseSecurityAdapter):
    """Orchestrates authorized WAF fingerprinting with scope enforcement and finding persistence."""

    @property
    def tool_name(self) -> str:
        return "wafw00f"

    @property
    def display_name(self) -> str:
        return "WAFW00F WAF Fingerprinter"

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db)
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()
        self.execution_service = ToolExecutionService(db=db)

    def build_command(self, options: WAFW00FOptions) -> List[str]:
        """Constructs safe argument list for WAFW00F."""
        base_cmd = self.registry.resolve_command("wafw00f", [])
        args = list(base_cmd)
        args.append(options.target_url)
        if options.find_all:
            args.append("-a")
        return args

    def cancel(self) -> bool:
        return self.runner.cancel()

    def parse_output(self, output: str, target_url: str) -> WAFDetectionResult:
        """Extracts detected WAF name and request count from WAFW00F stdout."""
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output)

        # Regex for detected WAF
        # Example: "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
        waf_match = re.search(
            r"is behind (?:a )?([A-Za-z0-9_\-\.\s\(\)]+?)(?: WAF|\.|\n|$)",
            clean_text,
            re.IGNORECASE,
        )
        waf_name = None
        waf_detected = False

        if waf_match:
            candidate = waf_match.group(1).strip()
            # Exclude generic non-WAF messages
            if "generic detection" not in candidate.lower() and "no waf" not in candidate.lower():
                waf_name = candidate
                waf_detected = True

        if not waf_detected and ("no waf detected" in clean_text.lower() or "none" in clean_text.lower()):
            waf_detected = False
            waf_name = None

        # Regex for requests: "[~] Number of requests: 14"
        req_match = re.search(r"Number of requests:\s*(\d+)", clean_text, re.IGNORECASE)
        num_requests = int(req_match.group(1)) if req_match else 0

        return WAFDetectionResult(
            target_url=target_url,
            waf_detected=waf_detected,
            waf_name=waf_name,
            num_requests=num_requests,
            raw_output=clean_text,
        )

    def execute_scan(
        self,
        project_id: int,
        options: WAFW00FOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        project: Optional[Project] = None,
        assessment_id: Optional[int] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Validates scope and lifecycle, runs WAFW00F via ToolExecutionService, and parses findings."""
        target_url = options.target_url.strip()
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.hostname or target_url

        # 1. Enforce Scope and Engagement Lifecycle Validation
        if project is None and self.db and project_id:
            project = self.db.get_project(project_id)

        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            host, scopes, project=project
        )
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[SCOPE REJECTED] Target '{host}' is outside authorized scope: {scope_check.reason}\n", "stderr")
            return False, f"Target out of scope: {scope_check.reason}", [], None

        # 2. Build Safe Command
        try:
            command = self.build_command(options)
        except Exception as exc:
            return False, f"Command resolution failed: {exc}", [], None

        tool_meta = self.registry.get_tool("wafw00f")
        env = dict(os.environ)
        if tool_meta and tool_meta.python_path_dir:
            resolved_pypath = str(Path(tool_meta.python_path_dir).resolve())
            env["PYTHONPATH"] = f"{resolved_pypath}:{env.get('PYTHONPATH', '')}"

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            full_output = job.stdout + "\n" + job.stderr
            parsed_result = self.parse_output(full_output, target_url)
            findings: List[Finding] = []

            if parsed_result.waf_detected and parsed_result.waf_name:
                finding = Finding(
                    project_id=project_id,
                    execution_id=job.execution_record_id,
                    title=f"Web Application Firewall (WAF) Detected: {parsed_result.waf_name}",
                    description=(
                        f"Target URL '{target_url}' is protected by Web Application Firewall: "
                        f"'{parsed_result.waf_name}'. WAF fingerprints were confirmed via {parsed_result.num_requests} diagnostic probes."
                    ),
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target_url,
                    remediation=(
                        "Informational reconnaissance finding. Note the presence of the WAF during penetration testing "
                        "as rate limiting, IP blocking, or payload inspection may alter vulnerability test results."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="wafw00f",
                    assessment_id=assessment_id,
                )
                findings.append(finding)
            elif "site appears to be down" not in full_output.lower() and "connection refused" not in full_output.lower():
                finding = Finding(
                    project_id=project_id,
                    execution_id=job.execution_record_id,
                    title="No Web Application Firewall (WAF) Detected",
                    description=(
                        f"No active Web Application Firewall was identified protecting '{target_url}' after "
                        f"{parsed_result.num_requests} fingerprinting requests."
                    ),
                    severity=FindingSeverity.LOW,
                    affected_asset=target_url,
                    remediation=(
                        "Consider deploying a Web Application Firewall (WAF) or cloud proxy (e.g., Cloudflare, AWS WAF, "
                        "or ModSecurity) in front of the application to defend against automated exploit attacks."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="wafw00f",
                    assessment_id=assessment_id,
                )
                findings.append(finding)

            if not findings and full_output.strip():
                norm_findings, _ = UniversalParser.parse(
                    raw_output=full_output,
                    tool_hint="wafw00f",
                    target_url=target_url,
                    execution_id=job.execution_record_id,
                )
                for nf in norm_findings:
                    f = nf.to_finding(project_id=project_id)
                    f.assessment_id = assessment_id
                    findings.append(f)

            return findings

        job = ExecutionJob(
            tool_name="wafw00f",
            display_name="WAFW00F WAF Fingerprinter",
            target=host,
            command=command,
            project_id=project_id,
            scopes=scopes,
            assessment_id=assessment_id,
            timeout=options.timeout,
            env=env,
            evidence_dir=evidence_dir,
            runner=self.runner,
            custom_parser=custom_parser,
        )

        finished_job = self.execution_service.execute_job_sync(
            job=job,
            on_output=on_output,
        )

        db_execution = finished_job.execution_record or (self.db.get_execution(finished_job.execution_record_id, project_id=project_id) if (self.db and finished_job.execution_record_id) else None)
        is_success = (finished_job.state == JobState.COMPLETED)
        status_msg = "Scan completed successfully" if is_success else (finished_job.error_message or "Execution Failed")

        return is_success, status_msg, finished_job.findings, db_execution
