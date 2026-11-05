"""SQLMap Execution and Vulnerability Detection Adapter.

Safely invokes the open-source SQLMap engine (from source/web/sqlmap/sqlmap.py
or host PATH), enforces pre-execution target scope authorization, streams output
without freezing the GUI, and persists discovered SQL injection vulnerabilities
as structured findings and cryptographic evidence.
"""

from __future__ import annotations

import hashlib
import json
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
class SQLMapOptions:
    target_url: str
    risk: int = 1         # 1: Low risk, 2: Medium, 3: High
    level: int = 1        # 1: Basic tests, 2: Cookie, 3: User-Agent, 5: Host
    crawl_depth: int = 0  # 0: Just target URL
    batch_mode: bool = True
    timeout: float = 30.0
    max_duration: float = 300.0
    rate_limit_delay: float = 0.0  # Seconds between requests (--delay)
    confirmed_high_risk: bool = False


@dataclass
class SQLMapFindingItem:
    parameter: str
    param_type: str
    injection_type: str
    title: str
    payload: str
    dbms: str


class SQLMapAdapter(BaseSecurityAdapter):
    """Orchestrates authorized SQLMap security testing within scope."""

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    @property
    def display_name(self) -> str:
        return "SQLMap Automated Injection Tester"

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db)
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()
        self.execution_service = ToolExecutionService(db=db)
        self._current_job_id: Optional[str] = None

    def build_command(self, options: SQLMapOptions) -> List[str]:
        """Constructs safe argument array for SQLMap."""
        base_cmd = self.registry.resolve_command("sqlmap", [])

        args = list(base_cmd)
        args.extend(["-u", options.target_url])
        args.extend(["--risk", str(options.risk)])
        args.extend(["--level", str(options.level)])

        if options.batch_mode:
            args.append("--batch")

        if options.crawl_depth > 0:
            args.extend(["--crawl", str(options.crawl_depth)])

        if getattr(options, "rate_limit_delay", 0.0) > 0:
            args.extend(["--delay", str(options.rate_limit_delay)])

        # Safety options: disable color codes for clean regex parsing
        args.append("--disable-coloring")
        return args

    def cancel(self) -> bool:
        if self._current_job_id:
            return self.execution_service.cancel_job(self._current_job_id)
        return self.runner.cancel()

    def execute_scan(
        self,
        project_id: int,
        options: SQLMapOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        project: Optional[Project] = None,
        assessment_id: Optional[int] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Validates scope and lifecycle, checks high-risk confirmation, runs SQLMap via ToolExecutionService, and parses findings."""
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
                on_output(f"[-] SQLMap execution blocked by Scope Guard: {scope_check.reason}\n", "stderr")
            return False, scope_check.reason, [], None

        # 2. Enforce High-Risk Intrusive Scan Authorization
        is_intrusive = (options.risk > 1 or options.level > 1 or options.crawl_depth > 0)
        if is_intrusive:
            if not getattr(options, "confirmed_high_risk", False):
                msg = "High-Risk Operational Safety Block: Intrusive SQLMap scanning (risk > 1, level > 1, or crawling) requires explicit confirmed_high_risk authorization."
                if on_output:
                    on_output(f"[-] {msg}\n", "stderr")
                return False, msg, [], None
            # Log explicit confirmation in engagement audit log
            if self.db and project_id:
                try:
                    from storage.models import EngagementAuditLog
                    self.db.add_audit_log(EngagementAuditLog(
                        project_id=project_id,
                        action="sqlmap_intrusive_scan_confirmed",
                        actor="security_operator",
                        details=f"Explicit high-risk confirmation granted for target {target_url} (risk={options.risk}, level={options.level}, crawl={options.crawl_depth})",
                    ))
                except Exception as e:
                    pass

        # 3. Build Safe Command
        try:
            cmd = self.build_command(options)
        except FileNotFoundError as e:
            if on_output:
                on_output(f"[-] Tool not available: {e}\n", "stderr")
            return False, str(e), [], None

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            findings = self.parse_sqlmap_output(
                stdout_text=job.stdout,
                target_url=target_url,
                project_id=project_id,
                execution_id=job.execution_record_id,
                assessment_id=assessment_id,
            )
            if not findings and job.stdout.strip():
                norm_findings, _ = UniversalParser.parse(
                    raw_output=job.stdout,
                    tool_hint="sqlmap",
                    target_url=target_url,
                    execution_id=job.execution_record_id,
                )
                for nf in norm_findings:
                    f = nf.to_finding(project_id=project_id)
                    f.assessment_id = assessment_id
                    findings.append(f)
            return findings

        effective_timeout = min(options.timeout, getattr(options, "max_duration", options.timeout))

        job = ExecutionJob(
            tool_name="sqlmap",
            display_name="SQLMap Automated Injection Tester",
            target=host,
            command=cmd,
            project_id=project_id,
            scopes=scopes,
            assessment_id=assessment_id,
            timeout=effective_timeout,
            evidence_dir=evidence_dir,
            runner=self.runner,
            custom_parser=custom_parser,
        )

        self._current_job_id = job.job_id
        finished_job = self.execution_service.execute_job_sync(
            job=job,
            on_output=on_output,
        )

        db_execution = finished_job.execution_record or (self.db.get_execution(finished_job.execution_record_id, project_id=project_id) if (self.db and finished_job.execution_record_id) else None)
        is_success = (finished_job.state == JobState.COMPLETED)
        status_msg = "Success" if is_success else (finished_job.error_message or "Execution Failed")

        if self.db and project_id:
            try:
                from storage.models import EngagementAuditLog
                self.db.add_audit_log(EngagementAuditLog(
                    project_id=project_id,
                    action="sqlmap_scan_completed",
                    actor="automated_adapter",
                    details=f"SQLMap execution finished for {target_url} (State: {finished_job.state.value}, Findings: {len(finished_job.findings)})",
                ))
            except Exception:
                pass

        return is_success, status_msg, finished_job.findings, db_execution

    @staticmethod
    def parse_sqlmap_output(
        stdout_text: str,
        target_url: str,
        project_id: int,
        execution_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parses injection details and DBMS info from SQLMap stdout text."""
        findings: List[Finding] = []

        # Check for confirmed injection
        # Look for pattern:
        # Parameter: id (GET)
        #    Type: boolean-based blind
        #    Title: AND boolean-based blind - WHERE or HAVING clause
        #    Payload: id=1 AND 5258=5258
        param_blocks = re.findall(
            r"Parameter:\s+(\w+)\s+\(([^)]+)\)\s+Type:\s+([^\n]+)\s+Title:\s+([^\n]+)\s+Payload:\s+([^\n]+)",
            stdout_text,
            re.MULTILINE,
        )

        for param, p_type, inj_type, title, payload in param_blocks:
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"SQL Injection in parameter '{param}' ({p_type}): {title.strip()}",
                    severity=FindingSeverity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset=urlparse(target_url).hostname or target_url,
                    affected_port_service="Web / Database",
                    description=(
                        f"SQLMap confirmed an exploitable SQL injection vulnerability in parameter '{param}' "
                        f"via {p_type}. Injection type: {inj_type.strip()}."
                    ),
                    reproduction_steps=f"Target URL: {target_url}\nParameter: {param}\nPayload: {payload.strip()}",
                    remediation=(
                        "Implement parameterized queries (Prepared Statements) or use an Object-Relational "
                        "Mapper (ORM) with automated escaping. Never concatenate untrusted user input directly into SQL strings."
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="sqlmap",
                    execution_id=execution_id,
                    assessment_id=assessment_id,
                )
            )

        # Fallback heuristic: check if sqlmap identified DBMS
        dbms_match = re.search(r"the back-end DBMS is\s+([^\n]+)", stdout_text, re.IGNORECASE)
        if dbms_match and not findings:
            dbms_name = dbms_match.group(1).strip()
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Back-End DBMS Fingerprinted: {dbms_name}",
                    severity=FindingSeverity.LOW,
                    cvss_score=3.1,
                    affected_asset=urlparse(target_url).hostname or target_url,
                    affected_port_service="Web / Database",
                    description=f"SQLMap successfully fingerprinted the back-end database management system as: {dbms_name}.",
                    remediation="Suppress verbose database error messages and remove server identification banners.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="sqlmap",
                    execution_id=execution_id,
                    assessment_id=assessment_id,
                )
            )

        return findings
