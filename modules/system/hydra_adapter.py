"""THC-Hydra Password Auditing and Authentication Testing Adapter.

Safely integrates /usr/bin/hydra for authorized credential auditing and brute-force testing.
Enforces:
- Scope Authorization before execution (fails closed).
- Anti-Lockout safeguards & task throttling (-t 4 default, safe delays).
- Dry-run command preview.
- Credential masking in execution logs and reports.
- Standardized findings creation (CWE-521: Weak Password Requirements) and SHA-256 evidence vaulting.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
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


@dataclass
class HydraCredential:
    """Represents a discovered valid login credential."""
    service: str
    target: str
    port: int
    username: str
    password: str


@dataclass
class HydraOptions:
    """Execution options for Hydra password auditing."""
    target: str
    service: str = "ssh"           # ssh, ftp, telnet, smb, rdp, mysql, postgres, http-get
    port: Optional[int] = None
    username: Optional[str] = None
    user_file: Optional[str] = None
    password: Optional[str] = None
    pass_file: Optional[str] = None
    tasks: int = 4                 # Concurrency limit (default 4 for safety)
    wait_time_sec: float = 1.0     # Time to wait between calls to prevent DoS/lockout
    timeout: float = 60.0
    max_duration: float = 300.0
    exit_on_first_found: bool = True
    dry_run: bool = False
    confirmed_high_risk: bool = False


class HydraAdapter(BaseSecurityAdapter):
    """Orchestrates authorized authentication security testing with Hydra."""

    @property
    def tool_name(self) -> str:
        return "hydra"

    @property
    def display_name(self) -> str:
        return "THC-Hydra Credential Auditor"

    SUPPORTED_SERVICES = {
        "ssh": 22,
        "ftp": 21,
        "telnet": 23,
        "smb": 445,
        "rdp": 3389,
        "mysql": 3306,
        "postgres": 5432,
        "http-get": 80,
    }

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db=db)
        self.registry = registry or ToolRegistry()
        self.execution_service = ToolExecutionService.get_instance(db=db)
        self._current_job_id: Optional[str] = None

    def cancel(self) -> bool:
        if self._current_job_id:
            return self.execution_service.cancel_job(self._current_job_id)
        return False

    def is_installed(self) -> Tuple[bool, Optional[str]]:
        path = shutil.which("hydra") or "/usr/bin/hydra"
        if os.path.exists(path) and os.access(path, os.X_OK):
            return True, path
        return False, None

    def build_command(self, options: HydraOptions) -> List[str]:
        """Constructs safe tokenized argument list for Hydra."""
        binary = shutil.which("hydra") or "/usr/bin/hydra"
        cmd = [binary]

        # Target and port
        port = options.port or self.SUPPORTED_SERVICES.get(options.service, 22)
        cmd.extend(["-s", str(port)])

        # Username / Userlist
        if options.user_file and os.path.exists(options.user_file):
            cmd.extend(["-L", options.user_file])
        elif options.username:
            cmd.extend(["-l", options.username])
        else:
            cmd.extend(["-l", "admin"])

        # Password / Passlist
        if options.pass_file and os.path.exists(options.pass_file):
            cmd.extend(["-P", options.pass_file])
        elif options.password:
            cmd.extend(["-p", options.password])
        else:
            cmd.extend(["-p", "password"])

        # Safety & Concurrency
        safe_tasks = max(1, min(options.tasks, 16))
        cmd.extend(["-t", str(safe_tasks)])

        if options.exit_on_first_found:
            cmd.append("-f")

        # Delay throttling to avoid lockout
        if options.wait_time_sec > 0:
            cmd.extend(["-W", str(int(options.wait_time_sec))])

        cmd.extend(["-vV", f"{options.service}://{options.target}"])
        return cmd

    @classmethod
    def parse_hydra_output(cls, raw_output: str, target: str, service: str, port: int) -> List[HydraCredential]:
        """Extracts valid credentials from Hydra stdout output."""
        creds: List[HydraCredential] = []
        # Pattern: [22][ssh] host: 127.0.0.1   login: admin   password: password123
        regex = re.compile(
            r"\[(\d+)\]\[([a-zA-Z0-9_\-]+)\]\s+host:\s*([^\s]+)\s+login:\s*([^\s]+)\s+password:\s*([^\r\n]+)",
            re.IGNORECASE,
        )
        for line in raw_output.splitlines():
            line_str = line.strip()
            match = regex.search(line_str)
            if match:
                creds.append(
                    HydraCredential(
                        port=int(match.group(1)),
                        service=match.group(2).lower(),
                        target=match.group(3),
                        username=match.group(4),
                        password=match.group(5).strip(),
                    )
                )
        return creds

    def execute_audit(
        self,
        project_id: int,
        options: HydraOptions,
        scopes: List[TargetScope],
        evidence_dir: Optional[Path] = None,
        assessment_id: Optional[int] = None,
        project: Optional[Project] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        on_done: Optional[Callable[[SecurityToolResult], None]] = None,
    ) -> SecurityToolResult:
        """Executes authorized authentication audit using centralized execution engine."""
        # 1. Enforce Scope and Engagement Validation
        if project is None and self.db and project_id:
            project = self.db.get_project(project_id)

        scope_check = ScopeAuthorizationService.is_target_authorized(
            options.target, scopes, project=project
        )
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[-] Hydra blocked: Target '{options.target}' is unauthorized: {scope_check.reason}\n", "stderr")
            res = SecurityToolResult(
                tool_name="hydra",
                target=options.target,
                is_authorized=False,
                scope_reason=scope_check.reason,
                execution_status=ExecutionStatus.FAILED,
                error_message=f"Scope Authorization Blocked: {scope_check.reason}",
                assessment_id=assessment_id,
            )
            if on_done:
                on_done(res)
            return res

        # 1.5 Enforce High-Risk Intrusive Brute-Force Authorization
        is_intrusive = (options.tasks > 4 or (bool(options.user_file) and bool(options.pass_file)))
        if is_intrusive and not options.dry_run:
            if not getattr(options, "confirmed_high_risk", False):
                msg = "High-Risk Operational Safety Block: Intrusive online brute-force auditing (tasks > 4 or full user+password dictionary) requires explicit confirmed_high_risk authorization."
                if on_output:
                    on_output(f"[-] {msg}\n", "stderr")
                res = SecurityToolResult(
                    tool_name="hydra",
                    target=options.target,
                    is_authorized=False,
                    scope_reason="High-Risk Confirmation Required",
                    execution_status=ExecutionStatus.FAILED,
                    error_message=msg,
                    assessment_id=assessment_id,
                )
                if on_done:
                    on_done(res)
                return res
            # Log confirmation in audit log
            if self.db and project_id:
                try:
                    from storage.models import EngagementAuditLog
                    self.db.add_audit_log(EngagementAuditLog(
                        project_id=project_id,
                        action="hydra_intrusive_bruteforce_confirmed",
                        actor="security_operator",
                        details=f"Explicit high-risk confirmation granted for Hydra brute-force on {options.target} (tasks={options.tasks}, service={options.service})",
                    ))
                except Exception:
                    pass

        # 2. Dry run preview
        cmd = self.build_command(options)
        redacted_cmd = ToolExecutionService.redact_sensitive_args(cmd)
        if options.dry_run:
            if on_output:
                on_output(f"[*] [DRY RUN] Generated Hydra Command:\n    {redacted_cmd}\n", "stdout")
            res = SecurityToolResult(
                tool_name="hydra",
                target=options.target,
                is_authorized=True,
                scope_reason="Dry Run Simulation Approved",
                execution_status=ExecutionStatus.COMPLETED,
                raw_output=f"Dry Run Command: {redacted_cmd}",
                assessment_id=assessment_id,
            )
            if on_done:
                on_done(res)
            return res

        # 3. Create execution job
        port = options.port or self.SUPPORTED_SERVICES.get(options.service, 22)

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            creds = self.parse_hydra_output(job.stdout, options.target, options.service, port)
            findings: List[Finding] = []
            for c in creds:
                f = Finding(
                    project_id=project_id,
                    title=f"Weak/Default Credentials Discovered on {c.service.upper()} ({c.username})",
                    severity=FindingSeverity.CRITICAL,
                    affected_asset=c.target,
                    affected_port_service=f"{c.port}/{c.service}",
                    description=(
                        f"Automated credential auditing successfully authenticated against {c.service.upper()} service "
                        f"on port {c.port} using valid credentials.\n"
                        f"Username: {c.username}\n"
                        f"Password: ***REDACTED*** (Password identified during security audit)"
                    ),
                    remediation=(
                        "Enforce strong password complexity policies, multi-factor authentication (MFA), "
                        "and progressive account lockout / IP rate-limiting to prevent brute-force attacks. (CWE-521)"
                    ),
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="hydra",
                    assessment_id=assessment_id,
                )
                findings.append(f)
            return findings

        effective_timeout = min(options.timeout, getattr(options, "max_duration", options.timeout))

        job = ExecutionJob(
            tool_name="hydra",
            display_name="THC-Hydra Credential Auditor",
            target=options.target,
            command=cmd,
            project_id=project_id,
            assessment_id=assessment_id,
            timeout=effective_timeout,
            evidence_dir=evidence_dir,
            custom_parser=custom_parser,
        )

        self._current_job_id = job.job_id
        finished_job = self.execution_service.execute_job_sync(
            job=job,
            on_output=on_output,
        )

        if self.db and project_id:
            try:
                from storage.models import EngagementAuditLog
                self.db.add_audit_log(EngagementAuditLog(
                    project_id=project_id,
                    action="hydra_scan_completed",
                    actor="automated_adapter",
                    details=f"Hydra execution finished for {options.target} (State: {finished_job.state.value}, Credentials: {len(finished_job.findings)})",
                ))
            except Exception:
                pass

        tool_res = SecurityToolResult(
            tool_name="hydra",
            target=options.target,
            is_authorized=True,
            scope_reason=scope_check.reason,
            execution_status=ExecutionStatus.COMPLETED if finished_job.state == JobState.COMPLETED else ExecutionStatus.FAILED,
            execution_id=finished_job.execution_record_id,
            evidence_id=finished_job.evidence_id,
            evidence_hash=finished_job.evidence_hash,
            findings=finished_job.findings,
            raw_output=finished_job.stdout,
            error_message=finished_job.error_message,
            duration_seconds=finished_job.duration_seconds,
            assessment_id=assessment_id,
        )

        if on_done:
            on_done(tool_res)
        return tool_res

    # Backward compatibility alias
    execute_hydra = execute_audit
