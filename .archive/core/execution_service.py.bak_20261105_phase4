"""Centralized Real Security Tool Execution Service for CyberSecuritySuite.

Manages the complete operational lifecycle of real security testing tools:
JobState State Machine: QUEUED -> VALIDATING -> RUNNING -> PARSING -> COMPLETED / FAILED / CANCELLED / TIMED_OUT / BLOCKED.
Guarantees:
- Safe subprocess invocation with tokenized argument arrays (shell=False).
- Strict target scope and engagement lifecycle validation before execution.
- Non-blocking execution off the Qt UI thread.
- Standard output and error segregation with real-time streaming.
- Secret and credential redaction from execution logs.
- Automatic cryptographic evidence vaulting with SHA-256 provenance.
- Deduplicated finding persistence linked to active assessments.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.activity_logger import ActivityLogger
from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    Project,
    TargetScope,
    ToolExecution,
    _utc_now_iso,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


class JobState(str, Enum):
    """Execution lifecycle state machine."""
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    PARSING = "parsing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"


@dataclass
class ExecutionJob:
    """Encapsulates a single security tool execution job."""
    tool_name: str
    target: str
    command: List[str]
    project_id: int
    display_name: str = ""
    assessment_id: Optional[int] = None
    timeout: float = 300.0
    cwd: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    evidence_dir: Optional[Path] = None
    scopes: Optional[List[TargetScope]] = None
    runner: Optional[ProcessRunner] = None
    custom_evidence_payload: Optional[str] = None
    custom_evidence_mime: Optional[str] = None
    custom_evidence_ext: Optional[str] = None
    post_execution_callback: Optional[Callable[[ExecutionJob], None]] = None
    job_id: str = field(default_factory=lambda: f"job_{uuid.uuid4().hex[:8]}")
    state: JobState = JobState.QUEUED
    created_at: str = field(default_factory=_utc_now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error_message: str = ""
    evidence_id: Optional[int] = None
    evidence_hash: Optional[str] = None
    execution_record_id: Optional[int] = None
    execution_record: Optional[ToolExecution] = None
    findings: List[Finding] = field(default_factory=list)
    custom_parser: Optional[Callable[[ExecutionJob], List[Finding]]] = None


class ToolExecutionService:
    """Centralized orchestrator for executing real penetration testing tools."""

    _instance: Optional[ToolExecutionService] = None

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.registry = ToolRegistry()
        self._active_runners: Dict[str, ProcessRunner] = {}
        self._jobs: Dict[str, ExecutionJob] = {}
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls, db: Optional[Database] = None) -> ToolExecutionService:
        if cls._instance is None:
            cls._instance = cls(db=db)
        elif db is not None:
            cls._instance.db = db
        return cls._instance

    @staticmethod
    def redact_sensitive_args(args: List[str], tool_name: str = "") -> str:
        """Redacts passwords, tokens, and hashes from command strings."""
        redacted = []
        skip_next = False
        tool_lower = (tool_name or "").lower()
        # For network tools like Nmap, '-p' is port specification, NOT a password.
        if tool_lower in ("nmap", "gobuster", "nikto"):
            sensitive_flags = {"-P", "--pass", "--password", "-token", "--token", "--secret", "--auth", "--cookie", "--header"}
        else:
            sensitive_flags = {"-p", "-P", "--pass", "--password", "-a", "-token", "--token", "--secret", "--auth", "--cookie", "--header"}

        for i, arg in enumerate(args):
            if skip_next:
                redacted.append("***REDACTED***")
                skip_next = False
                continue

            lower_arg = arg.lower()
            if arg in sensitive_flags:
                redacted.append(arg)
                skip_next = True
            elif any(lower_arg.startswith(f"{f}=") for f in sensitive_flags):
                prefix = arg.split("=", 1)[0]
                redacted.append(f"{prefix}=***REDACTED***")
            else:
                redacted.append(arg)
        return " ".join(redacted)

    def cancel_job(self, job_id: str) -> bool:
        """Cancels an active running job by triggering runner cancellation."""
        with self._lock:
            runner = self._active_runners.get(job_id)
            job = self._jobs.get(job_id)

        if runner and runner.is_running:
            runner.cancel()
            if job:
                job.state = JobState.CANCELLED
                job.finished_at = _utc_now_iso()
            return True
        return False

    def get_job(self, job_id: str) -> Optional[ExecutionJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def execute_job_sync(
        self,
        job: ExecutionJob,
        on_output: Optional[Callable[[str, str], None]] = None,
        on_state_change: Optional[Callable[[ExecutionJob], None]] = None,
    ) -> ExecutionJob:
        """Synchronously executes a security job through the full operational lifecycle."""
        with self._lock:
            self._jobs[job.job_id] = job

        def change_state(new_state: JobState):
            job.state = new_state
            if on_state_change:
                try:
                    on_state_change(job)
                except Exception:
                    pass

        # 1. State: VALIDATING
        change_state(JobState.VALIDATING)

        # Scope and engagement verification
        if self.db and job.project_id:
            project = self.db.get_project(job.project_id)
            scopes = job.scopes if job.scopes is not None else self.db.list_scopes(job.project_id)
            scope_check = ScopeAuthorizationService.is_target_authorized(
                job.target, scopes, project=project
            )
            if not scope_check.is_allowed:
                job.error_message = f"Scope Blocked: {scope_check.reason}"
                change_state(JobState.BLOCKED)
                if on_output:
                    on_output(f"[-] Operational Block: Target '{job.target}' is unauthorized: {scope_check.reason}\n", "stderr")
                if self.db:
                    ActivityLogger(self.db).log(
                        project_id=job.project_id,
                        action="tool_execution_blocked",
                        outcome="blocked",
                        details={"tool": job.tool_name, "target": job.target, "reason": scope_check.reason},
                    )
                return job

        # Binary availability verification
        binary = job.command[0] if job.command else ""
        if not shutil.which(binary) and not os.path.exists(binary):
            tool = self.registry.get_tool(job.tool_name)
            resolved = tool.binary_path if tool else None
            if not resolved or not os.path.exists(resolved):
                job.error_message = f"Executable '{binary}' for tool '{job.tool_name}' not found on host."
                change_state(JobState.FAILED)
                if on_output:
                    on_output(f"[-] Execution Error: {job.error_message}\n", "stderr")
                return job
            job.command[0] = resolved

        # Create ToolExecution record in SQLite
        clean_command_str = self.redact_sensitive_args(job.command, tool_name=job.tool_name)
        if self.db and job.project_id:
            record = ToolExecution(
                project_id=job.project_id,
                tool_name=job.tool_name,
                command=clean_command_str,
                status=ExecutionStatus.RUNNING,
                assessment_id=job.assessment_id,
            )
            created_record = self.db.create_execution(record)
            job.execution_record_id = created_record.id
            job.execution_record = created_record

            ActivityLogger(self.db).log(
                project_id=job.project_id,
                action="tool_execution_started",
                outcome="running",
                details={
                    "tool": job.tool_name,
                    "target": job.target,
                    "command": clean_command_str,
                    "assessment_id": job.assessment_id,
                },
            )

        # 2. State: RUNNING
        change_state(JobState.RUNNING)
        job.started_at = _utc_now_iso()
        runner = job.runner or ProcessRunner()
        with self._lock:
            self._active_runners[job.job_id] = runner

        try:
            res: ProcessExecutionResult = runner.run(
                command=job.command,
                timeout=job.timeout,
                on_output=on_output,
                cwd=job.cwd,
                env=job.env,
            )
        finally:
            with self._lock:
                self._active_runners.pop(job.job_id, None)

        job.finished_at = res.finished_at
        job.duration_seconds = res.duration_seconds
        job.exit_code = res.exit_code
        job.stdout = res.stdout
        job.stderr = res.stderr

        # 3. Vault Cryptographic Evidence immediately upon process termination
        raw_output = job.custom_evidence_payload or (job.stdout if job.stdout.strip() else job.stderr)
        if raw_output.strip() and job.evidence_dir and self.db and job.project_id:
            try:
                job.evidence_dir.mkdir(parents=True, exist_ok=True)
                ext = job.custom_evidence_ext or ("xml" if ("<?xml" in raw_output or "<nmaprun" in raw_output) else ("json" if raw_output.strip().startswith(("{", "[")) else "log"))
                mime = job.custom_evidence_mime or ("application/xml" if ext == "xml" else ("application/json" if ext == "json" else "text/plain"))
                ev_file = job.evidence_dir / f"{job.tool_name}_{job.job_id}.{ext}"
                ev_file.write_text(raw_output, encoding="utf-8")

                sha256 = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
                job.evidence_hash = sha256
                evidence_entry = self.db.add_evidence(
                    Evidence(
                        project_id=job.project_id,
                        execution_id=job.execution_record_id,
                        file_path=str(ev_file),
                        sha256_hash=sha256,
                        description=f"Raw execution artifact from {job.tool_name} against {job.target} (Exit: {job.exit_code})",
                        mime_type=mime,
                        assessment_id=job.assessment_id,
                    )
                )
                job.evidence_id = evidence_entry.id
            except Exception as ev_err:
                if on_output:
                    on_output(f"[-] Warning: Failed to vault evidence artifact: {ev_err}\n", "stderr")

        def _persist_job_findings():
            if self.db and job.project_id and job.findings:
                from core.evidence_intelligence import EvidenceIntelligenceService
                ev_intel = EvidenceIntelligenceService(self.db)
                for f in job.findings:
                    f.project_id = job.project_id
                    if job.assessment_id:
                        f.assessment_id = job.assessment_id
                    if job.execution_record_id:
                        f.execution_id = job.execution_record_id
                    if job.evidence_id:
                        setattr(f, "evidence_id", job.evidence_id)
                    ev_intel.enforce_confirmed_evidence_guard(f, project_id=job.project_id)
                    saved = self.db.upsert_finding_deduplicated(f)
                    if job.evidence_id and saved and saved.id:
                        try:
                            with self.db.session() as conn:
                                conn.execute("UPDATE evidence SET finding_id = ? WHERE id = ? AND finding_id IS NULL", (saved.id, job.evidence_id))
                        except Exception:
                            pass

        if res.status == ExecutionStatus.CANCELLED:
            change_state(JobState.CANCELLED)
            job.error_message = "Execution cancelled by operator."
        elif res.status == ExecutionStatus.TIMEOUT:
            change_state(JobState.TIMED_OUT)
            job.error_message = f"Execution timed out after {job.timeout}s."
        elif res.status == ExecutionStatus.FAILED:
            change_state(JobState.FAILED)
            job.error_message = res.stderr.strip() or f"Process failed with exit code {res.exit_code}"
            if job.custom_parser and (res.stdout.strip() or res.stderr.strip()):
                try:
                    job.findings = job.custom_parser(job)
                except Exception as parse_err:
                    job.error_message += f" (Parser Error: {parse_err})"
            _persist_job_findings()
        else:
            # 4. State: PARSING
            change_state(JobState.PARSING)
            parser_failed = False
            if job.custom_parser:
                try:
                    job.findings = job.custom_parser(job)
                except Exception as parse_err:
                    job.error_message = f"Parser Error: {parse_err}"
                    parser_failed = True

            _persist_job_findings()

            if parser_failed or (job.exit_code is not None and job.exit_code != 0 and job.tool_name not in ("nikto",)):
                change_state(JobState.FAILED)
            else:
                change_state(JobState.COMPLETED)

        # 5. Post-Execution Callback Hook
        if job.post_execution_callback:
            try:
                job.post_execution_callback(job)
            except Exception as cb_err:
                logger.exception("Error in post_execution_callback for %s", job.job_id)
                if on_output:
                    on_output(f"[-] Post-execution callback error: {cb_err}\n", "stderr")

        # 5. Update DB Execution Record
        if self.db and job.execution_record_id:
            db_status = {
                JobState.COMPLETED: ExecutionStatus.COMPLETED,
                JobState.CANCELLED: ExecutionStatus.CANCELLED,
                JobState.TIMED_OUT: ExecutionStatus.TIMEOUT,
                JobState.FAILED: ExecutionStatus.FAILED,
                JobState.BLOCKED: ExecutionStatus.FAILED,
            }.get(job.state, ExecutionStatus.FAILED)

            exec_rec = ToolExecution(
                id=job.execution_record_id,
                project_id=job.project_id,
                tool_name=job.tool_name,
                command=clean_command_str,
                status=db_status,
                started_at=job.started_at or _utc_now_iso(),
                finished_at=job.finished_at or _utc_now_iso(),
                duration_seconds=job.duration_seconds,
                exit_code=job.exit_code,
                assessment_id=job.assessment_id,
            )
            self.db.update_execution(exec_rec)
            job.execution_record = exec_rec

            ActivityLogger(self.db).log(
                project_id=job.project_id,
                action="tool_execution_finished",
                outcome=job.state.value,
                details={
                    "tool": job.tool_name,
                    "target": job.target,
                    "state": job.state.value,
                    "exit_code": job.exit_code,
                    "findings_count": len(job.findings),
                },
            )

        return job

    def execute_job_async(
        self,
        job: ExecutionJob,
        on_output: Optional[Callable[[str, str], None]] = None,
        on_state_change: Optional[Callable[[ExecutionJob], None]] = None,
        on_done: Optional[Callable[[ExecutionJob], None]] = None,
    ) -> threading.Thread:
        """Launches the execution in an isolated background thread to keep PySide6 responsive."""
        def _worker():
            finished_job = self.execute_job_sync(
                job=job,
                on_output=on_output,
                on_state_change=on_state_change,
            )
            if on_done:
                try:
                    on_done(finished_job)
                except Exception:
                    pass

        thread = threading.Thread(target=_worker, name=f"Worker-{job.job_id}", daemon=True)
        thread.start()
        return thread

