"""FFUF (Fuzz Faster U Fool) Web Fuzzer Adapter.

Safely orchestrates authorized FFUF fuzzing executions via ToolExecutionService,
enforces pre-execution target scope authorization, parses JSON or text output
into structured findings, and records evidence with cryptographic provenance.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
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
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner

logger = logging.getLogger(__name__)


@dataclass
class FFUFOptions:
    target_url: str
    wordlist_path: Optional[str] = None
    threads: int = 20
    timeout: float = 60.0
    extensions: Optional[str] = None
    filter_status: Optional[str] = "404"
    extra_args: Optional[List[str]] = None


class FFUFAdapter(BaseSecurityAdapter):
    """Adapter for authorized FFUF endpoint fuzzing with scope boundaries."""

    @property
    def tool_name(self) -> str:
        return "ffuf"

    @property
    def display_name(self) -> str:
        return "FFUF Fast Web Fuzzer"

    DEFAULT_FALLBACK_WORDS = [
        "admin", "login", "api", "dashboard", "robots.txt",
        ".git", "backup", "config", "test", "v1", "v2",
        "portal", "console", "server-status", "health",
        "swagger", "openapi.json", "env", ".env", "uploads",
    ]

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db)
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()
        self.execution_service = ToolExecutionService(db=db)

    def resolve_wordlist(self, user_path: Optional[str] = None) -> Tuple[str, bool]:
        """Resolves existing wordlist or creates a temporary fallback list."""
        if user_path and Path(user_path).is_file():
            return user_path, False

        candidates = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for c in candidates:
            if Path(c).is_file():
                return c, False

        tmp = tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False)
        tmp.write("\n".join(self.DEFAULT_FALLBACK_WORDS) + "\n")
        tmp.flush()
        tmp.close()
        return tmp.name, True

    def build_command(self, options: FFUFOptions, wordlist_path: str) -> List[str]:
        """Builds safe command list for ffuf execution."""
        url = options.target_url.rstrip("/")
        if "FUZZ" not in url:
            url = f"{url}/FUZZ"

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist_path,
            "-t", str(options.threads),
            "-timeout", str(int(options.timeout)),
            "-s",  # silent / cleaner JSON stdout
            "-json",
        ]

        if options.filter_status:
            cmd.extend(["-fc", str(options.filter_status)])

        if options.extensions:
            cmd.extend(["-e", options.extensions])

        if options.extra_args:
            cmd.extend(options.extra_args)

        return cmd

    def run_fuzz(
        self,
        project_id: int,
        options: FFUFOptions,
        scopes: List[TargetScope],
        project: Optional[Project] = None,
        assessment_id: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Executes authorized FFUF scan within scope boundary."""
        target_url = options.target_url.strip()
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.hostname or target_url

        if project is None and self.db and project_id:
            project = self.db.get_project(project_id)

        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            host, scopes, project=project
        )
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[SCOPE REJECTED] Target '{host}' is outside authorized scope: {scope_check.reason}\n", "stderr")
            return False, f"Target out of scope: {scope_check.reason}", [], None

        wordlist_path, is_temp = self.resolve_wordlist(options.wordlist_path)

        try:
            command = self.build_command(options, wordlist_path)
        except Exception as exc:
            if is_temp and os.path.exists(wordlist_path):
                os.unlink(wordlist_path)
            return False, f"Command resolution failed: {exc}", [], None

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            norm_findings, _ = UniversalParser.parse(
                raw_output=job.stdout,
                tool_hint="ffuf",
                target_url=target_url,
                execution_id=job.execution_record_id,
            )
            findings: List[Finding] = []
            for nf in norm_findings:
                f = nf.to_finding(project_id=project_id)
                f.assessment_id = assessment_id
                findings.append(f)
            return findings

        job = ExecutionJob(
            tool_name="ffuf",
            display_name="FFUF Fast Web Fuzzer",
            target=host,
            command=command,
            project_id=project_id,
            scopes=scopes,
            assessment_id=assessment_id,
            timeout=options.timeout,
            evidence_dir=evidence_dir,
            runner=self.runner,
            custom_parser=custom_parser,
        )

        try:
            finished_job = self.execution_service.execute_job_sync(
                job=job,
                on_output=on_output,
            )
        finally:
            if is_temp and os.path.exists(wordlist_path):
                try:
                    os.unlink(wordlist_path)
                except OSError:
                    pass

        db_execution = finished_job.execution_record or (
            self.db.get_execution(finished_job.execution_record_id, project_id=project_id)
            if (self.db and finished_job.execution_record_id)
            else None
        )
        is_success = (finished_job.state == JobState.COMPLETED)
        status_msg = f"FFUF completed ({len(finished_job.findings)} endpoints found)" if is_success else (finished_job.error_message or "Execution Failed")

        return is_success, status_msg, finished_job.findings, db_execution

