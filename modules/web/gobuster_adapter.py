"""Gobuster Directory and Endpoint Brute-Forcing Adapter.

Safely invokes the open-source Gobuster engine (host binary /usr/bin/gobuster),
enforces pre-execution target scope authorization, streams discovered paths in real time,
and persists valid endpoints and sensitive paths as structured findings in SQLite.
"""

from __future__ import annotations

import hashlib
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
class GobusterOptions:
    target_url: str
    wordlist_path: Optional[str] = None
    threads: int = 10
    timeout: float = 60.0
    extensions: Optional[str] = None


@dataclass
class DiscoveredEndpoint:
    path: str
    status_code: int
    size: Optional[int] = None
    redirect_url: Optional[str] = None


class GobusterAdapter(BaseSecurityAdapter):
    """Orchestrates authorized Gobuster endpoint enumeration with scope guard and persistence."""

    @property
    def tool_name(self) -> str:
        return "gobuster"

    @property
    def display_name(self) -> str:
        return "Gobuster Directory Fuzzer"

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
        """Resolves an existing wordlist on the host or generates a safe temporary one.
        
        Returns (resolved_path, is_temporary).
        """
        if user_path and Path(user_path).is_file():
            return user_path, False

        # Known standard wordlists on Linux/Debian/Ubuntu
        candidates = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for c in candidates:
            if Path(c).is_file():
                return c, False

        # Create temporary fallback wordlist
        tmp = tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False)
        tmp.write("\n".join(self.DEFAULT_FALLBACK_WORDS) + "\n")
        tmp.flush()
        tmp.close()
        return tmp.name, True

    def build_command(self, options: GobusterOptions, wordlist_file: str) -> List[str]:
        """Constructs safe argument list for Gobuster directory scan."""
        base_cmd = self.registry.resolve_command("gobuster", [])
        cmd = list(base_cmd)
        cmd.extend([
            "dir",
            "-u", options.target_url,
            "-w", wordlist_file,
            "-q",
            "--no-color",
            "-t", str(max(1, min(options.threads, 50))),
        ])
        if options.extensions:
            cmd.extend(["-x", options.extensions])
        return cmd

    def cancel(self) -> bool:
        return self.runner.cancel()

    def parse_output(self, output: str) -> List[DiscoveredEndpoint]:
        """Parses Gobuster standard output lines into structured endpoints."""
        endpoints: List[DiscoveredEndpoint] = []
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output)

        for line in clean_text.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("[+]"):
                continue

            # Example: "/admin (Status: 301) [Size: 178] [--> http://127.0.0.1/admin/]"
            # Or: "/login (Status: 200) [Size: 4523]"
            match = re.search(
                r"^([^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*([^\s\]]+)\])?",
                line,
            )
            if match:
                path = match.group(1).strip()
                status_code = int(match.group(2))
                size = int(match.group(3)) if match.group(3) else None
                redirect_url = match.group(4).strip() if match.group(4) else None
                endpoints.append(
                    DiscoveredEndpoint(
                        path=path,
                        status_code=status_code,
                        size=size,
                        redirect_url=redirect_url,
                    )
                )

        return endpoints

    def execute_scan(
        self,
        project_id: int,
        options: GobusterOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        project: Optional[Project] = None,
        assessment_id: Optional[int] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Validates scope and lifecycle, runs Gobuster via ToolExecutionService, and parses findings."""
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

        # 2. Resolve Wordlist
        wordlist_path, is_temp = self.resolve_wordlist(options.wordlist_path)

        try:
            command = self.build_command(options, wordlist_path)
        except Exception as exc:
            if is_temp and os.path.exists(wordlist_path):
                os.unlink(wordlist_path)
            return False, f"Command resolution failed: {exc}", [], None

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            endpoints = self.parse_output(job.stdout)
            findings: List[Finding] = []
            sensitive_patterns = [r"\.git", r"\.env", r"backup", r"config", r"swagger", r"admin"]

            for ep in endpoints:
                is_sensitive = any(re.search(pat, ep.path, re.IGNORECASE) for pat in sensitive_patterns)
                severity = FindingSeverity.MEDIUM if (is_sensitive and ep.status_code == 200) else FindingSeverity.INFORMATIONAL

                title = f"Discovered Endpoint: {ep.path} (HTTP {ep.status_code})"
                description = (
                    f"Web content enumeration identified endpoint '{ep.path}' with HTTP status {ep.status_code} "
                    f"on target '{target_url}' (Response size: {ep.size or 'N/A'} bytes)."
                )
                if ep.redirect_url:
                    description += f" Redirects to: {ep.redirect_url}"

                remediation = (
                    "Ensure that access control mechanisms are enforced on administrative or sensitive endpoints. "
                    "Disable directory listings and remove unnecessary backup or configuration files."
                )

                finding = Finding(
                    project_id=project_id,
                    execution_id=job.execution_record_id,
                    title=title,
                    description=description,
                    severity=severity,
                    affected_asset=f"{target_url.rstrip('/')}{ep.path}",
                    remediation=remediation,
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="gobuster",
                    assessment_id=assessment_id,
                )
                findings.append(finding)

            if not findings and job.stdout.strip():
                norm_findings, _ = UniversalParser.parse(
                    raw_output=job.stdout,
                    tool_hint="gobuster",
                    target_url=target_url,
                    execution_id=job.execution_record_id,
                )
                for nf in norm_findings:
                    f = nf.to_finding(project_id=project_id)
                    f.assessment_id = assessment_id
                    findings.append(f)

            return findings

        job = ExecutionJob(
            tool_name="gobuster",
            display_name="Gobuster Directory Fuzzer",
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

        db_execution = finished_job.execution_record or (self.db.get_execution(finished_job.execution_record_id, project_id=project_id) if (self.db and finished_job.execution_record_id) else None)
        is_success = (finished_job.state == JobState.COMPLETED)
        status_msg = f"Scan finished ({len(finished_job.findings)} endpoints discovered)" if is_success else (finished_job.error_message or "Execution Failed")

        return is_success, status_msg, finished_job.findings, db_execution
