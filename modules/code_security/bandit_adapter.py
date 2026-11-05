"""Bandit Python AST Code Security Scanner Adapter.

Safely invokes the Bandit static code analyzer, verifies dependencies,
streams execution progress, and parses JSON output into structured findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from core.registry import ToolRegistry
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


@dataclass
class BanditOptions:
    target_path: str
    severity_level: str = "all"  # "all", "low", "medium", "high"
    confidence_level: str = "all"
    timeout: float = 60.0


class BanditAdapter:
    """Orchestrates Python static application security testing (SAST) via Bandit."""

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def is_runnable(self) -> Tuple[bool, str]:
        """Checks if Bandit executable or module is available in the current environment."""
        if shutil.which("bandit"):
            return True, "Bandit host binary found."

        # Check if python module is importable
        try:
            import bandit  # noqa: F401
            import yaml  # noqa: F401
            return True, "Bandit Python library available."
        except ImportError as exc:
            return (
                False,
                f"Bandit dependencies missing ({exc}). Installation guidance: 'pip install bandit pyyaml stevedore'",
            )

    def build_command(self, options: BanditOptions) -> List[str]:
        """Constructs safe argument list for Bandit JSON execution."""
        binary = shutil.which("bandit") or "bandit"
        cmd = [binary, "-r", options.target_path, "-f", "json", "-q"]

        if options.severity_level == "medium":
            cmd.append("-m")
        elif options.severity_level == "high":
            cmd.append("-lll")

        return cmd

    def cancel(self) -> bool:
        return self.runner.cancel()

    def parse_output(self, json_text: str) -> List[dict]:
        """Parses Bandit JSON output into issue dictionaries."""
        try:
            data = json.loads(json_text)
            return data.get("results", [])
        except (json.JSONDecodeError, AttributeError):
            return []

    def execute_scan(
        self,
        project_id: int,
        options: BanditOptions,
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Verifies target path and runs Bandit scan, returning structured findings."""
        target = Path(options.target_path)
        if not target.exists():
            msg = f"Target code path does not exist: '{options.target_path}'"
            if on_output:
                on_output(f"[ERROR] {msg}\n", "stderr")
            return False, msg, [], None

        runnable, reason = self.is_runnable()
        if not runnable:
            if on_output:
                on_output(f"[DEPENDENCY ERROR] {reason}\n", "stderr")
            return False, reason, [], None

        try:
            command = self.build_command(options)
        except Exception as exc:
            return False, f"Command resolution failed: {exc}", [], None

        tool_exec = ToolExecution(
            project_id=project_id,
            tool_name="bandit",
            command=" ".join(command),
            status=ExecutionStatus.RUNNING,
        )
        saved_exec = self.db.create_tool_execution(tool_exec)

        proc_result: ProcessExecutionResult = self.runner.run(
            command=command,
            timeout=options.timeout,
            on_output=on_output,
        )

        saved_exec.finished_at = proc_result.finished_at
        saved_exec.status = proc_result.status
        saved_exec.exit_code = proc_result.exit_code
        self.db.update_tool_execution(saved_exec)

        full_output = proc_result.stdout + "\n" + proc_result.stderr

        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"bandit_exec_{saved_exec.id}.json"
            ev_file.write_text(proc_result.stdout or "{}", encoding="utf-8")
            sha256 = hashlib.sha256((proc_result.stdout or "").encode("utf-8")).hexdigest()

            evidence = Evidence(
                project_id=project_id,
                execution_id=saved_exec.id,
                file_path=str(ev_file),
                file_hash=sha256,
                description=f"Bandit SAST output for {target.name}",
            )
            self.db.create_evidence(evidence)

        raw_issues = self.parse_output(proc_result.stdout)
        findings: List[Finding] = []

        sev_map = {
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
        }

        for issue in raw_issues:
            test_id = issue.get("test_id", "B000")
            test_name = issue.get("test_name", "Unknown Issue")
            issue_text = issue.get("issue_text", "")
            raw_sev = issue.get("issue_severity", "LOW").upper()
            confidence = issue.get("issue_confidence", "LOW")
            fname = issue.get("filename", "")
            line = issue.get("line_number", 0)
            code_snippet = issue.get("code", "")

            finding = Finding(
                project_id=project_id,
                execution_id=saved_exec.id,
                title=f"SAST [{test_id}]: {issue_text or test_name}",
                description=(
                    f"Bandit identified security issue in '{fname}:{line}'.\n"
                    f"Confidence: {confidence}\n\nCode snippet:\n{code_snippet}"
                ),
                severity=sev_map.get(raw_sev, FindingSeverity.LOW),
                affected_asset=f"{fname}:{line}",
                remediation=f"Inspect line {line} of {fname} and refactor code according to Bandit {test_id} security recommendations.",
                validation_status=ValidationStatus.CONFIRMED,
            )
            created = self.db.create_finding(finding)
            findings.append(created)

        # Bandit exits with 0 on no findings, or 1 on findings detected
        is_success = proc_result.status == ExecutionStatus.COMPLETED and proc_result.exit_code in (0, 1)
        return is_success, f"Scan finished ({len(findings)} issues identified)", findings, saved_exec

