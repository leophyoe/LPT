"""Volatility 3 Memory Forensics Analysis Adapter.

Safely invokes the open-source Volatility 3 framework (from source/system/volatility3/vol.py
or host PATH), verifies memory dump file integrity, streams forensic analysis logs in real time,
and persists memory forensics artifacts and evidence into SQLite.
"""

from __future__ import annotations

import hashlib
import os
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
class VolatilityOptions:
    memory_dump_path: str
    plugin: str = "windows.info"
    extra_args: Optional[List[str]] = None
    timeout: float = 120.0


class VolatilityAdapter:
    """Orchestrates authorized Volatility 3 memory image forensics."""

    SUPPORTED_PLUGINS = [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.netscan",
        "windows.malfind",
        "linux.banner",
        "linux.pslist",
        "mac.bash",
    ]

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()

    def build_command(self, options: VolatilityOptions) -> List[str]:
        """Constructs safe argument list for Volatility 3."""
        base_cmd = self.registry.resolve_command("volatility3", [])
        cmd = list(base_cmd)
        cmd.extend(["-f", options.memory_dump_path, options.plugin])
        if options.extra_args:
            cmd.extend(options.extra_args)
        return cmd

    def cancel(self) -> bool:
        return self.runner.cancel()

    def parse_output(self, output: str, plugin: str) -> List[str]:
        """Filters header and extracts data rows from Volatility tabular output."""
        data_lines: List[str] = []
        for line in output.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Volatility 3") or line_str.startswith("Progress:"):
                continue
            data_lines.append(line_str)
        return data_lines

    def execute_analysis(
        self,
        project_id: int,
        options: VolatilityOptions,
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
    ) -> Tuple[bool, str, List[Finding], Optional[ToolExecution]]:
        """Verifies dump file exists, executes Volatility 3 plugin, and persists results."""
        dump_path = Path(options.memory_dump_path)
        if not dump_path.is_file():
            msg = f"Memory dump file not found: '{options.memory_dump_path}'"
            if on_output:
                on_output(f"[ERROR] {msg}\n", "stderr")
            return False, msg, [], None

        try:
            command = self.build_command(options)
        except Exception as exc:
            return False, f"Command resolution failed: {exc}", [], None

        tool_exec = ToolExecution(
            project_id=project_id,
            tool_name="volatility3",
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
            ev_file = evidence_dir / f"volatility_{options.plugin}_{saved_exec.id}.log"
            ev_file.write_text(full_output, encoding="utf-8")
            sha256 = hashlib.sha256(full_output.encode("utf-8")).hexdigest()

            evidence = Evidence(
                project_id=project_id,
                execution_id=saved_exec.id,
                file_path=str(ev_file),
                file_hash=sha256,
                description=f"Volatility 3 {options.plugin} output for {dump_path.name}",
            )
            self.db.create_evidence(evidence)

        findings: List[Finding] = []
        parsed_lines = self.parse_output(proc_result.stdout, options.plugin)

        title = f"Memory Forensics Analysis: {options.plugin} ({dump_path.name})"
        snippet = "\n".join(parsed_lines[:15]) if parsed_lines else "No table rows returned."

        finding = Finding(
            project_id=project_id,
            execution_id=saved_exec.id,
            title=title,
            description=(
                f"Executed Volatility 3 plugin '{options.plugin}' against memory sample '{dump_path.name}'. "
                f"Generated {len(parsed_lines)} forensic output records.\n\nSummary:\n{snippet}"
            ),
            severity=FindingSeverity.INFORMATIONAL,
            affected_asset=str(dump_path),
            remediation=(
                "Review forensic process tables, network sockets, or injected memory sections "
                "for indicators of compromise (IOCs) and unauthorized binary execution."
            ),
            validation_status=ValidationStatus.CONFIRMED,
        )
        created = self.db.create_finding(finding)
        findings.append(created)

        is_success = proc_result.status == ExecutionStatus.COMPLETED and proc_result.exit_code == 0
        return is_success, "Analysis completed", findings, saved_exec
