"""Nmap tool execution adapter.

Constructs validated Nmap scan commands, verifies target scope,
executes via ProcessRunner, parses XML output, imports external XML with
cryptographic provenance, and persists findings and asset nodes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from core.activity_logger import ActivityLogger
from core.asset_inventory import AssetInventoryService
from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.parsers.universal_parser import UniversalParser
from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.network.nmap_parser import NmapParser, NmapScanResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Evidence,
    ExecutionStatus,
    Finding,
    Project,
    TargetScope,
    ToolExecution,
)
from terminal.runner import ProcessRunner

logger = logging.getLogger(__name__)


class ScanProfile(str, Enum):
    PING_DISCOVERY = "ping_discovery"
    TOP_PORTS = "top_ports"
    SERVICE_VERSION = "service_version"
    OS_FINGERPRINT = "os_fingerprint"
    FIREWALL_DETECTION = "firewall_detection"
    UDP_SCAN = "udp_scan"
    CUSTOM = "custom"


@dataclass
class NmapScanOptions:
    target: str
    profile: ScanProfile = ScanProfile.TOP_PORTS
    ports: Optional[str] = None
    extra_args: Optional[List[str]] = None
    timeout: float = 300.0
    skip_host_discovery: bool = False


@dataclass
class NmapExecutionResult:
    is_authorized: bool
    scope_reason: str
    execution: Optional[ToolExecution] = None
    scan_result: Optional[NmapScanResult] = None
    findings: List[Finding] = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class NmapAdapter(BaseSecurityAdapter):
    """Orchestrates authorized Nmap scanning, execution, XML import, and finding creation."""

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def display_name(self) -> str:
        return "Nmap Network Scanner"

    ALLOWED_FLAGS = {
        "-sS", "-sT", "-sU", "-sV", "-sC", "-sn", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM", "-sO", "-b",
        "-Pn", "-P0", "-PE", "-PP", "-PM", "-PS", "-PA", "-PU", "-PY", "-n", "-R",
        "-F", "-p-",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-O", "--osscan-limit", "--osscan-guess",
        "--version-intensity", "--version-light", "--version-all", "--version-trace",
        "-v", "-vv", "-vvv", "-d", "-dd", "--reason", "--open", "--packet-trace",
    }

    ALLOWED_PARAM_PREFIXES = (
        "-p", "--top-ports", "--min-rate", "--max-rate",
        "--min-parallelism", "--max-parallelism",
        "--min-hostgroup", "--max-hostgroup",
        "--scan-delay", "--max-scan-delay",
        "--host-timeout", "--max-retries",
        "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
        "--stats-every",
    )

    PROHIBITED_PREFIXES = (
        "-iL", "-iR", "--random-targets", "--exclude", "--excludefile",
        "--script", "--script-args", "--script-args-file", "--script-help", "--script-trace", "--script-updatedb",
        "-oN", "-oX", "-oG", "-oA", "-oS", "--stylesheet", "--webxml", "--no-stylesheet", "--resume",
        "--interactive", "--privileged", "--unprivileged",
    )

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        super().__init__(db)
        self.registry = registry or ToolRegistry()
        self.runner = ProcessRunner()
        self.execution_service = ToolExecutionService(db=db)

    @classmethod
    def validate_extra_arg(cls, arg: str) -> None:
        """Validates that an extra CLI option complies with security allowlist."""
        if not arg or not isinstance(arg, str):
            raise ValueError("Empty or invalid argument type in Nmap options.")

        # Reject command separators or shell metacharacters
        if any(c in arg for c in (";", "|", "&", "$", "`", "\n", "\r")):
            raise ValueError(f"Prohibited metacharacter in Nmap option: '{arg}'")

        # Explicitly check prohibited prefixes first
        for p in cls.PROHIBITED_PREFIXES:
            if arg == p or arg.startswith(p + "=") or arg.startswith(p):
                raise ValueError(f"Prohibited Nmap option rejected: '{arg}'. Scope evasion and output redirection are prohibited.")

        # Check exact allowed flags
        if arg in cls.ALLOWED_FLAGS:
            return

        # Check parameter options
        for prefix in cls.ALLOWED_PARAM_PREFIXES:
            if arg == prefix:
                return  # Flag itself, followed by value in next arg
            if arg.startswith(prefix + "="):
                val = arg[len(prefix) + 1:]
                if not re.match(r"^[0-9a-zA-Z,\.\-:]+$", val):
                    raise ValueError(f"Invalid characters in option value: '{arg}'")
                return
            if arg.startswith(prefix) and not prefix.startswith("--"):
                val = arg[len(prefix):]
                if re.match(r"^[0-9a-zA-Z,\.\-:]+$", val):
                    return

        # If it's a numeric/safe standalone parameter value following an option
        if re.match(r"^[0-9a-zA-Z,\.\-:]+$", arg):
            return

        raise ValueError(f"Unsupported Nmap option rejected: '{arg}'. Only authorized scan options are permitted.")

    def build_command(self, options: NmapScanOptions) -> List[str]:
        """Construct a safe argument list for Nmap execution."""
        nmap_meta = self.registry.get_tool("nmap")
        binary = nmap_meta.binary_path if (nmap_meta and nmap_meta.binary_path) else "nmap"

        cmd = [binary]

        is_root = False
        try:
            is_root = (os.geteuid() == 0)
        except AttributeError:
            is_root = True

        if options.skip_host_discovery:
            cmd.append("-Pn")

        if options.profile == ScanProfile.PING_DISCOVERY:
            cmd.extend(["-sn"])
        elif options.profile == ScanProfile.TOP_PORTS:
            cmd.extend(["-F", "-T4"])
        elif options.profile == ScanProfile.SERVICE_VERSION:
            cmd.extend(["-sV", "-T4"])
        elif options.profile == ScanProfile.OS_FINGERPRINT:
            if is_root:
                cmd.extend(["-O", "-sV", "-T4"])
            else:
                # -O requires raw sockets / root. Gracefully fall back to comprehensive version detection
                cmd.extend(["-sV", "--version-all", "-T4"])
        elif options.profile == ScanProfile.FIREWALL_DETECTION:
            cmd.extend(["-sA", "-T4"])
            if "-Pn" not in cmd:
                cmd.append("-Pn")
        elif options.profile == ScanProfile.UDP_SCAN:
            cmd.extend(["-sU", "-F", "-T4"])
        elif options.profile == ScanProfile.CUSTOM and options.ports:
            cmd.extend(["-p", options.ports])

        if options.ports and options.profile not in (ScanProfile.CUSTOM, ScanProfile.PING_DISCOVERY):
            cmd.extend(["-p", options.ports])

        if options.extra_args:
            for arg in options.extra_args:
                self.validate_extra_arg(arg)
                cmd.append(arg)

        # Force XML output to stdout for programmatic parsing
        cmd.extend(["-oX", "-"])
        cmd.append(options.target)

        return cmd

    def _sync_assets(
        self,
        project_id: int,
        scan_result: NmapScanResult,
        scopes: List[TargetScope],
        session_id: Optional[str] = None,
        source_tool: str = "nmap",
        evidence_id: Optional[int] = None,
    ) -> None:
        """Persist discovered in-scope hosts and hostnames to the asset inventory with historical observations."""
        AssetInventoryService(self.db).sync_scan_assets(
            project_id=project_id,
            scan_result=scan_result,
            scopes=scopes,
            session_id=session_id,
            source_tool=source_tool,
            evidence_id=evidence_id,
        )

    def execute_scan(
        self,
        project_id: int,
        options: NmapScanOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        project: Optional[Project] = None,
        session_id: Optional[str] = None,
        assessment_id: Optional[int] = None,
    ) -> NmapExecutionResult:
        """Validate scope and lifecycle, run Nmap through centralized ToolExecutionService, parse results, record findings, and sync assets."""
        # 1. Enforce Scope and Engagement Lifecycle Validation
        if project is None and self.db and project_id:
            project = self.db.get_project(project_id)

        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            options.target, scopes, project=project
        )
        if not scope_check.is_allowed:
            return NmapExecutionResult(
                is_authorized=False,
                scope_reason=scope_check.reason,
            )

        # 2. Build command (enforces security allowlist)
        try:
            command = self.build_command(options)
        except ValueError as exc:
            return NmapExecutionResult(
                is_authorized=False,
                scope_reason=f"Security Validation Blocked: {exc}",
            )

        parsed_scan_result: List[Optional[NmapScanResult]] = [None]
        nmap_findings: List[Finding] = []

        def custom_parser(job: ExecutionJob) -> List[Finding]:
            raw_xml = job.stdout
            if not raw_xml.strip():
                if job.exit_code != 0 and job.stderr.strip():
                    err_f = Finding(
                        project_id=project_id,
                        title=f"Nmap Execution Failure (Exit Code {job.exit_code})",
                        severity=FindingSeverity.INFORMATIONAL,
                        affected_asset=options.target,
                        affected_port_service="cli/error",
                        description=f"Nmap command failed with exit code {job.exit_code}.\nError output:\n{job.stderr.strip()[:400]}",
                        remediation="Verify target address format, port specifications, and authorization rules.",
                        validation_status=ValidationStatus.OBSERVED,
                        source_tool="nmap",
                        execution_id=job.execution_record_id,
                    )
                    if assessment_id:
                        err_f.assessment_id = assessment_id
                    nmap_findings.append(err_f)
                    return [err_f]
                parse_err = ValueError("Nmap completed without XML output.")
                if on_output:
                    on_output(f"[-] Failed to parse Nmap output: {parse_err}\n", "stderr")
                raise parse_err

            try:
                if "<nmaprun" in raw_xml or "<?xml" in raw_xml:
                    sr = NmapParser.parse_xml(raw_xml)
                elif "Nmap scan report for" in raw_xml:
                    sr = NmapParser.parse_text(raw_xml)
                    if not sr.hosts:
                        sr = NmapParser.parse_xml(raw_xml)
                else:
                    sr = NmapParser.parse_xml(raw_xml)

                parsed_scan_result[0] = sr
                f_list = NmapParser.to_findings(
                    sr, project_id=project_id, execution_id=job.execution_record_id
                )

                for f in f_list:
                    if assessment_id:
                        f.assessment_id = assessment_id
                    nmap_findings.append(f)
                return f_list
            except (ValueError, Exception) as exc:
                logger.exception("Could not parse Nmap XML output for execution %s", job.execution_record_id)
                if on_output:
                    on_output(f"[-] Failed to parse Nmap XML output: {exc}\n", "stderr")
                raise exc

        def post_exec_hook(job: ExecutionJob):
            if parsed_scan_result[0] is not None:
                self._sync_assets(
                    project_id,
                    parsed_scan_result[0],
                    scopes,
                    session_id=session_id,
                    source_tool="nmap",
                    evidence_id=job.evidence_id,
                )

        job = ExecutionJob(
            tool_name="nmap",
            display_name="Nmap Network Scanner",
            target=options.target,
            command=command,
            project_id=project_id,
            scopes=scopes,
            assessment_id=assessment_id,
            timeout=options.timeout,
            evidence_dir=evidence_dir,
            runner=self.runner,
            custom_parser=custom_parser,
            post_execution_callback=post_exec_hook,
        )

        finished_job = self.execution_service.execute_job_sync(
            job=job,
            on_output=on_output,
        )

        db_execution = finished_job.execution_record or (self.db.get_execution(finished_job.execution_record_id, project_id=project_id) if (self.db and finished_job.execution_record_id) else None)

        return NmapExecutionResult(
            is_authorized=True,
            scope_reason=scope_check.reason,
            execution=db_execution,
            scan_result=parsed_scan_result[0],
            findings=nmap_findings,
        )

    def import_nmap_xml(
        self,
        project_id: int,
        xml_content: str,
        scopes: List[TargetScope],
        source_filename: str = "imported_nmap.xml",
        evidence_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        assessment_id: Optional[int] = None,
    ) -> NmapExecutionResult:
        """Import externally generated Nmap XML with cryptographic provenance, session linkage, and scope checks."""
        if not xml_content or not xml_content.strip():
            ActivityLogger(self.db).log(
                project_id=project_id,
                action="scan_import_failed",
                outcome="failed",
                session_id=session_id,
                details={"source": source_filename, "error": "Empty XML content"},
            )
            raise ValueError("Provided Nmap XML content is empty.")

        try:
            scan_result = NmapParser.parse_xml(xml_content)
        except Exception as parse_err:
            ActivityLogger(self.db).log(
                project_id=project_id,
                action="scan_import_failed",
                outcome="failed",
                session_id=session_id,
                details={"source": source_filename, "error": str(parse_err)},
            )
            raise ValueError(f"Malformed or incomplete Nmap XML file: {parse_err}") from parse_err

        if not scan_result.hosts:
            ActivityLogger(self.db).log(
                project_id=project_id,
                action="scan_import_failed",
                outcome="failed",
                session_id=session_id,
                details={"source": source_filename, "error": "No hosts found in XML"},
            )
            raise ValueError("No hosts found in the provided Nmap XML file.")

        # Re-check scope for each discovered host (fail-closed per host)
        in_scope_hosts = []
        out_of_scope_hosts = []

        for host in scan_result.hosts:
            chk = ScopeAuthorizationService.is_target_authorized(host.ip, scopes)
            if chk.is_allowed:
                in_scope_hosts.append(host)
            else:
                out_of_scope_hosts.append(host.ip)

        if not in_scope_hosts:
            ActivityLogger(self.db).log(
                project_id=project_id,
                action="scan_import_blocked",
                outcome="blocked",
                session_id=session_id,
                details={"source": source_filename, "quarantined_hosts": out_of_scope_hosts},
            )
            return NmapExecutionResult(
                is_authorized=False,
                scope_reason=f"All hosts in imported XML are outside authorized scope: {', '.join(out_of_scope_hosts)}",
                scan_result=scan_result,
            )

        # Create execution record to record provenance
        cmd_summary = f"import_nmap_xml(source='{Path(source_filename).name}', args='{scan_result.command_args}')"
        execution = ToolExecution(
            project_id=project_id,
            tool_name="nmap_import",
            command=cmd_summary,
            status=ExecutionStatus.COMPLETED,
            assessment_id=assessment_id,
        )
        execution = self.db.create_execution(execution)

        # Store evidence with SHA-256 hash
        sha256 = hashlib.sha256(xml_content.encode("utf-8")).hexdigest()
        evidence_entry = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"nmap_import_{execution.id}_{Path(source_filename).name}"
            ev_file.write_text(xml_content, encoding="utf-8")
            execution.raw_output_path = str(ev_file)

            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Imported Nmap XML from '{Path(source_filename).name}' (Execution #{execution.id})",
                    mime_type="application/xml",
                    assessment_id=assessment_id,
                )
            )

        self.db.update_execution(execution)

        # Filter scan result to only in-scope hosts
        filtered_result = NmapScanResult(
            command_args=scan_result.command_args,
            hosts=in_scope_hosts,
            raw_xml=xml_content,
            scanner=scan_result.scanner,
            version=scan_result.version,
            start_time=scan_result.start_time,
            finish_time=scan_result.finish_time,
            summary=scan_result.summary,
        )

        findings = NmapParser.to_findings(
            filtered_result, project_id=project_id, execution_id=execution.id
        )
        for f in findings:
            if assessment_id:
                f.assessment_id = assessment_id
            self.db.upsert_finding_deduplicated(f)

        self._sync_assets(
            project_id,
            filtered_result,
            scopes,
            session_id=session_id,
            source_tool="nmap_import",
            evidence_id=evidence_entry.id if evidence_entry else None,
        )

        ActivityLogger(self.db).log(
            project_id=project_id,
            action="nmap_xml_imported",
            outcome="success",
            session_id=session_id,
            details={
                "source": Path(source_filename).name,
                "in_scope_count": len(in_scope_hosts),
                "quarantined_count": len(out_of_scope_hosts),
                "execution_id": execution.id,
            },
        )

        reason = f"Successfully imported {len(in_scope_hosts)} in-scope host(s)."
        if out_of_scope_hosts:
            reason += f" Quarantined {len(out_of_scope_hosts)} out-of-scope host(s): {', '.join(out_of_scope_hosts)}."

        return NmapExecutionResult(
            is_authorized=True,
            scope_reason=reason,
            execution=execution,
            scan_result=filtered_result,
            findings=findings,
        )
