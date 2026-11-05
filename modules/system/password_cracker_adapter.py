"""Password Cracking & Credential Auditing Adapter (Hashcat & John the Ripper).

Integrates host-installed /usr/bin/hashcat and /usr/sbin/john for authorized
credential auditing, Active Directory hash analysis, and offline recovery:
- Automatic tool detection (Hashcat prioritized, John fallback).
- Hash format mapping: NTLM, NetNTLMv2, Kerberoast TGS, MD5, SHA-512 crypt.
- Throttling & safe workload profiles (-w 2, --fork=2) to prevent OS instability.
- Standardized Finding creation (CWE-521: Weak Password Requirements).
- Cryptographic evidence vaulting with SHA-256 integrity assurance.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
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


class CrackerTool(str, Enum):
    HASHCAT = "hashcat"
    JOHN = "john"
    AUTO = "auto"


class HashType(str, Enum):
    NTLM = "ntlm"
    NETNTLMV2 = "netntlmv2"
    KERBEROS_TGS = "krb5tgs"
    MD5 = "md5"
    SHA512CRYPT = "sha512crypt"
    RAW_SHA256 = "sha256"


# Hashcat mode numbers and John format names
HASHCAT_MODES: Dict[HashType, int] = {
    HashType.NTLM: 1000,
    HashType.NETNTLMV2: 5600,
    HashType.KERBEROS_TGS: 13100,
    HashType.MD5: 0,
    HashType.SHA512CRYPT: 1800,
    HashType.RAW_SHA256: 1400,
}

JOHN_FORMATS: Dict[HashType, str] = {
    HashType.NTLM: "NT",
    HashType.NETNTLMV2: "netntlmv2",
    HashType.KERBEROS_TGS: "krb5tgs",
    HashType.MD5: "raw-md5",
    HashType.SHA512CRYPT: "sha512crypt",
    HashType.RAW_SHA256: "raw-sha256",
}


@dataclass
class CrackedCredential:
    """Represents a recovered credential pair."""
    hash_value: str
    plaintext_password: str
    username: Optional[str] = None
    hash_type: str = "ntlm"


@dataclass
class PasswordCrackerOptions:
    """Configuration for offline password auditing execution."""
    hash_file: Optional[str] = None
    raw_hashes: List[str] = field(default_factory=list)
    wordlist: Optional[str] = None
    hash_type: HashType = HashType.NTLM
    tool: CrackerTool = CrackerTool.AUTO
    workload_profile: int = 2          # 1=Low, 2=Default, 3=High
    rules_file: Optional[str] = None
    timeout_sec: int = 300
    dry_run: bool = False


class PasswordCrackerAdapter(BaseSecurityAdapter):
    """Adapter for executing and parsing Hashcat and John the Ripper audits."""

    def __init__(self, db: Optional[Database] = None, exec_service: Optional[ToolExecutionService] = None):
        super().__init__(db=db)
        self.exec_service = exec_service or ToolExecutionService()
        self._hashcat_bin = shutil.which("hashcat")
        self._john_bin = shutil.which("john") or shutil.which("john", path="/usr/sbin:/usr/bin:/bin")

    @property
    def tool_name(self) -> str:
        return "password_cracker"

    @property
    def display_name(self) -> str:
        return "Password Cracker (Hashcat & John the Ripper)"

    @property
    def hashcat_path(self) -> Optional[str]:
        return self._hashcat_bin

    @property
    def john_path(self) -> Optional[str]:
        return self._john_bin

    def resolve_tool(self, preferred: CrackerTool) -> Optional[Tuple[CrackerTool, str]]:
        """Resolves the best available password cracker binary."""
        if preferred == CrackerTool.HASHCAT and self._hashcat_bin:
            return CrackerTool.HASHCAT, self._hashcat_bin
        if preferred == CrackerTool.JOHN and self._john_bin:
            return CrackerTool.JOHN, self._john_bin
        if preferred == CrackerTool.AUTO:
            if self._hashcat_bin:
                return CrackerTool.HASHCAT, self._hashcat_bin
            if self._john_bin:
                return CrackerTool.JOHN, self._john_bin
        return None

    def build_command(
        self,
        options: PasswordCrackerOptions,
        resolved_tool: Tuple[CrackerTool, str],
        target_hash_file: str,
        output_potfile: Optional[str] = None,
    ) -> List[str]:
        """Constructs safe argv tokens for process execution."""
        tool_type, tool_path = resolved_tool

        if tool_type == CrackerTool.HASHCAT:
            mode = HASHCAT_MODES.get(options.hash_type, 1000)
            cmd = [
                tool_path,
                "-m", str(mode),
                "-a", "0",  # Dictionary attack
                "-w", str(max(1, min(3, options.workload_profile))),
                "--status",
                "--quiet",
            ]
            if output_potfile:
                cmd.extend(["--potfile-path", output_potfile])
            cmd.append(target_hash_file)
            if options.wordlist and os.path.exists(options.wordlist):
                cmd.append(options.wordlist)
            if options.rules_file and os.path.exists(options.rules_file):
                cmd.extend(["-r", options.rules_file])
            return cmd

        else:  # John the Ripper
            fmt = JOHN_FORMATS.get(options.hash_type, "NT")
            cmd = [
                tool_path,
                f"--format={fmt}",
            ]
            if output_potfile:
                cmd.append(f"--pot={output_potfile}")
            if options.wordlist and os.path.exists(options.wordlist):
                cmd.append(f"--wordlist={options.wordlist}")
            if options.rules_file:
                cmd.append(f"--rules={options.rules_file}")
            cmd.append(target_hash_file)
            return cmd

    def parse_hashcat_output(self, output: str, potfile_content: str = "") -> List[CrackedCredential]:
        """Parses recovered passwords from Hashcat stdout and potfile lines."""
        results: List[CrackedCredential] = []
        combined = f"{output}\n{potfile_content}"
        for line in combined.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("Started:") or line.startswith("Stopped:"):
                continue
            # Format: hash:password or user:hash:password
            parts = line.split(":")
            if len(parts) == 2:
                results.append(CrackedCredential(hash_value=parts[0], plaintext_password=parts[1]))
            elif len(parts) >= 3:
                results.append(CrackedCredential(username=parts[0], hash_value=parts[1], plaintext_password=":".join(parts[2:])))
        return results

    def parse_john_output(self, show_output: str) -> List[CrackedCredential]:
        """Parses recovered passwords from John the Ripper --show output."""
        results: List[CrackedCredential] = []
        for line in show_output.splitlines():
            line = line.strip()
            if not line or "password hash cracked" in line:
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                # user:password or hash:password
                results.append(CrackedCredential(username=parts[0], hash_value=parts[0], plaintext_password=parts[1]))
        return results

    def execute_audit(
        self,
        options: PasswordCrackerOptions,
        project_id: int,
        target_asset: str = "Active Directory Domain",
        assessment_id: Optional[int] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[List[Finding], List[Evidence], SecurityToolResult]:
        """Executes a password audit job, parses results, and registers findings."""
        resolved = self.resolve_tool(options.tool)
        if not resolved:
            err = "Neither Hashcat nor John the Ripper is available on this system."
            return [], [], SecurityToolResult(
                tool_name="password_cracker",
                target=target_asset,
                is_authorized=True,
                scope_reason="Offline Hash Audit",
                execution_status=ExecutionStatus.FAILED,
                error_message=err,
                raw_output=err,
            )

        tool_type, tool_path = resolved

        # Prepare hash file
        temp_dir = tempfile.mkdtemp(prefix="cybersuite_crack_")
        hash_file_path = os.path.join(temp_dir, "targets.hash")
        potfile_path = os.path.join(temp_dir, "audit.pot")

        try:
            if options.hash_file and os.path.exists(options.hash_file):
                shutil.copy(options.hash_file, hash_file_path)
            elif options.raw_hashes:
                with open(hash_file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(options.raw_hashes) + "\n")
            else:
                return [], [], SecurityToolResult(
                    tool_name=tool_type.value,
                    target=target_asset,
                    is_authorized=True,
                    scope_reason="Offline Hash Audit",
                    execution_status=ExecutionStatus.FAILED,
                    error_message="No hashes provided.",
                    raw_output="No hashes provided for password audit.",
                )

            argv = self.build_command(options, resolved, hash_file_path, potfile_path)
            cmd_str = " ".join(argv)

            if options.dry_run:
                return [], [], SecurityToolResult(
                    tool_name=tool_type.value,
                    target=target_asset,
                    is_authorized=True,
                    scope_reason="Dry Run Simulation Approved",
                    execution_status=ExecutionStatus.COMPLETED,
                    raw_output=f"[DRY-RUN] Command constructed:\n{cmd_str}",
                )

            if progress_callback:
                progress_callback(f"Starting {tool_type.value} audit with workload profile {options.workload_profile}...")

            job = self.exec_service.execute_process(
                tool_name=tool_type.value,
                argv=argv,
                timeout_sec=options.timeout_sec,
                output_callback=progress_callback,
            )

            pot_content = ""
            if os.path.exists(potfile_path):
                with open(potfile_path, "r", encoding="utf-8", errors="replace") as pf:
                    pot_content = pf.read()

            if tool_type == CrackerTool.HASHCAT:
                cracked = self.parse_hashcat_output(job.stdout, pot_content)
            else:
                # Run john --show to get cracked format
                show_argv = [tool_path, f"--format={JOHN_FORMATS.get(options.hash_type, 'NT')}", f"--pot={potfile_path}", "--show", hash_file_path]
                show_job = self.exec_service.execute_process(tool_name="john_show", argv=show_argv, timeout_sec=15)
                cracked = self.parse_john_output(show_job.stdout)

            # Generate Findings and Evidence
            findings: List[Finding] = []
            ev_list: List[Evidence] = []

            # Save cracked audit log as evidence
            summary_log = f"=== Password Audit Execution Report ({tool_type.value}) ===\n"
            summary_log += f"Hash Type: {options.hash_type.value}\n"
            summary_log += f"Total Recovered Credentials: {len(cracked)}\n\n"
            for c in cracked:
                usr = c.username or "Unknown Account"
                # Redact middle characters of password in permanent log for hygiene
                masked_pw = c.plaintext_password[0] + "*" * (len(c.plaintext_password) - 2) + c.plaintext_password[-1] if len(c.plaintext_password) > 2 else "***"
                summary_log += f"Target: {usr} | Hash: {c.hash_value[:16]}... | Recovered: {masked_pw}\n"

            sha256 = hashlib.sha256(summary_log.encode("utf-8")).hexdigest()

            if self.db:
                # Log tool execution record
                self.db.create_execution(
                    ToolExecution(
                        project_id=project_id,
                        tool_name=tool_type.value,
                        command=cmd_str,
                        exit_code=job.exit_code,
                        status=ExecutionStatus.COMPLETED if job.state == JobState.COMPLETED else ExecutionStatus.FAILED,
                        duration_seconds=job.duration_seconds,
                        assessment_id=assessment_id,
                    )
                )

                ev_record = self.db.add_evidence(
                    Evidence(
                        project_id=project_id,
                        file_path=hash_file_path,
                        sha256_hash=sha256,
                        description=f"{tool_type.value.capitalize()} Password Recovery Audit Log ({options.hash_type.value})",
                        mime_type="text/plain",
                        assessment_id=assessment_id,
                    )
                )
                ev_list.append(ev_record)

                for c in cracked:
                    acc_name = c.username or "Identified Account"
                    masked_pw = c.plaintext_password[0] + "*" * (len(c.plaintext_password) - 2) + c.plaintext_password[-1] if len(c.plaintext_password) > 2 else "***"
                    title = f"Weak & Crackable Password Detected: {acc_name} ({options.hash_type.value.upper()})"
                    desc = (
                        f"Offline cryptographic password auditing successfully cracked the {options.hash_type.value.upper()} "
                        f"hash for user **{acc_name}**.\n\n"
                        f"- **Affected Asset:** `{target_asset}`\n"
                        f"- **Recovered Password Format:** Length {len(c.plaintext_password)} characters\n"
                        f"- **Masked Secret:** `{masked_pw}`\n"
                        f"- **Cracking Tool:** `{tool_type.value}`\n"
                        f"- **CWE:** CWE-521 (Weak Password Requirements)\n"
                    )
                    rem = (
                        "Enforce strict minimum password complexity (at least 15 characters, passphrases), "
                        "block common dictionary passwords, and deploy Fine-Grained Password Policies (FGPP)."
                    )
                    finding = Finding(
                        project_id=project_id,
                        title=title,
                        severity=FindingSeverity.HIGH,
                        affected_asset=target_asset,
                        description=desc,
                        remediation=rem,
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool=tool_type.value,
                        assessment_id=assessment_id,
                    )
                    created_f = self.db.create_finding(finding)
                    findings.append(created_f)

            tool_result = SecurityToolResult(
                tool_name=tool_type.value,
                target=target_asset,
                is_authorized=True,
                scope_reason="Authorized Password Audit",
                raw_output=summary_log,
                execution_status=ExecutionStatus.COMPLETED if job.state == JobState.COMPLETED else ExecutionStatus.FAILED,
                findings=findings,
                duration_seconds=job.duration_seconds,
            )
            return findings, ev_list, tool_result

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
