"""IoT & Embedded Firmware Analysis Engine.

Performs static unpacking, filesystem carving, architecture identification,
and security auditing for IoT firmware images:
1. Binary header inspection (ELF, U-Boot uImage, SquashFS, CramFS, JFFS2, Gzip, LZMA, XZ).
2. Architecture & Endianness detection (MIPS, ARM, AArch64, x86, PowerPC).
3. Binwalk extraction with safe pure-Python signature fallback.
4. Embedded secret & credential auditor (/etc/shadow, private keys, API tokens, telnetd).
5. Binary hardening checks (NX / executable stack detection).
6. Scope Authorization Guard & Evidence Vault integration with SHA-256 integrity hashing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    ValidationStatus,
)


@dataclass
class FirmwareComponent:
    """Represents a discovered filesystem, header, or compressed section in firmware."""

    offset: int
    component_type: str
    description: str
    size: Optional[int] = None
    extracted_path: Optional[str] = None


@dataclass
class FirmwareSecretFinding:
    """Represents a secret, credential, or sensitive configuration found in firmware."""

    category: str  # "SHADOW_HASH", "PRIVATE_KEY", "HARDCODED_CREDS", "INSECURE_DAEMON", "MISSING_NX"
    severity: FindingSeverity
    title: str
    file_path: str
    description: str
    snippet: str
    remediation: str


@dataclass
class FirmwareAnalysisResult:
    """Consolidated outcome of firmware static analysis and extraction."""

    source_image: str
    file_size_bytes: int
    sha256_hash: str
    detected_architecture: str = "Unknown"
    endianness: str = "Unknown"
    components: List[FirmwareComponent] = field(default_factory=list)
    secrets: List[FirmwareSecretFinding] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    extraction_dir: Optional[str] = None
    evidence_id: Optional[int] = None
    is_authorized: bool = True
    scope_reason: str = "Authorized"


class FirmwareAnalyzer:
    """Automated security analyzer for embedded IoT firmware binaries and filesystems."""

    # ELF Machine Architectures
    ELF_MACHINES = {
        3: "x86 (32-bit)",
        8: "MIPS",
        20: "PowerPC",
        40: "ARM (32-bit)",
        62: "x86-64 (AMD64)",
        183: "AArch64 (ARM 64-bit)",
    }

    # Filesystem & Compression Magic Signatures
    SIGNATURES = [
        (b"\x7fELF", "ELF Binary", "Executable and Linkable Format binary"),
        (b"\x27\x05\x19\x56", "U-Boot uImage", "U-Boot legacy firmware image header"),
        (b"hsqs", "SquashFS (LE)", "Squashfs filesystem, little endian"),
        (b"sqsh", "SquashFS (BE)", "Squashfs filesystem, big endian"),
        (b"\x28\xcd\x3d\x45", "CramFS (LE)", "CramFS filesystem, little endian"),
        (b"\x45\x3d\xcd\x28", "CramFS (BE)", "CramFS filesystem, big endian"),
        (b"\x19\x85", "JFFS2", "JFFS2 filesystem node"),
        (b"\x1f\x8b\x08", "Gzip", "Gzip compressed data"),
        (b"]\x00\x00", "LZMA", "LZMA compressed stream"),
        (b"\xfd7zXZ\x00", "XZ", "XZ compressed data"),
    ]

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def analyze_image(
        self,
        image_path: Path,
        project_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
        extraction_dir: Optional[Path] = None,
        extract_files: bool = True,
        max_extract_mb: int = 250,
    ) -> FirmwareAnalysisResult:
        """Inspects, scans signatures, extracts, and performs deep secret auditing on a firmware image."""
        image_path = Path(image_path)
        if not image_path.exists() or not image_path.is_file():
            raise FileNotFoundError(f"Firmware image not found: {image_path}")

        file_size = image_path.stat().st_size
        raw_head = image_path.read_bytes()[: min(file_size, 10 * 1024 * 1024)]  # Up to 10MB for headers
        sha256 = hashlib.sha256(image_path.read_bytes()).hexdigest()

        # 1. Scan Signatures & Identify Components
        components = self._scan_signatures(raw_head)

        # 2. Architecture & Endianness Detection
        arch, endian = self._detect_architecture(raw_head)

        # 3. Extraction via binwalk or fallback directory creation
        out_dir = None
        if extract_files:
            target_out = extraction_dir or (image_path.parent / f"extracted_{image_path.stem}")
            out_dir = self._extract_firmware(image_path, target_out, max_extract_mb)

        # 4. Deep Secret & Vulnerability Scan across Extracted Filesystem
        secrets: List[FirmwareSecretFinding] = []
        scan_target = Path(out_dir) if (out_dir and Path(out_dir).exists()) else None
        if scan_target:
            secrets = self._audit_filesystem(scan_target)
        else:
            # Fallback scan across binary raw content strings
            secrets = self._audit_raw_binary(raw_head, image_path.name)

        # 5. Build Normalized Findings
        findings: List[Finding] = []
        if project_id:
            findings = self._generate_findings(
                project_id=project_id,
                image_name=image_path.name,
                arch=arch,
                secrets=secrets,
                components=components,
                assessment_id=assessment_id,
            )

        # 6. Scope Authorization Guard
        is_authorized = True
        scope_reason = "Firmware asset within authorized scope"
        authorized_findings: List[Finding] = []

        if project_id and self.db:
            scopes = self.db.list_scopes(project_id)
            project = self.db.get_project(project_id)
            if scopes:
                in_scope = any(
                    s.target.strip().lower() in (image_path.name.lower(), image_path.stem.lower())
                    for s in scopes
                )
                if not in_scope:
                    chk = ScopeAuthorizationService.is_target_authorized(
                        image_path.name, scopes, project=project
                    )
                    in_scope = chk.is_allowed

                if in_scope:
                    authorized_findings = findings
                else:
                    is_authorized = False
                    scope_reason = f"Firmware image '{image_path.name}' outside authorized project scope"

        # 7. Evidence Vault Registration
        evidence_entry = None
        if project_id and self.db:
            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    file_path=str(image_path),
                    sha256_hash=sha256,
                    description=f"Firmware binary: {image_path.name} ({arch}, {len(components)} sections, {len(secrets)} secrets)",
                    mime_type="application/octet-stream",
                    assessment_id=assessment_id,
                )
            )

            for f in authorized_findings:
                self.db.upsert_finding_deduplicated(f)

            ActivityLogger(self.db).log(
                project_id=project_id,
                action="firmware_image_analyzed",
                outcome="completed",
                details={
                    "image": image_path.name,
                    "arch": arch,
                    "endianness": endian,
                    "components_count": len(components),
                    "secrets_count": len(secrets),
                    "sha256": sha256,
                },
            )

        return FirmwareAnalysisResult(
            source_image=str(image_path),
            file_size_bytes=file_size,
            sha256_hash=sha256,
            detected_architecture=arch,
            endianness=endian,
            components=components,
            secrets=secrets,
            findings=authorized_findings if (project_id and self.db) else findings,
            extraction_dir=str(out_dir) if out_dir else None,
            evidence_id=evidence_entry.id if evidence_entry else None,
            is_authorized=is_authorized,
            scope_reason=scope_reason,
        )

    def _scan_signatures(self, raw_bytes: bytes) -> List[FirmwareComponent]:
        """Scans raw binary bytes for filesystem and compression signatures."""
        components: List[FirmwareComponent] = []
        seen_offsets: Set[int] = set()

        for magic, comp_type, desc in self.SIGNATURES:
            start = 0
            while True:
                idx = raw_bytes.find(magic, start)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    components.append(
                        FirmwareComponent(
                            offset=idx,
                            component_type=comp_type,
                            description=desc,
                        )
                    )
                start = idx + 1
                if len(components) >= 100:  # Cap at top 100 components
                    break

        components.sort(key=lambda c: c.offset)
        return components

    def _detect_architecture(self, raw_bytes: bytes) -> Tuple[str, str]:
        """Inspects ELF headers to determine target CPU architecture and endianness."""
        idx = raw_bytes.find(b"\x7fELF")
        if idx != -1 and len(raw_bytes) >= idx + 20:
            elf_hdr = raw_bytes[idx : idx + 20]
            endian_val = elf_hdr[5]
            endian = "Little Endian" if endian_val == 1 else "Big Endian"
            endian_char = "<" if endian_val == 1 else ">"

            machine_code = struct.unpack(f"{endian_char}H", elf_hdr[18:20])[0]
            arch = self.ELF_MACHINES.get(machine_code, f"ELF Machine ({machine_code})")
            return arch, endian

        # Check U-Boot uImage Header (offset 28..30 indicates arch/os)
        uboot_idx = raw_bytes.find(b"\x27\x05\x19\x56")
        if uboot_idx != -1 and len(raw_bytes) >= uboot_idx + 32:
            arch_byte = raw_bytes[uboot_idx + 29]
            uboot_archs = {
                1: "ARM",
                2: "x86",
                5: "MIPS",
                6: "MIPS64",
                7: "PowerPC",
                14: "AArch64",
            }
            arch = uboot_archs.get(arch_byte, f"U-Boot Arch ({arch_byte})")
            return arch, "Big Endian (uImage)"

        return "Unknown Architecture", "Unknown"

    def _extract_firmware(
        self, image_path: Path, out_dir: Path, max_extract_mb: int
    ) -> Optional[Path]:
        """Extracts firmware using binwalk if available, with safety timeout and sandbox bounds."""
        binwalk_bin = shutil.which("binwalk")
        if not binwalk_bin:
            return None

        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Run binwalk non-destructively: -e (extract), -C (directory), -q (quiet)
            # Add --run-as=root flag only if running as UID 0
            cmd = [binwalk_bin, "-e", "-q", "-C", str(out_dir)]
            if os.geteuid() == 0:
                cmd.append("--run-as=root")
            cmd.append(str(image_path))

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            return out_dir
        except Exception:
            return None

    def _audit_filesystem(self, root_dir: Path) -> List[FirmwareSecretFinding]:
        """Recursively audits an extracted firmware root directory for secrets and misconfigurations."""
        secrets: List[FirmwareSecretFinding] = []
        files_scanned = 0

        # Pattern definitions
        re_priv_key = re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.MULTILINE
        )
        re_cred = re.compile(
            r"""(?i)(?:password|passwd|secret_key|api_key|auth_token)\s*[:=]\s*["']([^"'\r\n]{4,})["']"""
        )
        re_aws = re.compile(r"AKIA[0-9A-Z]{16}")

        for p in root_dir.rglob("*"):
            if not p.is_file():
                continue

            files_scanned += 1
            if files_scanned > 2000:  # Guard against massive unpacked archives
                break

            rel_path = str(p.relative_to(root_dir))

            # 1. Shadow & Password Auditing
            if p.name in ("shadow", "shadow-", "passwd", "passwd-"):
                self._audit_shadow_file(p, rel_path, secrets)
                continue

            # 2. Private Key Detection by extension or content
            if p.suffix in (".pem", ".key", ".crt") or "id_rsa" in p.name:
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    if re_priv_key.search(content):
                        secrets.append(
                            FirmwareSecretFinding(
                                category="PRIVATE_KEY",
                                severity=FindingSeverity.CRITICAL,
                                title=f"Embedded Private Cryptographic Key in '{rel_path}'",
                                file_path=rel_path,
                                description=(
                                    f"Discovered an unencrypted private key file at {rel_path}. "
                                    "Attackers can leverage this key for SSH authentication or TLS spoofing."
                                ),
                                snippet=content[:200] + "...",
                                remediation="Remove all static private keys from firmware. Generate keys dynamically on first boot.",
                            )
                        )
                except Exception:
                    pass

            # 3. Text Files Secret Scanner (.conf, .ini, .sh, .json, .xml, .py, .php)
            if p.suffix in (
                ".conf",
                ".ini",
                ".sh",
                ".json",
                ".xml",
                ".cfg",
                ".txt",
                ".py",
                ".php",
            ):
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    # Check AWS keys
                    aws_match = re_aws.search(content)
                    if aws_match:
                        secrets.append(
                            FirmwareSecretFinding(
                                category="HARDCODED_CREDS",
                                severity=FindingSeverity.HIGH,
                                title=f"Embedded Cloud Access Key in '{rel_path}'",
                                file_path=rel_path,
                                description=f"Found hardcoded AWS Access Key ID '{aws_match.group(0)}' in {rel_path}.",
                                snippet=aws_match.group(0),
                                remediation="Revoke cloud credentials immediately and use IAM roles or external KMS.",
                            )
                        )

                    # Check hardcoded passwords
                    for cred_match in re_cred.finditer(content):
                        val = cred_match.group(1)
                        if val.lower() not in ("null", "none", "false", "true", "password", "default"):
                            secrets.append(
                                FirmwareSecretFinding(
                                    category="HARDCODED_CREDS",
                                    severity=FindingSeverity.HIGH,
                                    title=f"Hardcoded Credential in '{rel_path}'",
                                    file_path=rel_path,
                                    description=f"Discovered embedded credential assignment in {rel_path}.",
                                    snippet=cred_match.group(0),
                                    remediation="Replace static credentials with environment variables or secure credential storage.",
                                )
                            )
                            break  # Avoid spamming multiple matches in same file
                except Exception:
                    pass

            # 4. Insecure Network Daemons in Startup Scripts
            if "init.d" in rel_path or "rc.local" in rel_path:
                try:
                    script = p.read_text(encoding="utf-8", errors="ignore")
                    if "telnetd" in script:
                        secrets.append(
                            FirmwareSecretFinding(
                                category="INSECURE_DAEMON",
                                severity=FindingSeverity.HIGH,
                                title=f"Insecure Plaintext Telnet Daemon Enabled in '{rel_path}'",
                                file_path=rel_path,
                                description=f"Startup script {rel_path} invokes 'telnetd', exposing unencrypted remote root access.",
                                snippet="telnetd execution detected in startup configuration",
                                remediation="Disable telnetd and enforce SSH (Dropbear/OpenSSH) with key authentication.",
                            )
                        )
                except Exception:
                    pass

            # 5. ELF Binary NX (Executable Stack) Check
            if p.suffix in ("", ".so") and p.stat().st_size > 1024:
                try:
                    header = p.read_bytes()[:1024]
                    if header.startswith(b"\x7fELF"):
                        if self._check_elf_executable_stack(header):
                            secrets.append(
                                FirmwareSecretFinding(
                                    category="MISSING_NX",
                                    severity=FindingSeverity.MEDIUM,
                                    title=f"Missing NX Protection (Executable Stack) in '{rel_path}'",
                                    file_path=rel_path,
                                    description=(
                                        f"ELF binary '{rel_path}' has GNU_STACK marked with Read+Write+Execute (RWX) permissions. "
                                        "This allows trivial stack-based buffer overflow exploitation without ROP."
                                    ),
                                    snippet="PT_GNU_STACK permissions: RWX (Executable)",
                                    remediation="Recompile binaries with GCC flag '-z noexecstack'.",
                                )
                            )
                except Exception:
                    pass

        return secrets

    def _audit_shadow_file(
        self, p: Path, rel_path: str, secrets: List[FirmwareSecretFinding]
    ):
        """Audits /etc/shadow or /etc/passwd entries for crackable hashes or default passwords."""
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in lines:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    user, pwd_hash = parts[0], parts[1]
                    if not pwd_hash:
                        secrets.append(
                            FirmwareSecretFinding(
                                category="SHADOW_HASH",
                                severity=FindingSeverity.CRITICAL,
                                title=f"Empty Password for Account '{user}' in '{rel_path}'",
                                file_path=rel_path,
                                description=f"Account '{user}' has an empty password field in {rel_path}.",
                                snippet=f"{user}::...",
                                remediation=f"Lock account '{user}' or assign a strong randomized password.",
                            )
                        )
                    elif pwd_hash not in ("*", "!", "x"):
                        # Hash algorithm identification
                        algo = "DES (Legacy)"
                        if pwd_hash.startswith("$1$"):
                            algo = "MD5-Crypt (Weak)"
                        elif pwd_hash.startswith("$5$"):
                            algo = "SHA-256"
                        elif pwd_hash.startswith("$6$"):
                            algo = "SHA-512"
                        elif pwd_hash.startswith("$y$"):
                            algo = "Yescrypt"

                        secrets.append(
                            FirmwareSecretFinding(
                                category="SHADOW_HASH",
                                severity=FindingSeverity.HIGH,
                                title=f"Embedded Password Hash ({algo}) for '{user}' in '{rel_path}'",
                                file_path=rel_path,
                                description=(
                                    f"Discovered an offline crackable password hash for '{user}' in {rel_path}.\n"
                                    f"Hash Algorithm: {algo}"
                                ),
                                snippet=f"{user}:{pwd_hash[:25]}...",
                                remediation="Do not ship hardcoded password hashes in firmware. Prompt user to set root password on first boot.",
                            )
                        )
        except Exception:
            pass

    def _check_elf_executable_stack(self, header: bytes) -> bool:
        """Inspects ELF Program Headers for PT_GNU_STACK flag (p_flags & 0x1 indicates Executable)."""
        if len(header) < 52:
            return False

        is_64 = header[4] == 2
        endian = "<" if header[5] == 1 else ">"

        try:
            if is_64:
                phoff, phentsize, phnum = struct.unpack(f"{endian}QHH", header[32:44])
            else:
                phoff, phentsize, phnum = struct.unpack(f"{endian}IHH", header[28:36])

            PT_GNU_STACK = 0x6474E551
            PF_X = 0x1

            for i in range(phnum):
                offset = phoff + (i * phentsize)
                if offset + phentsize > len(header):
                    break
                p_type = struct.unpack(f"{endian}I", header[offset : offset + 4])[0]
                if p_type == PT_GNU_STACK:
                    flags_offset = offset + (4 if is_64 else 24)
                    flags = struct.unpack(
                        f"{endian}I", header[flags_offset : flags_offset + 4]
                    )[0]
                    return bool(flags & PF_X)
        except Exception:
            pass
        return False

    def _audit_raw_binary(
        self, raw_bytes: bytes, image_name: str
    ) -> List[FirmwareSecretFinding]:
        """Performs raw string regex extraction when firmware unpacking is unavailable."""
        secrets: List[FirmwareSecretFinding] = []
        try:
            text = raw_bytes.decode("latin1")
            if "BEGIN RSA PRIVATE KEY" in text:
                secrets.append(
                    FirmwareSecretFinding(
                        category="PRIVATE_KEY",
                        severity=FindingSeverity.CRITICAL,
                        title=f"Embedded Private RSA Key in Firmware '{image_name}'",
                        file_path=image_name,
                        description="Raw binary contains an unencrypted RSA private key header.",
                        snippet="-----BEGIN RSA PRIVATE KEY-----",
                        remediation="Remove embedded private keys before manufacturing.",
                    )
                )

            if "root:$1$" in text or "root:$6$" in text:
                secrets.append(
                    FirmwareSecretFinding(
                        category="SHADOW_HASH",
                        severity=FindingSeverity.HIGH,
                        title=f"Embedded Root Password Hash in Firmware '{image_name}'",
                        file_path=image_name,
                        description="Raw binary contains an embedded /etc/shadow password hash for root.",
                        snippet="root:$...",
                        remediation="Prompt users for root password upon initial provisioning.",
                    )
                )
        except Exception:
            pass
        return secrets

    def _generate_findings(
        self,
        project_id: int,
        image_name: str,
        arch: str,
        secrets: List[FirmwareSecretFinding],
        components: List[FirmwareComponent],
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Converts firmware secrets and security flaws into normalized Finding records."""
        findings: List[Finding] = []

        for sec in secrets:
            cvss_score = 8.5 if sec.severity == FindingSeverity.CRITICAL else (7.0 if sec.severity == FindingSeverity.HIGH else 5.0)
            findings.append(
                Finding(
                    project_id=project_id,
                    title=sec.title,
                    severity=sec.severity,
                    cvss_score=cvss_score,
                    affected_asset=image_name,
                    affected_port_service=f"firmware/{arch}",
                    description=sec.description,
                    reproduction_steps=(
                        f"Firmware Image: {image_name}\n"
                        f"File Location: {sec.file_path}\n"
                        f"Evidence Snippet:\n{sec.snippet}"
                    ),
                    remediation=sec.remediation,
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="firmware_analyzer",
                    assessment_id=assessment_id,
                )
            )

        return findings
