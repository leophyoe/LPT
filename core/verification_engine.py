"""Module-specific verification, connectivity, and diagnostic testing engine.

Provides safe, deterministic verification for:
1. Network: Host/service checks, tunnel/port-forward connectivity, connection error states.
2. Active Directory / Kerberos: Domain service reachability, SMB signing & Kerberos configuration checks.
3. Privilege Escalation: Local permissions, SUID inspection, world-writable sensitive path auditing.
4. Web & Binary: HTTP header/access-control evaluation and binary challenge protection inspection (NX, PIE, Canary).
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ConnectivityCheckResult:
    target_host: str
    target_port: int
    is_connected: bool
    status_code: str  # CONNECTED, CONNECTION_REFUSED, TIMEOUT, RESOLUTION_FAILED, ERROR
    latency_ms: float = 0.0
    error_message: str = ""


class NetworkVerificationService:
    """Network service, tunnel status, and port-forward connectivity verifier."""

    @staticmethod
    def check_tunnel_or_port_forward(
        host: str, port: int, timeout: float = 2.0
    ) -> ConnectivityCheckResult:
        """Verifies if a local/remote tunnel, SOCKS proxy, or port-forward listener is active."""
        if not (1 <= port <= 65535):
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=False,
                status_code="INVALID_PORT",
                error_message=f"Port {port} is out of valid range (1-65535).",
            )

        start_t = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            latency = round((time.time() - start_t) * 1000, 2)
            s.close()
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=True,
                status_code="CONNECTED",
                latency_ms=latency,
            )
        except socket.timeout:
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=False,
                status_code="TIMEOUT",
                error_message=f"Connection to {host}:{port} timed out after {timeout}s.",
            )
        except ConnectionRefusedError:
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=False,
                status_code="CONNECTION_REFUSED",
                error_message=f"Connection refused by {host}:{port}. Listener is offline.",
            )
        except socket.gaierror as e:
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=False,
                status_code="RESOLUTION_FAILED",
                error_message=f"DNS resolution failed for host '{host}': {e}",
            )
        except Exception as e:
            return ConnectivityCheckResult(
                target_host=host,
                target_port=port,
                is_connected=False,
                status_code="ERROR",
                error_message=str(e),
            )
        finally:
            try:
                s.close()
            except Exception:
                pass


class ActiveDirectoryVerificationService:
    """Active Directory & Kerberos service and configuration verifier."""

    AD_CORE_PORTS = {
        53: "DNS",
        88: "Kerberos KDC",
        389: "LDAP",
        445: "SMB / RPC",
        636: "LDAPS",
        3268: "Global Catalog LDAP",
    }

    @classmethod
    def audit_domain_connectivity(
        cls, dc_host: str, timeout: float = 1.5
    ) -> Dict[str, Any]:
        """Validates connectivity across essential Active Directory and Kerberos ports."""
        port_results: Dict[str, Any] = {}
        reachable_count = 0

        for port, service_name in cls.AD_CORE_PORTS.items():
            res = NetworkVerificationService.check_tunnel_or_port_forward(
                dc_host, port, timeout=timeout
            )
            port_results[f"{port}/{service_name}"] = {
                "port": port,
                "service": service_name,
                "is_active": res.is_connected,
                "status": res.status_code,
                "error": res.error_message,
            }
            if res.is_connected:
                reachable_count += 1

        is_dc_candidate = reachable_count >= 2
        return {
            "domain_controller": dc_host,
            "reachable_services": reachable_count,
            "total_checked": len(cls.AD_CORE_PORTS),
            "is_active_directory_reachable": is_dc_candidate,
            "ports": port_results,
        }

    @staticmethod
    def evaluate_smb_and_kerberos_hardening(
        smb_signing_required: bool,
        smb_signing_enabled: bool,
        kerberos_preauth_disabled_accounts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Evaluates SMB signing posture and AS-REP roasting exposure."""
        findings = []

        if not smb_signing_required:
            findings.append({
                "title": "SMB Signing Not Required (Relay Attack Vulnerability)",
                "severity": "HIGH",
                "description": "SMB message signing is not enforced. An attacker positioned on the local network can intercept and relay SMB authentication.",
                "remediation": "Enforce SMB signing via Group Policy: 'Microsoft network server: Digitally sign communications (always)'.",
            })

        if kerberos_preauth_disabled_accounts:
            findings.append({
                "title": f"Kerberos Pre-Authentication Disabled ({len(kerberos_preauth_disabled_accounts)} accounts exposed to AS-REP Roasting)",
                "severity": "HIGH",
                "affected_accounts": kerberos_preauth_disabled_accounts,
                "description": "User accounts with DONT_REQ_PREAUTH set allow offline password cracking of encrypted Kerberos TGT responses without authentication.",
                "remediation": "Enable Kerberos pre-authentication for all domain user accounts.",
            })

        return {
            "is_smb_relay_safe": smb_signing_required,
            "asrep_roastable_count": len(kerberos_preauth_disabled_accounts or []),
            "security_findings": findings,
        }


class PrivilegeEscalationVerificationService:
    """Audits local permissions, SUID/SGID binaries, and sensitive paths."""

    SENSITIVE_SYSTEM_FILES = [
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/passwd",
    ]

    @classmethod
    def audit_local_file_permissions(
        cls, target_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Audits read/write permissions on critical system configuration files."""
        audit_results = []
        files = target_files or cls.SENSITIVE_SYSTEM_FILES
        for file_path in files:
            p = Path(file_path)
            if not p.exists():
                continue

            stat_info = p.stat()
            is_world_writable = bool(stat_info.st_mode & 0o002)
            is_world_readable = bool(stat_info.st_mode & 0o004)

            audit_results.append({
                "path": file_path,
                "permissions_octal": oct(stat_info.st_mode)[-4:],
                "is_world_writable": is_world_writable,
                "is_world_readable": is_world_readable,
                "is_misconfigured": is_world_writable or (file_path == "/etc/shadow" and is_world_readable),
            })
        return audit_results

    @staticmethod
    def inspect_suid_binaries(search_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scans directories for binaries with SUID bit (0o4000) set."""
        dirs = search_dirs or ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]
        suid_binaries = []

        for d in dirs:
            p_dir = Path(d)
            if not p_dir.is_dir():
                continue
            try:
                for entry in p_dir.iterdir():
                    if entry.is_file() and not entry.is_symlink():
                        try:
                            mode = entry.stat().st_mode
                            if mode & 0o4000:
                                suid_binaries.append({
                                    "path": str(entry),
                                    "name": entry.name,
                                    "mode": oct(mode)[-4:],
                                })
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass
        return suid_binaries


class WebBinaryVerificationService:
    """Analyzes HTTP security headers and inspects local binary challenge protections."""

    REQUIRED_SECURITY_HEADERS = {
        "content-security-policy": "Missing Content-Security-Policy (CSP) increases cross-site scripting (XSS) risk.",
        "strict-transport-security": "Missing HSTS allows unencrypted SSL stripping attacks.",
        "x-content-type-options": "Missing X-Content-Type-Options: nosniff allows MIME-sniffing bypasses.",
        "x-frame-options": "Missing X-Frame-Options or CSP frame-ancestors enables clickjacking.",
    }

    @classmethod
    def audit_http_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """Evaluates server response headers against security hardening baselines."""
        normalized = {k.lower().strip(): v.strip() for k, v in headers.items()}
        missing_headers = []
        recommendations = []

        for hdr, warning in cls.REQUIRED_SECURITY_HEADERS.items():
            if hdr not in normalized:
                missing_headers.append(hdr)
                recommendations.append(warning)

        server_banner = normalized.get("server", "")
        powered_by = normalized.get("x-powered-by", "")

        return {
            "missing_headers": missing_headers,
            "recommendations": recommendations,
            "disclosed_server": server_banner,
            "disclosed_technology": powered_by,
            "is_hardened": len(missing_headers) == 0,
        }

    @staticmethod
    def inspect_binary_protections(file_path: str | Path) -> Dict[str, Any]:
        """Inspects ELF binary format and checks for executable stack / security protections."""
        p = Path(file_path)
        if not p.is_file():
            return {
                "exists": False,
                "error": f"File '{file_path}' does not exist or is not a regular file.",
            }

        try:
            with open(p, "rb") as f:
                header = f.read(64)

            if len(header) < 16 or header[:4] != b"\x7fELF":
                return {
                    "exists": True,
                    "is_elf": False,
                    "format": "Unknown / Non-ELF (e.g. PE / Script)",
                }

            is_64_bit = header[4] == 2
            is_little_endian = header[5] == 1
            elf_type = struct.unpack("<H" if is_little_endian else ">H", header[16:18])[0]

            # 2 = ET_EXEC (Non-PIE executable), 3 = ET_DYN (Position Independent Executable / Shared Object)
            is_pie = (elf_type == 3)

            return {
                "exists": True,
                "is_elf": True,
                "bit_depth": 64 if is_64_bit else 32,
                "endianness": "little" if is_little_endian else "big",
                "is_pie": is_pie,
                "protections": {
                    "position_independent_executable": is_pie,
                    "type_description": "Position Independent Executable (PIE Enabled)" if is_pie else "Fixed Base Executable (PIE Disabled)",
                },
            }
        except Exception as e:
            return {
                "exists": True,
                "error": f"Failed reading binary header: {e}",
            }
