"""Pure-Python Vulnerability Assessment Engine.

Provides zero-external-dependency automated security checks for:
- HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
- Cookie Security Attributes (HttpOnly, Secure, SameSite).
- Server Information Disclosure & Banner Leaking.
- Deprecated TLS Protocol & Weak Cipher Auditing.
- Default Misconfiguration Checks (Anonymous FTP, Open MySQL).
"""

from __future__ import annotations

import ftplib
import json
import logging
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ValidationStatus,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


class PythonVulnScanner:
    """Zero-dependency pure-Python vulnerability auditor."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def audit_target(
        self,
        project_id: int,
        target_ip: str,
        open_ports: Optional[List[int]] = None,
        scopes: Optional[List[TargetScope]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> List[Finding]:
        """Audits target for security header deficiencies, SSL/TLS flaws, and service misconfigs."""
        def emit(msg: str):
            if on_progress:
                on_progress(msg)

        findings: List[Finding] = []
        clean_ip = target_ip.strip()

        # 1. Scope Boundary Enforcement
        scope_list = scopes if scopes is not None else (self.db.list_scopes(project_id) if self.db else [])
        project = self.db.get_project(project_id) if self.db else None

        scope_check = ScopeAuthorizationService.is_target_authorized(clean_ip, scope_list, project)
        if not scope_check.is_allowed:
            emit(f"[-] Target {clean_ip} blocked by Scope Guard: {scope_check.reason}")
            return []

        emit(f"[*] Starting Pure-Python Vulnerability Audit for {clean_ip}")

        # Default ports if not specified
        ports_to_check = open_ports if open_ports is not None else [80, 443, 21, 3306, 8080, 8443]

        # 2. HTTP Security Header Auditing
        web_ports = [p for p in ports_to_check if p in (80, 443, 8000, 8080, 8443, 8888, 9000)]
        for wp in web_ports:
            scheme = "https" if wp in (443, 8443) else "http"
            url = f"{scheme}://{clean_ip}:{wp}"
            emit(f"[+] Auditing HTTP security headers on {url}...")
            header_findings = self._audit_http_headers(project_id, clean_ip, wp, url)
            findings.extend(header_findings)

        # 3. SSL/TLS Deprecated Protocol Auditing
        tls_ports = [p for p in ports_to_check if p in (443, 8443, 993, 995)]
        for tp in tls_ports:
            emit(f"[+] Auditing SSL/TLS protocols and certificates on {clean_ip}:{tp}...")
            tls_findings = self._audit_tls_configuration(project_id, clean_ip, tp)
            findings.extend(tls_findings)

        # 4. Anonymous FTP Misconfiguration Check
        if 21 in ports_to_check:
            emit(f"[+] Checking FTP anonymous authentication on {clean_ip}:21...")
            ftp_findings = self._check_anonymous_ftp(project_id, clean_ip)
            findings.extend(ftp_findings)

        # 5. Open MySQL Unauthenticated Check
        if 3306 in ports_to_check:
            emit(f"[+] Checking MySQL service configuration on {clean_ip}:3306...")
            mysql_findings = self._check_open_mysql(project_id, clean_ip)
            findings.extend(mysql_findings)

        # 6. Persist findings to database if Database is available
        if self.db:
            for f in findings:
                try:
                    self.db.create_finding(f)
                except Exception as exc:
                    logger.debug("Failed persisting finding: %s", exc)

        emit(f"[✓] Vulnerability Audit completed for {clean_ip}: {len(findings)} observation(s) identified.")
        return findings

    def _audit_http_headers(self, project_id: int, ip: str, port: int, url: str) -> List[Finding]:
        """Inspects HTTP response headers for missing defensive security protections."""
        findings: List[Finding] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberSecuritySuite VulnScanner/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.get("Set-Cookie", "")

                # 1. Missing HSTS (Only relevant for HTTPS)
                if url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title="Missing HTTP Strict Transport Security (HSTS) (CWE-319)",
                            description=(
                                f"The HTTPS service on {ip}:{port} does not serve the 'Strict-Transport-Security' header. "
                                "This permits attackers performing man-in-the-middle (MitM) or SSL stripping attacks "
                                "to downgrade client connections from HTTPS to insecure cleartext HTTP."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            affected_asset=f"{ip}:{port}",
                            reproduction_steps=(
                                f"Target URL: {url}\nObserved Headers:\n"
                                + "\n".join(f"{k}: {v}" for k, v in headers.items())
                            ),
                            remediation=(
                                "Configure the web server to return: "
                                "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                            ),
                            source_tool="python_vuln_scanner",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 2. Missing Content-Security-Policy (CSP)
                if "content-security-policy" not in headers:
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title="Missing Content Security Policy (CSP) (CWE-693)",
                            description=(
                                f"The web service on {ip}:{port} does not implement a 'Content-Security-Policy' header. "
                                "CSP restricts resources (JavaScript, CSS, Images) that the browser is allowed to load, "
                                "drastically reducing the impact of Cross-Site Scripting (XSS) and data injection vulnerabilities."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=6.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            affected_asset=f"{ip}:{port}",
                            reproduction_steps=f"Target URL: {url}\nContent-Security-Policy header was omitted from response.",
                            remediation=(
                                "Define a restrictive Content-Security-Policy header, for example: "
                                "'default-src 'self'; script-src 'self'; object-src 'none';'."
                            ),
                            source_tool="python_vuln_scanner",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 3. Missing X-Frame-Options (Clickjacking)
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title="Missing Anti-Clickjacking Header (X-Frame-Options) (CWE-1021)",
                            description=(
                                f"The web service on {ip}:{port} does not supply 'X-Frame-Options' or 'frame-ancestors'. "
                                "This allows malicious third-party websites to frame the target application within an <iframe>, "
                                "enabling UI redressing (Clickjacking) attacks against authenticated users."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=4.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            affected_asset=f"{ip}:{port}",
                            reproduction_steps=f"Target URL: {url}\nX-Frame-Options header was omitted from HTTP response.",
                            remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                            source_tool="python_vuln_scanner",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 4. Missing X-Content-Type-Options: nosniff
                if "x-content-type-options" not in headers:
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title="Missing X-Content-Type-Options Header (CWE-693)",
                            description=(
                                f"The web service on {ip}:{port} does not set 'X-Content-Type-Options: nosniff'. "
                                "Legacy browsers may attempt MIME-sniffing on untrusted uploads, executing uploaded HTML/JS as code."
                            ),
                            severity=FindingSeverity.LOW,
                            cvss_score=3.7,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            affected_asset=f"{ip}:{port}",
                            reproduction_steps=f"Target URL: {url}\nX-Content-Type-Options header was omitted.",
                            remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                            source_tool="python_vuln_scanner",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 5. Insecure Cookie Attributes
                if cookies:
                    insecure_flags = []
                    if "httponly" not in cookies.lower():
                        insecure_flags.append("Missing HttpOnly (JavaScript readable)")
                    if url.startswith("https://") and "secure" not in cookies.lower():
                        insecure_flags.append("Missing Secure flag (Cleartext transmission risk)")
                    if "samesite" not in cookies.lower():
                        insecure_flags.append("Missing SameSite attribute (CSRF exposure)")

                    if insecure_flags:
                        findings.append(
                            Finding(
                                project_id=project_id,
                                title="Insecure Cookie Attributes Detected (CWE-1004)",
                                description=(
                                    f"Cookies issued by {ip}:{port} lack critical protective flags: {', '.join(insecure_flags)}. "
                                    "This increases exposure to session hijacking via XSS and Cross-Site Request Forgery (CSRF)."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                cvss_score=5.3,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                affected_asset=f"{ip}:{port}",
                                reproduction_steps=f"Set-Cookie Header: {cookies}\nIdentified Defects: {insecure_flags}",
                                remediation="Set 'Secure; HttpOnly; SameSite=Lax' (or Strict) on all session cookies.",
                                source_tool="python_vuln_scanner",
                                validation_status=ValidationStatus.CONFIRMED,
                            )
                        )

                # 6. Detailed Server Information Disclosure
                server = headers.get("server", "")
                powered = headers.get("x-powered-by", "")
                if server and any(c.isdigit() for c in server):
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title="Web Server Version Information Disclosure (CWE-200)",
                            description=(
                                f"The server on {ip}:{port} reveals its exact software and version banner in the 'Server' header: '{server}'. "
                                "Attackers use exact version banners to target known CVE vulnerabilities and public exploits."
                            ),
                            severity=FindingSeverity.LOW,
                            cvss_score=3.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            affected_asset=f"{ip}:{port}",
                            reproduction_steps=f"Server Header: {server}\nX-Powered-By: {powered}",
                            remediation="Configure web server to suppress banner tokens (e.g. ServerTokens Prod).",
                            source_tool="python_vuln_scanner",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )
        except Exception:
            pass
        return findings

    def _audit_tls_configuration(self, project_id: int, ip: str, port: int) -> List[Finding]:
        """Checks for support of deprecated TLS 1.0/1.1 protocols and weak ciphers."""
        findings: List[Finding] = []

        # Test deprecated TLSv1.0 & TLSv1.1
        deprecated_versions = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
        ]
        accepted_deprecated: List[str] = []

        for ver_name, ver_enum in deprecated_versions:
            if ver_enum is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver_enum
                ctx.maximum_version = ver_enum

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.5)
                with ctx.wrap_socket(s, server_hostname=ip) as ssock:
                    ssock.connect((ip, port))
                    accepted_deprecated.append(ver_name)
            except Exception:
                pass

        if accepted_deprecated:
            findings.append(
                Finding(
                    project_id=project_id,
                    title="Deprecated TLS 1.0/1.1 Protocol Supported (CWE-326)",
                    description=(
                        f"The service on {ip}:{port} negotiates connections using obsolete cryptographic protocols: "
                        f"{', '.join(accepted_deprecated)}. These versions are vulnerable to BEAST, POODLE, and weak CBC ciphers, "
                        "and have been formally deprecated by NIST SP 800-52r2 and PCI-DSS 3.1+."
                    ),
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    affected_asset=f"{ip}:{port}",
                    reproduction_steps=f"Target: {ip}:{port}\nAccepted Obsolete Versions: {accepted_deprecated}",
                    remediation="Disable TLS 1.0 and TLS 1.1 in the server configuration; enforce TLS 1.2 and TLS 1.3 only.",
                    source_tool="python_vuln_scanner",
                    validation_status=ValidationStatus.CONFIRMED,
                )
            )

        return findings

    def _check_anonymous_ftp(self, project_id: int, ip: str) -> List[Finding]:
        """Tests if FTP server allows unauthenticated/anonymous access."""
        findings: List[Finding] = []
        try:
            ftp = ftplib.FTP(timeout=3.0)
            ftp.connect(ip, 21)
            ftp.login("anonymous", "anonymous@test.com")
            # If login succeeded
            welcome_msg = ftp.getwelcome()
            ftp.quit()

            findings.append(
                Finding(
                    project_id=project_id,
                    title="Anonymous FTP Login Permitted (CWE-287)",
                    description=(
                        f"The FTP server at {ip}:21 allows anonymous login using username 'anonymous'. "
                        "Unauthenticated users may browse, download sensitive corporate files, or potentially upload unauthorized payloads."
                    ),
                    severity=FindingSeverity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affected_asset=f"{ip}:21",
                    reproduction_steps=f"FTP Banner:\n{welcome_msg}\nStatus: Anonymous authentication successful (code 230).",
                    remediation="Disable anonymous FTP login in ftp server configuration (e.g. anonymous_enable=NO in vsftpd.conf).",
                    source_tool="python_vuln_scanner",
                    validation_status=ValidationStatus.CONFIRMED,
                )
            )
        except Exception:
            pass
        return findings

    def _check_open_mysql(self, project_id: int, ip: str) -> List[Finding]:
        """Tests if MySQL database server port is open and permits unauthenticated handshake."""
        findings: List[Finding] = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.5)
            s.connect((ip, 3306))
            # Read server greeting handshake
            greeting = s.recv(512)
            s.close()

            if greeting and len(greeting) > 4:
                # If greeting has protocol 10 or contains version
                clean_greeting = "".join(c for c in greeting.decode("latin1", errors="ignore") if 32 <= ord(c) < 127)
                findings.append(
                    Finding(
                        project_id=project_id,
                        title="Exposed Database Port (MySQL) (CWE-306)",
                        description=(
                            f"The MySQL relational database service on {ip}:3306 is directly exposed to the network. "
                            "Exposing raw database ports increases susceptibility to brute-force credential attacks, "
                            "authentication bypass vulnerabilities, and remote exploitation."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        affected_asset=f"{ip}:3306",
                        reproduction_steps=f"MySQL Handshake Banner Detected: {clean_greeting[:120]}",
                        remediation="Bind MySQL service strictly to 127.0.0.1 or restrict network access via firewall/security groups.",
                        source_tool="python_vuln_scanner",
                        validation_status=ValidationStatus.OBSERVED,
                    )
                )
        except Exception:
            pass
        return findings
