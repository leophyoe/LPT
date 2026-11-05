"""Web and API security assessment adapter.

Integrates c0desec reconnaissance, security header inspection, CORS analysis,
endpoint discovery, and JavaScript secret scanning within project scope.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult

# Integrate c0desec constants if available
C0DESEC_PATH = Path(__file__).resolve().parent.parent.parent / "source" / "web" / "c0desec-pentest"
if str(C0DESEC_PATH) not in sys.path and C0DESEC_PATH.is_dir():
    sys.path.insert(0, str(C0DESEC_PATH))

try:
    from c0desec.constants import SECRET_PATTERNS
except ImportError:
    # Standalone fallback patterns if c0desec source is isolated
    SECRET_PATTERNS = {
        "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret_key": re.compile(r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I),
        "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        "stripe_live_key": re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
        "private_key_header": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\sKEY-----"),
    }


@dataclass
class WebScanOptions:
    target_url: str
    check_headers: bool = True
    check_cors: bool = True
    check_js_secrets: bool = True
    discover_endpoints: bool = True
    check_dns: bool = True
    timeout: float = 10.0
    max_response_size: int = 5 * 1024 * 1024  # 5 MB max response limit
    rate_limit_delay: float = 0.05  # Seconds between requests


@dataclass
class DiscoveredSecret:
    secret_type: str
    redacted_preview: str
    raw_sha256: str
    source_url: str
    context_snippet: str


@dataclass
class WebScanResult:
    target_url: str
    ip_addresses: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    endpoints: List[str] = field(default_factory=list)
    secrets: List[DiscoveredSecret] = field(default_factory=list)
    cors_vulnerable: bool = False
    cors_details: str = ""
    findings: List[Finding] = field(default_factory=list)


def redact_secret_value(value: str) -> str:
    """Mask secret value preserving only first 4 chars for safe preview."""
    clean = value.strip()
    if len(clean) <= 6:
        return "[REDACTED]"
    return f"{clean[:4]}...[REDACTED_LEN_{len(clean)}]"


class WebSecurityAdapter(BaseSecurityAdapter):
    """Orchestrates passive web assessment, secret detection, and scope enforcement."""

    @property
    def tool_name(self) -> str:
        return "c0desec"

    @property
    def display_name(self) -> str:
        return "c0desec Web & Secret Scanner"

    def __init__(self, db: Database):
        super().__init__(db)
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def execute_scan(
        self,
        project_id: int,
        options: WebScanOptions,
        scopes: List[TargetScope],
        on_output: Optional[Callable[[str, str], None]] = None,
        evidence_dir: Optional[Path] = None,
        session: Optional[requests.Session] = None,
        project: Optional[Project] = None,
        assessment_id: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[WebScanResult], Optional[ToolExecution]]:
        """Run authorized web assessment within scope, stream logs, and save findings."""
        target = options.target_url.strip()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        if self._is_cancelled:
            execution = ToolExecution(
                project_id=project_id,
                tool_name="c0desec",
                command=f"c0desec-web-assessment {target}",
                status=ExecutionStatus.CANCELLED,
                assessment_id=assessment_id,
            )
            execution = self.db.create_execution(execution)
            if on_output:
                on_output("[-] Assessment cancelled by user.\n", "stderr")
            return True, "Assessment cancelled by user", None, execution

        self._is_cancelled = False

        # 1. Enforce Scope Authorization with Project Lifecycle
        if project is None and self.db and project_id:
            project = self.db.get_project(project_id)
        parsed_target = urlparse(target)
        host = parsed_target.hostname or target
        scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
            host, scopes, project=project
        )
        if not scope_check.is_allowed:
            if on_output:
                on_output(f"[-] Execution blocked: {scope_check.reason}\n", "stderr")
            return False, scope_check.reason, None, None

        # 2. Record tool execution in database
        cmd_str = f"c0desec-web-assessment {target}"
        execution = ToolExecution(
            project_id=project_id,
            tool_name="c0desec",
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
            assessment_id=assessment_id,
        )
        execution = self.db.create_execution(execution)

        def emit(msg: str, stream: str = "stdout"):
            if on_output:
                on_output(msg, stream)

        emit(f"[*] Starting authorized web security assessment against: {target}\n", "system")
        emit(f"[*] Scope validation: OK ({scope_check.reason})\n", "stdout")

        scan_result = WebScanResult(target_url=target)
        http = session or requests.Session()
        http.headers.update({"User-Agent": "CyberSecuritySuite-WebRecon/1.0"})

        # 3. DNS and Host Intelligence
        if options.check_dns and not self._is_cancelled:
            emit("[*] Gathering host network intelligence...\n", "stdout")
            try:
                ip = socket.gethostbyname(host)
                scan_result.ip_addresses.append(ip)
                emit(f"    [+] Resolved IP: {ip}\n", "stdout")
            except socket.gaierror as e:
                emit(f"    [-] DNS Resolution failed: {e}\n", "stderr")

        # 4. Fetch Base Web Response with Hop-by-Hop Redirect Scope Guard
        response = None
        raw_body = ""
        current_url = target
        max_redirect_hops = 5
        try:
            emit(f"[*] Sending probe to {target} (timeout: {options.timeout}s)...\n", "stdout")
            for hop in range(max_redirect_hops + 1):
                response = http.get(current_url, timeout=options.timeout, allow_redirects=False)
                if response.is_redirect and "Location" in response.headers:
                    loc = response.headers.get("Location", "").strip()
                    next_url = urljoin(current_url, loc)
                    emit(f"    [*] Detected HTTP {response.status_code} redirect to '{loc}'\n", "stdout")
                    red_check = ScopeAuthorizationService.validate_web_redirect(
                        initial_url=current_url,
                        redirect_location=loc,
                        scopes=scopes,
                        project=project,
                    )
                    if not red_check.is_allowed:
                        emit(f"    [!] REDIRECT BLOCKED: Location '{loc}' outside authorized scope: {red_check.reason}\n", "stderr")
                        execution.status = ExecutionStatus.FAILED
                        self.db.update_execution(execution)
                        return False, f"Redirect to '{loc}' is out of authorized scope: {red_check.reason}", scan_result, execution
                    current_url = next_url
                else:
                    break

            scan_result.headers = dict(response.headers)
            raw_text = response.text or ""
            if len(raw_text) > options.max_response_size:
                emit(f"    [!] Response body ({len(raw_text)} bytes) exceeded max size limit; truncating to {options.max_response_size} bytes\n", "stderr")
                raw_body = raw_text[:options.max_response_size]
            else:
                raw_body = raw_text
            emit(f"    [+] HTTP Status: {response.status_code} ({len(raw_body)} bytes received)\n", "stdout")
        except requests.exceptions.Timeout as e:
            emit(f"[-] Connection to {target} timed out after {options.timeout}s: {e}\n", "stderr")
            execution.status = ExecutionStatus.TIMEOUT
            self.db.update_execution(execution)
            return True, f"Timeout after {options.timeout}s", scan_result, execution
        except Exception as e:
            emit(f"[-] Web request to {target} failed: {e}\n", "stderr")
            execution.status = ExecutionStatus.FAILED
            self.db.update_execution(execution)
            return True, str(e), scan_result, execution

        # 5. Security Headers Analysis
        if options.check_headers and not self._is_cancelled:
            emit("[*] Analyzing HTTP security headers...\n", "stdout")
            self._analyze_headers(target, host, scan_result, project_id, execution.id, emit)

        # 6. CORS Configuration Analysis
        if options.check_cors and not self._is_cancelled:
            emit("[*] Inspecting CORS policy...\n", "stdout")
            self._analyze_cors(target, host, scan_result, project_id, execution.id, http, options.timeout, emit)

        # 7. Endpoint Discovery
        if options.discover_endpoints and not self._is_cancelled and raw_body:
            emit("[*] Extracting endpoints, forms, and scripts...\n", "stdout")
            self._discover_endpoints(target, raw_body, scan_result, emit)

        # 8. JavaScript Secret Candidate Detection
        if options.check_js_secrets and not self._is_cancelled:
            emit("[*] Scanning web assets and JavaScript for secrets...\n", "stdout")
            self._scan_for_secrets(target, raw_body, scan_result, project_id, execution.id, http, options, emit)

        # Check cancellation before saving findings
        if self._is_cancelled:
            execution.status = ExecutionStatus.CANCELLED
            self.db.update_execution(execution)
            emit("[-] Assessment cancelled by user.\n", "stderr")
            return True, "Assessment cancelled by user", scan_result, execution

        # 9. Evidence Persistence with SHA-256
        if evidence_dir and raw_body:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"web_exec_{execution.id}.json"
            ev_data = {
                "target": target,
                "status_code": response.status_code if response else None,
                "headers": scan_result.headers,
                "endpoints": scan_result.endpoints,
                "secrets_found": len(scan_result.secrets),
                "findings": len(scan_result.findings),
            }
            json_text = json.dumps(ev_data, indent=2)
            ev_file.write_text(json_text, encoding="utf-8")

            sha256 = hashlib.sha256(json_text.encode("utf-8")).hexdigest()
            execution.raw_output_path = str(ev_file)
            self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    execution_id=execution.id,
                    assessment_id=assessment_id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"Web assessment report for {target}",
                    mime_type="application/json",
                )
            )

        # Save all findings in DB with deduplication
        for f in scan_result.findings:
            if assessment_id:
                f.assessment_id = assessment_id
            self.db.upsert_finding_deduplicated(f)

        execution.status = ExecutionStatus.COMPLETED
        self.db.update_execution(execution)
        emit(f"[+] Assessment completed. {len(scan_result.findings)} findings recorded.\n", "success")

        return True, "Success", scan_result, execution

    def _analyze_headers(
        self,
        url: str,
        host: str,
        result: WebScanResult,
        project_id: int,
        execution_id: int,
        emit: Callable,
    ):
        headers_lower = {k.lower(): v for k, v in result.headers.items()}

        # 1. Check Missing HSTS (if HTTPS)
        if url.startswith("https://") and "strict-transport-security" not in headers_lower:
            emit("    [-] Missing HSTS header (Strict-Transport-Security)\n", "stderr")
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    severity=FindingSeverity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset=host,
                    affected_port_service="443/https",
                    description="The web server does not enforce HTTPS connections via HSTS.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to server configuration.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="c0desec",
                    execution_id=execution_id,
                )
            )

        # 2. Check Missing CSP
        if "content-security-policy" not in headers_lower:
            emit("    [-] Missing Content-Security-Policy header\n", "stderr")
            result.findings.append(
                Finding(
                    project_id=project_id,
                    title="Missing Content-Security-Policy (CSP) Header",
                    severity=FindingSeverity.MEDIUM,
                    cvss_score=4.3,
                    affected_asset=host,
                    description="Absence of CSP reduces defense-in-depth against XSS and data exfiltration.",
                    remediation="Implement a restrictive Content-Security-Policy header.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="c0desec",
                    execution_id=execution_id,
                )
            )

        # 3. Check Server Banner Leakage
        if "server" in headers_lower:
            server_banner = headers_lower["server"]
            if any(char.isdigit() for char in server_banner):  # Version disclosed
                emit(f"    [-] Server banner reveals software version: {server_banner}\n", "stderr")
                result.findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Server Version Disclosure ({server_banner})",
                        severity=FindingSeverity.LOW,
                        cvss_score=3.1,
                        affected_asset=host,
                        description=f"The web server discloses exact version information: '{server_banner}'.",
                        remediation="Configure the server banner to generic tokens or suppress it completely.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="c0desec",
                        execution_id=execution_id,
                    )
                )

    def _analyze_cors(
        self,
        url: str,
        host: str,
        result: WebScanResult,
        project_id: int,
        execution_id: int,
        http: requests.Session,
        timeout: float,
        emit: Callable,
    ):
        try:
            evil_origin = "https://attacker.evil.com"
            resp = http.options(url, headers={"Origin": evil_origin}, timeout=timeout)
            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

            if acao == evil_origin and acac == "true":
                result.cors_vulnerable = True
                result.cors_details = f"Reflected arbitrary origin '{evil_origin}' with credentials=true"
                emit(f"    [!] HIGH RISK: Insecure CORS policy reflects origin with credentials!\n", "stderr")
                result.findings.append(
                    Finding(
                        project_id=project_id,
                        title="Insecure Cross-Origin Resource Sharing (CORS) Misconfiguration",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        affected_asset=host,
                        description="The application reflects arbitrary untrusted Origin headers with Access-Control-Allow-Credentials: true, enabling unauthorized cross-origin data theft.",
                        remediation="Do not reflect user-controlled Origin headers. Maintain an explicit whitelist of trusted domains and disallow credentials on wildcards.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="c0desec",
                        execution_id=execution_id,
                    )
                )
            elif acao == "*":
                emit("    [*] CORS wildcard '*' detected\n", "stdout")
        except Exception as e:
            emit(f"    [-] CORS check failed: {e}\n", "stderr")

    def _discover_endpoints(
        self,
        base_url: str,
        html: str,
        result: WebScanResult,
        emit: Callable,
    ):
        # Extract href and src paths
        path_pattern = re.compile(r'''(?:href|src|action)=["']([^"'>\s#]+)["']''', re.I)
        found: Set[str] = set()

        for match in path_pattern.finditer(html):
            rel_path = match.group(1).strip()
            if rel_path.startswith(("javascript:", "mailto:", "tel:")):
                continue
            full_url = urljoin(base_url, rel_path)
            # Stay within same host
            if urlparse(full_url).hostname == urlparse(base_url).hostname:
                found.add(full_url)

        result.endpoints = sorted(list(found))
        emit(f"    [+] Discovered {len(result.endpoints)} internal routes/endpoints\n", "stdout")

    def _scan_for_secrets(
        self,
        base_url: str,
        body: str,
        result: WebScanResult,
        project_id: int,
        execution_id: int,
        http: requests.Session,
        options: WebScanOptions,
        emit: Callable,
    ):
        # 1. Scan main HTML body
        self._scan_text_blob(body, base_url, result, project_id, execution_id, emit)

        # 2. Extract and scan referenced JS scripts
        js_pattern = re.compile(r'''<script[^>]+src=["']([^"'>]+\.js(?:[?#][^"'>]*)?)["']''', re.I)
        js_urls = []
        for match in js_pattern.finditer(body):
            js_urls.append(urljoin(base_url, match.group(1)))

        for js_url in js_urls[:5]:  # Limit to top 5 JS files for bounded execution
            if self._is_cancelled:
                break
            try:
                time.sleep(options.rate_limit_delay)
                resp = http.get(js_url, timeout=options.timeout)
                if resp.status_code == 200 and resp.text:
                    script_text = resp.text[:options.max_response_size]
                    emit(f"    [*] Scanning script: {js_url} ({len(script_text)} bytes)...\n", "stdout")
                    self._scan_text_blob(script_text, js_url, result, project_id, execution_id, emit)
            except Exception:
                pass

    def _scan_text_blob(
        self,
        text: str,
        source_url: str,
        result: WebScanResult,
        project_id: int,
        execution_id: int,
        emit: Callable,
    ):
        for kind, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                raw_match = match.group(0)
                # Compute SHA-256 of raw secret to identify uniqueness without logging secret
                secret_hash = hashlib.sha256(raw_match.encode("utf-8")).hexdigest()

                if any(s.raw_sha256 == secret_hash for s in result.secrets):
                    continue

                redacted = redact_secret_value(raw_match)
                start, end = match.span()
                context = text[max(0, start - 40):min(len(text), end + 40)].replace("\n", " ")

                secret_record = DiscoveredSecret(
                    secret_type=kind,
                    redacted_preview=redacted,
                    raw_sha256=secret_hash,
                    source_url=source_url,
                    context_snippet=context,
                )
                result.secrets.append(secret_record)
                emit(f"    [!] Sensitive Candidate Found: {kind} ({redacted}) in {source_url}\n", "stderr")

                # Record as High/Critical Finding
                result.findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Hardcoded Secret Candidate: {kind} in Web Asset",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        affected_asset=urlparse(source_url).hostname or source_url,
                        affected_port_service="Web Asset",
                        description=f"A potential sensitive credential of type '{kind}' was detected. Value preview: {redacted}. Source: {source_url}",
                        remediation="Revoke and rotate the exposed credential immediately. Move private keys and secrets to environment variables or backend secrets managers.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="c0desec",
                        execution_id=execution_id,
                    )
                )

