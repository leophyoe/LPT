"""Nikto Web Vulnerability Scanner Output Parser.

Parses both structured JSON and streaming text output from Nikto.
Extracts security findings, assigns CVSS approximation, normalizes severity,
and produces persisted CyberSecuritySuite Finding objects.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from storage.models import Finding, FindingSeverity, ValidationStatus


@dataclass
class NiktoItem:
    """Represents a single issue or observation detected by Nikto."""
    msg: str
    uri: str = "/"
    method: str = "GET"
    osvdb_id: str = ""
    nikto_id: str = ""
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    title: str = ""
    remediation: str = ""


@dataclass
class NiktoScanResult:
    """Consolidated results of a Nikto assessment run."""
    target_host: str
    target_ip: str = ""
    target_port: str = "80"
    banner: str = ""
    items: List[NiktoItem] = field(default_factory=list)


class NiktoParser:
    """Parser for Nikto vulnerability scanner outputs."""

    # Heuristics for classifying severity from Nikto message text
    CRITICAL_PATTERNS = [
        r"remote\s+code\s+execution",
        r"\brce\b",
        r"command\s+execution",
        r"web\s*shell",
        r"sql\s+injection",
        r"arbitrary\s+file",
        r"database\s+credentials",
        r"cve-202[1-9]-\d+",
        r"root\s+access",
        r"file\s+upload",
    ]

    HIGH_PATTERNS = [
        r"admin\s+(?:interface|portal|console|login|page)",
        r"/admin(?:/|\b)",
        r"password\s+file",
        r"directory\s+traversal",
        r"path\s+traversal",
        r"lfi|rfi",
        r"source\s+code\s+disclosure",
        r"phpinfo",
        r"unauthenticated",
        r"without\s+authentication",
        r"backup\s+file",
        r"vulnerable\s+to",
    ]

    MEDIUM_PATTERNS = [
        r"interesting\s+(?:file|directory)",
        r"cross\s*site\s*scripting|xss",
        r"login\s+page",
        r"information\s+disclosure",
        r"sensitive\s+information",
        r"osvdb-\d+",
        r"cve-\d{4}-\d+",
        r"trace\s+method\s+is\s+active",
        r"webdav",
    ]

    LOW_PATTERNS = [
        r"anti-clickjacking",
        r"x-frame-options",
        r"x-content-type-options",
        r"x-xss-protection",
        r"strict-transport-security|hsts",
        r"content-security-policy|csp",
        r"etag",
        r"cookie\s+without\s+(?:secure|httponly)",
        r"default\s+file",
    ]

    @classmethod
    def determine_severity(cls, text: str) -> FindingSeverity:
        """Determines finding severity based on matched keyword patterns."""
        t = text.lower()
        for pat in cls.CRITICAL_PATTERNS:
            if re.search(pat, t):
                return FindingSeverity.CRITICAL
        for pat in cls.HIGH_PATTERNS:
            if re.search(pat, t):
                return FindingSeverity.HIGH
        for pat in cls.MEDIUM_PATTERNS:
            if re.search(pat, t):
                return FindingSeverity.MEDIUM
        for pat in cls.LOW_PATTERNS:
            if re.search(pat, t):
                return FindingSeverity.LOW
        return FindingSeverity.INFORMATIONAL

    @classmethod
    def generate_title(cls, msg: str, uri: str) -> str:
        """Generates a concise finding title from Nikto message text."""
        clean = msg.strip()
        # Remove leading "+ "
        if clean.startswith("+ "):
            clean = clean[2:].strip()

        # Handle OSVDB prefix
        clean = re.sub(r"^OSVDB-\d+:\s*", "", clean)

        # Truncate or use first sentence
        parts = clean.split(". ")
        first_clause = parts[0].strip()

        if uri and uri != "/" and not first_clause.startswith(uri):
            return f"Nikto: {uri} — {first_clause[:70]}"
        return f"Nikto: {first_clause[:80]}"

    @classmethod
    def generate_remediation(cls, msg: str) -> str:
        """Suggests remediation guidance based on finding category."""
        t = msg.lower()
        if "x-frame-options" in t or "anti-clickjacking" in t:
            return "Configure the 'X-Frame-Options: DENY' or 'SAMEORIGIN' header to prevent clickjacking attacks."
        if "x-content-type-options" in t:
            return "Configure 'X-Content-Type-Options: nosniff' header to prevent MIME type sniffing."
        if "strict-transport-security" in t or "hsts" in t:
            return "Enforce HTTP Strict Transport Security (HSTS) with 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        if "x-xss-protection" in t:
            return "Configure Content-Security-Policy (CSP) headers to mitigate cross-site scripting."
        if "admin" in t or "login" in t:
            return "Restrict administrative portals and authentication interfaces to internal IP ranges and enforce Multi-Factor Authentication (MFA)."
        if "backup" in t or "bak" in t:
            return "Remove backup and temporary files from the web root; do not deploy development artifacts to production."
        if "rce" in t or "command" in t or "traversal" in t:
            return "Apply upstream vendor security patches immediately and sanitize all path parameters."
        return "Review the server configuration and apply recommended defense-in-depth hardening."

    @classmethod
    def parse_json(cls, json_str: str) -> NiktoScanResult:
        """Parses Nikto JSON report format."""
        try:
            data = json.loads(json_str)
        except Exception as e:
            raise ValueError(f"Failed to parse Nikto JSON: {e}")

        # Nikto JSON may wrap in {"nikto": {...}} or root dict
        root = data.get("nikto", data)
        host = root.get("host", root.get("target_host", "Unknown"))
        ip = root.get("ip", "")
        port = str(root.get("port", "80"))
        banner = root.get("banner", "")

        result = NiktoScanResult(target_host=host, target_ip=ip, target_port=port, banner=banner)

        raw_vulns = root.get("vulnerabilities", [])
        for item in raw_vulns:
            msg = item.get("msg", "")
            if not msg:
                continue
            uri = item.get("url", "/")
            method = item.get("method", "GET")
            osvdb = str(item.get("OSVDB", ""))
            nikto_id = str(item.get("id", ""))
            sev = cls.determine_severity(msg)
            title = cls.generate_title(msg, uri)
            remediation = cls.generate_remediation(msg)

            result.items.append(
                NiktoItem(
                    msg=msg,
                    uri=uri,
                    method=method,
                    osvdb_id=osvdb,
                    nikto_id=nikto_id,
                    severity=sev,
                    title=title,
                    remediation=remediation,
                )
            )

        return result

    @classmethod
    def parse_text(cls, text: str) -> NiktoScanResult:
        """Parses Nikto standard human-readable text output."""
        host = ""
        ip = ""
        port = "80"
        banner = ""
        items: List[NiktoItem] = []

        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("+"):
                continue

            # Extract header metadata
            if "+ Target IP:" in line:
                ip = line.split(":", 1)[1].strip()
            elif "+ Target Hostname:" in line:
                host = line.split(":", 1)[1].strip()
            elif "+ Target Port:" in line:
                port = line.split(":", 1)[1].strip()
            elif "+ Server:" in line:
                banner = line.split(":", 1)[1].strip()

            # Ignore progress or delimiter lines
            if any(ign in line for ign in (
                "Target IP:", "Target Hostname:", "Target Port:", "Start Time:",
                "End Time:", "requests:", "host(s) tested", "-------"
            )):
                continue

            # Treat as vulnerability or observation
            msg = line[1:].strip() if line.startswith("+") else line
            if not msg or len(msg) < 5:
                continue

            # Check for URI reference
            uri_match = re.search(r"(\/[a-zA-Z0-9_\-\.\/]+)", msg)
            uri = uri_match.group(1) if uri_match else "/"

            # Check for OSVDB
            osvdb_match = re.search(r"OSVDB-(\d+)", msg)
            osvdb = osvdb_match.group(1) if osvdb_match else ""

            sev = cls.determine_severity(msg)
            title = cls.generate_title(msg, uri)
            remediation = cls.generate_remediation(msg)

            items.append(
                NiktoItem(
                    msg=msg,
                    uri=uri,
                    method="GET",
                    osvdb_id=osvdb,
                    nikto_id="",
                    severity=sev,
                    title=title,
                    remediation=remediation,
                )
            )

        if not host:
            host = ip or "Target Host"

        return NiktoScanResult(target_host=host, target_ip=ip, target_port=port, banner=banner, items=items)

    @classmethod
    def to_findings(
        cls,
        scan_result: NiktoScanResult,
        project_id: int,
        execution_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Converts parsed NiktoScanResult items into CyberSecuritySuite Finding models."""
        findings: List[Finding] = []
        target_asset = scan_result.target_host or scan_result.target_ip or "Target Host"

        for item in scan_result.items:
            # Skip pure info banners if desired, or keep as informational
            desc_parts = [
                f"**Observation:** {item.msg}",
                f"**Affected URI:** `{item.uri}` (Method: {item.method})",
            ]
            if item.osvdb_id and item.osvdb_id != "0":
                desc_parts.append(f"**OSVDB Reference:** OSVDB-{item.osvdb_id}")
            if scan_result.banner:
                desc_parts.append(f"**Server Banner:** {scan_result.banner}")

            description = "\n\n".join(desc_parts)

            # CVSS approximations
            cvss_score = {
                FindingSeverity.CRITICAL: 9.8,
                FindingSeverity.HIGH: 7.5,
                FindingSeverity.MEDIUM: 5.3,
                FindingSeverity.LOW: 3.1,
                FindingSeverity.INFORMATIONAL: 0.0,
            }.get(item.severity, 0.0)

            finding = Finding(
                project_id=project_id,
                title=item.title,
                severity=item.severity,
                cvss_score=cvss_score,
                affected_asset=target_asset,
                affected_port_service=f"{scan_result.target_port}/tcp",
                description=description,
                reproduction_steps=f"Execute Nikto web audit:\nnikto -host {scan_result.target_host} -port {scan_result.target_port}",
                remediation=item.remediation,
                validation_status=ValidationStatus.UNVERIFIED,
                source_tool="nikto",
                execution_id=execution_id,
                assessment_id=assessment_id,
            )
            findings.append(finding)

        return findings
