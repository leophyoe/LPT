"""Autonomous finding triage, risk scoring, and remediation playbook generator.

Inspired by usestrix/strix (https://github.com/usestrix/strix).
Evaluates raw vulnerability findings, applies false positive heuristics,
calculates CVSS v3.1 score approximations, and generates actionable mitigation playbooks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from storage.models import Finding, FindingSeverity


@dataclass
class TriagedFinding:
    original_finding: Finding
    cvss_score: float
    cvss_vector: str
    owasp_category: str
    is_likely_false_positive: bool
    confidence: str  # High, Medium, Low
    remediation_summary: str
    remediation_snippet: str
    references: List[str]


class StrixTriageEngine:
    """Strix AI-inspired autonomous triage, risk evaluation, and developer fix generator."""

    OWASP_MAPPINGS: Dict[str, str] = {
        "sqli": "A03:2021 - Injection",
        "sql": "A03:2021 - Injection",
        "xss": "A03:2021 - Injection",
        "command": "A03:2021 - Injection",
        "jwt": "A07:2021 - Identification and Authentication Failures",
        "auth": "A07:2021 - Identification and Authentication Failures",
        "cors": "A01:2021 - Broken Access Control",
        "secret": "A02:2021 - Cryptographic Failures",
        "header": "A05:2021 - Security Misconfiguration",
        "traversal": "A01:2021 - Broken Access Control",
        "port": "A05:2021 - Security Misconfiguration",
    }

    REMEDIATION_TEMPLATES: Dict[str, Dict[str, str]] = {
        "header,csp,hsts,x-frame,clickjack": {
            "summary": "Configure explicit, restrictive HTTP security response headers on the web server or reverse proxy.",
            "snippet": (
                "# Nginx Configuration Directive:\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\";\n"
                "add_header X-Frame-Options \"DENY\";\n"
                "add_header X-Content-Type-Options \"nosniff\";\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
            ),
        },
        "cors,origin": {
            "summary": "Restrict Cross-Origin Resource Sharing to explicitly trusted domains rather than using wildcard ('*').",
            "snippet": (
                "// Secure CORS Configuration (Express.js / Node.js):\n"
                "const allowedOrigins = ['https://trusted.corp', 'https://app.trusted.corp'];\n"
                "app.use(cors({\n"
                "  origin: (origin, callback) => {\n"
                "    if (!origin || allowedOrigins.includes(origin)) callback(null, true);\n"
                "    else callback(new Error('Blocked by CORS Policy'));\n"
                "  },\n"
                "  credentials: true\n"
                "}));"
            ),
        },
        "sql,sqli,injection": {
            "summary": "Enforce parameterized queries (prepared statements) across all database queries; never format raw strings into SQL.",
            "snippet": (
                "# Python (sqlite3 / psycopg2) Parameterized Query:\n"
                "cursor.execute(\n"
                "    \"SELECT id, username, email FROM users WHERE id = ?\", (user_input_id,)\n"
                ")"
            ),
        },
        "xss,cross-site,scripting": {
            "summary": "Implement context-aware HTML entity encoding and sanitize untrusted user input before rendering in DOM.",
            "snippet": (
                "// Secure DOMPurify Sanitization:\n"
                "import DOMPurify from 'dompurify';\n"
                "const cleanHtml = DOMPurify.sanitize(userProvidedHtml);\n"
                "// In standard DOM manipulation:\n"
                "element.textContent = userProvidedText; // Use textContent instead of innerHTML"
            ),
        },
        "jwt,token": {
            "summary": "Enforce strong asymmetric or HMAC keys (minimum 256-bit entropy) and strictly reject the 'none' algorithm.",
            "snippet": (
                "// Python (PyJWT) Secure Decoding:\n"
                "decoded = jwt.decode(\n"
                "    token,\n"
                "    key=SECRET_KEY,\n"
                "    algorithms=['HS256'],  # Strictly whitelist algorithms; never allow 'none'\n"
                "    options={'require': ['exp', 'iat', 'nbf']}\n"
                ")"
            ),
        },
        "secret,credential,password,key": {
            "summary": "Revoke the exposed API key or token immediately, audit access logs, and migrate to environment variables or a Secret Vault.",
            "snippet": (
                "# 1. Immediately revoke credential at provider portal\n"
                "# 2. Load via system environment variables instead of hardcoding:\n"
                "import os\n"
                "API_KEY = os.environ.get('SERVICE_API_KEY')"
            ),
        },
        "traversal,lfi,rfi,path": {
            "summary": "Validate and sanitize file paths using strict whitelisting, basename extraction, and canonical path checks.",
            "snippet": (
                "# Secure Path Resolution (Python):\n"
                "import os\n"
                "safe_path = os.path.abspath(os.path.join(BASE_DIR, os.path.basename(user_path)))\n"
                "if not safe_path.startswith(BASE_DIR):\n"
                "    raise PermissionError('Path traversal detected')"
            ),
        },
        "command,rce,exec": {
            "summary": "Avoid shell invocation; use parameterized subprocess execution with shell=False and strict argument lists.",
            "snippet": (
                "# Secure Subprocess Execution:\n"
                "import subprocess\n"
                "subprocess.run(['/usr/bin/tool', '--arg', safe_argument], shell=False, check=True)"
            ),
        },
    }

    @classmethod
    def triage_finding(cls, finding: Finding) -> TriagedFinding:
        """Evaluates an individual finding, estimates CVSS score, and generates a remediation playbook."""
        title_lower = finding.title.lower()
        desc_lower = (finding.description or "").lower()
        combined = f"{title_lower} {desc_lower}"

        # 1. Base CVSS estimation
        if finding.severity == FindingSeverity.CRITICAL:
            base_score = 9.8
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        elif finding.severity == FindingSeverity.HIGH:
            base_score = 7.5
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        elif finding.severity == FindingSeverity.MEDIUM:
            base_score = 5.3
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        elif finding.severity == FindingSeverity.LOW:
            base_score = 3.1
            vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        else:
            base_score = 0.0
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

        # 2. OWASP Top 10 Mapping
        owasp_cat = "A05:2021 - Security Misconfiguration"
        for key, cat in cls.OWASP_MAPPINGS.items():
            if key in combined:
                owasp_cat = cat
                break

        # 3. False Positive Heuristics
        is_fp = False
        confidence = "High"
        if "info" in title_lower and "disclosure" in title_lower:
            confidence = "Medium"
        if "test" in desc_lower and "mock" in desc_lower:
            is_fp = True
            confidence = "Low"

        # 4. Remediation Playbook
        rem_summary = "Review the affected asset and apply vendor security patches."
        rem_snippet = "# Review security configuration according to OWASP guidelines."
        for key, template in cls.REMEDIATION_TEMPLATES.items():
            keywords = [k.strip() for k in key.split(",")]
            if any(k in combined for k in keywords):
                rem_summary = template["summary"]
                rem_snippet = template["snippet"]
                break

        return TriagedFinding(
            original_finding=finding,
            cvss_score=base_score,
            cvss_vector=vector,
            owasp_category=owasp_cat,
            is_likely_false_positive=is_fp,
            confidence=confidence,
            remediation_summary=rem_summary,
            remediation_snippet=rem_snippet,
            references=[
                "https://owasp.org/Top10/",
                "https://cwe.mitre.org/",
            ],
        )

    @classmethod
    def triage(cls, finding: Finding) -> TriagedFinding:
        """Alias for triage_finding."""
        return cls.triage_finding(finding)

    @classmethod
    def triage_all(cls, findings: List[Finding]) -> List[TriagedFinding]:
        """Triages a collection of assessment findings, sorted by descending risk severity."""
        triaged = [cls.triage_finding(f) for f in findings]
        triaged.sort(key=lambda x: x.cvss_score, reverse=True)
        return triaged
