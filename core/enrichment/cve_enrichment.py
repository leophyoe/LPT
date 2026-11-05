"""Curated Offline CVE and CVSS Enrichment Service.

Provides deterministic, offline vulnerability signature enrichment for discovered
services and software versions. Guarantees:
1. Zero Hallucination: All CVE mappings originate from a strictly curated catalog.
2. Strict Status Demarcation: Software version matches default to ValidationStatus.NEEDS_VALIDATION
   or OBSERVED with confidence <= 0.65 (accounting for OS package backports).
3. Distinguishes passive software observations from empirically confirmed exploits.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.parsers.normalized_models import NormalizedFinding, NormalizedService
from storage.models import FindingSeverity, ValidationStatus, _utc_now_iso

logger = logging.getLogger(__name__)


@dataclass
class CuratedVulnerability:
    """Entry in the local curated CVE catalog."""
    cve_id: str
    product_pattern: str
    version_regex: str
    title: str
    severity: FindingSeverity
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    description: str
    remediation: str
    exploit_available: bool = False


class CVEEnrichmentService:
    """Enriches discovered services and finding records with offline curated CVE intelligence."""

    CATALOG_TYPE: str = "CURATED_OFFLINE_INCOMPLETE"
    CATALOG_DISCLAIMER: str = (
        "This catalog contains a curated, non-exhaustive subset of high-impact vulnerabilities for offline matching. "
        "It does NOT represent a complete NVD or CVE database. Software version matches are heuristic candidates "
        "and NEVER auto-confirmed findings; OS package backports (e.g. Debian, RHEL, Ubuntu) may render the service "
        "immune despite the banner version."
    )

    # Curated authoritative vulnerability database (Zero LLM Hallucinations)
    CURATED_CATALOG: List[CuratedVulnerability] = [
        CuratedVulnerability(
            cve_id="CVE-2021-41773",
            product_pattern=r"apache(?:\s+httpd)?",
            version_regex=r"^2\.4\.49$",
            title="Apache HTTP Server 2.4.49 Path Traversal & Remote Code Execution",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-22",
            description=(
                "A path traversal flaw was found in Apache HTTP Server 2.4.49. An attacker could use "
                "a path traversal attack to map URLs to files outside the expected document root. "
                "If files outside of document roots are not protected by 'require all denied' and CGI is enabled, "
                "arbitrary command execution is possible."
            ),
            remediation="Upgrade Apache HTTP Server to version 2.4.51 or later immediately.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2021-42013",
            product_pattern=r"apache(?:\s+httpd)?",
            version_regex=r"^2\.4\.50$",
            title="Apache HTTP Server 2.4.50 Path Traversal & RCE (Incomplete Fix for CVE-2021-41773)",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-22",
            description=(
                "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. "
                "An attacker could use a path traversal attack using double-encoded URL characters (%252e) "
                "to execute arbitrary code if CGI scripts are configured."
            ),
            remediation="Upgrade Apache HTTP Server to version 2.4.51 or later.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2024-6387",
            product_pattern=r"openssh",
            version_regex=r"^(?:8\.[5-9]|9\.[0-7])p[1-9]$",
            title="OpenSSH Server regreSSHion Signal Handler Remote Code Execution",
            severity=FindingSeverity.HIGH,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-364",
            description=(
                "A signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote code "
                "execution as root on glibc-based Linux systems (regreSSHion). Exploitation requires timing "
                "the SIGALRM handler during LoginGraceTime."
            ),
            remediation="Upgrade OpenSSH to version 9.8p1 or set 'LoginGraceTime 0' as a temporary mitigation.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2015-3306",
            product_pattern=r"proftpd",
            version_regex=r"^1\.3\.5(?:rc\d+)?$",
            title="ProFTPD 1.3.5 mod_copy Remote Arbitrary File Copy & Execution",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-284",
            description=(
                "The mod_copy module in ProFTPD 1.3.5 allows remote unauthenticated attackers to read and write "
                "arbitrary files via the SITE CPFR and SITE CPTO commands."
            ),
            remediation="Upgrade ProFTPD to 1.3.5a or later, or disable mod_copy in proftpd.conf.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2011-2523",
            product_pattern=r"vsftpd",
            version_regex=r"^2\.3\.4$",
            title="vsftpd 2.3.4 Smiley Face Backdoor Remote Command Execution",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-78",
            description=(
                "vsftpd 2.3.4 source code was compromised in July 2011 to include a backdoor. "
                "Authenticating with a smiley face in the username (':)') opens a root shell listener on port 6200."
            ),
            remediation="Upgrade vsftpd or download clean release from official distribution repository.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2017-7494",
            product_pattern=r"samba",
            version_regex=r"^(?:3\.5\.|4\.[0-6]\.)",
            title="Samba 'SambaCry' Remote Code Execution",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-94",
            description=(
                "All versions of Samba from 3.5.0 onwards are vulnerable to a remote code execution vulnerability "
                "allowing a malicious client to upload a shared library to a writable share and cause the server "
                "to load and execute it."
            ),
            remediation="Upgrade Samba to version 4.6.4, 4.5.10, or 4.4.14, or set 'nt pipe support = no'.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2014-0160",
            product_pattern=r"openssl",
            version_regex=r"^1\.0\.1[a-f]?$",
            title="OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe_id="CWE-125",
            description=(
                "The TLS and DTLS implementations in OpenSSL 1.0.1 through 1.0.1f do not properly handle Heartbeat "
                "Extension packets, allowing remote attackers to read up to 64KB of server process memory per request."
            ),
            remediation="Upgrade OpenSSL to version 1.0.1g or later, or recompile with -DOPENSSL_NO_HEARTBEATS.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2021-23017",
            product_pattern=r"nginx",
            version_regex=r"^1\.20\.0$",
            title="Nginx 1.20.0 DNS Resolver 1-Byte Memory Overwrite",
            severity=FindingSeverity.HIGH,
            cvss_score=7.7,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-193",
            description=(
                "A 1-byte memory overwrite vulnerability in the DNS resolver module of Nginx 0.6.18 through 1.20.0 "
                "allows remote attackers to cause worker process crash or potentially execute arbitrary code."
            ),
            remediation="Upgrade Nginx to version 1.20.1 or 1.21.0 or later.",
            exploit_available=True,
        ),
        CuratedVulnerability(
            cve_id="CVE-2017-0144",
            product_pattern=r"(?:microsoft\s+smb|smbv1|windows)",
            version_regex=r".*",
            title="Microsoft SMBv1 Remote Code Execution (MS17-010 / EternalBlue)",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-787",
            description=(
                "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via "
                "crafted packets (MS17-010 EternalBlue)."
            ),
            remediation="Disable SMBv1 across all systems and apply Microsoft security bulletin MS17-010.",
            exploit_available=True,
        ),
    ]

    @classmethod
    def lookup_product_vulnerabilities(
        cls,
        product: str,
        version: str,
    ) -> List[CuratedVulnerability]:
        """Finds matching catalog entries based on product string and version."""
        if not product:
            return []

        matched: List[CuratedVulnerability] = []
        prod_clean = product.strip().lower()
        ver_clean = version.strip()

        for entry in cls.CURATED_CATALOG:
            if re.search(entry.product_pattern, prod_clean, re.IGNORECASE):
                if not entry.version_regex or entry.version_regex == ".*":
                    matched.append(entry)
                elif ver_clean and re.search(entry.version_regex, ver_clean, re.IGNORECASE):
                    matched.append(entry)

        return matched

    @classmethod
    def enrich_service(
        cls,
        service: NormalizedService,
        evidence_id: Optional[int] = None,
        execution_id: Optional[int] = None,
    ) -> List[NormalizedFinding]:
        """Enriches a discovered service by generating candidate findings for matched CVE signatures."""
        search_product = service.product or service.service_name or ""
        search_version = service.version or ""

        matches = cls.lookup_product_vulnerabilities(search_product, search_version)
        findings: List[NormalizedFinding] = []

        for m in matches:
            desc = (
                f"{m.description}\n\n"
                f"Detected Exposure:\n"
                f"- Host: {service.host}:{service.port}/{service.protocol}\n"
                f"- Fingerprint: {service.service_summary}\n"
                f"- Match Confidence: 0.65 (Heuristic Version Match - Backported patches possible)\n\n"
                f"Validation Notice:\n"
                f"Software version matches represent candidate vulnerabilities. Controlled empirical "
                f"probing or OS package changelog verification is required before confirmation."
            )

            finding = NormalizedFinding(
                title=f"Potential {m.cve_id}: {m.title}",
                severity=m.severity,
                affected_asset=service.host,
                affected_service=f"{service.port}/{service.protocol}",
                port=service.port,
                protocol=service.protocol,
                cve_ids=[m.cve_id],
                cvss_score=m.cvss_score,
                cvss_vector=m.cvss_vector,
                cwe_id=m.cwe_id,
                description=desc,
                remediation=m.remediation,
                evidence_id=evidence_id,
                execution_id=execution_id,
                source_tool="cve_enrichment",
                confidence=0.65,
                validation_status=ValidationStatus.NEEDS_VALIDATION,
                validation_method="Offline Curated Signature Matching (Potential/Unverified)",
                severity_rationale="Version banner matches vulnerable release range; verification probe required to confirm unpatched state due to OS vendor backporting.",
            )
            findings.append(finding)

        return findings

    @classmethod
    def enrich_finding(cls, finding: NormalizedFinding) -> NormalizedFinding:
        """Enriches an existing finding by filling in missing CVE, CVSS, and CWE data if matched."""
        if not finding.cve_ids:
            return finding

        for cve in finding.cve_ids:
            cve_clean = cve.strip().upper()
            for entry in cls.CURATED_CATALOG:
                if entry.cve_id == cve_clean:
                    if finding.cvss_score is None:
                        finding.cvss_score = entry.cvss_score
                    if not finding.cvss_vector:
                        finding.cvss_vector = entry.cvss_vector
                    if not finding.cwe_id:
                        finding.cwe_id = entry.cwe_id
                    if not finding.remediation:
                        finding.remediation = entry.remediation
                    break

        return finding

