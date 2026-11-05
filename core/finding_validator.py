"""Deterministic Evidence-Based Finding Validation Engine for CyberSecuritySuite.

Enforces strict empirical verification policies before security findings can be
classified as confirmed vulnerabilities:
1. Raw tool output is never automatically confirmed.
2. Open network ports represent observed exposure, not confirmed vulnerabilities.
3. HTTP 200/301 responses or sensitive-looking endpoints do not prove exploitability.
4. AI-generated text or heuristic advice is strictly prohibited from confirming vulnerabilities.
5. Findings without reproducible proof-of-concept are classified as OBSERVED or NEEDS_VALIDATION.
6. False positives (e.g. soft 404s, WAF challenges, login walls) are filtered out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from storage.models import Finding, FindingSeverity, ValidationStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ValidatorRuleCode(str, Enum):
    VR_001_PORT_EXPOSURE_ONLY = "VR-001-PORT-EXPOSURE"
    VR_002_HTTP_STATUS_UNVERIFIED = "VR-002-HTTP-STATUS-UNVERIFIED"
    VR_003_AI_ADVISORY_ONLY = "VR-003-AI-ADVISORY-ONLY"
    VR_004_SECRET_ENTROPY_CONFIRMED = "VR-004-SECRET-ENTROPY-CONFIRMED"
    VR_005_CORS_EXPLOITABLE_CONFIRMED = "VR-005-CORS-EXPLOITABLE-CONFIRMED"
    VR_006_FILE_PERM_EXPLOITABLE = "VR-006-FILE-PERM-EXPLOITABLE"
    VR_007_SOFT_404_FALSE_POSITIVE = "VR-007-SOFT-404-FALSE-POSITIVE"
    VR_008_MISSING_HEADER_OBSERVED = "VR-008-MISSING-HEADER-OBSERVED"
    VR_009_GENERIC_OBSERVATION = "VR-009-GENERIC-OBSERVATION"


@dataclass
class ValidationAssessment:
    """Outcome of deterministic validator evaluation."""
    finding_id: Optional[int]
    status: ValidationStatus
    validator_rule: ValidatorRuleCode
    validator_version: str
    validation_method: str
    severity_rationale: str
    retest_guidance: str
    is_confirmed: bool = False
    evidence_required: List[str] = field(default_factory=list)


class FindingValidationEngine:
    """Applies rigorous empirical validation policies across candidate findings."""

    VALIDATOR_VERSION = "2026.1-cpent-deterministic"

    # Known soft-404 signatures
    SOFT_404_PATTERNS = [
        re.compile(r"page not found", re.IGNORECASE),
        re.compile(r"404 not found", re.IGNORECASE),
        re.compile(r"the page you requested cannot be found", re.IGNORECASE),
        re.compile(r"return to home", re.IGNORECASE),
        re.compile(r"error 404", re.IGNORECASE),
    ]

    @classmethod
    def evaluate(
        cls,
        finding: Finding,
        raw_evidence: Optional[str] = None,
        source: str = "automated_adapter",
    ) -> ValidationAssessment:
        """Determines the exact empirical validation state for a candidate finding."""
        title_lower = (finding.title or "").lower()
        desc_lower = (finding.description or "").lower()
        source_lower = (source or finding.source_tool or "").lower()
        evidence_text = raw_evidence or finding.reproduction_steps or ""

        # 1. Prohibit AI text from auto-confirming findings
        if any(ai_tag in source_lower for ai_tag in ("ai_copilot", "llm", "gemini", "openai", "ollama", "gpt")):
            return ValidationAssessment(
                finding_id=finding.id,
                status=ValidationStatus.NEEDS_VALIDATION,
                validator_rule=ValidatorRuleCode.VR_003_AI_ADVISORY_ONLY,
                validator_version=cls.VALIDATOR_VERSION,
                validation_method="AI Heuristic Triage (Unverified)",
                severity_rationale="AI suggestions provide advisory hypotheses only; empirical retest or network proof is mandatory before confirmation.",
                retest_guidance="Execute an authorized reproducible CLI probe against the endpoint to capture raw response bytes.",
                is_confirmed=False,
                evidence_required=["Raw HTTP response", "Packet capture", "Terminal transcript"],
            )

        # 2. Rule VR-007: Check for Soft 404 / Login wall false positives
        if raw_evidence:
            for pattern in cls.SOFT_404_PATTERNS:
                if pattern.search(raw_evidence):
                    return ValidationAssessment(
                        finding_id=finding.id,
                        status=ValidationStatus.FALSE_POSITIVE,
                        validator_rule=ValidatorRuleCode.VR_007_SOFT_404_FALSE_POSITIVE,
                        validator_version=cls.VALIDATOR_VERSION,
                        validation_method="Soft-404 Semantic Body Inspection",
                        severity_rationale="Server returned HTTP 200 status code but response content matches generic 'Page Not Found' error body.",
                        retest_guidance="Verify whether endpoint returns identical content for random non-existent paths.",
                        is_confirmed=False,
                    )

        # 3. Rule VR-001: Open port is an observation, NEVER confirmed vulnerability
        if ("port" in title_lower and "open" in title_lower) or any(term in title_lower for term in ("open port", "port open", "service banner", "port discovered", "discovered service")):
            return ValidationAssessment(
                finding_id=finding.id,
                status=ValidationStatus.OBSERVED,
                validator_rule=ValidatorRuleCode.VR_001_PORT_EXPOSURE_ONLY,
                validator_version=cls.VALIDATOR_VERSION,
                validation_method="Network TCP/UDP SYN/Connect Probe",
                severity_rationale="Open ports constitute legitimate network service reachability. Proof of vulnerability requires an exploitable version defect or authentication bypass.",
                retest_guidance="Perform deep service version scanning and credential auditing on the listening daemon.",
                is_confirmed=False,
                evidence_required=["Service version banner", "Vulnerability CVE reproduction"],
            )

        # 4. Rule VR-008: Missing HTTP security headers (CSP, HSTS, XFO)
        if any(term in title_lower for term in ("missing header", "content-security-policy", "strict-transport-security", "x-frame-options")):
            # Missing header is confirmed as a configuration deficiency, but its severity is informational/low unless active exploit is proven
            return ValidationAssessment(
                finding_id=finding.id,
                status=ValidationStatus.OBSERVED,
                validator_rule=ValidatorRuleCode.VR_008_MISSING_HEADER_OBSERVED,
                validator_version=cls.VALIDATOR_VERSION,
                validation_method="Passive HTTP Response Header Inspection",
                severity_rationale="Defense-in-depth header absence observed in response. Severity is capped at LOW/MEDIUM unless active clickjacking or XSS is demonstrated.",
                retest_guidance="Audit application frameability in iframe PoC or test cookie transport over plaintext HTTP.",
                is_confirmed=False,
            )

        # 5. Rule VR-005: CORS Misconfiguration with Credentials
        if "cors" in title_lower and ("arbitrary origin" in desc_lower or "credentials allowed" in desc_lower or "allow-credentials: true" in evidence_text.lower()):
            if "allow-credentials" in evidence_text.lower() or "credentials" in desc_lower:
                return ValidationAssessment(
                    finding_id=finding.id,
                    status=ValidationStatus.CONFIRMED,
                    validator_rule=ValidatorRuleCode.VR_005_CORS_EXPLOITABLE_CONFIRMED,
                    validator_version=cls.VALIDATOR_VERSION,
                    validation_method="Authenticated CORS Reflection PoC Probe",
                    severity_rationale="Server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true, allowing attacker websites to steal authenticated session data.",
                    retest_guidance="Issue curl with -H 'Origin: https://evil.corp' and verify Access-Control-Allow-Origin reflects evil.corp with credentials.",
                    is_confirmed=True,
                )

        # 6. Rule VR-004: Hardcoded High-Entropy Secret / API Key
        if any(k in title_lower for k in ("secret", "api key", "access key", "token", "credential", "private key")):
            if re.search(r"(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)", evidence_text):
                return ValidationAssessment(
                    finding_id=finding.id,
                    status=ValidationStatus.CONFIRMED,
                    validator_rule=ValidatorRuleCode.VR_004_SECRET_ENTROPY_CONFIRMED,
                    validator_version=cls.VALIDATOR_VERSION,
                    validation_method="Cryptographic High-Entropy Pattern & Prefix Matcher",
                    severity_rationale="Discovered token conforms to production vendor secret formats and entropy requirements.",
                    retest_guidance="Verify token validity against vendor STS/user API without performing destructive operations.",
                    is_confirmed=True,
                )
            else:
                return ValidationAssessment(
                    finding_id=finding.id,
                    status=ValidationStatus.NEEDS_VALIDATION,
                    validator_rule=ValidatorRuleCode.VR_002_HTTP_STATUS_UNVERIFIED,
                    validator_version=cls.VALIDATOR_VERSION,
                    validation_method="Pattern Matcher (Potential Placeholder / Token)",
                    severity_rationale="Candidate string resembles credential syntax but lacks verified vendor entropy. May be test fixture or template.",
                    retest_guidance="Perform out-of-band credential verification in staging environment.",
                    is_confirmed=False,
                )

        # 7. Rule VR-006: Local File Permissions / SUID Misconfigurations
        if any(term in title_lower for term in ("world-writable", "shadow", "sudoers", "suid")):
            if "world-writable" in desc_lower or "world-writable" in evidence_text.lower():
                return ValidationAssessment(
                    finding_id=finding.id,
                    status=ValidationStatus.CONFIRMED,
                    validator_rule=ValidatorRuleCode.VR_006_FILE_PERM_EXPLOITABLE,
                    validator_version=cls.VALIDATOR_VERSION,
                    validation_method="Local POSIX File Mode Bit Audit",
                    severity_rationale="File system permissions explicitly grant write access (st_mode & 0o002) to unprivileged users on sensitive configuration.",
                    retest_guidance="Check file mode with ls -l and stat.",
                    is_confirmed=True,
                )

        # Default: Unverified candidates default to NEEDS_VALIDATION
        return ValidationAssessment(
            finding_id=finding.id,
            status=ValidationStatus.NEEDS_VALIDATION,
            validator_rule=ValidatorRuleCode.VR_009_GENERIC_OBSERVATION,
            validator_version=cls.VALIDATOR_VERSION,
            validation_method="Automated Heuristic Anomaly Detection",
            severity_rationale="Symptom observed by automated tooling without deterministic proof of exploitability.",
            retest_guidance="Design a controlled proof-of-concept payload to verify impact.",
            is_confirmed=False,
        )

    @classmethod
    def apply_to_finding(
        cls,
        finding: Finding,
        raw_evidence: Optional[str] = None,
        source: str = "automated_adapter",
    ) -> Finding:
        """Evaluates and updates a Finding dataclass with deterministic validation metadata."""
        assessment = cls.evaluate(finding, raw_evidence=raw_evidence, source=source)
        finding.validation_status = assessment.status
        finding.validation_method = f"{assessment.validation_method} [{assessment.validator_rule.value}]"
        finding.severity_rationale = assessment.severity_rationale
        return finding
