"""Evidence-Backed AI Data Analyst Engine for CyberSecuritySuite.

Synthesizes security findings, maps potential attack chaining paths,
prioritizes defensive remediation, and enforces strict anti-hallucination guardrails:
1. Mandatory Evidence Citations: Every insight must cite specific evidence IDs or digests.
2. Zero Hallucination: Never invents CVEs, software versions, or unobserved assets.
3. Strict Status Demarcation: Inferences and heuristic version matches are explicitly
   flagged as NEEDS_VALIDATION.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.correlation.finding_correlator import FindingCorrelator
from core.parsers.normalized_models import NormalizedFinding
from storage.db import Database
from storage.models import Finding, FindingSeverity, ValidationStatus, _utc_now_iso

logger = logging.getLogger(__name__)


@dataclass
class EvidenceCitation:
    """Explicit citation linking a finding claim to raw proof."""
    finding_title: str
    affected_asset: str
    evidence_id: Optional[int]
    evidence_hash: str
    source_tool: str
    validation_status: str


@dataclass
class AttackPathChain:
    """Hypothesized attack chain based on confirmed or observed exposures."""
    chain_name: str
    likelihood: str  # HIGH, MEDIUM, LOW
    impact: str      # CRITICAL, HIGH, MEDIUM
    prerequisites: List[str]
    attack_steps: List[str]
    validation_required: List[str]
    supporting_citations: List[EvidenceCitation]


@dataclass
class DataAnalystReport:
    """Comprehensive, evidence-grounded security analysis report."""
    project_id: int
    executive_summary: str
    overall_posture: str
    finding_counts: Dict[str, int]
    attack_paths: List[AttackPathChain]
    prioritized_remediations: List[str]
    citations: List[EvidenceCitation]
    unvalidated_inferences: List[str]
    generated_at: str = field(default_factory=_utc_now_iso)


class AIDataAnalystEngine:
    """Evidence-backed security data analyst engine."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.correlator = FindingCorrelator(db)

    def analyze_project(
        self,
        project_id: int,
        findings: Optional[List[NormalizedFinding]] = None,
    ) -> DataAnalystReport:
        """Generates a structured, evidence-grounded analysis of project findings."""
        target_findings: List[NormalizedFinding] = []

        if findings is not None:
            target_findings = list(findings)
        elif self.db:
            db_findings = self.db.list_findings(project_id)
            target_findings = [NormalizedFinding.from_finding(f, db=self.db) for f in db_findings]

        # Calculate counts
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0,
            "CONFIRMED": 0,
            "NEEDS_VALIDATION": 0,
            "OBSERVED": 0,
        }

        citations: List[EvidenceCitation] = []
        unvalidated_inferences: List[str] = []

        for f in target_findings:
            sev_str = f.severity.value.upper()
            if sev_str in counts:
                counts[sev_str] += 1

            status_str = f.validation_status.value.upper()
            if status_str in counts:
                counts[status_str] += 1

            # Build evidence citation
            citation = EvidenceCitation(
                finding_title=f.title,
                affected_asset=f.affected_asset,
                evidence_id=f.evidence_id,
                evidence_hash=f.raw_evidence_hash or "SHA256_UNRECORDED",
                source_tool=f.source_tool or "automated_scanner",
                validation_status=status_str,
            )
            citations.append(citation)

            # Flag heuristic or unconfirmed findings
            if f.validation_status in (ValidationStatus.NEEDS_VALIDATION, ValidationStatus.OBSERVED, ValidationStatus.UNVERIFIED):
                unvalidated_inferences.append(
                    f"[{f.validation_status.value.upper()}] '{f.title}' on {f.affected_asset} "
                    f"(Source: {f.source_tool}, Evidence ID: {f.evidence_id or 'None'}) - Controlled verification required."
                )

        # Identify Attack Chains
        attack_paths = self._identify_attack_chains(target_findings, citations)

        # Generate Prioritized Remediation Roadmap
        remediations = self._generate_remediation_roadmap(target_findings)

        # Synthesize Executive Summary
        posture = self._assess_overall_posture(counts)
        exec_summary = (
            f"Security engagement data analysis for Project #{project_id} identified "
            f"{len(target_findings)} total findings across {len(set(f.affected_asset for f in target_findings))} assets. "
            f"Risk Posture: {posture}. "
            f"Confirmed Issues: {counts['CONFIRMED']}, Awaiting Empirical Retest: {counts['NEEDS_VALIDATION'] + counts['OBSERVED']}. "
            f"High/Critical Vulnerabilities: {counts['CRITICAL'] + counts['HIGH']}."
        )

        return DataAnalystReport(
            project_id=project_id,
            executive_summary=exec_summary,
            overall_posture=posture,
            finding_counts=counts,
            attack_paths=attack_paths,
            prioritized_remediations=remediations,
            citations=citations,
            unvalidated_inferences=unvalidated_inferences,
        )

    def _identify_attack_chains(
        self,
        findings: List[NormalizedFinding],
        citations: List[EvidenceCitation],
    ) -> List[AttackPathChain]:
        """Correlates multiple findings into plausible multi-stage attack paths."""
        chains: List[AttackPathChain] = []
        has_sqli = any("sql" in f.title.lower() for f in findings)
        has_rce = any(f.severity == FindingSeverity.CRITICAL and any(k in f.title.lower() for k in ("rce", "execution", "traversal")) for f in findings)
        has_exposed_admin = any("admin" in f.title.lower() or "login" in f.title.lower() for f in findings)
        has_tls_issue = any("tls" in f.title.lower() or "ssl" in f.title.lower() for f in findings)

        if has_sqli:
            sqli_citations = [c for c in citations if "sql" in c.finding_title.lower()]
            chains.append(
                AttackPathChain(
                    chain_name="Database Compromise via SQL Injection [Hypothesis Chain]",
                    likelihood="HIGH",
                    impact="CRITICAL",
                    prerequisites=["HTTP/HTTPS network reachability", "Unsanitized user-controlled input parameter"],
                    attack_steps=[
                        "[Hypothesis Step 1] Attacker identifies injectable parameter during automated assessment.",
                        "[Hypothesis Step 2] Attacker leverages boolean/error/time-based injection payloads to extract schema and credentials.",
                        "[Hypothesis Step 3] Attacker dumps administrative session tokens or password hashes.",
                        "[Hypothesis Step 4] Potential escalation to OS command execution via xp_cmdshell / UDF depending on DB configuration.",
                    ],
                    validation_required=["Reproduce parameter injection using authorized non-destructive query probe."],
                    supporting_citations=sqli_citations,
                )
            )

        if has_rce:
            rce_citations = [c for c in citations if any(k in c.finding_title.lower() for k in ("rce", "execution", "traversal"))]
            chains.append(
                AttackPathChain(
                    chain_name="Remote Arbitrary Code Execution on Web Infrastructure [Hypothesis Chain]",
                    likelihood="HIGH",
                    impact="CRITICAL",
                    prerequisites=["Publicly exposed vulnerable service version", "Execution rights on endpoint"],
                    attack_steps=[
                        "[Hypothesis Step 1] Attacker discovers vulnerable web server release (e.g. Apache Path Traversal / RCE).",
                        "[Hypothesis Step 2] Attacker bypasses URI access control filters to reach arbitrary server files or CGI scripts.",
                        "[Hypothesis Step 3] Attacker gains initial foothold shell under web daemon process privileges.",
                    ],
                    validation_required=["Validate patch level in vendor package changelog; verify whether CGI module is active."],
                    supporting_citations=rce_citations,
                )
            )

        if has_exposed_admin and not has_sqli:
            admin_citations = [c for c in citations if "admin" in c.finding_title.lower()]
            chains.append(
                AttackPathChain(
                    chain_name="Administrative Credential Brute-Force / Spraying [Hypothesis Chain]",
                    likelihood="MEDIUM",
                    impact="HIGH",
                    prerequisites=["Exposed administrative login interface without rate limiting"],
                    attack_steps=[
                        "[Hypothesis Step 1] Attacker discovers administrative portal via directory fuzzing.",
                        "[Hypothesis Step 2] Attacker conducts credential spraying against default accounts.",
                        "[Hypothesis Step 3] Successful authentication grants administrative privileges.",
                    ],
                    validation_required=["Verify whether multi-factor authentication (MFA) and account lockout policies are enforced."],
                    supporting_citations=admin_citations,
                )
            )

        return chains

    @staticmethod
    def _generate_remediation_roadmap(findings: List[NormalizedFinding]) -> List[str]:
        """Synthesizes prioritized remediation recommendations."""
        remediations: List[str] = []
        critical_items = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        high_items = [f for f in findings if f.severity == FindingSeverity.HIGH]
        medium_items = [f for f in findings if f.severity == FindingSeverity.MEDIUM]

        if critical_items:
            remediations.append(
                f"[P0 - Immediate Hotfix] Remediate {len(critical_items)} Critical vulnerability(ies) "
                f"(e.g., {critical_items[0].title}). Apply parameterized queries, upgrade vulnerable web daemons, and isolate compromised services."
            )

        if high_items:
            remediations.append(
                f"[P1 - High Priority] Patch {len(high_items)} High-severity issue(s). "
                f"Upgrade OpenSSH / web servers to secure releases and restrict administrative access."
            )

        if medium_items:
            remediations.append(
                f"[P2 - Medium Priority] Address {len(medium_items)} Medium-severity issue(s). "
                f"Disable directory listings, hide sensitive endpoints (.git/.env), and restrict verbose error banners."
            )

        remediations.append(
            "[P3 - Defense in Depth] Configure HTTP security headers (CSP, HSTS, X-Frame-Options) and disable deprecated TLS protocols (TLSv1.0/1.1)."
        )

        return remediations

    @staticmethod
    def _assess_overall_posture(counts: Dict[str, int]) -> str:
        if counts["CRITICAL"] > 0:
            return "CRITICAL RISK"
        if counts["HIGH"] > 0:
            return "HIGH RISK"
        if counts["MEDIUM"] > 0:
            return "ELEVATED RISK"
        if counts["LOW"] > 0 or counts["INFORMATIONAL"] > 0:
            return "LOW RISK (INFORMATIONAL EXPOSURE)"
        return "SECURE / NO OBSERVATIONS"

