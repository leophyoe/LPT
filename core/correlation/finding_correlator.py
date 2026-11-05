"""Cross-Tool Finding Correlation and Deduplication Engine.

Intelligently correlates findings produced by multiple independent tools (e.g. Nmap,
Nikto, SQLMap, Gobuster) without fragile fuzzy matching. Preserves multi-tool provenance,
corroborating evidence digests, and CVE/CWE linkages.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.parsers.normalized_models import NormalizedFinding
from storage.db import Database
from storage.models import Finding, FindingSeverity, ValidationStatus, _utc_now_iso

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFindingGroup:
    """Group of findings from one or more tools representing the same root vulnerability."""
    correlation_key: str
    primary_finding: NormalizedFinding
    corroborating_findings: List[NormalizedFinding] = field(default_factory=list)
    source_tools: Set[str] = field(default_factory=set)
    evidence_ids: Set[int] = field(default_factory=set)
    execution_ids: Set[int] = field(default_factory=set)
    cve_ids: Set[str] = field(default_factory=set)
    cwe_ids: Set[str] = field(default_factory=set)


class FindingCorrelator:
    """Correlates and deduplicates security findings across multiple assessment tools."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    @classmethod
    def canonical_vuln_category(cls, finding: NormalizedFinding) -> str:
        """Derives a canonical vulnerability signature category from finding attributes."""
        title = (finding.title or "").lower()
        desc = (finding.description or "").lower()
        cwe = (finding.cwe_id or "").upper()

        # 1. Overlapping CVE is the strongest signature
        if finding.cve_ids:
            return f"cve:{sorted(finding.cve_ids)[0].upper()}"

        # 2. Specific vulnerability patterns
        if "sql injection" in title or "sqli" in title or cwe == "CWE-89":
            # Preserve target parameter if present
            param_match = re.search(r"parameter\s*['\"]?([a-zA-Z0-9_\-]+)", title + " " + desc)
            param = f":{param_match.group(1).lower()}" if param_match else ""
            return f"sql_injection{param}"

        if any(w in title for w in ("cross-site scripting", "cross site scripting", "xss")) or cwe == "CWE-79":
            return "cross_site_scripting"

        if any(w in title or w in desc for w in ("ssl-enum-ciphers", "sslv3", "tlsv1.0", "tlsv1.1", "weak cipher")):
            return "tls_weak_cipher_or_deprecated_protocol"

        if "directory indexing" in title or "directory listing" in title or "osvdb-3268" in desc:
            return "directory_indexing"

        if "web application firewall" in title or "waf" in title:
            if "detected" in title:
                return "waf_detected"
            return "waf_not_detected"

        if any(w in title for w in ("missing security header", "x-frame-options", "content-security-policy", "strict-transport-security")):
            return "missing_security_headers"

        if ".git" in title or ".env" in title:
            return "sensitive_source_control_or_env_exposure"

        if "admin" in title and ("portal" in title or "login" in title):
            return "admin_portal_exposure"

        # 3. Fallback: normalize title words excluding common tool prefixes
        cleaned_title = re.sub(r"^(nmap|nikto|gobuster|ffuf|sqlmap|wafw00f)[:\s\-]+", "", title).strip()
        words = re.findall(r"[a-z0-9]+", cleaned_title)[:4]
        return f"generic:{'_'.join(words)}"

    @classmethod
    def generate_correlation_key(cls, finding: NormalizedFinding) -> str:
        """Generates a composite correlation key: (affected_asset, port, canonical_category)."""
        asset = (finding.affected_asset or "").strip().lower()
        # Normalize asset: strip protocol if present
        if "://" in asset:
            asset = asset.split("://", 1)[1]
        asset = asset.rstrip("/")

        port_str = str(finding.port) if finding.port is not None else (finding.affected_service or "any")
        category = cls.canonical_vuln_category(finding)

        return f"{asset}|{port_str}|{category}"

    def correlate_findings(
        self,
        findings: List[NormalizedFinding],
    ) -> List[NormalizedFinding]:
        """Deduplicates and correlates an in-memory list of findings across tools."""
        if not findings:
            return []

        groups: Dict[str, CorrelatedFindingGroup] = {}

        for f in findings:
            key = self.generate_correlation_key(f)
            if key not in groups:
                group = CorrelatedFindingGroup(
                    correlation_key=key,
                    primary_finding=f,
                    corroborating_findings=[],
                )
                if f.source_tool:
                    group.source_tools.add(f.source_tool)
                if f.evidence_id:
                    group.evidence_ids.add(f.evidence_id)
                if f.execution_id:
                    group.execution_ids.add(f.execution_id)
                for cve in f.cve_ids:
                    group.cve_ids.add(cve)
                if f.cwe_id:
                    group.cwe_ids.add(f.cwe_id)
                groups[key] = group
            else:
                group = groups[key]
                group.corroborating_findings.append(f)
                if f.source_tool:
                    group.source_tools.add(f.source_tool)
                if f.evidence_id:
                    group.evidence_ids.add(f.evidence_id)
                if f.execution_id:
                    group.execution_ids.add(f.execution_id)
                for cve in f.cve_ids:
                    group.cve_ids.add(cve)
                if f.cwe_id:
                    group.cwe_ids.add(f.cwe_id)

                # Prioritize higher severity as primary representation
                if self._severity_weight(f.severity) > self._severity_weight(group.primary_finding.severity):
                    group.corroborating_findings.append(group.primary_finding)
                    group.primary_finding = f

        # Synthesize correlated findings
        correlated_results: List[NormalizedFinding] = []
        for group in groups.values():
            merged = self._merge_finding_group(group)
            correlated_results.append(merged)

        return correlated_results

    @classmethod
    def _merge_finding_group(cls, group: CorrelatedFindingGroup) -> NormalizedFinding:
        """Merges corroborating findings into a unified, evidence-rich finding."""
        primary = group.primary_finding
        if not group.corroborating_findings:
            return primary

        # Calculate corroborated confidence
        all_confidences = [primary.confidence] + [f.confidence for f in group.corroborating_findings]
        corroborated_confidence = min(1.0, max(all_confidences) + (0.05 * len(group.source_tools) if len(group.source_tools) > 1 else 0.0))

        # Select highest severity
        all_severities = [primary.severity] + [f.severity for f in group.corroborating_findings]
        max_sev = max(all_severities, key=cls._severity_weight)

        # Merge descriptions with cross-tool corroboration section
        sources_str = ", ".join(sorted(group.source_tools))
        corroboration_note = (
            f"\n\n[Cross-Tool Corroboration]\n"
            f"Vulnerability verified across {len(group.source_tools)} tool(s): {sources_str}.\n"
            f"Corroborating Evidence IDs: {', '.join(str(e) for e in sorted(group.evidence_ids)) or 'N/A'}"
        )

        merged_description = primary.description
        corroborating_descs = [f.description for f in group.corroborating_findings if f.description and f.description != primary.description]
        if corroborating_descs:
            merged_description += "\n\n[Corroborating Tool Observations]\n" + "\n".join(f"- {d}" for d in corroborating_descs)
        if corroboration_note not in merged_description:
            merged_description += corroboration_note

        # Promote validation status if confirmed by any tool
        val_status = primary.validation_status
        if any(f.validation_status == ValidationStatus.CONFIRMED for f in [primary] + group.corroborating_findings):
            val_status = ValidationStatus.CONFIRMED
        elif any(f.validation_status == ValidationStatus.NEEDS_VALIDATION for f in [primary] + group.corroborating_findings):
            val_status = ValidationStatus.NEEDS_VALIDATION

        # Best CVSS
        all_cvss = [f.cvss_score for f in [primary] + group.corroborating_findings if f.cvss_score is not None]
        best_cvss = max(all_cvss, default=None)

        return NormalizedFinding(
            title=primary.title,
            severity=max_sev,
            affected_asset=primary.affected_asset,
            affected_service=primary.affected_service,
            port=primary.port,
            protocol=primary.protocol,
            cve_ids=sorted(group.cve_ids),
            cvss_score=best_cvss,
            cvss_vector=primary.cvss_vector,
            cwe_id=sorted(group.cwe_ids)[0] if group.cwe_ids else primary.cwe_id,
            description=merged_description,
            reproduction_steps=primary.reproduction_steps,
            remediation=primary.remediation,
            evidence_id=primary.evidence_id or (min(group.evidence_ids) if group.evidence_ids else None),
            execution_id=primary.execution_id or (min(group.execution_ids) if group.execution_ids else None),
            raw_evidence_hash=primary.raw_evidence_hash,
            source_tool=sources_str,
            confidence=corroborated_confidence,
            validation_status=val_status,
            validation_method=f"Corroborated by {sources_str}",
            severity_rationale=f"Multi-tool consensus ({len(group.source_tools)} sources)",
            timestamp=primary.timestamp or _utc_now_iso(),
        )

    @staticmethod
    def _severity_weight(sev: FindingSeverity) -> int:
        weights = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFORMATIONAL: 1,
        }
        return weights.get(sev, 0)
