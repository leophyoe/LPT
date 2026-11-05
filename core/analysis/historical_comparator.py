"""Historical Scan Comparison and Vulnerability Delta Engine.

Compares findings across consecutive executions or assessments within the same project.
Accurately categorizes findings into NEW, PERSISTENT/RECURRING, RESOLVED/CLOSED, and CHANGED.
Calculates risk posture trajectory (Improving, Degrading, Stable).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from core.correlation.finding_correlator import FindingCorrelator
from core.parsers.normalized_models import NormalizedFinding
from storage.db import Database
from storage.models import Finding, FindingSeverity, ValidationStatus

logger = logging.getLogger(__name__)


class FindingDeltaStatus(str, Enum):
    NEW = "NEW"
    PERSISTENT = "PERSISTENT"
    RESOLVED = "RESOLVED"
    CHANGED = "CHANGED"


@dataclass
class FindingDeltaItem:
    """Represents a finding in relation to historical scan baseline."""
    delta_status: FindingDeltaStatus
    current_finding: Optional[NormalizedFinding] = None
    prior_finding: Optional[NormalizedFinding] = None
    change_summary: str = ""


@dataclass
class ScanDeltaReport:
    """Comprehensive comparison report between baseline and current scan."""
    project_id: int
    baseline_execution_id: Optional[int]
    current_execution_id: Optional[int]
    new_findings: List[NormalizedFinding] = field(default_factory=list)
    persistent_findings: List[NormalizedFinding] = field(default_factory=list)
    resolved_findings: List[NormalizedFinding] = field(default_factory=list)
    changed_findings: List[FindingDeltaItem] = field(default_factory=list)
    prior_risk_score: float = 0.0
    current_risk_score: float = 0.0
    risk_delta: float = 0.0
    risk_trend: str = "STABLE"  # IMPROVING, DEGRADING, STABLE

    @property
    def total_active_current(self) -> int:
        return len(self.new_findings) + len(self.persistent_findings) + len(self.changed_findings)


class HistoricalComparator:
    """Performs deterministic comparison of findings across assessment executions."""

    SEVERITY_WEIGHTS = {
        FindingSeverity.CRITICAL: 10.0,
        FindingSeverity.HIGH: 7.0,
        FindingSeverity.MEDIUM: 4.0,
        FindingSeverity.LOW: 2.0,
        FindingSeverity.INFORMATIONAL: 0.5,
    }

    def __init__(self, db: Optional[Database] = None):
        self.db = db
        self.correlator = FindingCorrelator(db)

    def calculate_risk_score(self, findings: List[NormalizedFinding]) -> float:
        """Computes aggregate risk score weighted by severity and CVSS."""
        score = 0.0
        for f in findings:
            if f.validation_status == ValidationStatus.FALSE_POSITIVE:
                continue
            base = self.SEVERITY_WEIGHTS.get(f.severity, 1.0)
            multiplier = (f.cvss_score / 5.0) if f.cvss_score else 1.0
            score += base * multiplier
        return round(score, 2)

    def compare_executions(
        self,
        project_id: int,
        prior_findings: List[NormalizedFinding],
        current_findings: List[NormalizedFinding],
        prior_execution_id: Optional[int] = None,
        current_execution_id: Optional[int] = None,
        rescanned_assets: Optional[Set[str]] = None,
        scan_successful: bool = True,
    ) -> ScanDeltaReport:
        """Compares prior findings with current findings and classifies each finding."""
        # Index prior findings by correlation key
        prior_by_key: Dict[str, NormalizedFinding] = {}
        for pf in prior_findings:
            key = self.correlator.generate_correlation_key(pf)
            prior_by_key[key] = pf

        current_by_key: Dict[str, NormalizedFinding] = {}
        for cf in current_findings:
            key = self.correlator.generate_correlation_key(cf)
            current_by_key[key] = cf

        new_items: List[NormalizedFinding] = []
        persistent_items: List[NormalizedFinding] = []
        changed_items: List[FindingDeltaItem] = []
        resolved_items: List[NormalizedFinding] = []

        # Evaluate current findings
        for key, cf in current_by_key.items():
            if key not in prior_by_key:
                new_items.append(cf)
            else:
                pf = prior_by_key[key]
                changes = self._detect_changes(pf, cf)
                if changes:
                    changed_items.append(
                        FindingDeltaItem(
                            delta_status=FindingDeltaStatus.CHANGED,
                            current_finding=cf,
                            prior_finding=pf,
                            change_summary="; ".join(changes),
                        )
                    )
                else:
                    persistent_items.append(cf)

        # Evaluate prior findings for resolved items
        # Guard: Incomplete, failed, or unverified empty scans must NEVER mark findings as resolved!
        for key, pf in prior_by_key.items():
            if key not in current_by_key:
                if not scan_successful:
                    persistent_items.append(pf)
                    continue

                asset = (pf.affected_asset or "").strip().lower()
                if not current_findings and not rescanned_assets:
                    # Empty scan output without explicitly confirmed target scope cannot verify remediation
                    persistent_items.append(pf)
                    continue

                if rescanned_assets is not None:
                    if any(a.lower() in asset for a in rescanned_assets):
                        resolved_items.append(pf)
                    else:
                        # Asset was not rescanned in this run, keep as persistent
                        persistent_items.append(pf)
                else:
                    resolved_items.append(pf)

        prior_score = self.calculate_risk_score(prior_findings)
        curr_score = self.calculate_risk_score(current_findings)
        risk_delta = round(curr_score - prior_score, 2)

        if risk_delta < -1.0:
            trend = "IMPROVING"
        elif risk_delta > 1.0:
            trend = "DEGRADING"
        else:
            trend = "STABLE"

        return ScanDeltaReport(
            project_id=project_id,
            baseline_execution_id=prior_execution_id,
            current_execution_id=current_execution_id,
            new_findings=new_items,
            persistent_findings=persistent_items,
            resolved_findings=resolved_items,
            changed_findings=changed_items,
            prior_risk_score=prior_score,
            current_risk_score=curr_score,
            risk_delta=risk_delta,
            risk_trend=trend,
        )

    @staticmethod
    def _detect_changes(prior: NormalizedFinding, current: NormalizedFinding) -> List[str]:
        """Detects meaningful changes between two instances of a finding."""
        changes: List[str] = []
        if prior.severity != current.severity:
            changes.append(f"Severity changed from {prior.severity.value} to {current.severity.value}")
        if prior.cvss_score != current.cvss_score:
            changes.append(f"CVSS score changed from {prior.cvss_score} to {current.cvss_score}")
        if prior.validation_status != current.validation_status:
            changes.append(f"Validation status changed from {prior.validation_status.value} to {current.validation_status.value}")
        if set(prior.cve_ids) != set(current.cve_ids):
            added_cves = set(current.cve_ids) - set(prior.cve_ids)
            if added_cves:
                changes.append(f"New associated CVEs: {', '.join(added_cves)}")
        return changes

