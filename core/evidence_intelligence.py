"""Evidence Intelligence and Cryptographic Provenance Service.

Enforces strict empirical evidence linking for all findings in CyberSecuritySuite:
1. Every candidate finding must trace back to a vaulted raw output artifact.
2. Invariant: "Zero unbacked confirmed findings":
   A finding cannot possess ValidationStatus.CONFIRMED without a verified evidence
   record possessing matching SHA-256 digest and reproducible tool execution context.
3. Automatically audits, verifies, and reconciles evidence integrity across projects.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from storage.db import Database
from storage.models import (
    Evidence,
    Finding,
    ValidationStatus,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


@dataclass
class EvidenceVerificationResult:
    """Outcome of verifying evidence integrity and finding provenance."""
    is_valid: bool
    status_message: str
    finding_id: Optional[int] = None
    evidence_id: Optional[int] = None
    expected_sha256: str = ""
    actual_sha256: str = ""
    file_path: str = ""
    evidence: Optional[Evidence] = None


class EvidenceIntelligenceService:
    """Manages evidence vaulting, cryptographic hashing, and finding linkage."""

    def __init__(self, db: Database):
        self.db = db

    @classmethod
    def calculate_sha256(cls, content: Union[str, bytes]) -> str:
        """Computes SHA-256 digest of string or raw bytes."""
        if isinstance(content, str):
            data = content.encode("utf-8")
        else:
            data = content or b""
        return hashlib.sha256(data).hexdigest()

    def verify_finding_evidence(
        self,
        finding: Finding,
        project_id: Optional[int] = None,
    ) -> EvidenceVerificationResult:
        """Verifies that a finding is backed by an authentic, un-tampered evidence record."""
        pid = project_id if project_id is not None else finding.project_id
        fid = finding.id

        evidence: Optional[Evidence] = None

        # 1. Look up by in-memory evidence_id if attached
        ev_id = getattr(finding, "evidence_id", None)
        if ev_id:
            evidence = self.db.get_evidence(ev_id, project_id=pid)
            if not evidence:
                return EvidenceVerificationResult(
                    is_valid=False,
                    status_message=f"Evidence ID #{ev_id} not found in project #{pid} (cross-project access rejected or missing record).",
                    finding_id=fid,
                    evidence_id=ev_id,
                )

        # 2. Look up via database relationship (finding_id or execution_id)
        if not evidence and fid:
            evidence = self.db.get_evidence_for_finding(fid, project_id=pid)

        # 3. Look up via execution_id directly if present on finding
        if not evidence and finding.execution_id:
            ev_list = self.db.list_evidence(pid)
            for ev in ev_list:
                if ev.execution_id == finding.execution_id:
                    evidence = ev
                    break

        if not evidence:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"No supporting evidence artifact found in database for finding #{fid or 'new'}.",
                finding_id=fid,
            )

        # Verify project isolation
        if evidence.project_id != pid:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"Cross-project evidence rejection: finding in project #{pid}, evidence in project #{evidence.project_id}.",
                finding_id=fid,
                evidence_id=evidence.id,
                evidence=evidence,
            )

        # Verify execution linkage if both specify execution_id
        if finding.execution_id and evidence.execution_id and finding.execution_id != evidence.execution_id:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"Evidence execution mismatch: finding specifies execution #{finding.execution_id}, evidence specifies execution #{evidence.execution_id}.",
                finding_id=fid,
                evidence_id=evidence.id,
                evidence=evidence,
            )

        # 4. Verify file exists on disk
        file_path = Path(evidence.file_path)
        if not file_path.is_absolute():
            repo_root = Path(__file__).resolve().parent.parent
            candidate = repo_root / file_path
            if candidate.exists():
                file_path = candidate

        if not file_path.exists():
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"Evidence file missing on disk: {evidence.file_path}",
                finding_id=fid,
                evidence_id=evidence.id,
                file_path=str(file_path),
                evidence=evidence,
            )

        # 5. Compute and compare SHA-256 digest
        expected_hash = (evidence.sha256_hash or evidence.file_hash or "").strip().lower()
        if not expected_hash:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message="Evidence record lacks expected SHA-256 hash.",
                finding_id=fid,
                evidence_id=evidence.id,
                file_path=str(file_path),
                evidence=evidence,
            )

        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            actual_hash = hasher.hexdigest().lower()
        except Exception as e:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"Failed to read evidence file: {e}",
                finding_id=fid,
                evidence_id=evidence.id,
                file_path=str(file_path),
                evidence=evidence,
            )

        if actual_hash != expected_hash:
            return EvidenceVerificationResult(
                is_valid=False,
                status_message=f"Evidence digest mismatch (Tampered or modified). Expected {expected_hash}, calculated {actual_hash}.",
                finding_id=fid,
                evidence_id=evidence.id,
                expected_sha256=expected_hash,
                actual_sha256=actual_hash,
                file_path=str(file_path),
                evidence=evidence,
            )

        return EvidenceVerificationResult(
            is_valid=True,
            status_message="Evidence cryptographically verified and intact.",
            finding_id=fid,
            evidence_id=evidence.id,
            expected_sha256=expected_hash,
            actual_sha256=actual_hash,
            file_path=str(file_path),
            evidence=evidence,
        )

    def enforce_confirmed_evidence_guard(
        self,
        finding: Finding,
        project_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Enforces the 'Zero unbacked confirmed findings' policy.

        If a finding is claimed as CONFIRMED, this method verifies its evidence.
        If verification fails, it downgrades the validation status to NEEDS_VALIDATION.

        Returns (was_allowed, explanation).
        """
        pid = project_id if project_id is not None else finding.project_id
        if finding.validation_status != ValidationStatus.CONFIRMED:
            return True, "Finding is not marked CONFIRMED; no downgrade necessary."

        verification = self.verify_finding_evidence(finding, project_id=pid)
        if not verification.is_valid:
            finding.validation_status = ValidationStatus.NEEDS_VALIDATION
            finding.severity_rationale = (
                f"[UNBACKED DOWNGRADE] Status downgraded to NEEDS_VALIDATION because: {verification.status_message}"
            )
            logger.warning(
                "Downgraded finding '%s' (#%s) to NEEDS_VALIDATION: %s",
                finding.title,
                finding.id,
                verification.status_message,
            )
            return False, verification.status_message

        return True, "Finding has verified evidence backing."

    def link_evidence_to_findings(
        self,
        evidence_id: int,
        findings: List[Finding],
    ):
        """Attaches evidence_id to a collection of in-memory findings."""
        for f in findings:
            setattr(f, "evidence_id", evidence_id)

