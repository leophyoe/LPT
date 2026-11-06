"""Normalized Data Models for Universal Parser Architecture.

Defines standardized representations of security findings, discovered services,
and parser execution results across all security tooling in CyberSecuritySuite.
Enforces strict evidence provenance, reproducibility, and auditability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from storage.models import (
    Finding,
    FindingSeverity,
    ValidationStatus,
    _utc_now_iso,
)


@dataclass
class NormalizedService:
    """Standardized representation of an open or inspected network service."""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    banner: str = ""
    cpe_list: List[str] = field(default_factory=list)
    confidence: float = 1.0
    source_tool: str = ""
    state: str = "open"
    scripts: Dict[str, str] = field(default_factory=dict)

    @property
    def service_summary(self) -> str:
        parts = [self.service_name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(filter(None, parts)) or f"Port {self.port}/{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "banner": self.banner,
            "cpe_list": self.cpe_list,
            "confidence": self.confidence,
            "source_tool": self.source_tool,
            "state": self.state,
            "scripts": self.scripts,
        }


@dataclass
class NormalizedFinding:
    """Standardized representation of a security observation or finding.

    Strict provenance tracking: every finding maintains its link to raw evidence,
    execution record, source tool, and cryptographic digest.
    """
    title: str
    severity: FindingSeverity
    affected_asset: str
    affected_service: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str = ""
    reproduction_steps: str = ""
    remediation: str = ""
    evidence_id: Optional[int] = None
    execution_id: Optional[int] = None
    raw_evidence_hash: str = ""
    source_tool: str = ""
    confidence: float = 1.0
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    validation_method: str = ""
    severity_rationale: str = ""
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_finding(self, project_id: int, assessment_id: Optional[int] = None) -> Finding:
        """Converts this normalized representation into a persistent storage Finding model."""
        affected_port_service = self.affected_service
        if not affected_port_service and self.port is not None:
            affected_port_service = f"{self.port}/{self.protocol}"

        desc = self.description
        if self.cve_ids and not any(cve in desc for cve in self.cve_ids):
            desc += f"\n\nAssociated CVEs: {', '.join(self.cve_ids)}"
        if self.cwe_id and self.cwe_id not in desc:
            desc += f"\nCWE: {self.cwe_id}"

        return Finding(
            project_id=project_id,
            title=self.title,
            severity=self.severity,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector,
            affected_asset=self.affected_asset,
            affected_port_service=affected_port_service,
            description=desc.strip(),
            reproduction_steps=self.reproduction_steps,
            remediation=self.remediation,
            validation_status=self.validation_status,
            source_tool=self.source_tool,
            execution_id=self.execution_id,
            validation_method=self.validation_method,
            severity_rationale=self.severity_rationale,
            confidence=self.confidence,
            assessment_id=assessment_id,
        )

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        raw_evidence_hash: str = "",
        db: Optional[Any] = None,
        evidence: Optional[Any] = None,
    ) -> NormalizedFinding:
        """Constructs a NormalizedFinding from an existing storage Finding."""
        port = None
        protocol = "tcp"
        if finding.affected_port_service:
            parts = finding.affected_port_service.split("/")
            if parts and parts[0].isdigit():
                port = int(parts[0])
            if len(parts) > 1 and parts[1].isalpha():
                protocol = parts[1].lower()

        ev_id = None
        ev_hash = ""

        # Evidence identifiers and digests are trusted only when backed by a linked record.
        if evidence is not None:
            ev = evidence
        elif db is not None:
            ev = None
            pid = finding.project_id
            requested_ev_id = getattr(finding, "evidence_id", None)
            if requested_ev_id and hasattr(db, "get_evidence"):
                ev = db.get_evidence(requested_ev_id, project_id=pid)
            if not ev and getattr(finding, "id", None) and hasattr(db, "get_evidence_for_finding"):
                ev = db.get_evidence_for_finding(finding.id, project_id=pid)
        else:
            ev = None

        evidence_id = getattr(ev, "id", None) if ev is not None else None
        finding_id = getattr(finding, "id", None)
        evidence_finding_id = getattr(ev, "finding_id", None) if ev is not None else None
        evidence_execution_id = getattr(ev, "execution_id", None) if ev is not None else None
        finding_execution_id = getattr(finding, "execution_id", None)
        is_linked = (
            (
                finding_id is not None
                and evidence_finding_id == finding_id
            )
            or getattr(finding, "evidence_id", None) == evidence_id
            or (
                finding_execution_id is not None
                and evidence_execution_id == finding_execution_id
            )
        )
        if (
            ev is not None
            and getattr(ev, "project_id", None) == finding.project_id
            and type(evidence_id) is int
            and evidence_id > 0
            and is_linked
            and (
                evidence_finding_id is None
                or evidence_finding_id == finding_id
            )
            and (
                evidence_execution_id is None
                or finding_execution_id is None
                or evidence_execution_id == finding_execution_id
            )
        ):
            ev_id = ev.id
            candidate_hash = (
                getattr(ev, "sha256_hash", "")
                or getattr(ev, "file_hash", "")
                or raw_evidence_hash
                or ""
            )
            if isinstance(candidate_hash, str) and re.fullmatch(r"[0-9a-fA-F]{64}", candidate_hash):
                ev_hash = candidate_hash.lower()

        return cls(
            title=finding.title,
            severity=finding.severity,
            affected_asset=finding.affected_asset,
            affected_service=finding.affected_port_service,
            port=port,
            protocol=protocol,
            cvss_score=finding.cvss_score,
            cvss_vector=finding.cvss_vector,
            description=finding.description,
            reproduction_steps=finding.reproduction_steps,
            remediation=finding.remediation,
            evidence_id=ev_id,
            execution_id=finding.execution_id,
            raw_evidence_hash=ev_hash,
            source_tool=finding.source_tool,
            confidence=finding.confidence,
            validation_status=finding.validation_status,
            validation_method=finding.validation_method,
            severity_rationale=finding.severity_rationale,
            timestamp=finding.created_at or _utc_now_iso(),
        )


@dataclass
class NormalizedParserResult:
    """Consolidated outcome of parsing tool output."""
    tool_name: str
    target: str
    command_args: str = ""
    services: List[NormalizedService] = field(default_factory=list)
    findings: List[NormalizedFinding] = field(default_factory=list)
    raw_evidence_hash: str = ""
    raw_output: str = ""
    parser_warnings: List[str] = field(default_factory=list)
    success: bool = True

    def __iter__(self):
        return iter((self.findings, self.services))
