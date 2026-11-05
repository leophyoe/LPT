"""Core domain models for CyberSecuritySuite.

Defines dataclasses for Projects, Target Scopes, Tool Executions,
Security Findings, and Evidence records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectStatus(str, Enum):
    DRAFT = "draft"
    AWAITING_APPROVAL = "awaiting_approval"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    PAUSED = "paused"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ScopeRuleType(str, Enum):
    ALLOWED = "allowed"
    EXCLUDED = "excluded"


class TargetType(str, Enum):
    IP_ADDRESS = "ip_address"
    CIDR_RANGE = "cidr_range"
    HOSTNAME = "hostname"
    URL = "url"
    ASN = "asn"
    APPLICATION = "application"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ValidationStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    OBSERVED = "observed"
    NEEDS_VALIDATION = "needs_validation"
    REMEDIATED = "remediated"
    UNVERIFIED = "unverified"


class AssessmentStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    DRAFT = "draft"
    PREFLIGHT_PASSED = "preflight_passed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class TestCategory(str, Enum):
    __test__ = False
    NETWORK_DISCOVERY = "network_discovery"
    ACTIVE_DIRECTORY = "active_directory"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEB_APPLICATION = "web_application"
    BINARY_EXPLOITATION = "binary_exploitation"


@dataclass
class Project:
    name: str
    id: Optional[int] = None
    client_name: str = ""
    description: str = ""
    status: ProjectStatus = ProjectStatus.ACTIVE
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    # Engagement Management & Legal RoE metadata
    engagement_id: str = ""
    lead_tester: str = ""
    authorized_contact: str = ""
    emergency_contact: str = ""
    sow_reference: str = ""
    authorization_doc: str = ""
    start_date: str = ""
    end_date: str = ""
    timezone: str = "UTC"
    allowed_hours: str = ""
    max_rate_limit: int = 100
    allow_active_recon: bool = False
    prohibited_tests: str = "DoS/DDoS, Social Engineering, Physical Intrusion, Account Lockout Brute Force"


@dataclass
class TargetScope:
    project_id: int
    target: str
    id: Optional[int] = None
    target_type: TargetType = TargetType.IP_ADDRESS
    is_authorized: bool = True
    notes: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    rule_type: ScopeRuleType = ScopeRuleType.ALLOWED
    environment: str = "production"
    ports_allowed: str = ""
    expires_at: Optional[str] = None
    effective_from: Optional[str] = None


@dataclass
class EngagementAuditLog:
    project_id: int
    action: str
    actor: str = "security_lead"
    details: str = ""
    id: Optional[int] = None
    timestamp: str = field(default_factory=_utc_now_iso)


@dataclass
class AssetNode:
    project_id: int
    node_type: str  # domain, subdomain, ip, asn, netblock, dns_record, cert
    value: str
    label: str = ""
    source_tool: str = ""
    confidence: float = 1.0
    metadata_json: str = "{}"
    id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class AssetEdge:
    project_id: int
    source_node_id: int
    target_node_id: int
    relation_type: str  # RESOLVES_TO, SUBDOMAIN_OF, PART_OF_NETBLOCK, BELONGS_TO_ASN, HAS_CERTIFICATE, COMMUNICATES_WITH, ROUTED_VIA
    source_tool: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)
    verification_state: str = "observed"  # observed, inferred, manual
    confidence: float = 1.0  # Operational evidence-strength value (1.0 active probe, 0.85 packet flow, 0.7 cache, 0.5 inferred)
    evidence_id: Optional[int] = None
    last_seen: str = ""
    metadata_json: str = "{}"


@dataclass
class ToolExecution:
    project_id: int
    tool_name: str
    command: str
    id: Optional[int] = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    exit_code: Optional[int] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    raw_output_path: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)
    assessment_id: Optional[int] = None


@dataclass
class Finding:
    project_id: int
    title: str
    id: Optional[int] = None
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_asset: str = ""
    affected_port_service: str = ""
    description: str = ""
    reproduction_steps: str = ""
    remediation: str = ""
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    source_tool: str = ""
    execution_id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)
    affected_target: Optional[str] = None
    validation_method: str = ""
    severity_rationale: str = ""
    confidence: float = 1.0
    assessment_id: Optional[int] = None
    updated_at: str = field(default_factory=_utc_now_iso)

    def __post_init__(self):
        if self.affected_target and not self.affected_asset:
            self.affected_asset = self.affected_target

    @property
    def status(self) -> str:
        return self.validation_status.value if hasattr(self.validation_status, "value") else str(self.validation_status)

    @status.setter
    def status(self, val: Any):
        if isinstance(val, ValidationStatus):
            self.validation_status = val
        else:
            try:
                self.validation_status = ValidationStatus(str(val).lower())
            except ValueError:
                self.validation_status = ValidationStatus.UNVERIFIED


@dataclass
class Evidence:
    project_id: int
    file_path: str
    sha256_hash: str = ""
    id: Optional[int] = None
    finding_id: Optional[int] = None
    execution_id: Optional[int] = None
    description: str = ""
    mime_type: str = "text/plain"
    file_hash: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)
    assessment_id: Optional[int] = None

    def __post_init__(self):
        if not self.sha256_hash and self.file_hash:
            self.sha256_hash = self.file_hash
        elif not self.file_hash and self.sha256_hash:
            self.file_hash = self.sha256_hash


@dataclass
class TerminalSessionRecord:
    session_id: str
    project_id: int
    id: Optional[int] = None
    started_at: str = field(default_factory=_utc_now_iso)
    ended_at: Optional[str] = None
    working_directory: str = ""
    exit_status: Optional[int] = None
    raw_output_path: Optional[str] = None
    plain_text_path: Optional[str] = None
    sha256_hash: str = ""
    evidence_id: Optional[int] = None
    execution_id: Optional[int] = None
    command_count: int = 0
    commands_json: str = "[]"
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class OSINTCase:
    project_id: int
    title: str
    target_domain: str
    objective: str = "External Attack Surface & Passive Intelligence"
    authorization_reference: str = ""
    status: str = "active"  # draft, active, completed, archived
    analyst_notes: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class Observation:
    project_id: int
    title: str
    case_id: Optional[int] = None
    asset_id: Optional[int] = None
    source_tool: str = ""
    method: str = "passive"  # passive_dns, cert_transparency, whois, web_archive, amass_enum
    raw_data: str = ""
    confidence: float = 1.0
    verification_status: str = "unverified"  # unverified, verified, quarantined, out_of_scope
    evidence_id: Optional[int] = None
    id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class AssessmentPlan:
    project_id: int
    title: str
    target: str
    id: Optional[int] = None
    description: str = ""
    test_category: TestCategory = TestCategory.NETWORK_DISCOVERY
    acceptance_criteria: str = ""
    status: AssessmentStatus = AssessmentStatus.DRAFT
    preflight_blockers: str = ""
    execution_id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class AssessmentSession:
    project_id: int
    session_id: str
    id: Optional[int] = None
    authorized_scope: str = ""
    selected_tools: str = "[]"
    status: str = "pending"  # pending, in_progress, completed, failed, cancelled
    started_at: str = field(default_factory=_utc_now_iso)
    ended_at: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)
    metadata_json: str = "{}"


@dataclass
class Assessment:
    project_id: int
    name: str
    id: Optional[int] = None
    description: str = ""
    authorized_scope: str = ""
    start_date: str = ""
    end_date: str = ""
    status: AssessmentStatus = AssessmentStatus.PLANNED
    notes: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    @property
    def title(self) -> str:
        return self.name

    @title.setter
    def title(self, value: str):
        self.name = value

    @property
    def target(self) -> str:
        return self.authorized_scope

    @target.setter
    def target(self, value: str):
        self.authorized_scope = value


# Model Aliases for Open Asset Model & Multi-tool Compatibility
Asset = AssetNode
Relationship = AssetEdge
CollectionRun = ToolExecution


