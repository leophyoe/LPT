"""Automated Test Suite for Phase 7: Assessment Workflow & Findings Management.

Validates:
1. Assessment CRUD, timeline, scope, notes, and status transitions (Planned, In Progress, Paused, Completed, Archived).
2. Fail-closed Scope Authorization (allowed, excluded, non-destructive defaults, network map node non-authorization).
3. Findings Management Lifecycle (New, Confirmed, False Positive, Remediation in Progress, Resolved, Accepted Risk).
4. Finding Deduplication and sensitive credential / secret scrubbing.
5. Cryptographic Evidence Integrity (SHA-256 validation, provenance, tamper detection).
6. Tool Execution scan activity linkage to assessments.
7. Assessment-scoped Reporting (PDF, HTML, Markdown, JSON) with unverified data tags and secret redaction.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.activity_logger import sanitize_text
from core.scope import ScopeAuthorizationService
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def memory_db():
    """Provides a fresh in-memory SQLite database instance."""
    db = Database(":memory:")
    yield db
    db.close()


@pytest.fixture
def sample_project(memory_db):
    """Creates a sample penetration testing project."""
    project = Project(
        name="Alpha Global Bank Pentest",
        client_name="Alpha Global Bank Ltd.",
        description="Annual external & internal penetration test against core infrastructure.",
        status=ProjectStatus.ACTIVE,
        lead_tester="Senior Pentester",
        prohibited_tests="DoS/DDoS, Destructive Exploitation, Social Engineering",
        allow_active_recon=True,
    )
    return memory_db.create_project(project)


# =========================================================================
# 1. Assessment Management & Status Transitions
# =========================================================================
def test_assessment_crud_and_status_transitions(memory_db, sample_project):
    """Verifies Assessment creation, retrieval, updates, status transitions, and deletion."""
    # 1. Create Assessment
    assessment = Assessment(
        project_id=sample_project.id,
        name="External Perimeter Assessment",
        description="Blackbox external attack surface assessment.",
        authorized_scope="198.51.100.0/24",
        start_date="2026-11-01",
        end_date="2026-11-15",
        status=AssessmentStatus.PLANNED,
        notes="Testing restricted to maintenance windows.",
    )
    created = memory_db.create_assessment(assessment)
    assert created.id is not None
    assert created.name == "External Perimeter Assessment"
    assert created.status == AssessmentStatus.PLANNED

    # 2. Retrieve Assessment
    fetched = memory_db.get_assessment(created.id)
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.authorized_scope == "198.51.100.0/24"
    assert fetched.notes == "Testing restricted to maintenance windows."

    # 3. Status Transitions: Planned -> In Progress -> Paused -> Completed -> Archived
    status_flow = [
        AssessmentStatus.IN_PROGRESS,
        AssessmentStatus.PAUSED,
        AssessmentStatus.IN_PROGRESS,
        AssessmentStatus.COMPLETED,
        AssessmentStatus.ARCHIVED,
    ]
    for st in status_flow:
        fetched.status = st
        assert memory_db.update_assessment(fetched) is True
        current = memory_db.get_assessment(created.id)
        assert current.status == st

    # 4. Filter by status
    in_progress_list = memory_db.list_assessments(sample_project.id, status="in_progress")
    assert len(in_progress_list) == 0  # Currently archived
    archived_list = memory_db.list_assessments(sample_project.id, status="archived")
    assert len(archived_list) == 1
    assert archived_list[0].id == created.id

    # 5. Delete Assessment
    assert memory_db.delete_assessment(created.id) is True
    assert memory_db.get_assessment(created.id) is None
    assert len(memory_db.list_assessments(sample_project.id)) == 0


# =========================================================================
# 2. Scope Validation, Fail-Closed & Non-Destructive Defaults
# =========================================================================
def test_scope_validation_fail_closed_and_guard(memory_db, sample_project):
    """Enforces that scans fail closed for out-of-scope or excluded targets and non-destructive checks."""
    # Setup authorized and excluded scopes
    memory_db.add_scope(
        TargetScope(
            project_id=sample_project.id,
            target="192.168.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    memory_db.add_scope(
        TargetScope(
            project_id=sample_project.id,
            target="192.168.10.50",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
            notes="Critical core banking database - strictly excluded",
        )
    )
    scopes = memory_db.list_scopes(sample_project.id)

    # 1. Verify summary
    summary = ScopeAuthorizationService.get_scope_summary(scopes)
    assert "192.168.10.0/24" in summary["allowed"]
    assert "192.168.10.50" in summary["excluded"]

    # 2. In-scope allowed target
    ok, msg = ScopeAuthorizationService.verify_scan_intent("192.168.10.15", scopes, project=sample_project)
    assert ok is True
    assert "within authorized scope" in msg

    # 3. Excluded target must FAIL CLOSED
    ok, msg = ScopeAuthorizationService.verify_scan_intent("192.168.10.50", scopes, project=sample_project)
    assert ok is False
    assert "Scope authorization blocked" in msg

    # 4. Out-of-scope target must FAIL CLOSED
    ok, msg = ScopeAuthorizationService.verify_scan_intent("10.50.0.1", scopes, project=sample_project)
    assert ok is False
    assert "Scope authorization blocked" in msg

    # 5. Network map node does NOT confer authorization
    ok, msg = ScopeAuthorizationService.verify_scan_intent(
        "192.168.10.15", scopes, project=sample_project, source="network_map"
    )
    assert ok is False
    assert "Network map visualization nodes do NOT confer authorization" in msg

    # 6. Destructive actions blocked by RoE constraints
    ok, msg = ScopeAuthorizationService.verify_scan_intent(
        "192.168.10.15", scopes, project=sample_project, is_destructive=True
    )
    assert ok is False
    assert "Destructive tests are strictly prohibited" in msg


# =========================================================================
# 3. Findings Management Lifecycle, Deduplication & Secret Scrubbing
# =========================================================================
def test_findings_management_lifecycle_and_scrubbing(memory_db, sample_project):
    """Tests finding creation, full lifecycle transitions, deduplication, and secret scrubbing."""
    assessment = memory_db.create_assessment(
        Assessment(project_id=sample_project.id, name="Web App Assessment")
    )

    raw_description = (
        "Found hardcoded API secret in configuration file.\n"
        "Key: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecrettoken123\n"
        "Database password: Password123!"
    )
    scrubbed_desc = sanitize_text(raw_description)
    assert "Bearer [REDACTED]" in scrubbed_desc
    assert "supersecrettoken123" not in scrubbed_desc

    finding = Finding(
        project_id=sample_project.id,
        title="Hardcoded API Secret Exposure",
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        affected_asset="192.168.10.20",
        affected_port_service="8443/https",
        description=scrubbed_desc,
        reproduction_steps="curl -k https://192.168.10.20:8443/config.json",
        remediation="Extract credentials into environment variables and revoke compromised tokens.",
        validation_status=ValidationStatus.NEW,
        confidence=0.9,
        assessment_id=assessment.id,
    )
    created = memory_db.create_finding(finding)
    assert created.id is not None
    assert created.status == "new"

    # Status transitions across the Phase 7 lifecycle
    lifecycles = [
        ValidationStatus.CONFIRMED,
        ValidationStatus.REMEDIATION_IN_PROGRESS,
        ValidationStatus.RESOLVED,
        ValidationStatus.ACCEPTED_RISK,
        ValidationStatus.FALSE_POSITIVE,
    ]
    for st in lifecycles:
        assert memory_db.update_finding_status(created.id, st) is True
        f = memory_db.get_finding(created.id)
        assert f.validation_status == st

    # Deduplication test on repeated imports
    dup_finding = Finding(
        project_id=sample_project.id,
        title="Hardcoded API Secret Exposure",
        severity=FindingSeverity.HIGH,
        affected_asset="192.168.10.20",
        affected_port_service="8443/https",
        assessment_id=assessment.id,
    )
    upserted = memory_db.upsert_finding_deduplicated(dup_finding)
    assert upserted.id == created.id  # Reused existing ID, no duplicate created
    all_findings = memory_db.list_findings(sample_project.id)
    assert len(all_findings) == 1


# =========================================================================
# 4. Evidence Integration & Cryptographic Integrity Verification
# =========================================================================
def test_evidence_linkage_and_integrity(memory_db, sample_project, tmp_path):
    """Verifies evidence creation with SHA-256 hash, linkage to finding/assessment, and integrity checking."""
    assessment = memory_db.create_assessment(
        Assessment(project_id=sample_project.id, name="Infra Audit")
    )
    finding = memory_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="TLS Insecure Cipher Suites",
            severity=FindingSeverity.MEDIUM,
            affected_asset="192.168.10.25",
            assessment_id=assessment.id,
        )
    )

    # Create evidence file on disk
    ev_file = tmp_path / "nmap_ssl_ciphers.txt"
    content = "TLS_RSA_WITH_3DES_EDE_CBC_SHA - SWEET32 Vulnerable\nClient Token: [REDACTED]"
    ev_file.write_text(content, encoding="utf-8")
    expected_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

    evidence = Evidence(
        project_id=sample_project.id,
        file_path=str(ev_file),
        sha256_hash=expected_sha256,
        finding_id=finding.id,
        assessment_id=assessment.id,
        description="SSL cipher suite scan proof",
        mime_type="text/plain",
    )
    saved_ev = memory_db.add_evidence(evidence)
    assert saved_ev.id is not None
    assert saved_ev.assessment_id == assessment.id

    # Verify integrity passes
    is_valid, msg = memory_db.verify_evidence_integrity(saved_ev)
    assert is_valid is True
    assert "Integrity verified" in msg

    # Tamper with evidence file on disk
    ev_file.write_text("Modified content that tampers with evidence!", encoding="utf-8")
    is_valid, msg = memory_db.verify_evidence_integrity(saved_ev)
    assert is_valid is False
    assert "Integrity mismatch" in msg


# =========================================================================
# 5. Scan Activity Linkage to Assessment
# =========================================================================
def test_scan_activity_linkage(memory_db, sample_project):
    """Tests associating tool executions and telemetry logs with an assessment."""
    assessment = memory_db.create_assessment(
        Assessment(project_id=sample_project.id, name="Discovery Assessment")
    )

    exec1 = ToolExecution(
        project_id=sample_project.id,
        tool_name="nmap",
        command="nmap -sV -sC 192.168.10.0/24",
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        started_at="2026-11-01T10:00:00Z",
        finished_at="2026-11-01T10:05:00Z",
        duration_seconds=300.0,
        assessment_id=assessment.id,
    )
    saved_exec = memory_db.create_execution(exec1)
    assert saved_exec.id is not None
    assert saved_exec.assessment_id == assessment.id

    # Execution for different / global context
    exec2 = ToolExecution(
        project_id=sample_project.id,
        tool_name="whois",
        command="whois target.org",
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        assessment_id=None,
    )
    memory_db.create_execution(exec2)

    # Verify scoped querying
    scoped_execs = memory_db.list_executions(sample_project.id, assessment_id=assessment.id)
    assert len(scoped_execs) == 1
    assert scoped_execs[0].id == saved_exec.id
    assert scoped_execs[0].tool_name == "nmap"

    all_execs = memory_db.list_executions(sample_project.id)
    assert len(all_execs) == 2


# =========================================================================
# 6. Assessment-Scoped Multi-Format Report Generation
# =========================================================================
def test_assessment_scoped_report_generation(memory_db, sample_project, tmp_path):
    """Verifies that PDF, HTML, Markdown, and JSON reports can be generated for a specific assessment."""
    # Setup Assessment with in-scope finding and unverified finding
    assessment = memory_db.create_assessment(
        Assessment(
            project_id=sample_project.id,
            name="Q4 Red Team Assessment",
            authorized_scope="192.168.10.0/24",
            start_date="2026-11-01",
            end_date="2026-11-10",
            notes="Focused on perimeter boundary testing.",
        )
    )

    # Add verified finding
    memory_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Exposed Administration Panel",
            severity=FindingSeverity.HIGH,
            affected_asset="192.168.10.10",
            validation_status=ValidationStatus.CONFIRMED,
            assessment_id=assessment.id,
        )
    )

    # Add unverified finding (must display UNVERIFIED tag)
    memory_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Potential SMB Signing Disabled",
            severity=FindingSeverity.MEDIUM,
            affected_asset="192.168.10.12",
            validation_status=ValidationStatus.UNVERIFIED,
            assessment_id=assessment.id,
        )
    )

    builder = ReportBuilder(memory_db)

    # 1. JSON Report
    json_path = tmp_path / "report.json"
    json_text = builder.generate_json(
        sample_project.id, output_path=json_path, assessment_id=assessment.id
    )
    parsed = json.loads(json_text)
    assert parsed["assessment"] is not None
    assert parsed["assessment"]["id"] == assessment.id
    assert parsed["assessment"]["name"] == "Q4 Red Team Assessment"
    assert len(parsed["findings"]) == 2

    # 2. Markdown Report
    md_path = tmp_path / "report.md"
    md_text = builder.generate_markdown(
        sample_project.id, output_path=md_path, assessment_id=assessment.id
    )
    assert "Q4 Red Team Assessment" in md_text
    assert "[UNVERIFIED - PENDING EVIDENCE]" in md_text
    assert md_path.exists()

    # 3. HTML Report
    html_path = tmp_path / "report.html"
    html_text = builder.generate_html(
        sample_project.id, output_path=html_path, assessment_id=assessment.id
    )
    assert "Q4 Red Team Assessment" in html_text
    assert "UNVERIFIED - PENDING EVIDENCE" in html_text
    assert html_path.exists()

    # 4. PDF Report
    pdf_path = tmp_path / "report.pdf"
    res_pdf = builder.generate_pdf(
        sample_project.id, output_path=pdf_path, assessment_id=assessment.id
    )
    assert res_pdf.exists()
    assert res_pdf.stat().st_size > 0

    # 5. Generate All
    all_reports = builder.generate_all(
        sample_project.id, tmp_path / "batch", assessment_id=assessment.id
    )
    for fmt in ["pdf", "html", "markdown", "json"]:
        assert fmt in all_reports
        assert all_reports[fmt].exists()
        assert all_reports[fmt].stat().st_size > 0
