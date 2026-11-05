"""Comprehensive verification and assessment testing suite.

Tests:
1. Assessment Plan Model, Schema & CRUD in Database.
2. Preflight Checker (Fail-Closed Scope & Project Lifecycle Authorization).
3. Module Verification Services (Network tunnel, AD/Kerberos, PrivEsc, Web/Binary).
4. Evidence Cryptographic Integrity Verification (SHA-256 tamper detection).
5. Finding Validation Lifecycle & Reporting Integration.
"""

import hashlib
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from core.preflight import PreflightChecker, VerificationCheckStatus
from core.verification_engine import (
    ActiveDirectoryVerificationService,
    NetworkVerificationService,
    PrivilegeEscalationVerificationService,
    WebBinaryVerificationService,
)
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import (
    AssessmentPlan,
    AssessmentStatus,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    TestCategory,
    ToolExecution,
    ValidationStatus,
)

# Prevent pytest from attempting to collect the TestCategory enum as a test class
TestCategory.__test__ = False


@pytest.fixture
def test_db():
    """Provides a fresh in-memory database."""
    return Database(":memory:")


@pytest.fixture
def authorized_project(test_db: Database) -> Project:
    """Creates an active, authorized penetration testing engagement with scopes."""
    p = test_db.create_project(
        Project(
            name="BankCorp Q4 Assessment",
            client_name="BankCorp Holdings",
            engagement_id="ENG-2026-BC-001",
            status=ProjectStatus.ACTIVE,
            start_date="2026-01-01",
            end_date="2026-12-31",
            allowed_hours="00:00-23:59",
            timezone="UTC",
        )
    )
    # Add allowed scope
    test_db.add_scope(
        TargetScope(
            project_id=p.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    # Add excluded scope
    test_db.add_scope(
        TargetScope(
            project_id=p.id,
            target="10.99.99.99",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )
    return p


# =========================================================================
# 1. Assessment Plan CRUD & Database Tests
# =========================================================================

def test_assessment_plan_crud(test_db: Database, authorized_project: Project):
    """Verifies creation, retrieval, update, and deletion of assessment plans."""
    plan = AssessmentPlan(
        project_id=authorized_project.id,
        title="Web Security & Header Compliance Assessment",
        target="127.0.0.1",
        description="Verify CSP, HSTS, and CORS on internal web endpoints.",
        test_category=TestCategory.WEB_APPLICATION,
        acceptance_criteria="Zero unauthenticated bypasses; strict CSP configured.",
        status=AssessmentStatus.DRAFT,
    )
    created = test_db.create_assessment_plan(plan)
    assert created.id is not None
    assert created.title == "Web Security & Header Compliance Assessment"
    assert created.status == AssessmentStatus.DRAFT
    assert created.test_category == TestCategory.WEB_APPLICATION

    # Retrieve
    retrieved = test_db.get_assessment_plan(created.id)
    assert retrieved is not None
    assert retrieved.id == created.id
    assert retrieved.target == "127.0.0.1"

    # List
    plans = test_db.list_assessment_plans(authorized_project.id)
    assert len(plans) == 1
    assert plans[0].id == created.id

    # Update with valid execution to satisfy foreign key constraint
    exec_rec = test_db.create_execution(
        ToolExecution(
            project_id=authorized_project.id,
            tool_name="nmap",
            command="nmap -sV 127.0.0.1",
        )
    )
    retrieved.status = AssessmentStatus.PREFLIGHT_PASSED
    retrieved.execution_id = exec_rec.id
    retrieved.preflight_blockers = ""
    updated = test_db.update_assessment_plan(retrieved)
    assert updated is True
    re_retrieved = test_db.get_assessment_plan(created.id)
    assert re_retrieved.status == AssessmentStatus.PREFLIGHT_PASSED
    assert re_retrieved.execution_id == exec_rec.id

    # Delete
    deleted = test_db.delete_assessment_plan(created.id)
    assert deleted is True
    assert test_db.get_assessment_plan(created.id) is None


# =========================================================================
# 2. Preflight Checker Fail-Closed Tests
# =========================================================================

def test_preflight_blocks_when_no_project(test_db: Database):
    """Preflight must fail closed if no active project is provided."""
    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="127.0.0.1",
        project=None,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is False
    assert result.status == VerificationCheckStatus.BLOCKED
    assert any("No active assessment project selected" in b for b in result.blockers)


def test_preflight_blocks_when_target_missing(test_db: Database, authorized_project: Project):
    """Preflight must fail closed when target specification is empty."""
    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="",
        project=authorized_project,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is False
    assert result.status == VerificationCheckStatus.BLOCKED
    assert any("Target specification is missing or empty" in b for b in result.blockers)


def test_preflight_blocks_unauthorized_target(test_db: Database, authorized_project: Project):
    """Preflight must fail closed when target is outside scope."""
    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="192.168.100.5",
        project=authorized_project,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is False
    assert result.status == VerificationCheckStatus.BLOCKED
    assert any("Target '192.168.100.5' is not in authorized scope" in b for b in result.blockers)


def test_preflight_blocks_explicitly_excluded_target(test_db: Database, authorized_project: Project):
    """Preflight must block targets matching explicit exclusions."""
    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="10.99.99.99",
        project=authorized_project,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is False
    assert result.status == VerificationCheckStatus.BLOCKED


def test_preflight_passes_for_authorized_target_in_no_tool_category(test_db: Database, authorized_project: Project):
    """Preflight passes when target is in-scope and category requires no missing external tools."""
    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="127.0.0.1",
        project=authorized_project,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is True
    assert result.status in (VerificationCheckStatus.PASSED, VerificationCheckStatus.NEEDS_REVIEW)
    assert len(result.blockers) == 0


def test_preflight_blocks_when_engagement_inactive(test_db: Database, authorized_project: Project):
    """Preflight blocks when engagement is paused or archived."""
    authorized_project.status = ProjectStatus.PAUSED
    test_db.update_project(authorized_project)

    checker = PreflightChecker(test_db)
    result = checker.run_preflight(
        target="127.0.0.1",
        project=authorized_project,
        test_category=TestCategory.PRIVILEGE_ESCALATION,
    )
    assert result.is_ready is False
    assert result.status == VerificationCheckStatus.BLOCKED
    assert any("Engagement lifecycle validation failed" in b for b in result.blockers)


# =========================================================================
# 3. Module Verification Services Tests
# =========================================================================

def test_network_verification_open_and_closed_ports():
    """Tests socket tunnel and port forward check against a local listener and closed port."""
    # 1. Closed port test
    res_closed = NetworkVerificationService.check_tunnel_or_port_forward(
        host="127.0.0.1",
        port=59998,
        timeout=0.3,
    )
    assert res_closed.is_connected is False
    assert res_closed.status_code in ("CONNECTION_REFUSED", "TIMEOUT", "ERROR")

    # 2. Open port test via temporary local listener
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    assigned_port = listener.getsockname()[1]

    def accept_thread():
        try:
            conn, _ = listener.accept()
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=accept_thread, daemon=True)
    t.start()

    try:
        res_open = NetworkVerificationService.check_tunnel_or_port_forward(
            host="127.0.0.1",
            port=assigned_port,
            timeout=1.0,
        )
        assert res_open.is_connected is True
        assert res_open.status_code == "CONNECTED"
        assert res_open.latency_ms >= 0.0
    finally:
        listener.close()


def test_ad_and_kerberos_hardening_evaluation():
    """Tests evaluation of SMB signing and Kerberos roastable accounts."""
    # Test insecure configuration
    report_insecure = ActiveDirectoryVerificationService.evaluate_smb_and_kerberos_hardening(
        smb_signing_required=False,
        smb_signing_enabled=True,
        kerberos_preauth_disabled_accounts=["krbtgt_backup", "svc_sql"],
    )
    assert report_insecure["is_smb_relay_safe"] is False
    assert report_insecure["asrep_roastable_count"] == 2
    assert len(report_insecure["security_findings"]) == 2

    # Test hardened configuration
    report_hardened = ActiveDirectoryVerificationService.evaluate_smb_and_kerberos_hardening(
        smb_signing_required=True,
        smb_signing_enabled=True,
        kerberos_preauth_disabled_accounts=[],
    )
    assert report_hardened["is_smb_relay_safe"] is True
    assert report_hardened["asrep_roastable_count"] == 0
    assert len(report_hardened["security_findings"]) == 0


def test_privilege_escalation_file_permissions(tmp_path: Path):
    """Tests local file permissions audit, detecting sensitive world-writable files."""
    test_file = tmp_path / "simulated_shadow"
    test_file.write_text("root:$6$hash:19000:0:99999:7:::\n")
    # Make world-writable (0o666)
    test_file.chmod(0o666)

    results = PrivilegeEscalationVerificationService.audit_local_file_permissions(
        target_files=[str(test_file)]
    )

    assert len(results) == 1
    rec = results[0]
    assert rec["path"] == str(test_file)
    assert rec["is_world_writable"] is True
    assert rec["is_misconfigured"] is True


def test_web_header_verification():
    """Tests HTTP security header verification engine."""
    headers_insecure = {
        "Server": "Apache/2.4.41",
        "Content-Type": "text/html; charset=UTF-8",
    }
    audit = WebBinaryVerificationService.audit_http_headers(headers_insecure)
    assert len(audit["missing_headers"]) >= 4
    assert audit["is_hardened"] is False

    headers_hardened = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    audit_good = WebBinaryVerificationService.audit_http_headers(headers_hardened)
    assert len(audit_good["missing_headers"]) == 0
    assert audit_good["is_hardened"] is True


def test_binary_protections_inspection():
    """Tests ELF header parsing and protection checks on a system binary."""
    # Target /bin/ls or /usr/bin/python3
    candidate = "/bin/ls" if os.path.exists("/bin/ls") else "/usr/bin/python3"
    info = WebBinaryVerificationService.inspect_binary_protections(candidate)
    assert info["is_elf"] is True
    assert info["bit_depth"] in (32, 64)
    assert info["endianness"] in ("little", "big")
    assert isinstance(info["is_pie"], bool)


# =========================================================================
# 4. Cryptographic Evidence Integrity Tests
# =========================================================================

def test_evidence_integrity_verification(test_db: Database, authorized_project: Project, tmp_path: Path):
    """Verifies SHA-256 hash validation and detection of tampered or missing evidence files."""
    evidence_file = tmp_path / "nmap_scan_output.txt"
    evidence_content = b"Nmap scan report for 127.0.0.1\nPORT 80/tcp OPEN http\n"
    evidence_file.write_bytes(evidence_content)
    real_hash = hashlib.sha256(evidence_content).hexdigest()

    ev = test_db.create_evidence(
        Evidence(
            project_id=authorized_project.id,
            file_path=str(evidence_file),
            sha256_hash=real_hash,
            description="Raw Nmap port scan evidence",
            mime_type="text/plain",
        )
    )
    assert ev.id is not None

    # 1. Verification of pristine evidence
    valid, msg = test_db.verify_evidence_integrity(ev.id)
    assert valid is True
    assert "Integrity verified" in msg

    # 2. Tampered evidence
    evidence_file.write_bytes(b"TAMPERED CONTENT INJECTED BY ATTACKER")
    valid_tampered, msg_tampered = test_db.verify_evidence_integrity(ev.id)
    assert valid_tampered is False
    assert "Integrity mismatch" in msg_tampered

    # 3. Missing file
    evidence_file.unlink()
    valid_missing, msg_missing = test_db.verify_evidence_integrity(ev.id)
    assert valid_missing is False
    assert "does not exist on disk" in msg_missing


# =========================================================================
# 5. Finding Validation Lifecycle & Reporting Integration Tests
# =========================================================================

def test_finding_validation_lifecycle_and_reporting(test_db: Database, authorized_project: Project):
    """Tests new validation states (observed, needs_validation) and report serialization."""
    f1 = test_db.create_finding(
        Finding(
            project_id=authorized_project.id,
            title="Potential SMB Signing Disabled Observation",
            severity=FindingSeverity.MEDIUM,
            affected_asset="127.0.0.1",
            affected_port_service="445/smb",
            validation_status=ValidationStatus.OBSERVED,
            validation_method="Passive traffic observation",
            severity_rationale="SMB signing is not enforced, enabling potential relay attacks.",
        )
    )
    f2 = test_db.create_finding(
        Finding(
            project_id=authorized_project.id,
            title="Kerberos AS-REP Roasting Vulnerability",
            severity=FindingSeverity.HIGH,
            affected_asset="127.0.0.1",
            affected_port_service="88/kerberos",
            validation_status=ValidationStatus.NEEDS_VALIDATION,
            validation_method="LDAP userAccountControl query",
            severity_rationale="Account does not require Kerberos pre-authentication.",
        )
    )

    # Add an assessment plan to the project
    test_db.create_assessment_plan(
        AssessmentPlan(
            project_id=authorized_project.id,
            title="AD & Kerberos Hardening Verification",
            target="127.0.0.1",
            test_category=TestCategory.ACTIVE_DIRECTORY,
            acceptance_criteria="Enforce SMB signing; disable DONT_REQ_PREAUTH on all user accounts.",
            status=AssessmentStatus.PREFLIGHT_PASSED,
        )
    )

    report_builder = ReportBuilder(test_db)
    data = report_builder.build_report_data(authorized_project.id)

    # Check metrics breakdown
    assert data.metrics.observed_findings == 1
    assert data.metrics.needs_validation_findings == 1
    assert len(data.assessment_plans) == 1

    # Check JSON export
    json_text = report_builder.generate_json(authorized_project.id)
    assert "Passive traffic observation" in json_text
    assert "LDAP userAccountControl query" in json_text
    assert "AD & Kerberos Hardening Verification" in json_text
    assert "observed" in json_text
    assert "needs_validation" in json_text

    # Check Markdown export
    md_text = report_builder.generate_markdown(authorized_project.id)
    assert "Validation Method" in md_text
    assert "Severity Rationale" in md_text
    assert "Assessment Plans & Acceptance Criteria" in md_text
