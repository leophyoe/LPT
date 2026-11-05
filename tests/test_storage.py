"""Unit tests for storage models and SQLite database operations."""

import pytest
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def db():
    """In-memory SQLite database for test isolation."""
    return Database(":memory:")


def test_project_crud(db: Database):
    project = Project(
        name="CPENT Lab Assessment",
        client_name="Internal Security Lab",
        description="Practical network penetration testing project.",
        status=ProjectStatus.ACTIVE,
    )
    saved = db.create_project(project)
    assert saved.id is not None
    assert saved.name == "CPENT Lab Assessment"

    retrieved = db.get_project(saved.id)
    assert retrieved is not None
    assert retrieved.client_name == "Internal Security Lab"

    all_projects = db.list_projects()
    assert len(all_projects) == 1

    deleted = db.delete_project(saved.id)
    assert deleted is True
    assert db.get_project(saved.id) is None


def test_target_scope_cascade(db: Database):
    project = db.create_project(Project(name="Scope Test Project"))
    assert project.id is not None

    scope = TargetScope(
        project_id=project.id,
        target="10.10.10.0/24",
        target_type=TargetType.CIDR_RANGE,
        is_authorized=True,
    )
    saved_scope = db.add_scope(scope)
    assert saved_scope.id is not None

    scopes = db.list_scopes(project.id)
    assert len(scopes) == 1
    assert scopes[0].target == "10.10.10.0/24"

    # Test cascade delete
    db.delete_project(project.id)
    assert len(db.list_scopes(project.id)) == 0


def test_tool_execution_lifecycle(db: Database):
    project = db.create_project(Project(name="Execution Test"))
    assert project.id is not None

    execution = ToolExecution(
        project_id=project.id,
        tool_name="nmap",
        command="nmap -sV -p 80,443 10.10.10.5",
        status=ExecutionStatus.PENDING,
    )
    saved_exec = db.create_execution(execution)
    assert saved_exec.id is not None
    assert saved_exec.status == ExecutionStatus.PENDING

    # Update execution when completed
    saved_exec.status = ExecutionStatus.COMPLETED
    saved_exec.exit_code = 0
    saved_exec.duration_seconds = 4.25
    saved_exec.raw_output_path = "/tmp/nmap_output.xml"
    db.update_execution(saved_exec)

    executions = db.list_executions(project.id)
    assert len(executions) == 1
    assert executions[0].status == ExecutionStatus.COMPLETED
    assert executions[0].exit_code == 0
    assert executions[0].duration_seconds == 4.25


def test_finding_and_evidence(db: Database):
    project = db.create_project(Project(name="Findings Test"))
    assert project.id is not None

    finding = Finding(
        project_id=project.id,
        title="Open SMB Port with Insecure Signing",
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        affected_asset="10.10.10.20",
        affected_port_service="445/tcp",
        description="SMB signing is disabled on the target host.",
        remediation="Enable SMB message signing in Group Policy.",
        validation_status=ValidationStatus.CONFIRMED,
        source_tool="nmap",
    )
    saved_finding = db.create_finding(finding)
    assert saved_finding.id is not None
    assert saved_finding.severity == FindingSeverity.HIGH

    evidence = Evidence(
        project_id=project.id,
        finding_id=saved_finding.id,
        file_path="/evidence/smb_scan.xml",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        description="Nmap NSE script output demonstrating SMB signing status.",
    )
    saved_evidence = db.add_evidence(evidence)
    assert saved_evidence.id is not None

    findings = db.list_findings(project.id)
    assert len(findings) == 1
    assert findings[0].title == "Open SMB Port with Insecure Signing"

    evidence_list = db.list_evidence(project.id)
    assert len(evidence_list) == 1
    assert evidence_list[0].finding_id == saved_finding.id

    # Test get_evidence by ID
    fetched_evidence = db.get_evidence(saved_evidence.id)
    assert fetched_evidence is not None
    assert fetched_evidence.id == saved_evidence.id
    assert fetched_evidence.sha256_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_evidence_integrity_verification(db: Database, tmp_path):
    project = db.create_project(Project(name="Integrity Verification Test"))
    assert project.id is not None

    test_file = tmp_path / "evidence_payload.txt"
    test_content = b"CRITICAL: Verified remote code execution vulnerability payload proof."
    test_file.write_bytes(test_content)

    import hashlib
    correct_hash = hashlib.sha256(test_content).hexdigest()

    # Valid evidence record
    ev_valid = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(test_file),
            sha256_hash=correct_hash,
            description="Captured exploit payload verification",
        )
    )
    is_valid, msg = db.verify_evidence_integrity(ev_valid)
    assert is_valid is True
    assert "Integrity verified" in msg

    # Tampered evidence record (wrong hash)
    ev_tampered = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(test_file),
            sha256_hash="0000000000000000000000000000000000000000000000000000000000000000",
            description="Tampered proof",
        )
    )
    is_tampered_valid, tampered_msg = db.verify_evidence_integrity(ev_tampered)
    assert is_tampered_valid is False
    assert "Integrity mismatch" in tampered_msg

    # Missing file evidence record
    ev_missing = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path="/nonexistent/file/path.log",
            sha256_hash=correct_hash,
            description="Missing file proof",
        )
    )
    is_missing_valid, missing_msg = db.verify_evidence_integrity(ev_missing)
    assert is_missing_valid is False
    assert "does not exist on disk" in missing_msg


def test_file_based_persistence(tmp_path):
    db_file = tmp_path / "test_cybersecurity.db"
    db = Database(db_file)
    p = db.create_project(Project(name="Persistent Project", client_name="Acme Corp"))
    assert p.id is not None
    db.close()

    # Reopen same database file
    db_reopened = Database(db_file)
    projects = db_reopened.list_projects()
    assert len(projects) == 1
    assert projects[0].name == "Persistent Project"
    assert projects[0].client_name == "Acme Corp"
    db_reopened.close()

