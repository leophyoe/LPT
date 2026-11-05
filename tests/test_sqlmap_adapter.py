"""Unit tests for SQLMapAdapter."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from core.registry import ToolRegistry
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    ExecutionStatus,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def db():
    return Database(":memory:")


def test_sqlmap_build_command(db: Database):
    adapter = SQLMapAdapter(db)
    options = SQLMapOptions(
        target_url="http://127.0.0.1:8080/item?id=1",
        risk=1,
        level=1,
        batch_mode=True,
    )
    cmd = adapter.build_command(options)

    assert any("sqlmap.py" in arg or arg.endswith("sqlmap") for arg in cmd)
    assert "-u" in cmd
    assert "http://127.0.0.1:8080/item?id=1" in cmd
    assert "--batch" in cmd
    assert "--disable-coloring" in cmd


def test_sqlmap_scope_guard_blocks_unauthorized(db: Database):
    adapter = SQLMapAdapter(db)
    project = db.create_project(Project(name="SQLMap Scope Test"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="internal.authorized.corp",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        )
    ]
    assessment = db.create_assessment(
        Assessment(
            project_id=project.id,
            name="SQLMap Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )

    options = SQLMapOptions(target_url="http://evil.external.target/vuln.php?id=1")
    success, reason, findings, execution = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
    )

    assert success is False
    assert "NOT in the authorized scope list" in reason
    assert len(findings) == 0
    assert execution is None


def test_sqlmap_parse_output(db: Database):
    adapter = SQLMapAdapter(db)

    simulated_stdout = """
    [12:00:01] [INFO] testing connection to the target URL
    [12:00:02] [INFO] checking if the target is protected by some kind of WAF/IPS
    sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
    ---
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: id=1 AND 5258=5258
    ---
    [12:00:05] [INFO] the back-end DBMS is MySQL
    web server operating system: Linux Ubuntu
    """

    findings = adapter.parse_sqlmap_output(
        stdout_text=simulated_stdout,
        target_url="http://127.0.0.1:8080/products?id=1",
        project_id=1,
        execution_id=1,
    )

    assert len(findings) == 1
    f = findings[0]
    assert "SQL Injection in parameter 'id'" in f.title
    assert f.severity == FindingSeverity.CRITICAL
    assert f.cvss_score == 9.8
    assert "id=1 AND 5258=5258" in f.reproduction_steps
    assert "Prepared Statements" in f.remediation


def test_sqlmap_safe_local_run(db: Database, tmp_path: Path):
    """Executes a real local scan with mock runner to test end-to-end integration."""
    adapter = SQLMapAdapter(db)
    project = db.create_project(Project(name="Local SQLMap Test"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]
    assessment = db.create_assessment(
        Assessment(
            project_id=project.id,
            name="SQLMap Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )
    # Mock process runner to return simulated output cleanly
    mock_runner = MagicMock()
    sim_stdout = """
    Parameter: category (GET)
        Type: error-based
        Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause
        Payload: category=books' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x71,0x71,0x71) FROM INFORMATION_SCHEMA.TABLES GROUP BY 1)a)-- 
    """
    mock_runner.run.return_value = ProcessExecutionResult(
        command=["python3", "sqlmap.py"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout=sim_stdout,
        stderr="",
        started_at="2026-10-20T12:00:00Z",
        finished_at="2026-10-20T12:00:02Z",
        duration_seconds=2.0,
    )
    adapter.runner = mock_runner

    options = SQLMapOptions(target_url="http://127.0.0.1:8080/store?category=books")
    success, msg, findings, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        evidence_dir=tmp_path / "evidence",
        assessment_id=assessment.id,
    )

    assert success is True
    assert len(findings) == 1
    assert exec_rec is not None
    assert exec_rec.status == ExecutionStatus.COMPLETED
    assert exec_rec.assessment_id == assessment.id

    # Verify stored in DB
    db_findings = db.list_findings(project.id)
    assert len(db_findings) == 1
    assert "category" in db_findings[0].title
    assert db_findings[0].assessment_id == assessment.id

    # Verify evidence vaulted
    ev_list = db.list_evidence(project.id)
    assert len(ev_list) == 1
    assert ev_list[0].execution_id == exec_rec.id
    assert ev_list[0].assessment_id == assessment.id
