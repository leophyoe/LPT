"""Comprehensive unit and integration tests for Nikto Adapter and Parser.

Tests Scope Guard enforcement, safe command building, output parsing (text & JSON),
cryptographic evidence capture (SHA-256), and SQLite finding persistence.
"""

import hashlib
import json
import pytest
from unittest.mock import MagicMock, patch

from core.registry import ToolRegistry
from modules.web.nikto_adapter import NiktoAdapter, NiktoExecutionResult, NiktoScanOptions
from modules.web.nikto_parser import NiktoItem, NiktoParser, NiktoScanResult
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def test_db():
    return Database(":memory:")


@pytest.fixture
def sample_project(test_db):
    proj = test_db.create_project(Project(name="Nikto Assessment Alpha", client_name="TestCorp"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="127.0.0.1", target_type=TargetType.IP_ADDRESS))
    test_db.add_scope(TargetScope(project_id=proj.id, target="targetlab.corp", target_type=TargetType.HOSTNAME))
    return proj


# ---------------------------------------------------------------------------
# 1. Command Builder Tests
# ---------------------------------------------------------------------------

def test_nikto_build_command_default(test_db):
    adapter = NiktoAdapter(db=test_db)
    opts = NiktoScanOptions(target="http://127.0.0.1:8080/app")
    cmd = adapter.build_command(opts, output_file="/tmp/nikto.json")

    assert "-host" in cmd
    assert "127.0.0.1" in cmd
    assert "-port" in cmd
    assert "8080" in cmd
    assert "-nointeractive" in cmd
    assert "-nocheck" in cmd
    assert "-Format" in cmd
    assert "json" in cmd
    assert "/tmp/nikto.json" in cmd


def test_nikto_build_command_ssl_and_tuning(test_db):
    adapter = NiktoAdapter(db=test_db)
    opts = NiktoScanOptions(
        target="https://targetlab.corp",
        tuning="1,2,b",
        extra_args=["-useragent", "SecurityAuditTool/1.0"],
    )
    cmd = adapter.build_command(opts)

    assert "-host" in cmd
    assert "targetlab.corp" in cmd
    assert "-ssl" in cmd
    assert "-Tuning" in cmd
    assert "1,2,b" in cmd
    assert "-useragent" in cmd
    assert "SecurityAuditTool/1.0" in cmd


# ---------------------------------------------------------------------------
# 2. Nikto Parser Tests (Text & JSON)
# ---------------------------------------------------------------------------

SYNTHETIC_NIKTO_TEXT = """
- Nikto v2.6.1
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        8080
+ Start Time:         2026-10-21 00:00:00 (GMT)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.
+ OSVDB-3092: /admin/: This might be interesting.
+ /wp-config.php.bak: Backup file found containing database credentials.
+ Apache/2.4.49 - Vulnerable to Path Traversal and Remote Code Execution (CVE-2021-41773).
+ 7915 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-10-21 00:00:15 (GMT) (15 seconds)
---------------------------------------------------------------------------
"""


def test_nikto_parser_text_parsing():
    result = NiktoParser.parse_text(SYNTHETIC_NIKTO_TEXT)
    assert result.target_ip == "127.0.0.1"
    assert result.target_port == "8080"
    assert "Apache/2.4.41" in result.banner
    assert len(result.items) >= 4

    # Check Severities
    severities = [item.severity for item in result.items]
    assert FindingSeverity.CRITICAL in severities  # CVE-2021-41773 and backup file
    assert FindingSeverity.HIGH in severities      # /admin/
    assert FindingSeverity.LOW in severities       # anti-clickjacking / headers


def test_nikto_parser_json_parsing():
    synthetic_json = json.dumps({
        "host": "targetlab.corp",
        "ip": "192.168.1.100",
        "port": "443",
        "banner": "nginx/1.18.0",
        "vulnerabilities": [
            {
                "id": "999996",
                "OSVDB": "0",
                "method": "GET",
                "url": "/",
                "msg": "The anti-clickjacking X-Frame-Options header is not present.",
            },
            {
                "id": "003092",
                "OSVDB": "3092",
                "method": "GET",
                "url": "/secret_admin/",
                "msg": "/secret_admin/: Admin login portal identified.",
            },
        ],
    })

    result = NiktoParser.parse_json(synthetic_json)
    assert result.target_host == "targetlab.corp"
    assert result.target_ip == "192.168.1.100"
    assert result.target_port == "443"
    assert len(result.items) == 2
    assert result.items[0].severity == FindingSeverity.LOW
    assert result.items[1].severity == FindingSeverity.HIGH


def test_nikto_parser_to_findings():
    result = NiktoParser.parse_text(SYNTHETIC_NIKTO_TEXT)
    findings = NiktoParser.to_findings(
        result, project_id=1, execution_id=42, assessment_id=43
    )

    assert len(findings) >= 4
    for f in findings:
        assert f.project_id == 1
        assert f.execution_id == 42
        assert f.assessment_id == 43
        assert f.source_tool == "nikto"
        assert f.affected_asset == result.target_host
        assert f.affected_port_service == "8080/tcp"
        assert f.remediation != ""
        assert f.cvss_score is not None


# ---------------------------------------------------------------------------
# 3. Scope Guard Enforcement Tests
# ---------------------------------------------------------------------------

def test_nikto_adapter_scope_guard_blocks_unauthorized(test_db, sample_project):
    adapter = NiktoAdapter(db=test_db)
    scopes = test_db.list_scopes(sample_project.id)

    # Attempt to scan an unauthorized public domain
    res = adapter.execute_scan(
        project_id=sample_project.id,
        options=NiktoScanOptions(target="http://evil-external-target.com"),
        scopes=scopes,
    )

    assert not res.is_authorized
    assert "authorized scope" in res.scope_reason.lower()
    assert res.execution is None
    assert len(res.findings) == 0


# ---------------------------------------------------------------------------
# 4. End-to-End Execution & SQLite Persistence Tests (Mocked Subprocess)
# ---------------------------------------------------------------------------

def test_nikto_adapter_execution_persists_sqlite(test_db, sample_project, tmp_path):
    adapter = NiktoAdapter(db=test_db)
    scopes = test_db.list_scopes(sample_project.id)
    assessment = test_db.create_assessment(
        Assessment(
            project_id=sample_project.id,
            name="Nikto Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )

    mock_proc = ProcessExecutionResult(
        command=["bin/nikto", "-host", "127.0.0.1"],
        exit_code=0,
        status=ExecutionStatus.COMPLETED,
        stdout=SYNTHETIC_NIKTO_TEXT,
        stderr="",
        started_at="2026-10-21T00:00:00",
        finished_at="2026-10-21T00:00:05",
        duration_seconds=5.0,
    )

    with patch.object(adapter.runner, "run", return_value=mock_proc):
        res: NiktoExecutionResult = adapter.execute_scan(
            project_id=sample_project.id,
            options=NiktoScanOptions(target="http://127.0.0.1:8080"),
            scopes=scopes,
            evidence_dir=tmp_path,
            assessment_id=assessment.id,
        )

    # 1. Execution Result Verification
    assert res.is_authorized
    assert res.execution is not None
    assert res.execution.tool_name == "nikto"
    assert res.execution.status == ExecutionStatus.COMPLETED
    assert res.execution.duration_seconds == 5.0

    # 2. SQLite ToolExecution Persistence
    db_execs = test_db.list_executions(sample_project.id)
    assert len(db_execs) == 1
    assert db_execs[0].tool_name == "nikto"
    assert db_execs[0].status == ExecutionStatus.COMPLETED
    assert db_execs[0].assessment_id == assessment.id

    # 3. Cryptographic Evidence Persistence
    assert res.evidence is not None
    assert res.evidence.sha256_hash != ""
    assert res.evidence.assessment_id == assessment.id
    expected_hash = hashlib.sha256(SYNTHETIC_NIKTO_TEXT.encode("utf-8")).hexdigest()
    assert res.evidence.sha256_hash == expected_hash

    # 4. SQLite Findings Persistence
    assert len(res.findings) >= 4
    db_findings = test_db.list_findings(sample_project.id)
    assert len(db_findings) == len(res.findings)
    assert all(f.assessment_id == assessment.id for f in db_findings)

    # Verify Strix AI enrichment
    for f in db_findings:
        assert f.source_tool == "nikto"
        assert f.cvss_score is not None
        assert f.cvss_score >= 0.0


def test_nikto_adapter_cancellation(test_db):
    adapter = NiktoAdapter(db=test_db)
    with patch.object(adapter.runner, "cancel") as mock_cancel:
        adapter.cancel()
        mock_cancel.assert_called_once()
