"""Tests for WAFW00F, Gobuster, Volatility, and Bandit adapters."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import json
from unittest.mock import MagicMock
import pytest
from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService
from modules.code_security.bandit_adapter import BanditAdapter, BanditOptions
from modules.system.volatility_adapter import VolatilityAdapter, VolatilityOptions
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    ExecutionStatus,
    Project,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def temp_db():
    return Database(":memory:")


@pytest.fixture
def test_project(temp_db):
    proj = Project(name="Adapter Test Lab", client_name="Internal Testing")
    created = temp_db.create_project(proj)
    scope = TargetScope(
        project_id=created.id,
        target="127.0.0.1",
        target_type=TargetType.IP_ADDRESS,
        is_authorized=True,
    )
    temp_db.add_scope(scope)
    return created


# ---------------------------------------------------------------------------
# WAFW00F Tests
# ---------------------------------------------------------------------------

def test_wafw00f_build_command(temp_db):
    adapter = WAFW00FAdapter(temp_db)
    opts = WAFW00FOptions(target_url="http://127.0.0.1:8080", find_all=True)
    cmd = adapter.build_command(opts)
    assert len(cmd) >= 2
    assert "http://127.0.0.1:8080" in cmd
    assert "-a" in cmd


def test_wafw00f_scope_guard_blocks_unauthorized(temp_db, test_project):
    adapter = WAFW00FAdapter(temp_db)
    scopes = temp_db.list_scopes(test_project.id)
    opts = WAFW00FOptions(target_url="http://unauthorized-bank.com")

    allowed, reason, findings, execution = adapter.execute_scan(
        project_id=test_project.id,
        options=opts,
        scopes=scopes,
    )
    assert not allowed
    assert "out of scope" in reason.lower()
    assert len(findings) == 0
    assert execution is None


def test_wafw00f_parse_output_detected(temp_db):
    adapter = WAFW00FAdapter(temp_db)
    sample_output = """
    [*] Checking https://example.com
    [+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
    [~] Number of requests: 14
    """
    res = adapter.parse_output(sample_output, "https://example.com")
    assert res.waf_detected is True
    assert "Cloudflare" in (res.waf_name or "")
    assert res.num_requests == 14


def test_wafw00f_parse_output_none(temp_db):
    adapter = WAFW00FAdapter(temp_db)
    sample_output = """
    [*] Checking http://127.0.0.1:8080
    [-] No WAF detected by the generic detection
    [~] Number of requests: 7
    """
    res = adapter.parse_output(sample_output, "http://127.0.0.1:8080")
    assert res.waf_detected is False
    assert res.waf_name is None
    assert res.num_requests == 7


def test_wafw00f_persists_results_to_selected_assessment(temp_db, test_project, tmp_path):
    adapter = WAFW00FAdapter(temp_db)
    assessment = temp_db.create_assessment(
        Assessment(
            project_id=test_project.id,
            name="WAF Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )
    adapter.runner = MagicMock()
    adapter.runner.run.return_value = ProcessExecutionResult(
        command=["wafw00f", "http://127.0.0.1"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="[+] The site http://127.0.0.1 is behind Cloudflare (Cloudflare Inc.) WAF.",
        stderr="",
        started_at="2026-10-28T00:00:00Z",
        finished_at="2026-10-28T00:00:01Z",
        duration_seconds=1.0,
    )

    success, _, findings, execution = adapter.execute_scan(
        project_id=test_project.id,
        options=WAFW00FOptions(target_url="http://127.0.0.1"),
        scopes=temp_db.list_scopes(test_project.id),
        evidence_dir=tmp_path,
        assessment_id=assessment.id,
    )

    assert success
    assert execution is not None and execution.assessment_id == assessment.id
    assert findings and all(f.assessment_id == assessment.id for f in findings)
    assert temp_db.list_evidence(test_project.id, assessment_id=assessment.id)


# ---------------------------------------------------------------------------
# Gobuster Tests
# ---------------------------------------------------------------------------

def test_gobuster_build_command(temp_db, tmp_path):
    adapter = GobusterAdapter(temp_db)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nlogin\napi\n", encoding="utf-8")

    opts = GobusterOptions(
        target_url="http://127.0.0.1:8080",
        wordlist_path=str(wordlist),
        threads=5,
        extensions="php,html",
    )
    cmd = adapter.build_command(opts, str(wordlist))
    assert "dir" in cmd
    assert "-u" in cmd
    assert "http://127.0.0.1:8080" in cmd
    assert "-w" in cmd
    assert str(wordlist) in cmd
    assert "-x" in cmd
    assert "php,html" in cmd


def test_gobuster_scope_guard_blocks_unauthorized(temp_db, test_project):
    adapter = GobusterAdapter(temp_db)
    scopes = temp_db.list_scopes(test_project.id)
    opts = GobusterOptions(target_url="http://evil-site.com")

    allowed, reason, findings, execution = adapter.execute_scan(
        project_id=test_project.id,
        options=opts,
        scopes=scopes,
    )
    assert not allowed
    assert "out of scope" in reason.lower()
    assert len(findings) == 0


def test_gobuster_parse_output(temp_db):
    adapter = GobusterAdapter(temp_db)
    sample_output = """
    ===============================================================
    Gobuster v3.6
    ===============================================================
    /admin                (Status: 301) [Size: 178] [--> http://127.0.0.1/admin/]
    /login                (Status: 200) [Size: 4523]
    /config.php           (Status: 403) [Size: 289]
    """
    endpoints = adapter.parse_output(sample_output)
    assert len(endpoints) == 3
    assert endpoints[0].path == "/admin"
    assert endpoints[0].status_code == 301
    assert endpoints[0].redirect_url == "http://127.0.0.1/admin/"
    assert endpoints[1].path == "/login"
    assert endpoints[1].status_code == 200
    assert endpoints[1].size == 4523
    assert endpoints[2].path == "/config.php"
    assert endpoints[2].status_code == 403


def test_gobuster_persists_results_to_selected_assessment(temp_db, test_project, tmp_path):
    adapter = GobusterAdapter(temp_db)
    assessment = temp_db.create_assessment(
        Assessment(
            project_id=test_project.id,
            name="Gobuster Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    adapter.runner = MagicMock()
    adapter.runner.run.return_value = ProcessExecutionResult(
        command=["gobuster", "dir", "-u", "http://127.0.0.1"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="/.env (Status: 200) [Size: 10]\n",
        stderr="",
        started_at="2026-10-28T00:00:00Z",
        finished_at="2026-10-28T00:00:01Z",
        duration_seconds=1.0,
    )

    success, _, findings, execution = adapter.execute_scan(
        project_id=test_project.id,
        options=GobusterOptions(
            target_url="http://127.0.0.1",
            wordlist_path=str(wordlist),
        ),
        scopes=temp_db.list_scopes(test_project.id),
        evidence_dir=tmp_path / "evidence",
        assessment_id=assessment.id,
    )

    assert success
    assert execution is not None and execution.assessment_id == assessment.id
    assert findings and all(f.assessment_id == assessment.id for f in findings)
    assert temp_db.list_evidence(test_project.id, assessment_id=assessment.id)


# ---------------------------------------------------------------------------
# Volatility 3 Tests
# ---------------------------------------------------------------------------

def test_volatility_build_command(temp_db, tmp_path):
    adapter = VolatilityAdapter(temp_db)
    fake_dump = tmp_path / "memory.dmp"
    fake_dump.write_bytes(b"MZ" + b"\x00" * 1024)

    opts = VolatilityOptions(memory_dump_path=str(fake_dump), plugin="windows.info")
    cmd = adapter.build_command(opts)
    assert len(cmd) >= 4
    assert "-f" in cmd
    assert str(fake_dump) in cmd
    assert "windows.info" in cmd


def test_volatility_rejects_missing_dump(temp_db, test_project):
    adapter = VolatilityAdapter(temp_db)
    opts = VolatilityOptions(memory_dump_path="/non_existent/memory.raw")

    ok, msg, findings, execution = adapter.execute_analysis(
        project_id=test_project.id,
        options=opts,
    )
    assert not ok
    assert "not found" in msg.lower()
    assert len(findings) == 0
    assert execution is None


def test_volatility_parse_output(temp_db):
    adapter = VolatilityAdapter(temp_db)
    sample_output = """
    Volatility 3 Framework 2.28.3
    Progress:  100.00
    Variable\tValue
    Major/Minor\t15.19041
    MachineType\t34404
    KeNumberProcessors\t4
    """
    lines = adapter.parse_output(sample_output, "windows.info")
    assert len(lines) == 4
    assert any("Major/Minor" in l for l in lines)


# ---------------------------------------------------------------------------
# Bandit Tests
# ---------------------------------------------------------------------------

def test_bandit_build_command(temp_db, tmp_path):
    adapter = BanditAdapter(temp_db)
    opts = BanditOptions(target_path=str(tmp_path), severity_level="high")
    cmd = adapter.build_command(opts)
    assert "bandit" in cmd[0]
    assert "-r" in cmd
    assert str(tmp_path) in cmd
    assert "-lll" in cmd


def test_bandit_rejects_missing_path(temp_db, test_project):
    adapter = BanditAdapter(temp_db)
    opts = BanditOptions(target_path="/non_existent_folder_abc_123")
    ok, msg, findings, execution = adapter.execute_scan(
        project_id=test_project.id,
        options=opts,
    )
    assert not ok
    assert "does not exist" in msg.lower()


def test_bandit_parse_output(temp_db):
    adapter = BanditAdapter(temp_db)
    sample_json = json.dumps({
        "results": [
            {
                "code": "eval(user_input)",
                "filename": "app.py",
                "issue_confidence": "HIGH",
                "issue_severity": "HIGH",
                "issue_text": "Use of possibly insecure function - eval was detected.",
                "line_number": 42,
                "test_id": "B307",
                "test_name": "blacklist",
            }
        ]
    })
    issues = adapter.parse_output(sample_json)
    assert len(issues) == 1
    assert issues[0]["test_id"] == "B307"
    assert issues[0]["line_number"] == 42
