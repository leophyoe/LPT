"""Comprehensive test suite verifying P0 and P1 security boundary fixes in CyberSecuritySuite.

Covers:
1. Hop-by-Hop Web Redirect Scope Guard (c0desec_adapter & ptk_engine).
2. Universal Adapter Lifecycle Enforcement (Nmap, SQLMap, Wafw00f, Gobuster).
3. Read-Only Report Generation (No database audit log mutation during build_report_data).
4. Evidence Secret Redaction & Project Handling (Terminal output scrub & no auto-created project).
5. OSINT Worker Thread Exception Safety.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions
from modules.web.c0desec_adapter import WebSecurityAdapter, WebScanOptions
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.ptk_engine import PTKRequestBuilder
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_sec.db"
    return Database(str(db_file))


@pytest.fixture
def active_project(test_db: Database) -> Project:
    p = test_db.create_project(
        Project(
            name="Active Authorized Engagement",
            client_name="Fintech Bank",
            status=ProjectStatus.ACTIVE,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=p.id,
            target="target.local",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=p.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return p


@pytest.fixture
def archived_project(test_db: Database) -> Project:
    p = test_db.create_project(
        Project(
            name="Archived Engagement",
            client_name="Old Client",
            status=ProjectStatus.ARCHIVED,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=p.id,
            target="192.168.1.50",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return p


# ---------------------------------------------------------------------------
# 1. Hop-by-Hop Web Redirect Scope Guard (P0)
# ---------------------------------------------------------------------------

def test_c0desec_blocks_out_of_scope_redirect_hop(test_db: Database, active_project: Project):
    """Verifies that c0desec halts with allow_redirects=False when target redirects to off-scope host."""
    adapter = WebSecurityAdapter(test_db)
    scopes = test_db.list_scopes(active_project.id)

    # Mock response 1: 302 redirect from target.local to external-malicious.com (out of scope)
    mock_resp_redirect = MagicMock()
    mock_resp_redirect.is_redirect = True
    mock_resp_redirect.status_code = 302
    mock_resp_redirect.headers = {"Location": "http://external-malicious.com/pwn"}

    with patch("requests.Session.get", return_value=mock_resp_redirect) as mock_get:
        success, msg, scan_res, exec_rec = adapter.execute_scan(
            project_id=active_project.id,
            options=WebScanOptions(target_url="http://target.local/login"),
            scopes=scopes,
            project=active_project,
        )

        assert success is False
        assert "outside authorized scope" in msg or "out of authorized scope" in msg
        assert exec_rec.status == ExecutionStatus.FAILED
        # Verify allow_redirects=False was strictly enforced
        mock_get.assert_called_once()
        assert mock_get.call_args.args == ("http://target.local/login",)
        assert mock_get.call_args.kwargs["allow_redirects"] is False


def test_ptk_engine_blocks_out_of_scope_redirect_hop(test_db: Database, active_project: Project):
    """Verifies that PTKEngine stops hop-by-hop following when redirect points to out-of-scope host."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.status_code = 301
    mock_resp.reason = "Moved Permanently"
    mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
    mock_resp.text = "Redirecting..."
    mock_resp.content = b"Redirecting..."

    with patch("requests.request", return_value=mock_resp) as mock_req:
        result = PTKRequestBuilder.send_request(
            method="GET",
            url="http://192.168.1.50/",
            allow_redirects=True,
            project=active_project,
            db=test_db,
        )

        assert result.success is False
        assert result.is_authorized is False
        assert "Scope Guard Violation on Redirect" in result.error
        # Verify requests was called with allow_redirects=False
        assert mock_req.call_args[1]["allow_redirects"] is False


# ---------------------------------------------------------------------------
# 2. Universal Adapter Lifecycle Enforcement (P1)
# ---------------------------------------------------------------------------

def test_nmap_adapter_blocks_archived_engagement(test_db: Database, archived_project: Project):
    """Verifies NmapAdapter fails closed when project lifecycle is ARCHIVED."""
    adapter = NmapAdapter(test_db)
    scopes = test_db.list_scopes(archived_project.id)

    result = adapter.execute_scan(
        project_id=archived_project.id,
        options=NmapScanOptions(target="192.168.1.50"),
        scopes=scopes,
        project=archived_project,
    )

    assert result.is_authorized is False
    assert "not active" in result.scope_reason.lower() or "archived" in result.scope_reason.lower()


def test_sqlmap_adapter_blocks_archived_engagement(test_db: Database, archived_project: Project):
    """Verifies SQLMapAdapter fails closed when project lifecycle is ARCHIVED."""
    adapter = SQLMapAdapter(test_db)
    scopes = test_db.list_scopes(archived_project.id)

    success, msg, findings, exec_rec = adapter.execute_scan(
        project_id=archived_project.id,
        options=SQLMapOptions(target_url="http://192.168.1.50/vuln.php?id=1"),
        scopes=scopes,
        project=archived_project,
    )

    assert success is False
    assert "not active" in msg.lower() or "archived" in msg.lower()
    assert exec_rec is None


def test_wafw00f_adapter_blocks_archived_engagement(test_db: Database, archived_project: Project):
    """Verifies WAFW00FAdapter fails closed when project lifecycle is ARCHIVED."""
    adapter = WAFW00FAdapter(test_db)
    scopes = test_db.list_scopes(archived_project.id)

    success, msg, findings, exec_rec = adapter.execute_scan(
        project_id=archived_project.id,
        options=WAFW00FOptions(target_url="http://192.168.1.50/"),
        scopes=scopes,
        project=archived_project,
    )

    assert success is False
    assert "not active" in msg.lower() or "archived" in msg.lower()


def test_gobuster_adapter_blocks_archived_engagement(test_db: Database, archived_project: Project):
    """Verifies GobusterAdapter fails closed when project lifecycle is ARCHIVED."""
    adapter = GobusterAdapter(test_db)
    scopes = test_db.list_scopes(archived_project.id)

    success, msg, findings, exec_rec = adapter.execute_scan(
        project_id=archived_project.id,
        options=GobusterOptions(target_url="http://192.168.1.50/"),
        scopes=scopes,
        project=archived_project,
    )

    assert success is False
    assert "not active" in msg.lower() or "archived" in msg.lower()


# ---------------------------------------------------------------------------
# 3. Read-Only Report Generation (P1)
# ---------------------------------------------------------------------------

def test_report_builder_is_strictly_read_only(test_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that calling build_report_data does NOT insert audit logs or mutate database."""
    # Add an XML evidence file with invalid content to verify safe exception handling
    corrupted_xml = tmp_path / "corrupt.xml"
    corrupted_xml.write_text("<invalid>xml", encoding="utf-8")
    test_db.add_evidence(
        Evidence(
            project_id=active_project.id,
            file_path=str(corrupted_xml),
            sha256_hash="11223344",
            mime_type="application/xml",
        )
    )

    # Initial audit log count
    logs_before = test_db.list_audit_logs(active_project.id)
    initial_count = len(logs_before)

    builder = ReportBuilder(test_db)
    report_data = builder.build_report_data(active_project.id)

    assert report_data is not None
    assert report_data.workflow_summary is not None

    # Audit logs count must be completely unchanged!
    logs_after = test_db.list_audit_logs(active_project.id)
    assert len(logs_after) == initial_count


# ---------------------------------------------------------------------------
# 4. Evidence Secret Redaction & Project Handling (P1)
# ---------------------------------------------------------------------------

def test_terminal_scrubs_secrets_from_evidence(qtbot, test_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that stdout/stderr with secrets are redacted before writing evidence files."""
    from desktop.widgets.terminal_view import TerminalWidget

    terminal = TerminalWidget(db=test_db)
    qtbot.addWidget(terminal)
    terminal.set_active_project(active_project, test_db)

    now_iso = "2026-10-23T00:00:00Z"
    mock_res = ProcessExecutionResult(
        command=["cat", "credentials.txt"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="Admin Password: SuperSecretP@ssword123!\nAPI_KEY=AIzaSyD-1234567890abcdef\n",
        stderr="",
        started_at=now_iso,
        finished_at=now_iso,
        duration_seconds=0.2,
    )

    terminal._save_command_result(mock_res, "cat credentials.txt", active_project)

    evidence_list = test_db.list_evidence(active_project.id)
    assert len(evidence_list) == 1
    ev_content = Path(evidence_list[0].file_path).read_text(encoding="utf-8")

    # Plaintext password and API key must be redacted
    assert "SuperSecretP@ssword123!" not in ev_content
    assert "[REDACTED_SECRET]" in ev_content or "[REDACTED" in ev_content


def test_terminal_does_not_auto_create_project_when_none_selected(qtbot, test_db: Database):
    """Verifies that if no project is selected, terminal does not auto-create dummy projects."""
    from desktop.widgets.terminal_view import TerminalWidget

    terminal = TerminalWidget(db=test_db)
    qtbot.addWidget(terminal)
    assert terminal.active_project is None

    now_iso = "2026-10-23T00:00:00Z"
    mock_res = ProcessExecutionResult(
        command=["ping", "127.0.0.1"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="64 bytes from 127.0.0.1...",
        stderr="",
        started_at=now_iso,
        finished_at=now_iso,
        duration_seconds=0.1,
    )

    terminal._save_command_result(mock_res, "ping 127.0.0.1", None)

    # Active project remains None and no projects are created
    assert terminal.active_project is None
    assert len(test_db.list_projects()) == 0


# ---------------------------------------------------------------------------
# 5. OSINT Worker Thread Exception Handling (P1)
# ---------------------------------------------------------------------------

def test_osint_worker_thread_exception_safety(qtbot, test_db: Database, active_project: Project):
    """Verifies that uncaught adapter errors in OSINTView thread emit failure signal and re-enable UI."""
    from desktop.views.osint_view import OSINTView

    view = OSINTView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(active_project)

    # Mock adapter that raises unexpected exception
    failing_adapter = MagicMock()
    failing_adapter.name = "failing_tool"
    failing_adapter.is_available.return_value = True
    failing_adapter.run_discovery.side_effect = RuntimeError("Simulated unhandled network crash")
    view.adapters["failing_tool"] = failing_adapter

    # Select failing tool
    idx = view.combo_source.findData("failing_tool")
    if idx >= 0:
        view.combo_source.setCurrentIndex(idx)
    else:
        view.combo_source.addItem("Failing Tool", "failing_tool")
        view.combo_source.setCurrentIndex(view.combo_source.count() - 1)

    view.txt_discovery_target.setText("target.local")

    # The completion handler shows a modal error dialog for failed results;
    # suppress it so the worker signal can be observed without blocking Qt.
    with patch("desktop.views.osint_view.QMessageBox.critical"):
        with qtbot.waitSignal(view.signals.discovery_finished, timeout=5000) as blocker:
            view._on_launch_discovery()

    # Verify discovery_finished was caught and emitted despite the RuntimeError
    result = blocker.args[0]
    assert result.status == "failed"
    assert "Simulated unhandled network crash" in result.error_message
    # UI launch button must be re-enabled
    assert view.btn_launch_discovery.isEnabled() is True
    assert view.btn_cancel_discovery.isEnabled() is False
