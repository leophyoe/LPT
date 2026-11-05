"""Unit and UI tests for WebScanView."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QSignalSpy
from desktop.views.web_scan_view import WebScanView
from modules.web.c0desec_adapter import WebScanResult
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
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_web_scan_view_initial_state(qtbot, test_db):
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert "No project selected" in view.project_label.text()
    assert "No Project Selected" in view.scope_status_label.text()
    assert view.scan_btn.isEnabled()
    assert not view.cancel_btn.isEnabled()
    assert view.cb_headers.isChecked()
    assert view.cb_cors.isChecked()
    assert view.cb_secrets.isChecked()
    assert view.cb_endpoints.isChecked()
    assert view.findings_table.rowCount() == 0
    assert view.endpoints_table.rowCount() == 0
    assert view.secrets_table.rowCount() == 0
    assert view.headers_table.rowCount() == 0


def test_web_scan_view_set_active_project(qtbot, test_db):
    project = test_db.create_project(Project(name="Web Target Engagement", client_name="Acme"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view.set_active_project(project)
    assert "Web Target Engagement" in view.project_label.text()
    assert str(project.id) in view.project_label.text()

    view.set_active_project(None)
    assert "No project selected" in view.project_label.text()


def test_web_scan_view_live_scope_validation(qtbot, test_db):
    project = test_db.create_project(Project(name="Live Scope Test"))
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="targetlab.corp",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        )
    )

    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)

    # 1. Initially awaiting URL
    assert "Awaiting Target URL" in view.scope_status_label.text()

    # 2. Type in-scope URL
    view.url_input.setText("https://targetlab.corp/api")
    assert "Authorized (In-Scope) ✓" in view.scope_status_label.text()

    # 3. Type out-of-scope URL
    view.url_input.setText("https://evil.external.corp/login")
    assert "Unauthorized / Out of Scope ✗" in view.scope_status_label.text()


def test_web_scan_view_validation_without_url(qtbot, test_db, monkeypatch):
    project = test_db.create_project(Project(name="Acme Web Project"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)

    # Mock QMessageBox to prevent blocking
    warn_calls = []
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, msg: warn_calls.append((title, msg)))

    # Empty URL click
    view.url_input.setText("")
    qtbot.mouseClick(view.scan_btn, Qt.MouseButton.LeftButton)
    assert len(warn_calls) == 1
    assert "Input Error" in warn_calls[0][0]


def test_web_scan_view_populates_findings_and_details(qtbot, test_db):
    project = test_db.create_project(Project(name="Findings UI Test"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)

    dummy_finding = Finding(
        project_id=project.id,
        title="Missing Content-Security-Policy (CSP) Header",
        severity=FindingSeverity.MEDIUM,
        cvss_score=4.3,
        affected_asset="127.0.0.1",
        description="Absence of CSP reduces defense-in-depth against XSS.",
        remediation="Implement a restrictive Content-Security-Policy header.",
        validation_status=ValidationStatus.CONFIRMED,
        source_tool="c0desec",
    )

    res = WebScanResult(
        target_url="http://127.0.0.1:8080",
        endpoints=["http://127.0.0.1:8080/admin"],
        findings=[dummy_finding],
    )

    exec_mock = MagicMock()
    exec_mock.status.value = "completed"

    view._on_scan_completed(
        success=True,
        message="Success",
        result=res,
        execution=exec_mock,
    )

    # Verify findings table has 1 row
    assert view.findings_table.rowCount() == 1
    assert view.findings_table.item(0, 0).text() == "MEDIUM"
    assert view.findings_table.item(0, 2).text() == "Missing Content-Security-Policy (CSP) Header"

    # Select row and verify details panel updates
    view.findings_table.selectRow(0)
    view._on_finding_selected()
    details_content = view.finding_details_text.toPlainText()
    assert "Missing Content-Security-Policy" in details_content
    assert "CVSS: 4.3" in details_content
    assert "Absence of CSP reduces defense-in-depth" in details_content


def test_completed_web_scan_signals_project_data_refresh(qtbot, test_db):
    project = test_db.create_project(Project(name="Web Data Refresh"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(project)
    spy = QSignalSpy(view.project_data_updated)

    execution = MagicMock()
    execution.status = ExecutionStatus.COMPLETED
    result = WebScanResult(target_url="http://127.0.0.1")

    view._on_scan_completed(True, "completed", result, execution)

    assert spy.count() == 1


def test_web_scan_active_tools_require_confirmation(qtbot, test_db, monkeypatch):
    project = test_db.create_project(Project(name="Active Guard Project"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)
    view.url_input.setText("http://127.0.0.1:8080")

    # Enable active SQLMap check
    view.cb_sqlmap.setChecked(True)

    questions = []
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: (questions.append(args), QMessageBox.StandardButton.No)[1],
    )

    qtbot.mouseClick(view.scan_btn, Qt.MouseButton.LeftButton)
    assert len(questions) == 1
    assert "Active Security Assessment" in str(questions[0])
    assert "Active scan aborted by user" in view.status_label.text()


def test_web_scan_worker_uses_captured_project_and_assessment(qtbot, test_db, monkeypatch):
    project = test_db.create_project(Project(name="Captured Web Scan"))
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    )
    assessment = test_db.create_assessment(
        Assessment(
            project_id=project.id,
            name="Local Web Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(project)
    view.url_input.setText("http://127.0.0.1")
    for checkbox in (view.cb_headers, view.cb_cors, view.cb_secrets, view.cb_endpoints):
        checkbox.setChecked(False)

    calls = []
    execution = ToolExecution(
        project_id=project.id,
        tool_name="wafw00f",
        command="wafw00f http://127.0.0.1",
        status=ExecutionStatus.COMPLETED,
    )

    def run_waf(**kwargs):
        calls.append(kwargs)
        return True, "completed", [], execution

    class ImmediateThread:
        def __init__(self, target, daemon=True):
            self.target = target

        def start(self):
            self.target()

        def is_alive(self):
            return False

    import desktop.views.web_scan_view as web_scan_module
    monkeypatch.setattr(
        web_scan_module,
        "threading",
        SimpleNamespace(Thread=ImmediateThread),
    )
    monkeypatch.setattr(view.wafw00f_adapter, "execute_scan", run_waf)
    with qtbot.waitSignal(view.signals.scan_completed, timeout=3000):
        view._start_scan()
    qtbot.waitUntil(
        lambda: (
            view.scan_btn.isEnabled()
            and view.status_label.text() == "Status: Assessment completed successfully"
            and view._scan_thread is not None
            and not view._scan_thread.is_alive()
        ),
        timeout=3000,
    )

    assert len(calls) == 1
    assert calls[0]["project_id"] == project.id
    assert calls[0]["assessment_id"] == assessment.id
    assert [scope.target for scope in calls[0]["scopes"]] == ["127.0.0.1"]
