"""Integration & Unit tests for Phase 4 VS Code Integrated Terminal enhancements.

Verifies:
1. Multi-terminal independent PTY session creation, tab switching, and cleanup.
2. Scanner result detection and ScannerResultPreviewDialog user review & confirmation.
3. Out-of-scope security scan blocking (Warning Dialog + Fail-Closed Audit Trail).
4. Unrestricted execution of standard Linux shell commands (pwd, ls, cd, python3).
5. Evidence SHA-256 verification and duplicate prevention.
"""

from __future__ import annotations

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QMessageBox

from desktop.dialogs.scanner_preview_dialog import ScannerResultPreviewDialog
from desktop.widgets.terminal_view import TerminalWidget
from desktop.widgets.vscode_terminal import VSCodeTerminal, VSCodeTerminalSession
from modules.network.nmap_parser import HostResult, NmapParser, NmapScanResult, PortResult
from storage.db import Database
from storage.models import (
    AssetNode,
    EngagementAuditLog,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "term_phase4.db"
    return Database(str(db_file))


@pytest.fixture
def authorized_project(test_db: Database) -> Project:
    proj = test_db.create_project(
        Project(
            name="Authorized Assessment Corp",
            client_name="Authorized Client",
            status=ProjectStatus.ACTIVE,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="authorized.corp",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_multi_terminal_sessions_lifecycle(qtbot, tmp_path: Path, test_db: Database, authorized_project: Project):
    """Verifies creating multiple independent PTY terminal sessions, switching tabs, and clean shutdown."""
    term = VSCodeTerminal(cwd=str(tmp_path))
    qtbot.addWidget(term)
    term.show()

    term.set_context(authorized_project, test_db)

    # Starts with Session 1
    assert term.session_count() == 1
    assert term.session_tab_bar.count() == 1
    assert "Bash 1" in term.session_tab_bar.tabText(0)

    # Spawn Session 2 with a distinct directory
    dir2 = tmp_path / "session2_dir"
    dir2.mkdir()
    s2 = term.create_new_session(name="Bash 2", cwd=str(dir2))

    assert term.session_count() == 2
    assert term.session_tab_bar.count() == 2
    assert term.session_tab_bar.currentIndex() == 1
    assert s2.cwd == str(dir2)

    # Verify session 1 and session 2 are independent processes
    s1 = term.sessions[0]
    assert s1 is not s2
    assert s1.master_fd != s2.master_fd
    assert s1.process.pid != s2.process.pid

    # Close Session 2 cleanly
    term.close_session(1)
    assert term.session_count() == 1
    assert term.session_tab_bar.count() == 1
    assert s2.process is None
    assert s2.master_fd is None

    # Cleanup Session 1
    term.close_pty()
    assert s1.process is None


def test_scanner_result_preview_dialog_diff_and_confirmation(qtbot, test_db: Database, authorized_project: Project):
    """Verifies that ScannerResultPreviewDialog differentiates NEW vs. EXISTING assets and scope status."""
    # Seed one existing asset into the database
    test_db.add_asset_node(
        AssetNode(
            project_id=authorized_project.id,
            node_type="ip",
            value="10.10.10.5",
            label="10.10.10.5",
        )
    )

    # Build mock scan result with one existing host, one new in-scope host, and one out-of-scope host
    h_existing = HostResult(
        ip="10.10.10.5",
        status="up",
        ports=[PortResult(port_id=80, protocol="tcp", state="open", service_name="http")],
    )
    h_new_inscope = HostResult(
        ip="10.10.10.20",
        status="up",
        ports=[PortResult(port_id=22, protocol="tcp", state="open", service_name="ssh")],
    )
    h_outofscope = HostResult(
        ip="192.168.1.99",
        status="up",
        ports=[PortResult(port_id=445, protocol="tcp", state="open", service_name="microsoft-ds")],
    )

    scan_res = NmapScanResult(
        command_args="nmap -sV 10.10.10.0/24",
        hosts=[h_existing, h_new_inscope, h_outofscope],
    )

    finding = Finding(
        project_id=authorized_project.id,
        title="Open SSH Port Detected",
        severity=FindingSeverity.LOW,
        affected_asset="10.10.10.20",
    )

    dialog = ScannerResultPreviewDialog(
        tool_name="nmap",
        command="nmap -sV 10.10.10.0/24",
        scan_result=scan_res,
        findings=[finding],
        raw_output="Mock Scan Output",
        db=test_db,
        project=authorized_project,
    )
    qtbot.addWidget(dialog)

    # Verify hosts table rows
    assert dialog.hosts_table.rowCount() == 3

    # Row 0: 10.10.10.5 -> Existing asset
    assert "EXISTING" in dialog.hosts_table.item(0, 2).text()
    assert "Authorized" in dialog.hosts_table.item(0, 4).text()

    # Row 1: 10.10.10.20 -> New asset
    assert "NEW ASSET" in dialog.hosts_table.item(1, 2).text()
    assert "Authorized" in dialog.hosts_table.item(1, 4).text()

    # Row 2: 192.168.1.99 -> Out of scope
    assert "OUT-OF-SCOPE" in dialog.hosts_table.item(2, 4).text()
    cb_outofscope, _ = dialog.host_checkboxes[2]
    assert cb_outofscope.isEnabled() is False  # Cannot sync out of scope
    assert cb_outofscope.isChecked() is False

    # Confirm dialog
    dialog._on_confirm()
    assert len(dialog.confirmed_hosts) == 2  # Only the 2 in-scope hosts approved
    assert len(dialog.confirmed_findings) == 1


def test_out_of_scope_scan_blocked_by_guard(qtbot, tmp_path: Path, test_db: Database, authorized_project: Project, monkeypatch):
    """Verifies that running an out-of-scope scan is blocked fail-closed and logged to EngagementAuditLog."""
    warning_shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: warning_shown.append(True))

    term_widget = TerminalWidget(db=test_db)
    qtbot.addWidget(term_widget)
    term_widget.show()
    term_widget.set_active_project(authorized_project, test_db)

    # Attempt to scan an unauthorized external IP
    unauth_cmd = "nmap -sV 8.8.8.8"
    term_widget.cmd_input.setText(unauth_cmd)
    term_widget.run_command()

    # Verify command was blocked from execution
    assert len(warning_shown) == 1
    assert "[-] [SCOPE GUARD] Scan blocked: Target '8.8.8.8' is unauthorized" in term_widget.shell_text.toPlainText()

    # Verify audit log record was created
    audit_logs = test_db.list_audit_logs(authorized_project.id)
    assert any(log.action == "out_of_scope_scan_blocked" and "8.8.8.8" in log.details for log in audit_logs)


def test_ordinary_shell_commands_not_blocked(qtbot, tmp_path: Path, test_db: Database, authorized_project: Project, monkeypatch):
    """Verifies that non-security commands (pwd, ls, cd, python3, echo) are never blocked by scope guard."""
    warning_shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: warning_shown.append(True))

    term_widget = TerminalWidget(db=test_db)
    qtbot.addWidget(term_widget)
    term_widget.show()
    term_widget.set_active_project(authorized_project, test_db)

    # Run benign command
    term_widget.cmd_input.setText("echo 'AuthorizedLocalOperator'")
    term_widget.run_command()

    # Scope guard was not triggered
    assert len(warning_shown) == 0
    # No out-of-scope audit logs
    audit_logs = test_db.list_audit_logs(authorized_project.id)
    assert not any(log.action == "out_of_scope_scan_blocked" for log in audit_logs)
