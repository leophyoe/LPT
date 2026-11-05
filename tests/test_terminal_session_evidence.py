"""Comprehensive Verification Tests for Phase 8: Terminal Session Evidence & Report Integration."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import json
import tempfile
from pathlib import Path

import pytest
from PySide6.QtWidgets import QMessageBox

from desktop.widgets.terminal_session_history import (
    SessionViewerDialog,
    TerminalSessionHistoryWidget,
)
from desktop.widgets.terminal_view import TerminalWidget
from desktop.widgets.vscode_terminal import VSCodeTerminal
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import Project, TargetScope, TerminalSessionRecord
from terminal.recorder import (
    TerminalSessionRecorder,
    redact_sensitive_text,
    strip_ansi,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db = Database(str(tmp_path / "phase8_test.db"))
    return db


@pytest.fixture
def test_project(test_db: Database) -> Project:
    proj = test_db.create_project(
        Project(
            name="Session Evidence Engagement",
            client_name="Acme Corp",
            description="Testing session evidence and reporting features.",
        )
    )
    test_db.add_scope(TargetScope(project_id=proj.id, target="127.0.0.1", is_authorized=True))
    return proj


def test_pty_session_recording_lifecycle(qtbot, tmp_path: Path, test_db: Database, test_project: Project, monkeypatch):
    """Verifies VSCodeTerminal PTY session recording, input/output tracking, and evidence saving."""
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    term = VSCodeTerminal(cwd=str(tmp_path))
    qtbot.addWidget(term)
    term.show()

    # Initial state without project
    assert "Disabled" in term.lbl_record_status.text()

    # Connect context
    term.set_context(test_project, test_db)
    assert "Off" in term.lbl_record_status.text()

    # Toggle start recording
    term.toggle_recording()
    assert term.recorder.is_recording
    assert "Active" in term.lbl_record_status.text()

    # Simulate PTY input and output data
    term._on_message_from_xterm(json.dumps({"type": "input", "data": "uname -a\n"}))
    term._on_pty_data("Linux workstation 6.8.0 #1 SMP Ubuntu x86_64\r\n")

    assert len(term.recorder.events) == 2
    assert term.recorder.events[0].event_type == "input"
    assert term.recorder.events[1].event_type == "output"

    # Stop recording
    term.toggle_recording()
    assert not term.recorder.is_recording
    assert "Stopped" in term.lbl_record_status.text()

    # Save session evidence
    term.save_session_evidence()

    # Verify database persistence
    sessions = test_db.list_terminal_sessions(test_project.id)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.session_id == term.recorder.session_id
    assert s.sha256_hash != ""
    assert s.evidence_id is not None

    evidence_list = test_db.list_evidence(test_project.id)
    assert len(evidence_list) == 1
    assert evidence_list[0].sha256_hash == s.sha256_hash

    # Clean up PTY process
    term.close_pty()


def test_command_shell_recording_and_vault(qtbot, tmp_path: Path, test_db: Database, test_project: Project, monkeypatch):
    """Verifies Command Shell recording, command boundary tracking, and vault table refresh."""
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    term_widget = TerminalWidget()
    qtbot.addWidget(term_widget)
    term_widget.show()

    term_widget.set_active_project(test_project, test_db)

    # Start shell recording
    term_widget.toggle_shell_recording()
    assert term_widget.shell_recorder.is_recording
    assert "Active" in term_widget.lbl_shell_rec_status.text()

    # Run command
    term_widget.cmd_input.setText("echo TestingShellRecorderOutput")
    term_widget.run_command()

    qtbot.waitUntil(lambda: "Process finished with exit code 0" in term_widget.shell_text.toPlainText(), timeout=4000)

    # Verify command was recorded with exit code
    assert len(term_widget.shell_recorder.recorded_commands) >= 1
    assert "echo" in term_widget.shell_recorder.recorded_commands[0].command
    assert term_widget.shell_recorder.recorded_commands[0].exit_code == 0

    # Stop recording
    term_widget.toggle_shell_recording()
    assert not term_widget.shell_recorder.is_recording

    # Save session evidence
    ev = term_widget.save_session_as_evidence("shell")
    assert ev is not None

    # Check Vault Table in Tab 5
    vault = term_widget.session_vault
    assert vault.table.rowCount() == 1
    assert vault.table.item(0, 0).text() == term_widget.shell_recorder.session_id


def test_session_deduplication(tmp_path: Path, test_db: Database, test_project: Project):
    """Ensures saving the same terminal session multiple times does not produce duplicate evidence records."""
    recorder = TerminalSessionRecorder(project_id=test_project.id, session_id="dedup_test_sess")
    recorder.start(project_id=test_project.id, cwd=str(tmp_path))
    recorder.record_input("whoami\n")
    recorder.record_output("cybersecurity_analyst\n")
    recorder.stop(exit_status=0)

    res1 = recorder.save_session_as_evidence(db=test_db, storage_dir=tmp_path / "ev")
    assert not res1.is_duplicate

    ev_list_1 = test_db.list_evidence(test_project.id)
    assert len(ev_list_1) == 1

    # Save a second time
    res2 = recorder.save_session_as_evidence(db=test_db, storage_dir=tmp_path / "ev")
    assert res2.is_duplicate
    assert res2.sha256_hash == res1.sha256_hash

    # Evidence count must remain 1
    ev_list_2 = test_db.list_evidence(test_project.id)
    assert len(ev_list_2) == 1
    assert ev_list_2[0].id == ev_list_1[0].id


def test_reports_include_terminal_sessions_and_redaction(tmp_path: Path, test_db: Database, test_project: Project):
    """Tests HTML, Markdown, and JSON report generation with recorded terminal sessions and secret masking."""
    recorder = TerminalSessionRecorder(project_id=test_project.id, session_id="report_sess_42")
    recorder.start(project_id=test_project.id, cwd=str(tmp_path))

    # Output containing sensitive password and token
    recorder.record_input("sqlmap -u http://127.0.0.1 -p id --password TopSecretPentestKey!\n")
    recorder.record_output("[+] Database user authenticated with password TopSecretPentestKey!\n")
    recorder.record_command("sqlmap -u http://127.0.0.1 -p id --password TopSecretPentestKey!", exit_code=0, cwd=str(tmp_path))
    recorder.stop(exit_status=0)

    res = recorder.save_session_as_evidence(db=test_db, storage_dir=tmp_path / "ev")

    # Verify original raw file preserves exact bytes without alteration
    raw_file_content = Path(res.raw_path).read_text(encoding="utf-8")
    assert "TopSecretPentestKey!" in raw_file_content

    # Generate Reports
    builder = ReportBuilder(test_db)

    # 1. Markdown Report
    md = builder.generate_markdown(test_project.id)
    assert "report_sess_42" in md
    assert res.sha256_hash[:16] in md
    assert "TopSecretPentestKey!" not in md  # Must be redacted in report!
    assert "[REDACTED_PASSWORD]" in md

    # 2. HTML Report
    html = builder.generate_html(test_project.id)
    assert "report_sess_42" in html
    assert res.sha256_hash in html
    assert "TopSecretPentestKey!" not in html  # Must be redacted in report!
    assert "[REDACTED_PASSWORD]" in html
    assert "Interactive Terminal Sessions &amp; Command Audit Trail" in html or "Interactive Terminal Sessions & Command Audit Trail" in html

    # 3. JSON Report
    json_str = builder.generate_json(test_project.id)
    parsed = json.loads(json_str)
    assert "terminal_sessions" in parsed
    assert len(parsed["terminal_sessions"]) == 1
    sess_json = parsed["terminal_sessions"][0]
    assert sess_json["session_id"] == "report_sess_42"
    assert sess_json["sha256_hash"] == res.sha256_hash
    # Redacted in commands
    assert "TopSecretPentestKey!" not in sess_json["commands"][0]["command"]
    assert "[REDACTED_PASSWORD]" in sess_json["commands"][0]["command"]


def test_session_viewer_dialog_and_missing_file_handling(qtbot, tmp_path: Path):
    """Tests the SessionViewerDialog tabs and graceful handling of missing or corrupted log files."""
    session_rec = TerminalSessionRecord(
        session_id="missing_file_sess",
        project_id=1,
        started_at="2026-10-20T10:00:00Z",
        ended_at="2026-10-20T10:05:00Z",
        working_directory="/test/dir",
        exit_status=0,
        raw_output_path=str(tmp_path / "nonexistent_raw.raw"),
        plain_text_path=str(tmp_path / "nonexistent_plain.txt"),
        sha256_hash="abcdef0123456789",
        command_count=0,
    )

    dlg = SessionViewerDialog(session_rec)
    qtbot.addWidget(dlg)
    dlg.show()

    # Verifies graceful message without crash
    assert "not found on disk" in dlg.txt_plain.toPlainText()
    assert "not found on disk" in dlg.txt_raw.toPlainText()
    dlg.close()
