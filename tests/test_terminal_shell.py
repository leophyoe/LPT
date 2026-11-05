"""Tests for the interactive command shell in TerminalWidget."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import time
import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent

from desktop.widgets.terminal_view import TerminalWidget


def test_command_history_line_edit(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    input_widget = terminal.cmd_input
    input_widget.add_to_history("nmap 127.0.0.1")
    input_widget.add_to_history("sqlmap -u http://127.0.0.1")
    input_widget.add_to_history("gobuster dir -u http://127.0.0.1")

    assert len(input_widget.history) == 3

    # Up arrow retrieves last command
    key_up = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Up, Qt.KeyboardModifier.NoModifier)
    input_widget.keyPressEvent(key_up)
    assert input_widget.text() == "gobuster dir -u http://127.0.0.1"

    # Up arrow again retrieves previous command
    input_widget.keyPressEvent(key_up)
    assert input_widget.text() == "sqlmap -u http://127.0.0.1"

    # Down arrow navigates back down
    key_down = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
    input_widget.keyPressEvent(key_down)
    assert input_widget.text() == "gobuster dir -u http://127.0.0.1"


def test_terminal_builtin_cd(qtbot, tmp_path):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    original_cwd = terminal.cwd
    target_dir = str(tmp_path)

    terminal.cmd_input.setText(f"cd {target_dir}")
    terminal.run_command()

    assert terminal.cwd == target_dir
    assert target_dir in terminal.shell_text.toPlainText()

    # Invalid directory
    terminal.cmd_input.setText("cd /non_existent_folder_xyz_123")
    terminal.run_command()
    assert "No such directory" in terminal.shell_text.toPlainText()


def test_terminal_shell_executes_echo_command(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    terminal.cmd_input.setText("echo CybersecuritySuiteShellActive")
    terminal.run_command()

    # Wait for execution thread to finish
    qtbot.waitUntil(lambda: "Process finished with exit code 0" in terminal.shell_text.toPlainText(), timeout=4000)
    assert terminal.btn_run.isEnabled()
    assert not terminal.btn_stop.isEnabled()


def test_terminal_shell_handles_failed_command(qtbot):
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    # Run non-existent command
    terminal.cmd_input.setText("nonexistentcommand987xyz")
    terminal.run_command()

    qtbot.waitUntil(lambda: "Execution error" in terminal.shell_text.toPlainText() or "exited with code" in terminal.shell_text.toPlainText(), timeout=4000)
    assert terminal.btn_run.isEnabled()


def test_vscode_terminal_pty_lifecycle(qtbot, tmp_path):
    from desktop.widgets.vscode_terminal import VSCodeTerminal

    term = VSCodeTerminal(cwd=str(tmp_path))
    qtbot.addWidget(term)

    assert term.process is not None
    assert term.process.poll() is None
    assert term.master_fd is not None
    assert term.server is not None
    assert term.server.isListening()

    # Test restart
    term.restart_shell()
    assert term.process is not None
    assert term.process.poll() is None

    # Test cleanup
    term.close_pty()
    assert term.process is None
    assert term.master_fd is None


def test_terminal_save_session_as_evidence(qtbot, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    from reports.builder import ReportBuilder
    from storage.db import Database
    from storage.models import Project

    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    db = Database(str(tmp_path / "term_ev.db"))
    proj = db.create_project(Project(name="Terminal Evidence Lab"))

    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    terminal.set_active_project(proj, db)
    terminal._append_shell_text("PORT 22/tcp open ssh OpenSSH 8.2\nPORT 80/tcp open http nginx\n", "stdout")

    # Save session as evidence
    ev = terminal.save_session_as_evidence("shell")
    assert ev is not None
    assert ev.project_id == proj.id
    assert ev.file_path != ""
    assert ev.sha256_hash != ""
    assert os.path.exists(ev.file_path)

    # Verify it is recorded in database
    ev_list = db.list_evidence(proj.id)
    assert len(ev_list) == 1
    assert ev_list[0].sha256_hash == ev.sha256_hash

    # Verify it appears in generated report
    builder = ReportBuilder(db)
    md_report = builder.generate_markdown(proj.id)
    assert ev.sha256_hash in md_report


def test_terminal_ai_assistant_integration(qtbot, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    from storage.db import Database
    from storage.models import Project, TargetScope

    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    db = Database(str(tmp_path / "ai_term.db"))
    proj = db.create_project(Project(name="AI Terminal Test"))
    db.add_scope(TargetScope(project_id=proj.id, target="127.0.0.1", is_authorized=True))

    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    terminal.set_active_project(proj, db)
    assert hasattr(terminal, "ai_assistant")

    # Set mock output in terminal
    terminal.clear_shell()
    terminal._append_shell_text("21/tcp open ftp vsftpd 2.0.8\n80/tcp open http Apache\n", "stdout")

    # Test diagnosis
    terminal.ai_assistant._diagnose_terminal_output()
    diag_text = terminal.ai_assistant.txt_diagnosis.toPlainText()
    assert "Technical Analysis" in diag_text

    # Test AI command insertion
    terminal.ai_assistant._on_provider_changed(0)
    terminal.ai_assistant.cmd_prompt_input.setText("fast scan on 127.0.0.1")
    terminal.ai_assistant._generate_command()
    assert "nmap" in terminal.ai_assistant.lbl_cmd_preview.text()

    # Apply command to terminal input
    terminal.ai_assistant._insert_generated_command()
    assert "nmap" in terminal.cmd_input.text()

    # Test finding extraction and saving to DB
    terminal.ai_assistant._extract_findings()
    assert terminal.ai_assistant.findings_table.rowCount() == 2  # ftp and http

    terminal.ai_assistant._save_findings_to_db()
    findings = db.list_findings(proj.id)
    assert len(findings) == 2
    assert any("FTP" in f.title for f in findings)


def test_terminal_panel_tab_labels(qtbot):
    """Verifies that all bottom terminal panel tabs have the updated labels and icons."""
    terminal = TerminalWidget()
    qtbot.addWidget(terminal)
    terminal.show()

    tab_texts = [terminal.tabs.tabText(i) for i in range(terminal.tabs.count())]

    # Verify updated tab labels are present
    assert any(term in t for term in ("Terminal", "Command Console") for t in tab_texts)
    assert any("System Logs" in t for t in tab_texts)
    assert any("AI Analyzer" in t for t in tab_texts)
    assert any("Evidence Vault" in t for t in tab_texts)

    # Ensure none of the old outdated labels exist in tab texts
    assert not any("Interactive Terminal" in t for t in tab_texts)
    assert not any("Command Shell" in t for t in tab_texts)
    assert not any("Tool & System Logs" in t for t in tab_texts)
    assert not any("Tool _ System Logs" in t for t in tab_texts)
    assert not any("AI Copilot & Analyzer" in t for t in tab_texts)
    assert not any("AI Copilot _ Analyzer" in t for t in tab_texts)
    assert not any("Sessions & Evidence Vault" in t for t in tab_texts)
    assert not any("Sessions _ Evidence Vault" in t for t in tab_texts)

    # Verify tab tooltips
    tab_tooltips = [terminal.tabs.tabToolTip(i) for i in range(terminal.tabs.count())]
    assert any(term in tt for term in ("Terminal", "Command Console") for tt in tab_tooltips)
    assert any("System & Tool Execution Logs" in tt for tt in tab_tooltips)
    assert any("AI Security Analyzer" in tt for tt in tab_tooltips)
    assert any("Evidence Vault" in tt for tt in tab_tooltips)

    # Verify switching to Terminal via AI callback works
    terminal._on_ai_command_ready("whoami")
    current_tab = terminal.tabs.tabText(terminal.tabs.currentIndex())
    assert any(term in current_tab for term in ("Terminal", "Command Console"))
    assert terminal.cmd_input.text() == "whoami"



