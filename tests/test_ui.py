"""GUI tests for PySide6 MainWindow using pytest-qt."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from unittest.mock import patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QMessageBox
from desktop.main_window import MainWindow
from desktop.views.projects_view import NewProjectDialog
from storage.db import Database
from storage.models import Project, ProjectStatus, TargetScope, TargetType


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_main_window_initialization(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Check window title and consolidated 4 workspaces
    assert "CyberSecuritySuite" in window.windowTitle()
    assert window.view_stack.count() == 4
    assert window.view_stack.currentIndex() == 0  # Scope & Projects is the default home
    assert window.btn_scope_projects.text().endswith("Projects")
    assert window.btn_security_workspace.text().endswith("Assessment")
    assert window.btn_findings_reports.text().endswith("Reports")
    assert window.btn_cpent_labs.text().endswith("Labs & Playbooks")

    # Verify all 9 functional views are preserved and instantiated
    assert hasattr(window, "projects_view")
    assert hasattr(window, "dashboard_view")
    assert hasattr(window, "ai_chat_view")
    assert hasattr(window, "network_view")
    assert hasattr(window, "web_view")
    assert hasattr(window, "osint_view")
    assert hasattr(window, "tools_view")
    assert hasattr(window, "findings_view")
    assert hasattr(window, "cpent_view")
    assert hasattr(window, "terminal_widget")
    assert hasattr(window, "topology_view")

    # Verify status bar
    assert "Nmap: Ready" in window.status_nmap_label.text()
    assert "Project: None" in window.status_project_label.text()


def test_main_window_navigation(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Click Security Workspace button
    qtbot.mouseClick(window.btn_security_workspace, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 1

    # Click Findings & Reports button
    qtbot.mouseClick(window.btn_findings_reports, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 2

    # Click CPENT Labs button
    qtbot.mouseClick(window.btn_cpent_labs, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 3

    # Click Scope & Projects button
    qtbot.mouseClick(window.btn_scope_projects, Qt.MouseButton.LeftButton)
    assert window.view_stack.currentIndex() == 0

    # Test targeted sub-navigation across workspaces
    window._navigate_to_workspace_subtab(1, 0)  # Network Recon in Security Workspace
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.network_view

    window._navigate_to_workspace_subtab(1, 1)  # Web & API in Security Workspace
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.web_view

    window._navigate_to_workspace_subtab(0, 1)  # Engagement Dashboard in Scope Workspace
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentWidget() == window.dashboard_view


def test_project_selection_updates_views_and_terminal(qtbot, test_db):
    # Create a project directly in test DB
    project = test_db.create_project(Project(name="Test Assessment Alpha", client_name="TestCorp"))
    assert project.id is not None

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Reload and select the project
    window.projects_view.load_projects()
    window.projects_view.select_project_by_id(project.id)

    # Check status bar update
    assert "Test Assessment Alpha" in window.status_project_label.text()
    assert window.network_view.active_project is not None
    assert window.network_view.active_project.name == "Test Assessment Alpha"
    assert window.web_view.active_project is not None
    assert window.web_view.active_project.name == "Test Assessment Alpha"

    # Verify message in terminal
    terminal_text = window.terminal_widget.text_edit.toPlainText()
    assert "Active project switched to: 'Test Assessment Alpha'" in terminal_text


def test_project_edit_saves_details_and_refreshes_active_views(qtbot, test_db):
    project = test_db.create_project(Project(name="Before Edit", client_name="Old Client"))
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.projects_view.select_project_by_id(project.id)

    updated_details = {
        "name": "After Edit",
        "client_name": "New Client",
        "engagement_id": "ENG-42",
        "sow_reference": "SOW-42",
        "lead_tester": "Tester",
        "emergency_contact": "SOC",
        "start_date": "2026-10-01",
        "end_date": "2026-10-31",
        "description": "Updated engagement scope",
    }
    with (
        patch.object(NewProjectDialog, "exec", return_value=QDialog.DialogCode.Accepted),
        patch.object(NewProjectDialog, "get_data", return_value=updated_details),
    ):
        window.projects_view._on_edit_project()

    saved = test_db.get_project(project.id)
    assert saved is not None
    assert saved.name == "After Edit"
    assert saved.client_name == "New Client"
    assert saved.engagement_id == "ENG-42"
    assert saved.description == "Updated engagement scope"
    assert window.active_project.name == "After Edit"
    assert "After Edit" in window.status_project_label.text()
    assert any(log.action == "project_details_updated" for log in test_db.list_audit_logs(project.id))


def test_archiving_project_preserves_records_and_blocks_reactivation(qtbot, test_db):
    project = test_db.create_project(Project(name="Keep My Records"))
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.0.2.10",
            target_type=TargetType.IP_ADDRESS,
        )
    )
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.projects_view.select_project_by_id(project.id)

    with patch(
        "desktop.views.projects_view.QMessageBox.question",
        return_value=QMessageBox.StandardButton.Yes,
    ):
        window.projects_view._on_archive_project()

    saved = test_db.get_project(project.id)
    assert saved is not None
    assert saved.status == ProjectStatus.ARCHIVED
    assert len(test_db.list_scopes(project.id)) == 1
    assert window.projects_view.btn_archive_project.isEnabled() is False
    assert any(log.action == "project_archived" for log in test_db.list_audit_logs(project.id))


def test_edit_project_dialog_prefills_and_returns_saved_fields(qtbot):
    project = Project(
        name="Existing Project",
        client_name="Client",
        engagement_id="ENG-5",
        description="Original objectives",
    )
    dialog = NewProjectDialog(project=project)
    qtbot.addWidget(dialog)

    assert dialog.windowTitle() == "Edit Project Details"
    assert dialog.name_input.text() == "Existing Project"
    assert dialog.client_input.text() == "Client"
    assert dialog.eng_id_input.text() == "ENG-5"
    assert dialog.desc_input.toPlainText() == "Original objectives"

    dialog.name_input.setText("Updated Project")
    assert dialog.get_data()["name"] == "Updated Project"


def test_terminal_widget_operations(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    terminal = window.terminal_widget
    terminal.append_output("Standard output line\n", "stdout")
    terminal.append_output("Error alert line\n", "stderr")
    terminal.append_system_msg("System ready")

    content = terminal.text_edit.toPlainText()
    assert "Standard output line" in content
    assert "Error alert line" in content
    assert "System ready" in content

    # Test clear
    terminal.clear()
    assert terminal.text_edit.toPlainText() == ""


def test_main_window_ai_settings_button(qtbot, test_db):
    from unittest.mock import patch
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    assert hasattr(window, "btn_ai_settings")
    with patch("desktop.dialogs.ai_settings_dialog.AISettingsDialog.exec", return_value=0) as mock_exec:
        qtbot.mouseClick(window.btn_ai_settings, Qt.MouseButton.LeftButton)
        mock_exec.assert_called_once()


def test_main_window_terminal_tab_switching(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Switch away from console tab
    window.terminal_widget.tabs.setCurrentIndex(window.terminal_widget.tabs.count() - 1)

    # Test _on_open_shell_requested
    window._on_open_shell_requested("nmap", "nmap -sV 127.0.0.1")
    current_tab = window.terminal_widget.tabs.tabText(window.terminal_widget.tabs.currentIndex())
    assert any(term in current_tab for term in ("Terminal", "Command Console"))
    assert window.terminal_widget.cmd_input.text() == "nmap -sV 127.0.0.1"

    # Switch away again and test _on_ai_command_to_shell
    window.terminal_widget.tabs.setCurrentIndex(window.terminal_widget.tabs.count() - 1)
    window._on_ai_command_to_shell("nikto -h http://127.0.0.1")
    current_tab = window.terminal_widget.tabs.tabText(window.terminal_widget.tabs.currentIndex())
    assert any(term in current_tab for term in ("Terminal", "Command Console"))
    assert window.terminal_widget.cmd_input.text() == "nikto -h http://127.0.0.1"


def test_startup_selects_active_project_and_propagates_to_all_views(qtbot, test_db):
    """Verify that an existing active project is auto-selected on startup and propagates to all views."""
    # Seed multiple projects: an older paused one and a newer active one
    p_paused = test_db.create_project(Project(name="Paused Engagement", client_name="Client Alpha", status=ProjectStatus.PAUSED))
    p_active = test_db.create_project(Project(name="Active Pentest", client_name="Client Beta", status=ProjectStatus.ACTIVE))

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Active project must be preferred over paused project
    assert window.active_project is not None
    assert window.active_project.id == p_active.id
    assert window.active_project.name == "Active Pentest"

    # Status bar
    assert "Active Pentest" in window.status_project_label.text()
    assert "Client Beta" in window.status_project_label.text()

    # Network view
    assert window.network_view.active_project is not None
    assert window.network_view.active_project.id == p_active.id
    assert "Active Pentest" in window.network_view.project_label.text()

    # Web view
    assert window.web_view.active_project is not None
    assert window.web_view.active_project.id == p_active.id
    assert "Active Pentest" in window.web_view.project_label.text()

    # Findings view
    assert window.findings_view.active_project_id == p_active.id

    # Dashboard view
    assert window.dashboard_view.active_project is not None
    assert window.dashboard_view.active_project.id == p_active.id

    # AI Chat view
    assert window.ai_chat_view.active_project is not None
    assert window.ai_chat_view.active_project.id == p_active.id
    assert "Active Pentest" in window.ai_chat_view.lbl_context.text()

    # OSINT view
    assert window.osint_view.active_project is not None
    assert window.osint_view.active_project.id == p_active.id
    assert "Active Pentest" in window.osint_view.lbl_project_status.text()

    # Terminal widget
    assert window.terminal_widget.active_project is not None
    assert window.terminal_widget.active_project.id == p_active.id
    terminal_text = window.terminal_widget.text_edit.toPlainText()
    assert "Active project switched to: 'Active Pentest'" in terminal_text

    # Projects view row synchronization
    assert window.projects_view.active_project is not None
    assert window.projects_view.active_project.id == p_active.id


def test_startup_no_projects_produces_safe_none_state(qtbot, test_db):
    """Verify that startup with an empty database produces a safe None state across all views."""
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    assert window.active_project is None
    assert "Project: None" in window.status_project_label.text()
    assert window.network_view.active_project is None
    assert "No project" in window.network_view.project_label.text()
    assert window.web_view.active_project is None
    assert "No project" in window.web_view.project_label.text()
    assert window.findings_view.active_project_id is None
    assert window.dashboard_view.active_project is None
    assert window.terminal_widget.active_project is None


def test_startup_fallback_when_no_active_project(qtbot, test_db):
    """Verify that startup gracefully falls back to the existing project when none is active."""
    p_draft = test_db.create_project(Project(name="Draft Assessment", status=ProjectStatus.DRAFT))
    p_paused = test_db.create_project(Project(name="Paused Assessment", status=ProjectStatus.PAUSED))

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Should select one of the available projects without error and without altering its status in DB
    assert window.active_project is not None
    assert window.active_project.id in (p_draft.id, p_paused.id)

    db_draft = test_db.get_project(p_draft.id)
    assert db_draft.status == ProjectStatus.DRAFT
    db_paused = test_db.get_project(p_paused.id)
    assert db_paused.status == ProjectStatus.PAUSED


def test_manual_project_selection_continues_to_work_and_synchronizes(qtbot, test_db):
    """Verify manual project switching updates all views and avoids duplicate or recursive events."""
    p1 = test_db.create_project(Project(name="Engagement One", status=ProjectStatus.ACTIVE))
    p2 = test_db.create_project(Project(name="Engagement Two", status=ProjectStatus.ACTIVE))

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Switch manually to project 1
    window.projects_view.select_project_by_id(p1.id)
    assert window.active_project.id == p1.id
    assert "Engagement One" in window.status_project_label.text()
    assert window.network_view.active_project.id == p1.id
    assert window.web_view.active_project.id == p1.id
    assert window.findings_view.active_project_id == p1.id

    # Switch manually to project 2
    window.projects_view.select_project_by_id(p2.id)
    assert window.active_project.id == p2.id
    assert "Engagement Two" in window.status_project_label.text()
    assert window.network_view.active_project.id == p2.id
    assert window.web_view.active_project.id == p2.id
    assert window.findings_view.active_project_id == p2.id


def test_preserves_already_established_project_on_startup(qtbot, test_db):
    """Verify that an explicitly established project before startup hook is preserved."""
    p1 = test_db.create_project(Project(name="Default One", status=ProjectStatus.ACTIVE))
    p2 = test_db.create_project(Project(name="Preselected Two", status=ProjectStatus.ACTIVE))

    # Simulate established project before _select_initial_project is called
    window = MainWindow.__new__(MainWindow)
    window.db = test_db
    window.registry = None
    window.active_project = p2
    # Calling _select_initial_project must not overwrite established active_project
    window._select_initial_project()
    assert window.active_project.id == p2.id


def test_ui_label_consistency(qtbot, test_db):
    """Verifies that all user-facing product labels conform to the simplified UI terminology."""
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)

    # 1. Core Navigation Sidebar
    assert "Projects" in window.btn_scope_projects.text()
    assert "Assessment" in window.btn_security_workspace.text()
    assert "Reports" in window.btn_findings_reports.text()
    assert "Labs & Playbooks" in window.btn_cpent_labs.text()

    # 2. Security Workspace Tabs
    tab_labels = [window.security_tabs.tabText(i) for i in range(window.security_tabs.count())]
    assert any("Network Discovery" in t for t in tab_labels)
    assert any("Tools" in t and "Security Tools" not in t for t in tab_labels)
    assert any("Network Map" in t for t in tab_labels)
    assert "AI Assistant" in window.btn_ai_chat.text()

    # 3. Network Discovery Sub-tabs
    net_tab_labels = [window.network_view.tab_widget.tabText(i) for i in range(window.network_view.tab_widget.count())]
    assert any("Activity & Evidence" in t for t in net_tab_labels)

    # 4. Tools Dashboard Tabs
    tool_tab_labels = [window.tools_view.tabs.tabText(i) for i in range(window.tools_view.tabs.count())]
    assert any("Tools Matrix" in t for t in tool_tab_labels)
    assert any("Tools Catalog" in t for t in tool_tab_labels)

    # 5. Report Generator View
    assert hasattr(window.findings_view, "btn_export_pdf")
    assert "Export PDF" in window.findings_view.btn_export_pdf.text()
