"""Tests for the modern collapsible SidebarNavWidget and MainWindow routing integration.

Verifies:
1. SidebarNavWidget layout, width constraints (220px expanded, 58px collapsed), and collapse toggle.
2. Complete methodology taxonomy across WORKSPACE, PENTEST WORKFLOW, INTELLIGENCE & TOOLS, EVIDENCE & DELIVERY, and SYSTEM.
3. Expanded vs collapsed label, tooltip, and section header visibility.
4. Deep-routing to target workspaces and sub-tabs upon item selection.
5. Active project and scope context card synchronization.
6. Backward compatibility with legacy nav buttons (btn_scope_projects, btn_security_workspace, etc.).
"""

from __future__ import annotations

from pathlib import Path
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.widgets.sidebar_nav import SidebarNavItem, SidebarNavWidget
from storage.db import Database
from storage.models import Project, ProjectStatus, TargetScope, TargetType


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "sidebar_test.db"
    return Database(db_file)


def test_sidebar_nav_initial_geometry_and_collapse(qtbot):
    widget = SidebarNavWidget()
    qtbot.addWidget(widget)
    widget.show()

    assert widget.width() == SidebarNavWidget.EXPANDED_WIDTH
    assert widget.is_collapsed is False
    assert widget.lbl_brand.isVisible() is True
    assert widget.context_card.isVisible() is True

    # Test collapse
    widget.toggle_collapse()
    assert widget.is_collapsed is True
    assert widget.width() == SidebarNavWidget.COLLAPSED_WIDTH
    assert widget.lbl_brand.isVisible() is False
    assert widget.context_card.isVisible() is False
    assert widget.btn_collapse.text() == "▶"

    # Test expand
    widget.toggle_collapse()
    assert widget.is_collapsed is False
    assert widget.width() == SidebarNavWidget.EXPANDED_WIDTH
    assert widget.lbl_brand.isVisible() is True
    assert widget.context_card.isVisible() is True
    assert widget.btn_collapse.text() == "◀"


def test_sidebar_nav_contains_all_methodology_items(qtbot):
    widget = SidebarNavWidget()
    qtbot.addWidget(widget)

    # Verify all 6 methodology section headers
    expected_headers = [
        "WORKSPACE",
        "RECONNAISSANCE & OSINT",
        "NETWORK & INFRASTRUCTURE",
        "VULNERABILITY & AUDITING",
        "EXPLOITATION & DELIVERY",
        "SYSTEM",
    ]
    actual_headers = [h.text() for h in widget.section_headers]
    assert actual_headers == expected_headers

    # Verify all 20 canonical items and backward-compatible aliases
    expected_items = [
        # WORKSPACE
        "dashboard",
        "projects",
        "scope",
        "audit",
        # RECONNAISSANCE & OSINT
        "recon",
        "footprint",
        "footprinting",
        "osint",
        # NETWORK & INFRASTRUCTURE
        "enum",
        "discovery",
        "ports",
        "studio",
        "topology",
        "pcap",
        # VULNERABILITY & AUDITING
        "vuln",
        "web",
        "web_scan",
        "ad",
        "active_directory",
        "wireless_iot",
        "code_security",
        "sast",
        # EXPLOITATION & DELIVERY
        "pivoting",
        "exploit_lab",
        "findings",
        "reports",
        "evidence",
        "reports_evidence",
        # SYSTEM
        "tools",
        "ai_copilot",
        "settings",
    ]
    for item_id in expected_items:
        assert item_id in widget.nav_items, f"Missing sidebar item: {item_id}"
        item = widget.nav_items[item_id]
        assert isinstance(item, SidebarNavItem)
        assert len(item.tooltip_text) > 0

    assert hasattr(widget, "btn_settings")
    assert widget.btn_settings is not None
    assert hasattr(widget, "btn_theme")
    assert widget.btn_theme is not None


def test_sidebar_nav_routing_integration(qtbot, test_db: Database):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Route: dashboard
    window.sidebar_nav.nav_items["dashboard"].click()
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentIndex() == 1

    # Route: projects
    window.sidebar_nav.nav_items["projects"].click()
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentIndex() == 0
    assert window.projects_view.tabs.currentIndex() == 4

    # Route: scope
    window.sidebar_nav.nav_items["scope"].click()
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentIndex() == 0
    assert window.projects_view.tabs.currentIndex() == 0

    # Route: recon (Footprint)
    window.sidebar_nav.nav_items["recon"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.network_view
    assert window.network_view.tab_widget.currentIndex() == 0

    # Route: osint
    window.sidebar_nav.nav_items["osint"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.osint_view

    # Route: enum (Fingerprinting)
    window.sidebar_nav.nav_items["enum"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.network_view
    assert window.network_view.tab_widget.currentIndex() == 2

    # Route: vuln (Vuln Assessment)
    window.sidebar_nav.nav_items["vuln"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.network_view.tab_widget.currentIndex() == 3

    # Route: ad
    window.sidebar_nav.nav_items["ad"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.ad_view

    # Route: wireless_iot
    window.sidebar_nav.nav_items["wireless_iot"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.wireless_iot_view

    # Route: code_security
    window.sidebar_nav.nav_items["code_security"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.code_security_view

    # Route: exploit_lab (Simulator)
    window.sidebar_nav.nav_items["exploit_lab"].click()
    assert window.view_stack.currentIndex() == 3
    assert window.cpent_view.tabs.currentIndex() == 5

    # Route: pivoting
    window.sidebar_nav.nav_items["pivoting"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.pivoting_view

    # Route: studio (Cyber Sentinel Studio)
    window.sidebar_nav.nav_items["studio"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.topology_view

    # Route: pcap
    window.sidebar_nav.nav_items["pcap"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.network_view.tab_widget.currentWidget() == window.network_view.pcap_tab

    # Route: web
    window.sidebar_nav.nav_items["web"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.web_view

    # Route: tools
    window.sidebar_nav.nav_items["tools"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.tools_view

    # Route: findings
    window.sidebar_nav.nav_items["findings"].click()
    assert window.view_stack.currentIndex() == 2
    assert window.findings_reports_tabs.currentIndex() == 1

    # Route: evidence
    window.sidebar_nav.nav_items["evidence"].click()
    assert window.view_stack.currentIndex() == 2
    assert window.findings_reports_tabs.currentIndex() == 0
    assert window.reports_view.tabs.currentIndex() == 1

    # Route: reports
    window.sidebar_nav.nav_items["reports"].click()
    assert window.view_stack.currentIndex() == 2
    assert window.findings_reports_tabs.currentIndex() == 0
    assert window.reports_view.tabs.currentIndex() == 3

    # Route: audit
    window.sidebar_nav.nav_items["audit"].click()
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentIndex() == 0
    assert window.projects_view.tabs.currentIndex() == 3

    # Route: settings (verifies modal dialog triggers safely without double-invocation)
    from unittest.mock import patch
    with patch("desktop.dialogs.ai_settings_dialog.AISettingsDialog.exec", return_value=0) as mock_settings:
        window.sidebar_nav.nav_items["settings"].click()
        mock_settings.assert_called_once()

    # Route: aliases
    window.sidebar_nav.nav_items["footprint"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.network_view.tab_widget.currentIndex() == 0

    window.sidebar_nav.nav_items["topology"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.topology_view

    window.sidebar_nav.nav_items["active_directory"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.ad_view

    window.sidebar_nav.nav_items["sast"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.code_security_view

    # Route: 10 simplified primary workspaces
    window.sidebar_nav.nav_items["discovery"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.network_view

    window.sidebar_nav.nav_items["assessment"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.web_view

    window.sidebar_nav.nav_items["visualization"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.topology_view

    window.sidebar_nav.nav_items["terminal_tools"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.tools_view

    window.sidebar_nav.nav_items["cpent_labs"].click()
    assert window.view_stack.currentIndex() == 3
    assert window.cpent_view.tabs.currentIndex() == 5


def test_sidebar_project_context_display(qtbot, test_db: Database):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Initial state
    assert "None" in window.sidebar_nav.lbl_project_name.text()

    # Select active project
    proj = test_db.create_project(Project(name="Alpha Strike", client_name="FinCorp", status=ProjectStatus.ACTIVE))
    test_db.add_scope(TargetScope(project_id=proj.id, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE))
    test_db.add_scope(TargetScope(project_id=proj.id, target="10.0.0.0/8", target_type=TargetType.CIDR_RANGE))

    window._on_project_selected(proj)
    assert "Alpha Strike" in window.sidebar_nav.lbl_project_name.text()
    assert "2 Boundary Rules" in window.sidebar_nav.lbl_scope_count.text()

    # Unselect
    window._on_project_selected(None)
    assert "None" in window.sidebar_nav.lbl_project_name.text()
    assert "Unassigned" in window.sidebar_nav.lbl_scope_count.text()
