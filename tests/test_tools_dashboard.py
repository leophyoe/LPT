"""Tests for ToolsDashboardView and tool integration inventory."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from core.registry import ToolRegistry
from desktop.views.tools_view import ToolsDashboardView
from storage.db import Database


@pytest.fixture
def db():
    return Database(":memory:")


def test_tools_dashboard_initialization_and_metrics(qtbot, db):
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    # Verify table has rows matching tools count
    reg = ToolRegistry()
    assert view.table.rowCount() == len(reg.list_tools())
    assert view.table.columnCount() == 8

    # Verify metric cards are populated
    all_tools = reg.list_tools()
    installed_count = sum(1 for t in all_tools if t.is_installed)
    missing_count = len(all_tools) - installed_count

    assert int(view.card_total.findChildren(object)[-1].text()) == len(all_tools)
    assert int(view.card_installed.findChildren(object)[-1].text()) == installed_count
    assert int(view.card_missing.findChildren(object)[-1].text()) == missing_count


def test_tools_dashboard_search_and_category_filtering(qtbot, db):
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    # Search for nmap
    view.search_input.setText("nmap")
    assert view.table.rowCount() == 1
    assert "Nmap" in view.table.item(0, 0).text()

    # Clear search
    view.search_input.clear()
    assert view.table.rowCount() > 10

    # Filter by category: Network
    view.cat_filter.setCurrentText("Network")
    assert view.table.rowCount() >= 2
    for r in range(view.table.rowCount()):
        assert "Network" in view.table.item(r, 1).text()

    # Filter by category: Web
    view.cat_filter.setCurrentText("Web")
    assert view.table.rowCount() >= 3
    for r in range(view.table.rowCount()):
        assert "Web" in view.table.item(r, 1).text()

    # Reset
    view.cat_filter.setCurrentText("All Categories")


def test_tools_dashboard_status_filtering(qtbot, db):
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    # Filter by Installed
    view.status_filter.setCurrentText("Installed")
    for r in range(view.table.rowCount()):
        assert view.table.item(r, 2).text() == "Installed"

    # Filter by Missing
    view.status_filter.setCurrentText("Missing")
    for r in range(view.table.rowCount()):
        assert view.table.item(r, 2).text() in ("Missing", "Source Unbuilt")


def test_tools_dashboard_selection_populates_details(qtbot, db):
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    # Select Nmap (row 0 or find it)
    view.search_input.setText("nmap")
    assert view.table.rowCount() == 1
    view.table.selectRow(0)

    assert "Nmap" in view.lbl_tool_title.text()
    assert "Network exploration" in view.lbl_tool_desc.text()
    assert view.btn_test.isEnabled()
    assert view.btn_open_gui.isEnabled()
    assert "sudo apt install nmap" in view.txt_install.toPlainText()


def test_tools_dashboard_open_gui_signal(qtbot, db):
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    view.search_input.setText("nmap")
    view.table.selectRow(0)

    with qtbot.waitSignal(view.open_scanner_requested, timeout=2000) as blocker:
        view.btn_open_gui.click()

    assert blocker.args == ["nmap"]


def test_tools_dashboard_available_and_unavailable_quick_filters(qtbot, db):
    """Verify quick filters isolate installed tools and unavailable installation guides."""
    view = ToolsDashboardView(db=db)
    qtbot.addWidget(view)
    view.show()

    # Click available tools button
    view.btn_filter_installed.click()
    assert view.status_filter.currentText() == "Installed"
    for r in range(view.table.rowCount()):
        assert view.table.item(r, 2).text() == "Installed"

    # Click unavailable tools button
    view.btn_filter_missing.click()
    assert view.status_filter.currentText() == "Missing"
    for r in range(view.table.rowCount()):
        assert view.table.item(r, 2).text() in ("Missing", "Source Unbuilt")

    # Reset to all tools
    view.btn_filter_all.click()
    assert view.status_filter.currentText() == "All Statuses"
    assert view.table.rowCount() > 20
