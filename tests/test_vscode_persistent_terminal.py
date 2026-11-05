"""Unit & Integration tests for the VS Code-style Persistent Bottom Terminal."""

from __future__ import annotations

import pytest
from PySide6.QtCore import Qt

from desktop.main_window import MainWindow
from storage.db import Database


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_term.db"
    return Database(str(db_file))


def test_persistent_terminal_visible_on_startup(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.resize(1280, 800)
    window.show()

    assert hasattr(window, "content_splitter")
    assert hasattr(window, "terminal_widget")
    assert window.content_splitter.count() == 2
    assert window.content_splitter.widget(0) == window.view_stack
    assert window.content_splitter.widget(1) == window.terminal_widget

    sizes = window.content_splitter.sizes()
    assert len(sizes) == 2
    assert sizes[0] > 200  # Workspace is visible
    assert sizes[1] > 50   # Terminal is visible on startup
    assert window._terminal_visible is True


def test_terminal_persists_across_all_workspaces(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.resize(1280, 800)
    window.show()

    initial_term_instance = window.terminal_widget
    initial_text_edit = window.terminal_widget.shell_text

    # Write a test command in the terminal to verify session preservation
    window.terminal_widget.cmd_input.setText("echo 'Session Active'")

    methodology_routes = [
        "dashboard",
        "projects",
        "info_gathering",
        "enumeration",
        "vulnerability",
        "post_exploitation",
        "reporting",
        "terminal_tools",
        "cpent_labs",
    ]

    for route in methodology_routes:
        window._on_sidebar_route_requested(route)
        sizes = window.content_splitter.sizes()
        # Verify terminal remains open and visible with sufficient height
        assert sizes[1] > 50, f"Terminal collapsed on route: {route}"
        # Verify terminal widget was NOT recreated
        assert window.terminal_widget is initial_term_instance
        assert window.terminal_widget.shell_text is initial_text_edit
        assert window.terminal_widget.cmd_input.text() == "echo 'Session Active'"


def test_terminal_toggle_visibility_and_shortcuts(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.resize(1280, 800)
    window.show()

    assert window._terminal_visible is True

    # 1. Hide terminal via toggle
    window._toggle_terminal_visibility()
    assert window._terminal_visible is False
    assert window.content_splitter.sizes()[1] == 0

    # 2. Navigating while hidden preserves hidden state
    window._on_sidebar_route_requested("dashboard")
    assert window.content_splitter.sizes()[1] == 0
    window._on_sidebar_route_requested("enumeration")
    assert window.content_splitter.sizes()[1] == 0

    # 3. Restore terminal via toggle
    window._toggle_terminal_visibility()
    assert window._terminal_visible is True
    assert window.content_splitter.sizes()[1] > 50

    # 4. Navigating again preserves visible state
    window._on_sidebar_route_requested("vulnerability")
    assert window.content_splitter.sizes()[1] > 50


def test_terminal_maximize_and_restore(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.resize(1280, 800)
    window.show()

    # Maximize terminal
    window._toggle_terminal_expanded()
    assert window._terminal_expanded is True
    sizes = window.content_splitter.sizes()
    assert sizes[0] == 0  # Workspace collapsed
    assert sizes[1] > 500  # Terminal full height

    # Restore terminal
    window._toggle_terminal_expanded()
    assert window._terminal_expanded is False
    sizes = window.content_splitter.sizes()
    assert sizes[0] > 200  # Workspace restored
    assert sizes[1] > 50   # Terminal restored split


def test_terminal_clear_active_output(qtbot, test_db):
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    window.terminal_widget.shell_text.setPlainText("Some prior output...")
    assert len(window.terminal_widget.shell_text.toPlainText()) > 0

    window.terminal_widget.clear_active_tab_output()
    assert window.terminal_widget.shell_text.toPlainText() == ""

