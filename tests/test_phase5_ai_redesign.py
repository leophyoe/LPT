"""Comprehensive verification suite for Phase 1 AI Assistant UI/UX Redesign."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from urllib.parse import quote, unquote
import pytest
from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import QApplication

from core.ai_copilot import AICopilotEngine, AIProvider
from desktop.theme import ThemeManager, ThemeMode
from desktop.views.ai_chat_view import AIChatView
from storage.db import Database
from storage.models import Project


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_ai_chat_header_and_mode_indicators(qtbot, test_db):
    """Verify modern compact header controls, mode indicator badges, and provider transitions."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # 1. Header titles and controls exist
    assert hasattr(view, "lbl_title")
    assert "AI Assistant" in view.lbl_title.text()
    assert hasattr(view, "lbl_mode")
    assert "Offline Mode" in view.lbl_mode.text()
    assert hasattr(view, "btn_new_chat")
    assert hasattr(view, "btn_clear")
    assert hasattr(view, "btn_settings")
    assert hasattr(view, "btn_collapse")

    # 2. Mode indicator updates dynamically with provider switch
    # Local Ollama
    view.provider_combo.setCurrentIndex(1)
    assert view.engine.provider == AIProvider.LOCAL_OLLAMA
    assert "Local Ollama" in view.lbl_mode.text()
    assert "Local (No Key)" in view.lbl_key_status.text()

    # Cloud Provider (Gemini)
    view.provider_combo.setCurrentIndex(2)
    assert view.engine.provider == AIProvider.GEMINI_API
    assert "Cloud API" in view.lbl_mode.text()
    assert "Key Missing" in view.lbl_key_status.text()

    # Reset to Offline
    view.provider_combo.setCurrentIndex(0)
    assert view.engine.provider == AIProvider.BUILTIN_OFFLINE
    assert "Offline Mode" in view.lbl_mode.text()
    assert "Offline Ready" in view.lbl_key_status.text()


def test_ai_chat_empty_state_and_new_chat(qtbot, test_db):
    """Verify clean empty state placeholder on startup, new chat, and reset."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # On init, empty state is displayed
    plain = view.chat_display.toPlainText()
    assert "CyberSecuritySuite AI Assistant" in plain
    assert "Quick Actions" in plain
    assert len(view.chat_history) == 0

    # Simulate message arrival
    view._append_message("user", "Hello security copilot")
    assert len(view.chat_history) == 1
    # Empty state replaced by message
    assert "👤 You" in view.chat_display.toPlainText()
    assert "Hello security copilot" in view.chat_display.toPlainText()

    # Click New Chat
    view.new_chat()
    assert len(view.chat_history) == 0
    assert len(view.messages) == 0
    assert "CyberSecuritySuite AI Assistant" in view.chat_display.toPlainText()


def test_markdown_code_card_and_copy_code_action(qtbot, test_db):
    """Verify code block rendering with language badge and 1-click clipboard copy action."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    content = (
        "Here is the scanning routine:\n\n"
        "```bash\n"
        "nmap -sS -Pn -T4 192.168.1.1\n"
        "```\n\n"
        "Please review open ports."
    )
    view._append_message("assistant", content, "builtin_offline")

    html_rendered = view.chat_display.toHtml()
    assert "BASH" in html_rendered
    assert "Copy Code" in html_rendered
    assert "Copy Response" in html_rendered

    # Test clipboard copy action via copy: URL scheme
    expected_code = "nmap -sS -Pn -T4 192.168.1.1"
    copy_url = QUrl(f"copy:{quote(expected_code)}")
    view._on_anchor_clicked(copy_url)

    clipboard_text = QApplication.clipboard().text()
    assert clipboard_text == expected_code
    assert "Copied to clipboard" in view.lbl_loading.text()


def test_copy_full_response_action(qtbot, test_db):
    """Verify 1-click Copy Response action copies entire markdown response to system clipboard."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    response_text = "### Triage Report\nCritical vulnerability detected on port 445: MS17-010."
    view._append_message("assistant", response_text, "builtin_offline")

    copy_url = QUrl(f"copy:{quote(response_text)}")
    view._on_anchor_clicked(copy_url)

    assert QApplication.clipboard().text() == response_text
    assert "Copied to clipboard" in view.lbl_loading.text()


def test_stop_generation_control(qtbot, test_db):
    """Verify Stop Generation control aborts running query and restores input controls."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert not view.btn_stop.isEnabled()
    assert view.btn_send.isEnabled()

    # Trigger generation
    view.input_edit.setText("generate complex pentest guide")
    view._on_send_clicked()

    # During generation
    assert view.btn_stop.isEnabled()
    assert not view.btn_send.isEnabled()
    assert not view.input_edit.isEnabled()
    assert "thinking" in view.lbl_loading.text().lower()

    # Operator clicks stop
    view._stop_generation()

    assert not view.btn_stop.isEnabled()
    assert view.btn_send.isEnabled()
    assert view.input_edit.isEnabled()
    assert "stopped" in view.lbl_loading.text().lower()
    assert "[Generation stopped by operator]" in view.chat_history[-1]["content"]


def test_error_handling_and_retry_action(qtbot, test_db):
    """Verify error banner with 1-click Retry query action restores and re-runs failed query."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view._last_user_query = "exploit smb protocol"
    view._on_worker_error("Connection refused by upstream endpoint")

    assert "Error executing query" in view.chat_display.toPlainText()
    assert "Retry Query" in view.chat_display.toPlainText()

    # Click retry link
    retried_text = []
    view._worker = None
    original_send = view._on_send_clicked

    def mock_send():
        retried_text.append(view.input_edit.toPlainText())

    view._on_send_clicked = mock_send

    retry_url = QUrl("retry:last")
    view._on_anchor_clicked(retry_url)

    assert len(retried_text) == 1
    assert retried_text[0] == "exploit smb protocol"


def test_quick_action_menu_templates(qtbot, test_db):
    """Verify Quick Actions popup menu populates editor with structured templates."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert hasattr(view, "btn_quick_menu")
    assert hasattr(view, "quick_menu")
    actions = view.quick_menu.actions()
    assert len(actions) == 5

    titles = [a.text() for a in actions]
    assert any("Explain Vulnerability" in t for t in titles)
    assert any("Analyze Nmap Output" in t for t in titles)
    assert any("Explain Command" in t for t in titles)
    assert any("CPENT Learning" in t for t in titles)
    assert any("Generate Report Outline" in t for t in titles)

    # Trigger 'Explain Vulnerability'
    actions[0].trigger()
    QApplication.processEvents()
    assert "Explain this vulnerability" in view.input_edit.toPlainText()

    # Trigger 'Analyze Nmap Output'
    actions[1].trigger()
    assert "Analyze the following Nmap scan" in view.input_edit.toPlainText()


def test_theme_switch_preserves_messages(qtbot, test_db):
    """Verify switching Dark and Light themes updates styling without message loss."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view._append_message("user", "Test prompt 1")
    view._append_message("assistant", "Test response 1", "builtin_offline")

    assert len(view.chat_history) == 2

    # Switch to Light Mode
    ThemeManager.instance().set_theme_mode(ThemeMode.LIGHT)
    view.update_theme("light")
    assert len(view.chat_history) == 2
    assert "Test prompt 1" in view.chat_display.toPlainText()
    assert "Test response 1" in view.chat_display.toPlainText()

    # Switch back to Dark Mode
    ThemeManager.instance().set_theme_mode(ThemeMode.DARK)
    view.update_theme("dark")
    assert len(view.chat_history) == 2
    assert "Test prompt 1" in view.chat_display.toPlainText()
    assert "Test response 1" in view.chat_display.toPlainText()
