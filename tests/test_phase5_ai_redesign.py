"""Comprehensive verification suite for Phase 5.1.1 AI Assistant UI Acceptance Fixes.

Covers:
1. Empty conversation displays no welcome paragraphs or decorative cards.
2. New Chat returns to a completely blank conversation.
3. Clear Conversation returns to a completely blank conversation.
4. Stop button immediately updates UI without blocking.
5. Stop does not block the Qt GUI event loop.
6. Cancelled worker responses are ignored.
7. Late signals from an old worker cannot overwrite new conversation state.
8. Worker completion safely restores controls.
9. Repeated Stop clicks do not create duplicate messages.
10. Application shutdown handles an active worker safely.
11. Existing Offline AI remains functional.
12. Existing cloud provider integrations remain compatible.
"""

from __future__ import annotations

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import time
from urllib.parse import quote
import pytest
from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtWidgets import QApplication

from core.ai_copilot import AICopilotEngine, AIProvider
from desktop.theme import ThemeManager, ThemeMode
from desktop.views.ai_chat_view import AIChatView, AIChatWorker
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


def test_empty_conversation_displays_no_welcome_paragraphs(qtbot, test_db):
    """Verify empty conversation is completely clean with no welcome paragraphs, robot emoji, or banners."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # 1. Conversation transcript is completely empty
    plain_text = view.chat_display.toPlainText().strip()
    assert plain_text == "", f"Expected empty transcript, got: '{plain_text}'"
    assert "CyberSecuritySuite" not in plain_text
    assert "Welcome" not in plain_text
    assert "Quick Actions" not in plain_text
    assert len(view.chat_history) == 0

    # 2. Message composer and controls are visible and accessible
    assert view.input_edit.isVisible()
    assert view.btn_send.isVisible()
    assert view.btn_stop.isVisible()
    assert not view.btn_stop.isEnabled()
    assert view.btn_send.isEnabled()


def test_new_chat_and_clear_conversation_return_to_blank(qtbot, test_db):
    """Verify New Chat and Clear Conversation reset memory and return to a blank conversation."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Populate chat
    view._append_message("user", "What is an SUID bit?")
    view._append_message("assistant", "An SUID bit allows binary execution with owner permissions.", "builtin_offline")
    assert len(view.chat_history) == 2
    assert "SUID" in view.chat_display.toPlainText()

    # 1. Test New Chat action
    view.new_chat()
    assert len(view.chat_history) == 0
    assert len(view.messages) == 0
    assert view.chat_display.toPlainText().strip() == ""
    assert "CyberSecuritySuite" not in view.chat_display.toPlainText()

    # 2. Test Clear Conversation action
    view._append_message("user", "Check port 445")
    assert len(view.chat_history) == 1
    view.clear_chat()
    assert len(view.chat_history) == 0
    assert len(view.messages) == 0
    assert view.chat_display.toPlainText().strip() == ""


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


def test_stop_button_immediately_updates_ui_non_blocking(qtbot, test_db, monkeypatch):
    """Verify Stop button immediately responds in < 50ms without blocking the UI thread."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Simulate a slow network/query call in engine
    def slow_chat(*args, **kwargs):
        time.sleep(1.0)
        return "Slow response", "slow_cloud"

    monkeypatch.setattr(view.engine, "chat", slow_chat)

    view.input_edit.setText("Query slow provider")
    view._on_send_clicked()

    # During generation
    assert view.btn_stop.isEnabled()
    assert not view.btn_send.isEnabled()
    assert not view.input_edit.isEnabled()
    assert "thinking" in view.lbl_loading.text().lower()

    # Measure stop execution time
    t0 = time.perf_counter()
    view._stop_generation()
    elapsed = time.perf_counter() - t0

    # Stop must be immediate and non-blocking (< 0.05 seconds)
    assert elapsed < 0.05, f"Stop generation blocked GUI thread for {elapsed:.4f}s"
    assert not view.btn_stop.isEnabled()
    assert view.btn_send.isEnabled()
    assert view.input_edit.isEnabled()
    assert "stopped" in view.lbl_loading.text().lower()
    assert "[Generation stopped by operator]" in view.chat_history[-1]["content"]


def test_stop_does_not_block_qt_gui_event_loop(qtbot, test_db, monkeypatch):
    """Verify that after stopping generation, the Qt GUI event loop processes events seamlessly."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    def very_slow_chat(*args, **kwargs):
        time.sleep(0.8)
        return "Delayed", "offline"

    monkeypatch.setattr(view.engine, "chat", very_slow_chat)

    view.input_edit.setText("Long query")
    view._on_send_clicked()

    # Stop while thread is sleeping
    view._stop_generation()

    # Verify event loop remains responsive
    events_processed = False

    def on_timer():
        nonlocal events_processed
        events_processed = True

    QTimer.singleShot(10, on_timer)
    qtbot.waitUntil(lambda: events_processed is True, timeout=500)
    assert events_processed is True


def test_cancelled_worker_responses_are_ignored(qtbot, test_db):
    """Verify that late signals emitted from a cancelled worker are dropped and never rendered."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view._is_generating = True
    view._current_generation_id = 1

    # Simulate arrival of response from cancelled generation
    view._stop_generation()
    assert view._is_generating is False

    # A cancelled worker attempts to emit response_ready with the old generation_id
    view._on_response_ready("Unauthorized rogue response", "cloud_api", generation_id=1)

    # Transcript must NOT contain the late response
    assert "Unauthorized rogue response" not in view.chat_display.toPlainText()
    assert not any("Unauthorized rogue response" in m["content"] for m in view.chat_history)


def test_late_signals_from_old_worker_cannot_overwrite_new_conversation(qtbot, test_db):
    """Verify that late signals from an older generation ID cannot corrupt a newer active query."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Generation 1 starts and is cancelled
    view._is_generating = True
    view._current_generation_id = 1
    view._stop_generation()
    gen1_id = 1

    # Generation 2 starts
    view._is_generating = True
    view._current_generation_id = 2
    gen2_id = 2

    # Old Worker 1 late response arrives
    view._on_response_ready("Stale Gen1 Response", "cloud_api", generation_id=gen1_id)
    assert "Stale Gen1 Response" not in view.chat_display.toPlainText()

    # Active Worker 2 valid response arrives
    view._on_response_ready("Valid Gen2 Response", "builtin_offline", generation_id=gen2_id)
    assert "Valid Gen2 Response" in view.chat_display.toPlainText()
    assert any("Valid Gen2 Response" in m["content"] for m in view.chat_history)


def test_worker_completion_safely_restores_controls(qtbot, test_db):
    """Verify normal worker completion cleanly restores composer controls and frees worker reference."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view.input_edit.setText("Normal query")
    view._on_send_clicked()

    # Wait for completion
    qtbot.waitUntil(lambda: len(view.messages) >= 2, timeout=4000)
    assert view.btn_send.isEnabled()
    assert not view.btn_stop.isEnabled()
    assert view.input_edit.isEnabled()
    assert view._is_generating is False


def test_repeated_stop_clicks_do_not_create_duplicate_messages(qtbot, test_db):
    """Verify that clicking Stop multiple times does not produce duplicate cancellation notes."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view._is_generating = True
    view._stop_generation()
    view._stop_generation()
    view._stop_generation()

    stop_messages = [m for m in view.chat_history if m.get("provider") == "stopped"]
    assert len(stop_messages) == 1, f"Expected 1 stop message, got {len(stop_messages)}"


def test_application_shutdown_handles_active_worker_safely(qtbot, test_db, monkeypatch):
    """Verify widget closeEvent safely cancels active background workers without crash."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    def slow_chat(*args, **kwargs):
        time.sleep(0.4)
        return "Done", "offline"

    monkeypatch.setattr(view.engine, "chat", slow_chat)

    view.input_edit.setText("Shutdown test query")
    view._on_send_clicked()
    assert len(view._active_workers) == 1

    # Close view while worker is running
    view.close()
    assert len(view._active_workers) == 0


def test_existing_offline_ai_remains_functional(qtbot, test_db):
    """Verify built-in offline engine answers penetration testing methodologies correctly."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    reply, prov = view.engine.chat([{"role": "user", "content": "Nmap stealth scan"}])
    assert prov == "builtin_offline"
    assert "nmap" in reply.lower()
    assert "-sS" in reply or "SYN" in reply


def test_existing_cloud_provider_integrations_remain_compatible(qtbot, test_db):
    """Verify cloud provider selector maintains correct provider enums and key status behavior."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Gemini
    view.provider_combo.setCurrentIndex(2)
    assert view.engine.provider == AIProvider.GEMINI_API
    assert "Key Missing" in view.lbl_key_status.text()

    # OpenAI
    view.provider_combo.setCurrentIndex(3)
    assert view.engine.provider == AIProvider.OPENAI_API
    assert "Key Missing" in view.lbl_key_status.text()

    # DeepSeek
    view.provider_combo.setCurrentIndex(4)
    assert view.engine.provider == AIProvider.DEEPSEEK_API
    assert "Key Missing" in view.lbl_key_status.text()

    # Anthropic Claude
    view.provider_combo.setCurrentIndex(5)
    assert view.engine.provider == AIProvider.ANTHROPIC_API
    assert "Key Missing" in view.lbl_key_status.text()


def test_error_handling_and_retry_action(qtbot, test_db):
    """Verify error banner with 1-click Retry query action restores and re-runs failed query."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view._last_user_query = "exploit smb protocol"
    view._on_worker_error("Connection refused by upstream endpoint", generation_id=0)

    assert "Error executing query" in view.chat_display.toPlainText()
    assert "Retry Query" in view.chat_display.toPlainText()

    # Click retry link
    retried_text = []
    view._worker = None

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

    actions[0].trigger()
    QApplication.processEvents()
    assert "Explain this vulnerability" in view.input_edit.toPlainText()

    actions[1].trigger()
    QApplication.processEvents()
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
