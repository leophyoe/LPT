"""Tests for Conversational AI Security Chatbot and Proxy Tools Integration."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import QPushButton

from core.ai_copilot import AICopilotEngine, AIProvider
from core.credential_manager import CredentialManager
from desktop.views.ai_chat_view import AIChatView
from desktop.views.web_scan_view import WebScanView
from storage.db import Database
from storage.models import Project


@pytest.fixture
def test_db():
    return Database(":memory:")


@pytest.fixture(autouse=True)
def isolate_credentials(tmp_path, monkeypatch):
    """Isolate vault files and session cache to a temporary directory so real saved keys are not touched."""
    test_vault_dir = tmp_path / "config" / "cybersecuritysuite"
    test_vault_file = test_vault_dir / ".vault_credentials"
    monkeypatch.setattr("core.credential_manager.VAULT_DIR", test_vault_dir)
    monkeypatch.setattr("core.credential_manager.VAULT_FILE", test_vault_file)
    monkeypatch.setattr("core.credential_manager.CredentialManager._session_cache", {})
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield


def test_ai_copilot_chat_offline_methodologies():
    """Verify built-in offline chat responses across essential security topics."""
    engine = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)

    # 1. ZAP & Burp Suite
    reply_zap, prov = engine.chat([{"role": "user", "content": "How do I configure ZAP and Burp Suite?"}])
    assert prov == "builtin_offline"
    assert "OWASP ZAP" in reply_zap
    assert "Burp Suite" in reply_zap
    assert "127.0.0.1:8080" in reply_zap or "127.0.0.1:8090" in reply_zap

    # 2. Where are other tools
    reply_tools, prov = engine.chat([{"role": "user", "content": "other tools တွေ ဘယ်မှာလဲ"}])
    assert prov == "builtin_offline"
    assert "Tool Integration" in reply_tools
    assert "Nmap" in reply_tools or "SQLMap" in reply_tools

    # 3. CPENT Pivoting & Chisel
    reply_pivot, _ = engine.chat([{"role": "user", "content": "How do I setup CPENT pivoting with chisel?"}])
    assert "chisel" in reply_pivot.lower()
    assert "socks" in reply_pivot.lower()

    # 4. OWASP PTK & Denis Podgurskii
    reply_ptk, prov_ptk = engine.chat([{"role": "user", "content": "Tell me about pentestkit and JWT R-Builder tools"}])
    assert prov_ptk == "builtin_offline"
    assert "OWASP PTK" in reply_ptk
    assert "R-Builder" in reply_ptk
    assert "JWT" in reply_ptk

    # 5. Burmese greeting
    reply_burmese, _ = engine.chat([{"role": "user", "content": "မင်္ဂလာပါ AI"}])
    assert "မင်္ဂလာပါ" in reply_burmese

    # 6. Empty messages
    empty_reply, _ = engine.chat([])
    assert "Hello" in empty_reply


def test_ai_chat_view_widget(qtbot, test_db):
    """Verify AIChatView UI initialization, welcome banner, and quick prompt chips."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert "CyberSecuritySuite AI Assistant" in view.chat_display.toPlainText()
    assert view.provider_combo.count() == 7
    assert "Offline Ready" in view.lbl_key_status.text()

    # Test selecting DeepSeek provider
    view.provider_combo.setCurrentIndex(4)
    assert view.engine.provider == AIProvider.DEEPSEEK_API
    assert "Key Missing" in view.lbl_key_status.text()

    # Reset back to offline for chat test
    view.provider_combo.setCurrentIndex(0)
    assert view.engine.provider == AIProvider.BUILTIN_OFFLINE

    # Test setting active project
    project = test_db.create_project(Project(name="RedTeam-2026", client_name="AcmeCorp"))
    view.set_active_project(project)
    assert "RedTeam-2026" in view.lbl_context.text()

    terminal_commands = []
    view.command_to_shell_requested.connect(terminal_commands.append)

    # Test sending a question via input edit
    view.input_edit.setText("nmap stealth scan commands")
    view._on_send_clicked()

    # Wait for response in background worker
    qtbot.waitUntil(lambda: len(view.messages) >= 2, timeout=6000)
    assert len(view.messages) >= 2
    assert "Nmap" in view.messages[-1]["content"]
    assert terminal_commands == []


def test_web_scan_proxy_tab_elements(qtbot, test_db):
    """Verify WebScanView preserves proxy controls while keeping redundant GUI launchers hidden by default."""
    web_view = WebScanView(db=test_db)
    qtbot.addWidget(web_view)
    web_view.show()

    # Verify external GUI launcher tab is hidden by default to prevent UI clutter
    tab_titles_initial = [web_view.results_tabs.tabText(i) for i in range(web_view.results_tabs.count())]
    assert not any("Interception Proxy" in t for t in tab_titles_initial)

    # Check ZAP and Burp controls exist on view
    assert hasattr(web_view, "btn_launch_zap_gui")
    assert hasattr(web_view, "btn_launch_zap_daemon")
    assert hasattr(web_view, "btn_launch_burp")
    assert hasattr(web_view, "btn_stop_zap")

    # Verify optional display toggle
    web_view.set_proxy_tab_visible(True)
    tab_titles_shown = [web_view.results_tabs.tabText(i) for i in range(web_view.results_tabs.count())]
    assert any("Interception Proxy" in t for t in tab_titles_shown)

    web_view.set_proxy_tab_visible(False)
    tab_titles_hidden = [web_view.results_tabs.tabText(i) for i in range(web_view.results_tabs.count())]
    assert not any("Interception Proxy" in t for t in tab_titles_hidden)


def test_ai_chat_command_extraction(qtbot):
    """Verify code block and shell command parsing in AIChatView."""
    view = AIChatView()

    sample_md = """
Here are your scan options:
```bash
# Network sweep
$ nmap -sS -Pn -T4 10.10.10.5
nikto -h http://10.10.10.5:8080
```

And for python automation:
```python
import socket
s = socket.socket()
```
"""
    code_blocks = view.extract_code_blocks(sample_md)
    assert len(code_blocks) == 2
    assert code_blocks[0]["language"] == "bash"
    assert "nmap" in code_blocks[0]["code"]
    assert code_blocks[1]["language"] == "python"

    cmds = view.extract_shell_commands(sample_md)
    assert len(cmds) == 2
    assert cmds[0] == "nmap -sS -Pn -T4 10.10.10.5"
    assert cmds[1] == "nikto -h http://10.10.10.5:8080"


def test_ai_chat_interactive_shelf_and_signals(qtbot, test_db):
    """Verify AI suggestions populate the interactive shelf and emit terminal signals upon operator click."""
    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    terminal_commands = []
    view.command_to_shell_requested.connect(terminal_commands.append)

    assert not view.commands_shelf.isVisible()

    # Simulate arrival of an AI response containing commands
    ai_reply = """
### Assessment Recommendations
```bash
nmap -sS -sV -Pn 192.168.1.50
sqlmap -u "http://192.168.1.50/vuln.php?id=1" --batch
```
"""
    view._on_response_ready(ai_reply, "builtin_offline")

    # Verify shelf is now visible and contains chips
    assert view.commands_shelf.isVisible()
    assert len(view.extracted_commands) == 2
    assert view.extracted_commands[0] == "nmap -sS -sV -Pn 192.168.1.50"
    assert terminal_commands == []  # Not automatically sent without user action!

    # Find the command button and click it
    buttons = [view.commands_chips_layout.itemAt(i).widget() for i in range(view.commands_chips_layout.count())]
    cmd_buttons = [b for b in buttons if isinstance(b, QPushButton)]
    assert len(cmd_buttons) >= 2

    # Operator clicks the first command chip
    cmd_buttons[0].click()
    assert len(terminal_commands) == 1
    assert terminal_commands[0] == "nmap -sS -sV -Pn 192.168.1.50"
    assert "Loaded into Console" in view.lbl_context.text()

    # Test anchor clicked with shell scheme
    view._on_anchor_clicked(QUrl("shell:nikto%20-h%20http%3A//target.local"))
    assert len(terminal_commands) == 2
    assert terminal_commands[1] == "nikto -h http://target.local"

    # Test clearing chat hides shelf
    view.clear_chat()
    assert not view.commands_shelf.isVisible()
    assert len(view.extracted_commands) == 0


def test_deepseek_and_extended_providers_configuration(monkeypatch):
    """Verifies DeepSeek, Anthropic, and Custom API key storage, resolution, and masking."""
    engine = AICopilotEngine()

    # 1. DeepSeek API key operations
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) is None
    engine.set_api_key(AIProvider.DEEPSEEK_API, "sk-deepseek-test-abcdef123456")
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) == "sk-deepseek-test-abcdef123456"
    assert CredentialManager.get_key("deepseek") == "sk-deepseek-test-abcdef123456"

    # Masking check
    masked = CredentialManager.mask_key("sk-deepseek-test-abcdef123456")
    assert masked.startswith("sk-d")
    assert masked.endswith("3456")
    assert "••••••••" in masked

    engine.clear_api_key(AIProvider.DEEPSEEK_API)
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) is None

    # 2. Environment variable fallback for DeepSeek
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-ds-env-999888")
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) == "sk-ds-env-999888"

    # 3. Anthropic & Custom API key operations
    engine.set_api_key(AIProvider.ANTHROPIC_API, "sk-ant-test-777")
    assert engine.get_api_key(AIProvider.ANTHROPIC_API) == "sk-ant-test-777"
    engine.clear_api_key(AIProvider.ANTHROPIC_API)

    engine.set_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE, "custom-token-xyz")
    assert engine.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE) == "custom-token-xyz"
    engine.clear_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)


def test_ai_settings_dialog_deepseek_and_providers(qtbot):
    """Verifies AISettingsDialog DeepSeek and custom endpoint tabs and key entry."""
    from desktop.dialogs.ai_settings_dialog import AISettingsDialog

    engine = AICopilotEngine()
    dlg = AISettingsDialog(engine=engine)
    qtbot.addWidget(dlg)

    # Verify tab names
    tab_titles = [dlg.tabs.tabText(i) for i in range(dlg.tabs.count())]
    assert "DeepSeek API" in tab_titles
    assert "Anthropic Claude API" in tab_titles
    assert "Custom Endpoint" in tab_titles

    # Set DeepSeek key via dialog input
    dlg.input_deepseek_key.setText("sk-deepseek-from-dialog-1234")
    dlg._save_deepseek()
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) == "sk-deepseek-from-dialog-1234"
    assert "Saved Key: sk-d••••••••1234" in dlg.lbl_deepseek_saved.text()

    # Clear DeepSeek key via dialog
    dlg._clear_deepseek()
    assert engine.get_api_key(AIProvider.DEEPSEEK_API) is None
    assert "Not Configured" in dlg.lbl_deepseek_saved.text()


def test_persistent_ai_panel_in_main_window(qtbot, test_db):
    """Verify right-docked persistent AI Assistant side-panel, toggle controls, and shortcuts in MainWindow."""
    from desktop.main_window import MainWindow
    from PySide6.QtCore import QSettings

    QSettings("CyberSecuritySuite", "Layout").clear()

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # 1. Right persistent panel exists, is visible, and holds AIChatView
    assert hasattr(window, "right_ai_panel")
    assert hasattr(window, "ai_chat_view")
    assert window.right_ai_panel.isVisible()
    assert window.ai_chat_view.parent() == window.right_ai_panel

    # 2. Main horizontal splitter layout
    assert hasattr(window, "main_horizontal_splitter")
    sizes = window.main_horizontal_splitter.sizes()
    assert len(sizes) == 2
    assert sizes[0] > 0
    assert sizes[1] > 0

    # 3. Toggle via _toggle_ai_panel
    window._toggle_ai_panel()
    assert not window.right_ai_panel.isVisible()

    window._toggle_ai_panel()
    assert window.right_ai_panel.isVisible()

    # 4. Collapse via panel header button
    window.ai_chat_view.btn_collapse.click()
    assert not window.right_ai_panel.isVisible()

    # 5. Focus AI panel ensures visibility and focus
    window._focus_ai_panel()
    from PySide6.QtWidgets import QApplication
    QApplication.processEvents()
    assert window.right_ai_panel.isVisible()
    assert window.ai_chat_view.input_edit.hasFocus() or QApplication.focusWidget() == window.ai_chat_view.input_edit

    # 6. Global shortcuts exist
    assert hasattr(window, "shortcut_ai_l")
    assert hasattr(window, "shortcut_ai_i")
    assert window.shortcut_ai_l.key().toString() == "Ctrl+L"
    assert window.shortcut_ai_i.key().toString() == "Ctrl+I"


def test_ai_chat_input_multiline_and_enter_key(qtbot, test_db):
    """Verify ChatInputTextEdit Enter-to-send and Shift+Enter for multiline newline insertion."""
    from PySide6.QtGui import QKeyEvent
    from desktop.views.ai_chat_view import ChatInputTextEdit

    view = AIChatView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    edit = view.input_edit
    assert isinstance(edit, ChatInputTextEdit)
    assert edit.text() == ""

    # Shift+Enter inserts a newline
    edit.setText("Line 1")
    shift_enter = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
    edit.keyPressEvent(shift_enter)
    assert "\n" in edit.toPlainText() or edit.toPlainText().startswith("Line 1")

    # Regular Enter triggers return_pressed signal
    enter_pressed = []
    edit.return_pressed.connect(lambda: enter_pressed.append(True))
    plain_enter = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    edit.keyPressEvent(plain_enter)
    assert len(enter_pressed) == 1


def test_ai_chat_context_aware_workspace_updates(qtbot, test_db):
    """Verify switching workspaces and selecting projects dynamically informs the persistent AI panel."""
    from desktop.main_window import MainWindow

    project = test_db.create_project(Project(name="Engagement Apollo", client_name="Olympus"))
    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Select project
    window._on_project_selected(project)
    assert "Engagement Apollo" in window.ai_chat_view.lbl_context.text()

    # Switch workspace to Assessment (index 1)
    window.view_stack.setCurrentIndex(1)
    assert "Assessment" in window.ai_chat_view.current_workspace

    # Switch sub-tab to Web Testing
    window.security_tabs.setCurrentWidget(window.web_view)
    assert "Web Testing" in window.ai_chat_view.current_workspace

    # Switch workspace to Reports & Findings (index 2)
    window.view_stack.setCurrentIndex(2)
    assert "Reports & Findings" in window.ai_chat_view.current_workspace

    # Context sharing toggle
    assert hasattr(window.ai_chat_view, "cb_safe_context")
    assert window.ai_chat_view.cb_safe_context.isChecked()


def test_qsettings_layout_persistence(qtbot, test_db):
    """Verify right AI panel layout and visibility state save and restore via QSettings."""
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    from desktop.main_window import MainWindow

    settings = QSettings("CyberSecuritySuite", "Layout")
    settings.setValue("ai_panel_visible", False)

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()
    QApplication.processEvents()

    # Initial restore from settings
    assert not window.right_ai_panel.isVisible()

    # Make visible and save
    window._toggle_ai_panel(force_visible=True)
    QApplication.processEvents()
    assert window.right_ai_panel.isVisible()
    window._save_ai_panel_settings()

    saved_vis = settings.value("ai_panel_visible")
    assert str(saved_vis).lower() in ("true", "1")

    # Reset for next tests
    settings.setValue("ai_panel_visible", True)

