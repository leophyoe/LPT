"""AI Provider Settings and API Key Management Dialog for CyberSecuritySuite.

Allows secure entry, testing, masking, and persistent storage of Google Gemini,
OpenAI, and Local Ollama AI settings using the system credential store or user vault.
"""

from __future__ import annotations

import webbrowser
from typing import Optional

from PySide6.QtCore import Qt, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.ai_copilot import AICopilotEngine, AIProvider
from core.credential_manager import CredentialManager
from desktop.theme import CPENTTheme


class AISettingsDialog(QDialog):
    """Dialog for configuring AI providers, models, and managing secure API keys."""

    def __init__(self, engine: Optional[AICopilotEngine] = None, parent=None):
        super().__init__(parent)
        self.engine = engine or AICopilotEngine()
        self.setWindowTitle("⚙️ AI Provider Settings & API Key Management")
        self.setMinimumWidth(680)
        self.setMinimumHeight(520)

        self._init_ui()
        self._load_current_values()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # Header Title
        title = QLabel("🤖 AI Provider Settings & API Key Management")
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE}; font-family: {CPENTTheme.FONT_FAMILY_HEADING};")
        main_layout.addWidget(title)

        desc = QLabel(
            "Configure cloud intelligence (Google Gemini, OpenAI) or local LLMs (Ollama). "
            "API keys are stored securely using your operating system credential store or machine-bound vault (0600 permissions). "
            "Keys are never logged, committed to git, or sent in terminal commands."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        main_layout.addWidget(desc)

        # Storage Backend Indicator Badge
        backend_frame = QFrame()
        backend_frame.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; padding: 6px;")
        bf_layout = QHBoxLayout(backend_frame)
        bf_layout.setContentsMargins(8, 4, 8, 4)

        lbl_storage_icon = QLabel("🔒")
        bf_layout.addWidget(lbl_storage_icon)

        backend_desc = CredentialManager.get_backend_description()
        self.lbl_storage_status = QLabel(f"Storage Backend: {backend_desc}")
        self.lbl_storage_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px; font-weight: 500;")
        bf_layout.addWidget(self.lbl_storage_status)
        bf_layout.addStretch()

        main_layout.addWidget(backend_frame)

        # Provider Tabs
        self.tabs = QTabWidget()

        # -------------------------------------------------------------
        # Tab 1: Google Gemini API
        # -------------------------------------------------------------
        tab_gemini = QWidget()
        g_layout = QVBoxLayout(tab_gemini)
        g_layout.setSpacing(10)

        lbl_g_info = QLabel("Use Google's generative models for deep scan diagnosis and exploit triage.")
        lbl_g_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        g_layout.addWidget(lbl_g_info)

        # Model Selector
        m_row = QHBoxLayout()
        lbl_m = QLabel("Gemini Model:")
        lbl_m.setFixedWidth(110)
        m_row.addWidget(lbl_m)

        self.combo_gemini_model = QComboBox()
        self.combo_gemini_model.setEditable(True)
        self.combo_gemini_model.addItems(["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"])
        m_row.addWidget(self.combo_gemini_model, 1)
        g_layout.addLayout(m_row)

        # API Key Input
        k_row = QHBoxLayout()
        lbl_k = QLabel("Gemini API Key:")
        lbl_k.setFixedWidth(110)
        k_row.addWidget(lbl_k)

        self.input_gemini_key = QLineEdit()
        self.input_gemini_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_gemini_key.setPlaceholderText("Enter AIza... key here")
        k_row.addWidget(self.input_gemini_key, 1)

        self.btn_toggle_gemini = QPushButton("👁️ Show")
        self.btn_toggle_gemini.setFixedWidth(75)
        self.btn_toggle_gemini.clicked.connect(lambda: self._toggle_echo(self.input_gemini_key, self.btn_toggle_gemini))
        k_row.addWidget(self.btn_toggle_gemini)
        g_layout.addLayout(k_row)

        # Key Status
        self.lbl_gemini_saved = QLabel("Saved Key: Not Configured")
        self.lbl_gemini_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        g_layout.addWidget(self.lbl_gemini_saved)

        # Buttons
        gb_row = QHBoxLayout()
        self.btn_test_gemini = QPushButton("🔌 Test Connection")
        self.btn_test_gemini.clicked.connect(self._test_gemini)
        gb_row.addWidget(self.btn_test_gemini)

        self.btn_save_gemini = QPushButton("💾 Save Gemini Settings")
        self.btn_save_gemini.setProperty("class", "action-primary")
        self.btn_save_gemini.clicked.connect(self._save_gemini)
        gb_row.addWidget(self.btn_save_gemini)

        self.btn_clear_gemini = QPushButton("🗑️ Clear Key")
        self.btn_clear_gemini.clicked.connect(self._clear_gemini)
        gb_row.addWidget(self.btn_clear_gemini)

        btn_doc_gemini = QPushButton("🔗 Get Gemini API Key")
        btn_doc_gemini.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://aistudio.google.com/app/apikey")))
        gb_row.addWidget(btn_doc_gemini)
        g_layout.addLayout(gb_row)

        self.lbl_gemini_status = QLabel("")
        self.lbl_gemini_status.setWordWrap(True)
        g_layout.addWidget(self.lbl_gemini_status)
        g_layout.addStretch()

        self.tabs.addTab(tab_gemini, "Google Gemini API")

        # -------------------------------------------------------------
        # Tab 2: OpenAI API
        # -------------------------------------------------------------
        tab_openai = QWidget()
        o_layout = QVBoxLayout(tab_openai)
        o_layout.setSpacing(10)

        lbl_o_info = QLabel("Connect to OpenAI GPT-4o models for terminal error analysis and command generation.")
        lbl_o_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        o_layout.addWidget(lbl_o_info)

        # Model Selector
        om_row = QHBoxLayout()
        lbl_om = QLabel("OpenAI Model:")
        lbl_om.setFixedWidth(110)
        om_row.addWidget(lbl_om)

        self.combo_openai_model = QComboBox()
        self.combo_openai_model.setEditable(True)
        self.combo_openai_model.addItems(["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"])
        om_row.addWidget(self.combo_openai_model, 1)
        o_layout.addLayout(om_row)

        # API Key Input
        ok_row = QHBoxLayout()
        lbl_ok = QLabel("OpenAI API Key:")
        lbl_ok.setFixedWidth(110)
        ok_row.addWidget(lbl_ok)

        self.input_openai_key = QLineEdit()
        self.input_openai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_openai_key.setPlaceholderText("Enter sk-... key here")
        ok_row.addWidget(self.input_openai_key, 1)

        self.btn_toggle_openai = QPushButton("👁️ Show")
        self.btn_toggle_openai.setFixedWidth(75)
        self.btn_toggle_openai.clicked.connect(lambda: self._toggle_echo(self.input_openai_key, self.btn_toggle_openai))
        ok_row.addWidget(self.btn_toggle_openai)
        o_layout.addLayout(ok_row)

        # Key Status
        self.lbl_openai_saved = QLabel("Saved Key: Not Configured")
        self.lbl_openai_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        o_layout.addWidget(self.lbl_openai_saved)

        # Buttons
        ob_row = QHBoxLayout()
        self.btn_test_openai = QPushButton("🔌 Test Connection")
        self.btn_test_openai.clicked.connect(self._test_openai)
        ob_row.addWidget(self.btn_test_openai)

        self.btn_save_openai = QPushButton("💾 Save OpenAI Settings")
        self.btn_save_openai.setProperty("class", "action-primary")
        self.btn_save_openai.clicked.connect(self._save_openai)
        ob_row.addWidget(self.btn_save_openai)

        self.btn_clear_openai = QPushButton("🗑️ Clear Key")
        self.btn_clear_openai.clicked.connect(self._clear_openai)
        ob_row.addWidget(self.btn_clear_openai)

        btn_doc_openai = QPushButton("🔗 Get OpenAI API Key")
        btn_doc_openai.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://platform.openai.com/api-keys")))
        ob_row.addWidget(btn_doc_openai)
        o_layout.addLayout(ob_row)

        self.lbl_openai_status = QLabel("")
        self.lbl_openai_status.setWordWrap(True)
        o_layout.addWidget(self.lbl_openai_status)
        o_layout.addStretch()

        self.tabs.addTab(tab_openai, "OpenAI API")

        # -------------------------------------------------------------
        # Tab: DeepSeek API (Cloud)
        # -------------------------------------------------------------
        tab_deepseek = QWidget()
        ds_layout = QVBoxLayout(tab_deepseek)
        ds_layout.setSpacing(10)

        lbl_ds_info = QLabel(
            "Connect to DeepSeek models (DeepSeek-V3, DeepSeek-R1) for fast, deep cybersecurity reasoning and exploit analysis."
        )
        lbl_ds_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        ds_layout.addWidget(lbl_ds_info)

        # Model Selector
        dsm_row = QHBoxLayout()
        lbl_dsm = QLabel("DeepSeek Model:")
        lbl_dsm.setFixedWidth(120)
        dsm_row.addWidget(lbl_dsm)

        self.combo_deepseek_model = QComboBox()
        self.combo_deepseek_model.setEditable(True)
        self.combo_deepseek_model.addItems(["deepseek-chat", "deepseek-reasoner"])
        dsm_row.addWidget(self.combo_deepseek_model, 1)
        ds_layout.addLayout(dsm_row)

        # API Key Input
        dsk_row = QHBoxLayout()
        lbl_dsk = QLabel("DeepSeek API Key:")
        lbl_dsk.setFixedWidth(120)
        dsk_row.addWidget(lbl_dsk)

        self.input_deepseek_key = QLineEdit()
        self.input_deepseek_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_deepseek_key.setPlaceholderText("Enter sk-... key here")
        dsk_row.addWidget(self.input_deepseek_key, 1)

        self.btn_toggle_deepseek = QPushButton("👁️ Show")
        self.btn_toggle_deepseek.setFixedWidth(75)
        self.btn_toggle_deepseek.clicked.connect(lambda: self._toggle_echo(self.input_deepseek_key, self.btn_toggle_deepseek))
        dsk_row.addWidget(self.btn_toggle_deepseek)
        ds_layout.addLayout(dsk_row)

        # Key Status
        self.lbl_deepseek_saved = QLabel("Saved Key: Not Configured")
        self.lbl_deepseek_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        ds_layout.addWidget(self.lbl_deepseek_saved)

        # Buttons
        dsb_row = QHBoxLayout()
        self.btn_test_deepseek = QPushButton("🔌 Test Connection")
        self.btn_test_deepseek.clicked.connect(self._test_deepseek)
        dsb_row.addWidget(self.btn_test_deepseek)

        self.btn_save_deepseek = QPushButton("💾 Save DeepSeek Settings")
        self.btn_save_deepseek.setProperty("class", "action-primary")
        self.btn_save_deepseek.clicked.connect(self._save_deepseek)
        dsb_row.addWidget(self.btn_save_deepseek)

        self.btn_clear_deepseek = QPushButton("🗑️ Clear Key")
        self.btn_clear_deepseek.clicked.connect(self._clear_deepseek)
        dsb_row.addWidget(self.btn_clear_deepseek)

        btn_doc_deepseek = QPushButton("🔗 Get API Key")
        btn_doc_deepseek.setToolTip("Open DeepSeek API Key management")
        btn_doc_deepseek.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://platform.deepseek.com/api_keys")))
        dsb_row.addWidget(btn_doc_deepseek)

        btn_topup_deepseek = QPushButton("💳 Top Up Balance")
        btn_topup_deepseek.setToolTip("Open DeepSeek Billing & Balance Top Up page")
        btn_topup_deepseek.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://platform.deepseek.com/top_up")))
        dsb_row.addWidget(btn_topup_deepseek)
        ds_layout.addLayout(dsb_row)

        self.lbl_deepseek_status = QLabel("")
        self.lbl_deepseek_status.setWordWrap(True)
        ds_layout.addWidget(self.lbl_deepseek_status)
        ds_layout.addStretch()

        self.tabs.addTab(tab_deepseek, "DeepSeek API")

        # -------------------------------------------------------------
        # Tab: Anthropic Claude API (Cloud)
        # -------------------------------------------------------------
        tab_anthropic = QWidget()
        ant_layout = QVBoxLayout(tab_anthropic)
        ant_layout.setSpacing(10)

        lbl_ant_info = QLabel("Connect to Anthropic Claude 3.5 Sonnet / Haiku for advanced methodology guidance and report analysis.")
        lbl_ant_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        ant_layout.addWidget(lbl_ant_info)

        # Model Selector
        antm_row = QHBoxLayout()
        lbl_antm = QLabel("Claude Model:")
        lbl_antm.setFixedWidth(120)
        antm_row.addWidget(lbl_antm)

        self.combo_anthropic_model = QComboBox()
        self.combo_anthropic_model.setEditable(True)
        self.combo_anthropic_model.addItems(["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"])
        antm_row.addWidget(self.combo_anthropic_model, 1)
        ant_layout.addLayout(antm_row)

        # API Key Input
        antk_row = QHBoxLayout()
        lbl_antk = QLabel("Anthropic API Key:")
        lbl_antk.setFixedWidth(120)
        antk_row.addWidget(lbl_antk)

        self.input_anthropic_key = QLineEdit()
        self.input_anthropic_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_anthropic_key.setPlaceholderText("Enter sk-ant-... key here")
        antk_row.addWidget(self.input_anthropic_key, 1)

        self.btn_toggle_anthropic = QPushButton("👁️ Show")
        self.btn_toggle_anthropic.setFixedWidth(75)
        self.btn_toggle_anthropic.clicked.connect(lambda: self._toggle_echo(self.input_anthropic_key, self.btn_toggle_anthropic))
        antk_row.addWidget(self.btn_toggle_anthropic)
        ant_layout.addLayout(antk_row)

        # Key Status
        self.lbl_anthropic_saved = QLabel("Saved Key: Not Configured")
        self.lbl_anthropic_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        ant_layout.addWidget(self.lbl_anthropic_saved)

        # Buttons
        antb_row = QHBoxLayout()
        self.btn_test_anthropic = QPushButton("🔌 Test Connection")
        self.btn_test_anthropic.clicked.connect(self._test_anthropic)
        antb_row.addWidget(self.btn_test_anthropic)

        self.btn_save_anthropic = QPushButton("💾 Save Anthropic Settings")
        self.btn_save_anthropic.setProperty("class", "action-primary")
        self.btn_save_anthropic.clicked.connect(self._save_anthropic)
        antb_row.addWidget(self.btn_save_anthropic)

        self.btn_clear_anthropic = QPushButton("🗑️ Clear Key")
        self.btn_clear_anthropic.clicked.connect(self._clear_anthropic)
        antb_row.addWidget(self.btn_clear_anthropic)

        btn_doc_anthropic = QPushButton("🔗 Get Anthropic API Key")
        btn_doc_anthropic.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://console.anthropic.com/settings/keys")))
        antb_row.addWidget(btn_doc_anthropic)
        ant_layout.addLayout(antb_row)

        self.lbl_anthropic_status = QLabel("")
        self.lbl_anthropic_status.setWordWrap(True)
        ant_layout.addWidget(self.lbl_anthropic_status)
        ant_layout.addStretch()

        self.tabs.addTab(tab_anthropic, "Anthropic Claude API")

        # -------------------------------------------------------------
        # Tab: Custom OpenAI-Compatible Endpoint (...etc...)
        # -------------------------------------------------------------
        tab_custom = QWidget()
        c_layout = QVBoxLayout(tab_custom)
        c_layout.setSpacing(10)

        lbl_c_info = QLabel(
            "Connect to any custom OpenAI-compatible API endpoint (Groq, OpenRouter, Together AI, vLLM, LM Studio, Perplexity, etc.)."
        )
        lbl_c_info.setWordWrap(True)
        lbl_c_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        c_layout.addWidget(lbl_c_info)

        # Base URL
        cu_row = QHBoxLayout()
        lbl_cu = QLabel("Base Endpoint URL:")
        lbl_cu.setFixedWidth(120)
        cu_row.addWidget(lbl_cu)

        self.input_custom_url = QLineEdit()
        self.input_custom_url.setPlaceholderText("e.g. https://api.groq.com/openai/v1 or https://openrouter.ai/api/v1")
        cu_row.addWidget(self.input_custom_url, 1)
        c_layout.addLayout(cu_row)

        # Model Name
        cm_row = QHBoxLayout()
        lbl_cm = QLabel("Model Name:")
        lbl_cm.setFixedWidth(120)
        cm_row.addWidget(lbl_cm)

        self.input_custom_model = QLineEdit()
        self.input_custom_model.setPlaceholderText("e.g. llama-3.3-70b-versatile or deepseek/deepseek-r1")
        cm_row.addWidget(self.input_custom_model, 1)
        c_layout.addLayout(cm_row)

        # API Key
        ck_row = QHBoxLayout()
        lbl_ck = QLabel("Custom API Key:")
        lbl_ck.setFixedWidth(120)
        ck_row.addWidget(lbl_ck)

        self.input_custom_key = QLineEdit()
        self.input_custom_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_custom_key.setPlaceholderText("Enter API key (if required by endpoint)")
        ck_row.addWidget(self.input_custom_key, 1)

        self.btn_toggle_custom = QPushButton("👁️ Show")
        self.btn_toggle_custom.setFixedWidth(75)
        self.btn_toggle_custom.clicked.connect(lambda: self._toggle_echo(self.input_custom_key, self.btn_toggle_custom))
        ck_row.addWidget(self.btn_toggle_custom)
        c_layout.addLayout(ck_row)

        # Key Status
        self.lbl_custom_saved = QLabel("Saved Key: Not Configured")
        self.lbl_custom_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")
        c_layout.addWidget(self.lbl_custom_saved)

        # Buttons
        cb_row = QHBoxLayout()
        self.btn_test_custom = QPushButton("🔌 Test Connection")
        self.btn_test_custom.clicked.connect(self._test_custom)
        cb_row.addWidget(self.btn_test_custom)

        self.btn_save_custom = QPushButton("💾 Save Custom Settings")
        self.btn_save_custom.setProperty("class", "action-primary")
        self.btn_save_custom.clicked.connect(self._save_custom)
        cb_row.addWidget(self.btn_save_custom)

        self.btn_clear_custom = QPushButton("🗑️ Clear Key")
        self.btn_clear_custom.clicked.connect(self._clear_custom)
        cb_row.addWidget(self.btn_clear_custom)
        c_layout.addLayout(cb_row)

        self.lbl_custom_status = QLabel("")
        self.lbl_custom_status.setWordWrap(True)
        c_layout.addWidget(self.lbl_custom_status)
        c_layout.addStretch()

        self.tabs.addTab(tab_custom, "Custom Endpoint")

        # -------------------------------------------------------------
        # Tab 3: Local Ollama (Offline)
        # -------------------------------------------------------------
        tab_ollama = QWidget()
        ol_layout = QVBoxLayout(tab_ollama)
        ol_layout.setSpacing(10)

        lbl_ol_info = QLabel("Run local open-weight models (Llama 3, DeepSeek, Mistral) on your machine with zero data leaving your computer.")
        lbl_ol_info.setWordWrap(True)
        lbl_ol_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        ol_layout.addWidget(lbl_ol_info)

        # Server URL
        u_row = QHBoxLayout()
        lbl_u = QLabel("Server URL:")
        lbl_u.setFixedWidth(110)
        u_row.addWidget(lbl_u)

        self.input_ollama_url = QLineEdit()
        self.input_ollama_url.setText("http://127.0.0.1:11434")
        u_row.addWidget(self.input_ollama_url, 1)
        ol_layout.addLayout(u_row)

        # Model Name
        olm_row = QHBoxLayout()
        lbl_olm = QLabel("Ollama Model:")
        lbl_olm.setFixedWidth(110)
        olm_row.addWidget(lbl_olm)

        self.combo_ollama_model = QComboBox()
        self.combo_ollama_model.setEditable(True)
        self.combo_ollama_model.addItems(["llama3", "deepseek-r1", "mistral", "codellama"])
        olm_row.addWidget(self.combo_ollama_model, 1)
        ol_layout.addLayout(olm_row)

        # Buttons
        olb_row = QHBoxLayout()
        self.btn_test_ollama = QPushButton("🔌 Test Ollama Connection")
        self.btn_test_ollama.clicked.connect(self._test_ollama)
        olb_row.addWidget(self.btn_test_ollama)

        self.btn_save_ollama = QPushButton("💾 Save Ollama Settings")
        self.btn_save_ollama.setProperty("class", "action-primary")
        self.btn_save_ollama.clicked.connect(self._save_ollama)
        olb_row.addWidget(self.btn_save_ollama)

        btn_doc_ollama = QPushButton("🔗 Ollama Docs")
        btn_doc_ollama.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://ollama.com")))
        olb_row.addWidget(btn_doc_ollama)
        ol_layout.addLayout(olb_row)

        self.lbl_ollama_status = QLabel("")
        self.lbl_ollama_status.setWordWrap(True)
        ol_layout.addWidget(self.lbl_ollama_status)
        ol_layout.addStretch()

        self.tabs.addTab(tab_ollama, "Local Ollama")

        # -------------------------------------------------------------
        # Tab 4: Built-in Offline Security Engine
        # -------------------------------------------------------------
        tab_builtin = QWidget()
        b_layout = QVBoxLayout(tab_builtin)
        b_layout.setSpacing(10)

        lbl_b_title = QLabel("🛡️ Built-in Cybersecurity Heuristic Engine")
        lbl_b_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #38bdf8;")
        b_layout.addWidget(lbl_b_title)

        lbl_b_desc = QLabel(
            "The Built-in Security Engine operates 100% offline without sending any bytes over the network. "
            "It incorporates expert penetration testing heuristic rules for 25+ security tools (Nmap, SQLMap, Gobuster, "
            "WAFW00F, Bandit, Volatility, etc.), exit code analysis, permission remediation, and automatic finding extraction."
        )
        lbl_b_desc.setWordWrap(True)
        lbl_b_desc.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        b_layout.addWidget(lbl_b_desc)

        btn_set_offline = QPushButton("✓ Set Built-in Offline Engine as Active")
        btn_set_offline.setProperty("class", "action-primary")
        btn_set_offline.clicked.connect(self._set_offline_active)
        b_layout.addWidget(btn_set_offline)
        b_layout.addStretch()

        self.tabs.addTab(tab_builtin, "Built-in Offline Engine")

        main_layout.addWidget(self.tabs)

        # Bottom Close Row
        bot_row = QHBoxLayout()
        bot_row.addStretch()
        btn_close = QPushButton("Done")
        btn_close.clicked.connect(self.accept)
        bot_row.addWidget(btn_close)
        main_layout.addLayout(bot_row)

    def _toggle_echo(self, line_edit: QLineEdit, toggle_btn: QPushButton):
        if line_edit.echoMode() == QLineEdit.EchoMode.Password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            toggle_btn.setText("🔒 Hide")
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            toggle_btn.setText("👁️ Show")

    def _load_current_values(self):
        # Gemini
        self.combo_gemini_model.setCurrentText(self.engine.gemini_model)
        gemini_key = self.engine.get_api_key(AIProvider.GEMINI_API)
        if gemini_key:
            masked = CredentialManager.mask_key(gemini_key)
            self.lbl_gemini_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_gemini_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_gemini_saved.setText("Saved Key: Not Configured")
            self.lbl_gemini_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # OpenAI
        self.combo_openai_model.setCurrentText(self.engine.openai_model)
        openai_key = self.engine.get_api_key(AIProvider.OPENAI_API)
        if openai_key:
            masked = CredentialManager.mask_key(openai_key)
            self.lbl_openai_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_openai_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_openai_saved.setText("Saved Key: Not Configured")
            self.lbl_openai_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # Ollama
        self.input_ollama_url.setText(self.engine.ollama_url)
        self.combo_ollama_model.setCurrentText(self.engine.ollama_model)

        # DeepSeek
        self.combo_deepseek_model.setCurrentText(self.engine.deepseek_model)
        deepseek_key = self.engine.get_api_key(AIProvider.DEEPSEEK_API)
        if deepseek_key:
            masked = CredentialManager.mask_key(deepseek_key)
            self.lbl_deepseek_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_deepseek_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_deepseek_saved.setText("Saved Key: Not Configured")
            self.lbl_deepseek_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # Anthropic
        self.combo_anthropic_model.setCurrentText(self.engine.anthropic_model)
        anthropic_key = self.engine.get_api_key(AIProvider.ANTHROPIC_API)
        if anthropic_key:
            masked = CredentialManager.mask_key(anthropic_key)
            self.lbl_anthropic_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_anthropic_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_anthropic_saved.setText("Saved Key: Not Configured")
            self.lbl_anthropic_saved.setStyleSheet("color: #f87171; font-size: 11px; font-family: monospace;")

        # Custom Endpoint
        self.input_custom_url.setText(self.engine.custom_api_url)
        self.input_custom_model.setText(self.engine.custom_model)
        custom_key = self.engine.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
        if custom_key:
            masked = CredentialManager.mask_key(custom_key)
            self.lbl_custom_saved.setText(f"Saved Key: {masked} (Active)")
            self.lbl_custom_saved.setStyleSheet("color: #4ade80; font-size: 11px; font-family: monospace;")
        else:
            self.lbl_custom_saved.setText("Saved Key: Not Configured (Optional for local servers)")
            self.lbl_custom_saved.setStyleSheet("color: #94a3b8; font-size: 11px; font-family: monospace;")

    # -------------------------------------------------------------
    # Gemini Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_gemini(self):
        new_key = self.input_gemini_key.text().strip()
        model = self.combo_gemini_model.currentText().strip()
        self.engine.gemini_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.GEMINI_API, new_key)
            self.input_gemini_key.clear()
            self._load_current_values()
            self.lbl_gemini_status.setText("✓ Gemini API key and model saved successfully.")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_gemini_status.setText("✓ Gemini model preference updated.")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_gemini(self):
        self.lbl_gemini_status.setText("Connecting to Google Gemini API...")
        self.lbl_gemini_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_gemini_key.text().strip() or None
        model = self.combo_gemini_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.GEMINI_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_gemini_status.setText(f"✓ {msg}")
            self.lbl_gemini_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_gemini_status.setText(f"✗ {msg}")
            self.lbl_gemini_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_gemini(self):
        self.engine.clear_api_key(AIProvider.GEMINI_API)
        self.input_gemini_key.clear()
        self._load_current_values()
        self.lbl_gemini_status.setText("Gemini API key cleared.")
        self.lbl_gemini_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # OpenAI Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_openai(self):
        new_key = self.input_openai_key.text().strip()
        model = self.combo_openai_model.currentText().strip()
        self.engine.openai_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.OPENAI_API, new_key)
            self.input_openai_key.clear()
            self._load_current_values()
            self.lbl_openai_status.setText("✓ OpenAI API key and model saved successfully.")
            self.lbl_openai_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_openai_status.setText("✓ OpenAI model preference updated.")
            self.lbl_openai_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_openai(self):
        self.lbl_openai_status.setText("Connecting to OpenAI API...")
        self.lbl_openai_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_openai_key.text().strip() or None
        model = self.combo_openai_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.OPENAI_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_openai_status.setText(f"✓ {msg}")
            self.lbl_openai_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_openai_status.setText(f"✗ {msg}")
            self.lbl_openai_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_openai(self):
        self.engine.clear_api_key(AIProvider.OPENAI_API)
        self.input_openai_key.clear()
        self._load_current_values()
        self.lbl_openai_status.setText("OpenAI API key cleared.")
        self.lbl_openai_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # DeepSeek Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_deepseek(self):
        new_key = self.input_deepseek_key.text().strip()
        model = self.combo_deepseek_model.currentText().strip()
        self.engine.deepseek_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.DEEPSEEK_API, new_key)
            self.input_deepseek_key.clear()
            self._load_current_values()
            self.lbl_deepseek_status.setText("✓ DeepSeek API key and model saved successfully.")
            self.lbl_deepseek_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_deepseek_status.setText("✓ DeepSeek model preference updated.")
            self.lbl_deepseek_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_deepseek(self):
        self.lbl_deepseek_status.setText("Connecting to DeepSeek API...")
        self.lbl_deepseek_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_deepseek_key.text().strip() or None
        model = self.combo_deepseek_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.DEEPSEEK_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_deepseek_status.setText(f"✓ {msg}")
            self.lbl_deepseek_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            if "402" in msg or "Insufficient Balance" in msg:
                extra = "\n💡 Tip: DeepSeek requires prepaid balance top-up at platform.deepseek.com/top_up. If you want a 100% free cloud API without balance, switch to the 'Google Gemini API' tab or use the 'Built-in Security Engine (100% Offline)'."
                self.lbl_deepseek_status.setText(f"✗ {msg}{extra}")
            else:
                self.lbl_deepseek_status.setText(f"✗ {msg}")
            self.lbl_deepseek_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_deepseek(self):
        self.engine.clear_api_key(AIProvider.DEEPSEEK_API)
        self.input_deepseek_key.clear()
        self._load_current_values()
        self.lbl_deepseek_status.setText("DeepSeek API key cleared.")
        self.lbl_deepseek_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # Anthropic Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_anthropic(self):
        new_key = self.input_anthropic_key.text().strip()
        model = self.combo_anthropic_model.currentText().strip()
        self.engine.anthropic_model = model

        if new_key:
            self.engine.set_api_key(AIProvider.ANTHROPIC_API, new_key)
            self.input_anthropic_key.clear()
            self._load_current_values()
            self.lbl_anthropic_status.setText("✓ Anthropic API key and model saved successfully.")
            self.lbl_anthropic_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_anthropic_status.setText("✓ Anthropic model preference updated.")
            self.lbl_anthropic_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_anthropic(self):
        self.lbl_anthropic_status.setText("Connecting to Anthropic API...")
        self.lbl_anthropic_status.setStyleSheet("color: #38bdf8;")
        test_key = self.input_anthropic_key.text().strip() or None
        model = self.combo_anthropic_model.currentText().strip()

        ok, msg = self.engine.test_connection(
            provider=AIProvider.ANTHROPIC_API,
            model=model,
            api_key=test_key,
        )
        if ok:
            self.lbl_anthropic_status.setText(f"✓ {msg}")
            self.lbl_anthropic_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_anthropic_status.setText(f"✗ {msg}")
            self.lbl_anthropic_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_anthropic(self):
        self.engine.clear_api_key(AIProvider.ANTHROPIC_API)
        self.input_anthropic_key.clear()
        self._load_current_values()
        self.lbl_anthropic_status.setText("Anthropic API key cleared.")
        self.lbl_anthropic_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # Custom Endpoint Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_custom(self):
        self.engine.custom_api_url = self.input_custom_url.text().strip()
        self.engine.custom_model = self.input_custom_model.text().strip()
        new_key = self.input_custom_key.text().strip()

        if new_key:
            self.engine.set_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE, new_key)
            self.input_custom_key.clear()

        self._load_current_values()
        self.lbl_custom_status.setText("✓ Custom endpoint settings saved.")
        self.lbl_custom_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_custom(self):
        self.lbl_custom_status.setText("Connecting to Custom API endpoint...")
        self.lbl_custom_status.setStyleSheet("color: #38bdf8;")
        self.engine.custom_api_url = self.input_custom_url.text().strip()
        self.engine.custom_model = self.input_custom_model.text().strip()
        test_key = self.input_custom_key.text().strip() or None

        ok, msg = self.engine.test_connection(
            provider=AIProvider.CUSTOM_OPENAI_COMPATIBLE,
            model=self.engine.custom_model,
            api_key=test_key,
        )
        if ok:
            self.lbl_custom_status.setText(f"✓ {msg}")
            self.lbl_custom_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_custom_status.setText(f"✗ {msg}")
            self.lbl_custom_status.setStyleSheet("color: #f87171; font-weight: bold;")

    @Slot()
    def _clear_custom(self):
        self.engine.clear_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
        self.input_custom_key.clear()
        self._load_current_values()
        self.lbl_custom_status.setText("Custom API key cleared.")
        self.lbl_custom_status.setStyleSheet("color: #94a3b8;")

    # -------------------------------------------------------------
    # Ollama Actions
    # -------------------------------------------------------------
    @Slot()
    def _save_ollama(self):
        self.engine.ollama_url = self.input_ollama_url.text().strip()
        self.engine.ollama_model = self.combo_ollama_model.currentText().strip()
        self.lbl_ollama_status.setText("✓ Ollama settings saved.")
        self.lbl_ollama_status.setStyleSheet("color: #4ade80;")

    @Slot()
    def _test_ollama(self):
        self.lbl_ollama_status.setText("Connecting to Ollama...")
        self.lbl_ollama_status.setStyleSheet("color: #38bdf8;")
        self.engine.ollama_url = self.input_ollama_url.text().strip()
        self.engine.ollama_model = self.combo_ollama_model.currentText().strip()

        ok, msg = self.engine.test_connection(provider=AIProvider.LOCAL_OLLAMA)
        if ok:
            self.lbl_ollama_status.setText(f"✓ {msg}")
            self.lbl_ollama_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        else:
            self.lbl_ollama_status.setText(f"✗ {msg}")
            self.lbl_ollama_status.setStyleSheet("color: #f87171; font-weight: bold;")

    # -------------------------------------------------------------
    # Built-in Offline Action
    # -------------------------------------------------------------
    @Slot()
    def _set_offline_active(self):
        self.engine.provider = AIProvider.BUILTIN_OFFLINE
        QMessageBox.information(
            self,
            "Built-in Engine Active",
            "The Built-in Cybersecurity Heuristic Engine is now selected as your active AI engine.\n\n"
            "All output diagnosis and command generation will operate 100% offline without external network transmission.",
        )
