"""Dedicated Conversational AI Security Copilot and Penetration Testing Chatbot View.

Provides an interactive multi-turn chatbot interface with prompt templates,
code block extractors, offline CPENT heuristic knowledge, and live terminal integration.
Redesigned for Phase 1 with a modern, compact, ChatGPT/Copilot-style interface.
"""

from __future__ import annotations

import datetime
import html
import json
import os
import re
from typing import Dict, List, Optional
from urllib.parse import quote, unquote

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QDesktopServices, QFont, QTextCursor, QTextDocument
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.activity_logger import sanitize_text
from core.ai_copilot import AICopilotEngine, AIProvider
from core.ai_tool_router import AIToolRouter
from desktop.theme import CPENTTheme, ThemeManager
from storage.db import Database
from storage.models import FindingSeverity, Project, ScopeRuleType


class ChatInputTextEdit(QTextEdit):
    """Multi-line chat input supporting Enter to send and Shift+Enter for newlines."""

    return_pressed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptRichText(False)
        self.setMinimumHeight(44)
        self.setMaximumHeight(85)
        self.setFont(QFont("sans-serif", 10))
        self.setPlaceholderText(
            "Ask a question or request a command (Enter to send, Shift+Enter for newline)..."
        )

    def text(self) -> str:
        """Backward-compatible alias for toPlainText()."""
        return self.toPlainText()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                super().keyPressEvent(event)
            else:
                self.return_pressed.emit()
                event.accept()
        else:
            super().keyPressEvent(event)


class AIChatWorker(QThread):
    """Background worker executing chat query to prevent GUI freeze."""

    response_ready = Signal(str, str)  # reply_text, provider_used
    error_occurred = Signal(str)

    def __init__(
        self,
        engine: AICopilotEngine,
        messages: List[Dict[str, str]],
        project_context: Optional[str] = None,
        user_consented: bool = True,
    ):
        super().__init__()
        self.engine = engine
        self.messages = messages
        self.project_context = project_context
        self.user_consented = user_consented
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            if self._is_cancelled:
                return
            reply, prov = self.engine.chat(
                self.messages,
                project_context=self.project_context,
                user_consented=self.user_consented,
            )
            if not self._is_cancelled:
                self.response_ready.emit(reply, prov)
        except Exception as e:
            if not self._is_cancelled:
                self.error_occurred.emit(str(e))


class AIChatView(QWidget):
    """Right-docked persistent interactive penetration testing chatbot with multi-turn memory."""

    command_to_shell_requested = Signal(str)  # Emits command to load into terminal
    open_settings_requested = Signal()
    collapse_requested = Signal()

    def __init__(
        self,
        db: Optional[Database] = None,
        engine: Optional[AICopilotEngine] = None,
        parent=None,
    ):
        super().__init__(parent)
        self.db = db
        self.engine = engine or AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
        self.active_project: Optional[Project] = None
        self.current_workspace: str = "Projects"
        self.router = AIToolRouter()
        self.messages: List[Dict[str, str]] = []
        self.chat_history: List[Dict[str, str]] = []
        self._worker: Optional[AIChatWorker] = None
        self.extracted_commands: List[str] = []
        self._last_user_query: str = ""

        ThemeManager.instance().theme_changed.connect(self.update_theme)

        self._init_ui()
        self._show_empty_state()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        self._update_context_label()

    def set_current_workspace(self, workspace_name: str, context_details: Optional[Dict] = None):
        """Updates the active workspace context to give context-aware security suggestions."""
        self.current_workspace = workspace_name
        self._update_context_label()

    def focus_input(self):
        """Focuses the chat input box ready for operator typing."""
        if hasattr(self, "input_edit"):
            self.input_edit.setFocus()
            cursor = self.input_edit.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.input_edit.setTextCursor(cursor)

    def _update_context_label(self):
        parts = []
        if self.active_project:
            parts.append(f"Project: '{self.active_project.name}' (ID: {self.active_project.id})")
        else:
            parts.append("Project: None")
        parts.append(f"📌 {self.current_workspace}")

        if hasattr(self, "lbl_context"):
            self.lbl_context.setText(" | ".join(parts))
            is_light = ThemeManager.instance().is_light
            if self.active_project:
                col = "#15803D" if is_light else "#4ade80"
                self.lbl_context.setStyleSheet(f"color: {col}; font-size: 11px; font-weight: 500;")
            else:
                col = "#475569" if is_light else "#94a3b8"
                self.lbl_context.setStyleSheet(f"color: {col}; font-size: 11px;")

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        # 1. Compact Header (ChatGPT / Copilot Style)
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(4)

        # Row 1: Title, Mode Indicator Badge, Stretch, and Panel Actions
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        self.lbl_title = QLabel("🤖 AI Assistant")
        self.lbl_title.setObjectName("viewHeader")
        self.lbl_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        top_row.addWidget(self.lbl_title)

        self.lbl_mode = QLabel("[ 🔒 Offline Mode ]")
        self.lbl_mode.setStyleSheet(
            "font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; "
            "background: rgba(74, 222, 128, 0.15); color: #4ade80;"
        )
        top_row.addWidget(self.lbl_mode)
        top_row.addStretch()

        self.btn_new_chat = QPushButton("➕")
        self.btn_new_chat.setFixedSize(26, 26)
        self.btn_new_chat.setToolTip("Start New Conversation")
        self.btn_new_chat.setStyleSheet("QPushButton { font-size: 12px; padding: 0; }")
        self.btn_new_chat.clicked.connect(self.new_chat)
        top_row.addWidget(self.btn_new_chat)

        self.btn_clear = QPushButton("🗑️")
        self.btn_clear.setFixedSize(26, 26)
        self.btn_clear.setToolTip("Clear Conversation History")
        self.btn_clear.setStyleSheet("QPushButton { font-size: 12px; padding: 0; }")
        self.btn_clear.clicked.connect(self.clear_chat)
        top_row.addWidget(self.btn_clear)

        self.btn_settings = QPushButton("⚙️")
        self.btn_settings.setFixedSize(26, 26)
        self.btn_settings.setToolTip("Configure AI Provider & API Keys")
        self.btn_settings.setStyleSheet("QPushButton { font-size: 12px; padding: 0; }")
        self.btn_settings.clicked.connect(self._open_settings)
        top_row.addWidget(self.btn_settings)

        self.btn_collapse = QPushButton("◨")
        self.btn_collapse.setFixedSize(26, 26)
        self.btn_collapse.setToolTip("Toggle AI Assistant Panel (Ctrl+L)")
        self.btn_collapse.setStyleSheet("QPushButton { font-size: 13px; font-weight: bold; padding: 0; }")
        self.btn_collapse.clicked.connect(self.collapse_requested.emit)
        top_row.addWidget(self.btn_collapse)

        header_layout.addLayout(top_row)

        # Row 2: Provider Selector & Real Connection Status Indicator
        engine_row = QHBoxLayout()
        engine_row.setSpacing(6)
        self.provider_combo = QComboBox()
        self.provider_combo.addItems([
            "Built-in Security Engine (100% Offline)",
            "Local Ollama (http://127.0.0.1:11434)",
            "Google Gemini API (Cloud)",
            "OpenAI API (Cloud)",
            "DeepSeek API (Cloud)",
            "Anthropic Claude API (Cloud)",
            "Custom Endpoint (OpenAI-Compatible)",
        ])
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        engine_row.addWidget(self.provider_combo, 1)

        self.lbl_key_status = QLabel("● Offline Ready")
        engine_row.addWidget(self.lbl_key_status)
        header_layout.addLayout(engine_row)

        # Row 3: Active Context Label
        ctx_row = QHBoxLayout()
        ctx_row.setSpacing(6)
        self.lbl_context = QLabel("Project: None | 📌 Projects")
        self._update_context_label()
        ctx_row.addWidget(self.lbl_context, 1)
        header_layout.addLayout(ctx_row)

        layout.addWidget(header_widget)

        # 2. Main Chat History Transcript
        self.chat_display = QTextBrowser()
        self.chat_display.setObjectName("aiChatDisplay")
        self.chat_display.setOpenExternalLinks(False)
        self.chat_display.anchorClicked.connect(self._on_anchor_clicked)
        self.chat_display.setFont(QFont("sans-serif", 10))
        layout.addWidget(self.chat_display, 1)

        # 2.5. Suggested Commands Action Shelf (Collapsible)
        self.commands_shelf = QFrame()
        self.commands_shelf.setObjectName("commandsShelf")
        self.commands_shelf.setVisible(False)
        self.commands_shelf_layout = QVBoxLayout(self.commands_shelf)
        self.commands_shelf_layout.setContentsMargins(6, 4, 6, 4)
        self.commands_shelf_layout.setSpacing(4)

        shelf_header = QHBoxLayout()
        lbl_shelf_title = QLabel("⚡ Suggested Commands (Click to load into Console for review):")
        lbl_shelf_title.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {CPENTTheme.AMBER_ACCENT};")
        shelf_header.addWidget(lbl_shelf_title)
        shelf_header.addStretch()

        btn_dismiss = QPushButton("✕")
        btn_dismiss.setFixedSize(18, 18)
        btn_dismiss.setToolTip("Dismiss suggestions")
        btn_dismiss.setStyleSheet("QPushButton { border: none; background: transparent; font-size: 11px; font-weight: bold; }")
        btn_dismiss.clicked.connect(lambda: self.commands_shelf.setVisible(False))
        shelf_header.addWidget(btn_dismiss)
        self.commands_shelf_layout.addLayout(shelf_header)

        self.commands_chips_layout = QHBoxLayout()
        self.commands_chips_layout.setSpacing(6)
        self.commands_shelf_layout.addLayout(self.commands_chips_layout)

        layout.addWidget(self.commands_shelf)

        # 3. Bottom Composer Area
        input_frame = QFrame()
        input_frame.setObjectName("dashboardPanel")
        input_layout = QVBoxLayout(input_frame)
        input_layout.setContentsMargins(6, 6, 6, 6)
        input_layout.setSpacing(6)

        self.input_edit = ChatInputTextEdit()
        self.input_edit.setObjectName("aiChatInput")
        self.input_edit.return_pressed.connect(self._on_send_clicked)
        input_layout.addWidget(self.input_edit)

        # Action Toolbar below multiline input
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(6)

        # Quick Actions Dropdown Menu Button
        self.btn_quick_menu = QPushButton("⚡ Quick Actions ▾")
        self.btn_quick_menu.setFixedHeight(26)
        self.btn_quick_menu.setStyleSheet("font-size: 11px;")
        self.btn_quick_menu.setToolTip("Insert structured prompt template")
        self._setup_quick_menu()
        bottom_row.addWidget(self.btn_quick_menu)

        self.cb_safe_context = QCheckBox("Share context")
        self.cb_safe_context.setChecked(True)
        self.cb_safe_context.setStyleSheet("font-size: 11px;")
        self.cb_safe_context.setToolTip(
            "Shares sanitized project & workspace summary with AI without sensitive credentials"
        )
        bottom_row.addWidget(self.cb_safe_context)

        bottom_row.addStretch()

        self.lbl_loading = QLabel("")
        self.lbl_loading.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-size: 11px; font-style: italic;")
        bottom_row.addWidget(self.lbl_loading)

        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.setFixedHeight(26)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setToolTip("Stop active AI generation")
        self.btn_stop.clicked.connect(self._stop_generation)
        bottom_row.addWidget(self.btn_stop)

        self.btn_send = QPushButton("✈ Send")
        self.btn_send.setProperty("class", "action-primary")
        self.btn_send.setFixedSize(70, 26)
        self.btn_send.clicked.connect(self._on_send_clicked)
        bottom_row.addWidget(self.btn_send)

        input_layout.addLayout(bottom_row)
        layout.addWidget(input_frame)

    def _setup_quick_menu(self):
        """Creates the compact quick-action template menu."""
        self.quick_menu = QMenu(self)
        actions = [
            (
                "🔍 Explain Vulnerability",
                "Explain this vulnerability in detail, including CVSS score, root cause, and remediation steps:\n",
            ),
            (
                "📊 Analyze Nmap Output",
                "Analyze the following Nmap scan output and suggest next enumeration steps:\n",
            ),
            (
                "💻 Explain Command",
                "Explain what this penetration testing command does and its risk level:\n",
            ),
            (
                "🎯 CPENT Learning",
                "Explain the methodology and tools for CPENT pivoting and privilege escalation:\n",
            ),
            (
                "📝 Generate Report Outline",
                "Generate a professional penetration testing report executive summary for our findings:\n",
            ),
        ]
        for title, prompt_tmpl in actions:
            act = self.quick_menu.addAction(title)
            act.triggered.connect(lambda checked=False, t=prompt_tmpl: self._insert_quick_action(t))
        self.btn_quick_menu.setMenu(self.quick_menu)

    def _insert_quick_action(self, template: str):
        """Inserts quick-action prompt into composer and focuses editor."""
        self.input_edit.setText(template)
        self.input_edit.setFocus()
        cursor = self.input_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.input_edit.setTextCursor(cursor)

    def _show_empty_state(self):
        """Renders a clean, compact placeholder when no conversation is active."""
        is_light = ThemeManager.instance().is_light
        text_color = "#475569" if is_light else "#94A3B8"
        heading_color = "#0F172A" if is_light else "#F8FAFC"
        sub_color = "#64748B" if is_light else "#64748B"
        border_color = "#E2E8F0" if is_light else "#1E293B"
        card_bg = "#F8FAFC" if is_light else "#0F172A"

        html_content = (
            f"<div style='text-align: center; margin: 30px 10px; padding: 24px; "
            f"border: 1px dashed {border_color}; border-radius: 8px; background-color: {card_bg};'>"
            f"<div style='font-size: 26px; margin-bottom: 6px;'>🤖</div>"
            f"<div style='font-size: 14px; font-weight: bold; color: {heading_color}; margin-bottom: 6px;'>"
            f"CyberSecuritySuite AI Assistant</div>"
            f"<div style='font-size: 12px; color: {sub_color}; max-width: 340px; margin: 0 auto; line-height: 1.5;'>"
            f"Ready to assist with penetration testing, scan analysis, tool guidance, and CPENT methodologies.<br>"
            f"<span style='font-size: 11px; color: {text_color};'>Type a question or click <b>⚡ Quick Actions</b> below.</span>"
            f"</div>"
            f"</div>"
        )
        self.chat_display.setHtml(html_content)

    def _add_welcome_message(self):
        """Backward-compatible entry point that resets display to clean empty state."""
        self._show_empty_state()

    def _send_quick_prompt(self, prompt: str):
        """Populates composer and immediately dispatches query."""
        self.input_edit.setText(prompt)
        self._on_send_clicked()

    @Slot()
    def new_chat(self):
        """Starts a fresh conversation, clearing memory and history."""
        self.chat_history.clear()
        self.messages.clear()
        self.chat_display.clear()
        self._update_commands_shelf([])
        self._update_context_label()
        self._show_empty_state()

    @Slot()
    def clear_chat(self):
        """Clears conversation transcript."""
        self.new_chat()

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait()
        super().closeEvent(event)

    @Slot()
    def _stop_generation(self):
        """Immediately stops the running AI query worker safely."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait()

        self.btn_send.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.input_edit.setEnabled(True)
        self.lbl_loading.setText("Generation stopped by operator.")
        self.input_edit.setFocus()
        self._append_message("assistant", "*[Generation stopped by operator]*", "stopped")

    def retry_last(self):
        """Retries the last user query if available."""
        if self._last_user_query:
            self.input_edit.setText(self._last_user_query)
            self._on_send_clicked()

    @Slot()
    def _on_send_clicked(self):
        text = self.input_edit.toPlainText().strip() if hasattr(self.input_edit, "toPlainText") else self.input_edit.text().strip()
        if not text:
            return

        self._last_user_query = text
        self.input_edit.clear()
        self.btn_send.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.input_edit.setEnabled(False)
        self.lbl_loading.setText("⏳ AI Assistant is thinking...")
        self.commands_shelf.setVisible(False)

        # Append user message with secret scrubbing
        clean_user_text = sanitize_text(text)
        self.messages.append({"role": "user", "content": clean_user_text})
        self._append_message("user", clean_user_text)

        # Prepare rich, evidence-grounded context string (if safe context sharing is checked)
        ctx = None
        if hasattr(self, "cb_safe_context") and self.cb_safe_context.isChecked():
            ctx_items = []
            if self.active_project:
                pid = self.active_project.id
                status_str = getattr(self.active_project.status, "value", str(self.active_project.status))
                ctx_items.append(f"Engagement: {self.active_project.name} (Client: {self.active_project.client_name or 'N/A'}, Status: {status_str})")
                if self.db and pid:
                    try:
                        scopes = self.db.list_scopes(pid)
                        if scopes:
                            allowed_targets = [s.target for s in scopes if s.is_authorized]
                            excluded_targets = [s.target for s in scopes if s.rule_type == ScopeRuleType.EXCLUDED]
                            ctx_items.append(f"Authorized Scopes ({len(allowed_targets)}): {', '.join(allowed_targets[:6])}")
                            if excluded_targets:
                                ctx_items.append(f"Strict Exclusions ({len(excluded_targets)}): {', '.join(excluded_targets[:4])}")

                        # Include Authoritative Asset Inventory
                        nodes = self.db.list_asset_nodes(pid)
                        ip_nodes = [n for n in nodes if n.node_type == "ip"]
                        if ip_nodes:
                            asset_summaries = []
                            for n in ip_nodes[:8]:
                                meta = {}
                                try:
                                    meta = json.loads(n.metadata_json) if n.metadata_json else {}
                                except Exception:
                                    meta = {}
                                open_ports = meta.get("open_ports", [])
                                port_str = f"ports: {open_ports}" if open_ports else "0 open ports"
                                hn = f" ({n.label})" if (n.label and n.label != n.value) else ""
                                asset_summaries.append(f"{n.value}{hn} [{port_str}, via {n.source_tool}]")
                            ctx_items.append(f"Discovered Assets ({len(ip_nodes)} total): " + "; ".join(asset_summaries))

                        # Include Findings Summary
                        findings = self.db.list_findings(pid)
                        if findings:
                            crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
                            high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
                            med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
                            low = sum(1 for f in findings if f.severity in (FindingSeverity.LOW, FindingSeverity.INFORMATIONAL))
                            top_findings = [f"[{f.severity.value.upper()}] {f.title} on {f.affected_asset} ({f.validation_status.value})" for f in findings[:5]]
                            ctx_items.append(f"Findings: {len(findings)} total (Critical: {crit}, High: {high}, Medium: {med}, Low: {low}). Top: " + "; ".join(top_findings))

                        # Evidence Count
                        ev_list = self.db.list_evidence(pid)
                        ctx_items.append(f"Evidence Artifacts: {len(ev_list)} cryptographic logs/captures verified")
                    except Exception:
                        pass
            ctx_items.append(f"Active Workspace: {self.current_workspace}")
            ctx = " | ".join(ctx_items)

        # Run in worker thread
        self._worker = AIChatWorker(
            engine=self.engine,
            messages=self.messages,
            project_context=ctx,
            user_consented=False,
        )
        self._worker.response_ready.connect(self._on_response_ready)
        self._worker.error_occurred.connect(self._on_worker_error)
        self._worker.start()

    @Slot(str, str)
    def _on_response_ready(self, reply: str, provider_used: str):
        self.btn_send.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.input_edit.setEnabled(True)
        self.lbl_loading.setText("")
        self.input_edit.setFocus()

        clean_reply = sanitize_text(reply)
        self.messages.append({"role": "assistant", "content": clean_reply})
        self._append_message("assistant", clean_reply, provider_used)

        # Extract executable commands for interactive operator review in Command Console
        commands = self.extract_shell_commands(clean_reply)
        self._update_commands_shelf(commands)

    @Slot(str)
    def _on_worker_error(self, err_msg: str):
        self.btn_send.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.input_edit.setEnabled(True)
        self.lbl_loading.setText("")
        self.input_edit.setFocus()
        clean_err = sanitize_text(err_msg)
        self._append_message("assistant", f"⚠️ **Error executing query**: {clean_err}\n\n[ 🔄 Retry Query ](retry:last)", "error")

    def extract_code_blocks(self, text: str) -> List[Dict[str, str]]:
        """Extract fenced markdown code blocks with language and content."""
        blocks: List[Dict[str, str]] = []
        pattern = re.compile(r"```([a-zA-Z0-9_\-+]*)\s*\n(.*?)\n```", re.DOTALL)
        for lang, code in pattern.findall(text):
            blocks.append({"language": lang.strip().lower(), "code": code.strip()})
        return blocks

    def extract_shell_commands(self, text: str) -> List[str]:
        """Extract actionable shell commands from code blocks and inline suggestions."""
        commands: List[str] = []
        code_block_pattern = re.compile(
            r"```(?:bash|sh|shell|console|zsh)?\s*\n(.*?)\n```",
            re.DOTALL | re.IGNORECASE,
        )
        for block in code_block_pattern.findall(text):
            for line in block.strip().splitlines():
                line = line.strip()
                if line.startswith("$ "):
                    line = line[2:].strip()
                elif line.startswith("# ") and not line.startswith("#!"):
                    continue
                if line and not line.startswith("#"):
                    commands.append(line)

        if not commands:
            tool_prefixes = (
                "nmap ", "sqlmap ", "nikto ", "gobuster ", "hydra ", "amass ", "nuclei ",
                "c0desec ", "vol ", "volatility3 ", "wafw00f ", "zap ", "chisel ", "curl ",
                "whois ", "dig ", "wpscan ", "sn1per ", "msfconsole ", "john ", "hashcat ",
                "./chisel"
            )
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("$ "):
                    line = line[2:].strip()
                if any(line.startswith(p) for p in tool_prefixes):
                    commands.append(line)

        # Deduplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for cmd in commands:
            if cmd not in seen:
                seen.add(cmd)
                deduped.append(cmd)
        return deduped

    def _update_commands_shelf(self, commands: List[str]):
        """Populate the suggested commands shelf with interactive buttons."""
        self.extracted_commands = list(commands)
        while self.commands_chips_layout.count():
            item = self.commands_chips_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not commands:
            self.commands_shelf.setVisible(False)
            return

        for cmd in commands[:4]:
            display_cmd = cmd if len(cmd) <= 50 else cmd[:47] + "..."
            btn = QPushButton(f"↗ {display_cmd}")
            btn.setFixedHeight(26)
            btn.setToolTip(f"Click to load command into Console prompt for review:\n{cmd}")
            btn.setProperty("class", "action-chip")
            btn.clicked.connect(lambda checked=False, c=cmd: self._send_command_to_shell(c))
            self.commands_chips_layout.addWidget(btn)

        self.commands_chips_layout.addStretch()
        self.commands_shelf.setVisible(True)

    def _send_command_to_shell(self, cmd: str):
        """Emits command to be loaded into the interactive Command Console."""
        self.command_to_shell_requested.emit(cmd)
        display_cmd = cmd if len(cmd) <= 50 else cmd[:47] + "..."
        self.lbl_context.setText(f"✓ Loaded into Console: {display_cmd}")
        is_light = ThemeManager.instance().is_light
        ok_col = "#15803D" if is_light else "#4ade80"
        self.lbl_context.setStyleSheet(f"color: {ok_col}; font-size: 11px; font-weight: 500;")

    @Slot(QUrl)
    def _on_anchor_clicked(self, url: QUrl):
        """Handles link clicks in the chat transcript: copy:, retry:, shell:, and web links."""
        scheme = url.scheme()
        if scheme == "copy":
            raw_spec = url.toString()
            payload = raw_spec[5:] if raw_spec.startswith("copy:") else raw_spec
            text_to_copy = unquote(payload).strip()
            if text_to_copy:
                QApplication.clipboard().setText(text_to_copy)
                self.lbl_loading.setText("✓ Copied to clipboard")
                QTimer.singleShot(
                    2500,
                    lambda: self.lbl_loading.setText("")
                    if self.lbl_loading.text() == "✓ Copied to clipboard"
                    else None,
                )
        elif scheme == "retry":
            self.retry_last()
        elif scheme == "shell":
            raw_spec = url.toString()
            cmd_part = raw_spec[6:] if raw_spec.startswith("shell:") else raw_spec
            if cmd_part.startswith("//"):
                cmd_part = cmd_part[2:]
            cmd = unquote(cmd_part).strip()
            if cmd:
                self._send_command_to_shell(cmd)
        elif scheme in ("http", "https"):
            QDesktopServices.openUrl(url)

    def _markdown_to_html(self, content: str, is_light: bool = False) -> str:
        """Converts markdown content into theme-aware HTML with copyable code blocks."""
        # 1. Preprocess fenced code blocks into placeholders
        blocks: List[tuple[str, str]] = []

        def repl_code(m):
            lang = m.group(1).strip() or "CODE"
            code = m.group(2).strip()
            idx = len(blocks)
            blocks.append((lang, code))
            return f"\n\n@@@CODE_BLOCK_{idx}@@@\n\n"

        code_pattern = re.compile(r"```([a-zA-Z0-9_\-+]*)\s*\n(.*?)\n```", re.DOTALL)
        preprocessed = code_pattern.sub(repl_code, content)

        # 2. Render markdown using QTextDocument
        doc = QTextDocument()
        doc.setMarkdown(preprocessed)
        raw_html = doc.toHtml()

        body_start = raw_html.find("<body")
        if body_start != -1:
            content_start = raw_html.find(">", body_start) + 1
            content_end = raw_html.rfind("</body>")
            inner_html = raw_html[content_start:content_end]
        else:
            inner_html = raw_html

        text_color = "#182230" if is_light else "#F8FAFC"
        heading_color = "#0F172A" if is_light else "#FFFFFF"
        code_card_bg = "#F1F5F9" if is_light else "#0F172A"
        code_header_bg = "#E2E8F0" if is_light else "#1E293B"
        code_fg = "#0369A1" if is_light else "#38BDF8"
        code_border = "#CBD5E1" if is_light else "#334155"
        accent_blue = "#1D4ED8" if is_light else "#60A5FA"

        # Explicitly colorize paragraphs, headings, list items, and spans
        inner_html = inner_html.replace("<p style=\"", f"<p style=\"color: {text_color}; margin-top: 4px; margin-bottom: 4px; ")
        inner_html = inner_html.replace("<p>", f"<p style=\"color: {text_color}; margin-top: 4px; margin-bottom: 4px;\">")
        for h in ["h1", "h2", "h3", "h4", "h5", "h6"]:
            inner_html = inner_html.replace(f"<{h} style=\"", f"<{h} style=\"color: {heading_color}; margin-top: 8px; margin-bottom: 4px; ")
            inner_html = inner_html.replace(f"<{h}>", f"<{h} style=\"color: {heading_color}; margin-top: 8px; margin-bottom: 4px;\">")
        inner_html = inner_html.replace("<li style=\"", f"<li style=\"color: {text_color}; ")
        inner_html = inner_html.replace("<li>", f"<li style=\"color: {text_color};\">")
        inner_html = inner_html.replace("<span style=\"", f"<span style=\"color: {text_color}; ")
        inner_html = inner_html.replace("<span>", f"<span style=\"color: {text_color};\">")

        # 3. Replace placeholders with rich code cards (with [ 📋 Copy Code ] action)
        for idx, (lang, code) in enumerate(blocks):
            esc_code = html.escape(code)
            quoted_code = quote(code)
            code_card = (
                f"<div style='margin: 8px 0; border: 1px solid {code_border}; border-radius: 6px; background-color: {code_card_bg};'>"
                f"<div style='padding: 4px 8px; background-color: {code_header_bg}; border-bottom: 1px solid {code_border}; font-size: 11px;'>"
                f"<span style='font-weight: bold; color: {heading_color};'>{lang.upper()}</span> &nbsp;&nbsp; "
                f"<a href='copy:{quoted_code}' style='color: {accent_blue}; text-decoration: none; font-weight: bold;'>[ 📋 Copy Code ]</a>"
                f"</div>"
                f"<pre style='margin: 0; padding: 8px 10px; color: {code_fg}; font-family: monospace; font-size: 12px;'>{esc_code}</pre>"
                f"</div>"
            )
            # Match both plain and paragraph-wrapped placeholder
            inner_html = inner_html.replace(f"<p>@@@CODE_BLOCK_{idx}@@@</p>", code_card)
            inner_html = inner_html.replace(f"@@@CODE_BLOCK_{idx}@@@", code_card)

        # Style any residual <pre> blocks
        inner_html = inner_html.replace(
            "<pre style=\"",
            f"<pre style=\"background-color: {code_card_bg}; color: {code_fg}; border: 1px solid {code_border}; padding: 8px 10px; border-radius: 6px; font-family: monospace; "
        )
        if "<pre>" in inner_html:
            inner_html = inner_html.replace(
                "<pre>",
                f"<pre style=\"background-color: {code_card_bg}; color: {code_fg}; border: 1px solid {code_border}; padding: 8px 10px; border-radius: 6px; font-family: monospace;\">"
            )
        return f"<div style=\"color: {text_color}; font-size: 13px; line-height: 1.5;\">{inner_html}</div>"

    def _render_message(self, role: str, content: str, provider_used: str = "", timestamp: str = ""):
        # If this is the first message being rendered, clear the empty state
        if len(self.chat_history) <= 1:
            self.chat_display.clear()

        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.chat_display.setTextCursor(cursor)

        is_light = ThemeManager.instance().is_light
        time_str = timestamp or datetime.datetime.now().strftime("%H:%M")

        if role == "user":
            escaped_user = html.escape(content).replace("\n", "<br>")
            bubble_bg = "#E2E8F0" if is_light else "#1E293B"
            bubble_fg = "#0F172A" if is_light else "#F8FAFC"
            bubble_border = "#CBD5E1" if is_light else "#334155"
            ts_color = "#64748B" if is_light else "#94A3B8"
            user_html = (
                f"<div style='margin: 10px 0; text-align: right;'>"
                f"<div style='display: inline-block; background-color: {bubble_bg}; color: {bubble_fg}; "
                f"padding: 8px 12px; border: 1px solid {bubble_border}; border-radius: 8px; max-width: 82%; text-align: left;'>"
                f"<div style='font-size: 11px; margin-bottom: 4px; color: {ts_color};'><b>👤 You</b> · {time_str}</div>"
                f"<div style='font-size: 13px; line-height: 1.4;'>{escaped_user}</div>"
                f"</div></div>"
            )
            cursor.insertHtml(user_html)
        else:
            accent_blue = "#1D4ED8" if is_light else "#60A5FA"
            heading_color = "#0F172A" if is_light else "#FFFFFF"
            ts_color = "#64748B" if is_light else "#94A3B8"
            prov_badge = f"<span style='color: {accent_blue}; font-size: 10px; font-weight: 500;'> [{provider_used}]</span>" if provider_used else ""

            header_html = (
                f"<div style='margin-top: 10px; margin-bottom: 4px; color: {heading_color}; font-size: 12px;'>"
                f"<b>🤖 AI Assistant</b>{prov_badge} <span style='color: {ts_color}; font-size: 10px;'>· {time_str}</span>"
                f"</div>"
            )
            cursor.insertHtml(header_html)

            styled_html = self._markdown_to_html(content, is_light=is_light)
            cursor.insertHtml(styled_html)

            # Footer actions: [ 📋 Copy Response ] + Shell Action Links
            quoted_full = quote(content)
            amber = "#B45309" if is_light else "#F59E0B"
            footer_html = "<div style='margin-top: 6px; margin-bottom: 8px; font-size: 11px;'>"
            footer_html += (
                f"<a href='copy:{quoted_full}' style='color: {accent_blue}; text-decoration: none; margin-right: 14px; font-weight: bold;'>"
                f"[ 📋 Copy Response ]</a>"
            )

            cmds = self.extract_shell_commands(content)
            if cmds:
                footer_html += f"<span style='color: {amber}; font-weight: bold;'>⚡ Shell Actions: </span>"
                for cmd in cmds[:3]:
                    escaped_cmd = html.escape(cmd if len(cmd) <= 45 else cmd[:42] + "...")
                    quoted_cmd = quote(cmd)
                    footer_html += (
                        f"<a href='shell:{quoted_cmd}' style='color: {accent_blue}; text-decoration: none; margin-right: 10px;'>"
                        f"<b>[ ↗ Load: <code>{escaped_cmd}</code> ]</b></a>"
                    )
            footer_html += "</div>"
            cursor.insertHtml(footer_html)

            divider_color = "#CBD5E1" if is_light else "#334155"
            cursor.insertHtml(f"<hr style='border: 0; border-top: 1px solid {divider_color}; margin: 8px 0;'>")

        sb = self.chat_display.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _append_message(self, role: str, content: str, provider_used: str = ""):
        timestamp = datetime.datetime.now().strftime("%H:%M")
        self.chat_history.append({
            "role": role,
            "content": content,
            "provider": provider_used,
            "timestamp": timestamp,
        })
        self._render_message(role, content, provider_used, timestamp)

    def update_theme(self, mode: Optional[str] = None):
        """Re-renders existing chat history with updated theme colors and refreshes status badges."""
        self.chat_display.clear()
        if not self.chat_history:
            self._show_empty_state()
        else:
            for msg in self.chat_history:
                self._render_message(
                    msg["role"],
                    msg["content"],
                    msg.get("provider", ""),
                    msg.get("timestamp", ""),
                )
        self._update_context_label()
        self._update_key_status_label()

    def _update_key_status_label(self):
        """Updates provider status label and mode indicator with accessible high-contrast colors."""
        if not hasattr(self, "lbl_key_status") or not hasattr(self, "provider_combo"):
            return
        idx = self.provider_combo.currentIndex()
        is_light = ThemeManager.instance().is_light
        ok_color = "#15803D" if is_light else "#4ade80"
        warn_color = "#B45309" if is_light else "#F59E0B"
        info_color = "#1D4ED8" if is_light else "#60A5FA"

        if idx == 0:
            self.lbl_key_status.setText("● Offline Ready")
            self.lbl_key_status.setStyleSheet(f"color: {ok_color}; font-size: 11px; font-weight: bold;")
            if hasattr(self, "lbl_mode"):
                self.lbl_mode.setText("[ 🔒 Offline Mode ]")
                self.lbl_mode.setStyleSheet(
                    f"font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; "
                    f"background: rgba(74, 222, 128, 0.15); color: {ok_color};"
                )
        elif idx == 1:
            self.lbl_key_status.setText("● Local (No Key)")
            self.lbl_key_status.setStyleSheet(f"color: {info_color}; font-size: 11px; font-weight: bold;")
            if hasattr(self, "lbl_mode"):
                self.lbl_mode.setText("[ 🏠 Local Ollama ]")
                self.lbl_mode.setStyleSheet(
                    f"font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; "
                    f"background: rgba(96, 165, 250, 0.15); color: {info_color};"
                )
        else:
            provider_map = {
                2: AIProvider.GEMINI_API,
                3: AIProvider.OPENAI_API,
                4: AIProvider.DEEPSEEK_API,
                5: AIProvider.ANTHROPIC_API,
                6: AIProvider.CUSTOM_OPENAI_COMPATIBLE,
            }
            p = provider_map.get(idx)
            has_key = bool(self.engine.get_api_key(p)) if p else False
            if idx == 6 and ("localhost" in self.engine.custom_api_url or "127.0.0.1" in self.engine.custom_api_url):
                has_key = True
            if has_key:
                self.lbl_key_status.setText("● Key Ready" if idx != 6 else "● Ready")
                self.lbl_key_status.setStyleSheet(f"color: {ok_color}; font-size: 11px; font-weight: bold;")
            else:
                self.lbl_key_status.setText("○ Key Missing")
                self.lbl_key_status.setStyleSheet(f"color: {warn_color}; font-size: 11px; font-weight: bold;")
            if hasattr(self, "lbl_mode"):
                self.lbl_mode.setText("[ ☁️ Cloud API ]")
                self.lbl_mode.setStyleSheet(
                    f"font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; "
                    f"background: rgba(245, 158, 11, 0.15); color: {warn_color if not has_key else ok_color};"
                )

    @Slot(int)
    def _on_provider_changed(self, index: int):
        provider_map = {
            0: AIProvider.BUILTIN_OFFLINE,
            1: AIProvider.LOCAL_OLLAMA,
            2: AIProvider.GEMINI_API,
            3: AIProvider.OPENAI_API,
            4: AIProvider.DEEPSEEK_API,
            5: AIProvider.ANTHROPIC_API,
            6: AIProvider.CUSTOM_OPENAI_COMPATIBLE,
        }
        if index in provider_map:
            self.engine.provider = provider_map[index]
        self._update_key_status_label()

    @Slot()
    def _open_settings(self):
        from desktop.dialogs.ai_settings_dialog import AISettingsDialog
        dlg = AISettingsDialog(engine=self.engine, parent=self)
        if dlg.exec():
            self._on_provider_changed(self.provider_combo.currentIndex())
