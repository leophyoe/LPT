"""Terminal AI Copilot and Intelligent Security Assistant Widget.

Provides one-click terminal output diagnosis, error root-cause explanation,
natural language to pentest command synthesis with live scope validation,
and automated finding extraction for assessment reports.
"""

from __future__ import annotations

import os
from typing import List, Optional

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.ai_copilot import AICopilotEngine, AIProvider
from desktop.theme import CPENTTheme
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project, TargetScope


class TerminalAIAssistantWidget(QWidget):
    """Integrated AI Copilot for interactive terminal assistance and report generation."""

    command_ready = Signal(str)  # Emits generated command to insert into terminal

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
        self.active_project: Optional[Project] = None
        self.db: Optional[Database] = None
        self.terminal_get_output_cb = None
        self._extracted_findings: List[Finding] = []

        self._init_ui()

    def set_context(self, project: Optional[Project], db: Optional[Database]):
        self.active_project = project
        self.db = db
        if project:
            self.lbl_context.setText(f"Active Scope Context: Project '{project.name}' (ID: {project.id})")
            self.lbl_context.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: 500;")
        else:
            self.lbl_context.setText("Active Scope Context: No project selected (Scope validation disabled)")
            self.lbl_context.setStyleSheet("color: #94a3b8; font-size: 11px;")

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # 1. Header Toolbar in scroll area for responsive fitting
        top_bar_scroll = QScrollArea()
        top_bar_scroll.setWidgetResizable(True)
        top_bar_scroll.setFixedHeight(38)
        top_bar_scroll.setFrameShape(QFrame.NoFrame)
        top_bar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        top_bar_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        top_container = QWidget()
        top_bar = QHBoxLayout(top_container)
        top_bar.setContentsMargins(0, 0, 0, 0)
        top_bar.setSpacing(6)

        title = QLabel("🤖 AI Terminal Copilot & Report Assistant")
        title.setStyleSheet(f"font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE}; font-size: 13px; font-family: {CPENTTheme.FONT_FAMILY_HEADING};")
        top_bar.addWidget(title)
        top_bar.addStretch()

        lbl_prov = QLabel("Engine:")
        lbl_prov.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        top_bar.addWidget(lbl_prov)

        self.provider_combo = QComboBox()
        self.provider_combo.addItems([
            "Built-in Security Engine (100% Offline)",
            "Local Ollama (http://127.0.0.1:11434)",
            "Google Gemini API (Cloud)",
            "OpenAI API (Cloud)",
        ])
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        top_bar.addWidget(self.provider_combo)

        self.lbl_key_status = QLabel("● Offline Ready")
        self.lbl_key_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px; font-weight: bold;")
        top_bar.addWidget(self.lbl_key_status)

        self.btn_open_settings = QPushButton("⚙️ Settings & Keys")
        self.btn_open_settings.setFixedHeight(24)
        self.btn_open_settings.clicked.connect(self._open_ai_settings)
        top_bar.addWidget(self.btn_open_settings)

        self.btn_open_full_chat = QPushButton("💬 Full Chat")
        self.btn_open_full_chat.setFixedHeight(24)
        self.btn_open_full_chat.setProperty("class", "action-primary")
        self.btn_open_full_chat.clicked.connect(self._open_full_chat)
        top_bar.addWidget(self.btn_open_full_chat)

        top_bar_scroll.setWidget(top_container)
        layout.addWidget(top_bar_scroll)

        self.lbl_context = QLabel("Active Scope Context: No project selected")
        self.lbl_context.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        layout.addWidget(self.lbl_context)

        # 2. Main Work Area (Splitter: Diagnosis on top, Command & Finding Extractor on bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # --- Top Section: Output Diagnosis & Error Helper ---
        diag_frame = QFrame()
        diag_frame.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px;")
        diag_layout = QVBoxLayout(diag_frame)
        diag_layout.setContentsMargins(8, 8, 8, 8)
        diag_layout.setSpacing(6)

        diag_hdr = QHBoxLayout()
        lbl_diag = QLabel("🔍 Terminal Output Diagnosis & Error Root-Cause")
        lbl_diag.setStyleSheet(f"font-weight: 600; color: {CPENTTheme.PRIMARY_TEXT}; font-size: 12px;")
        diag_hdr.addWidget(lbl_diag)
        diag_hdr.addStretch()

        self.btn_diagnose = QPushButton("⚡ Analyze Current Terminal Output")
        self.btn_diagnose.setProperty("class", "action-primary")
        self.btn_diagnose.clicked.connect(self._diagnose_terminal_output)
        diag_hdr.addWidget(self.btn_diagnose)
        diag_layout.addLayout(diag_hdr)

        self.chk_consent = QCheckBox("Consent to send sanitized terminal snippet to Cloud AI (Passwords and tokens automatically redacted)")
        self.chk_consent.setChecked(True)
        self.chk_consent.setVisible(False)
        self.chk_consent.setStyleSheet("color: #94a3b8; font-size: 11px;")
        diag_layout.addWidget(self.chk_consent)

        self.txt_diagnosis = QTextEdit()
        self.txt_diagnosis.setReadOnly(True)
        self.txt_diagnosis.setFont(QFont("Monospace", 9))
        self.txt_diagnosis.setPlaceholderText("Click 'Analyze Current Terminal Output' to diagnose errors, root cause, and next pentest steps...")
        self.txt_diagnosis.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.PRIMARY_TEXT}; border: 1px solid {CPENTTheme.BORDER}; min-height: 80px;")
        diag_layout.addWidget(self.txt_diagnosis)

        self.btn_insert_fix = QPushButton("⚡ Load Suggested Fix Command into Shell")
        self.btn_insert_fix.setEnabled(False)
        self.btn_insert_fix.clicked.connect(self._apply_suggested_fix)
        diag_layout.addWidget(self.btn_insert_fix)

        splitter.addWidget(diag_frame)

        # --- Bottom Section: Natural Language Command & Finding Extractor ---
        bottom_frame = QFrame()
        bottom_frame.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px;")
        bot_layout = QVBoxLayout(bottom_frame)
        bot_layout.setContentsMargins(8, 8, 8, 8)
        bot_layout.setSpacing(6)

        # Row A: Natural Language Command
        lbl_cmd = QLabel("⚡ Natural Language to Pentest Command (Scope-Guarded)")
        lbl_cmd.setStyleSheet(f"font-weight: 600; color: {CPENTTheme.PRIMARY_TEXT}; font-size: 12px;")
        bot_layout.addWidget(lbl_cmd)

        cmd_input_row = QHBoxLayout()
        self.cmd_prompt_input = QLineEdit()
        self.cmd_prompt_input.setPlaceholderText("Type request (e.g. 'fast port scan on 127.0.0.1', 'find login directory with gobuster')...")
        self.cmd_prompt_input.returnPressed.connect(self._generate_command)
        cmd_input_row.addWidget(self.cmd_prompt_input, 4)

        self.btn_gen_cmd = QPushButton("Generate Command")
        self.btn_gen_cmd.setProperty("class", "action-primary")
        self.btn_gen_cmd.clicked.connect(self._generate_command)
        cmd_input_row.addWidget(self.btn_gen_cmd, 1)
        bot_layout.addLayout(cmd_input_row)

        cmd_result_row = QHBoxLayout()
        self.lbl_cmd_preview = QLabel("Command: (Awaiting prompt)")
        self.lbl_cmd_preview.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-family: {CPENTTheme.FONT_FAMILY_MONO}; font-size: 11px;")
        self.lbl_cmd_preview.setWordWrap(True)
        cmd_result_row.addWidget(self.lbl_cmd_preview, 3)

        self.lbl_scope_pill = QLabel("Scope: —")
        self.lbl_scope_pill.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px; font-weight: bold;")
        cmd_result_row.addWidget(self.lbl_scope_pill, 1)

        self.btn_send_to_shell = QPushButton("Insert to Terminal")
        self.btn_send_to_shell.setEnabled(False)
        self.btn_send_to_shell.clicked.connect(self._insert_generated_command)
        cmd_result_row.addWidget(self.btn_send_to_shell, 1)
        bot_layout.addLayout(cmd_result_row)

        # Row B: Extract Findings to Assessment Report
        bot_layout.addSpacing(6)
        ext_hdr = QHBoxLayout()
        lbl_ext = QLabel("🛡️ Extract Findings from Terminal into Assessment Report")
        lbl_ext.setStyleSheet("font-weight: 600; color: #f8fafc; font-size: 12px;")
        ext_hdr.addWidget(lbl_ext)
        ext_hdr.addStretch()

        self.btn_extract = QPushButton("🔍 Extract Findings from Output")
        self.btn_extract.setProperty("class", "action-secondary")
        self.btn_extract.clicked.connect(self._extract_findings)
        ext_hdr.addWidget(self.btn_extract)

        self.btn_save_findings = QPushButton("💾 Save Extracted Findings to Report DB")
        self.btn_save_findings.setProperty("class", "action-primary")
        self.btn_save_findings.setEnabled(False)
        self.btn_save_findings.clicked.connect(self._save_findings_to_db)
        ext_hdr.addWidget(self.btn_save_findings)
        bot_layout.addLayout(ext_hdr)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Discovered Finding Title", "Target", "Remediation"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setAlternatingRowColors(True)
        bot_layout.addWidget(self.findings_table)

        splitter.addWidget(bottom_frame)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        layout.addWidget(splitter)

    @Slot(int)
    def _on_provider_changed(self, index: int):
        if index == 0:
            self.engine.provider = AIProvider.BUILTIN_OFFLINE
            self.lbl_key_status.setText("● Offline Ready")
            self.lbl_key_status.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: bold;")
            self.chk_consent.setVisible(False)
        elif index == 1:
            self.engine.provider = AIProvider.LOCAL_OLLAMA
            self.lbl_key_status.setText("● Local (No Key)")
            self.lbl_key_status.setStyleSheet("color: #38bdf8; font-size: 11px; font-weight: bold;")
            self.chk_consent.setVisible(False)
        elif index == 2:
            self.engine.provider = AIProvider.GEMINI_API
            has_key = bool(self.engine.get_api_key(AIProvider.GEMINI_API))
            if has_key:
                self.lbl_key_status.setText("● Key Ready")
                self.lbl_key_status.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: bold;")
            else:
                self.lbl_key_status.setText("⚠️ Key Missing (Click ⚙️)")
                self.lbl_key_status.setStyleSheet("color: #f87171; font-size: 11px; font-weight: bold;")
            self.chk_consent.setVisible(True)
        elif index == 3:
            self.engine.provider = AIProvider.OPENAI_API
            has_key = bool(self.engine.get_api_key(AIProvider.OPENAI_API))
            if has_key:
                self.lbl_key_status.setText("● Key Ready")
                self.lbl_key_status.setStyleSheet("color: #4ade80; font-size: 11px; font-weight: bold;")
            else:
                self.lbl_key_status.setText("⚠️ Key Missing (Click ⚙️)")
                self.lbl_key_status.setStyleSheet("color: #f87171; font-size: 11px; font-weight: bold;")
            self.chk_consent.setVisible(True)

    @Slot()
    def _open_ai_settings(self):
        from desktop.dialogs.ai_settings_dialog import AISettingsDialog
        dlg = AISettingsDialog(self.engine, parent=self)
        if dlg.exec():
            self._on_provider_changed(self.provider_combo.currentIndex())

    @Slot()
    def _diagnose_terminal_output(self):
        output = ""
        if callable(self.terminal_get_output_cb):
            output = self.terminal_get_output_cb()

        if not output.strip():
            self.txt_diagnosis.setPlainText("Terminal has no recorded output to analyze yet. Run a command first.")
            return

        user_consented = self.chk_consent.isChecked() if self.chk_consent.isVisible() else True
        diag = self.engine.diagnose_output(output, user_consented=user_consented)
        text = (
            f"=== Technical Analysis ({diag.provider_used}) ===\n{diag.analysis}\n\n"
            f"=== Root Cause / Observation ===\n{diag.root_cause}\n\n"
            f"=== Recommended Action / Remediation ===\n{diag.suggested_fix}\n"
        )
        if diag.suggested_command:
            text += f"\n=== Suggested Command ===\n{diag.suggested_command}\n"
            self.btn_insert_fix.setEnabled(True)
            self.btn_insert_fix.setProperty("fix_cmd", diag.suggested_command)
        else:
            self.btn_insert_fix.setEnabled(False)

        self.txt_diagnosis.setPlainText(text)

    @Slot()
    def _apply_suggested_fix(self):
        cmd = self.btn_insert_fix.property("fix_cmd")
        if cmd:
            self.command_ready.emit(cmd)

    @Slot()
    def _generate_command(self):
        prompt = self.cmd_prompt_input.text().strip()
        if not prompt:
            return

        if not self.db or not self.active_project:
            self.btn_send_to_shell.setEnabled(False)
            self.lbl_scope_pill.setText("Scope: ✗ Select an authorized project")
            self.lbl_scope_pill.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-size: 11px; font-weight: bold;")
            self.lbl_cmd_preview.setText("Select an active project with authorized target scopes to generate a runnable command.")
            return

        scopes = self.db.list_scopes(self.active_project.id)
        target_hint = None
        if scopes and len(scopes) > 0:
            target_hint = scopes[0].target

        res = self.engine.generate_command(prompt=prompt, target=target_hint, scopes=scopes)
        self.lbl_cmd_preview.setText(f"Generated Command: {res.command}\nExplanation: {res.explanation}")

        if res.is_in_scope:
            self.lbl_scope_pill.setText("Scope: ✓ Authorized")
            self.lbl_scope_pill.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px; font-weight: bold;")
            self.btn_send_to_shell.setEnabled(True)
            self.btn_send_to_shell.setProperty("gen_cmd", res.command)
        else:
            self.lbl_scope_pill.setText("Scope: ✗ Blocked Out-of-Scope")
            self.lbl_scope_pill.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-size: 11px; font-weight: bold;")
            self.btn_send_to_shell.setEnabled(False)
            QMessageBox.warning(
                self,
                "Scope Guard Alert",
                f"Generated command target is OUT OF SCOPE:\n\n{res.scope_reason}\n\n"
                "To run this test, explicitly add the target to your project scope first.",
            )

    @Slot()
    def _insert_generated_command(self):
        cmd = self.btn_send_to_shell.property("gen_cmd")
        if cmd:
            self.command_ready.emit(cmd)

    @Slot()
    def _extract_findings(self):
        output = ""
        if callable(self.terminal_get_output_cb):
            output = self.terminal_get_output_cb()

        if not output.strip():
            QMessageBox.information(self, "No Output", "No terminal output available to extract findings.")
            return

        target = "127.0.0.1"
        if self.db and self.active_project:
            scopes = self.db.list_scopes(self.active_project.id)
            if scopes:
                target = scopes[0].target

        proj_id = self.active_project.id if self.active_project else 1
        self._extracted_findings = self.engine.extract_findings_from_terminal(
            output=output, target=target, project_id=proj_id
        )

        self.findings_table.setRowCount(len(self._extracted_findings))
        for row, f in enumerate(self._extracted_findings):
            # Severity Item
            item_sev = QTableWidgetItem(f.severity.value.upper())
            item_sev.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if f.severity == FindingSeverity.CRITICAL:
                item_sev.setForeground(QColor(CPENTTheme.ERROR_RED))
            elif f.severity == FindingSeverity.HIGH:
                item_sev.setForeground(QColor("#F97316"))
            elif f.severity == FindingSeverity.MEDIUM:
                item_sev.setForeground(QColor(CPENTTheme.AMBER_ACCENT))
            else:
                item_sev.setForeground(QColor(CPENTTheme.INFO_CYAN))
            self.findings_table.setItem(row, 0, item_sev)

            self.findings_table.setItem(row, 1, QTableWidgetItem(f.title))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f.affected_asset))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f.remediation))

        if self._extracted_findings:
            self.btn_save_findings.setEnabled(True)
            self.btn_save_findings.setText(f"💾 Save {len(self._extracted_findings)} Findings to Report DB")
        else:
            self.btn_save_findings.setEnabled(False)
            QMessageBox.information(
                self,
                "Extraction Complete",
                "No explicit security vulnerabilities or open services identified in current terminal output.",
            )

    @Slot()
    def _save_findings_to_db(self):
        if not self.db or not self.active_project:
            QMessageBox.warning(self, "No Project", "Select an active project before saving findings to database.")
            return

        if not self._extracted_findings:
            return

        saved_count = 0
        for f in self._extracted_findings:
            f.project_id = self.active_project.id
            self.db.create_finding(f)
            saved_count += 1

        self.btn_save_findings.setEnabled(False)
        self.btn_save_findings.setText("✓ Saved to Report Database")

        # Refresh findings view if main window exists
        win = self.window()
        if hasattr(win, "findings_view"):
            win.findings_view.load_findings(self.active_project.id)

        QMessageBox.information(
            self,
            "Findings Saved",
            f"Successfully persisted {saved_count} findings to project '{self.active_project.name}'.\n\n"
            "These findings are now permanently stored and will appear in generated HTML, Markdown, and JSON reports.",
        )

    @Slot()
    def _open_full_chat(self):
        """Switches to the full AI Security Copilot Chatbot view."""
        win = self.window()
        if hasattr(win, "btn_ai_chat") and hasattr(win, "view_stack"):
            win.btn_ai_chat.setChecked(True)
            win.view_stack.setCurrentIndex(6)

