"""Web Application and API assessment view integrating c0desec."""

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.scope import ScopeAuthorizationService
from core.strix_triage import StrixTriageEngine
from desktop.theme import CPENTTheme
from modules.orchestration.sn1per_orchestrator import Sn1perScanMode
from modules.web.burp_adapter import BurpSuiteAdapter
from modules.web.c0desec_adapter import (
    WebScanOptions,
    WebScanResult,
    WebSecurityAdapter,
)
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.nikto_adapter import NiktoAdapter, NiktoScanOptions
from modules.web.zap_adapter import ZAPAdapter
from modules.web.ptk_engine import (
    PTKEncoder,
    PTKJWTAnalyzer,
    PTKPayloads,
    PTKRequestBuilder,
    PTKSCAAnalyzer,
)
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import ExecutionStatus, Finding, FindingSeverity, Project, ToolExecution


class WebWorkerSignals(QObject):
    output_received = Signal(str, str)
    scan_completed = Signal(bool, str, object, object)


class WebScanView(QWidget):
    """Web & API assessment interface with scope enforcement, live validation, and secret detection."""

    project_data_updated = Signal()

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.adapter = WebSecurityAdapter(db)
        self.wafw00f_adapter = WAFW00FAdapter(db)
        self.sqlmap_adapter = SQLMapAdapter(db)
        self.gobuster_adapter = GobusterAdapter(db)
        self.nikto_adapter = NiktoAdapter(db)
        self.zap_adapter = ZAPAdapter(db)
        self.burp_adapter = BurpSuiteAdapter(db)
        self.active_project: Optional[Project] = None
        self._scan_project_id: Optional[int] = None
        self._current_findings: List[Finding] = []
        self._zap_proc: Optional[subprocess.Popen] = None
        self._scan_thread: Optional[threading.Thread] = None

        self.signals = WebWorkerSignals()
        self.signals.output_received.connect(self._on_output_received)
        self.signals.scan_completed.connect(self._on_scan_completed)

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        if project:
            self.project_label.setText(f"Active Project: {project.name} (ID: {project.id})")
        else:
            self.project_label.setText("No project selected.")
        self._validate_scope_live()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 1. Header bar
        top_bar = QHBoxLayout()
        header = QLabel("Web Testing")
        header.setObjectName("viewHeader")
        top_bar.addWidget(header)
        top_bar.addStretch()

        self.project_label = QLabel("No project selected.")
        self.project_label.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-weight: 600;")
        top_bar.addWidget(self.project_label)
        layout.addLayout(top_bar)

        # 2. Config & Scope Guard Box
        config_group = QGroupBox("Target Scope & Assessment Profiles")
        form = QFormLayout(config_group)

        # Target URL & Live Scope Status
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g. http://127.0.0.1:8080, https://app.targetlab.corp)")
        self.url_input.textChanged.connect(self._validate_scope_live)
        url_row.addWidget(self.url_input, 4)

        self.scope_status_label = QLabel("Scope: No Project Selected")
        self.scope_status_label.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-weight: 500; padding-left: 8px;")
        url_row.addWidget(self.scope_status_label, 2)
        form.addRow("Target Web URL *:", url_row)

        # Checkboxes for modules
        check_box = QVBoxLayout()
        row1 = QHBoxLayout()
        self.cb_headers = QCheckBox("HTTP Security Headers")
        self.cb_headers.setChecked(True)
        self.cb_cors = QCheckBox("CORS Policy")
        self.cb_cors.setChecked(True)
        self.cb_secrets = QCheckBox("JS Secret Scanning")
        self.cb_secrets.setChecked(True)
        self.cb_endpoints = QCheckBox("Endpoint Discovery")
        self.cb_endpoints.setChecked(True)
        row1.addWidget(self.cb_headers)
        row1.addWidget(self.cb_cors)
        row1.addWidget(self.cb_secrets)
        row1.addWidget(self.cb_endpoints)
        row1.addStretch()

        row2 = QHBoxLayout()
        self.cb_waf = QCheckBox("WAF Fingerprint (WAFW00F)")
        self.cb_waf.setChecked(True)
        self.cb_sqlmap = QCheckBox("SQL Injection (SQLMap)")
        self.cb_sqlmap.setChecked(False)
        self.cb_gobuster = QCheckBox("Directory Fuzzing (Gobuster)")
        self.cb_gobuster.setChecked(False)
        self.cb_nikto = QCheckBox("Server Vuln Scan (Nikto)")
        self.cb_nikto.setChecked(False)
        row2.addWidget(self.cb_waf)
        row2.addWidget(self.cb_sqlmap)
        row2.addWidget(self.cb_gobuster)
        row2.addWidget(self.cb_nikto)
        row2.addStretch()

        check_box.addLayout(row1)
        check_box.addLayout(row2)

        # Sn1per Chained Scanning Profiles (1N3/Sn1per)
        profile_row = QHBoxLayout()
        lbl_prof = QLabel("⚡ Sn1per Orchestration Mode:")
        lbl_prof.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8;")
        profile_row.addWidget(lbl_prof)

        btn_sn1per_recon = QPushButton("🔍 Recon")
        btn_sn1per_recon.setToolTip("Passive Web Recon: Headers, CORS, Secrets, Endpoints (c0desec)")
        btn_sn1per_recon.clicked.connect(lambda: self._set_sn1per_profile("recon"))
        profile_row.addWidget(btn_sn1per_recon)

        btn_sn1per_stealth = QPushButton("🥷 Stealth")
        btn_sn1per_stealth.setToolTip("Stealth Network & WAF Fingerprinting")
        btn_sn1per_stealth.clicked.connect(lambda: self._set_sn1per_profile("stealth"))
        profile_row.addWidget(btn_sn1per_stealth)

        btn_sn1per_web = QPushButton("🌐 Web Full")
        btn_sn1per_web.setToolTip("Web Perimeter Audit: Headers, CORS, Secrets, Endpoints, WAF, and Gobuster Fuzzing")
        btn_sn1per_web.clicked.connect(lambda: self._set_sn1per_profile("web_full"))
        profile_row.addWidget(btn_sn1per_web)

        btn_sn1per_airstrike = QPushButton("💥 Airstrike")
        btn_sn1per_airstrike.setToolTip("Full Perimeter Assault: All Modules + SQLMap + Gobuster")
        btn_sn1per_airstrike.clicked.connect(lambda: self._set_sn1per_profile("airstrike"))
        profile_row.addWidget(btn_sn1per_airstrike)

        profile_row.addStretch()
        check_box.addLayout(profile_row)

        form.addRow("Security Modules:", check_box)

        # Execution Controls & Progress
        btn_bar = QHBoxLayout()
        self.scan_btn = QPushButton("Execute Authorized Web Scan")
        self.scan_btn.setProperty("class", "action-primary")
        self.scan_btn.clicked.connect(self._start_scan)
        btn_bar.addWidget(self.scan_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-secondary")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        btn_bar.addWidget(self.cancel_btn)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background-color: #1e293b; border-radius: 4px; text-align: center; font-size: 10px; color: #94a3b8; }"
            "QProgressBar::chunk { background-color: #0284c7; border-radius: 4px; }"
        )
        btn_bar.addWidget(self.progress_bar, 2)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color: #94a3b8;")
        btn_bar.addWidget(self.status_label, 2)
        form.addRow(btn_bar)

        layout.addWidget(config_group)

        # 3. Multi-Tab Results Display
        self.results_tabs = QTabWidget()

        # Tab 0: Structured Findings (Primary Table + Details Pane)
        findings_widget = QWidget()
        findings_layout = QVBoxLayout(findings_widget)
        findings_layout.setContentsMargins(4, 4, 4, 4)

        findings_splitter = QSplitter(Qt.Orientation.Vertical)

        # Findings Table
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Affected Asset / URL", "Finding Title", "Remediation"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.itemSelectionChanged.connect(self._on_finding_selected)
        findings_splitter.addWidget(self.findings_table)

        # Details Panel
        detail_container = QWidget()
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(6, 6, 6, 6)
        detail_layout.setSpacing(6)

        detail_header = QLabel("Finding Details & Redacted Evidence")
        detail_header.setStyleSheet("font-weight: 600; color: #38bdf8;")
        detail_layout.addWidget(detail_header)

        self.finding_details_text = QTextEdit()
        self.finding_details_text.setReadOnly(True)
        self.finding_details_text.setPlaceholderText("Select a finding row above to view technical details, explanation, and redacted evidence.")
        detail_layout.addWidget(self.finding_details_text)

        findings_splitter.addWidget(detail_container)
        findings_splitter.setStretchFactor(0, 6)
        findings_splitter.setStretchFactor(1, 4)

        findings_layout.addWidget(findings_splitter)
        self.results_tabs.addTab(findings_widget, "🛡️ Structured Findings")

        # Tab 1: Endpoints
        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(1)
        self.endpoints_table.setHorizontalHeaderLabels(["Discovered Endpoint / Route URL"])
        self.endpoints_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_tabs.addTab(self.endpoints_table, "🌐 Discovered Routes")

        # Tab 2: Secrets
        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(4)
        self.secrets_table.setHorizontalHeaderLabels(["Secret Kind", "Redacted Preview", "Source Asset", "Context Snippet"])
        self.secrets_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_tabs.addTab(self.secrets_table, "🔑 JS Secret Candidates")

        # Tab 3: Headers
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Header Name", "Header Value"])
        self.headers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.headers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_tabs.addTab(self.headers_table, "📋 Response Headers")

        # Tab 4: Interception Proxy (OWASP ZAP & Burp Suite) - Optional external GUI launchers
        self.proxy_tab = self._create_proxy_tools_tab()
        self._proxy_tab_visible = False
        # External GUI hacking tools (ZAP/Burp launchers) are hidden by default to keep the interface
        # clean, uncluttered, and terminal-centric. Call set_proxy_tab_visible(True) if needed.

        # Tab 5: OWASP PTK Workbench (R-Builder / JWT Lab / Encoders / SCA)
        self.ptk_tab = self._create_ptk_workbench_tab()
        self.results_tabs.addTab(self.ptk_tab, "🧰 OWASP PTK Workbench")

        layout.addWidget(self.results_tabs)

    def set_proxy_tab_visible(self, visible: bool):
        """Shows or hides the external GUI proxy launcher tab."""
        if visible and not getattr(self, "_proxy_tab_visible", False):
            self.results_tabs.addTab(self.proxy_tab, "🌐 Interception Proxy (ZAP / Burp Suite)")
            self._proxy_tab_visible = True
        elif not visible and getattr(self, "_proxy_tab_visible", False):
            for idx in range(self.results_tabs.count()):
                if self.results_tabs.widget(idx) == self.proxy_tab:
                    self.results_tabs.removeTab(idx)
                    break
            self._proxy_tab_visible = False

    def is_proxy_tab_visible(self) -> bool:
        return getattr(self, "_proxy_tab_visible", False)

    def _validate_scope_live(self):
        """Live scope validation as user types the target URL."""
        if not self.active_project:
            self.scope_status_label.setText("Scope: No Project Selected")
            self.scope_status_label.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-weight: 500;")
            return

        raw_url = self.url_input.text().strip()
        if not raw_url:
            self.scope_status_label.setText("Scope: Awaiting Target URL")
            self.scope_status_label.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-weight: 500;")
            return

        target = raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}"
        parsed = urlparse(target)
        host = parsed.hostname or target

        scopes = self.db.list_scopes(self.active_project.id)
        check = ScopeAuthorizationService.is_target_authorized(host, scopes)
        if check.is_allowed:
            self.scope_status_label.setText("Scope: Authorized (In-Scope) ✓")
            self.scope_status_label.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold;")
        else:
            self.scope_status_label.setText("Scope: Unauthorized / Out of Scope ✗")
            self.scope_status_label.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-weight: bold;")

    def _start_scan(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an assessment project first.")
            return

        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please specify a target URL.")
            return

        # Active assessment confirmation guard
        if self.cb_sqlmap.isChecked() or self.cb_gobuster.isChecked():
            confirm = QMessageBox.question(
                self,
                "Confirm Active Security Assessment",
                f"You have selected ACTIVE assessment tools (SQLMap / Gobuster) targeting:\n\n{target_url}\n\n"
                "Active scans send fuzzing requests and test injection vectors.\n"
                "Do you confirm that you have explicit, documented authorization to test this target?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirm != QMessageBox.StandardButton.Yes:
                self.status_label.setText("Status: Active scan aborted by user.")
                return

        options = WebScanOptions(
            target_url=target_url,
            check_headers=self.cb_headers.isChecked(),
            check_cors=self.cb_cors.isChecked(),
            check_js_secrets=self.cb_secrets.isChecked(),
            discover_endpoints=self.cb_endpoints.isChecked(),
            check_dns=True,
            timeout=10.0,
        )

        scan_project = self.active_project
        project_id = scan_project.id
        self._scan_project_id = project_id
        scopes = self.db.list_scopes(project_id)
        assessment_id = self._get_active_assessment_id()
        evidence_dir = Path(__file__).resolve().parents[2] / "storage" / "evidence"

        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate animation
        self.status_label.setText(f"Status: Probing {target_url}...")
        self.status_label.setStyleSheet("color: #38bdf8;")

        run_waf = self.cb_waf.isChecked()
        run_sqlmap = self.cb_sqlmap.isChecked()
        run_gobuster = self.cb_gobuster.isChecked()
        run_nikto = self.cb_nikto.isChecked()

        def worker():
            all_findings = []
            all_endpoints = []
            all_secrets = []
            all_headers = {}
            primary_exec = None

            # 1. c0desec passive scan
            if options.check_headers or options.check_cors or options.check_js_secrets or options.discover_endpoints:
                success, msg, res, exec_rec = self.adapter.execute_scan(
                    project_id=project_id,
                    options=options,
                    scopes=scopes,
                    project=scan_project,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=evidence_dir,
                    assessment_id=assessment_id,
                )
                primary_exec = exec_rec
                if not success:
                    self.signals.scan_completed.emit(False, msg, None, exec_rec)
                    return
                if res:
                    all_findings.extend(res.findings)
                    all_endpoints.extend(res.endpoints)
                    all_secrets.extend(res.secrets)
                    all_headers.update(res.headers)

            # 2. WAFW00F fingerprinting
            if run_waf:
                self.signals.output_received.emit("\n[*] Launching WAFW00F Fingerprinting...\n", "stdout")
                waf_opts = WAFW00FOptions(target_url=target_url)
                w_ok, w_msg, w_findings, w_exec = self.wafw00f_adapter.execute_scan(
                    project_id=project_id,
                    options=waf_opts,
                    scopes=scopes,
                    assessment_id=assessment_id,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=evidence_dir,
                )
                if w_exec and not primary_exec:
                    primary_exec = w_exec
                all_findings.extend(w_findings)

            # 3. SQLMap injection check
            if run_sqlmap:
                self.signals.output_received.emit("\n[*] Launching SQLMap Injection Checks...\n", "stdout")
                s_opts = SQLMapOptions(target_url=target_url)
                s_ok, s_msg, s_findings, s_exec = self.sqlmap_adapter.execute_scan(
                    project_id=project_id,
                    options=s_opts,
                    scopes=scopes,
                    assessment_id=assessment_id,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=evidence_dir,
                )
                if s_exec and not primary_exec:
                    primary_exec = s_exec
                all_findings.extend(s_findings)

            # 4. Gobuster directory discovery
            if run_gobuster:
                self.signals.output_received.emit("\n[*] Launching Gobuster Directory Discovery...\n", "stdout")
                g_opts = GobusterOptions(target_url=target_url)
                g_ok, g_msg, g_findings, g_exec = self.gobuster_adapter.execute_scan(
                    project_id=project_id,
                    options=g_opts,
                    scopes=scopes,
                    assessment_id=assessment_id,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                    evidence_dir=evidence_dir,
                )
                if g_exec and not primary_exec:
                    primary_exec = g_exec
                all_findings.extend(g_findings)
                for f in g_findings:
                    if f.affected_asset and f.affected_asset not in all_endpoints:
                        all_endpoints.append(f.affected_asset)

            # 5. Nikto web vulnerability scan
            if run_nikto:
                self.signals.output_received.emit("\n[*] Launching Nikto Web Vulnerability Scanner...\n", "stdout")
                n_opts = NiktoScanOptions(target=target_url)
                n_res = self.nikto_adapter.execute_scan(
                    project_id=project_id,
                    options=n_opts,
                    scopes=scopes,
                    assessment_id=assessment_id,
                    on_output=lambda chunk, stream: self.signals.output_received.emit(chunk, stream),
                )
                if n_res.execution and not primary_exec:
                    primary_exec = n_res.execution
                all_findings.extend(n_res.findings)

            composite_res = WebScanResult(
                target_url=target_url,
                findings=all_findings,
                endpoints=all_endpoints,
                secrets=all_secrets,
                headers=all_headers,
            )
            self.signals.scan_completed.emit(True, "Assessment complete", composite_res, primary_exec)

        def guarded_worker():
            try:
                worker()
            except Exception as exc:
                message = f"Web scan failed: {exc}"
                self.signals.output_received.emit(f"[-] {message}\n", "stderr")
                self.signals.scan_completed.emit(False, message, None, None)

        self._scan_thread = threading.Thread(target=guarded_worker, daemon=True)
        self._scan_thread.start()

    def _cancel_scan(self):
        self.adapter.cancel()
        self.wafw00f_adapter.cancel()
        self.sqlmap_adapter.cancel()
        self.gobuster_adapter.cancel()
        self.nikto_adapter.cancel()
        self.status_label.setText("Status: Cancellation requested...")
        self.status_label.setStyleSheet("color: #fbbf24;")
        self.cancel_btn.setEnabled(False)

    @Slot(str, str)
    def _on_output_received(self, chunk: str, stream: str):
        window = self.window()
        if hasattr(window, "terminal_widget"):
            window.terminal_widget.append_output(chunk, stream)

    @Slot(bool, str, object, object)
    def _on_scan_completed(
        self,
        success: bool,
        message: str,
        result: Optional[WebScanResult],
        execution: Optional[ToolExecution],
    ):
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setRange(0, 100)

        if not success:
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Status: Error - {message}")
            self.status_label.setStyleSheet("color: #f87171; font-weight: bold;")
            if "scope" in message.lower() or "unauthorized" in message.lower():
                QMessageBox.critical(
                    self,
                    "Unauthorized Target Scope",
                    f"Web Assessment blocked by Scope Guard:\n\n{message}\n\n"
                    "Please add this domain/IP to the authorized project scopes first.",
                )
            else:
                QMessageBox.critical(self, "Web Scan Failed", message)
            self.project_data_updated.emit()
            return

        if (
            self._scan_project_id is not None
            and self.active_project
            and self.active_project.id != self._scan_project_id
        ):
            self.status_label.setText(
                f"Status: Results saved to project #{self._scan_project_id}; select that project to view them."
            )
            return

        status_str = execution.status.value if execution else "OK"
        if status_str == "completed":
            self.progress_bar.setValue(100)
            self.status_label.setText("Status: Assessment completed successfully")
            self.status_label.setStyleSheet("color: #4ade80;")
        elif status_str == "timeout":
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Status: Request Timeout ({message})")
            self.status_label.setStyleSheet("color: #f87171;")
        elif status_str == "cancelled":
            self.progress_bar.setValue(0)
            self.status_label.setText("Status: Assessment cancelled")
            self.status_label.setStyleSheet("color: #fbbf24;")
        else:
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Status: Error - {message}")
            self.status_label.setStyleSheet("color: #f87171;")

        if not result:
            return

        # 1. Populate Structured Findings Table
        self._current_findings = result.findings
        self.findings_table.setRowCount(len(result.findings))
        for row, f in enumerate(result.findings):
            # Severity Item with Color
            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if f.severity == FindingSeverity.CRITICAL:
                sev_item.setForeground(Qt.GlobalColor.red)
            elif f.severity == FindingSeverity.HIGH:
                sev_item.setForeground(Qt.GlobalColor.magenta)
            elif f.severity == FindingSeverity.MEDIUM:
                sev_item.setForeground(Qt.GlobalColor.yellow)
            elif f.severity == FindingSeverity.LOW:
                sev_item.setForeground(Qt.GlobalColor.cyan)
            else:
                sev_item.setForeground(Qt.GlobalColor.gray)

            self.findings_table.setItem(row, 0, sev_item)
            self.findings_table.setItem(row, 1, QTableWidgetItem(f.affected_asset))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f.title))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f.remediation))

        # 2. Populate Endpoints
        self.endpoints_table.setRowCount(len(result.endpoints))
        for row, ep in enumerate(result.endpoints):
            self.endpoints_table.setItem(row, 0, QTableWidgetItem(ep))

        # 3. Populate Secrets (With Redacted Values)
        self.secrets_table.setRowCount(len(result.secrets))
        for row, sec in enumerate(result.secrets):
            self.secrets_table.setItem(row, 0, QTableWidgetItem(sec.secret_type))
            self.secrets_table.setItem(row, 1, QTableWidgetItem(sec.redacted_preview))
            self.secrets_table.setItem(row, 2, QTableWidgetItem(sec.source_url))
            self.secrets_table.setItem(row, 3, QTableWidgetItem(sec.context_snippet))

        # 4. Populate Response Headers
        self.headers_table.setRowCount(len(result.headers))
        for row, (hname, hval) in enumerate(result.headers.items()):
            self.headers_table.setItem(row, 0, QTableWidgetItem(hname))
            self.headers_table.setItem(row, 1, QTableWidgetItem(hval))

        # Select first finding if available
        if result.findings:
            self.findings_table.selectRow(0)

        # Refresh global findings view
        window = self.window()
        if hasattr(window, "findings_view") and self.active_project:
            window.findings_view.load_findings(self.active_project.id)
        if execution and execution.status == ExecutionStatus.COMPLETED:
            self.project_data_updated.emit()

    def _set_sn1per_profile(self, mode: str):
        """Sets module checkboxes based on Sn1per scan pipeline profile (1N3/Sn1per)."""
        if mode == "recon":
            self.cb_headers.setChecked(True)
            self.cb_cors.setChecked(True)
            self.cb_secrets.setChecked(True)
            self.cb_endpoints.setChecked(True)
            self.cb_waf.setChecked(False)
            self.cb_sqlmap.setChecked(False)
            self.cb_gobuster.setChecked(False)
            self.cb_nikto.setChecked(False)
        elif mode == "stealth":
            self.cb_headers.setChecked(True)
            self.cb_cors.setChecked(False)
            self.cb_secrets.setChecked(False)
            self.cb_endpoints.setChecked(False)
            self.cb_waf.setChecked(True)
            self.cb_sqlmap.setChecked(False)
            self.cb_gobuster.setChecked(False)
            self.cb_nikto.setChecked(False)
        elif mode == "web_full":
            self.cb_headers.setChecked(True)
            self.cb_cors.setChecked(True)
            self.cb_secrets.setChecked(True)
            self.cb_endpoints.setChecked(True)
            self.cb_waf.setChecked(True)
            self.cb_sqlmap.setChecked(False)
            self.cb_gobuster.setChecked(True)
            self.cb_nikto.setChecked(True)
        elif mode == "airstrike":
            self.cb_headers.setChecked(True)
            self.cb_cors.setChecked(True)
            self.cb_secrets.setChecked(True)
            self.cb_endpoints.setChecked(True)
            self.cb_waf.setChecked(True)
            self.cb_sqlmap.setChecked(True)
            self.cb_gobuster.setChecked(True)
            self.cb_nikto.setChecked(True)

    def _on_finding_selected(self):
        """Displays technical details, Strix AI CVSS v3.1 triage, OWASP mapping, and remediation playbook."""
        selected_rows = self.findings_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row_idx = selected_rows[0].row()
        if 0 <= row_idx < len(self._current_findings):
            f = self._current_findings[row_idx]
            triaged = StrixTriageEngine.triage_finding(f)
            cvss_display = f.cvss_score if f.cvss_score is not None else triaged.cvss_score
            details = (
                f"### {f.title}\n\n"
                f"**Severity:** {f.severity.value.upper()} (CVSS: {cvss_display}) | **Vector:** {triaged.cvss_vector}\n\n"
                f"**OWASP Top 10 Category:** {triaged.owasp_category}\n\n"
                f"**Confidence:** {triaged.confidence} | **Likely False Positive:** {'⚠️ Yes' if triaged.is_likely_false_positive else '✅ No'}\n\n"
                f"**Affected Asset / URL:** {f.affected_asset}\n\n"
                f"**Service / Component:** {f.affected_port_service or 'Web Asset'}\n\n"
                f"**Verification Status:** {f.validation_status.value}\n\n"
                f"#### Description & Technical Explanation:\n"
                f"{f.description}\n\n"
                f"#### Actionable Remediation Guidance:\n"
                f"{triaged.remediation_summary}\n\n"
                f"#### Developer Code / Config Remediation Playbook (Strix AI):\n"
                f"```\n{triaged.remediation_snippet}\n```\n"
            )
            self.finding_details_text.setMarkdown(details)

    # -----------------------------------------------------------------------
    # Interception Proxy & Web Tools (OWASP ZAP & Burp Suite)
    # -----------------------------------------------------------------------

    def _create_proxy_tools_tab(self) -> QWidget:
        """Constructs dedicated interactive management tab for OWASP ZAP and Burp Suite."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(16)

        # Header Info Banner
        hdr_box = QFrame()
        hdr_box.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; padding: 10px;")
        hdr_layout = QVBoxLayout(hdr_box)
        hdr_title = QLabel("🌐 Interception Proxy & Web Penetration Testing Tools")
        hdr_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE}; font-family: {CPENTTheme.FONT_FAMILY_HEADING};")
        hdr_desc = QLabel(
            "Configure local browser HTTP/HTTPS proxies, launch OWASP ZAP or Burp Suite to intercept, inspect, "
            "and manipulate web requests, test for OWASP Top 10 vulnerabilities, and analyze API traffic."
        )
        hdr_desc.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        hdr_desc.setWordWrap(True)
        hdr_layout.addWidget(hdr_title)
        hdr_layout.addWidget(hdr_desc)
        layout.addWidget(hdr_box)

        # Splitter: Left = OWASP ZAP, Right = Burp Suite & Browser Proxy Helper
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ----------------- Left: OWASP ZAP -----------------
        zap_card = QFrame()
        zap_card.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 6px; padding: 12px;")
        zap_layout = QVBoxLayout(zap_card)
        zap_layout.setSpacing(10)

        zap_title_row = QHBoxLayout()
        zap_title = QLabel("🛡️ OWASP ZAP (Zed Attack Proxy)")
        zap_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_HEADING};")
        zap_title_row.addWidget(zap_title)
        zap_title_row.addStretch()

        zap_bin = shutil.which("zap.sh") or (
            "/usr/local/bin/zap.sh" if Path("/usr/local/bin/zap.sh").exists() else None
        )
        is_zap_ready = bool(zap_bin)

        self.lbl_zap_badge = QLabel("● Ready & Functional" if is_zap_ready else "● Not Found")
        self.lbl_zap_badge.setStyleSheet(
            f"color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold; font-size: 11px;"
            if is_zap_ready
            else f"color: {CPENTTheme.ERROR_RED}; font-weight: bold; font-size: 11px;"
        )
        zap_title_row.addWidget(self.lbl_zap_badge)
        zap_layout.addLayout(zap_title_row)

        zap_info = QLabel(
            f"<b>Status:</b> {'Installed at ' + (zap_bin or '') + ' (v2.17.0)' if is_zap_ready else 'Not found in system PATH'}<br>"
            "<b>Default Proxy Port:</b> <code>127.0.0.1:8090</code><br>"
            "<b>Capabilities:</b> Full Interception Proxy, Automated Spider, Active Scanner, Fuzzer, WebSockets."
        )
        zap_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        zap_info.setWordWrap(True)
        zap_layout.addWidget(zap_info)

        zap_btn_row = QHBoxLayout()
        self.btn_launch_zap_gui = QPushButton("🚀 Launch OWASP ZAP GUI")
        self.btn_launch_zap_gui.setProperty("class", "action-primary")
        self.btn_launch_zap_gui.setEnabled(is_zap_ready)
        self.btn_launch_zap_gui.clicked.connect(self._launch_zap_gui)
        zap_btn_row.addWidget(self.btn_launch_zap_gui)

        self.btn_launch_zap_daemon = QPushButton("⚡ Start ZAP Daemon (Port 8090)")
        self.btn_launch_zap_daemon.setProperty("class", "action-secondary")
        self.btn_launch_zap_daemon.setEnabled(is_zap_ready)
        self.btn_launch_zap_daemon.clicked.connect(self._launch_zap_daemon)
        zap_btn_row.addWidget(self.btn_launch_zap_daemon)

        self.btn_stop_zap = QPushButton("🛑 Stop ZAP")
        self.btn_stop_zap.setEnabled(False)
        self.btn_stop_zap.clicked.connect(self._stop_zap)
        zap_btn_row.addWidget(self.btn_stop_zap)

        self.btn_check_zap = QPushButton("🔌 Test ZAP Port (8090)")
        self.btn_check_zap.clicked.connect(lambda: self._test_proxy_listening("127.0.0.1", 8090, "OWASP ZAP"))
        zap_btn_row.addWidget(self.btn_check_zap)

        self.btn_import_zap = QPushButton("📥 Import ZAP Report (XML/JSON)")
        self.btn_import_zap.setProperty("class", "action-secondary")
        self.btn_import_zap.clicked.connect(self._import_zap_report)
        zap_btn_row.addWidget(self.btn_import_zap)
        zap_layout.addLayout(zap_btn_row)

        zap_guide = QLabel(
            "<b>Quick ZAP Usage:</b><br>"
            "1. Launch ZAP GUI above.<br>"
            "2. Configure browser proxy to <code>127.0.0.1:8090</code>.<br>"
            "3. Navigate to <code>http://zap</code> in browser to install Root CA.<br>"
            "4. Start spidering or active scanning within target scope."
        )
        zap_guide.setStyleSheet("background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 4px; padding: 8px; color: #94a3b8; font-size: 11px;")
        zap_layout.addWidget(zap_guide)
        zap_layout.addStretch()
        splitter.addWidget(zap_card)

        # ----------------- Right: Burp Suite & Browser Proxy -----------------
        burp_card = QFrame()
        burp_card.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 6px; padding: 12px;")
        burp_layout = QVBoxLayout(burp_card)
        burp_layout.setSpacing(10)

        burp_title_row = QHBoxLayout()
        burp_title = QLabel("🟧 Burp Suite & Browser Proxy Helper")
        burp_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_HEADING};")
        burp_title_row.addWidget(burp_title)
        burp_title_row.addStretch()

        burp_bin = shutil.which("burpsuite") or shutil.which("burp")
        self.lbl_burp_badge = QLabel("● Found in PATH" if burp_bin else "● Not Found in PATH (Manual Proxy)")
        self.lbl_burp_badge.setStyleSheet(
            f"color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold; font-size: 11px;"
            if burp_bin
            else f"color: {CPENTTheme.SECONDARY_TEXT}; font-weight: bold; font-size: 11px;"
        )
        burp_title_row.addWidget(self.lbl_burp_badge)
        burp_layout.addLayout(burp_title_row)

        burp_info = QLabel(
            "<b>Standard Interception Proxy:</b> <code>127.0.0.1:8080</code><br>"
            "<b>Burp Suite:</b> PortSwigger's industry-standard web proxy, repeater, and intruder suite."
        )
        burp_info.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        burp_info.setWordWrap(True)
        burp_layout.addWidget(burp_info)

        burp_btn_row = QHBoxLayout()
        self.btn_launch_burp = QPushButton("🚀 Launch Burp Suite")
        self.btn_launch_burp.setProperty("class", "action-primary")
        self.btn_launch_burp.setEnabled(bool(burp_bin))
        self.btn_launch_burp.clicked.connect(self._launch_burp)
        burp_btn_row.addWidget(self.btn_launch_burp)

        self.btn_check_burp = QPushButton("🔌 Test Burp Port (8080)")
        self.btn_check_burp.clicked.connect(lambda: self._test_proxy_listening("127.0.0.1", 8080, "Burp Suite"))
        burp_btn_row.addWidget(self.btn_check_burp)

        self.btn_get_burp = QPushButton("📥 PortSwigger Download Page")
        self.btn_get_burp.clicked.connect(lambda: self._open_browser_url("https://portswigger.net/burp/communitydownload"))
        burp_btn_row.addWidget(self.btn_get_burp)

        self.btn_import_burp = QPushButton("📥 Import Burp XML Report")
        self.btn_import_burp.setProperty("class", "action-secondary")
        self.btn_import_burp.clicked.connect(self._import_burp_report)
        burp_btn_row.addWidget(self.btn_import_burp)

        self.btn_import_modsec = QPushButton("🛡️ Import ModSecurity WAF Log")
        self.btn_import_modsec.setProperty("class", "action-secondary")
        self.btn_import_modsec.setToolTip("Import and correlate ModSecurity WAF audit logs into normalized findings and evidence")
        self.btn_import_modsec.clicked.connect(self._import_modsec_log)
        burp_btn_row.addWidget(self.btn_import_modsec)
        burp_layout.addLayout(burp_btn_row)

        # Quick Copy Helpers Row
        copy_row = QHBoxLayout()
        btn_copy_burp_proxy = QPushButton("📋 Copy Burp Proxy (8080)")
        btn_copy_burp_proxy.setFixedHeight(24)
        btn_copy_burp_proxy.clicked.connect(lambda: self._copy_text("127.0.0.1:8080", "Burp Proxy Address"))
        copy_row.addWidget(btn_copy_burp_proxy)

        btn_copy_zap_proxy = QPushButton("📋 Copy ZAP Proxy (8090)")
        btn_copy_zap_proxy.setFixedHeight(24)
        btn_copy_zap_proxy.clicked.connect(lambda: self._copy_text("127.0.0.1:8090", "ZAP Proxy Address"))
        copy_row.addWidget(btn_copy_zap_proxy)

        btn_copy_curl = QPushButton("📋 Copy Curl Proxy Command")
        btn_copy_curl.setFixedHeight(24)
        btn_copy_curl.clicked.connect(lambda: self._copy_text("curl -x http://127.0.0.1:8080 -k http://target.lab/", "Curl Proxy Command"))
        copy_row.addWidget(btn_copy_curl)
        burp_layout.addLayout(copy_row)

        proxy_setup_box = QLabel(
            "<b>How to Configure Browser & CA Certificate:</b><br>"
            "1. In Firefox / Chrome network settings, set Manual Proxy to <code>127.0.0.1</code> Port <code>8080</code> (Burp) or <code>8090</code> (ZAP).<br>"
            "2. Navigate to <code>http://burp</code> (or <code>http://zap</code>) in your browser.<br>"
            "3. Click <b>'CA Certificate'</b> in the top right to download <code>cacert.der</code>.<br>"
            "4. Go to Browser Settings -> Privacy & Security -> Certificates -> View Certificates -> Import.<br>"
            "5. Check <i>'Trust this CA to identify websites'</i> to intercept HTTPS traffic cleanly."
        )
        proxy_setup_box.setStyleSheet("background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 4px; padding: 8px; color: #94a3b8; font-size: 11px;")
        burp_layout.addWidget(proxy_setup_box)
        burp_layout.addStretch()
        splitter.addWidget(burp_card)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

        scroll.setWidget(container)
        return scroll

    @Slot()
    def _launch_zap_gui(self):
        """Launches OWASP ZAP GUI in a detached process."""
        zap_bin = shutil.which("zap.sh") or (
            "/usr/local/bin/zap.sh" if Path("/usr/local/bin/zap.sh").exists() else None
        )
        if not zap_bin:
            QMessageBox.warning(self, "ZAP Not Found", "OWASP ZAP binary (zap.sh) was not found on the system.")
            return

        cmd = [zap_bin, "-dir", "/tmp/.ZAP"]
        try:
            self._zap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.btn_stop_zap.setEnabled(True)
            QMessageBox.information(
                self,
                "OWASP ZAP Launched",
                "OWASP ZAP GUI has been launched in the background.\n"
                "Local Proxy: 127.0.0.1:8090\nConfiguration: /tmp/.ZAP",
            )
        except Exception as e:
            QMessageBox.critical(self, "Launch Error", f"Failed to launch OWASP ZAP:\n{e}")

    @Slot()
    def _launch_zap_daemon(self):
        """Launches OWASP ZAP in headless daemon mode on port 8090."""
        zap_bin = shutil.which("zap.sh") or (
            "/usr/local/bin/zap.sh" if Path("/usr/local/bin/zap.sh").exists() else None
        )
        if not zap_bin:
            QMessageBox.warning(self, "ZAP Not Found", "OWASP ZAP binary (zap.sh) was not found on the system.")
            return

        cmd = [zap_bin, "-daemon", "-port", "8090", "-dir", "/tmp/.ZAP"]
        try:
            self._zap_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.btn_stop_zap.setEnabled(True)
            QMessageBox.information(
                self,
                "ZAP Daemon Started",
                "OWASP ZAP Daemon is now listening on 127.0.0.1:8090 in headless mode.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Daemon Error", f"Failed to start ZAP daemon:\n{e}")

    @Slot()
    def _stop_zap(self):
        """Terminates spawned ZAP process."""
        if self._zap_proc:
            try:
                self._zap_proc.terminate()
                self._zap_proc = None
                self.btn_stop_zap.setEnabled(False)
                QMessageBox.information(self, "ZAP Stopped", "OWASP ZAP process has been terminated.")
            except Exception as e:
                QMessageBox.warning(self, "Stop Error", f"Error stopping ZAP: {e}")

    @Slot()
    def _launch_burp(self):
        """Launches Burp Suite if present on system."""
        burp_bin = shutil.which("burpsuite") or shutil.which("burp")
        if not burp_bin:
            QMessageBox.information(
                self,
                "Burp Suite",
                "Burp Suite executable was not detected on this host.\n"
                "You can download the Community Edition or run a JAR file manually.",
            )
            return

        try:
            subprocess.Popen([burp_bin], start_new_session=True)
            QMessageBox.information(self, "Burp Suite Launched", "Burp Suite GUI launched successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Launch Error", f"Failed to launch Burp Suite:\n{e}")

    def _copy_text(self, text: str, label: str):
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", f"{label} copied to clipboard:\n{text}")

    def _open_browser_url(self, url: str):
        import webbrowser
        webbrowser.open(url)

    def _test_proxy_listening(self, host: str, port: int, name: str):
        import socket
        try:
            with socket.create_connection((host, port), timeout=0.6):
                QMessageBox.information(
                    self,
                    f"{name} Proxy Active",
                    f"Successfully connected to {name} proxy listener at {host}:{port}!\n\n"
                    f"The proxy service is actively running and ready to intercept HTTP/HTTPS traffic.",
                )
        except (socket.timeout, ConnectionRefusedError, OSError):
            QMessageBox.warning(
                self,
                f"{name} Proxy Not Listening",
                f"Could not connect to {name} proxy at {host}:{port}.\n\n"
                f"Ensure {name} is started and its proxy listener is configured to listen on {host}:{port}.",
            )

    def _get_active_assessment_id(self) -> Optional[int]:
        if not self.active_project:
            return None
        asm_list = self.db.list_assessments(self.active_project.id)
        active_asms = [a for a in asm_list if getattr(a.status, "value", str(a.status)) in ("in_progress", "planned")]
        return active_asms[0].id if active_asms else (asm_list[0].id if asm_list else None)

    def _display_findings(self, findings: List[Finding]):
        """Populates the structured findings table with given findings."""
        self._current_findings = findings
        self.findings_table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if f.severity == FindingSeverity.CRITICAL:
                sev_item.setForeground(Qt.GlobalColor.red)
            elif f.severity == FindingSeverity.HIGH:
                sev_item.setForeground(Qt.GlobalColor.magenta)
            elif f.severity == FindingSeverity.MEDIUM:
                sev_item.setForeground(Qt.GlobalColor.yellow)
            elif f.severity == FindingSeverity.LOW:
                sev_item.setForeground(Qt.GlobalColor.cyan)
            else:
                sev_item.setForeground(Qt.GlobalColor.gray)

            self.findings_table.setItem(row, 0, sev_item)
            self.findings_table.setItem(row, 1, QTableWidgetItem(f.affected_asset))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f.title))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f.remediation))

        if findings:
            self.findings_table.selectRow(0)

        # Refresh global findings view
        window = self.window()
        if hasattr(window, "findings_view") and self.active_project:
            window.findings_view.load_findings(self.active_project.id)

    @Slot()
    def _import_zap_report(self):
        """Imports external OWASP ZAP XML or JSON report."""
        if not self.active_project:
            QMessageBox.warning(self, "Project Required", "Please select an active project before importing scan reports.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import OWASP ZAP Scan Report",
            "",
            "ZAP Report Files (*.xml *.json);;XML Files (*.xml);;JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            evidence_dir = Path("storage/evidence")
            asm_id = self._get_active_assessment_id()
            res = self.zap_adapter.import_zap_report(
                project_id=self.active_project.id,
                content=content,
                source_filename=Path(file_path).name,
                evidence_dir=evidence_dir,
                assessment_id=asm_id,
            )

            if res.execution_status == ExecutionStatus.COMPLETED:
                QMessageBox.information(
                    self,
                    "ZAP Report Imported",
                    f"Successfully imported OWASP ZAP scan report.\n\n"
                    f"Status: {res.scope_reason}\n"
                    f"Findings Created/Updated: {len(res.findings)}\n"
                    f"Evidence SHA-256: {res.evidence_hash[:16]}..."
                )
                if res.findings:
                    self._display_findings(res.findings)
                    self.results_tabs.setCurrentIndex(0)  # Switch to Structured Findings tab
                self.project_data_updated.emit()
            else:
                QMessageBox.warning(
                    self,
                    "Import Failed",
                    f"Could not import ZAP report:\n{res.error_message or res.scope_reason}"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", f"Failed to read/import ZAP report:\n{exc}")

    @Slot()
    def _import_burp_report(self):
        """Imports external Burp Suite XML issues export."""
        if not self.active_project:
            QMessageBox.warning(self, "Project Required", "Please select an active project before importing scan reports.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Burp Suite XML Issues Report",
            "",
            "Burp Suite XML Files (*.xml);;All Files (*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            evidence_dir = Path("storage/evidence")
            asm_id = self._get_active_assessment_id()
            res = self.burp_adapter.import_burp_xml(
                project_id=self.active_project.id,
                xml_content=content,
                source_filename=Path(file_path).name,
                evidence_dir=evidence_dir,
                assessment_id=asm_id,
            )

            if res.execution_status == ExecutionStatus.COMPLETED:
                QMessageBox.information(
                    self,
                    "Burp Suite Report Imported",
                    f"Successfully imported Burp Suite issues report.\n\n"
                    f"Status: {res.scope_reason}\n"
                    f"Findings Created/Updated: {len(res.findings)}\n"
                    f"Evidence SHA-256: {res.evidence_hash[:16]}..."
                )
                if res.findings:
                    self._display_findings(res.findings)
                    self.results_tabs.setCurrentIndex(0)  # Switch to Structured Findings tab
                self.project_data_updated.emit()
            else:
                QMessageBox.warning(
                    self,
                    "Import Failed",
                    f"Could not import Burp Suite report:\n{res.error_message or res.scope_reason}"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", f"Failed to read/import Burp Suite report:\n{exc}")

    @Slot()
    def _import_modsec_log(self):
        """Imports external ModSecurity WAF audit log file."""
        if not self.active_project:
            QMessageBox.warning(self, "Project Required", "Please select an active project before importing WAF audit logs.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import ModSecurity WAF Audit Log",
            "",
            "Log Files (*.log *.txt);;All Files (*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            from modules.web.modsec_parser import ModSecurityParser

            scopes = self.db.list_scopes(self.active_project.id)
            evidence_dir = Path("storage/evidence")
            asm_id = self._get_active_assessment_id()

            findings, evidence, scope_res = ModSecurityParser.import_modsec_log(
                db=self.db,
                project_id=self.active_project.id,
                log_content=content,
                scopes=scopes,
                source_filename=Path(file_path).name,
                evidence_dir=evidence_dir,
                assessment_id=asm_id,
            )

            if scope_res.is_allowed:
                QMessageBox.information(
                    self,
                    "ModSecurity Log Imported",
                    f"Successfully imported ModSecurity WAF audit log.\n\n"
                    f"Status: {scope_res.reason}\n"
                    f"WAF Findings Identified: {len(findings)}\n"
                    f"Evidence Records: {len(evidence)}"
                )
                if findings:
                    self._display_findings(findings)
                    self.results_tabs.setCurrentIndex(0)
                self.project_data_updated.emit()
            else:
                QMessageBox.warning(
                    self,
                    "Scope Check Blocked",
                    f"Could not import ModSecurity log:\n{scope_res.reason}"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Import Error", f"Failed to parse ModSecurity log:\n{exc}")

    # -------------------------------------------------------------------------
    # OWASP PTK (Penetration Testing Kit) Workbench Implementation
    # -------------------------------------------------------------------------

    def _create_ptk_workbench_tab(self) -> QWidget:
        """Creates the multi-tab OWASP PTK Security Workbench."""
        ptk_tabs = QTabWidget()

        # Subtab 1: R-Builder
        self.rbuilder_subtab = self._create_rbuilder_subtab()
        ptk_tabs.addTab(self.rbuilder_subtab, "⚡ R-Builder (Request Replayer & cURL)")

        # Subtab 2: JWT Security Lab
        self.jwt_subtab = self._create_jwt_subtab()
        ptk_tabs.addTab(self.jwt_subtab, "🔑 JWT Security Lab")

        # Subtab 3: Encoders & Payloads
        self.encoder_subtab = self._create_encoder_subtab()
        ptk_tabs.addTab(self.encoder_subtab, "🔄 Encoders & Pentest Payloads")

        # Subtab 4: Client-Side & SCA
        self.sca_subtab = self._create_sca_subtab()
        ptk_tabs.addTab(self.sca_subtab, "🛡️ Client-Side Audit & SCA")

        return ptk_tabs

    def _create_rbuilder_subtab(self) -> QWidget:
        """PTK R-Builder: interactive HTTP request composer, cURL import/export, and replayer."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top Bar: Method + Target URL + Live Scope
        url_bar = QHBoxLayout()
        self.ptk_r_method = QComboBox()
        self.ptk_r_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        self.ptk_r_method.setFixedWidth(90)
        url_bar.addWidget(self.ptk_r_method)

        self.ptk_r_url = QLineEdit()
        self.ptk_r_url.setPlaceholderText("Target URL (e.g. http://127.0.0.1:8080/api/login)")
        url_bar.addWidget(self.ptk_r_url, 4)

        self.btn_ptk_send = QPushButton("🚀 Send Request")
        self.btn_ptk_send.setProperty("class", "action-primary")
        self.btn_ptk_send.clicked.connect(self._on_ptk_send_request)
        url_bar.addWidget(self.btn_ptk_send)
        layout.addLayout(url_bar)

        # Action shortcuts
        shortcut_bar = QHBoxLayout()
        btn_import_curl = QPushButton("📥 Import cURL")
        btn_import_curl.clicked.connect(self._on_ptk_import_curl)
        shortcut_bar.addWidget(btn_import_curl)

        btn_copy_curl = QPushButton("📋 Copy as cURL")
        btn_copy_curl.clicked.connect(self._on_ptk_copy_curl)
        shortcut_bar.addWidget(btn_copy_curl)

        btn_add_json = QPushButton("+ JSON Header")
        btn_add_json.clicked.connect(lambda: self._append_rbuilder_header("Content-Type: application/json"))
        shortcut_bar.addWidget(btn_add_json)

        btn_add_bearer = QPushButton("+ Bearer Auth")
        btn_add_bearer.clicked.connect(lambda: self._append_rbuilder_header("Authorization: Bearer <token>"))
        shortcut_bar.addWidget(btn_add_bearer)

        btn_clear_req = QPushButton("🧹 Clear")
        btn_clear_req.clicked.connect(self._clear_rbuilder)
        shortcut_bar.addWidget(btn_clear_req)
        shortcut_bar.addStretch()
        layout.addLayout(shortcut_bar)

        # Splitter: Request Editor (Left) vs Response Viewer (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Request Editor
        req_box = QGroupBox("Request Specification")
        req_layout = QVBoxLayout(req_box)
        req_layout.setContentsMargins(6, 6, 6, 6)

        lbl_hdr = QLabel("Headers (one per line, e.g. Name: Value):")
        lbl_hdr.setStyleSheet("color: #94a3b8; font-size: 11px;")
        req_layout.addWidget(lbl_hdr)

        self.ptk_r_headers = QPlainTextEdit()
        self.ptk_r_headers.setPlaceholderText("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: */*")
        self.ptk_r_headers.setMaximumHeight(110)
        req_layout.addWidget(self.ptk_r_headers)

        lbl_body = QLabel("Request Body (JSON / Form / Raw):")
        lbl_body.setStyleSheet("color: #94a3b8; font-size: 11px;")
        req_layout.addWidget(lbl_body)

        self.ptk_r_body = QPlainTextEdit()
        self.ptk_r_body.setPlaceholderText('{\n  "username": "admin",\n  "password": "password123"\n}')
        req_layout.addWidget(self.ptk_r_body)
        splitter.addWidget(req_box)

        # Right: Response Viewer
        resp_box = QGroupBox("Response Inspector")
        resp_layout = QVBoxLayout(resp_box)
        resp_layout.setContentsMargins(6, 6, 6, 6)

        status_bar = QHBoxLayout()
        self.ptk_r_status_badge = QLabel("Status: Awaiting request")
        self.ptk_r_status_badge.setStyleSheet("color: #94a3b8; font-weight: bold;")
        status_bar.addWidget(self.ptk_r_status_badge)

        self.ptk_r_metrics = QLabel("")
        self.ptk_r_metrics.setStyleSheet("color: #38bdf8; font-size: 11px;")
        status_bar.addWidget(self.ptk_r_metrics)
        status_bar.addStretch()
        resp_layout.addLayout(status_bar)

        resp_tabs = QTabWidget()
        self.ptk_r_resp_body = QPlainTextEdit()
        self.ptk_r_resp_body.setReadOnly(True)
        self.ptk_r_resp_body.setPlaceholderText("Response content will appear here...")
        resp_tabs.addTab(self.ptk_r_resp_body, "📄 Response Body")

        self.ptk_r_resp_headers = QTableWidget()
        self.ptk_r_resp_headers.setColumnCount(2)
        self.ptk_r_resp_headers.setHorizontalHeaderLabels(["Header Name", "Header Value"])
        self.ptk_r_resp_headers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ptk_r_resp_headers.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        resp_tabs.addTab(self.ptk_r_resp_headers, "📋 Response Headers")

        self.ptk_r_curl_view = QPlainTextEdit()
        self.ptk_r_curl_view.setReadOnly(True)
        self.ptk_r_curl_view.setPlaceholderText("cURL command executed...")
        resp_tabs.addTab(self.ptk_r_curl_view, "💻 Executed cURL")

        resp_layout.addWidget(resp_tabs)
        splitter.addWidget(resp_box)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)
        return widget

    def _create_jwt_subtab(self) -> QWidget:
        """PTK JWT Security Lab: Token inspection, claim verification, and none-alg forge."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Input & Control Bar
        inp_box = QGroupBox("Target JSON Web Token (JWT)")
        inp_layout = QVBoxLayout(inp_box)
        self.ptk_jwt_input = QPlainTextEdit()
        self.ptk_jwt_input.setPlaceholderText("Paste encoded JWT token here (e.g. eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c)...")
        self.ptk_jwt_input.setMaximumHeight(70)
        inp_layout.addWidget(self.ptk_jwt_input)

        jwt_btn_row = QHBoxLayout()
        btn_analyze = QPushButton("🔍 Analyze & Audit JWT")
        btn_analyze.setProperty("class", "action-primary")
        btn_analyze.clicked.connect(self._on_ptk_analyze_jwt)
        jwt_btn_row.addWidget(btn_analyze)

        btn_forge = QPushButton("⚡ Forge 'alg: none' Bypass Token")
        btn_forge.clicked.connect(self._on_ptk_forge_none_jwt)
        jwt_btn_row.addWidget(btn_forge)

        btn_send_rbuilder = QPushButton("⚡ Send Token to R-Builder")
        btn_send_rbuilder.clicked.connect(self._on_ptk_send_jwt_to_rbuilder)
        jwt_btn_row.addWidget(btn_send_rbuilder)

        jwt_btn_row.addStretch()
        inp_layout.addLayout(jwt_btn_row)
        layout.addWidget(inp_box)

        # Splitter: Decoded Claims vs Security Audit
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Decoded Header & Payload
        claims_box = QGroupBox("Decoded Claims & Timestamps")
        claims_layout = QVBoxLayout(claims_box)

        self.ptk_jwt_meta_label = QLabel("Status: Awaiting JWT")
        self.ptk_jwt_meta_label.setStyleSheet("color: #38bdf8; font-weight: 500;")
        claims_layout.addWidget(self.ptk_jwt_meta_label)

        lbl_hdr = QLabel("Header (JOSE):")
        lbl_hdr.setStyleSheet("color: #94a3b8; font-size: 11px;")
        claims_layout.addWidget(lbl_hdr)
        self.ptk_jwt_header_view = QPlainTextEdit()
        self.ptk_jwt_header_view.setReadOnly(True)
        self.ptk_jwt_header_view.setMaximumHeight(90)
        claims_layout.addWidget(self.ptk_jwt_header_view)

        lbl_pay = QLabel("Payload (Claims):")
        lbl_pay.setStyleSheet("color: #94a3b8; font-size: 11px;")
        claims_layout.addWidget(lbl_pay)
        self.ptk_jwt_payload_view = QPlainTextEdit()
        self.ptk_jwt_payload_view.setReadOnly(True)
        claims_layout.addWidget(self.ptk_jwt_payload_view)
        splitter.addWidget(claims_box)

        # Right: Vulnerabilities & Forged Output
        audit_box = QGroupBox("Security Audit & Exploit Tools")
        audit_layout = QVBoxLayout(audit_box)

        lbl_vulns = QLabel("Identified Vulnerabilities & Warnings:")
        lbl_vulns.setStyleSheet("color: #ef4444; font-weight: 600; font-size: 11px;")
        audit_layout.addWidget(lbl_vulns)

        self.ptk_jwt_vulns_table = QTableWidget()
        self.ptk_jwt_vulns_table.setColumnCount(3)
        self.ptk_jwt_vulns_table.setHorizontalHeaderLabels(["Severity", "Finding", "Description"])
        self.ptk_jwt_vulns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ptk_jwt_vulns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ptk_jwt_vulns_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        audit_layout.addWidget(self.ptk_jwt_vulns_table)

        lbl_forged = QLabel("Forged 'alg: none' Token (Unsigned):")
        lbl_forged.setStyleSheet("color: #4ade80; font-weight: 600; font-size: 11px;")
        audit_layout.addWidget(lbl_forged)

        self.ptk_jwt_forged_view = QPlainTextEdit()
        self.ptk_jwt_forged_view.setReadOnly(True)
        self.ptk_jwt_forged_view.setMaximumHeight(80)
        audit_layout.addWidget(self.ptk_jwt_forged_view)
        splitter.addWidget(audit_box)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)
        return widget

    def _create_encoder_subtab(self) -> QWidget:
        """PTK Encoders & Pentest Payloads."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Live Encoders
        enc_box = QGroupBox("Data Transformation & Hashing")
        enc_layout = QVBoxLayout(enc_box)

        lbl_in = QLabel("Input Text / Data:")
        lbl_in.setStyleSheet("color: #94a3b8; font-size: 11px;")
        enc_layout.addWidget(lbl_in)

        self.ptk_enc_input = QPlainTextEdit()
        self.ptk_enc_input.setPlaceholderText("Enter raw text or encoded string to transform...")
        enc_layout.addWidget(self.ptk_enc_input)

        # Action Buttons
        btn_grid1 = QHBoxLayout()
        for op, title in [("url_enc", "URL Enc"), ("url_dec", "URL Dec"), ("b64_enc", "Base64 Enc"), ("b64_dec", "Base64 Dec")]:
            btn = QPushButton(title)
            btn.clicked.connect(lambda checked, o=op: self._on_ptk_transform(o))
            btn_grid1.addWidget(btn)
        enc_layout.addLayout(btn_grid1)

        btn_grid2 = QHBoxLayout()
        for op, title in [("hex_enc", "Hex Enc"), ("hex_dec", "Hex Dec"), ("html_enc", "HTML Enc"), ("html_dec", "HTML Dec")]:
            btn = QPushButton(title)
            btn.clicked.connect(lambda checked, o=op: self._on_ptk_transform(o))
            btn_grid2.addWidget(btn)
        enc_layout.addLayout(btn_grid2)

        btn_grid3 = QHBoxLayout()
        for op, title in [("md5", "MD5 Hash"), ("sha1", "SHA-1"), ("sha256", "SHA-256")]:
            btn = QPushButton(title)
            btn.clicked.connect(lambda checked, o=op: self._on_ptk_transform(o))
            btn_grid3.addWidget(btn)
        enc_layout.addLayout(btn_grid3)

        lbl_out = QLabel("Transformed Output:")
        lbl_out.setStyleSheet("color: #94a3b8; font-size: 11px;")
        enc_layout.addWidget(lbl_out)

        self.ptk_enc_output = QPlainTextEdit()
        self.ptk_enc_output.setReadOnly(True)
        enc_layout.addWidget(self.ptk_enc_output)

        out_actions = QHBoxLayout()
        btn_copy_out = QPushButton("📋 Copy Result")
        btn_copy_out.clicked.connect(lambda: self._copy_text(self.ptk_enc_output.toPlainText(), "Encoded/Decoded Output"))
        out_actions.addWidget(btn_copy_out)

        btn_swap = QPushButton("🔄 Swap In/Out")
        btn_swap.clicked.connect(self._swap_encoder_text)
        out_actions.addWidget(btn_swap)
        out_actions.addStretch()
        enc_layout.addLayout(out_actions)
        splitter.addWidget(enc_box)

        # Right: Pentest Payloads
        payload_box = QGroupBox("PTK Pentest Payload Catalog")
        payload_layout = QVBoxLayout(payload_box)

        cat_row = QHBoxLayout()
        cat_lbl = QLabel("Category:")
        cat_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        cat_row.addWidget(cat_lbl)

        self.ptk_payload_cat_combo = QComboBox()
        self.ptk_payload_cat_combo.addItems(PTKPayloads.get_categories())
        self.ptk_payload_cat_combo.currentTextChanged.connect(self._on_ptk_payload_cat_changed)
        cat_row.addWidget(self.ptk_payload_cat_combo, 1)
        payload_layout.addLayout(cat_row)

        self.ptk_payload_table = QTableWidget()
        self.ptk_payload_table.setColumnCount(2)
        self.ptk_payload_table.setHorizontalHeaderLabels(["Title / Variant", "Attack Payload"])
        self.ptk_payload_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ptk_payload_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.ptk_payload_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        payload_layout.addWidget(self.ptk_payload_table)

        pay_actions = QHBoxLayout()
        btn_copy_pay = QPushButton("📋 Copy Selected Payload")
        btn_copy_pay.clicked.connect(self._on_ptk_copy_payload)
        pay_actions.addWidget(btn_copy_pay)

        btn_insert_rbuilder = QPushButton("⚡ Send to R-Builder Body")
        btn_insert_rbuilder.clicked.connect(self._on_ptk_insert_payload_to_rbuilder)
        pay_actions.addWidget(btn_insert_rbuilder)
        pay_actions.addStretch()
        payload_layout.addLayout(pay_actions)

        splitter.addWidget(payload_box)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

        # Load initial payloads
        if PTKPayloads.get_categories():
            self._on_ptk_payload_cat_changed(PTKPayloads.get_categories()[0])

        return widget

    def _create_sca_subtab(self) -> QWidget:
        """PTK Client-Side Security & SCA Analyzer."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # URL Input & Audit Action
        top_bar = QHBoxLayout()
        self.ptk_sca_url = QLineEdit()
        self.ptk_sca_url.setPlaceholderText("Target Web URL to audit (e.g. http://127.0.0.1:8080)")
        top_bar.addWidget(self.ptk_sca_url, 4)

        btn_run_sca = QPushButton("🔎 Run Client-Side & SCA Audit")
        btn_run_sca.setProperty("class", "action-primary")
        btn_run_sca.clicked.connect(self._on_ptk_run_sca)
        top_bar.addWidget(btn_run_sca)
        layout.addLayout(top_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Box 1: Security Headers Compliance
        hdr_box = QGroupBox("Security Headers Audit (OWASP Standards)")
        hdr_layout = QVBoxLayout(hdr_box)
        self.ptk_sca_headers_table = QTableWidget()
        self.ptk_sca_headers_table.setColumnCount(3)
        self.ptk_sca_headers_table.setHorizontalHeaderLabels(["Severity", "Finding", "Remediation & Purpose"])
        self.ptk_sca_headers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ptk_sca_headers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ptk_sca_headers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        hdr_layout.addWidget(self.ptk_sca_headers_table)
        splitter.addWidget(hdr_box)

        # Box 2: JavaScript Library Components (SCA)
        sca_box = QGroupBox("Discovered Frontend Libraries & Vulnerability Matching (SCA)")
        sca_layout = QVBoxLayout(sca_box)
        self.ptk_sca_libs_table = QTableWidget()
        self.ptk_sca_libs_table.setColumnCount(4)
        self.ptk_sca_libs_table.setHorizontalHeaderLabels(["Component", "Detected Version", "Vulnerable", "Known CVEs / Risk"])
        self.ptk_sca_libs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ptk_sca_libs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ptk_sca_libs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ptk_sca_libs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        sca_layout.addWidget(self.ptk_sca_libs_table)
        splitter.addWidget(sca_box)

        layout.addWidget(splitter)
        return widget

    # -------------------------------------------------------------------------
    # PTK Slot Handlers & Actions
    # -------------------------------------------------------------------------

    @Slot()
    def _on_ptk_send_request(self):
        """Sends crafted HTTP request via PTKRequestBuilder under Scope Guard."""
        method = self.ptk_r_method.currentText()
        url = self.ptk_r_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing URL", "Please enter a valid target URL in the R-Builder.")
            return

        # Parse headers
        headers: dict = {}
        for line in self.ptk_r_headers.toPlainText().splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        body = self.ptk_r_body.toPlainText()

        self.ptk_r_status_badge.setText("Sending...")
        self.ptk_r_status_badge.setStyleSheet("color: #38bdf8; font-weight: bold;")
        QApplication.processEvents()

        res = PTKRequestBuilder.send_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            project=self.active_project,
            db=self.db,
        )

        if not res.is_authorized:
            self.ptk_r_status_badge.setText("🚫 Blocked by Scope Guard")
            self.ptk_r_status_badge.setStyleSheet("color: #ef4444; font-weight: bold;")
            QMessageBox.critical(self, "Scope Guard Violation", f"Target '{url}' is outside authorized assessment scope.\n\nReason: {res.scope_reason}")
            return

        if not res.success:
            self.ptk_r_status_badge.setText("❌ Connection Failed")
            self.ptk_r_status_badge.setStyleSheet("color: #ef4444; font-weight: bold;")
            self.ptk_r_resp_body.setPlainText(f"Error: {res.error}")
            return

        # Render Response
        code = res.status_code or 0
        if 200 <= code < 300:
            badge_color = "#4ade80"
        elif 300 <= code < 400:
            badge_color = "#38bdf8"
        elif 400 <= code < 500:
            badge_color = "#fbbf24"
        else:
            badge_color = "#f87171"

        self.ptk_r_status_badge.setText(f"Status: {res.status_code} {res.status_reason}")
        self.ptk_r_status_badge.setStyleSheet(f"color: {badge_color}; font-weight: bold;")
        self.ptk_r_metrics.setText(f"⏱️ {res.elapsed_ms} ms | 📦 {res.response_size_bytes:,} bytes")
        self.ptk_r_resp_body.setPlainText(res.response_body)

        # Headers Table
        self.ptk_r_resp_headers.setRowCount(len(res.response_headers))
        for r, (k, v) in enumerate(res.response_headers.items()):
            self.ptk_r_resp_headers.setItem(r, 0, QTableWidgetItem(k))
            self.ptk_r_resp_headers.setItem(r, 1, QTableWidgetItem(v))

        self.ptk_r_curl_view.setPlainText(res.curl_command)

    @Slot()
    def _on_ptk_import_curl(self):
        """Imports an existing cURL command and parses it into R-Builder inputs."""
        text, ok = QInputDialog.getMultiLineText(
            self,
            "Import cURL Command",
            "Paste your cURL command below to import method, URL, headers, and payload:",
            "curl -X POST https://targetlab.corp/api/login -H 'Content-Type: application/json' --data-raw '{\"username\":\"admin\"}'",
        )
        if not ok or not text.strip():
            return

        parsed = PTKRequestBuilder.parse_curl(text.strip())
        if parsed.get("method"):
            idx = self.ptk_r_method.findText(parsed["method"])
            if idx >= 0:
                self.ptk_r_method.setCurrentIndex(idx)
        if parsed.get("url"):
            self.ptk_r_url.setText(parsed["url"])
        if parsed.get("headers"):
            hdr_str = "\n".join(f"{k}: {v}" for k, v in parsed["headers"].items())
            self.ptk_r_headers.setPlainText(hdr_str)
        if parsed.get("body"):
            self.ptk_r_body.setPlainText(parsed["body"])

        QMessageBox.information(self, "cURL Imported", "Request parameters successfully loaded into R-Builder.")

    @Slot()
    def _on_ptk_copy_curl(self):
        """Exports the current R-Builder request as a copyable cURL command."""
        method = self.ptk_r_method.currentText()
        url = self.ptk_r_url.text().strip() or "http://example.com"
        headers: dict = {}
        for line in self.ptk_r_headers.toPlainText().splitlines():
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body = self.ptk_r_body.toPlainText()
        cmd = PTKRequestBuilder.to_curl(method, url, headers, body)
        self._copy_text(cmd, "R-Builder cURL Command")

    def _append_rbuilder_header(self, header_line: str):
        existing = self.ptk_r_headers.toPlainText().strip()
        if existing:
            self.ptk_r_headers.setPlainText(f"{existing}\n{header_line}")
        else:
            self.ptk_r_headers.setPlainText(header_line)

    def _clear_rbuilder(self):
        self.ptk_r_headers.clear()
        self.ptk_r_body.clear()
        self.ptk_r_resp_body.clear()
        self.ptk_r_resp_headers.setRowCount(0)
        self.ptk_r_status_badge.setText("Status: Awaiting request")
        self.ptk_r_status_badge.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.ptk_r_metrics.setText("")

    @Slot()
    def _on_ptk_analyze_jwt(self):
        """Parses JWT token and executes security checks."""
        token = self.ptk_jwt_input.toPlainText().strip()
        if not token:
            QMessageBox.warning(self, "Missing Token", "Please paste a JWT token into the input area.")
            return

        res = PTKJWTAnalyzer.analyze_token(token)
        if not res.is_valid_format:
            self.ptk_jwt_meta_label.setText(f"❌ Invalid: {res.error}")
            self.ptk_jwt_meta_label.setStyleSheet("color: #f87171; font-weight: bold;")
            return

        status_text = f"Algorithm: {res.algorithm} | Expired: {'Yes' if res.is_expired else 'No'}"
        if res.expiration_date:
            status_text += f" | Expires: {res.expiration_date}"
        self.ptk_jwt_meta_label.setText(status_text)
        self.ptk_jwt_meta_label.setStyleSheet("color: #4ade80; font-weight: 500;")

        self.ptk_jwt_header_view.setPlainText(json.dumps(res.header, indent=2))
        self.ptk_jwt_payload_view.setPlainText(json.dumps(res.payload, indent=2))

        # Vulnerabilities table
        self.ptk_jwt_vulns_table.setRowCount(len(res.vulnerabilities))
        for r, v in enumerate(res.vulnerabilities):
            sev_item = QTableWidgetItem(v.get("severity", "Info"))
            if v.get("severity") == "Critical":
                sev_item.setForeground(Qt.GlobalColor.red)
            elif v.get("severity") == "High":
                sev_item.setForeground(Qt.GlobalColor.yellow)
            self.ptk_jwt_vulns_table.setItem(r, 0, sev_item)
            self.ptk_jwt_vulns_table.setItem(r, 1, QTableWidgetItem(v.get("title", "")))
            self.ptk_jwt_vulns_table.setItem(r, 2, QTableWidgetItem(v.get("desc", "")))

    @Slot()
    def _on_ptk_forge_none_jwt(self):
        """Generates forged 'alg: none' token with privilege escalation candidate."""
        token = self.ptk_jwt_input.toPlainText().strip()
        if not token:
            QMessageBox.warning(self, "Missing Token", "Please paste an existing JWT token first.")
            return
        forged = PTKJWTAnalyzer.forge_none_token(token, {"admin": True, "role": "administrator"})
        self.ptk_jwt_forged_view.setPlainText(forged)
        self._copy_text(forged, "Forged 'alg: none' Token")

    @Slot()
    def _on_ptk_send_jwt_to_rbuilder(self):
        """Sends the active or forged JWT token to R-Builder's Authorization header."""
        forged = self.ptk_jwt_forged_view.toPlainText().strip()
        token = forged if forged else self.ptk_jwt_input.toPlainText().strip()
        if not token:
            QMessageBox.warning(self, "No Token", "Please enter or forge a JWT token first.")
            return
        self._append_rbuilder_header(f"Authorization: Bearer {token}")
        QMessageBox.information(self, "Token Applied", "Token loaded into R-Builder as 'Authorization: Bearer <token>'.")

    def _on_ptk_transform(self, op: str):
        """Executes selected text transformation or hashing."""
        inp = self.ptk_enc_input.toPlainText()
        out = ""
        if op == "url_enc":
            out = PTKEncoder.url_encode(inp)
        elif op == "url_dec":
            out = PTKEncoder.url_decode(inp)
        elif op == "b64_enc":
            out = PTKEncoder.base64_encode(inp)
        elif op == "b64_dec":
            out = PTKEncoder.base64_decode(inp)
        elif op == "hex_enc":
            out = PTKEncoder.hex_encode(inp)
        elif op == "hex_dec":
            out = PTKEncoder.hex_decode(inp)
        elif op == "html_enc":
            out = PTKEncoder.html_encode(inp)
        elif op == "html_dec":
            out = PTKEncoder.html_decode(inp)
        elif op == "md5":
            out = PTKEncoder.hash_md5(inp)
        elif op == "sha1":
            out = PTKEncoder.hash_sha1(inp)
        elif op == "sha256":
            out = PTKEncoder.hash_sha256(inp)
        self.ptk_enc_output.setPlainText(out)

    def _swap_encoder_text(self):
        cur_out = self.ptk_enc_output.toPlainText()
        self.ptk_enc_input.setPlainText(cur_out)
        self.ptk_enc_output.clear()

    def _on_ptk_payload_cat_changed(self, category: str):
        """Populates payload table based on category."""
        payloads = PTKPayloads.get_payloads(category)
        self.ptk_payload_table.setRowCount(len(payloads))
        for r, p in enumerate(payloads):
            self.ptk_payload_table.setItem(r, 0, QTableWidgetItem(p["title"]))
            self.ptk_payload_table.setItem(r, 1, QTableWidgetItem(p["payload"]))

    def _on_ptk_copy_payload(self):
        row = self.ptk_payload_table.currentRow()
        if row >= 0:
            pay = self.ptk_payload_table.item(row, 1).text()
            self._copy_text(pay, "Attack Payload")
        else:
            QMessageBox.information(self, "Select Payload", "Please select a payload row first.")

    def _on_ptk_insert_payload_to_rbuilder(self):
        row = self.ptk_payload_table.currentRow()
        if row >= 0:
            pay = self.ptk_payload_table.item(row, 1).text()
            self.ptk_r_body.setPlainText(pay)
            QMessageBox.information(self, "Payload Inserted", f"Payload copied to R-Builder request body:\n{pay}")
        else:
            QMessageBox.information(self, "Select Payload", "Please select a payload row first.")

    @Slot()
    def _on_ptk_run_sca(self):
        """Runs Client-Side Header and Library SCA Audit on given URL."""
        url = self.ptk_sca_url.text().strip() or self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing URL", "Please enter a target URL to audit.")
            return

        res = PTKRequestBuilder.send_request(
            method="GET",
            url=url,
            project=self.active_project,
            db=self.db,
        )

        if not res.is_authorized:
            QMessageBox.critical(self, "Scope Violation", f"Target is outside authorized assessment scope: {res.scope_reason}")
            return

        if not res.success:
            QMessageBox.warning(self, "Connection Error", f"Failed to retrieve target URL:\n{res.error}")
            return

        # 1. Audit Headers
        hdr_findings = PTKSCAAnalyzer.audit_headers(res.response_headers)
        self.ptk_sca_headers_table.setRowCount(len(hdr_findings))
        for r, f in enumerate(hdr_findings):
            sev_item = QTableWidgetItem(f["severity"])
            if f["severity"] == "Medium":
                sev_item.setForeground(Qt.GlobalColor.yellow)
            self.ptk_sca_headers_table.setItem(r, 0, sev_item)
            self.ptk_sca_headers_table.setItem(r, 1, QTableWidgetItem(f["title"]))
            self.ptk_sca_headers_table.setItem(r, 2, QTableWidgetItem(f["desc"]))

        # 2. Detect Components (SCA)
        comps = PTKSCAAnalyzer.detect_components(res.response_body)
        self.ptk_sca_libs_table.setRowCount(len(comps))
        for r, c in enumerate(comps):
            self.ptk_sca_libs_table.setItem(r, 0, QTableWidgetItem(c["name"]))
            self.ptk_sca_libs_table.setItem(r, 1, QTableWidgetItem(c["version"]))
            vuln_item = QTableWidgetItem("⚠️ Yes" if c["has_cve"] else "✅ No")
            if c["has_cve"]:
                vuln_item.setForeground(Qt.GlobalColor.red)
            self.ptk_sca_libs_table.setItem(r, 2, vuln_item)
            self.ptk_sca_libs_table.setItem(r, 3, QTableWidgetItem(c["cve_info"]))
