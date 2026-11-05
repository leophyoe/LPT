"""Tool Execution Center Widget for CyberSecuritySuite.

Interactive GUI workbench for configuring, validating, previewing, and executing
real security assessment tools through ToolExecutionService.
Guarantees:
- Pre-execution fail-closed ScopeAuthorizationService checking.
- Tokenized argument list generation without shell evaluation (shell=False).
- Real-time stdout and stderr output streaming with terminal colors.
- Thread-safe PySide6 GUI signals.
- Automatic cryptographic evidence vaulting (SHA-256) and finding persistence.
- Project-isolated execution history view.
- Dark and Light theme compliance adhering to CPENTTheme tokens.
"""

from __future__ import annotations

import html
import logging
import os
import re
import shlex
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import QObject, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.registry import ToolMetadata, ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from desktop.theme import CPENTTheme, ThemeManager, ThemeMode, get_ui_font
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


class ExecutionBridge(QObject):
    """Thread-safe signal dispatcher between background worker thread and PySide6 UI."""
    output_received = Signal(str, str)  # text, stream_type ("stdout" | "stderr")
    state_changed = Signal(str)         # new state string
    job_finished = Signal(object)       # ExecutionJob


class ToolExecutionCenterWidget(QWidget):
    """Integrated execution workbench for launching and monitoring real security tools."""

    execution_started = Signal(str)           # tool_name
    execution_completed = Signal(str, int, int) # tool_name, exit_code, evidence_id
    findings_discovered = Signal(list)        # list of Finding

    # Pre-configured safe profiles for popular security tools
    TOOL_PROFILES: Dict[str, Dict[str, Dict[str, Any]]] = {
        "nmap": {
            "Service Version Scan": {
                "args": ["-sV", "-T4"],
                "default_ports": "80,443,22,21,25,53,110,139,445,3389,8080",
                "high_risk": False,
                "desc": "Detects running application versions and protocols on open ports.",
            },
            "Fast Top 100 Ports": {
                "args": ["-sS", "-F", "-T4"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Quick SYN discovery of top 100 standard TCP service ports.",
            },
            "Aggressive Security Audit": {
                "args": ["-sV", "-sC", "-Pn", "-T4"],
                "default_ports": "80,443,8080,8443",
                "high_risk": False,
                "desc": "Service detection with default safe NSE scripts. Skips host ping discovery.",
            },
            "Ping Sweep (Host Discovery)": {
                "args": ["-sn"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Discovers active live hosts on subnet without performing port scans.",
            },
            "UDP Common Ports": {
                "args": ["-sU", "-T4"],
                "default_ports": "53,67,68,69,123,161,162,500,514",
                "high_risk": False,
                "desc": "Audits DNS, DHCP, NTP, and SNMP UDP service listeners.",
            },
        },
        "gobuster": {
            "Common Web Routes": {
                "args": ["dir", "-k", "-t", "10"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Fuzzes common directories and routes against web target.",
            },
            "API Endpoints & Configs": {
                "args": ["dir", "-k", "-x", "json,yaml,env,config,xml", "-t", "10"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Discovers exposed API endpoints and sensitive configuration files.",
            },
            "Sensitive Files (.git, .env)": {
                "args": ["dir", "-k", "-x", "git,env,bak,zip,tar.gz", "-t", "10"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Searches for critical repository leaks and backup archives.",
            },
        },
        "nikto": {
            "Standard Web Misconfigurations": {
                "args": ["-nointeractive"],
                "default_ports": "80,443",
                "high_risk": False,
                "desc": "Scans web servers for dangerous files, outdated versions, and misconfigurations.",
            },
            "Interest & Dangerous Files Only": {
                "args": ["-Tuning", "1,2", "-nointeractive"],
                "default_ports": "80,443",
                "high_risk": False,
                "desc": "Focused search for server misconfigurations and default admin files.",
            },
        },
        "nuclei": {
            "Critical & High CVEs": {
                "args": ["-severity", "critical,high", "-silent"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Executes template-based scans targeting known critical and high CVEs.",
            },
            "Exposed Admin Panels": {
                "args": ["-tags", "panel,login", "-silent"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Identifies exposed management portals, logins, and dashboards.",
            },
            "Technologies & Fingerprinting": {
                "args": ["-tags", "tech", "-silent"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Fingerprints underlying CMS, web servers, and third-party components.",
            },
        },
        "wafw00f": {
            "Detect Perimeter WAF": {
                "args": [],
                "default_ports": "",
                "high_risk": False,
                "desc": "Probes target web application to identify firewall vendors (Cloudflare, AWS, etc.).",
            },
            "Find All Active Protections": {
                "args": ["-a"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Thoroughly tests for all possible WAF responses without stopping at first match.",
            },
        },
        "sqlmap": {
            "Safe Batch Banner Check": {
                "args": ["--batch", "--banner", "--technique=BEU"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Non-destructive verification of DBMS banner without data extraction.",
            },
            "Detect Injection (Level 1)": {
                "args": ["--batch", "--level=1", "--risk=1"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Standard heuristic injection probe with minimal request traffic.",
            },
            "[High Risk] In-Depth Assessment": {
                "args": ["--batch", "--level=3", "--risk=2", "--current-db"],
                "default_ports": "",
                "high_risk": True,
                "desc": "Comprehensive SQL injection test. Requires explicit high-risk confirmation.",
            },
        },
        "hydra": {
            "Standard SSH Service Audit": {
                "args": ["-t", "4", "ssh"],
                "default_ports": "22",
                "high_risk": False,
                "desc": "Tests standard authentication with low concurrency to avoid service lockout.",
            },
            "[High Risk] High-Concurrency Probe": {
                "args": ["-t", "16", "ssh"],
                "default_ports": "22",
                "high_risk": True,
                "desc": "Aggressive authentication test. Requires explicit operator confirmation.",
            },
        },
        "bandit": {
            "Standard SAST Python Audit": {
                "args": ["-r"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Recursively analyzes Python source code for security vulnerabilities.",
            },
            "High Severity Findings Only": {
                "args": ["-r", "-lll"],
                "default_ports": "",
                "high_risk": False,
                "desc": "Filters out informational noise and reports only high-severity SAST flaws.",
            },
        },
    }

    def __init__(self, db: Database, project: Optional[Project] = None, parent=None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = project
        self.registry = ToolRegistry()
        self.execution_service = ToolExecutionService.get_instance(db=self.db)
        self._current_job: Optional[ExecutionJob] = None
        self._bridge = ExecutionBridge()
        self._bridge.output_received.connect(self._on_output_streamed)
        self._bridge.state_changed.connect(self._on_state_changed)
        self._bridge.job_finished.connect(self._on_job_completed)

        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._update_timer_display)
        self._start_time: float = 0.0

        self._init_ui()
        self.set_active_project(project)
        self.refresh_tools_list()
        self._update_scope_badge()
        self.refresh_history()

        ThemeManager.instance().theme_changed.connect(self._on_theme_changed)
        self._on_theme_changed(ThemeManager.instance().mode)

    def set_active_project(self, project: Optional[Project]):
        """Updates active project and re-validates scope authorization."""
        self.active_project = project
        if project:
            scopes = self.db.list_scopes(project.id) if self.db else []
            scope_desc = f"{len(scopes)} Authorized Scope(s)" if scopes else "No Authorized Scopes"
            self.lbl_project_badge.setText(f"📁 Active: <b>{html.escape(project.name)}</b> | {scope_desc}")
            self.lbl_project_badge.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px;")
        else:
            self.lbl_project_badge.setText("📁 No Active Project Selected (Testing Blocked)")
            self.lbl_project_badge.setStyleSheet(f"color: {CPENTTheme.AMBER_ACCENT}; font-size: 11px;")
        self._update_scope_badge()
        self.refresh_history()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # 1. Header Row
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        self.header_title = QLabel("⚡ Security Tool Execution Center")
        self.header_title.setObjectName("viewHeader")
        self.header_title.setFont(get_ui_font(16, bold=True, heading=True))
        self.header_subtitle = QLabel("Direct subprocess invocation with tokenized arguments, pre-execution scope enforcement, and evidence vaulting.")
        self.header_subtitle.setObjectName("viewSubtitle")
        title_box.addWidget(self.header_title)
        title_box.addWidget(self.header_subtitle)
        header_row.addLayout(title_box)
        header_row.addStretch()

        self.lbl_project_badge = QLabel("📁 Initializing Project Context...")
        self.lbl_project_badge.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        header_row.addWidget(self.lbl_project_badge)
        main_layout.addLayout(header_row)

        # 2. Splitter: Top (Form & Command Preview), Bottom (Live Streaming & Results)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # -------------------------------------------------------------
        # Top Panel: Configuration Form
        # -------------------------------------------------------------
        form_frame = QFrame()
        form_frame.setObjectName("executionFormCard")
        form_frame.setStyleSheet(f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 8px;")
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(14, 12, 14, 12)
        form_layout.setSpacing(10)

        # Row 1: Target Input + Scope Validation Status
        r1_layout = QHBoxLayout()
        lbl_target = QLabel("Target Address / Host / URL:")
        lbl_target.setFixedWidth(190)
        lbl_target.setFont(get_ui_font(11, bold=True))
        r1_layout.addWidget(lbl_target)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP, CIDR, Domain, or URL (e.g. 192.168.1.100, 10.0.0.0/24, example.local)")
        self.target_input.textChanged.connect(self._on_target_changed)
        r1_layout.addWidget(self.target_input, 2)

        self.lbl_scope_status = QLabel("Checking Scope...")
        self.lbl_scope_status.setMinimumWidth(220)
        self.lbl_scope_status.setFont(get_ui_font(10, bold=True))
        r1_layout.addWidget(self.lbl_scope_status)
        form_layout.addLayout(r1_layout)

        # Row 2: Tool Selection + Profile Preset
        r2_layout = QHBoxLayout()
        lbl_tool = QLabel("Security Tool:")
        lbl_tool.setFixedWidth(190)
        lbl_tool.setFont(get_ui_font(11, bold=True))
        r2_layout.addWidget(lbl_tool)

        self.combo_tool = QComboBox()
        self.combo_tool.currentTextChanged.connect(self._on_tool_changed)
        r2_layout.addWidget(self.combo_tool, 1)

        lbl_profile = QLabel("Profile Preset:")
        lbl_profile.setFixedWidth(100)
        lbl_profile.setFont(get_ui_font(11, bold=True))
        r2_layout.addWidget(lbl_profile)

        self.combo_profile = QComboBox()
        self.combo_profile.currentTextChanged.connect(self._on_profile_changed)
        r2_layout.addWidget(self.combo_profile, 2)
        form_layout.addLayout(r2_layout)

        # Row 3: Ports Specification, Timeout, Extra Arguments
        r3_layout = QHBoxLayout()
        lbl_ports = QLabel("Port Specification:")
        lbl_ports.setFixedWidth(190)
        lbl_ports.setFont(get_ui_font(11, bold=True))
        r3_layout.addWidget(lbl_ports)

        self.input_ports = QLineEdit()
        self.input_ports.setPlaceholderText("e.g. 80,443,8080 (Leave blank for tool default)")
        self.input_ports.textChanged.connect(self._update_command_preview)
        r3_layout.addWidget(self.input_ports, 1)

        lbl_timeout = QLabel("Timeout (sec):")
        lbl_timeout.setFixedWidth(90)
        lbl_timeout.setFont(get_ui_font(11, bold=True))
        r3_layout.addWidget(lbl_timeout)

        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(5, 3600)
        self.spin_timeout.setValue(300)
        self.spin_timeout.setFixedWidth(80)
        r3_layout.addWidget(self.spin_timeout)

        lbl_extra = QLabel("Extra Arguments:")
        lbl_extra.setFixedWidth(110)
        lbl_extra.setFont(get_ui_font(11, bold=True))
        r3_layout.addWidget(lbl_extra)

        self.input_extra = QLineEdit()
        self.input_extra.setPlaceholderText("e.g. -T4 --reason")
        self.input_extra.textChanged.connect(self._update_command_preview)
        r3_layout.addWidget(self.input_extra, 2)
        form_layout.addLayout(r3_layout)

        # Row 4: High-Risk Confirmation & Command Preview
        self.chk_high_risk = QCheckBox("I explicitly confirm this high-risk / intrusive operational test against the authorized target.")
        self.chk_high_risk.setStyleSheet(f"color: {CPENTTheme.AMBER_ACCENT}; font-size: 11px; font-weight: bold;")
        self.chk_high_risk.setVisible(False)
        self.chk_high_risk.stateChanged.connect(self._update_execute_button_state)
        form_layout.addWidget(self.chk_high_risk)

        # Command Preview Box
        cmd_prev_box = QVBoxLayout()
        cmd_prev_box.setSpacing(4)
        lbl_prev_hdr = QLabel("Command Preview (Tokenized Subprocess Array, shell=False):")
        lbl_prev_hdr.setStyleSheet(f"font-size: 10px; font-weight: bold; color: {CPENTTheme.SECONDARY_TEXT}; font-family: monospace;")
        cmd_prev_box.addWidget(lbl_prev_hdr)

        self.txt_command_preview = QLineEdit()
        self.txt_command_preview.setReadOnly(True)
        self.txt_command_preview.setFont(QFont("Monospace", 9))
        self.txt_command_preview.setStyleSheet("background-color: #0b1120; color: #38bdf8; border: 1px solid #1e293b; padding: 4px 8px; border-radius: 4px;")
        cmd_prev_box.addWidget(self.txt_command_preview)
        form_layout.addLayout(cmd_prev_box)

        # Row 5: Action Controls
        action_row = QHBoxLayout()
        self.btn_execute = QPushButton("▶️ Launch Tool Execution")
        self.btn_execute.setProperty("class", "action-primary")
        self.btn_execute.setFixedHeight(32)
        self.btn_execute.setFont(get_ui_font(11, bold=True))
        self.btn_execute.clicked.connect(self._on_execute_clicked)
        action_row.addWidget(self.btn_execute)

        self.btn_cancel = QPushButton("⏹️ Terminate Process")
        self.btn_cancel.setProperty("class", "action-secondary")
        self.btn_cancel.setFixedHeight(32)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._on_cancel_clicked)
        action_row.addWidget(self.btn_cancel)

        self.lbl_exec_status = QLabel("Status: Ready")
        self.lbl_exec_status.setFont(get_ui_font(11, bold=True))
        self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN};")
        action_row.addWidget(self.lbl_exec_status)

        action_row.addStretch()

        self.lbl_timer = QLabel("Elapsed: 0.0s")
        self.lbl_timer.setFont(QFont("Monospace", 10))
        self.lbl_timer.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT};")
        action_row.addWidget(self.lbl_timer)

        form_layout.addLayout(action_row)
        splitter.addWidget(form_frame)

        # -------------------------------------------------------------
        # Bottom Panel: Output, Findings, Evidence, and History Tabs
        # -------------------------------------------------------------
        self.output_tabs = QTabWidget()

        # Tab 1: Live stdout
        self.txt_stdout = QTextEdit()
        self.txt_stdout.setReadOnly(True)
        self.txt_stdout.setFont(QFont("Monospace", 9))
        self.txt_stdout.setPlaceholderText("Standard output stream (stdout) will appear here in real time as the tool runs...")
        self.output_tabs.addTab(self.txt_stdout, "📄 Standard Output (stdout)")

        # Tab 2: Standard error
        self.txt_stderr = QTextEdit()
        self.txt_stderr.setReadOnly(True)
        self.txt_stderr.setFont(QFont("Monospace", 9))
        self.txt_stderr.setPlaceholderText("Diagnostic errors and standard error output (stderr) will appear here...")
        self.output_tabs.addTab(self.txt_stderr, "⚠️ Standard Error (stderr)")

        # Tab 3: Parsed Findings
        tab_findings = QWidget()
        tf_layout = QVBoxLayout(tab_findings)
        tf_layout.setContentsMargins(0, 8, 0, 0)
        self.table_findings = QTableWidget()
        self.table_findings.setColumnCount(5)
        self.table_findings.setHorizontalHeaderLabels(["Title", "Severity", "Affected Asset", "Port / Service", "Remediation"])
        hdr_f = self.table_findings.horizontalHeader()
        hdr_f.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table_findings.setColumnWidth(0, 260)
        hdr_f.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_findings.setColumnWidth(1, 100)
        hdr_f.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_findings.setColumnWidth(2, 160)
        hdr_f.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table_findings.setColumnWidth(3, 110)
        hdr_f.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_findings.setAlternatingRowColors(True)
        self.table_findings.verticalHeader().setVisible(False)
        tf_layout.addWidget(self.table_findings)
        self.output_tabs.addTab(tab_findings, "🔍 Discovered Findings (0)")

        # Tab 4: Cryptographic Evidence Vault Record
        self.txt_evidence_info = QTextEdit()
        self.txt_evidence_info.setReadOnly(True)
        self.txt_evidence_info.setFont(QFont("Monospace", 9))
        self.txt_evidence_info.setPlaceholderText("Cryptographic SHA-256 evidence vault details will be generated upon scan completion...")
        self.output_tabs.addTab(self.txt_evidence_info, "🔒 Evidence Vault")

        # Tab 5: Execution History (from SQLite tool_executions)
        tab_history = QWidget()
        th_layout = QVBoxLayout(tab_history)
        th_layout.setContentsMargins(0, 8, 0, 0)
        self.table_history = QTableWidget()
        self.table_history.setColumnCount(6)
        self.table_history.setHorizontalHeaderLabels(["ID", "Timestamp", "Tool", "Command", "Status", "Duration"])
        hdr_h = self.table_history.horizontalHeader()
        hdr_h.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table_history.setColumnWidth(0, 50)
        hdr_h.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_history.setColumnWidth(1, 160)
        hdr_h.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_history.setColumnWidth(2, 100)
        hdr_h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr_h.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_history.setColumnWidth(4, 90)
        hdr_h.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table_history.setColumnWidth(5, 80)
        self.table_history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_history.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table_history.setAlternatingRowColors(True)
        self.table_history.verticalHeader().setVisible(False)
        self.table_history.itemSelectionChanged.connect(self._on_history_row_selected)
        th_layout.addWidget(self.table_history)
        self.output_tabs.addTab(tab_history, "📜 Execution History")

        splitter.addWidget(self.output_tabs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 7)
        main_layout.addWidget(splitter)

    # -----------------------------------------------------------------
    # Configuration and Command Construction Logic
    # -----------------------------------------------------------------

    def refresh_tools_list(self):
        """Populates the tool selector with installed and available tools."""
        self.combo_tool.blockSignals(True)
        self.combo_tool.clear()

        tools = self.registry.list_tools()
        # Prioritize key assessment tools with execution profiles
        preferred_order = ["nmap", "gobuster", "nikto", "nuclei", "wafw00f", "sqlmap", "hydra", "bandit", "amass", "tshark"]
        added = set()

        for t_name in preferred_order:
            t = self.registry.get_tool(t_name)
            if t:
                status_icon = "🟢" if t.is_installed else "⚪"
                self.combo_tool.addItem(f"{status_icon} {t.name}", t.name)
                added.add(t.name)

        for t in tools:
            if t.name not in added:
                status_icon = "🟢" if t.is_installed else "⚪"
                self.combo_tool.addItem(f"{status_icon} {t.name}", t.name)

        self.combo_tool.blockSignals(False)
        if self.combo_tool.count() > 0:
            self._on_tool_changed(self.combo_tool.currentText())

    def select_tool(self, tool_name: str, preset_name: Optional[str] = None):
        """Programmatically selects a tool and optional profile preset."""
        for i in range(self.combo_tool.count()):
            if self.combo_tool.itemData(i) == tool_name or tool_name in self.combo_tool.itemText(i):
                self.combo_tool.setCurrentIndex(i)
                break

        if preset_name:
            for j in range(self.combo_profile.count()):
                if preset_name.lower() in self.combo_profile.itemText(j).lower():
                    self.combo_profile.setCurrentIndex(j)
                    break

    @Slot(str)
    def _on_tool_changed(self, text: str):
        tool_name = self.combo_tool.currentData() or text.replace("🟢", "").replace("⚪", "").strip()
        self.combo_profile.blockSignals(True)
        self.combo_profile.clear()

        profiles = self.TOOL_PROFILES.get(tool_name, {})
        if profiles:
            for prof_name in profiles.keys():
                self.combo_profile.addItem(prof_name)
        else:
            self.combo_profile.addItem("Default Safe Scan")

        self.combo_profile.blockSignals(False)
        self._on_profile_changed(self.combo_profile.currentText())

    @Slot(str)
    def _on_profile_changed(self, profile_name: str):
        tool_name = self.combo_tool.currentData() or "nmap"
        profile_data = self.TOOL_PROFILES.get(tool_name, {}).get(profile_name, {})

        default_ports = profile_data.get("default_ports", "")
        self.input_ports.setPlaceholderText(default_ports or "Leave blank for default")

        is_high_risk = profile_data.get("high_risk", False) or tool_name in ("sqlmap", "hydra")
        self.chk_high_risk.setVisible(is_high_risk)
        if not is_high_risk:
            self.chk_high_risk.setChecked(False)

        self._update_command_preview()

    @Slot(str)
    def _on_target_changed(self, text: str):
        self._update_scope_badge()
        self._update_command_preview()

    def _update_scope_badge(self):
        target = self.target_input.text().strip()
        if not target:
            self.lbl_scope_status.setText("⚠️ Enter target to verify authorization")
            self.lbl_scope_status.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT};")
            self._update_execute_button_state()
            return

        if not self.active_project:
            self.lbl_scope_status.setText("🔴 Execution Blocked (No active project)")
            self.lbl_scope_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED};")
            self._update_execute_button_state()
            return

        scopes = self.db.list_scopes(self.active_project.id) if self.db else []
        res = ScopeAuthorizationService.is_target_authorized(target, scopes, project=self.active_project)

        if res.is_allowed:
            scope_type_str = res.matched_scope.target_type.value if (res.matched_scope and hasattr(res.matched_scope, "target_type")) else "Verified"
            self.lbl_scope_status.setText(f"🟢 Authorized In-Scope ({scope_type_str})")
            self.lbl_scope_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN};")
        else:
            reason_snippet = res.reason[:35] + "..." if len(res.reason) > 35 else res.reason
            self.lbl_scope_status.setText(f"🔴 Blocked: {reason_snippet}")
            self.lbl_scope_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED};")

        self._update_execute_button_state()

    def _update_execute_button_state(self):
        is_running = self._current_job is not None and self._current_job.state == JobState.RUNNING
        target = self.target_input.text().strip()

        if is_running:
            self.btn_execute.setEnabled(False)
            self.btn_cancel.setEnabled(True)
            return

        self.btn_cancel.setEnabled(False)

        if not target or not self.active_project:
            self.btn_execute.setEnabled(False)
            return

        scopes = self.db.list_scopes(self.active_project.id) if self.db else []
        scope_res = ScopeAuthorizationService.is_target_authorized(target, scopes, project=self.active_project)

        if not scope_res.is_allowed:
            self.btn_execute.setEnabled(False)
            return

        # High risk requires checkbox confirmation
        if self.chk_high_risk.isVisible() and not self.chk_high_risk.isChecked():
            self.btn_execute.setEnabled(False)
            return

        self.btn_execute.setEnabled(True)

    def _build_command_tokens(self) -> List[str]:
        """Builds clean tokenized command array without shell evaluation."""
        tool_name = self.combo_tool.currentData() or "nmap"
        profile_name = self.combo_profile.currentText()
        profile_data = self.TOOL_PROFILES.get(tool_name, {}).get(profile_name, {})

        target = self.target_input.text().strip() or "<TARGET>"
        tokens: List[str] = [tool_name]

        # 1. Add base profile args
        base_args = profile_data.get("args", [])
        tokens.extend(base_args)

        # 2. Add port specification if entered
        ports = self.input_ports.text().strip()
        if ports:
            if tool_name == "nmap":
                tokens.extend(["-p", ports])
            elif tool_name == "nikto":
                tokens.extend(["-port", ports])
            elif tool_name in ("hydra", "tshark"):
                tokens.extend(["-s", ports])

        # 3. Add extra arguments safely using shlex.split
        extra = self.input_extra.text().strip()
        if extra:
            try:
                tokens.extend(shlex.split(extra))
            except Exception:
                tokens.extend(extra.split())

        # 4. Append target in tool-appropriate syntax
        if tool_name == "sqlmap":
            url_target = target if "://" in target else f"http://{target}"
            tokens.extend(["-u", url_target])
        elif tool_name == "gobuster":
            url_target = target if "://" in target else f"http://{target}"
            tokens.extend(["-u", url_target])
        elif tool_name == "nikto":
            tokens.extend(["-h", target])
        elif tool_name == "nuclei":
            tokens.extend(["-u", target])
        elif tool_name == "wafw00f":
            tokens.append(target)
        else:
            tokens.append(target)

        return tokens

    def _update_command_preview(self):
        tokens = self._build_command_tokens()
        tool_name = self.combo_tool.currentData() or "tool"
        preview_str = ToolExecutionService.redact_sensitive_args(tokens, tool_name=tool_name)
        tokens_repr = str(tokens)
        self.txt_command_preview.setText(f"{preview_str}   -->   Tokens: {tokens_repr}")
        self._update_execute_button_state()

    # -----------------------------------------------------------------
    # Subprocess Execution Lifecycle
    # -----------------------------------------------------------------

    @Slot()
    def _on_execute_clicked(self):
        target = self.target_input.text().strip()
        if not target or not self.active_project:
            QMessageBox.warning(self, "Invalid Execution", "Please specify an active project and authorized target.")
            return

        scopes = self.db.list_scopes(self.active_project.id) if self.db else []
        scope_check = ScopeAuthorizationService.is_target_authorized(target, scopes, project=self.active_project)
        if not scope_check.is_allowed:
            QMessageBox.critical(
                self,
                "Operational Security Block",
                f"Execution Blocked! Target '{target}' is not in authorized project scope:\n\n{scope_check.reason}",
            )
            return

        tool_name = self.combo_tool.currentData() or "nmap"
        tokens = self._build_command_tokens()
        timeout = float(self.spin_timeout.value())

        # Clear output views
        self.txt_stdout.clear()
        self.txt_stderr.clear()
        self.table_findings.setRowCount(0)
        self.output_tabs.setTabText(2, "🔍 Discovered Findings (0)")
        self.txt_evidence_info.setText("Execution launched. Awaiting standard output and completion...")
        self.output_tabs.setCurrentIndex(0)

        job = ExecutionJob(
            tool_name=tool_name,
            target=target,
            command=tokens,
            project_id=self.active_project.id,
            display_name=f"{tool_name.upper()} Scan against {target}",
            timeout=timeout,
            scopes=scopes,
            high_risk_confirmed=self.chk_high_risk.isChecked() if self.chk_high_risk.isVisible() else True,
        )
        self._current_job = job

        # Update UI state
        self._start_time = time.time()
        self._timer.start()
        self._update_execute_button_state()
        self.lbl_exec_status.setText(f"Status: RUNNING ({tool_name})")
        self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE};")
        self.execution_started.emit(tool_name)

        # Launch async execution via ToolExecutionService
        self.execution_service.execute_job_async(
            job=job,
            on_output=lambda text, st: self._bridge.output_received.emit(text, st),
            on_state_change=lambda j: self._bridge.state_changed.emit(j.state.value),
            on_done=lambda j: self._bridge.job_finished.emit(j),
        )

    @Slot()
    def _on_cancel_clicked(self):
        if self._current_job:
            self.lbl_exec_status.setText("Status: Cancelling...")
            self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.AMBER_ACCENT};")
            self.execution_service.cancel_job(self._current_job.job_id)

    @Slot(str, str)
    def _on_output_streamed(self, text: str, stream_type: str):
        target_widget = self.txt_stderr if stream_type == "stderr" else self.txt_stdout
        target_widget.moveCursor(QTextCursor.MoveOperation.End)
        target_widget.insertPlainText(text)
        target_widget.moveCursor(QTextCursor.MoveOperation.End)

    @Slot(str)
    def _on_state_changed(self, state_str: str):
        self.lbl_exec_status.setText(f"Status: {state_str.upper()}")
        if state_str == JobState.COMPLETED.value:
            self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN};")
        elif state_str in (JobState.FAILED.value, JobState.BLOCKED.value, JobState.TIMED_OUT.value):
            self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED};")
        elif state_str == JobState.CANCELLED.value:
            self.lbl_exec_status.setStyleSheet(f"color: {CPENTTheme.AMBER_ACCENT};")

    @Slot(object)
    def _on_job_completed(self, job: ExecutionJob):
        self._timer.stop()
        self._update_timer_display()
        self._current_job = None
        self._update_execute_button_state()

        # Evidence Vault Summary
        ev_hash = job.evidence_hash or "N/A"
        ev_id = job.evidence_id or 0
        exec_id = job.execution_record_id or 0

        ev_text = (
            f"=== 🔒 CRYPTOGRAPHIC EVIDENCE VAULT RECORD ===\n"
            f"Status:           {job.state.value.upper()}\n"
            f"Exit Code:        {job.exit_code}\n"
            f"Duration:         {job.duration_seconds:.2f} seconds\n"
            f"Evidence ID:      {ev_id}\n"
            f"Execution ID:     {exec_id}\n"
            f"SHA-256 Digest:   {ev_hash}\n"
            f"Raw Output Size:  {len(job.stdout) + len(job.stderr)} bytes\n"
            f"Findings Parsed:  {len(job.findings)}\n\n"
            f"Target:           {job.target}\n"
            f"Command:          {' '.join(job.command)}\n"
        )
        self.txt_evidence_info.setText(ev_text)

        # Populate Findings Table
        self._populate_findings_table(job.findings)
        self.output_tabs.setTabText(2, f"🔍 Discovered Findings ({len(job.findings)})")

        self.refresh_history()
        self.execution_completed.emit(job.tool_name, job.exit_code or 0, ev_id)
        if job.findings:
            self.findings_discovered.emit(job.findings)

    def _populate_findings_table(self, findings: List[Finding]):
        self.table_findings.setRowCount(0)
        for row_idx, f in enumerate(findings):
            self.table_findings.insertRow(row_idx)

            title_item = QTableWidgetItem(f.title)
            title_item.setFont(get_ui_font(10, bold=True))

            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_color = {
                FindingSeverity.CRITICAL: QColor("#ef4444"),
                FindingSeverity.HIGH: QColor("#f97316"),
                FindingSeverity.MEDIUM: QColor("#eab308"),
                FindingSeverity.LOW: QColor("#3b82f6"),
                FindingSeverity.INFORMATIONAL: QColor("#64748b"),
            }.get(f.severity, QColor("#64748b"))
            sev_item.setForeground(sev_color)
            sev_item.setFont(get_ui_font(10, bold=True))

            asset_item = QTableWidgetItem(f.affected_asset)
            port_item = QTableWidgetItem(f.affected_port_service or "—")
            rem_item = QTableWidgetItem(f.remediation or "Review configuration")

            self.table_findings.setItem(row_idx, 0, title_item)
            self.table_findings.setItem(row_idx, 1, sev_item)
            self.table_findings.setItem(row_idx, 2, asset_item)
            self.table_findings.setItem(row_idx, 3, port_item)
            self.table_findings.setItem(row_idx, 4, rem_item)

    def refresh_history(self):
        """Loads previous execution history for active project from SQLite."""
        if not self.db or not self.active_project:
            self.table_history.setRowCount(0)
            return

        executions = self.db.list_executions(self.active_project.id)
        self.table_history.setRowCount(0)

        for row_idx, ex in enumerate(reversed(executions)):
            self.table_history.insertRow(row_idx)

            id_item = QTableWidgetItem(str(ex.id))
            ts_item = QTableWidgetItem(ex.started_at or ex.created_at)
            tool_item = QTableWidgetItem(ex.tool_name)
            tool_item.setFont(get_ui_font(10, bold=True))
            cmd_item = QTableWidgetItem(ex.command)
            status_item = QTableWidgetItem(ex.status.value.upper())
            dur_item = QTableWidgetItem(f"{ex.duration_seconds:.1f}s" if ex.duration_seconds else "—")

            if ex.status.value == "completed":
                status_item.setForeground(QColor(CPENTTheme.SUCCESS_GREEN))
            elif ex.status.value in ("failed", "blocked"):
                status_item.setForeground(QColor(CPENTTheme.ERROR_RED))

            self.table_history.setItem(row_idx, 0, id_item)
            self.table_history.setItem(row_idx, 1, ts_item)
            self.table_history.setItem(row_idx, 2, tool_item)
            self.table_history.setItem(row_idx, 3, cmd_item)
            self.table_history.setItem(row_idx, 4, status_item)
            self.table_history.setItem(row_idx, 5, dur_item)

    @Slot()
    def _on_history_row_selected(self):
        sel = self.table_history.selectedItems()
        if not sel or not self.db:
            return
        row = sel[0].row()
        exec_id_item = self.table_history.item(row, 0)
        if not exec_id_item:
            return

        try:
            ex_id = int(exec_id_item.text())
            ex = self.db.get_execution(ex_id, project_id=self.active_project.id if self.active_project else None)
            if ex and ex.evidence_id:
                ev = self.db.get_evidence(ex.evidence_id, project_id=self.active_project.id if self.active_project else None)
                if ev and ev.file_path and os.path.exists(ev.file_path):
                    content = Path(ev.file_path).read_text(encoding="utf-8", errors="replace")
                    self.txt_stdout.setText(content)
                    self.output_tabs.setCurrentIndex(0)
        except Exception as exc:
            logger.debug("Failed previewing historical execution: %s", exc)

    def _update_timer_display(self):
        if self._start_time > 0:
            elapsed = time.time() - self._start_time
            self.lbl_timer.setText(f"Elapsed: {elapsed:.1f}s")

    def _on_theme_changed(self, mode: ThemeMode):
        is_light = mode == ThemeMode.LIGHT
        bg = "#ffffff" if is_light else CPENTTheme.PANEL_BG
        border = "#cbd5e1" if is_light else CPENTTheme.BORDER
        fg = "#0f172a" if is_light else CPENTTheme.PRIMARY_TEXT

        form_card = self.findChild(QFrame, "executionFormCard")
        if form_card:
            form_card.setStyleSheet(f"background-color: {bg}; border: 1px solid {border}; border-radius: 8px;")

        term_bg = "#f8fafc" if is_light else "#0b1120"
        term_fg = "#0f172a" if is_light else "#e2e8f0"
        self.txt_stdout.setStyleSheet(f"background-color: {term_bg}; color: {term_fg}; font-family: monospace; border: 1px solid {border};")
        self.txt_stderr.setStyleSheet(f"background-color: {term_bg}; color: #f87171; font-family: monospace; border: 1px solid {border};")
