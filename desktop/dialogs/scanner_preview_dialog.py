"""Scanner Result Preview & User Confirmation Dialog — 5-Step Ingestion Wizard.

Displays structured preview of discovered assets, open ports, and security findings
detected from terminal or scanner executions before persisting to the project database:
1. Scan Summary (metadata, duration, raw evidence distinction)
2. Discovered Hosts (✨ NEW ASSET vs 🔄 EXISTING / UPDATE)
3. Scope Validation (Fail-closed authorization status & plain-language explanations)
4. Findings Review (vulnerabilities triage, separate from host discovery)
5. Confirm Import (final reconciliation & project database persistence)

Preserves 100% fail-closed authorization: out-of-scope targets cannot be synchronized
without explicit operator authorization.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme, ThemeManager, ThemeMode, get_ui_font
from modules.network.nmap_parser import HostResult, NmapScanResult
from storage.db import Database
from storage.models import Finding, Project, TargetScope, TargetType, ScopeRuleType


class ScannerResultPreviewDialog(QDialog):
    """5-Step Ingestion Wizard for reviewing and confirming scanner synchronization."""

    def __init__(
        self,
        tool_name: str,
        command: str,
        scan_result: Optional[NmapScanResult] = None,
        findings: Optional[List[Finding]] = None,
        raw_output: str = "",
        db: Optional[Database] = None,
        project: Optional[Project] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.tool_name = tool_name
        self.command = command
        self.scan_result = scan_result
        self.findings = findings or []
        self.raw_output = raw_output
        self.db = db
        self.project = project

        self.confirmed_hosts: List[HostResult] = []
        self.confirmed_findings: List[Finding] = []

        self.setWindowTitle(f"Review & Confirm Scan Ingestion — {tool_name.upper()}")
        self.resize(940, 700)
        self.setObjectName("scannerPreviewDialog")

        # Load existing assets for diff
        self.existing_asset_values: Set[str] = set()
        self.scopes: List[TargetScope] = []
        if self.db and self.project:
            try:
                for node in self.db.list_asset_nodes(self.project.id):
                    self.existing_asset_values.add(node.value.casefold())
                self.scopes = self.db.list_scopes(self.project.id)
            except Exception:
                pass

        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        # -------------------------------------------------------------
        # 1. TOP HEADER & METADATA
        # -------------------------------------------------------------
        top_bar = QHBoxLayout()
        tool_badge = QLabel(f" {self.tool_name.upper()} SCAN INGESTION ")
        tool_badge.setStyleSheet(
            "background-color: #0284c7; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 4px 10px; font-size: 11px;"
        )
        top_bar.addWidget(tool_badge)

        proj_name = self.project.name if self.project else "No Active Project"
        lbl_proj = QLabel(f"Target Engagement: <b>{proj_name}</b>")
        lbl_proj.setStyleSheet("color: #94a3b8; font-size: 12px;")
        top_bar.addWidget(lbl_proj)
        top_bar.addStretch()

        root.addLayout(top_bar)

        # -------------------------------------------------------------
        # 2. FIVE-STEP WIZARD NAVIGATION BAR
        # -------------------------------------------------------------
        self.step_btn_group = QButtonGroup(self)
        self.step_btn_group.setExclusive(True)

        step_bar_frame = QFrame()
        step_bar_frame.setStyleSheet(
            "QFrame { background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 2px; }"
        )
        step_bar_layout = QHBoxLayout(step_bar_frame)
        step_bar_layout.setContentsMargins(4, 4, 4, 4)
        step_bar_layout.setSpacing(4)

        hosts_count = len(self.scan_result.hosts) if self.scan_result and self.scan_result.hosts else 0
        findings_count = len(self.findings)

        step_labels = [
            ("1. Scan Summary", 0),
            (f"2. Discovered Hosts ({hosts_count})", 1),
            ("3. Scope Validation", 2),
            (f"4. Findings Review ({findings_count})", 3),
            ("5. Confirm Import", 4),
        ]

        self.step_buttons: List[QPushButton] = []
        for label, idx in step_labels:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn.setFixedHeight(30)
            btn.setStyleSheet(
                "QPushButton { background: transparent; color: #94a3b8; border: none; border-radius: 4px; font-size: 11px; font-weight: 600; padding: 4px 8px; }"
                "QPushButton:hover { background: #1e293b; color: #f8fafc; }"
                "QPushButton:checked { background: #2563eb; color: #ffffff; font-weight: bold; }"
            )
            btn.clicked.connect(lambda _, i=idx: self.set_step(i))
            self.step_btn_group.addButton(btn, idx)
            step_bar_layout.addWidget(btn)
            self.step_buttons.append(btn)

        self.step_buttons[0].setChecked(True)
        root.addWidget(step_bar_frame)

        # -------------------------------------------------------------
        # 3. WIZARD STACKED PAGES
        # -------------------------------------------------------------
        self.wizard_stack = QStackedWidget()
        root.addWidget(self.wizard_stack, 1)

        # Page 0: Scan Summary
        page_summary = self._create_page_summary(proj_name, hosts_count, findings_count)
        self.wizard_stack.addWidget(page_summary)

        # Page 1: Discovered Hosts Table
        page_hosts = self._create_page_hosts()
        self.wizard_stack.addWidget(page_hosts)

        # Page 2: Scope Validation & Authorization
        page_scope = self._create_page_scope(proj_name)
        self.wizard_stack.addWidget(page_scope)

        # Page 3: Findings Review Table
        page_findings = self._create_page_findings()
        self.wizard_stack.addWidget(page_findings)

        # Page 4: Confirm Import
        page_confirm = self._create_page_confirm(proj_name)
        self.wizard_stack.addWidget(page_confirm)

        self._recheck_scopes()

    # -----------------------------------------------------------------
    # PAGE 0: SCAN SUMMARY
    # -----------------------------------------------------------------
    def _create_page_summary(self, proj_name: str, hosts_count: int, findings_count: int) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 8, 4, 4)
        layout.setSpacing(12)

        card = QFrame()
        card.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(8)

        lbl_summary_title = QLabel("Execution Telemetry & Summary")
        lbl_summary_title.setFont(get_ui_font(13, bold=True, heading=True))
        lbl_summary_title.setStyleSheet("color: #38bdf8;")
        card_layout.addWidget(lbl_summary_title)

        clean_cmd = str(self.command).strip() or "No command string recorded"
        cmd_box = QLabel(f"Command: <code>{clean_cmd}</code>")
        cmd_box.setStyleSheet("color: #e2e8f0; font-size: 12px; font-family: monospace; background: #0b0f19; padding: 8px 12px; border-radius: 4px; border: 1px solid #1e293b;")
        cmd_box.setWordWrap(True)
        card_layout.addWidget(cmd_box)

        # Parse scan duration if available in raw output
        duration_str = "Completed"
        if self.raw_output:
            dur_match = re.search(r"in\s+([0-9\.]+\s*seconds)", self.raw_output)
            if dur_match:
                duration_str = f"Duration: {dur_match.group(1)}"

        # Metrics row
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)

        card_h = self._info_metric_box("Discovered Hosts", str(hosts_count), "#38bdf8")
        card_f = self._info_metric_box("Security Findings", str(findings_count), "#f87171" if findings_count > 0 else "#34d399")
        card_d = self._info_metric_box("Execution State", duration_str, "#a78bfa")

        metrics_row.addWidget(card_h)
        metrics_row.addWidget(card_f)
        metrics_row.addWidget(card_d)
        card_layout.addLayout(metrics_row)

        layout.addWidget(card)

        # Raw Evidence Preservation Card
        evidence_card = QFrame()
        evidence_card.setStyleSheet(
            "background-color: #0c1a2e; border: 1px solid #0284c7; border-radius: 8px; padding: 14px;"
        )
        ev_layout = QVBoxLayout(evidence_card)
        ev_layout.setSpacing(6)

        lbl_ev_title = QLabel("💾 Evidence Vault Preservation")
        lbl_ev_title.setFont(get_ui_font(12, bold=True))
        lbl_ev_title.setStyleSheet("color: #38bdf8;")
        ev_layout.addWidget(lbl_ev_title)

        lbl_ev_desc = QLabel(
            "Terminal execution output and command artifacts have already been securely captured and hashed (SHA-256) into your Evidence repository.\n\n"
            "This 5-step wizard allows you to selectively synchronize structured AssetNode and Finding records into your engagement database. "
            "Cancelling at any point will safely preserve the raw evidence without polluting your project asset tables."
        )
        lbl_ev_desc.setFont(get_ui_font(11))
        lbl_ev_desc.setStyleSheet("color: #cbd5e1; line-height: 1.4;")
        lbl_ev_desc.setWordWrap(True)
        ev_layout.addWidget(lbl_ev_desc)

        layout.addWidget(evidence_card)
        layout.addStretch()

        # Step Footer
        step_footer = QHBoxLayout()
        step_footer.addStretch()
        btn_next = QPushButton("Next: Discovered Hosts →")
        btn_next.setStyleSheet("background-color: #2563eb; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 6px 18px; font-size: 12px;")
        btn_next.clicked.connect(lambda: self.set_step(1))
        step_footer.addWidget(btn_next)
        layout.addLayout(step_footer)

        return page

    # -----------------------------------------------------------------
    # PAGE 1: DISCOVERED HOSTS & SERVICES
    # -----------------------------------------------------------------
    def _create_page_hosts(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        lbl_hdr = QLabel("📡 Step 2: Discovered Hosts & Network Ports")
        lbl_hdr.setFont(get_ui_font(13, bold=True, heading=True))
        lbl_hdr.setStyleSheet("color: #38bdf8;")
        layout.addWidget(lbl_hdr)

        lbl_sub = QLabel("Select in-scope hosts to synchronize into the Asset Inventory. Out-of-scope targets are disabled by default.")
        lbl_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(lbl_sub)

        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(5)
        self.hosts_table.setHorizontalHeaderLabels(["Include", "Host / IP", "Status", "Open Ports / Services", "Scope Authorization"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.hosts_table.setColumnWidth(1, 180)
        self.hosts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.hosts_table.setColumnWidth(2, 160)
        self.hosts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.hosts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.hosts_table.setColumnWidth(4, 220)
        self.hosts_table.setStyleSheet(
            "QTableWidget { background-color: #0b0f19; border: 1px solid #1e293b; color: #e2e8f0; font-size: 12px; gridline-color: #1e293b; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; padding: 6px; border: none; font-weight: bold; font-size: 11px; }"
        )
        layout.addWidget(self.hosts_table, 1)

        # Populate hosts table
        hosts_list = self.scan_result.hosts if self.scan_result and self.scan_result.hosts else []
        self.host_checkboxes: List[Tuple[QCheckBox, HostResult]] = []

        self.hosts_table.setRowCount(len(hosts_list))
        for row_idx, h in enumerate(hosts_list):
            cb = QCheckBox()
            cb.setChecked(True)
            self.host_checkboxes.append((cb, h))
            self.hosts_table.setCellWidget(row_idx, 0, cb)

            host_label = h.ip
            if h.hostname:
                host_label = f"{h.ip} ({h.hostname})"
            item_host = QTableWidgetItem(host_label)
            self.hosts_table.setItem(row_idx, 1, item_host)

            is_new = h.ip.casefold() not in self.existing_asset_values and (not h.hostname or h.hostname.casefold() not in self.existing_asset_values)
            status_text = "✨ NEW ASSET" if is_new else "🔄 EXISTING / UPDATE"
            item_status = QTableWidgetItem(status_text)
            item_status.setForeground(QColor("#4ade80" if is_new else "#38bdf8"))
            self.hosts_table.setItem(row_idx, 2, item_status)

            # Ports summary
            open_ports = [f"{getattr(p, 'port_id', getattr(p, 'portid', '?'))}/{p.protocol} ({p.service_name or 'unknown'})" for p in h.ports if p.state == "open"]
            ports_summary = ", ".join(open_ports) if open_ports else "No open ports reported"
            item_ports = QTableWidgetItem(ports_summary)
            self.hosts_table.setItem(row_idx, 3, item_ports)

            # Scope Check
            scope_check = ScopeAuthorizationService.is_target_authorized(h.ip, self.scopes, project=self.project)
            if not scope_check.is_allowed and h.hostname:
                scope_check = ScopeAuthorizationService.is_target_authorized(h.hostname, self.scopes, project=self.project)

            if scope_check.is_allowed:
                item_scope = QTableWidgetItem("✅ Authorized (In-Scope)")
                item_scope.setForeground(QColor("#4ade80"))
            else:
                item_scope = QTableWidgetItem(f"❌ OUT-OF-SCOPE ({scope_check.reason})")
                item_scope.setForeground(QColor("#ef4444"))
                cb.setChecked(False)
                cb.setEnabled(False)
            self.hosts_table.setItem(row_idx, 4, item_scope)

        if not hosts_list:
            self.hosts_table.setRowCount(1)
            self.hosts_table.setItem(0, 1, QTableWidgetItem("No host observations parsed from this execution."))

        # Step Footer
        step_footer = QHBoxLayout()
        btn_prev = QPushButton("← Previous: Summary")
        btn_prev.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 6px 14px; font-size: 11px;")
        btn_prev.clicked.connect(lambda: self.set_step(0))
        step_footer.addWidget(btn_prev)

        step_footer.addStretch()

        btn_next = QPushButton("Next: Scope Validation →")
        btn_next.setStyleSheet("background-color: #2563eb; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 6px 18px; font-size: 12px;")
        btn_next.clicked.connect(lambda: self.set_step(2))
        step_footer.addWidget(btn_next)
        layout.addLayout(step_footer)

        return page

    # -----------------------------------------------------------------
    # PAGE 2: SCOPE VALIDATION & AUTHORIZATION
    # -----------------------------------------------------------------
    def _create_page_scope(self, proj_name: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        lbl_hdr = QLabel("🎯 Step 3: Scope Validation & Authorization Enforcement")
        lbl_hdr.setFont(get_ui_font(13, bold=True, heading=True))
        lbl_hdr.setStyleSheet("color: #38bdf8;")
        layout.addWidget(lbl_hdr)

        # Scope Authorization Alert Banner
        self.scope_banner = QFrame()
        self.scope_banner.setStyleSheet("background-color: #451a03; border: 1px solid #b45309; border-radius: 6px; padding: 8px 12px;")
        sb_layout = QHBoxLayout(self.scope_banner)
        sb_layout.setContentsMargins(8, 6, 8, 6)
        sb_layout.setSpacing(10)

        self.lbl_scope_warn = QLabel("⚠️ Discovered targets require authorization in Engagement Scope before synchronization.")
        self.lbl_scope_warn.setStyleSheet("color: #fde68a; font-size: 11px; font-weight: 500;")
        sb_layout.addWidget(self.lbl_scope_warn)
        sb_layout.addStretch()

        self.btn_authorize_scope = QPushButton("➕ Authorize Target Subnet in Scope")
        self.btn_authorize_scope.setCursor(Qt.PointingHandCursor)
        self.btn_authorize_scope.setStyleSheet(
            "QPushButton { background-color: #d97706; color: #ffffff; font-weight: bold; font-size: 11px; border: none; border-radius: 4px; padding: 6px 14px; }"
            "QPushButton:hover { background-color: #b45309; }"
        )
        self.btn_authorize_scope.clicked.connect(self._authorize_scope_action)
        sb_layout.addWidget(self.btn_authorize_scope)
        layout.addWidget(self.scope_banner)

        # Scope Breakdown Box
        breakdown_box = QFrame()
        breakdown_box.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        b_layout = QVBoxLayout(breakdown_box)
        b_layout.setSpacing(6)

        lbl_b_title = QLabel("Target Scope Evaluation (Fail-Closed Guard)")
        lbl_b_title.setFont(get_ui_font(12, bold=True))
        lbl_b_title.setStyleSheet("color: #f8fafc;")
        b_layout.addWidget(lbl_b_title)

        self.lbl_scope_details = QLabel("Evaluating active project target scope boundaries...")
        self.lbl_scope_details.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        self.lbl_scope_details.setWordWrap(True)
        b_layout.addWidget(self.lbl_scope_details)

        layout.addWidget(breakdown_box, 1)

        # Step Footer
        step_footer = QHBoxLayout()
        btn_prev = QPushButton("← Previous: Hosts")
        btn_prev.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 6px 14px; font-size: 11px;")
        btn_prev.clicked.connect(lambda: self.set_step(1))
        step_footer.addWidget(btn_prev)

        step_footer.addStretch()

        btn_next = QPushButton("Next: Findings Review →")
        btn_next.setStyleSheet("background-color: #2563eb; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 6px 18px; font-size: 12px;")
        btn_next.clicked.connect(lambda: self.set_step(3))
        step_footer.addWidget(btn_next)
        layout.addLayout(step_footer)

        return page

    # -----------------------------------------------------------------
    # PAGE 3: FINDINGS REVIEW
    # -----------------------------------------------------------------
    def _create_page_findings(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        lbl_hdr = QLabel(f"🛡️ Step 4: Security Findings ({len(self.findings)} Detected)")
        lbl_hdr.setFont(get_ui_font(13, bold=True, heading=True))
        lbl_hdr.setStyleSheet("color: #38bdf8;")
        layout.addWidget(lbl_hdr)

        lbl_notice = QLabel(
            "Note: Host/port discovery results are categorized as Asset observations, not vulnerabilities. "
            "Only security flaws detected by vulnerability plugins or explicit script rules appear below."
        )
        lbl_notice.setStyleSheet("color: #94a3b8; font-size: 11px; font-style: italic;")
        lbl_notice.setWordWrap(True)
        layout.addWidget(lbl_notice)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels(["Include", "Finding Title", "Severity", "Target", "Scope"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.findings_table.setColumnWidth(3, 160)
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.setStyleSheet(
            "QTableWidget { background-color: #0b0f19; border: 1px solid #1e293b; color: #e2e8f0; font-size: 12px; gridline-color: #1e293b; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; padding: 6px; border: none; font-weight: bold; font-size: 11px; }"
        )
        layout.addWidget(self.findings_table, 1)

        self.finding_checkboxes: List[Tuple[QCheckBox, Finding]] = []
        self.findings_table.setRowCount(len(self.findings))

        for row_idx, f in enumerate(self.findings):
            cb_f = QCheckBox()
            cb_f.setChecked(True)
            self.finding_checkboxes.append((cb_f, f))
            self.findings_table.setCellWidget(row_idx, 0, cb_f)

            item_title = QTableWidgetItem(f.title)
            self.findings_table.setItem(row_idx, 1, item_title)

            sev_str = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            item_sev = QTableWidgetItem(sev_str)
            item_sev.setForeground(QColor("#ef4444" if sev_str in ("CRITICAL", "HIGH") else "#eab308"))
            self.findings_table.setItem(row_idx, 2, item_sev)

            item_target = QTableWidgetItem(f.affected_asset or "Unknown")
            self.findings_table.setItem(row_idx, 3, item_target)

            scope_check = ScopeAuthorizationService.is_target_authorized(f.affected_asset, self.scopes, project=self.project)
            if scope_check.is_allowed:
                item_f_scope = QTableWidgetItem("✅ In-Scope")
                item_f_scope.setForeground(QColor("#4ade80"))
            else:
                item_f_scope = QTableWidgetItem("❌ Blocked")
                item_f_scope.setForeground(QColor("#ef4444"))
                cb_f.setChecked(False)
                cb_f.setEnabled(False)
            self.findings_table.setItem(row_idx, 4, item_f_scope)

        if not self.findings:
            self.findings_table.setRowCount(1)
            self.findings_table.setItem(0, 1, QTableWidgetItem("No security vulnerabilities or exposures flagged."))

        # Step Footer
        step_footer = QHBoxLayout()
        btn_prev = QPushButton("← Previous: Scope")
        btn_prev.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 6px 14px; font-size: 11px;")
        btn_prev.clicked.connect(lambda: self.set_step(2))
        step_footer.addWidget(btn_prev)

        step_footer.addStretch()

        btn_next = QPushButton("Next: Confirm Import →")
        btn_next.setStyleSheet("background-color: #2563eb; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 6px 18px; font-size: 12px;")
        btn_next.clicked.connect(lambda: self.set_step(4))
        step_footer.addWidget(btn_next)
        layout.addLayout(step_footer)

        return page

    # -----------------------------------------------------------------
    # PAGE 4: CONFIRM IMPORT
    # -----------------------------------------------------------------
    def _create_page_confirm(self, proj_name: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(12)

        lbl_hdr = QLabel("✅ Step 5: Final Review & Confirmation")
        lbl_hdr.setFont(get_ui_font(13, bold=True, heading=True))
        lbl_hdr.setStyleSheet("color: #38bdf8;")
        layout.addWidget(lbl_hdr)

        # Reconciliation Box
        recon_box = QFrame()
        recon_box.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        r_layout = QVBoxLayout(recon_box)
        r_layout.setSpacing(8)

        lbl_r_title = QLabel("Reconciliation Summary")
        lbl_r_title.setFont(get_ui_font(12, bold=True))
        lbl_r_title.setStyleSheet("color: #ffffff;")
        r_layout.addWidget(lbl_r_title)

        self.lbl_recon_summary = QLabel("Calculating reconciliation totals...")
        self.lbl_recon_summary.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.5;")
        self.lbl_recon_summary.setWordWrap(True)
        r_layout.addWidget(self.lbl_recon_summary)

        layout.addWidget(recon_box)

        # Explicit Warning Card
        distinction_card = QFrame()
        distinction_card.setStyleSheet("background-color: #0b1528; border: 1px solid #1e3a8a; border-radius: 8px; padding: 14px;")
        d_layout = QVBoxLayout(distinction_card)
        d_layout.setSpacing(6)

        lbl_d_title = QLabel("📌 Explicit Separation of Evidence vs. Project Database")
        lbl_d_title.setFont(get_ui_font(12, bold=True))
        lbl_d_title.setStyleSheet("color: #38bdf8;")
        d_layout.addWidget(lbl_d_title)

        lbl_d_body = QLabel(
            "• <b>Save Evidence:</b> Your raw execution output has ALREADY been safely recorded into the Evidence Vault.\n"
            "• <b>Import into Project:</b> Clicking 'Confirm & Sync' below will ONLY persist the approved in-scope hosts as AssetNodes and findings into your engagement.\n"
            "• <b>Out-of-Scope Protection:</b> Blocked out-of-scope targets will NEVER be imported into project records."
        )
        lbl_d_body.setFont(get_ui_font(11))
        lbl_d_body.setStyleSheet("color: #cbd5e1; line-height: 1.4;")
        lbl_d_body.setWordWrap(True)
        d_layout.addWidget(lbl_d_body)
        layout.addWidget(distinction_card)

        layout.addStretch()

        # Action Bar
        action_bar = QHBoxLayout()
        action_bar.setContentsMargins(0, 8, 0, 0)
        action_bar.setSpacing(10)

        btn_prev = QPushButton("← Previous: Findings")
        btn_prev.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 6px 14px; font-size: 11px;")
        btn_prev.clicked.connect(lambda: self.set_step(3))
        action_bar.addWidget(btn_prev)

        action_bar.addStretch()

        btn_cancel = QPushButton("✕ Cancel (Keep as Raw Evidence Only)")
        btn_cancel.setFixedHeight(34)
        btn_cancel.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 6px 16px; font-weight: 500; font-size: 12px;")
        btn_cancel.clicked.connect(self.reject)
        action_bar.addWidget(btn_cancel)

        self.btn_confirm = QPushButton("✅ Confirm & Sync into Project")
        self.btn_confirm.setFixedHeight(34)
        self.btn_confirm.setStyleSheet(
            "QPushButton { background-color: #0284c7; color: #ffffff; border-radius: 4px; padding: 6px 20px; font-weight: bold; font-size: 12px; }"
            "QPushButton:hover { background-color: #0369a1; }"
            "QPushButton:disabled { background-color: #1e293b; color: #64748b; }"
        )
        self.btn_confirm.clicked.connect(self._on_confirm)
        action_bar.addWidget(self.btn_confirm)

        layout.addLayout(action_bar)
        return page

    def _info_metric_box(self, title: str, value: str, accent_color: str) -> QFrame:
        box = QFrame()
        box.setStyleSheet("background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; padding: 10px;")
        b_layout = QVBoxLayout(box)
        b_layout.setSpacing(2)

        lbl_v = QLabel(value)
        lbl_v.setFont(get_ui_font(16, bold=True, heading=True))
        lbl_v.setStyleSheet(f"color: {accent_color};")
        b_layout.addWidget(lbl_v)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 600;")
        b_layout.addWidget(lbl_t)

        return box

    def set_step(self, step_idx: int):
        """Switches wizard page and synchronizes step button states."""
        self.wizard_stack.setCurrentIndex(step_idx)
        for i, btn in enumerate(self.step_buttons):
            btn.setChecked(i == step_idx)
        self._update_confirm_page_summary()

    def _detect_suggested_subnet(self) -> str:
        """Derives a suggested CIDR subnet or target from command and discovered hosts."""
        if self.command:
            cidr_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b", self.command)
            if cidr_match:
                return cidr_match.group(1)
            ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", self.command)
            if ip_match:
                octs = ip_match.group(1).split(".")
                return f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"

        hosts_list = self.scan_result.hosts if self.scan_result and self.scan_result.hosts else []
        for h in hosts_list:
            if h.ip and "." in h.ip:
                octs = h.ip.split(".")
                if len(octs) == 4:
                    return f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"

        return "192.168.100.0/24"

    def _authorize_scope_action(self):
        """Authorizes suggested target/subnet into project scope and rechecks all items."""
        if not self.db or not self.project:
            QMessageBox.warning(self, "No Project", "Cannot add scope: active project or database not available.")
            return

        suggested = self._detect_suggested_subnet()

        reply = QMessageBox.question(
            self,
            "Authorize Target Scope",
            f"Add target <b>{suggested}</b> to authorized scope for Engagement <b>'{self.project.name}'</b>?<br><br>"
            f"This will authorize discovered hosts in this subnet and allow asset synchronization.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                new_scope = TargetScope(
                    project_id=self.project.id,
                    target=suggested,
                    target_type=TargetType.CIDR_RANGE if "/" in suggested else TargetType.IP_ADDRESS,
                    is_authorized=True,
                    rule_type=ScopeRuleType.ALLOWED,
                    notes=f"Authorized from {self.tool_name} scan ingestion",
                )
                self.db.add_scope(new_scope)
                self._recheck_scopes()
                QMessageBox.information(
                    self,
                    "Scope Authorized",
                    f"Target '{suggested}' has been added to authorized project scope!\n\nMatching hosts are now marked as In-Scope and ready for synchronization.",
                )
            except Exception as e:
                QMessageBox.critical(self, "Error Adding Scope", f"Failed to authorize scope: {e}")

    def _recheck_scopes(self):
        """Reloads project scopes and re-evaluates all host and finding rows."""
        if self.db and self.project:
            try:
                self.scopes = self.db.list_scopes(self.project.id)
            except Exception:
                pass

        has_blocked = False
        allowed_hosts = 0
        blocked_hosts = 0

        for row_idx, (cb, h) in enumerate(self.host_checkboxes):
            scope_check = ScopeAuthorizationService.is_target_authorized(h.ip, self.scopes, project=self.project)
            if not scope_check.is_allowed and h.hostname:
                scope_check = ScopeAuthorizationService.is_target_authorized(h.hostname, self.scopes, project=self.project)

            if scope_check.is_allowed:
                item_scope = QTableWidgetItem("✅ Authorized (In-Scope)")
                item_scope.setForeground(QColor("#4ade80"))
                cb.setEnabled(True)
                cb.setChecked(True)
                allowed_hosts += 1
            else:
                item_scope = QTableWidgetItem(f"❌ OUT-OF-SCOPE ({scope_check.reason})")
                item_scope.setForeground(QColor("#ef4444"))
                cb.setChecked(False)
                cb.setEnabled(False)
                has_blocked = True
                blocked_hosts += 1
            self.hosts_table.setItem(row_idx, 4, item_scope)

        allowed_findings = 0
        blocked_findings = 0
        for row_idx, (cb_f, f) in enumerate(self.finding_checkboxes):
            scope_check = ScopeAuthorizationService.is_target_authorized(f.affected_asset, self.scopes, project=self.project)
            if scope_check.is_allowed:
                item_f_scope = QTableWidgetItem("✅ In-Scope")
                item_f_scope.setForeground(QColor("#4ade80"))
                cb_f.setEnabled(True)
                cb_f.setChecked(True)
                allowed_findings += 1
            else:
                item_f_scope = QTableWidgetItem("❌ Blocked")
                item_f_scope.setForeground(QColor("#ef4444"))
                cb_f.setChecked(False)
                cb_f.setEnabled(False)
                has_blocked = True
                blocked_findings += 1
            self.findings_table.setItem(row_idx, 4, item_f_scope)

        if hasattr(self, "scope_banner"):
            self.scope_banner.setVisible(has_blocked or not self.scopes)
            if hasattr(self, "lbl_scope_warn"):
                if not self.scopes:
                    self.lbl_scope_warn.setText("⚠️ Project has NO authorized target scopes defined (Fail-Closed). Discovered targets are blocked.")
                else:
                    self.lbl_scope_warn.setText("⚠️ Discovered targets outside authorized Engagement Scope are blocked from synchronization.")

        if hasattr(self, "lbl_scope_details"):
            if not self.scopes:
                self.lbl_scope_details.setText(
                    "❌ <b>NO TARGET SCOPES AUTHORIZED:</b> This engagement has 0 active target scopes. "
                    "Under strict Rules of Engagement (RoE), all discovery data is blocked from persistence until you explicitly add an authorized subnet."
                )
            else:
                self.lbl_scope_details.setText(
                    f"• <b>Authorized In-Scope Targets:</b> {allowed_hosts} host(s) match current scope rules.<br>"
                    f"• <b>Blocked Out-of-Scope Targets:</b> {blocked_hosts} host(s) fall outside legal boundaries.<br>"
                    f"• <b>Active Scope Boundaries:</b> {len(self.scopes)} rule(s) configured in Project Management."
                )

        self._update_confirm_page_summary()

    def _update_confirm_page_summary(self):
        """Updates the reconciliation totals on Page 4."""
        if not hasattr(self, "lbl_recon_summary"):
            return

        eligible_hosts = sum(1 for cb, _ in self.host_checkboxes if cb.isChecked())
        eligible_findings = sum(1 for cb_f, _ in self.finding_checkboxes if cb_f.isChecked())
        total_blocked_hosts = sum(1 for cb, _ in self.host_checkboxes if not cb.isEnabled())

        proj_name = self.project.name if self.project else "No Active Project"
        self.lbl_recon_summary.setText(
            f"• <b>Target Project:</b> {proj_name}<br>"
            f"• <b>Hosts to Synchronize:</b> <font color='#4ade80'><b>{eligible_hosts} In-Scope Asset(s)</b></font><br>"
            f"• <b>Findings to Log:</b> <font color='#38bdf8'><b>{eligible_findings} Security Finding(s)</b></font><br>"
            f"• <b>Blocked / Excluded:</b> <font color='#ef4444'><b>{total_blocked_hosts} Out-of-Scope Host(s)</b></font>"
        )

        if hasattr(self, "btn_confirm"):
            # Disable confirm if zero items are selected
            has_selection = eligible_hosts > 0 or eligible_findings > 0 or (not self.host_checkboxes and not self.finding_checkboxes)
            self.btn_confirm.setEnabled(has_selection)

    def _on_confirm(self):
        """Collects only user-approved, in-scope hosts and findings."""
        self.confirmed_hosts = [h for cb, h in self.host_checkboxes if cb.isChecked()]
        self.confirmed_findings = [f for cb, f in self.finding_checkboxes if cb.isChecked()]
        if not self.confirmed_hosts and not self.confirmed_findings:
            if self.host_checkboxes or self.finding_checkboxes:
                QMessageBox.warning(
                    self,
                    "No Items Selected",
                    "No authorized, in-scope hosts or findings are selected for synchronization.\n\n"
                    "Please ensure target scopes are authorized and items are selected.",
                )
                return
        self.accept()
