"""Scanner Result Preview & User Confirmation Dialog.

Displays structured preview of discovered assets, open ports, and security findings
detected from terminal or scanner executions before persisting to the project database:
1. Distinguishes NEW assets vs. EXISTING/UPDATED assets.
2. Displays scope authorization status per asset.
3. Allows operators to review and selectively confirm synchronization.
4. Prevents unconfirmed or out-of-scope data from polluting the project database.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme, get_badge_qss
from modules.network.nmap_parser import HostResult, NmapScanResult
from storage.db import Database
from storage.models import Finding, Project, TargetScope, TargetType, ScopeRuleType


class ScannerResultPreviewDialog(QDialog):
    """Modal preview dialog allowing operators to review and confirm scanner synchronization."""

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
        self.resize(880, 680)
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
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        # Header card
        header_card = QFrame()
        header_card.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        h_layout = QVBoxLayout(header_card)
        h_layout.setContentsMargins(8, 8, 8, 8)
        h_layout.setSpacing(6)

        title_row = QHBoxLayout()
        tool_badge = QLabel(f" {self.tool_name.upper()} SCAN DETECTED ")
        tool_badge.setStyleSheet("background-color: #0369a1; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 4px 8px; font-size: 11px;")
        title_row.addWidget(tool_badge)

        proj_name = self.project.name if self.project else "No Active Project"
        lbl_proj = QLabel(f"Target Engagement: <b>{proj_name}</b>")
        lbl_proj.setStyleSheet("color: #94a3b8; font-size: 12px;")
        title_row.addWidget(lbl_proj)
        title_row.addStretch()

        h_layout.addLayout(title_row)

        cmd_label = QLabel(f"Command: <code>{self.command}</code>")
        cmd_label.setStyleSheet("color: #38bdf8; font-size: 11px; font-family: monospace;")
        cmd_label.setWordWrap(True)
        h_layout.addWidget(cmd_label)

        notice = QLabel("Review discovered hosts, ports, and security findings below before committing them to the project database.")
        notice.setStyleSheet("color: #64748b; font-size: 11px; font-style: italic;")
        h_layout.addWidget(notice)

        root.addWidget(header_card)

        # Scope Authorization Alert Banner
        self.scope_banner = QFrame()
        self.scope_banner.setStyleSheet("background-color: #451a03; border: 1px solid #b45309; border-radius: 6px; padding: 6px 12px;")
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
            "QPushButton { background-color: #d97706; color: #ffffff; font-weight: bold; font-size: 11px; border: none; border-radius: 4px; padding: 5px 12px; }"
            "QPushButton:hover { background-color: #b45309; }"
        )
        self.btn_authorize_scope.clicked.connect(self._authorize_scope_action)
        sb_layout.addWidget(self.btn_authorize_scope)
        root.addWidget(self.scope_banner)

        # Section 1: Discovered Hosts & Ports Table
        lbl_hosts = QLabel("📡 Discovered Hosts & Network Ports")
        lbl_hosts.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 13px; margin-top: 6px;")
        root.addWidget(lbl_hosts)

        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(5)
        self.hosts_table.setHorizontalHeaderLabels(["Include", "Host / IP", "Status", "Open Ports / Services", "Scope Authorization"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.hosts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table.setStyleSheet("QTableWidget { background-color: #0b0f19; border: 1px solid #1e293b; color: #e2e8f0; font-size: 11px; } QHeaderView::section { background-color: #1e293b; color: #94a3b8; padding: 4px; border: none; font-weight: bold; }")
        root.addWidget(self.hosts_table, 2)

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
            item_status.setForeground(Qt.GlobalColor.green if is_new else Qt.GlobalColor.cyan)
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
                item_scope.setForeground(Qt.GlobalColor.green)
            else:
                item_scope = QTableWidgetItem(f"❌ OUT-OF-SCOPE ({scope_check.reason})")
                item_scope.setForeground(Qt.GlobalColor.red)
                cb.setChecked(False)
                cb.setEnabled(False)  # Disallow syncing out of scope
            self.hosts_table.setItem(row_idx, 4, item_scope)

        if not hosts_list:
            self.hosts_table.setRowCount(1)
            self.hosts_table.setItem(0, 1, QTableWidgetItem("No host observations parsed from this execution."))

        # Section 2: Discovered Security Findings Table
        lbl_findings = QLabel(f"🛡️ Security Findings ({len(self.findings)} Detected)")
        lbl_findings.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 13px; margin-top: 6px;")
        root.addWidget(lbl_findings)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels(["Include", "Finding Title", "Severity", "Target", "Scope"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.setStyleSheet("QTableWidget { background-color: #0b0f19; border: 1px solid #1e293b; color: #e2e8f0; font-size: 11px; } QHeaderView::section { background-color: #1e293b; color: #94a3b8; padding: 4px; border: none; font-weight: bold; }")
        root.addWidget(self.findings_table, 2)

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
            item_sev.setForeground(Qt.GlobalColor.red if sev_str in ("CRITICAL", "HIGH") else Qt.GlobalColor.yellow)
            self.findings_table.setItem(row_idx, 2, item_sev)

            item_target = QTableWidgetItem(f.affected_asset or "Unknown")
            self.findings_table.setItem(row_idx, 3, item_target)

            scope_check = ScopeAuthorizationService.is_target_authorized(f.affected_asset, self.scopes, project=self.project)
            if scope_check.is_allowed:
                item_f_scope = QTableWidgetItem("✅ In-Scope")
                item_f_scope.setForeground(Qt.GlobalColor.green)
            else:
                item_f_scope = QTableWidgetItem("❌ Blocked")
                item_f_scope.setForeground(Qt.GlobalColor.red)
                cb_f.setChecked(False)
                cb_f.setEnabled(False)
            self.findings_table.setItem(row_idx, 4, item_f_scope)

        if not self.findings:
            self.findings_table.setRowCount(1)
            self.findings_table.setItem(0, 1, QTableWidgetItem("No security vulnerabilities or exposures flagged."))

        # Footer Action Bar
        action_bar = QHBoxLayout()
        action_bar.setContentsMargins(0, 8, 0, 0)

        lbl_summary = QLabel(f"Ready to synchronize approved records into project '{proj_name}'.")
        lbl_summary.setStyleSheet("color: #94a3b8; font-size: 11px;")
        action_bar.addWidget(lbl_summary)
        action_bar.addStretch()

        btn_cancel = QPushButton("✕ Cancel (Keep as Raw Evidence Only)")
        btn_cancel.setFixedHeight(30)
        btn_cancel.setStyleSheet("background-color: #334155; color: #ffffff; border-radius: 4px; padding: 4px 14px; font-weight: 500;")
        btn_cancel.clicked.connect(self.reject)
        action_bar.addWidget(btn_cancel)

        btn_confirm = QPushButton("✅ Confirm & Sync into Project")
        btn_confirm.setFixedHeight(30)
        btn_confirm.setStyleSheet("background-color: #0284c7; color: #ffffff; border-radius: 4px; padding: 4px 18px; font-weight: bold;")
        btn_confirm.clicked.connect(self._on_confirm)
        action_bar.addWidget(btn_confirm)

        root.addLayout(action_bar)
        self._recheck_scopes()

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
        for row_idx, (cb, h) in enumerate(self.host_checkboxes):
            scope_check = ScopeAuthorizationService.is_target_authorized(h.ip, self.scopes, project=self.project)
            if not scope_check.is_allowed and h.hostname:
                scope_check = ScopeAuthorizationService.is_target_authorized(h.hostname, self.scopes, project=self.project)

            if scope_check.is_allowed:
                item_scope = QTableWidgetItem("✅ Authorized (In-Scope)")
                item_scope.setForeground(Qt.GlobalColor.green)
                cb.setEnabled(True)
                cb.setChecked(True)
            else:
                item_scope = QTableWidgetItem(f"❌ OUT-OF-SCOPE ({scope_check.reason})")
                item_scope.setForeground(Qt.GlobalColor.red)
                cb.setChecked(False)
                cb.setEnabled(False)
                has_blocked = True
            self.hosts_table.setItem(row_idx, 4, item_scope)

        for row_idx, (cb_f, f) in enumerate(self.finding_checkboxes):
            scope_check = ScopeAuthorizationService.is_target_authorized(f.affected_asset, self.scopes, project=self.project)
            if scope_check.is_allowed:
                item_f_scope = QTableWidgetItem("✅ In-Scope")
                item_f_scope.setForeground(Qt.GlobalColor.green)
                cb_f.setEnabled(True)
                cb_f.setChecked(True)
            else:
                item_f_scope = QTableWidgetItem("❌ Blocked")
                item_f_scope.setForeground(Qt.GlobalColor.red)
                cb_f.setChecked(False)
                cb_f.setEnabled(False)
                has_blocked = True
            self.findings_table.setItem(row_idx, 4, item_f_scope)

        if hasattr(self, "scope_banner"):
            self.scope_banner.setVisible(has_blocked or not self.scopes)
            if hasattr(self, "lbl_scope_warn"):
                if not self.scopes:
                    self.lbl_scope_warn.setText("⚠️ Project has NO authorized target scopes defined (Fail-Closed). Discovered targets are blocked.")
                else:
                    self.lbl_scope_warn.setText("⚠️ Discovered targets outside authorized Engagement Scope are blocked from synchronization.")

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
