"""Active Directory / LDAP Live Enumerator Widget.

Provides an interactive GUI workspace for authorized, read-only Active Directory
and LDAP enumeration:
- Target, Port, SSL, and Credentials configuration (Anonymous vs Simple Bind)
- Categorized enumeration controls (RootDSE, DCs, Users, Groups, Computers, OUs, Password Policy, Security Checks)
- Live execution streaming and status
- Comprehensive Results Preview (Users, Groups, Computers, Security Findings)
- Asset Diffing: Distinguishes NEW ASSETS vs EXISTING ASSETS
- User-confirmed synchronization into the Project Database and Topology Graph.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
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
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.identity.ldap_adapter import LDAPEnumerationResult, LDAPLiveEnumerationAdapter
from storage.db import Database
from storage.models import AssetNode, Finding, FindingSeverity, Project, TargetScope


class LDAPWorkerThread(QThread):
    """Background worker thread for non-blocking LDAP execution."""

    output_received = Signal(str, str)
    enumeration_completed = Signal(object)

    def __init__(
        self,
        adapter: LDAPLiveEnumerationAdapter,
        project_id: int,
        target_host: str,
        port: int,
        use_ssl: bool,
        bind_dn: str,
        password: str,
        scopes: List[TargetScope],
        project: Optional[Project],
        categories: List[str],
        evidence_dir: Optional[Path],
        verify_cert: bool = True,
    ):
        super().__init__()
        self.adapter = adapter
        self.project_id = project_id
        self.target_host = target_host
        self.port = port
        self.use_ssl = use_ssl
        self.bind_dn = bind_dn
        self.password = password
        self.scopes = scopes
        self.project = project
        self.categories = categories
        self.evidence_dir = evidence_dir
        self.verify_cert = verify_cert
        self._is_cancelled = False

    def run(self):
        result = self.adapter.execute_enumeration(
            project_id=self.project_id,
            target_host=self.target_host,
            port=self.port,
            use_ssl=self.use_ssl,
            bind_dn=self.bind_dn,
            password=self.password,
            scopes=self.scopes,
            project=self.project,
            categories=self.categories,
            on_output=lambda msg, stream: self.output_received.emit(msg, stream),
            evidence_dir=self.evidence_dir,
            verify_cert=self.verify_cert,
        )
        self.enumeration_completed.emit(result)


class ADLDAPLiveEnumeratorWidget(QWidget):
    """Interactive GUI widget for Active Directory / LDAP live enumeration."""

    project_data_updated = Signal()

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.adapter = LDAPLiveEnumerationAdapter(db=self.db)
        self.worker: Optional[LDAPWorkerThread] = None
        self.last_result: Optional[LDAPEnumerationResult] = None

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        if project:
            self.lbl_project_status.setText(f"Active Project: <b>{project.name}</b> (ID: {project.id})")
            self.lbl_project_status.setStyleSheet("color: #38bdf8; font-size: 11px;")
        else:
            self.lbl_project_status.setText("Active Project: <i>None selected</i>")
            self.lbl_project_status.setStyleSheet("color: #f87171; font-size: 11px;")

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # Top Bar: Project Status & Help
        top_bar = QHBoxLayout()
        self.lbl_project_status = QLabel("Active Project: <i>None selected</i>")
        top_bar.addWidget(self.lbl_project_status)
        top_bar.addStretch()

        badge_readonly = QLabel("🔒 READ-ONLY ENUMERATION ONLY")
        badge_readonly.setStyleSheet(
            "font-size: 10px; font-weight: bold; padding: 2px 8px; border-radius: 4px; "
            "background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #059669;"
        )
        top_bar.addWidget(badge_readonly)
        main_layout.addLayout(top_bar)

        # Splitter: Controls (Left) vs Results (Right)
        splitter = QSplitter(Qt.Horizontal)

        # -------------------------------------------------------------
        # Left Panel: Connection & Configuration
        # -------------------------------------------------------------
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(4, 4, 4, 4)
        left_layout.setSpacing(6)

        # 1. Connection Group
        conn_group = QGroupBox("Target & Connection Settings")
        conn_layout = QGridLayout(conn_group)
        conn_layout.setSpacing(6)

        conn_layout.addWidget(QLabel("Target DC / Host:"), 0, 0)
        self.edit_host = QLineEdit()
        self.edit_host.setPlaceholderText("192.168.1.10 or dc01.corp.local")
        conn_layout.addWidget(self.edit_host, 0, 1)

        conn_layout.addWidget(QLabel("LDAP Port:"), 1, 0)
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(389)
        conn_layout.addWidget(self.spin_port, 1, 1)

        self.chk_ssl = QCheckBox("Use LDAPS / SSL (Port 636)")
        self.chk_ssl.toggled.connect(self._on_ssl_toggled)
        conn_layout.addWidget(self.chk_ssl, 2, 0, 1, 2)

        self.chk_verify_cert = QCheckBox("Strict TLS Cert Validation (Reject Self-Signed)")
        self.chk_verify_cert.setChecked(True)
        self.chk_verify_cert.setEnabled(False)
        self.chk_verify_cert.toggled.connect(self._on_verify_cert_toggled)
        conn_layout.addWidget(self.chk_verify_cert, 3, 0, 1, 2)

        left_layout.addWidget(conn_group)

        # 2. Authentication Group
        auth_group = QGroupBox("Authentication Mode")
        auth_layout = QVBoxLayout(auth_group)
        auth_layout.setSpacing(4)

        self.radio_anon = QRadioButton("Anonymous Bind (Unauthenticated Recon)")
        self.radio_anon.setChecked(True)
        self.radio_anon.toggled.connect(self._on_auth_mode_toggled)
        auth_layout.addWidget(self.radio_anon)

        self.radio_cred = QRadioButton("Authorized Read-Only Credentials (Simple Bind)")
        self.radio_cred.toggled.connect(self._on_auth_mode_toggled)
        auth_layout.addWidget(self.radio_cred)

        self.cred_frame = QFrame()
        cred_layout = QGridLayout(self.cred_frame)
        cred_layout.setContentsMargins(0, 4, 0, 0)
        cred_layout.setSpacing(4)

        cred_layout.addWidget(QLabel("User / Bind DN:"), 0, 0)
        self.edit_bind_dn = QLineEdit()
        self.edit_bind_dn.setPlaceholderText("CORP\\auditor or CN=auditor,...")
        cred_layout.addWidget(self.edit_bind_dn, 0, 1)

        cred_layout.addWidget(QLabel("Password:"), 1, 0)
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.edit_password.setPlaceholderText("Authorized read-only password")
        cred_layout.addWidget(self.edit_password, 1, 1)

        self.cred_frame.setVisible(False)
        auth_layout.addWidget(self.cred_frame)
        left_layout.addWidget(auth_group)

        # 3. Categories Selection Group
        cat_group = QGroupBox("Reconnaissance Categories")
        cat_layout = QVBoxLayout(cat_group)
        cat_layout.setSpacing(3)

        self.chk_root_dse = QCheckBox("RootDSE & Naming Contexts")
        self.chk_root_dse.setChecked(True)
        cat_layout.addWidget(self.chk_root_dse)

        self.chk_dcs = QCheckBox("Domain Controllers Discovery")
        self.chk_dcs.setChecked(True)
        cat_layout.addWidget(self.chk_dcs)

        self.chk_users = QCheckBox("Domain Users & UAC Flag Analysis")
        self.chk_users.setChecked(True)
        cat_layout.addWidget(self.chk_users)

        self.chk_groups = QCheckBox("Domain Security Groups")
        self.chk_groups.setChecked(True)
        cat_layout.addWidget(self.chk_groups)

        self.chk_computers = QCheckBox("Domain Computers & Workstations")
        self.chk_computers.setChecked(True)
        cat_layout.addWidget(self.chk_computers)

        self.chk_ous = QCheckBox("Organizational Units (OUs)")
        self.chk_ous.setChecked(True)
        cat_layout.addWidget(self.chk_ous)

        self.chk_policy = QCheckBox("Domain Password Policy")
        self.chk_policy.setChecked(True)
        cat_layout.addWidget(self.chk_policy)

        self.chk_security = QCheckBox("LDAP Security Checks (Anon, TLS, Signing)")
        self.chk_security.setChecked(True)
        cat_layout.addWidget(self.chk_security)

        left_layout.addWidget(cat_group)

        # 4. Action Buttons
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("⚡ Start Live LDAP Enumeration")
        self.btn_start.setStyleSheet(
            "background: #0284c7; color: white; font-weight: bold; padding: 8px 12px; border-radius: 4px;"
        )
        self.btn_start.clicked.connect(self._on_start_clicked)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹️ Cancel")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop_clicked)
        btn_layout.addWidget(self.btn_stop)
        left_layout.addLayout(btn_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)

        left_layout.addStretch()
        splitter.addWidget(left_widget)

        # -------------------------------------------------------------
        # Right Panel: Results & Preview Tabs
        # -------------------------------------------------------------
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(4, 4, 4, 4)
        right_layout.setSpacing(6)

        self.results_tabs = QTabWidget()

        # Tab 1: Live Log
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("Monospace", 9))
        self.txt_log.setStyleSheet("background: #090d16; color: #cbd5e1; border: 1px solid #1e293b;")
        self.results_tabs.addTab(self.txt_log, "🖥️ Live Execution Log")

        # Tab 2: Security Findings
        self.table_findings = QTableWidget(0, 5)
        self.table_findings.setHorizontalHeaderLabels(["Severity", "CVSS", "Finding Title", "Affected Asset", "Remediation"])
        self.table_findings.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_findings.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_tabs.addTab(self.table_findings, "🛡️ Security Findings")

        # Tab 3: Domain Users
        self.table_users = QTableWidget(0, 6)
        self.table_users.setHorizontalHeaderLabels(["sAMAccountName", "Display Name", "UPN", "UAC Flags", "AS-REP Roastable", "Never Expire"])
        self.table_users.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_users.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_tabs.addTab(self.table_users, "👥 Users Inventory")

        # Tab 4: Domain Groups
        self.table_groups = QTableWidget(0, 4)
        self.table_groups.setHorizontalHeaderLabels(["Group Name", "Admin Group", "Member Count", "Description"])
        self.table_groups.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_groups.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_tabs.addTab(self.table_groups, "🛡️ Groups Inventory")

        # Tab 5: Domain Computers
        self.table_computers = QTableWidget(0, 4)
        self.table_computers.setHorizontalHeaderLabels(["sAMAccountName", "DNS Hostname", "Operating System", "Version"])
        self.table_computers.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_computers.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_tabs.addTab(self.table_computers, "🖥️ Computers & DCs")

        # Tab 6: Asset Diff (NEW vs EXISTING)
        self.table_asset_diff = QTableWidget(0, 4)
        self.table_asset_diff.setHorizontalHeaderLabels(["Status", "Asset Type", "Asset Identifier", "Discovered Label"])
        self.table_asset_diff.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_asset_diff.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_tabs.addTab(self.table_asset_diff, "📋 Asset Diff (NEW vs EXISTING)")

        right_layout.addWidget(self.results_tabs, 1)

        # Bottom Bar: Synchronization Bar
        sync_bar = QHBoxLayout()
        self.lbl_sync_summary = QLabel("Run enumeration to preview and synchronize results.")
        self.lbl_sync_summary.setStyleSheet("font-size: 11px; color: #94a3b8;")
        sync_bar.addWidget(self.lbl_sync_summary)
        sync_bar.addStretch()

        self.btn_sync = QPushButton("✅ Confirm & Sync Assets to Project Database")
        self.btn_sync.setEnabled(False)
        self.btn_sync.setStyleSheet(
            "background: #10b981; color: white; font-weight: bold; padding: 6px 14px; border-radius: 4px;"
        )
        self.btn_sync.clicked.connect(self._on_sync_clicked)
        sync_bar.addWidget(self.btn_sync)

        self.btn_clear = QPushButton("✕ Clear")
        self.btn_clear.clicked.connect(self._on_clear_clicked)
        sync_bar.addWidget(self.btn_clear)

        right_layout.addLayout(sync_bar)
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter, 1)

    # --------------------------------------------------------------------------
    # Event Handlers
    # --------------------------------------------------------------------------
    def _on_ssl_toggled(self, checked: bool):
        self.chk_verify_cert.setEnabled(checked)
        if checked:
            if self.spin_port.value() == 389:
                self.spin_port.setValue(636)
        else:
            if self.spin_port.value() == 636:
                self.spin_port.setValue(389)

    def _on_verify_cert_toggled(self, checked: bool):
        if not checked and self.chk_ssl.isChecked():
            QMessageBox.warning(
                self,
                "Insecure TLS Lab Mode Warning",
                "⚠️ WARNING: Disabling TLS Certificate Verification allows connections to servers with "
                "untrusted, self-signed, or expired certificates.\n\n"
                "This mode disables hostname verification and certificate chain validation, exposing "
                "LDAPS network traffic to Machine-in-the-Middle (MitM) interception and credential sniffing.\n\n"
                "This setting is strictly intended for isolated lab exercises and authorized development environments.\n"
                "DO NOT disable certificate validation on production network assessments.",
            )

    def _on_auth_mode_toggled(self):
        self.cred_frame.setVisible(self.radio_cred.isChecked())

    def _on_start_clicked(self):
        target = self.edit_host.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please specify an Active Directory target host or IP.")
            return

        if not self.active_project:
            QMessageBox.warning(self, "No Active Project", "Please select an active project before running enumeration.")
            return

        # Check Scope before thread launch
        scopes = self.db.list_scopes(self.active_project.id) if self.db else []
        scope_check = self.adapter.validate_target_scope(target, self.active_project.id, self.active_project)
        if not scope_check.is_allowed:
            # Audit log
            if self.db:
                self.db.add_audit_log(
                    EngagementAuditLog(
                        project_id=self.active_project.id,
                        actor="operator",
                        action="out_of_scope_scan_blocked",
                        details=json.dumps({
                            "target": target,
                            "reason": scope_check.reason,
                            "source": "ldap_gui",
                        }),
                    )
                )
            QMessageBox.critical(
                self,
                "Out-of-Scope Execution Blocked",
                f"Target '{target}' is not within the authorized scope of this engagement.\n\n"
                f"Reason: {scope_check.reason}\n\n"
                "Operation blocked by fail-closed security policy.",
            )
            return

        categories = []
        if self.chk_root_dse.isChecked(): categories.append("root_dse")
        if self.chk_root_dse.isChecked(): categories.append("naming_contexts")
        if self.chk_dcs.isChecked(): categories.append("domain_controllers")
        if self.chk_users.isChecked(): categories.append("users")
        if self.chk_groups.isChecked(): categories.append("groups")
        if self.chk_computers.isChecked(): categories.append("computers")
        if self.chk_ous.isChecked(): categories.append("ous")
        if self.chk_policy.isChecked(): categories.append("password_policy")
        if self.chk_security.isChecked(): categories.append("security_checks")

        bind_dn = self.edit_bind_dn.text().strip() if self.radio_cred.isChecked() else ""
        password = self.edit_password.text() if self.radio_cred.isChecked() else ""

        self.txt_log.clear()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)

        evidence_dir = Path("storage/evidence") / f"project_{self.active_project.id}"

        self.worker = LDAPWorkerThread(
            adapter=self.adapter,
            project_id=self.active_project.id,
            target_host=target,
            port=self.spin_port.value(),
            use_ssl=self.chk_ssl.isChecked(),
            bind_dn=bind_dn,
            password=password,
            scopes=scopes,
            project=self.active_project,
            categories=categories,
            evidence_dir=evidence_dir,
            verify_cert=self.chk_verify_cert.isChecked(),
        )
        self.worker.output_received.connect(self._on_output_received)
        self.worker.enumeration_completed.connect(self._on_enumeration_completed)
        self.worker.start()

    def _on_stop_clicked(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self._on_output_received("\n[-] LDAP Enumeration stopped by operator.\n", "stderr")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)

    def _on_output_received(self, msg: str, stream: str):
        self.txt_log.insertPlainText(msg)
        self.txt_log.ensureCursorVisible()

    def _on_enumeration_completed(self, result: LDAPEnumerationResult):
        self.last_result = result
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)

        if not result.is_authorized:
            QMessageBox.critical(self, "Scope Rejection", f"Execution blocked: {result.scope_reason}")
            return

        if result.error_message and not result.root_dse:
            QMessageBox.warning(self, "Enumeration Error", f"Failed to complete enumeration:\n{result.error_message}")
            return

        # Populate tables
        self._populate_results(result)
        self.btn_sync.setEnabled(True)
        self.lbl_sync_summary.setText(
            f"Discovered: {len(result.discovered_nodes)} assets, {len(result.users)} users, "
            f"{len(result.groups)} groups, {len(result.findings)} findings. Ready to sync."
        )
        self.results_tabs.setCurrentIndex(1)  # Switch to Findings view

    def _populate_results(self, result: LDAPEnumerationResult):
        # 1. Findings Table
        self.table_findings.setRowCount(0)
        for row, f in enumerate(result.findings):
            self.table_findings.insertRow(row)
            sev_item = QTableWidgetItem(f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity))
            sev_item.setForeground(self._get_severity_color(f.severity))
            self.table_findings.setItem(row, 0, sev_item)
            self.table_findings.setItem(row, 1, QTableWidgetItem(str(f.cvss_score)))
            self.table_findings.setItem(row, 2, QTableWidgetItem(f.title))
            self.table_findings.setItem(row, 3, QTableWidgetItem(f.affected_asset))
            self.table_findings.setItem(row, 4, QTableWidgetItem(f.remediation))

        # 2. Users Table
        self.table_users.setRowCount(0)
        for row, u in enumerate(result.users):
            self.table_users.insertRow(row)
            self.table_users.setItem(row, 0, QTableWidgetItem(u["sam_name"]))
            self.table_users.setItem(row, 1, QTableWidgetItem(u.get("display_name") or ""))
            self.table_users.setItem(row, 2, QTableWidgetItem(u.get("upn") or ""))
            flags_str = ", ".join(u.get("uac_flags", []))
            self.table_users.setItem(row, 3, QTableWidgetItem(flags_str))

            asrep_item = QTableWidgetItem("⚠️ YES" if u.get("dont_req_preauth") else "No")
            if u.get("dont_req_preauth"):
                asrep_item.setForeground(QColor("#f87171"))
            self.table_users.setItem(row, 4, asrep_item)

            no_exp_item = QTableWidgetItem("Yes" if u.get("dont_expire_password") else "No")
            if u.get("dont_expire_password"):
                no_exp_item.setForeground(QColor("#fbbf24"))
            self.table_users.setItem(row, 5, no_exp_item)

        # 3. Groups Table
        self.table_groups.setRowCount(0)
        for row, g in enumerate(result.groups):
            self.table_groups.insertRow(row)
            self.table_groups.setItem(row, 0, QTableWidgetItem(g["sam_name"]))
            admin_item = QTableWidgetItem("🛡️ High Priv" if g.get("is_admin_group") else "Standard")
            if g.get("is_admin_group"):
                admin_item.setForeground(QColor("#38bdf8"))
            self.table_groups.setItem(row, 1, admin_item)
            self.table_groups.setItem(row, 2, QTableWidgetItem(str(g.get("member_count", 0))))
            self.table_groups.setItem(row, 3, QTableWidgetItem(g.get("description") or ""))

        # 4. Computers Table
        self.table_computers.setRowCount(0)
        for row, c in enumerate(result.computers):
            self.table_computers.insertRow(row)
            self.table_computers.setItem(row, 0, QTableWidgetItem(c["sam_name"]))
            self.table_computers.setItem(row, 1, QTableWidgetItem(c.get("dns_hostname") or ""))
            self.table_computers.setItem(row, 2, QTableWidgetItem(c.get("os") or "Unknown"))
            self.table_computers.setItem(row, 3, QTableWidgetItem(c.get("os_version") or ""))

        # 5. Asset Diff (NEW vs EXISTING)
        self.table_asset_diff.setRowCount(0)
        existing_assets = set()
        if self.db and self.active_project:
            existing_assets = {a.value.lower() for a in self.db.list_asset_nodes(self.active_project.id)}

        for row, node in enumerate(result.discovered_nodes):
            self.table_asset_diff.insertRow(row)
            is_new = node.value.lower() not in existing_assets

            diff_item = QTableWidgetItem("✨ NEW ASSET" if is_new else "🔄 EXISTING")
            diff_item.setForeground(QColor("#38bdf8") if is_new else QColor("#10b981"))
            self.table_asset_diff.setItem(row, 0, diff_item)
            self.table_asset_diff.setItem(row, 1, QTableWidgetItem(node.node_type.upper()))
            self.table_asset_diff.setItem(row, 2, QTableWidgetItem(node.value))
            self.table_asset_diff.setItem(row, 3, QTableWidgetItem(node.label))

    def _on_sync_clicked(self):
        if not self.last_result or not self.active_project:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Database Synchronization",
            f"Synchronize {len(self.last_result.discovered_nodes)} assets and "
            f"{len(self.last_result.findings)} findings into project '{self.active_project.name}'?\n\n"
            "This will update the project asset inventory, topology, and reports.",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        synced_assets, synced_findings = self.adapter.synchronize_to_database(
            project_id=self.active_project.id,
            result=self.last_result,
        )

        self.btn_sync.setEnabled(False)
        self.lbl_sync_summary.setText(
            f"✅ Synchronized: {synced_assets} new/updated assets and {synced_findings} findings persisted."
        )
        QMessageBox.information(
            self,
            "Synchronization Completed",
            f"Successfully synchronized:\n- {synced_assets} Assets\n- {synced_findings} Security Findings\n\n"
            "The Project Asset Inventory, 2D/3D Network Topology, and Reports have been updated.",
        )
        self.project_data_updated.emit()

    def _on_clear_clicked(self):
        self.last_result = None
        self.txt_log.clear()
        self.table_findings.setRowCount(0)
        self.table_users.setRowCount(0)
        self.table_groups.setRowCount(0)
        self.table_computers.setRowCount(0)
        self.table_asset_diff.setRowCount(0)
        self.btn_sync.setEnabled(False)
        self.lbl_sync_summary.setText("Run enumeration to preview and synchronize results.")

    @staticmethod
    def _get_severity_color(severity: Any) -> QColor:
        sev_str = (severity.value if hasattr(severity, "value") else str(severity)).upper()
        if "CRITICAL" in sev_str: return QColor("#dc2626")
        if "HIGH" in sev_str: return QColor("#f87171")
        if "MEDIUM" in sev_str: return QColor("#fbbf24")
        if "LOW" in sev_str: return QColor("#38bdf8")
        return QColor("#94a3b8")

