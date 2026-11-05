"""Open-Source Intelligence (OSINT) & Attack Surface Workspace for CyberSecuritySuite.

Implements an end-to-end intelligence reconnaissance lifecycle:
1. OSINT Case Management & Authorization Verification
2. Multi-Source Asset Discovery (OWASP Amass, Certificate Transparency, Optional Stubs)
3. Interactive Attack Surface Relationship Graph (Maltego Interoperability)
4. Asset Inventory & Scope Classification (In-Scope vs Quarantined)
5. Intelligence Observations & Cryptographic Evidence Vault
6. Intelligence Summary & Assessment Reports
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme
from desktop.widgets.attack_graph_view import AttackGraphView
from modules.osint.amass_osint_adapter import AmassOSINTAdapter
from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from modules.osint.cert_transparency_adapter import CertTransparencyAdapter
from modules.osint.maltego_graph import MaltegoGraphEngine
from modules.osint.passive_recon import PassiveReconAdapter
from modules.osint.recon_ng_adapter import ReconNgAdapter
from modules.osint.theharvester_adapter import TheHarvesterAdapter
from storage.db import Database
from storage.models import (
    AssetNode,
    Observation,
    OSINTCase,
    Project,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


class OSINTWorkerSignals(QObject):
    output_received = Signal(str, str)
    discovery_finished = Signal(object)


class OSINTView(QWidget):
    """Unified OSINT & Reconnaissance Intelligence Workspace."""

    project_data_updated = Signal()

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.active_case: Optional[OSINTCase] = None

        # Registered OSINT source adapters
        self.adapters: Dict[str, BaseOSINTAdapter] = {
            "passive_recon": PassiveReconAdapter(self.db),
            "cert_transparency": CertTransparencyAdapter(self.db),
            "amass": AmassOSINTAdapter(self.db),
            "theharvester": TheHarvesterAdapter(self.db),
            "recon_ng": ReconNgAdapter(self.db),
        }

        self.signals = OSINTWorkerSignals()
        self.signals.output_received.connect(self._on_output_received)
        self.signals.discovery_finished.connect(self._on_discovery_finished)

        self._active_thread: Optional[threading.Thread] = None
        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        """Binds the workspace to the currently selected assessment project."""
        self.active_project = project
        if project:
            self.lbl_project_status.setText(
                f"Active Engagement: <b>{project.name}</b> (Client: {project.client_name or 'N/A'}, Status: {project.status.value.upper()})"
            )
            self.lbl_project_status.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-size: 12px; font-weight: 500;")
            self.load_cases()
            self.load_assets()
            self.load_observations()
            self.graph_view.set_active_project(project)
        else:
            self.lbl_project_status.setText("No active project selected. Select a project in Projects & Scope first.")
            self.lbl_project_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-size: 12px; font-weight: 500;")
            self.cases_table.setRowCount(0)
            self.assets_table.setRowCount(0)
            self.observations_table.setRowCount(0)
            self.graph_view.set_active_project(None)

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(10, 10, 10, 10)
        root_layout.setSpacing(8)

        # Header bar
        header_bar = QHBoxLayout()
        title_label = QLabel("🔎  OSINT Intelligence Workspace")
        title_label.setObjectName("viewHeader")
        header_bar.addWidget(title_label)
        header_bar.addStretch()

        self.lbl_project_status = QLabel("No active project selected.")
        self.lbl_project_status.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 12px;")
        header_bar.addWidget(self.lbl_project_status)
        root_layout.addLayout(header_bar)

        # Main Workspace Tab View
        self.tabs = QTabWidget()

        # -------------------------------------------------------------
        # Tab 1: OSINT Case Management & Authorization
        # -------------------------------------------------------------
        self.tab_cases = self._create_cases_tab()
        self.tabs.addTab(self.tab_cases, "📁 Cases & Authorization")

        # -------------------------------------------------------------
        # Tab 2: Multi-Source Asset Discovery
        # -------------------------------------------------------------
        self.tab_discovery = self._create_discovery_tab()
        self.tabs.addTab(self.tab_discovery, "📡 Asset Discovery")

        # -------------------------------------------------------------
        # Tab 3: Relationship Graph (Maltego)
        # -------------------------------------------------------------
        self.graph_view = AttackGraphView(self.db)
        self.tabs.addTab(self.graph_view, "🕸️ Relationship Graph")

        # -------------------------------------------------------------
        # Tab 4: Asset Inventory & Scope Classification
        # -------------------------------------------------------------
        self.tab_inventory = self._create_inventory_tab()
        self.tabs.addTab(self.tab_inventory, "📦 Asset Inventory & Scope Review")

        # -------------------------------------------------------------
        # Tab 5: Observations & Evidence
        # -------------------------------------------------------------
        self.tab_observations = self._create_observations_tab()
        self.tabs.addTab(self.tab_observations, "👁️ Observations & Evidence")

        # -------------------------------------------------------------
        # Tab 6: Intelligence Report & Summary
        # -------------------------------------------------------------
        self.tab_reports = self._create_reports_tab()
        self.tabs.addTab(self.tab_reports, "📄 Intelligence Summary")

        root_layout.addWidget(self.tabs)

    # -----------------------------------------------------------------
    # Tab 1: Cases & Authorization
    # -----------------------------------------------------------------
    def _create_cases_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top: Active Cases Table
        top_box = QGroupBox("Active OSINT Cases for Engagement")
        top_layout = QVBoxLayout(top_box)

        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(6)
        self.cases_table.setHorizontalHeaderLabels(["ID", "Title", "Target Domain", "Objective", "Authorization Ref", "Status"])
        self.cases_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.cases_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cases_table.itemSelectionChanged.connect(self._on_case_selected)
        top_layout.addWidget(self.cases_table)

        splitter.addWidget(top_box)

        # Bottom: Create Case Form
        form_box = QGroupBox("Create New OSINT Investigation Case")
        form_layout = QVBoxLayout(form_box)

        row1 = QHBoxLayout()
        self.txt_case_title = QLineEdit()
        self.txt_case_title.setPlaceholderText("Case Title (e.g. Acme Corp Perimeter OSINT)")
        row1.addWidget(QLabel("Title:"))
        row1.addWidget(self.txt_case_title, 2)

        self.txt_case_domain = QLineEdit()
        self.txt_case_domain.setPlaceholderText("Target Domain (e.g. acme.com)")
        row1.addWidget(QLabel("Target Domain:"))
        row1.addWidget(self.txt_case_domain, 2)

        self.txt_case_auth = QLineEdit()
        self.txt_case_auth.setPlaceholderText("Authorization / SoW Ref (e.g. SOW-2026-001)")
        row1.addWidget(QLabel("Auth Ref:"))
        row1.addWidget(self.txt_case_auth, 2)
        form_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.txt_case_notes = QLineEdit()
        self.txt_case_notes.setPlaceholderText("Investigation Objectives and Analyst Notes...")
        row2.addWidget(QLabel("Notes:"))
        row2.addWidget(self.txt_case_notes, 3)

        self.btn_create_case = QPushButton("+ Create OSINT Case")
        self.btn_create_case.setProperty("class", "action-primary")
        self.btn_create_case.clicked.connect(self._on_create_case)
        row2.addWidget(self.btn_create_case)
        form_layout.addLayout(row2)

        splitter.addWidget(form_box)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)
        return widget

    # -----------------------------------------------------------------
    # Tab 2: Asset Discovery
    # -----------------------------------------------------------------
    def _create_discovery_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        ctrl_box = QGroupBox("Reconnaissance Controls")
        ctrl_layout = QVBoxLayout(ctrl_box)

        r1 = QHBoxLayout()
        lbl_engine = QLabel("Source Engine:")
        r1.addWidget(lbl_engine)
        self.combo_source = QComboBox()
        self.combo_source.addItem("Pure-Python Passive OSINT & Tech Profiler (Native)", "passive_recon")
        self.combo_source.addItem("Certificate Transparency & TLS (Passive)", "cert_transparency")
        self.combo_source.addItem("OWASP Amass (Subdomain & Netblock Mapping)", "amass")
        self.combo_source.addItem("theHarvester (Emails & Names)", "theharvester")
        self.combo_source.addItem("Recon-ng Framework", "recon_ng")
        r1.addWidget(self.combo_source, 2)

        lbl_target = QLabel("Target Domain:")
        r1.addWidget(lbl_target)
        self.txt_discovery_target = QLineEdit()
        self.txt_discovery_target.setPlaceholderText("Target Domain (e.g. example.com)")
        r1.addWidget(self.txt_discovery_target, 2)

        ctrl_layout.addLayout(r1)

        r2 = QHBoxLayout()
        self.radio_passive = QRadioButton("Passive Recon (Safe / Stealth)")
        self.radio_passive.setChecked(True)
        r2.addWidget(self.radio_passive)

        self.radio_active = QRadioButton("Active Recon (Requires RoE)")
        r2.addWidget(self.radio_active)

        r2.addStretch()

        self.btn_launch_discovery = QPushButton("🚀 Launch Discovery")
        self.btn_launch_discovery.setProperty("class", "action-primary")
        self.btn_launch_discovery.clicked.connect(self._on_launch_discovery)
        r2.addWidget(self.btn_launch_discovery)

        self.btn_cancel_discovery = QPushButton("⏹ Cancel")
        self.btn_cancel_discovery.setProperty("class", "action-secondary")
        self.btn_cancel_discovery.setEnabled(False)
        self.btn_cancel_discovery.clicked.connect(self._on_cancel_discovery)
        r2.addWidget(self.btn_cancel_discovery)

        ctrl_layout.addLayout(r2)
        layout.addWidget(ctrl_box)

        # Output Log Box
        self.discovery_log = QPlainTextEdit()
        self.discovery_log.setReadOnly(True)
        self.discovery_log.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_MONO}; font-size: 11px;")
        self.discovery_log.setPlaceholderText("Intelligence reconnaissance and discovery telemetry streams here in real-time...")
        layout.addWidget(self.discovery_log)

        return widget

    # -----------------------------------------------------------------
    # Tab 4: Asset Inventory & Scope Classification
    # -----------------------------------------------------------------
    def _create_inventory_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)

        bar = QHBoxLayout()
        self.lbl_inventory_summary = QLabel("Total Discovered Assets: 0")
        self.lbl_inventory_summary.setStyleSheet(f"font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE};")
        bar.addWidget(self.lbl_inventory_summary)
        bar.addStretch()

        self.btn_promote_to_scope = QPushButton("🎯 Authorize Selected in Project Scope")
        self.btn_promote_to_scope.clicked.connect(self._on_promote_to_scope)
        bar.addWidget(self.btn_promote_to_scope)

        self.btn_refresh_inventory = QPushButton("🔄 Refresh Inventory")
        self.btn_refresh_inventory.clicked.connect(self.load_assets)
        bar.addWidget(self.btn_refresh_inventory)

        layout.addLayout(bar)

        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(7)
        self.assets_table.setHorizontalHeaderLabels(["ID", "Type", "Asset Value", "Label", "Source Tool", "Confidence", "Scope Status"])
        self.assets_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.assets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.assets_table)

        return widget

    # -----------------------------------------------------------------
    # Tab 5: Observations & Evidence
    # -----------------------------------------------------------------
    def _create_observations_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Observations Table
        top = QWidget()
        t_layout = QVBoxLayout(top)
        t_layout.setContentsMargins(0, 0, 0, 0)

        t_bar = QHBoxLayout()
        t_label = QLabel("Correlated OSINT Observations (Distinct from Confirmed Vulnerabilities)")
        t_label.setStyleSheet("font-weight: bold; color: #f8fafc;")
        t_bar.addWidget(t_label)
        t_bar.addStretch()
        btn_refresh_obs = QPushButton("🔄 Refresh Observations")
        btn_refresh_obs.clicked.connect(self.load_observations)
        t_bar.addWidget(btn_refresh_obs)
        t_layout.addLayout(t_bar)

        self.observations_table = QTableWidget()
        self.observations_table.setColumnCount(6)
        self.observations_table.setHorizontalHeaderLabels(["ID", "Observation Title", "Source Tool", "Method", "Confidence", "Timestamp"])
        self.observations_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.observations_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.observations_table.itemSelectionChanged.connect(self._on_observation_selected)
        t_layout.addWidget(self.observations_table)
        splitter.addWidget(top)

        # Observation Raw Data
        bottom = QGroupBox("Observation Raw Data & Cryptographic Provenance")
        b_layout = QVBoxLayout(bottom)
        self.txt_observation_raw = QPlainTextEdit()
        self.txt_observation_raw.setReadOnly(True)
        self.txt_observation_raw.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_MONO}; font-size: 11px;")
        b_layout.addWidget(self.txt_observation_raw)
        splitter.addWidget(bottom)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)
        return widget

    # -----------------------------------------------------------------
    # Tab 6: Reports & Summary
    # -----------------------------------------------------------------
    def _create_reports_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        summary_box = QGroupBox("OSINT Intelligence Summary")
        s_layout = QVBoxLayout(summary_box)

        self.lbl_report_metrics = QLabel("Select an active engagement project to view metrics.")
        self.lbl_report_metrics.setStyleSheet("font-size: 13px; line-height: 1.6;")
        s_layout.addWidget(self.lbl_report_metrics)
        layout.addWidget(summary_box)

        action_box = QGroupBox("Export Intelligence & Graph Interoperability")
        a_layout = QHBoxLayout(action_box)

        btn_export_maltego_csv = QPushButton("Export Maltego CSV")
        btn_export_maltego_csv.clicked.connect(self._on_export_maltego_csv)
        a_layout.addWidget(btn_export_maltego_csv)

        btn_export_graphml = QPushButton("Export GraphML XML")
        btn_export_graphml.clicked.connect(self._on_export_graphml)
        a_layout.addWidget(btn_export_graphml)

        btn_export_json = QPushButton("Export OSINT JSON")
        btn_export_json.clicked.connect(self._on_export_json)
        a_layout.addWidget(btn_export_json)

        layout.addWidget(action_box)
        layout.addStretch()
        return widget

    # -----------------------------------------------------------------
    # Logic: Data Loaders
    # -----------------------------------------------------------------
    def load_cases(self):
        if not self.active_project:
            return
        cases = self.db.list_osint_cases(self.active_project.id)
        self.cases_table.setRowCount(len(cases))
        for row, c in enumerate(cases):
            self.cases_table.setItem(row, 0, QTableWidgetItem(str(c.id)))
            self.cases_table.setItem(row, 1, QTableWidgetItem(c.title))
            self.cases_table.setItem(row, 2, QTableWidgetItem(c.target_domain))
            self.cases_table.setItem(row, 3, QTableWidgetItem(c.objective))
            self.cases_table.setItem(row, 4, QTableWidgetItem(c.authorization_reference))
            self.cases_table.setItem(row, 5, QTableWidgetItem(c.status.upper()))

    def load_assets(self):
        if not self.active_project:
            return
        nodes = self.db.list_asset_nodes(self.active_project.id)
        scopes = self.db.list_scopes(self.active_project.id)
        self.assets_table.setRowCount(len(nodes))

        in_scope_count = 0
        quarantined_count = 0

        for row, n in enumerate(nodes):
            scope_res = ScopeAuthorizationService.is_target_authorized(n.value, scopes, self.active_project)
            status_text = "In-Scope" if scope_res.is_allowed else f"Quarantined ({scope_res.reason})"

            if scope_res.is_allowed:
                in_scope_count += 1
            else:
                quarantined_count += 1

            self.assets_table.setItem(row, 0, QTableWidgetItem(str(n.id)))
            self.assets_table.setItem(row, 1, QTableWidgetItem(n.node_type.upper()))
            self.assets_table.setItem(row, 2, QTableWidgetItem(n.value))
            self.assets_table.setItem(row, 3, QTableWidgetItem(n.label or n.value))
            self.assets_table.setItem(row, 4, QTableWidgetItem(n.source_tool or "OSINT"))
            self.assets_table.setItem(row, 5, QTableWidgetItem(f"{n.confidence * 100:.0f}%"))

            status_item = QTableWidgetItem(status_text)
            if not scope_res.is_allowed:
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.green)
            self.assets_table.setItem(row, 6, status_item)

        self.lbl_inventory_summary.setText(
            f"Total Discovered Assets: <b>{len(nodes)}</b> (Authorized: <b>{in_scope_count}</b>, Quarantined Out-of-Scope: <b>{quarantined_count}</b>)"
        )
        self._update_report_metrics(len(nodes), in_scope_count, quarantined_count)

    def load_observations(self):
        if not self.active_project:
            return
        obs_list = self.db.list_observations(self.active_project.id)
        self.observations_table.setRowCount(len(obs_list))
        for row, o in enumerate(obs_list):
            self.observations_table.setItem(row, 0, QTableWidgetItem(str(o.id)))
            self.observations_table.setItem(row, 1, QTableWidgetItem(o.title))
            self.observations_table.setItem(row, 2, QTableWidgetItem(o.source_tool))
            self.observations_table.setItem(row, 3, QTableWidgetItem(o.method))
            self.observations_table.setItem(row, 4, QTableWidgetItem(f"{o.confidence * 100:.0f}%"))
            self.observations_table.setItem(row, 5, QTableWidgetItem(o.created_at[:19].replace("T", " ")))

    def _update_report_metrics(self, total: int, in_scope: int, quarantined: int):
        if not self.active_project:
            return
        obs = self.db.list_observations(self.active_project.id)
        evidence = self.db.list_evidence(self.active_project.id)
        edges = self.db.list_asset_edges(self.active_project.id)

        self.lbl_report_metrics.setText(
            f"<b>Engagement:</b> {self.active_project.name}<br>"
            f"<b>Client:</b> {self.active_project.client_name or 'N/A'}<br><br>"
            f"• <b>Total Infrastructure Assets:</b> {total}<br>"
            f"• <b>Interconnected Relationship Edges:</b> {len(edges)}<br>"
            f"• <b>Authorized In-Scope Targets:</b> {in_scope}<br>"
            f"• <b>Quarantined Out-of-Scope Assets:</b> {quarantined}<br>"
            f"• <b>Intelligence Observations:</b> {len(obs)}<br>"
            f"• <b>Cryptographic Evidence Vault Files:</b> {len(evidence)}<br>"
        )

    # -----------------------------------------------------------------
    # Logic: Event Handlers & Workers
    # -----------------------------------------------------------------
    def _on_case_selected(self):
        row = self.cases_table.currentRow()
        if row < 0:
            return
        domain_item = self.cases_table.item(row, 2)
        if domain_item and domain_item.text():
            self.txt_discovery_target.setText(domain_item.text())

    def _on_create_case(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select an active assessment project first.")
            return

        title = self.txt_case_title.text().strip()
        domain = self.txt_case_domain.text().strip()
        auth = self.txt_case_auth.text().strip()
        notes = self.txt_case_notes.text().strip()

        if not title or not domain:
            QMessageBox.warning(self, "Validation Error", "Title and Target Domain are required.")
            return

        case = OSINTCase(
            project_id=self.active_project.id,
            title=title,
            target_domain=domain,
            authorization_reference=auth,
            analyst_notes=notes,
        )
        self.db.create_osint_case(case)
        self.txt_case_title.clear()
        self.txt_case_domain.clear()
        self.txt_case_auth.clear()
        self.txt_case_notes.clear()
        self.load_cases()
        self.txt_discovery_target.setText(domain)
        QMessageBox.information(self, "Case Created", f"OSINT Case '{title}' created successfully.")

    def _on_launch_discovery(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Select an active engagement project first.")
            return

        target = self.txt_discovery_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target domain.")
            return

        source_key = self.combo_source.currentData()
        adapter = self.adapters.get(source_key)
        if not adapter:
            QMessageBox.warning(self, "Unknown Source", f"Adapter '{source_key}' not found.")
            return

        if not adapter.is_available():
            QMessageBox.warning(
                self,
                "Tool Unavailable",
                f"{adapter.display_name} is not installed on this system.\n"
                "Please install the required binary or use Certificate Transparency (Native).",
            )
            return

        # Enforce Scope & Authorization Boundary check
        scopes = self.db.list_scopes(self.active_project.id)
        scope_res = ScopeAuthorizationService.is_target_authorized(target, scopes, self.active_project)
        if not scope_res.is_allowed:
            QMessageBox.critical(
                self,
                "Scope Authorization Blocked",
                f"Execution Boundary Rejected: '{target}' is not authorized!\nReason: {scope_res.reason}",
            )
            return

        passive_only = self.radio_passive.isChecked()
        if not passive_only and not self.active_project.allow_active_recon:
            QMessageBox.critical(
                self,
                "RoE Prohibited",
                "Active reconnaissance is prohibited by this engagement's Rules of Engagement.\n"
                "To permit active scanning, enable allow_active_recon in Project Scope.",
            )
            return

        self.btn_launch_discovery.setEnabled(False)
        self.btn_cancel_discovery.setEnabled(True)
        self.discovery_log.clear()

        # Execute discovery in worker thread
        def run_task():
            try:
                res = adapter.run_discovery(
                    target_domain=target,
                    project=self.active_project,
                    scopes=scopes,
                    passive_only=passive_only,
                    on_output=lambda msg, st: self.signals.output_received.emit(msg, st),
                )
                self.signals.discovery_finished.emit(res)
            except Exception as exc:
                err_res = OSINTDiscoveryResult(
                    source_tool=source_key,
                    target=target,
                    status="failed",
                    error_message=f"Unhandled discovery failure in {source_key}: {str(exc)}",
                )
                self.signals.output_received.emit(f"\n[-] Critical error during OSINT discovery: {exc}\n", "stderr")
                self.signals.discovery_finished.emit(err_res)

        self._active_thread = threading.Thread(target=run_task, daemon=True)
        self._active_thread.start()

    def _on_cancel_discovery(self):
        source_key = self.combo_source.currentData()
        adapter = self.adapters.get(source_key)
        if hasattr(adapter, "cancel"):
            adapter.cancel()
        self.discovery_log.appendPlainText("\n[!] Cancellation requested by user.\n")
        self.btn_cancel_discovery.setEnabled(False)

    @Slot(str, str)
    def _on_output_received(self, text: str, stream: str):
        self.discovery_log.moveCursor(self.discovery_log.textCursor().MoveOperation.End)
        self.discovery_log.insertPlainText(text)
        self.discovery_log.moveCursor(self.discovery_log.textCursor().MoveOperation.End)

    @Slot(object)
    def _on_discovery_finished(self, result: OSINTDiscoveryResult):
        self.btn_launch_discovery.setEnabled(True)
        self.btn_cancel_discovery.setEnabled(False)

        # Refresh all tabs
        self.load_assets()
        self.load_observations()
        self.graph_view.load_graph()
        self.project_data_updated.emit()

        if result.status == "completed":
            QMessageBox.information(
                self,
                "Discovery Completed",
                f"Reconnaissance completed.\nDiscovered {len(result.discovered_assets)} assets and {len(result.observations)} observations.",
            )
        elif result.status == "scope_rejected":
            QMessageBox.warning(self, "Scope Rejection", f"Discovery halted: {result.error_message}")
        elif result.status == "failed":
            QMessageBox.critical(self, "Discovery Failed", f"Execution error: {result.error_message}")

    def _on_observation_selected(self):
        row = self.observations_table.currentRow()
        if row < 0 or not self.active_project:
            return
        obs_id_item = self.observations_table.item(row, 0)
        if not obs_id_item:
            return
        obs_id = int(obs_id_item.text())
        observations = self.db.list_observations(self.active_project.id)
        for o in observations:
            if o.id == obs_id:
                self.txt_observation_raw.setPlainText(
                    f"Title: {o.title}\n"
                    f"Tool: {o.source_tool}\n"
                    f"Method: {o.method}\n"
                    f"Confidence: {o.confidence * 100:.1f}%\n"
                    f"Verification Status: {o.verification_status}\n"
                    f"Timestamp: {o.created_at}\n\n"
                    f"--- RAW DATA ---\n{o.raw_data}"
                )
                break

    def _on_promote_to_scope(self):
        """Promotes selected discovered subdomain into authorized TargetScope."""
        if not self.active_project:
            return
        row = self.assets_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select an asset row to authorize.")
            return

        val_item = self.assets_table.item(row, 2)
        if not val_item:
            return
        target_val = val_item.text().strip()

        # Add scope rule
        scope = TargetScope(
            project_id=self.active_project.id,
            target=target_val,
            target_type=TargetType.HOSTNAME if "." in target_val else TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
            notes="Promoted from OSINT asset discovery",
        )
        self.db.add_scope(scope)
        self.load_assets()
        self.project_data_updated.emit()
        QMessageBox.information(self, "Scope Updated", f"Target '{target_val}' added to authorized project scope.")

    def _on_export_maltego_csv(self):
        if not self.active_project:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Maltego CSV", f"osint_{self.active_project.name}.csv", "CSV Files (*.csv)")
        if path:
            engine = MaltegoGraphEngine(self.db)
            data = engine.export_csv(self.active_project.id)
            Path(path).write_text(data, encoding="utf-8")
            QMessageBox.information(self, "Export Success", f"Maltego CSV exported to:\n{path}")

    def _on_export_graphml(self):
        if not self.active_project:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export GraphML", f"osint_{self.active_project.name}.graphml", "GraphML XML (*.graphml)")
        if path:
            engine = MaltegoGraphEngine(self.db)
            data = engine.export_graphml(self.active_project.id)
            Path(path).write_text(data, encoding="utf-8")
            QMessageBox.information(self, "Export Success", f"GraphML exported to:\n{path}")

    def _on_export_json(self):
        if not self.active_project:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export OSINT JSON", f"osint_{self.active_project.name}.json", "JSON Files (*.json)")
        if path:
            engine = MaltegoGraphEngine(self.db)
            data = engine.export_json(self.active_project.id)
            Path(path).write_text(data, encoding="utf-8")
            QMessageBox.information(self, "Export Success", f"OSINT JSON exported to:\n{path}")

