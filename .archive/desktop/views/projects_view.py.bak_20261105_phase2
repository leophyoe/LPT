"""Penetration Testing Scoping & Engagement Management Workspace.

Provides:
1. Engagement Lifecycle & RoE Management (Legal Authority, Testing Windows, Prohibited Tests).
2. Advanced Scope Boundaries (In-Scope vs. Explicit Exclusions, CIDRs, Ports, Conflict Detection).
3. Integrated OWASP Amass OSINT Reconnaissance (Passive by default, Scope Quarantine).
4. Attack Surface Relationship Graph with Maltego CSV/GraphML interoperability.
5. Immutable Engagement Audit Logging.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.preflight import PreflightChecker, VerificationCheckStatus
from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme
from desktop.widgets.attack_graph_view import AttackGraphView
from modules.network.amass_adapter import AmassAdapter, AmassOptions
from reports.cpent_engagement_pack import CPENTEngagementPackGenerator
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentPlan,
    AssessmentStatus,
    EngagementAuditLog,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    TestCategory,
)


class NewProjectDialog(QDialog):
    """Dialog for creating or editing a penetration testing engagement."""

    def __init__(self, project: Optional[Project] = None, parent=None):
        super().__init__(parent)
        self.project = project
        self.setWindowTitle(
            "Edit Project Details" if project else "Create New Penetration Testing Engagement"
        )
        self.setMinimumWidth(520)
        self._init_ui()

    def _init_ui(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        project = self.project
        self.name_input = QLineEdit(project.name if project else "")
        self.name_input.setPlaceholderText("e.g. Q4 Financial Portal External Pentest")
        layout.addRow("Engagement Name *:", self.name_input)

        self.client_input = QLineEdit(project.client_name if project else "")
        self.client_input.setPlaceholderText("e.g. BankCorp Global Holdings")
        layout.addRow("Client / Target Lab:", self.client_input)

        self.eng_id_input = QLineEdit(project.engagement_id if project else "")
        self.eng_id_input.setPlaceholderText(f"ENG-{datetime.now().strftime('%Y%m')}-001")
        layout.addRow("Engagement ID:", self.eng_id_input)

        self.sow_input = QLineEdit(project.sow_reference if project else "")
        self.sow_input.setPlaceholderText("e.g. SOW-2026-BC-092 / PO-88412")
        layout.addRow("SoW / Auth Reference:", self.sow_input)

        self.lead_input = QLineEdit(project.lead_tester if project else "")
        self.lead_input.setPlaceholderText("e.g. Senior Pentester / Team Alpha")
        layout.addRow("Lead Tester / Owner:", self.lead_input)

        self.emergency_input = QLineEdit(project.emergency_contact if project else "")
        self.emergency_input.setPlaceholderText("e.g. SOC Hot-line: +1-555-0199 / CISO: ciso@client.corp")
        layout.addRow("Emergency Stop Contact:", self.emergency_input)

        dates_row = QHBoxLayout()
        self.start_date_input = QLineEdit(project.start_date if project else "")
        self.start_date_input.setPlaceholderText("YYYY-MM-DD (e.g. 2026-10-22)")
        dates_row.addWidget(self.start_date_input)
        dates_row.addWidget(QLabel("to"))
        self.end_date_input = QLineEdit(project.end_date if project else "")
        self.end_date_input.setPlaceholderText("YYYY-MM-DD (e.g. 2026-11-05)")
        dates_row.addWidget(self.end_date_input)
        layout.addRow("Testing Date Window:", dates_row)

        self.desc_input = QTextEdit()
        if project:
            self.desc_input.setText(project.description)
        self.desc_input.setPlaceholderText("Engagement objectives, special constraints, rules of engagement...")
        self.desc_input.setMaximumHeight(70)
        layout.addRow("Objectives & RoE:", self.desc_input)

        buttons = QHBoxLayout()
        buttons.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-secondary")
        self.cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Save Changes" if project else "Create Engagement")
        self.save_btn.setProperty("class", "action-primary")
        self.save_btn.clicked.connect(self._validate_and_accept)
        buttons.addWidget(self.save_btn)

        layout.addRow(buttons)

    def _validate_and_accept(self):
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Engagement name is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name": self.name_input.text().strip(),
            "client_name": self.client_input.text().strip(),
            "engagement_id": self.eng_id_input.text().strip(),
            "sow_reference": self.sow_input.text().strip(),
            "lead_tester": self.lead_input.text().strip(),
            "emergency_contact": self.emergency_input.text().strip(),
            "start_date": self.start_date_input.text().strip(),
            "end_date": self.end_date_input.text().strip(),
            "description": self.desc_input.toPlainText().strip(),
        }


class EditRoEDialog(QDialog):
    """Dialog for editing Rules of Engagement, Testing Hours, and Prohibited Techniques."""

    def __init__(self, project: Project, parent=None):
        super().__init__(parent)
        self.project = project
        self.setWindowTitle(f"Rules of Engagement — {project.name}")
        self.setMinimumWidth(560)
        self._init_ui()

    def _init_ui(self):
        layout = QFormLayout(self)
        layout.setSpacing(10)

        # Status Lifecycle
        self.status_combo = QComboBox()
        for st in ProjectStatus:
            self.status_combo.addItem(f"◉ {st.value.replace('_', ' ').title()}", st.value)
        idx = self.status_combo.findData(self.project.status.value)
        if idx >= 0:
            self.status_combo.setCurrentIndex(idx)
        layout.addRow("Lifecycle State:", self.status_combo)

        # Hours & Timezone
        time_row = QHBoxLayout()
        self.hours_input = QLineEdit(self.project.allowed_hours)
        self.hours_input.setPlaceholderText("e.g. 09:00-18:00 (blank for 24/7)")
        time_row.addWidget(self.hours_input)
        self.tz_input = QLineEdit(self.project.timezone or "UTC")
        self.tz_input.setMaximumWidth(90)
        time_row.addWidget(self.tz_input)
        layout.addRow("Allowed Hours & TZ:", time_row)

        # Rate Limit
        self.rate_input = QLineEdit(str(self.project.max_rate_limit or 100))
        layout.addRow("Max Rate Limit (req/sec):", self.rate_input)

        # Active Recon Flag
        self.active_recon_combo = QComboBox()
        self.active_recon_combo.addItem("Passive Recon Only (Default / Safe)", False)
        self.active_recon_combo.addItem("Active Recon Authorized (Brute-force DNS permitted)", True)
        self.active_recon_combo.setCurrentIndex(1 if self.project.allow_active_recon else 0)
        layout.addRow("Active Reconnaissance:", self.active_recon_combo)

        # Prohibited Tests
        self.prohibited_input = QTextEdit()
        self.prohibited_input.setText(self.project.prohibited_tests or "DoS/DDoS, Social Engineering, Physical Intrusion, Account Lockout Brute Force")
        self.prohibited_input.setMaximumHeight(70)
        layout.addRow("Prohibited Techniques:", self.prohibited_input)

        # Emergency Contact
        self.emergency_input = QLineEdit(self.project.emergency_contact)
        layout.addRow("Emergency Stop Hot-line:", self.emergency_input)

        buttons = QHBoxLayout()
        buttons.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)

        save_btn = QPushButton("Save RoE Settings")
        save_btn.setProperty("class", "action-primary")
        save_btn.clicked.connect(self.accept)
        buttons.addWidget(save_btn)

        layout.addRow(buttons)

    def apply_to_project(self, project: Project):
        project.status = ProjectStatus(self.status_combo.currentData())
        project.allowed_hours = self.hours_input.text().strip()
        project.timezone = self.tz_input.text().strip() or "UTC"
        try:
            project.max_rate_limit = int(self.rate_input.text().strip())
        except ValueError:
            project.max_rate_limit = 100
        project.allow_active_recon = bool(self.active_recon_combo.currentData())
        project.prohibited_tests = self.prohibited_input.toPlainText().strip()
        project.emergency_contact = self.emergency_input.text().strip()


class NewAssessmentPlanDialog(QDialog):
    """Dialog for creating an authorized assessment test plan."""

    def __init__(self, target_options: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Assessment Test Plan")
        self.setMinimumWidth(480)

        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("e.g. Core Network Service Discovery & Version Audit")
        layout.addRow("Test Plan Title *:", self.title_input)

        self.category_combo = QComboBox()
        self.category_combo.addItem("🌐 Network Discovery", TestCategory.NETWORK_DISCOVERY.value)
        self.category_combo.addItem("🏢 Active Directory & Kerberos", TestCategory.ACTIVE_DIRECTORY.value)
        self.category_combo.addItem("⚡ Privilege Escalation", TestCategory.PRIVILEGE_ESCALATION.value)
        self.category_combo.addItem("🛡️ Web Application & API", TestCategory.WEB_APPLICATION.value)
        self.category_combo.addItem("⚙️ Binary Challenge Inspection", TestCategory.BINARY_EXPLOITATION.value)
        layout.addRow("Test Category:", self.category_combo)

        self.target_combo = QComboBox()
        if target_options:
            for t in target_options:
                self.target_combo.addItem(t, t)
        else:
            self.target_combo.addItem("127.0.0.1", "127.0.0.1")
        self.target_combo.setEditable(True)
        layout.addRow("Target Specification *:", self.target_combo)

        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Assessment scope and technical objectives...")
        self.desc_input.setMaximumHeight(70)
        layout.addRow("Description:", self.desc_input)

        self.criteria_input = QTextEdit()
        self.criteria_input.setPlaceholderText("Define pass/fail acceptance criteria (e.g. Zero unauthenticated RCE; Service banners verified).")
        self.criteria_input.setMaximumHeight(80)
        layout.addRow("Acceptance Criteria *:", self.criteria_input)

        btn_box = QHBoxLayout()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("Create Plan")
        btn_ok.setProperty("class", "action-primary")
        btn_ok.clicked.connect(self._validate_and_accept)

        btn_box.addStretch()
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_ok)
        layout.addRow(btn_box)

    def _validate_and_accept(self):
        if not self.title_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Test plan title is required.")
            return
        if not self.target_combo.currentText().strip():
            QMessageBox.warning(self, "Validation Error", "Target specification is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "title": self.title_input.text().strip(),
            "test_category": TestCategory(self.category_combo.currentData()),
            "target": self.target_combo.currentText().strip(),
            "description": self.desc_input.toPlainText().strip(),
            "acceptance_criteria": self.criteria_input.toPlainText().strip(),
        }


class AssessmentDialog(QDialog):
    """Dialog for creating or editing an Assessment (Phase 7)."""

    def __init__(self, target_options: list[str], assessment: Optional[Assessment] = None, parent=None):
        super().__init__(parent)
        self.assessment = assessment
        self.setWindowTitle("Edit Assessment" if assessment else "New Assessment")
        self.setMinimumWidth(520)

        layout = QFormLayout(self)
        layout.setSpacing(10)

        self.name_input = QLineEdit(assessment.name if assessment else "")
        self.name_input.setPlaceholderText("e.g. Q4 External Network Penetration Test")
        layout.addRow("Assessment Name *:", self.name_input)

        self.status_combo = QComboBox()
        statuses = [
            ("Planned", AssessmentStatus.PLANNED),
            ("In Progress", AssessmentStatus.IN_PROGRESS),
            ("Paused", AssessmentStatus.PAUSED),
            ("Completed", AssessmentStatus.COMPLETED),
            ("Archived", AssessmentStatus.ARCHIVED),
        ]
        for label, val in statuses:
            self.status_combo.addItem(label, val)
        if assessment:
            idx = self.status_combo.findData(assessment.status)
            if idx >= 0:
                self.status_combo.setCurrentIndex(idx)
        layout.addRow("Status:", self.status_combo)

        self.scope_combo = QComboBox()
        if target_options:
            for t in target_options:
                self.scope_combo.addItem(t, t)
        else:
            self.scope_combo.addItem("All In-Scope Targets", "All In-Scope Targets")
        self.scope_combo.setEditable(True)
        if assessment and assessment.authorized_scope:
            self.scope_combo.setEditText(assessment.authorized_scope)
        layout.addRow("Authorized Scope *:", self.scope_combo)

        date_row = QHBoxLayout()
        now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.start_date_input = QLineEdit(assessment.start_date if assessment and assessment.start_date else now_date)
        self.start_date_input.setPlaceholderText("YYYY-MM-DD")
        self.end_date_input = QLineEdit(assessment.end_date if assessment and assessment.end_date else "")
        self.end_date_input.setPlaceholderText("YYYY-MM-DD (optional)")
        date_row.addWidget(QLabel("Start:"))
        date_row.addWidget(self.start_date_input)
        date_row.addWidget(QLabel("End:"))
        date_row.addWidget(self.end_date_input)
        layout.addRow("Timeline:", date_row)

        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Assessment goals, rules, and technical objectives...")
        self.desc_input.setText(assessment.description if assessment else "")
        self.desc_input.setMaximumHeight(70)
        layout.addRow("Description:", self.desc_input)

        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Internal tester notes, methodology reminders...")
        self.notes_input.setText(assessment.notes if assessment else "")
        self.notes_input.setMaximumHeight(70)
        layout.addRow("Notes:", self.notes_input)

        btn_box = QHBoxLayout()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("Save Assessment" if assessment else "Create Assessment")
        btn_ok.setProperty("class", "action-primary")
        btn_ok.clicked.connect(self._validate_and_accept)

        btn_box.addStretch()
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_ok)
        layout.addRow(btn_box)

    def _validate_and_accept(self):
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Assessment name is required.")
            return
        if not self.scope_combo.currentText().strip():
            QMessageBox.warning(self, "Validation Error", "Authorized scope is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name": self.name_input.text().strip(),
            "status": self.status_combo.currentData(),
            "authorized_scope": self.scope_combo.currentText().strip(),
            "start_date": self.start_date_input.text().strip(),
            "end_date": self.end_date_input.text().strip(),
            "description": self.desc_input.toPlainText().strip(),
            "notes": self.notes_input.toPlainText().strip(),
        }


class ProjectsView(QWidget):
    """Main view for project selection, scope configuration, and engagement operations."""

    project_selected = Signal(Project)
    scope_updated = Signal(int)

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self._amass_thread: Optional[threading.Thread] = None

        self._init_ui()
        self.load_projects()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(14, 14, 14, 14)
        root_layout.setSpacing(10)

        # Top Bar: Row 1 = Title & Status Badge
        header_bar = QHBoxLayout()
        header = QLabel("◈  Penetration Testing Engagements & Scoping")
        header.setObjectName("viewHeader")
        header.setStyleSheet("font-size: 18px; font-weight: 700; color: #f8fafc;")
        header.setWordWrap(True)
        header_bar.addWidget(header, 1)

        self.lbl_status_badge = QLabel("[No Active Engagement]")
        self.lbl_status_badge.setObjectName("viewSubtitle")
        self.lbl_status_badge.setStyleSheet(
            "background-color: #0f172a; color: #94a3b8; border: 1px solid #1e293b; border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px; margin-right: 8px;"
        )
        header_bar.addWidget(self.lbl_status_badge, 0)
        root_layout.addLayout(header_bar)

        # Action Buttons Toolbar in a horizontal scroll area for responsive fitting
        actions_scroll = QScrollArea()
        actions_scroll.setWidgetResizable(True)
        actions_scroll.setFixedHeight(46)
        actions_scroll.setFrameShape(QFrame.NoFrame)
        actions_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        actions_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        actions_widget = QWidget()
        top_bar = QHBoxLayout(actions_widget)
        top_bar.setContentsMargins(0, 0, 0, 0)
        top_bar.setSpacing(8)

        self.new_proj_btn = QPushButton("+ New Engagement")
        self.new_proj_btn.setProperty("class", "action-primary")
        self.new_proj_btn.setFixedHeight(30)
        self.new_proj_btn.clicked.connect(self._on_new_project)
        top_bar.addWidget(self.new_proj_btn)

        self.btn_edit_project = QPushButton("Edit Project")
        self.btn_edit_project.setProperty("class", "action-secondary")
        self.btn_edit_project.setFixedHeight(30)
        self.btn_edit_project.setEnabled(False)
        self.btn_edit_project.clicked.connect(self._on_edit_project)
        top_bar.addWidget(self.btn_edit_project)

        self.btn_edit_roe = QPushButton("📋 Edit RoE & State")
        self.btn_edit_roe.setProperty("class", "action-secondary")
        self.btn_edit_roe.setFixedHeight(30)
        self.btn_edit_roe.clicked.connect(self._on_edit_roe)
        top_bar.addWidget(self.btn_edit_roe)

        self.btn_export_cpent = QPushButton("📦 Export CPENT Pack")
        self.btn_export_cpent.setProperty("class", "action-secondary")
        self.btn_export_cpent.setFixedHeight(30)
        self.btn_export_cpent.clicked.connect(self._on_export_cpent_pack)
        top_bar.addWidget(self.btn_export_cpent)

        self.btn_archive_project = QPushButton("Archive Project")
        self.btn_archive_project.setProperty("class", "action-secondary")
        self.btn_archive_project.setFixedHeight(30)
        self.btn_archive_project.setEnabled(False)
        self.btn_archive_project.setToolTip(
            "Stop new authorized scans while retaining project records and evidence metadata"
        )
        self.btn_archive_project.clicked.connect(self._on_archive_project)
        top_bar.addWidget(self.btn_archive_project)
        top_bar.addStretch()

        actions_scroll.setWidget(actions_widget)
        root_layout.addWidget(actions_scroll)

        splitter = QSplitter(Qt.Vertical)

        # 1. Projects / Engagements Table
        eng_widget = QWidget()
        eng_layout = QVBoxLayout(eng_widget)
        eng_layout.setContentsMargins(0, 0, 0, 0)
        eng_layout.setSpacing(6)

        tbl_hdr = QLabel("Engagements Inventory")
        tbl_hdr.setStyleSheet("font-size: 12px; font-weight: bold; color: #94a3b8;")
        eng_layout.addWidget(tbl_hdr)

        self.projects_table = QTableWidget()
        self.projects_table.setColumnCount(6)
        self.projects_table.setHorizontalHeaderLabels(["ID", "Engagement Name", "Client / Lab", "Ref ID", "Status", "Dates Window"])
        proj_hdr = self.projects_table.horizontalHeader()
        proj_hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        proj_hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        proj_hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        proj_hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        proj_hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        proj_hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.projects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.projects_table.itemSelectionChanged.connect(self._on_project_selection_changed)
        eng_layout.addWidget(self.projects_table)

        splitter.addWidget(eng_widget)

        # 2. Tabbed Workspace
        self.tabs = QTabWidget()

        # Tab 1: Scope Boundaries & Exclusions
        scope_widget = QWidget()
        scope_layout = QVBoxLayout(scope_widget)
        scope_layout.setContentsMargins(8, 8, 8, 8)
        scope_layout.setSpacing(8)

        # Conflict Banner
        self.conflict_banner = QLabel()
        self.conflict_banner.setStyleSheet(
            f"background-color: #3D1014; color: {CPENTTheme.ERROR_RED}; border: 1px solid {CPENTTheme.RED_ACCENT}; "
            "padding: 6px 12px; border-radius: 4px; font-weight: bold;"
        )
        self.conflict_banner.setVisible(False)
        scope_layout.addWidget(self.conflict_banner)

        # Input Row
        input_bar = QHBoxLayout()
        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("Target IP, CIDR subnet, domain, or host (e.g. 10.0.0.0/24, *.corp.com, 10.0.0.50)")
        input_bar.addWidget(self.scope_input, 3)

        self.combo_scope_type = QComboBox()
        for tt in TargetType:
            self.combo_scope_type.addItem(tt.value.replace("_", " ").title(), tt.value)
        input_bar.addWidget(self.combo_scope_type, 1)

        self.combo_rule_type = QComboBox()
        self.combo_rule_type.addItem("Allowed (In-Scope)", ScopeRuleType.ALLOWED.value)
        self.combo_rule_type.addItem("EXCLUDED (Out-of-Scope)", ScopeRuleType.EXCLUDED.value)
        input_bar.addWidget(self.combo_rule_type, 1)

        self.env_combo = QComboBox()
        self.env_combo.addItems(["Production", "Staging", "Development"])
        input_bar.addWidget(self.env_combo)

        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Ports (e.g. 80,443)")
        self.ports_input.setMaximumWidth(110)
        input_bar.addWidget(self.ports_input)

        self.add_scope_btn = QPushButton("+ Add Scope Rule")
        self.add_scope_btn.setProperty("class", "action-primary")
        self.add_scope_btn.clicked.connect(self._on_add_scope)
        input_bar.addWidget(self.add_scope_btn)

        scope_layout.addLayout(input_bar)

        # Scopes Table
        self.scopes_table = QTableWidget()
        self.scopes_table.setColumnCount(7)
        self.scopes_table.setHorizontalHeaderLabels(["ID", "Target", "Type", "Rule Type", "Env", "Ports", "Status / Action"])
        scope_hdr = self.scopes_table.horizontalHeader()
        scope_hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        scope_hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        scope_hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        scope_hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        scope_hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        scope_hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        scope_hdr.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        scope_layout.addWidget(self.scopes_table)

        self.tabs.addTab(scope_widget, "🎯 Scope Boundaries & Exclusions")

        # Tab 2: OWASP Amass OSINT Reconnaissance
        amass_widget = QWidget()
        amass_layout = QVBoxLayout(amass_widget)
        amass_layout.setContentsMargins(8, 8, 8, 8)
        amass_layout.setSpacing(8)

        amass_ctrl = QHBoxLayout()
        self.amass_domain_input = QLineEdit()
        self.amass_domain_input.setPlaceholderText("Target Domain for OSINT Enumeration (e.g. example.com)")
        amass_ctrl.addWidget(self.amass_domain_input, 2)

        self.radio_passive = QRadioButton("Passive OSINT (Safe / Stealth)")
        self.radio_passive.setChecked(True)
        amass_ctrl.addWidget(self.radio_passive)

        self.radio_active = QRadioButton("Active Recon (Brute-Force)")
        amass_ctrl.addWidget(self.radio_active)

        self.btn_run_amass = QPushButton("🚀 Run OWASP Amass")
        self.btn_run_amass.setProperty("class", "action-primary")
        self.btn_run_amass.clicked.connect(self._on_run_amass)
        amass_ctrl.addWidget(self.btn_run_amass)

        amass_layout.addLayout(amass_ctrl)

        self.amass_log = QPlainTextEdit()
        self.amass_log.setReadOnly(True)
        self.amass_log.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_MONO};")
        self.amass_log.setPlaceholderText("OWASP Amass real-time execution logs and discovery telemetry will stream here...")
        amass_layout.addWidget(self.amass_log)

        self.tabs.addTab(amass_widget, "🌐 OWASP Amass OSINT")

        # Tab 3: Attack Surface Relationship Graph (Maltego)
        self.graph_view = AttackGraphView(self.db)
        self.tabs.addTab(self.graph_view, "🕸️ Attack Surface Graph (Maltego)")

        # Tab 4: RoE Details & Audit Log
        audit_widget = QWidget()
        audit_layout = QVBoxLayout(audit_widget)
        audit_layout.setContentsMargins(8, 8, 8, 8)

        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(4)
        self.audit_table.setHorizontalHeaderLabels(["Timestamp", "Actor", "Action", "Details"])
        self.audit_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        audit_layout.addWidget(self.audit_table)

        self.tabs.addTab(audit_widget, "📜 RoE & Audit Trail")

        # Tab 5: Assessments
        self.tab_plans = self._create_assessment_plans_tab()
        self.tabs.addTab(self.tab_plans, "📋 Assessments")

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([150, 250])

        root_layout.addWidget(splitter)

    def load_projects(self):
        projects = self.db.list_projects()
        self.projects_table.setRowCount(len(projects))
        for row, p in enumerate(projects):
            self.projects_table.setItem(row, 0, QTableWidgetItem(str(p.id)))
            self.projects_table.setItem(row, 1, QTableWidgetItem(p.name))
            self.projects_table.setItem(row, 2, QTableWidgetItem(p.client_name or "N/A"))
            self.projects_table.setItem(row, 3, QTableWidgetItem(p.engagement_id or f"ENG-{p.id}"))

            # Status with color
            status_item = QTableWidgetItem(p.status.value.replace("_", " ").title())
            if p.status == ProjectStatus.ACTIVE:
                status_item.setForeground(QColor(CPENTTheme.SUCCESS_GREEN))
            elif p.status == ProjectStatus.PAUSED:
                status_item.setForeground(QColor(CPENTTheme.AMBER_ACCENT))
            else:
                status_item.setForeground(QColor(CPENTTheme.SECONDARY_TEXT))
            self.projects_table.setItem(row, 4, status_item)

            date_str = f"{p.start_date or 'Any'} → {p.end_date or 'Any'}"
            self.projects_table.setItem(row, 5, QTableWidgetItem(date_str))

        if projects and self.active_project is None:
            self.projects_table.selectRow(0)

    def _on_new_project(self):
        dialog = NewProjectDialog(parent=self)
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            project = Project(
                name=data["name"],
                client_name=data["client_name"],
                description=data["description"],
                engagement_id=data["engagement_id"],
                sow_reference=data["sow_reference"],
                lead_tester=data["lead_tester"],
                emergency_contact=data["emergency_contact"],
                start_date=data["start_date"],
                end_date=data["end_date"],
                status=ProjectStatus.ACTIVE,
            )
            try:
                created = self.db.create_project(project)
            except sqlite3.IntegrityError as exc:
                QMessageBox.warning(
                    self,
                    "Could Not Create Project",
                    f"A project with this name already exists.\n\n{exc}",
                )
                return
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=created.id,
                    actor="security_lead",
                    action="engagement_created",
                    details=f"Engagement '{created.name}' initialized in Active status.",
                )
            )
            self.load_projects()
            self.select_project_by_id(created.id)

    def _on_edit_project(self):
        if not self.active_project or self.active_project.id is None:
            QMessageBox.warning(self, "No Project Selected", "Select a project before editing its details.")
            return

        dialog = NewProjectDialog(self.active_project, self)
        if dialog.exec() != QDialog.Accepted:
            return

        data = dialog.get_data()
        project = self.active_project
        project.name = data["name"]
        project.client_name = data["client_name"]
        project.engagement_id = data["engagement_id"]
        project.sow_reference = data["sow_reference"]
        project.lead_tester = data["lead_tester"]
        project.emergency_contact = data["emergency_contact"]
        project.start_date = data["start_date"]
        project.end_date = data["end_date"]
        project.description = data["description"]
        project.updated_at = datetime.now(timezone.utc).isoformat()

        try:
            saved = self.db.update_project(project)
        except sqlite3.IntegrityError as exc:
            QMessageBox.warning(
                self,
                "Could Not Save Project",
                f"Another project already uses this name.\n\n{exc}",
            )
            return
        if not saved:
            QMessageBox.critical(self, "Save Failed", "The project no longer exists in the database.")
            return

        self.db.add_audit_log(
            EngagementAuditLog(
                project_id=project.id,
                actor="security_lead",
                action="project_details_updated",
                details=f"Project details saved for '{project.name}'.",
            )
        )
        self.load_projects()
        self.select_project_by_id(project.id)

    def _on_archive_project(self):
        project = self.active_project
        if not project or project.id is None:
            QMessageBox.warning(self, "No Project Selected", "Select a project before archiving it.")
            return
        if project.status == ProjectStatus.ARCHIVED:
            return

        confirmation = QMessageBox.question(
            self,
            "Archive Project",
            f"Archive '{project.name}'?\n\n"
            "This preserves project data and evidence records, but blocks new authorized scans. "
            "You can restore it later from Edit RoE & State.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        project.status = ProjectStatus.ARCHIVED
        project.updated_at = datetime.now(timezone.utc).isoformat()
        if not self.db.update_project(project):
            QMessageBox.critical(self, "Archive Failed", "The project could not be updated in the database.")
            return

        self.db.add_audit_log(
            EngagementAuditLog(
                project_id=project.id,
                actor="security_lead",
                action="project_archived",
                details=f"Project '{project.name}' archived; existing records retained.",
            )
        )
        self.load_projects()
        self.select_project_by_id(project.id)

    def select_project_by_id(self, project_id: int):
        for row in range(self.projects_table.rowCount()):
            if int(self.projects_table.item(row, 0).text()) == project_id:
                self.projects_table.selectRow(row)
                self._on_project_selection_changed()
                break

    def _on_project_selection_changed(self):
        selected_rows = self.projects_table.selectedItems()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        project_id = int(self.projects_table.item(row, 0).text())
        project = self.db.get_project(project_id)
        if project:
            self.active_project = project
            self.btn_edit_project.setEnabled(True)
            self.btn_archive_project.setEnabled(project.status != ProjectStatus.ARCHIVED)
            self.btn_archive_project.setText(
                "Project Archived" if project.status == ProjectStatus.ARCHIVED else "Archive Project"
            )
            self.project_selected.emit(project)
            self._update_status_header(project)
            self.load_scopes(project.id)
            self.graph_view.set_active_project(project)
            self.load_audit_logs(project.id)
            self.load_assessment_plans(project.id)

    def _update_status_header(self, p: Project):
        is_active = p.status == ProjectStatus.ACTIVE
        bg = "#064e3b" if is_active else "#251c05" if p.status == ProjectStatus.PAUSED else "#1e293b"
        fg = "#10b981" if is_active else "#f59e0b" if p.status == ProjectStatus.PAUSED else "#94a3b8"
        border = "#059669" if is_active else "#b45309" if p.status == ProjectStatus.PAUSED else "#334155"
        self.lbl_status_badge.setText(f"● [{p.status.value.replace('_', ' ').upper()}] {p.name}")
        self.lbl_status_badge.setStyleSheet(
            f"background-color: {bg}; color: {fg}; border: 1px solid {border}; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px; margin-right: 8px;"
        )

    def _on_edit_roe(self):
        if not self.active_project:
            return
        dlg = EditRoEDialog(self.active_project, self)
        if dlg.exec() == QDialog.Accepted:
            dlg.apply_to_project(self.active_project)
            self.active_project.updated_at = datetime.now(timezone.utc).isoformat()
            self.db.update_project(self.active_project)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="roe_updated",
                    details=f"Status set to {self.active_project.status.value}, Rate Limit: {self.active_project.max_rate_limit} req/s",
                )
            )
            self.load_projects()
            self._update_status_header(self.active_project)
            self.load_audit_logs(self.active_project.id)

    def _on_export_cpent_pack(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Engagement Selected", "Please select an active engagement from the inventory to export.")
            return

        out_dir = Path.home() / "Desktop" / "cpent_engagements"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            generator = CPENTEngagementPackGenerator(self.db)
            files = generator.generate_pack(self.active_project.id, out_dir)
            root_dir = files["root_readme"].parent
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="cpent_pack_exported",
                    details=f"Exported CPENT Master Engagement Folder to {root_dir}",
                )
            )
            self.load_audit_logs(self.active_project.id)
            QMessageBox.information(
                self,
                "CPENT Pack Exported Successfully",
                f"Exported standardized CPENT Master Engagement Workspace to:\n\n{root_dir}\n\n"
                f"Generated {len(files)} official administration documents, RoE, and evidence manifests.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export CPENT Pack:\n{str(e)}")

    def load_scopes(self, project_id: int):
        scopes = self.db.list_scopes(project_id)
        self.scopes_table.setRowCount(len(scopes))
        for row, s in enumerate(scopes):
            self.scopes_table.setItem(row, 0, QTableWidgetItem(str(s.id)))
            self.scopes_table.setItem(row, 1, QTableWidgetItem(s.target))
            self.scopes_table.setItem(row, 2, QTableWidgetItem(s.target_type.value.replace("_", " ").title()))

            # Rule Type
            is_excluded = s.rule_type == ScopeRuleType.EXCLUDED or not s.is_authorized
            rule_item = QTableWidgetItem("EXCLUDED" if is_excluded else "ALLOWED")
            rule_item.setForeground(QColor(CPENTTheme.ERROR_RED) if is_excluded else QColor(CPENTTheme.SUCCESS_GREEN))
            self.scopes_table.setItem(row, 3, rule_item)

            self.scopes_table.setItem(row, 4, QTableWidgetItem(s.environment.title()))
            self.scopes_table.setItem(row, 5, QTableWidgetItem(s.ports_allowed or "All"))

            # Status and Delete Action
            action_box = QWidget()
            action_layout = QHBoxLayout(action_box)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(8)

            stat_lbl = QLabel("● Active" if s.is_authorized else "○ Inactive")
            stat_lbl.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN if s.is_authorized else CPENTTheme.ERROR_RED}; font-weight: bold; font-size: 11px;")
            action_layout.addWidget(stat_lbl)

            btn_del = QPushButton("🗑️")
            btn_del.setToolTip("Delete this scope rule")
            btn_del.setFixedSize(24, 24)
            btn_del.setCursor(Qt.PointingHandCursor)
            btn_del.setStyleSheet(
                "QPushButton { background: #334155; color: #f8fafc; border: none; border-radius: 4px; font-size: 11px; }"
                "QPushButton:hover { background: #dc2626; color: #ffffff; }"
            )
            btn_del.clicked.connect(lambda _, sid=s.id: self._on_delete_scope(sid))
            action_layout.addWidget(btn_del)
            action_layout.addStretch()

            self.scopes_table.setCellWidget(row, 6, action_box)

        # Check for Scope Conflicts & Overlaps
        conflicts = ScopeAuthorizationService.detect_scope_conflicts(scopes)
        if conflicts:
            msg = f"⚠️ Scope Conflict Warning: {conflicts[0]['message']}"
            if len(conflicts) > 1:
                msg += f" (+{len(conflicts)-1} more conflicts)"
            self.conflict_banner.setText(msg)
            self.conflict_banner.setVisible(True)
        else:
            self.conflict_banner.setVisible(False)

    def load_audit_logs(self, project_id: int):
        logs = self.db.list_audit_logs(project_id)
        self.audit_table.setRowCount(len(logs))
        for row, entry in enumerate(logs):
            self.audit_table.setItem(row, 0, QTableWidgetItem(entry.timestamp[:19].replace("T", " ")))
            self.audit_table.setItem(row, 1, QTableWidgetItem(entry.actor))
            self.audit_table.setItem(row, 2, QTableWidgetItem(entry.action.replace("_", " ").title()))
            self.audit_table.setItem(row, 3, QTableWidgetItem(entry.details))

    def _on_delete_scope(self, scope_id: int):
        if not self.active_project:
            return
        reply = QMessageBox.question(
            self,
            "Confirm Scope Rule Deletion",
            f"Are you sure you want to delete Scope Rule #{scope_id}?\n\nTargets in this range will no longer be authorized.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_scope(scope_id)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="scope_rule_deleted",
                    details=f"Deleted Scope Rule #{scope_id}",
                )
            )
            self.load_scopes(self.active_project.id)
            self.load_audit_logs(self.active_project.id)
            self.scope_updated.emit(self.active_project.id)

    def _on_add_scope(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select or create an engagement first.")
            return

        target_text = self.scope_input.text().strip()
        if not target_text:
            QMessageBox.warning(self, "Target Required", "Please enter a target IP address, CIDR subnet, or hostname.")
            return

        tt_val = self.combo_scope_type.currentData()
        rule_val = self.combo_rule_type.currentData()
        env_val = self.env_combo.currentText().lower()
        ports_val = self.ports_input.text().strip()

        scope = TargetScope(
            project_id=self.active_project.id,
            target=target_text,
            target_type=TargetType(tt_val),
            rule_type=ScopeRuleType(rule_val),
            environment=env_val,
            ports_allowed=ports_val,
            is_authorized=(rule_val == ScopeRuleType.ALLOWED.value),
            notes=f"Added by tester on {datetime.now().strftime('%Y-%m-%d')}",
        )
        self.db.add_scope(scope)
        self.db.add_audit_log(
            EngagementAuditLog(
                project_id=self.active_project.id,
                actor="security_lead",
                action="scope_rule_added",
                details=f"Added {rule_val.upper()} target '{target_text}' ({tt_val})",
            )
        )
        self.scope_input.clear()
        self.ports_input.clear()
        self.load_scopes(self.active_project.id)
        self.load_audit_logs(self.active_project.id)
        self.scope_updated.emit(self.active_project.id)

    def _on_run_amass(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Please select an active engagement project first.")
            return

        domain = self.amass_domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Domain Required", "Please enter a target domain to enumerate.")
            return

        is_active = self.radio_active.isChecked()
        if is_active and not self.active_project.allow_active_recon:
            res = QMessageBox.question(
                self,
                "Authorization Required",
                "Active reconnaissance is currently disabled in engagement Rules of Engagement.\n\n"
                "Do you want to authorize active brute-force enumeration for this engagement now?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if res == QMessageBox.Yes:
                self.active_project.allow_active_recon = True
                self.db.update_project(self.active_project)
                self.db.add_audit_log(
                    EngagementAuditLog(
                        project_id=self.active_project.id,
                        actor="security_lead",
                        action="active_recon_authorized",
                        details="User explicitly authorized active brute-force reconnaissance.",
                    )
                )
            else:
                return

        self.btn_run_amass.setEnabled(False)
        self.amass_log.clear()
        self.amass_log.appendPlainText(f"[*] Initializing OWASP Amass OSINT pipeline for: {domain}\n")

        adapter = AmassAdapter(self.db)
        scopes = self.db.list_scopes(self.active_project.id)
        options = AmassOptions(
            target_domain=domain,
            passive_only=not is_active,
            active_recon=is_active,
            timeout=180.0,
        )

        def on_stream(chunk: str, stream: str):
            self.amass_log.appendPlainText(chunk)

        def worker():
            try:
                success, msg, findings, exec_rec, result = adapter.execute_scan(
                    project=self.active_project,
                    options=options,
                    scopes=scopes,
                    on_output=on_stream,
                )
                self.db.add_audit_log(
                    EngagementAuditLog(
                        project_id=self.active_project.id,
                        actor="security_lead",
                        action="amass_scan_finished",
                        details=f"Amass finished with status: {msg}",
                    )
                )
            except Exception as e:
                self.amass_log.appendPlainText(f"\n[-] Execution Error: {e}\n")
            finally:
                self.btn_run_amass.setEnabled(True)
                self.graph_view.load_graph()
                self.load_audit_logs(self.active_project.id)

        self._amass_thread = threading.Thread(target=worker, daemon=True)
        self._amass_thread.start()

    def _create_assessment_plans_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top action toolbar
        toolbar = QHBoxLayout()
        lbl_info = QLabel("Assessments & Authorized Scopes")
        lbl_info.setStyleSheet("font-weight: bold; color: #f8fafc;")
        toolbar.addWidget(lbl_info)
        toolbar.addStretch()

        self.btn_new_plan = QPushButton("+ New Assessment")
        self.btn_new_plan.setProperty("class", "action-primary")
        self.btn_new_plan.clicked.connect(self._on_new_assessment)
        toolbar.addWidget(self.btn_new_plan)

        self.btn_edit_assessment = QPushButton("✏️ Edit")
        self.btn_edit_assessment.clicked.connect(self._on_edit_assessment)
        toolbar.addWidget(self.btn_edit_assessment)

        self.btn_start_assessment = QPushButton("▶️ Start")
        self.btn_start_assessment.clicked.connect(self._on_start_assessment)
        toolbar.addWidget(self.btn_start_assessment)

        self.btn_pause_assessment = QPushButton("⏸️ Pause")
        self.btn_pause_assessment.clicked.connect(self._on_pause_assessment)
        toolbar.addWidget(self.btn_pause_assessment)

        self.btn_complete_assessment = QPushButton("✅ Complete")
        self.btn_complete_assessment.clicked.connect(self._on_complete_assessment)
        toolbar.addWidget(self.btn_complete_assessment)

        self.btn_preflight_plan = QPushButton("🛡️ Preflight")
        self.btn_preflight_plan.clicked.connect(self._on_preflight_plan)
        toolbar.addWidget(self.btn_preflight_plan)

        self.btn_delete_plan = QPushButton("🗑️ Delete")
        self.btn_delete_plan.clicked.connect(self._on_delete_assessment)
        toolbar.addWidget(self.btn_delete_plan)

        layout.addLayout(toolbar)

        # Splitter with table on top/left and details on bottom/right
        splitter = QSplitter(Qt.Horizontal)

        # Table
        self.plans_table = QTableWidget()
        self.plans_table.setColumnCount(6)
        self.plans_table.setHorizontalHeaderLabels(["ID", "Name", "Status", "Authorized Scope", "Timeline", "Notes"])
        self.plans_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.plans_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.plans_table.itemSelectionChanged.connect(self._on_plan_selected)
        splitter.addWidget(self.plans_table)

        # Details & Criteria Panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(6, 0, 6, 0)
        details_layout.setSpacing(6)

        lbl_det = QLabel("Assessment Details & Scope")
        lbl_det.setStyleSheet(f"font-weight: bold; color: {CPENTTheme.SECONDARY_TEXT};")
        details_layout.addWidget(lbl_det)

        self.plan_detail_target = QLabel("Target: None selected")
        self.plan_detail_target.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-weight: bold;")
        details_layout.addWidget(self.plan_detail_target)

        self.plan_criteria_view = QTextEdit()
        self.plan_criteria_view.setReadOnly(True)
        self.plan_criteria_view.setPlaceholderText("Assessment scope and details will appear here...")
        self.plan_criteria_view.setMaximumHeight(90)
        details_layout.addWidget(self.plan_criteria_view)

        lbl_preflight = QLabel("Readiness, Status & Notes")
        lbl_preflight.setStyleSheet("font-weight: bold; color: #94a3b8;")
        details_layout.addWidget(lbl_preflight)

        self.plan_preflight_view = QPlainTextEdit()
        self.plan_preflight_view.setReadOnly(True)
        self.plan_preflight_view.setStyleSheet("background-color: #0b0f19; color: #f87171; font-family: monospace;")
        self.plan_preflight_view.setPlaceholderText("Preflight checks, blockers, and assessment notes...")
        details_layout.addWidget(self.plan_preflight_view)

        splitter.addWidget(details_widget)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)
        return widget

    def load_assessment_plans(self, project_id: int):
        assessments = self.db.list_assessments(project_id)
        if not assessments:
            # Fall back to legacy assessment_plans if any exist
            legacy_plans = self.db.list_assessment_plans(project_id)
            if legacy_plans:
                self.plans_table.setRowCount(len(legacy_plans))
                for row, p in enumerate(legacy_plans):
                    self.plans_table.setItem(row, 0, QTableWidgetItem(str(p.id)))
                    self.plans_table.setItem(row, 1, QTableWidgetItem(p.title))
                    status_item = QTableWidgetItem(p.status.value.replace("_", " ").upper())
                    self.plans_table.setItem(row, 2, status_item)
                    self.plans_table.setItem(row, 3, QTableWidgetItem(p.target))
                    self.plans_table.setItem(row, 4, QTableWidgetItem(p.created_at[:10]))
                    self.plans_table.setItem(row, 5, QTableWidgetItem(p.acceptance_criteria[:40]))
                if legacy_plans:
                    self.plans_table.selectRow(0)
                    self._on_plan_selected()
                return

        self.plans_table.setRowCount(len(assessments))
        for row, a in enumerate(assessments):
            self.plans_table.setItem(row, 0, QTableWidgetItem(str(a.id)))
            self.plans_table.setItem(row, 1, QTableWidgetItem(a.name))

            raw_stat = a.status.value if hasattr(a.status, "value") else str(a.status)
            status_item = QTableWidgetItem(raw_stat.replace("_", " ").upper())
            if raw_stat in ("completed", "preflight_passed"):
                status_item.setForeground(QColor(CPENTTheme.SUCCESS_GREEN))
            elif raw_stat in ("blocked", "failed", "archived"):
                status_item.setForeground(QColor(CPENTTheme.ERROR_RED))
            elif raw_stat == "in_progress":
                status_item.setForeground(QColor(CPENTTheme.PRIMARY_BLUE))
            elif raw_stat == "paused":
                status_item.setForeground(QColor(CPENTTheme.AMBER_ACCENT))
            else:
                status_item.setForeground(QColor(CPENTTheme.SECONDARY_TEXT))
            self.plans_table.setItem(row, 2, status_item)

            self.plans_table.setItem(row, 3, QTableWidgetItem(a.authorized_scope or "All Targets"))
            timeline = f"{a.start_date or 'N/A'} -> {a.end_date or 'Active'}"
            self.plans_table.setItem(row, 4, QTableWidgetItem(timeline))
            self.plans_table.setItem(row, 5, QTableWidgetItem(a.notes[:50] if a.notes else (a.description[:50] if a.description else "")))

        if assessments:
            self.plans_table.selectRow(0)
            self._on_plan_selected()
        else:
            self.plan_detail_target.setText("Target: None selected")
            self.plan_criteria_view.clear()
            self.plan_preflight_view.clear()

    def _on_plan_selected(self):
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        item = self.plans_table.item(row, 0)
        if not item:
            return
        item_id = int(item.text())
        assessment = self.db.get_assessment(item_id)
        if assessment:
            self.plan_detail_target.setText(f"Scope: {assessment.authorized_scope} | Status: {assessment.status.value.upper()}")
            timeline = f"Start: {assessment.start_date or 'N/A'} | End: {assessment.end_date or 'In Progress'}"
            self.plan_criteria_view.setPlainText(
                f"ASSESSMENT NAME: {assessment.name}\n{timeline}\n\nDESCRIPTION:\n{assessment.description or 'No description provided.'}"
            )
            self.plan_preflight_view.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.SUCCESS_GREEN if assessment.status == AssessmentStatus.IN_PROGRESS else CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_MONO};")
            notes_text = f"NOTES:\n{assessment.notes or 'No internal notes.'}\n\n[STATUS: {assessment.status.value.upper()}]"
            self.plan_preflight_view.setPlainText(notes_text)
            return

        plan = self.db.get_assessment_plan(item_id)
        if not plan:
            return
        self.plan_detail_target.setText(f"Target: {plan.target} | Category: {plan.test_category.value}")
        self.plan_criteria_view.setPlainText(
            f"ACCEPTANCE CRITERIA:\n{plan.acceptance_criteria}\n\nDESCRIPTION:\n{plan.description or 'N/A'}"
        )
        if plan.preflight_blockers:
            self.plan_preflight_view.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.ERROR_RED}; font-family: {CPENTTheme.FONT_FAMILY_MONO};")
            self.plan_preflight_view.setPlainText(f"BLOCKERS DETECTED:\n{plan.preflight_blockers}")
        elif plan.status == AssessmentStatus.PREFLIGHT_PASSED:
            self.plan_preflight_view.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.SUCCESS_GREEN}; font-family: {CPENTTheme.FONT_FAMILY_MONO};")
            self.plan_preflight_view.setPlainText("[+] Preflight verification checks passed! Target is authorized.")
        else:
            self.plan_preflight_view.setStyleSheet(f"background-color: {CPENTTheme.TERMINAL_BG}; color: {CPENTTheme.SECONDARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_MONO};")
            self.plan_preflight_view.setPlainText("[*] Preflight check pending.")

    def _on_new_assessment(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Engagement Selected", "Please select an active engagement project first.")
            return
        scopes = self.db.list_scopes(self.active_project.id)
        target_options = [s.target for s in scopes if s.is_authorized and s.rule_type == ScopeRuleType.ALLOWED]
        dlg = AssessmentDialog(target_options, parent=self)
        if dlg.exec() == QDialog.Accepted:
            data = dlg.get_data()
            assessment = Assessment(
                project_id=self.active_project.id,
                name=data["name"],
                status=data["status"],
                authorized_scope=data["authorized_scope"],
                start_date=data["start_date"],
                end_date=data["end_date"],
                description=data["description"],
                notes=data["notes"],
            )
            created = self.db.create_assessment(assessment)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="assessment_created",
                    details=f"Created assessment '{created.name}' for scope '{created.authorized_scope}'",
                )
            )
            self.load_assessment_plans(self.active_project.id)
            self.load_audit_logs(self.active_project.id)

    _on_new_plan = _on_new_assessment

    def _on_edit_assessment(self):
        if not self.active_project:
            return
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select an assessment to edit.")
            return
        row = selected_rows[0].row()
        item = self.plans_table.item(row, 0)
        if not item:
            return
        item_id = int(item.text())
        assessment = self.db.get_assessment(item_id)
        if not assessment:
            QMessageBox.information(self, "Legacy Plan", "Selected item is a legacy plan; editing not supported.")
            return

        scopes = self.db.list_scopes(self.active_project.id)
        target_options = [s.target for s in scopes if s.is_authorized and s.rule_type == ScopeRuleType.ALLOWED]
        dlg = AssessmentDialog(target_options, assessment=assessment, parent=self)
        if dlg.exec() == QDialog.Accepted:
            data = dlg.get_data()
            assessment.name = data["name"]
            assessment.status = data["status"]
            assessment.authorized_scope = data["authorized_scope"]
            assessment.start_date = data["start_date"]
            assessment.end_date = data["end_date"]
            assessment.description = data["description"]
            assessment.notes = data["notes"]
            self.db.update_assessment(assessment)
            self.load_assessment_plans(self.active_project.id)

    def _on_start_assessment(self):
        self._update_selected_assessment_status(AssessmentStatus.IN_PROGRESS)

    def _on_pause_assessment(self):
        self._update_selected_assessment_status(AssessmentStatus.PAUSED)

    def _on_complete_assessment(self):
        self._update_selected_assessment_status(AssessmentStatus.COMPLETED)

    def _update_selected_assessment_status(self, new_status: AssessmentStatus):
        if not self.active_project:
            return
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select an assessment from the table.")
            return
        row = selected_rows[0].row()
        item = self.plans_table.item(row, 0)
        if not item:
            return
        item_id = int(item.text())
        assessment = self.db.get_assessment(item_id)
        if assessment:
            assessment.status = new_status
            self.db.update_assessment(assessment)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action=f"assessment_{new_status.value}",
                    details=f"Assessment '{assessment.name}' marked {new_status.value.upper()}",
                )
            )
            self.load_assessment_plans(self.active_project.id)
            self.load_audit_logs(self.active_project.id)
            return

        plan = self.db.get_assessment_plan(item_id)
        if plan:
            plan.status = new_status
            self.db.update_assessment_plan(plan)
            self.load_assessment_plans(self.active_project.id)

    def _on_delete_assessment(self):
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select an assessment to delete.")
            return
        row = selected_rows[0].row()
        item = self.plans_table.item(row, 0)
        if not item:
            return
        item_id = int(item.text())
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete assessment #{item_id}?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            if not self.db.delete_assessment(item_id):
                self.db.delete_assessment_plan(item_id)
            if self.active_project:
                self.load_assessment_plans(self.active_project.id)

    _on_delete_plan = _on_delete_assessment

    def _on_preflight_plan(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Engagement Selected", "Please select an engagement first.")
            return
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Plan Selected", "Please select an assessment plan from the table.")
            return
        row = selected_rows[0].row()
        plan_id = int(self.plans_table.item(row, 0).text())
        plan = self.db.get_assessment_plan(plan_id)
        if not plan:
            return

        checker = PreflightChecker(self.db)
        res = checker.run_preflight(target=plan.target, project=self.active_project, test_category=plan.test_category)

        if not res.is_ready or res.blockers:
            plan.status = AssessmentStatus.BLOCKED
            plan.preflight_blockers = "\n".join(res.blockers)
            self.db.update_assessment_plan(plan)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="preflight_failed",
                    details=f"Preflight checks blocked for plan '{plan.title}': {len(res.blockers)} blocker(s)",
                )
            )
            self.load_assessment_plans(self.active_project.id)
            self.load_audit_logs(self.active_project.id)
            QMessageBox.critical(
                self,
                "Preflight Checks Blocked",
                f"Preflight verification failed for target '{plan.target}':\n\n" + "\n".join(f"• {b}" for b in res.blockers),
            )
        else:
            plan.status = AssessmentStatus.PREFLIGHT_PASSED
            plan.preflight_blockers = ""
            self.db.update_assessment_plan(plan)
            self.db.add_audit_log(
                EngagementAuditLog(
                    project_id=self.active_project.id,
                    actor="security_lead",
                    action="preflight_passed",
                    details=f"Preflight passed for plan '{plan.title}' on target '{plan.target}'",
                )
            )
            self.load_assessment_plans(self.active_project.id)
            self.load_audit_logs(self.active_project.id)
            msg = f"Target '{plan.target}' is authorized and environment checks passed."
            if res.warnings:
                msg += "\n\nWarnings:\n" + "\n".join(f"• {w}" for w in res.warnings)
            QMessageBox.information(self, "Preflight Verification Passed", msg)

    def _on_delete_plan(self):
        selected_rows = self.plans_table.selectedItems()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        plan_id = int(self.plans_table.item(row, 0).text())
        plan = self.db.get_assessment_plan(plan_id)
        if not plan:
            return
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete test plan '{plan.title}'?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self.db.delete_assessment_plan(plan_id)
            if self.active_project:
                self.load_assessment_plans(self.active_project.id)
