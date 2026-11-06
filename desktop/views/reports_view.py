"""CPENT Multi-Format Professional Report Generator & Executive Security Dashboard.

Inspired by modern enterprise security dashboards, KnowBe4 vulnerability matrices,
and SAST code audit inspectors:
1. Executive Security Posture circular gauge & Grade (A/B/C/D/F).
2. Severity KPI overview cards (Critical, High, Medium, Low, Informational).
3. CPENT 5-Pillar Vulnerability Matrix (Network, Web, AD, Wireless, IoT/Binary).
4. Discovered Network Topology preview card.
5. High-density findings matrix table with search filtering and evidence hash audit.
6. Selected finding inspector with CWE tags, CVSS badges, reproduction steps, and evidence vault pill.
7. CPENT 5-Pillar 3-Tier Remediation Roadmap (0-48h, 30d, 90d).
8. Multi-format export hub (PDF, HTML, Excel/CSV, Markdown, JSON, CPENT Pack ZIP).
9. Live report document previewer.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import html
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
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

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme, ThemeManager
from reports.builder import AssessmentReportData, ReportBuilder, ReportSummaryMetrics
from reports.cpent_engagement_pack import CPENTEngagementPackGenerator
from storage.db import Database
from storage.models import Assessment, Evidence, Finding, FindingSeverity, Project, ValidationStatus


class ReportsView(QWidget):
    """Unified desktop workbench for Executive Reporting and Multi-Format Exports."""

    reports_generated = Signal(str)

    SEVERITY_COLORS = {
        FindingSeverity.CRITICAL: QColor("#ef4444"),
        FindingSeverity.HIGH: QColor("#f97316"),
        FindingSeverity.MEDIUM: QColor("#eab308"),
        FindingSeverity.LOW: QColor("#3b82f6"),
        FindingSeverity.INFORMATIONAL: QColor("#64748b"),
    }

    def __init__(self, db: Database, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.report_builder = ReportBuilder(db)
        self.active_project_id: Optional[int] = None
        self._cached_report_data: Optional[AssessmentReportData] = None

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        """Binds active project to reporting workbench and updates data."""
        self.active_project_id = project.id if project else None
        self._refresh_assessments_dropdown()
        self.refresh_report_data()

    def update_theme(self, mode: Optional[str] = None):
        """Refreshes high-contrast cards and table colors on theme change."""
        self._refresh_kpi_styles()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 14, 16, 14)
        main_layout.setSpacing(10)

        # 1. Top Header Bar: Title, Project/Assessment Combos
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title_lbl = QLabel("CPENT Professional Report Generator & Executive Dashboard")
        title_lbl.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {CPENTTheme.PRIMARY_TEXT};")
        title_box.addWidget(title_lbl)

        self.lbl_project_status = QLabel("Project: None | Scope: Unbound")
        self.lbl_project_status.setStyleSheet(f"font-size: 11px; color: {CPENTTheme.SECONDARY_TEXT}; font-weight: 500;")
        title_box.addWidget(self.lbl_project_status)
        header_row.addLayout(title_box)
        header_row.addStretch()

        # Assessment Filter
        asm_lbl = QLabel("Assessment:")
        asm_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")
        header_row.addWidget(asm_lbl)

        self.combo_assessment = QComboBox()
        self.combo_assessment.setMinimumWidth(180)
        self.combo_assessment.currentIndexChanged.connect(lambda: self.refresh_report_data())
        header_row.addWidget(self.combo_assessment)
        main_layout.addLayout(header_row)

        # 2. Export Actions Toolbar Row
        actions_bar = QHBoxLayout()
        actions_bar.setSpacing(6)

        actions_lbl = QLabel("Export Deliverables:")
        actions_lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #a1a1aa;")
        actions_bar.addWidget(actions_lbl)

        self.btn_pdf = QPushButton("📕 PDF Report")
        self.btn_pdf.setToolTip("Export Executive & Technical Report in PDF")
        self.btn_pdf.setProperty("class", "action-primary")
        self.btn_pdf.clicked.connect(lambda: self._export_format("pdf"))
        actions_bar.addWidget(self.btn_pdf)

        self.btn_html = QPushButton("📄 HTML")
        self.btn_html.setToolTip("Export Interactive Self-Contained HTML Report")
        self.btn_html.setProperty("class", "action-secondary")
        self.btn_html.clicked.connect(lambda: self._export_format("html"))
        actions_bar.addWidget(self.btn_html)

        self.btn_csv = QPushButton("📊 Excel / CSV")
        self.btn_csv.setToolTip("Export Findings Matrix Spreadsheet (RFC-4180 CSV)")
        self.btn_csv.setStyleSheet("font-weight: 600;")
        self.btn_csv.clicked.connect(lambda: self._export_format("csv"))
        actions_bar.addWidget(self.btn_csv)

        self.btn_md = QPushButton("📝 Markdown")
        self.btn_md.setToolTip("Export GitHub-Flavored Markdown Report")
        self.btn_md.setProperty("class", "action-secondary")
        self.btn_md.clicked.connect(lambda: self._export_format("markdown"))
        actions_bar.addWidget(self.btn_md)

        self.btn_json = QPushButton("⚙️ JSON")
        self.btn_json.setToolTip("Export Machine-Readable JSON Telemetry")
        self.btn_json.setProperty("class", "action-secondary")
        self.btn_json.clicked.connect(lambda: self._export_format("json"))
        actions_bar.addWidget(self.btn_json)

        self.btn_cpent_methodology = QPushButton("📋 CPENT Methodology")
        self.btn_cpent_methodology.setToolTip("Export an original methodology report from stored plans, executions, findings, and evidence")
        self.btn_cpent_methodology.setProperty("class", "action-secondary")
        self.btn_cpent_methodology.clicked.connect(self._export_cpent_methodology)
        actions_bar.addWidget(self.btn_cpent_methodology)

        self.btn_pack = QPushButton("💼 CPENT Pack (ZIP)")
        self.btn_pack.setToolTip("Generate an original CPENT-informed engagement workspace ZIP")
        self.btn_pack.setStyleSheet("""
            QPushButton {
                background-color: #7c3aed;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 10px;
            }
            QPushButton:hover {
                background-color: #8b5cf6;
            }
        """)
        self.btn_pack.clicked.connect(self._export_cpent_pack)
        actions_bar.addWidget(self.btn_pack)

        actions_bar.addSpacing(10)
        self.export_status_lbl = QLabel("")
        self.export_status_lbl.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {CPENTTheme.SUCCESS_GREEN};")
        actions_bar.addWidget(self.export_status_lbl, 1)

        self.chk_auto_refresh = QCheckBox("Auto-sync reports on finding updates")
        self.chk_auto_refresh.setChecked(True)
        self.chk_auto_refresh.setStyleSheet("font-size: 11px;")
        actions_bar.addWidget(self.chk_auto_refresh)
        main_layout.addLayout(actions_bar)

        # Main Workspace Tab Widget
        self.tabs = QTabWidget()
        self.tab_executive = self._create_executive_tab()
        self.tab_matrix = self._create_matrix_tab()
        self.tab_roadmap = self._create_roadmap_tab()
        self.tab_preview = self._create_preview_tab()

        self.tabs.addTab(self.tab_executive, "📊 Executive Posture & Analytics")
        self.tabs.addTab(self.tab_matrix, "📑 Findings Matrix & Evidence Vault")
        self.tabs.addTab(self.tab_roadmap, "🛣️ 5-Pillar Remediation Roadmap")
        self.tabs.addTab(self.tab_preview, "👁️ Live Report Document Preview")
        main_layout.addWidget(self.tabs, 1)

    def _refresh_assessments_dropdown(self):
        self.combo_assessment.blockSignals(True)
        self.combo_assessment.clear()
        self.combo_assessment.addItem("All Scope / Assessments", None)
        if self.active_project_id:
            try:
                assessments = self.db.list_assessments(self.active_project_id)
                for asm in assessments:
                    self.combo_assessment.addItem(f"{asm.name} [{asm.status.value}]", asm.id)
            except Exception:
                pass
        self.combo_assessment.blockSignals(False)

    # =========================================================================
    # Tab 1: Executive Security Posture & Analytics (Inspired by Photo 1 & 3)
    # =========================================================================

    def _create_executive_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        # 1. Top Row: Security Posture Score Card & Severity KPI Cards
        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        # Posture Score Card (Matching Photo 1 Radial Score)
        self.posture_card = QFrame()
        self.posture_card.setFrameShape(QFrame.Shape.StyledPanel)
        self.posture_card.setMinimumWidth(240)
        self.posture_card.setStyleSheet("border-radius: 8px; padding: 10px;")
        posture_layout = QVBoxLayout(self.posture_card)
        posture_layout.setContentsMargins(10, 8, 10, 8)

        self.lbl_posture_title = QLabel("SECURITY POSTURE SCORE")
        self.lbl_posture_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #a1a1aa;")
        posture_layout.addWidget(self.lbl_posture_title)

        self.lbl_posture_val = QLabel("100%")
        self.lbl_posture_val.setStyleSheet("font-size: 32px; font-weight: 800; color: #10b981;")
        posture_layout.addWidget(self.lbl_posture_val)

        self.lbl_posture_grade = QLabel("Grade A — Robust Security Posture")
        self.lbl_posture_grade.setStyleSheet("font-size: 12px; font-weight: 600; color: #10b981;")
        posture_layout.addWidget(self.lbl_posture_grade)

        self.pbar_posture = QProgressBar()
        self.pbar_posture.setFixedHeight(8)
        self.pbar_posture.setRange(0, 100)
        self.pbar_posture.setValue(100)
        self.pbar_posture.setTextVisible(False)
        self.pbar_posture.setStyleSheet("QProgressBar::chunk { background-color: #10b981; border-radius: 4px; }")
        posture_layout.addWidget(self.pbar_posture)

        top_row.addWidget(self.posture_card, 1)

        # Severity KPI Stat Cards (Matching Photo 1 & 3)
        self.kpi_cards: Dict[str, Tuple[QLabel, QLabel]] = {}
        self.kpi_card_frames: Dict[str, QFrame] = {}
        severity_configs = [
            ("CRITICAL", "#ef4444", "0"),
            ("HIGH", "#f97316", "0"),
            ("MEDIUM", "#eab308", "0"),
            ("LOW", "#3b82f6", "0"),
            ("INFO", "#64748b", "0"),
        ]

        for name, col, def_val in severity_configs:
            card = QFrame()
            card.setFrameShape(QFrame.Shape.StyledPanel)
            card.setStyleSheet(f"border: 1px solid {col}; border-radius: 8px; background: rgba(17,24,39,0.85);")
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(10, 8, 10, 8)

            title = QLabel(name)
            title.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {col};")
            c_layout.addWidget(title)

            val = QLabel(def_val)
            val.setStyleSheet(f"font-size: 26px; font-weight: 800; color: {col};")
            c_layout.addWidget(val)

            sub = QLabel("Open Issues")
            sub.setStyleSheet("font-size: 10px; color: #a1a1aa;")
            c_layout.addWidget(sub)

            self.kpi_cards[name] = (val, sub)
            self.kpi_card_frames[name] = card
            top_row.addWidget(card, 1)

        layout.addLayout(top_row)

        # 2. Middle Row: CPENT 5-Pillars Risk Breakdown & Discovered Topology Summary
        middle_row = QHBoxLayout()
        middle_row.setSpacing(10)

        # CPENT 5-Pillars Category Breakdown (Matching Photo 3 'a')
        pillar_box = QGroupBox("CPENT 5-Pillar Vulnerability & Testing Breakdown")
        pillar_layout = QVBoxLayout(pillar_box)
        pillar_layout.setContentsMargins(10, 10, 10, 10)
        pillar_layout.setSpacing(8)

        self.pillar_labels: Dict[str, QLabel] = {}
        pillars = [
            ("Network & Infrastructure", "🌐", "Nmap / TCP / UDP / Routing"),
            ("Web Applications", "🌐", "OWASP ZAP / Burp Suite / SQLi / XSS"),
            ("Active Directory", "🏢", "Kerberos / Mimikatz / BloodHound"),
            ("802.11 Wireless", "📡", "WPA Handshakes / Rogue AP / Evil Twin"),
            ("IoT & Binary Firmware", "🔬", "Binwalk / Shadow Hashes / NX Protection"),
        ]

        for p_name, icon, subtitle in pillars:
            p_row = QHBoxLayout()
            p_lbl = QLabel(f"{icon}  <strong>{p_name}</strong><br><span style='font-size: 10px; color: #a1a1aa;'>{subtitle}</span>")
            p_lbl.setStyleSheet("font-size: 11px;")
            p_row.addWidget(p_lbl, 1)

            p_val = QLabel("0 Findings")
            p_val.setStyleSheet("font-size: 12px; font-weight: bold; padding: 2px 8px; border-radius: 4px; background: rgba(120,120,120,0.2);")
            p_row.addWidget(p_val)
            self.pillar_labels[p_name] = p_val
            pillar_layout.addLayout(p_row)

        middle_row.addWidget(pillar_box, 1)

        # Network Topology & Attack Surface Summary (Matching Photo 1 & 2)
        topo_box = QGroupBox("Attack Surface Topology & Discovered Assets")
        topo_layout = QVBoxLayout(topo_box)
        topo_layout.setContentsMargins(10, 10, 10, 10)

        self.lbl_topo_summary = QLabel(
            "Discovered Hosts: 0 | In-Scope Targets: 0 | Vaulted Evidence Files: 0"
        )
        self.lbl_topo_summary.setStyleSheet("font-size: 12px; font-weight: 600; color: #38bdf8;")
        topo_layout.addWidget(self.lbl_topo_summary)

        self.topo_svg_preview = QTextEdit()
        self.topo_svg_preview.setReadOnly(True)
        self.topo_svg_preview.setMaximumHeight(140)
        self.topo_svg_preview.setPlaceholderText("Network topology SVG will appear once scan data is available...")
        self.topo_svg_preview.setStyleSheet("font-size: 11px; background: #0f172a; color: #f1f5f9; border-radius: 6px;")
        topo_layout.addWidget(self.topo_svg_preview)

        middle_row.addWidget(topo_box, 1)
        layout.addLayout(middle_row)

        # 3. Bottom Row: Executive Summary Preview
        exec_box = QGroupBox("Executive Summary & Risk Narrative Preview")
        exec_layout = QVBoxLayout(exec_box)
        exec_layout.setContentsMargins(10, 10, 10, 10)

        self.exec_summary_edit = QTextEdit()
        self.exec_summary_edit.setReadOnly(True)
        self.exec_summary_edit.setMaximumHeight(160)
        self.exec_summary_edit.setPlaceholderText("Executive summary narrative will be dynamically compiled here...")
        self.exec_summary_edit.setStyleSheet("font-size: 12px; line-height: 1.4;")
        exec_layout.addWidget(self.exec_summary_edit)

        layout.addWidget(exec_box)
        scroll.setWidget(container)
        return scroll

    def _refresh_kpi_styles(self, mode: Optional[str] = None):
        if mode:
            is_light = (str(mode).lower() == "light")
        else:
            try:
                is_light = bool(ThemeManager.instance().is_light())
            except Exception:
                is_light = False
        bg = "#ffffff" if is_light else "#111827"
        border = "#e4e4e7" if is_light else "#1f2937"
        title_color = "#3f3f46" if is_light else "#a1a1aa"
        self.posture_card.setStyleSheet(f"background: {bg}; border: 1px solid {border}; border-radius: 8px;")
        if hasattr(self, "lbl_posture_title"):
            self.lbl_posture_title.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {title_color};")
        card_bg = "#ffffff" if is_light else "#111827"
        for name, card in getattr(self, "kpi_card_frames", {}).items():
            col = "#ef4444" if name == "CRITICAL" else ("#f97316" if name == "HIGH" else ("#eab308" if name == "MEDIUM" else ("#3b82f6" if name == "LOW" else "#64748b")))
            card.setStyleSheet(f"background: {card_bg}; border: 1px solid {col}; border-radius: 8px;")
        if hasattr(self, "topo_svg_preview"):
            topo_bg = "#f8fafc" if is_light else "#0f172a"
            topo_fg = "#0f172a" if is_light else "#f1f5f9"
            topo_border = "#cbd5e1" if is_light else "#334155"
            self.topo_svg_preview.setStyleSheet(f"font-size: 11px; background: {topo_bg}; color: {topo_fg}; border: 1px solid {topo_border}; border-radius: 6px;")

    # =========================================================================
    # Tab 2: Findings Matrix & Evidence Vault (Inspired by Photo 3 'c' & 4/5)
    # =========================================================================

    def _create_matrix_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Filter row (Search + Severity + Category filter)
        filter_row = QHBoxLayout()
        search_lbl = QLabel("Search:")
        search_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")
        filter_row.addWidget(search_lbl)

        self.matrix_search_input = QLineEdit()
        self.matrix_search_input.setPlaceholderText("Filter by title, asset, CVE/CWE, or tool...")
        self.matrix_search_input.setStyleSheet("padding: 4px 8px; font-size: 11px;")
        self.matrix_search_input.textChanged.connect(self._filter_matrix_table)
        filter_row.addWidget(self.matrix_search_input, 1)

        self.combo_matrix_severity = QComboBox()
        self.combo_matrix_severity.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Informational"])
        self.combo_matrix_severity.currentIndexChanged.connect(self._filter_matrix_table)
        filter_row.addWidget(self.combo_matrix_severity)

        self.combo_matrix_status = QComboBox()
        self.combo_matrix_status.addItems(["All Statuses", "Confirmed", "Observed", "Needs Validation", "Remediated", "False Positive"])
        self.combo_matrix_status.currentIndexChanged.connect(self._filter_matrix_table)
        filter_row.addWidget(self.combo_matrix_status)

        layout.addLayout(filter_row)

        # Splitter between matrix table and selected finding details
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Matrix Table (Matching Photo 3 'c')
        self.matrix_table = QTableWidget()
        self.matrix_table.setColumnCount(8)
        self.matrix_table.setHorizontalHeaderLabels([
            "ID", "Severity", "Finding Title", "Affected Asset", "Port / Service", "CVSS", "Status", "Tool"
        ])
        self.matrix_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.matrix_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.matrix_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.matrix_table.setAlternatingRowColors(True)
        self.matrix_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.matrix_table.itemSelectionChanged.connect(self._on_matrix_selection_changed)
        splitter.addWidget(self.matrix_table)

        # Finding Details Inspector Drawer (Matching Photo 4 & 5)
        inspector_box = QGroupBox("Selected Finding Telemetry & Evidence Proof")
        inspector_layout = QVBoxLayout(inspector_box)
        inspector_layout.setContentsMargins(8, 8, 8, 8)

        self.inspector_edit = QTextEdit()
        self.inspector_edit.setReadOnly(True)
        self.inspector_edit.setStyleSheet("font-size: 11px; line-height: 1.4;")
        inspector_layout.addWidget(self.inspector_edit)
        splitter.addWidget(inspector_box)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)
        layout.addWidget(splitter, 1)

        return container

    def _filter_matrix_table(self):
        query = self.matrix_search_input.text().strip().lower()
        sev_filter = self.combo_matrix_severity.currentText().lower()
        status_filter = self.combo_matrix_status.currentText().lower()

        for r in range(self.matrix_table.rowCount()):
            row_visible = True
            title = self.matrix_table.item(r, 2).text().lower()
            asset = self.matrix_table.item(r, 3).text().lower()
            tool = self.matrix_table.item(r, 7).text().lower()
            sev = self.matrix_table.item(r, 1).text().lower()
            status = self.matrix_table.item(r, 6).text().lower()

            if query and not (query in title or query in asset or query in tool):
                row_visible = False
            if sev_filter != "all severities" and sev_filter != sev:
                row_visible = False
            if status_filter != "all statuses" and status_filter != status:
                row_visible = False

            self.matrix_table.setRowHidden(r, not row_visible)

    def _on_matrix_selection_changed(self):
        row = self.matrix_table.currentRow()
        if row < 0 or not self._cached_report_data:
            self.inspector_edit.setMarkdown("*Select a finding row above to inspect technical details, attack reproduction, and cryptographic evidence.*")
            return

        fid_str = self.matrix_table.item(row, 0).text()
        finding = next((f for f in self._cached_report_data.findings if str(f.id) == fid_str), None)
        if not finding:
            return

        # Find attached evidence
        ev_items = [e for e in self._cached_report_data.evidence if e.finding_id == finding.id]
        ev_text = ""
        if ev_items:
            for ev in ev_items:
                ev_text += f"\n- **Evidence #{ev.id}:** `{Path(ev.file_path).name}`\n  `SHA-256:` `{ev.sha256_hash}` ✓ *Vaulted*\n"
        else:
            ev_text = "\n*No standalone evidence files vaulted directly for this finding.*"

        md = f"""### Finding #{finding.id}: {finding.title}

- **Severity:** `{finding.severity.value.upper()}` | **CVSS Score:** `{finding.cvss_score or 'N/A'}` (`{finding.cvss_vector or 'N/A'}`)
- **Affected Asset:** `{finding.affected_asset}` ({finding.affected_port_service or 'N/A'})
- **Status:** `{finding.validation_status.value.upper()}` | **Discovered By:** `{finding.source_tool or 'Manual'}`

#### Vulnerability Description
{finding.description}

#### Reproduction Steps & Proof of Concept
```text
{finding.reproduction_steps or 'No reproduction steps provided.'}
```

#### Remediation Guidance
{finding.remediation or 'Review standard patching and hardening guidelines.'}

#### Cryptographic Evidence Proofs
{ev_text}
"""
        self.inspector_edit.setMarkdown(md)

    # =========================================================================
    # Tab 3: 5-Pillar Remediation Roadmap & CPENT Master Pack
    # =========================================================================

    def _create_roadmap_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        # 3-Tier Remediation Plan Box
        roadmap_box = QGroupBox("CPENT 3-Tier Tactical & Strategic Remediation Roadmap")
        r_layout = QVBoxLayout(roadmap_box)
        r_layout.setContentsMargins(12, 10, 12, 10)
        r_layout.setSpacing(10)

        # Tier 1: Immediate Actions
        t1_card = QFrame()
        t1_card.setStyleSheet("border-left: 4px solid #ef4444; background: rgba(239, 68, 68, 0.08); padding: 8px; border-radius: 4px;")
        t1_l = QVBoxLayout(t1_card)
        t1_l.addWidget(QLabel("🚨 <strong>Tier 1: Immediate Tactical Containment (0 – 48 Hours)</strong>"))
        t1_desc = QLabel("Remediate Critical RCE, unauthenticated database exposure, blank root passwords, and revoke compromised private keys.")
        t1_desc.setWordWrap(True)
        t1_desc.setStyleSheet("font-size: 11px; color: #a1a1aa;")
        t1_l.addWidget(t1_desc)
        r_layout.addWidget(t1_card)

        # Tier 2: Short-Term Actions
        t2_card = QFrame()
        t2_card.setStyleSheet("border-left: 4px solid #f97316; background: rgba(249, 115, 22, 0.08); padding: 8px; border-radius: 4px;")
        t2_l = QVBoxLayout(t2_card)
        t2_l.addWidget(QLabel("⚠️ <strong>Tier 2: Short-Term Remediation & Hardening (1 – 30 Days)</strong>"))
        t2_desc = QLabel("Patch web application vulnerabilities (SQLi, XSS, Path Traversal), mitigate AD Kerberoasting, and compile IoT binaries with NX protection.")
        t2_desc.setWordWrap(True)
        t2_desc.setStyleSheet("font-size: 11px; color: #a1a1aa;")
        t2_l.addWidget(t2_desc)
        r_layout.addWidget(t2_card)

        # Tier 3: Medium-Term Actions
        t3_card = QFrame()
        t3_card.setStyleSheet("border-left: 4px solid #3b82f6; background: rgba(59, 130, 246, 0.08); padding: 8px; border-radius: 4px;")
        t3_l = QVBoxLayout(t3_card)
        t3_l.addWidget(QLabel("🛡️ <strong>Tier 3: Strategic Architectural Hardening (30 – 90 Days)</strong>"))
        t3_desc = QLabel("Enforce 802.1X network access control, disable deprecated TLS 1.0/1.1 protocols, migrate WEP/WPA to WPA3-SAE, and integrate CI/CD SAST scanning.")
        t3_desc.setWordWrap(True)
        t3_desc.setStyleSheet("font-size: 11px; color: #a1a1aa;")
        t3_l.addWidget(t3_desc)
        r_layout.addWidget(t3_card)

        layout.addWidget(roadmap_box)

        # CPENT Engagement Pack Structure Box
        pack_box = QGroupBox("CPENT-Informed Engagement Workspace")
        p_layout = QVBoxLayout(pack_box)
        p_layout.setContentsMargins(12, 10, 12, 10)

        pack_desc = QLabel(
            "Compiles an original engagement documentation structure with evidence references:\n\n"
            "📁 <strong>00_Administration/</strong>: Engagement Letter, Rules of Engagement (RoE), NDAs, Test Plans\n"
            "📁 <strong>01_SISGCA/</strong>: OSINT activity logs, scan outputs, and cryptographic evidence manifest (SHA-256)\n"
            "📁 <strong>02_SEVA_Tools/</strong>: Tool inventories, execution scripts, and automation recipes\n"
            "📁 <strong>03_Final_Reports/</strong>: Multi-format deliverables (Executive PDF, Interactive HTML, Markdown, JSON, and Excel/CSV matrix)"
        )
        pack_desc.setWordWrap(True)
        pack_desc.setStyleSheet("font-size: 12px; line-height: 1.5;")
        p_layout.addWidget(pack_desc)

        btn_compile = QPushButton("📦 Compile & Download CPENT Master Pack (.ZIP)")
        btn_compile.setFixedHeight(32)
        btn_compile.setStyleSheet("""
            QPushButton {
                background-color: #059669;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 14px;
            }
            QPushButton:hover {
                background-color: #10b981;
            }
        """)
        btn_compile.clicked.connect(self._export_cpent_pack)
        p_layout.addWidget(btn_compile)

        layout.addWidget(pack_box)
        scroll.setWidget(container)
        return scroll

    # =========================================================================
    # Tab 4: Live Report Document Previewer
    # =========================================================================

    def _create_preview_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        btn_bar = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Refresh Preview")
        btn_refresh.clicked.connect(self._update_preview_content)
        btn_bar.addWidget(btn_refresh)

        btn_copy = QPushButton("📋 Copy Markdown to Clipboard")
        btn_copy.clicked.connect(self._copy_markdown_preview)
        btn_bar.addWidget(btn_copy)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        self.preview_edit = QTextEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setStyleSheet("font-family: monospace; font-size: 12px;")
        layout.addWidget(self.preview_edit, 1)

        return container

    def _update_preview_content(self):
        if not self.active_project_id:
            self.preview_edit.setText("No active project selected.")
            return

        selected_asm = self.combo_assessment.currentData()
        try:
            md_text = self.report_builder.generate_markdown(self.active_project_id, assessment_id=selected_asm)
            self.preview_edit.setMarkdown(md_text)
        except Exception as e:
            self.preview_edit.setText(f"Error compiling report preview: {e}")

    def _copy_markdown_preview(self):
        text = self.preview_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Markdown report copied to clipboard.")

    # =========================================================================
    # Data Refresh & Analytics Engine
    # =========================================================================

    def refresh_report_data(self):
        """Loads project telemetry, computes posture metrics, and refreshes all UI tabs."""
        if not self.active_project_id:
            self.lbl_project_status.setText("Project: None | Scope: Unbound")
            self.lbl_posture_val.setText("N/A")
            self.lbl_posture_grade.setText("No Project Selected")
            self.matrix_table.setRowCount(0)
            return

        project = self.db.get_project(self.active_project_id)
        if not project:
            return

        selected_asm = self.combo_assessment.currentData()
        scopes = self.db.list_scopes(self.active_project_id)
        self.lbl_project_status.setText(f"Project: {project.name} | Scopes: {len(scopes)} Rules | Client: {project.client_name or 'N/A'}")

        # Build report data via ReportBuilder
        data = self.report_builder.build_report_data(self.active_project_id, assessment_id=selected_asm)
        self._cached_report_data = data
        m = data.metrics
        self._refresh_kpi_styles()

        # 1. Calculate Security Posture Score
        # Formula: 100 - (Crit*20 + High*8 + Med*3 + Low*1), bounded in [0, 100]
        penalties = (m.critical_count * 20) + (m.high_count * 8) + (m.medium_count * 3) + (m.low_count * 1)
        score = max(0, min(100, 100 - penalties))
        self.lbl_posture_val.setText(f"{score}%")
        self.pbar_posture.setValue(score)

        if score >= 90:
            grade_str = "Grade A — Robust Security Posture"
            color_hex = "#10b981"
        elif score >= 75:
            grade_str = "Grade B — Minor Security Weaknesses"
            color_hex = "#3b82f6"
        elif score >= 60:
            grade_str = "Grade C — Moderate Attack Surface"
            color_hex = "#eab308"
        elif score >= 40:
            grade_str = "Grade D — Substantial Vulnerabilities"
            color_hex = "#f97316"
        else:
            grade_str = "Grade F — Critical Remediation Required"
            color_hex = "#ef4444"

        self.lbl_posture_val.setStyleSheet(f"font-size: 32px; font-weight: 800; color: {color_hex};")
        self.lbl_posture_grade.setText(grade_str)
        self.lbl_posture_grade.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {color_hex};")
        self.pbar_posture.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color_hex}; border-radius: 4px; }}")

        # 2. Update Severity KPI Cards
        self.kpi_cards["CRITICAL"][0].setText(str(m.critical_count))
        self.kpi_cards["HIGH"][0].setText(str(m.high_count))
        self.kpi_cards["MEDIUM"][0].setText(str(m.medium_count))
        self.kpi_cards["LOW"][0].setText(str(m.low_count))
        self.kpi_cards["INFO"][0].setText(str(m.info_count))

        # 3. Update CPENT 5-Pillars Risk Breakdown
        pillar_counts = {
            "Network & Infrastructure": 0,
            "Web Applications": 0,
            "Active Directory": 0,
            "802.11 Wireless": 0,
            "IoT & Binary Firmware": 0,
        }

        for f in data.findings:
            context_text = f"{f.title} {f.source_tool or ''} {f.affected_port_service or ''} {f.description or ''}".lower()
            if any(k in context_text for k in ("wireless", "802.11", "eapol", "wpa", "bssid", "aircrack", "wifite")):
                pillar_counts["802.11 Wireless"] += 1
            elif any(k in context_text for k in ("firmware", "iot", "binwalk", "shadow", "nx", "mips", "arm", "qemu", "ghidra")):
                pillar_counts["IoT & Binary Firmware"] += 1
            elif any(k in context_text for k in ("active directory", "kerberos", "mimikatz", "bloodhound", "dcsync", "golden ticket", "silver ticket", "gpo abuse")):
                pillar_counts["Active Directory"] += 1
            elif any(k in context_text for k in ("web", "zap", "burp", "sql", "xss", "csrf", "http", "https", "modsec", "cors", "ssrf", "injection", "rest", "graphql", "api")):
                pillar_counts["Web Applications"] += 1
            else:
                pillar_counts["Network & Infrastructure"] += 1

        for p_name, cnt in pillar_counts.items():
            if p_name in self.pillar_labels:
                self.pillar_labels[p_name].setText(f"{cnt} Findings")

        # 4. Topology & Executive Summary
        self.lbl_topo_summary.setText(
            f"Discovered Hosts: {len(data.asset_nodes)} | Scopes: {len(data.scopes)} | Vaulted Evidence: {len(data.evidence)}"
        )
        if data.asset_nodes:
            host_lines = [f"• {n.label or n.value} [{n.node_type.upper()}] via {n.source_tool or 'Discovery'}" for n in data.asset_nodes[:5]]
            self.topo_svg_preview.setText("\n".join(host_lines))
        else:
            self.topo_svg_preview.setText("No network discovery scans registered yet.")

        # Executive narrative snippet
        self.exec_summary_edit.setMarkdown(
            f"**Executive Security Overview for {project.name}:**\n\n"
            f"During the engagement, **{m.total_findings}** total security findings were identified "
            f"across **{len(data.scopes)}** authorized target scopes. The posture assessment resulted in "
            f"a security score of **{score}% ({grade_str.split('—')[0].strip()})**.\n\n"
            f"- **Critical Issues:** {m.critical_count}\n"
            f"- **High Severity Issues:** {m.high_count}\n"
            f"- **Confirmed Exploitability:** {m.confirmed_findings} verified findings"
        )

        # 5. Populate Matrix Table
        self.matrix_table.setRowCount(len(data.findings))
        for r, f in enumerate(data.findings):
            self.matrix_table.setItem(r, 0, QTableWidgetItem(str(f.id or r + 1)))

            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_col = self.SEVERITY_COLORS.get(f.severity, QColor("#64748b"))
            sev_item.setForeground(sev_col)
            self.matrix_table.setItem(r, 1, sev_item)

            self.matrix_table.setItem(r, 2, QTableWidgetItem(f.title))
            self.matrix_table.setItem(r, 3, QTableWidgetItem(f.affected_asset))
            self.matrix_table.setItem(r, 4, QTableWidgetItem(f.affected_port_service or "N/A"))
            self.matrix_table.setItem(r, 5, QTableWidgetItem(str(f.cvss_score or "—")))
            self.matrix_table.setItem(r, 6, QTableWidgetItem(f.validation_status.value.capitalize()))
            self.matrix_table.setItem(r, 7, QTableWidgetItem(f.source_tool or "Manual"))

        self._update_preview_content()

    # =========================================================================
    # Export Engine
    # =========================================================================

    def _export_format(self, fmt: str):
        if not self.active_project_id:
            QMessageBox.warning(self, "Project Required", "Please select an active project first.")
            return

        project = self.db.get_project(self.active_project_id)
        if not project:
            return

        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name.lower())
        ext_map = {"pdf": "pdf", "html": "html", "markdown": "md", "json": "json", "csv": "csv"}
        ext = ext_map.get(fmt, "txt")

        filter_str = f"{fmt.upper()} Files (*.{ext});;All Files (*.*)"
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Export {fmt.upper()} Report", f"{clean_name}_report.{ext}", filter_str
        )
        if not file_path:
            return

        dest = Path(file_path)
        selected_asm = self.combo_assessment.currentData()

        try:
            if fmt == "pdf":
                self.report_builder.generate_pdf(self.active_project_id, output_path=dest, assessment_id=selected_asm)
            elif fmt == "html":
                self.report_builder.generate_html(self.active_project_id, output_path=dest, assessment_id=selected_asm)
            elif fmt == "markdown":
                self.report_builder.generate_markdown(self.active_project_id, output_path=dest, assessment_id=selected_asm)
            elif fmt == "json":
                self.report_builder.generate_json(self.active_project_id, output_path=dest, assessment_id=selected_asm)
            elif fmt == "csv":
                self.report_builder.generate_csv(self.active_project_id, output_path=dest, assessment_id=selected_asm)

            self.export_status_lbl.setText(f"✓ Exported {fmt.upper()} report to: {dest.name}")
            self.reports_generated.emit(str(dest))
            QMessageBox.information(self, "Export Successful", f"Assessment report exported successfully:\n\n{dest.resolve()}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to generate {fmt.upper()} report:\n{e}")

    def _export_cpent_pack(self):
        if not self.active_project_id:
            QMessageBox.warning(self, "Project Required", "Please select an active project first.")
            return

        project = self.db.get_project(self.active_project_id)
        if not project:
            return

        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name.lower())
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save CPENT-Informed Engagement Workspace", f"CPENT_PACK_{clean_name}.zip", "ZIP Archives (*.zip)"
        )
        if not file_path:
            return

        try:
            generator = CPENTEngagementPackGenerator(self.db)
            out_zip = generator.generate_pack_zip(self.active_project_id, Path(file_path))
            self.export_status_lbl.setText(f"✓ Exported CPENT Engagement Pack: {out_zip.name}")
            self.reports_generated.emit(str(out_zip))
            QMessageBox.information(
                self,
                "CPENT Pack Exported",
                f"Successfully compiled the CPENT-informed engagement workspace:\n\n{out_zip.resolve()}\n\n"
                f"Includes engagement documents, evidence manifest, and multi-format reports.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to compile CPENT engagement pack:\n{e}")

    def _export_cpent_methodology(self):
        if not self.active_project_id:
            QMessageBox.warning(self, "Project Required", "Please select an active project first.")
            return

        project = self.db.get_project(self.active_project_id)
        if not project:
            QMessageBox.warning(self, "Project Unavailable", "The selected project could not be loaded.")
            return

        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name.lower())
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CPENT Methodology & Evidence Report",
            f"{clean_name}_cpent_methodology.md",
            "Markdown Files (*.md);;All Files (*.*)",
        )
        if not file_path:
            return

        destination = Path(file_path)
        try:
            self.report_builder.generate_cpent_methodology_markdown(
                self.active_project_id,
                output_path=destination,
                assessment_id=self.combo_assessment.currentData(),
            )
            self.export_status_lbl.setText(f"✓ Exported CPENT methodology report: {destination.name}")
            self.reports_generated.emit(str(destination))
            QMessageBox.information(
                self,
                "Export Successful",
                f"CPENT methodology and evidence report exported:\n\n{destination.resolve()}",
            )
        except Exception as error:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to generate CPENT methodology report:\n{error}",
            )
