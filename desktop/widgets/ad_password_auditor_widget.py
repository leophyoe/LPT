"""Enterprise Active Directory & Weak Password Audit UI Widget.

Faithfully implements the user-referenced KnowBe4 Weak Password Test design:
- Top Red & Green KPI summary cards (Vulnerable vs Not Vulnerable accounts).
- Interactive High-DPI Donut / Pie chart visualizing vulnerability categories.
- Left-side category selector with dynamic count badges.
- Right-side searchable account matrix with verification checkmarks.
- Export to PDF and CSV/Excel.
- Direct synchronization with CPENT Project Findings and SQLite database.
"""

from __future__ import annotations

import csv
import math
from typing import Dict, List, Optional

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.ad_password_auditor import ADAccountRecord, ADAuditSummary, ADPasswordAuditor
from storage.db import Database


class DonutPieChartWidget(QWidget):
    """Custom high-DPI Donut/Pie Chart widget with interactive legend."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(420, 220)
        self.slices: List[Dict[str, any]] = []
        self.total_count = 0

    def set_data(self, slices: List[Dict[str, any]]):
        """Sets slice list: [{'label': str, 'count': int, 'color': QColor}]"""
        self.slices = [s for s in slices if s["count"] > 0]
        self.total_count = sum(s["count"] for s in self.slices)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Left area: Donut chart
        chart_size = min(w * 0.45, h - 30)
        chart_rect = QRectF(15, (h - chart_size) / 2, chart_size, chart_size)

        if self.total_count == 0:
            painter.setPen(QPen(QColor("#7f8c8d"), 1, Qt.DashLine))
            painter.drawEllipse(chart_rect)
            painter.setPen(QColor("#95a5a6"))
            painter.drawText(chart_rect, Qt.AlignCenter, "No Vulnerabilities\nDetected")
            return

        start_angle = 90 * 16
        for sl in self.slices:
            span_angle = int((sl["count"] / self.total_count) * 360 * 16)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(sl["color"]))
            painter.drawPie(chart_rect, start_angle, span_angle)
            start_angle += span_angle

        # Draw donut hole
        hole_size = chart_size * 0.45
        hole_rect = QRectF(
            chart_rect.center().x() - hole_size / 2,
            chart_rect.center().y() - hole_size / 2,
            hole_size,
            hole_size,
        )
        painter.setBrush(QBrush(QColor("#1e293b")))
        painter.drawEllipse(hole_rect)

        # Center text
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(hole_rect, Qt.AlignCenter, f"{self.total_count}\nIssues")

        # Right area: Legend list
        legend_x = chart_rect.right() + 25
        legend_y = 20
        line_height = 18

        painter.setFont(QFont("Segoe UI", 8))
        for sl in self.slices[:10]:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(sl["color"]))
            painter.drawRect(int(legend_x), int(legend_y), 10, 10)

            painter.setPen(QColor("#cbd5e1"))
            text = f"{sl['label']}: {sl['count']}"
            painter.drawText(int(legend_x + 16), int(legend_y + 9), text)
            legend_y += line_height


class ADPasswordAuditorWidget(QWidget):
    """Complete KnowBe4-style Active Directory Weak Password Audit view."""

    findings_generated = Signal(int)

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.auditor = ADPasswordAuditor(db=db)
        self.current_summary: Optional[ADAuditSummary] = None
        self.current_filter_category: str = "All Accounts"
        self._init_ui()
        self.load_default_audit()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.setSpacing(14)

        # Top Header Bar
        hdr_box = QHBoxLayout()
        title = QLabel("🏢 Active Directory & Weak Password Auditor")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setStyleSheet("color: #38bdf8;")
        hdr_box.addWidget(title)
        hdr_box.addStretch()

        self.btn_import_ntds = QPushButton("📥 Import NTDS.dit / SAM")
        self.btn_import_ntds.setStyleSheet(
            "background-color: #334155; color: white; border-radius: 6px; padding: 6px 12px; font-weight: bold;"
        )
        self.btn_import_ntds.clicked.connect(self._import_ntds_dialog)
        hdr_box.addWidget(self.btn_import_ntds)

        self.btn_save_findings = QPushButton("🛡️ Sync to Findings")
        self.btn_save_findings.setStyleSheet(
            "background-color: #0284c7; color: white; border-radius: 6px; padding: 6px 14px; font-weight: bold;"
        )
        self.btn_save_findings.clicked.connect(self._sync_findings_to_project)
        hdr_box.addWidget(self.btn_save_findings)

        root_layout.addLayout(hdr_box)

        # Top Metrics & Chart Panel (Cards matching KnowBe4 layout)
        top_panel = QFrame()
        top_panel.setStyleSheet(
            "QFrame { background-color: #1e293b; border-radius: 10px; border: 1px solid #334155; }"
        )
        top_layout = QHBoxLayout(top_panel)
        top_layout.setContentsMargins(16, 16, 16, 16)
        top_layout.setSpacing(16)

        # 1. Vulnerable Card (Red)
        self.card_vuln = QFrame()
        self.card_vuln.setFixedSize(170, 150)
        self.card_vuln.setStyleSheet(
            "background-color: #dc2626; border-radius: 8px; border: none;"
        )
        v_box = QVBoxLayout(self.card_vuln)
        v_box.setContentsMargins(12, 12, 12, 12)
        lbl_v_title = QLabel("VULNERABLE")
        lbl_v_title.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px;")
        self.lbl_v_count = QLabel("0 accounts")
        self.lbl_v_count.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        v_box.addWidget(lbl_v_title)
        v_box.addWidget(self.lbl_v_count)
        v_box.addStretch()
        top_layout.addWidget(self.card_vuln)

        # 2. Not Vulnerable Card (Green)
        self.card_not_vuln = QFrame()
        self.card_not_vuln.setFixedSize(170, 150)
        self.card_not_vuln.setStyleSheet(
            "background-color: #16a34a; border-radius: 8px; border: none;"
        )
        nv_box = QVBoxLayout(self.card_not_vuln)
        nv_box.setContentsMargins(12, 12, 12, 12)
        lbl_nv_title = QLabel("NOT VULNERABLE")
        lbl_nv_title.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px;")
        self.lbl_nv_count = QLabel("0 accounts")
        self.lbl_nv_count.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")
        nv_box.addWidget(lbl_nv_title)
        nv_box.addWidget(self.lbl_nv_count)
        nv_box.addStretch()
        top_layout.addWidget(self.card_not_vuln)

        # 3. Middle: Donut Pie Chart Widget
        self.chart_widget = DonutPieChartWidget()
        top_layout.addWidget(self.chart_widget, stretch=1)

        # 4. Right: Description & Rerun Test button
        desc_frame = QFrame()
        desc_frame.setStyleSheet("background: transparent; border: none;")
        desc_box = QVBoxLayout(desc_frame)
        desc_box.setContentsMargins(8, 8, 8, 8)
        lbl_desc_title = QLabel("Enterprise AD Password Audit")
        lbl_desc_title.setStyleSheet("color: #f8fafc; font-weight: bold; font-size: 12px;")
        lbl_desc_text = QLabel(
            "Scans Active Directory domain accounts against known passwords, "
            "shared hashes, cleartext values, and Kerberos encryption downgrades."
        )
        lbl_desc_text.setWordWrap(True)
        lbl_desc_text.setStyleSheet("color: #94a3b8; font-size: 10px;")

        self.btn_rerun = QPushButton("🔄 Rerun Audit")
        self.btn_rerun.setStyleSheet(
            "background-color: #ea580c; color: white; border-radius: 6px; padding: 10px 16px; font-weight: bold; font-size: 12px;"
        )
        self.btn_rerun.clicked.connect(self.load_default_audit)

        desc_box.addWidget(lbl_desc_title)
        desc_box.addWidget(lbl_desc_text)
        desc_box.addStretch()
        desc_box.addWidget(self.btn_rerun)
        top_layout.addWidget(desc_frame)

        root_layout.addWidget(top_panel)

        # Bottom Splitter: Category List (Left) and Accounts Matrix (Right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #334155; }")

        # Left Categories Panel
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 8, 0)
        lbl_cat_title = QLabel("Audit Categories")
        lbl_cat_title.setStyleSheet("color: #94a3b8; font-weight: bold; font-size: 11px;")
        left_layout.addWidget(lbl_cat_title)

        self.list_categories = QListWidget()
        self.list_categories.setStyleSheet(
            "QListWidget { background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #f1f5f9; }"
            "QListWidget::item { padding: 8px 10px; border-bottom: 1px solid #334155; }"
            "QListWidget::item:selected { background-color: #ea580c; color: #ffffff; font-weight: bold; border-radius: 4px; }"
        )
        self.list_categories.currentItemChanged.connect(self._on_category_selected)
        left_layout.addWidget(self.list_categories)
        splitter.addWidget(left_widget)

        # Right Accounts Table Panel
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(8, 0, 0, 0)

        # Table Control Bar
        table_bar = QHBoxLayout()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search Account Name...")
        self.txt_search.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; color: white; padding: 6px 10px;"
        )
        self.txt_search.textChanged.connect(self._apply_table_filters)
        table_bar.addWidget(self.txt_search)

        self.btn_export_csv = QPushButton("📊 Export CSV")
        self.btn_export_csv.setStyleSheet(
            "background-color: #334155; color: white; border-radius: 6px; padding: 6px 12px; font-weight: bold;"
        )
        self.btn_export_csv.clicked.connect(self._export_to_csv)
        table_bar.addWidget(self.btn_export_csv)

        right_layout.addLayout(table_bar)

        # Accounts Table Matrix
        self.table_accounts = QTableWidget()
        self.table_accounts.setStyleSheet(
            "QTableWidget { background-color: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #f1f5f9; gridline-color: #1e293b; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; font-weight: bold; border: 1px solid #334155; padding: 4px; font-size: 10px; }"
            "QTableWidget::item { padding: 4px; }"
            "QTableWidget::item:selected { background-color: #0284c7; }"
        )
        headers = [
            "Account Name",
            "Weak Pwd",
            "Shared Pwd",
            "Empty Pwd",
            "Clear Text",
            "Not Req",
            "Never Expires",
            "LM Hash",
            "No AES",
            "DES Only",
            "Missing Pre-Auth",
        ]
        self.table_accounts.setColumnCount(len(headers))
        self.table_accounts.setHorizontalHeaderLabels(headers)
        self.table_accounts.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in range(1, len(headers)):
            self.table_accounts.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)

        right_layout.addWidget(self.table_accounts)
        splitter.addWidget(right_widget)

        splitter.setSizes([260, 680])
        root_layout.addWidget(splitter, stretch=1)

    def load_default_audit(self):
        """Loads and audits default enterprise AD test sample."""
        accounts = self.auditor.get_sample_enterprise_dataset()
        self.current_summary = self.auditor.audit_accounts(accounts)
        self._refresh_ui()

    def _refresh_ui(self):
        if not self.current_summary:
            return

        s = self.current_summary

        # Update KPI Cards
        self.lbl_v_count.setText(f"{s.vulnerable_accounts} accounts")
        self.lbl_nv_count.setText(f"{s.not_vulnerable_accounts} accounts")

        # Update Donut Pie Chart Slices
        slices = [
            {"label": "Weak Password", "count": s.weak_password_count, "color": QColor("#f97316")},
            {"label": "Shared Password", "count": s.shared_password_count, "color": QColor("#38bdf8")},
            {"label": "Empty Password", "count": s.empty_password_count, "color": QColor("#2563eb")},
            {"label": "Clear Text Password", "count": s.clear_text_count, "color": QColor("#22c55e")},
            {"label": "Password Not Required", "count": s.pwd_not_required_count, "color": QColor("#14b8a6")},
            {"label": "Password Never Expires", "count": s.pwd_never_expires_count, "color": QColor("#06b6d4")},
            {"label": "LM Hash Password", "count": s.lm_hash_count, "color": QColor("#a855f7")},
            {"label": "AES Encryption Not Set", "count": s.no_aes_count, "color": QColor("#fbbf24")},
            {"label": "DES-Only Encryption", "count": s.des_only_count, "color": QColor("#ef4444")},
            {"label": "Missing Pre-Authentication", "count": s.missing_preauth_count, "color": QColor("#dc2626")},
        ]
        self.chart_widget.set_data(slices)

        # Update Left Categories List
        self.list_categories.clear()
        categories = [
            ("All Accounts", s.total_accounts),
            ("Weak Password", s.weak_password_count),
            ("Shared Password", s.shared_password_count),
            ("Empty Password", s.empty_password_count),
            ("Clear Text Password", s.clear_text_count),
            ("Password Not Required", s.pwd_not_required_count),
            ("Password Never Expires", s.pwd_never_expires_count),
            ("LM Hash Password", s.lm_hash_count),
            ("AES Encryption Not Set", s.no_aes_count),
            ("DES-Only Encryption", s.des_only_count),
            ("Missing Pre-Authentication", s.missing_preauth_count),
        ]

        for cat_name, count in categories:
            item = QListWidgetItem(f"{cat_name} ({count})")
            item.setData(Qt.UserRole, cat_name)
            self.list_categories.addItem(item)

        self.list_categories.setCurrentRow(0)
        self._apply_table_filters()

    def _on_category_selected(self, current: Optional[QListWidgetItem], previous: Optional[QListWidgetItem]):
        if current:
            self.current_filter_category = current.data(Qt.UserRole)
            self._apply_table_filters()

    def _apply_table_filters(self):
        if not self.current_summary:
            return

        search_text = self.txt_search.text().strip().lower()
        filtered_accounts = []

        for acc in self.current_summary.accounts:
            # Search filter
            if search_text and search_text not in acc.account_name.lower():
                continue

            # Category filter
            cat = self.current_filter_category
            if cat == "Weak Password" and not acc.is_weak_password:
                continue
            elif cat == "Shared Password" and not acc.is_shared_password:
                continue
            elif cat == "Empty Password" and not acc.is_empty_password:
                continue
            elif cat == "Clear Text Password" and not bool(acc.clear_text_password):
                continue
            elif cat == "Password Not Required" and not acc.password_not_required:
                continue
            elif cat == "Password Never Expires" and not acc.password_never_expires:
                continue
            elif cat == "LM Hash Password" and not acc.is_lm_hash_present:
                continue
            elif cat == "AES Encryption Not Set" and acc.aes_encryption_set:
                continue
            elif cat == "DES-Only Encryption" and not acc.des_only_encryption:
                continue
            elif cat == "Missing Pre-Authentication" and not acc.missing_preauth:
                continue

            filtered_accounts.append(acc)

        self.table_accounts.setRowCount(len(filtered_accounts))
        for row, acc in enumerate(filtered_accounts):
            # Column 0: Account Name
            item_name = QTableWidgetItem(acc.account_name)
            item_name.setForeground(QColor("#f8fafc"))
            if acc.is_vulnerable:
                item_name.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.table_accounts.setItem(row, 0, item_name)

            flags = [
                acc.is_weak_password,
                acc.is_shared_password,
                acc.is_empty_password,
                bool(acc.clear_text_password),
                acc.password_not_required,
                acc.password_never_expires,
                acc.is_lm_hash_present,
                not acc.aes_encryption_set,
                acc.des_only_encryption,
                acc.missing_preauth,
            ]

            for col_idx, is_set in enumerate(flags, start=1):
                cell = QTableWidgetItem("✔" if is_set else "")
                cell.setTextAlignment(Qt.AlignCenter)
                if is_set:
                    cell.setForeground(QColor("#ef4444" if col_idx in (1, 3, 9, 10) else "#f97316"))
                    cell.setFont(QFont("Segoe UI", 11, QFont.Bold))
                self.table_accounts.setItem(row, col_idx, cell)

    def _import_ntds_dialog(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Secretsdump / SAM / NTDS Dump", "", "Text Files (*.txt *.dit *.out *.csv);;All Files (*)"
        )
        if filepath:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                accounts = self.auditor.parse_secretsdump_output(content)
                if not accounts:
                    QMessageBox.warning(self, "Import Warning", "No valid accounts parsed from selected file.")
                    return
                self.current_summary = self.auditor.audit_accounts(accounts)
                self._refresh_ui()
                QMessageBox.information(
                    self, "Import Successful", f"Successfully audited {len(accounts)} domain accounts!"
                )
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to read file: {e}")

    def _sync_findings_to_project(self):
        if not self.current_summary:
            QMessageBox.warning(self, "No Data", "Run or import an Active Directory audit first.")
            return

        if not self.db:
            QMessageBox.warning(self, "No Database", "Database connection is not available.")
            return

        projects = self.db.list_projects()
        if not projects:
            QMessageBox.warning(self, "No Project", "Create or open a project before synchronizing findings.")
            return

        active_project = projects[0]
        findings = self.auditor.generate_findings_for_project(
            summary=self.current_summary,
            project_id=active_project.id,
            domain_name="CORP.LOCAL",
        )
        self.findings_generated.emit(len(findings))
        QMessageBox.information(
            self,
            "Findings Synchronized",
            f"Successfully persisted {len(findings)} normalized Active Directory vulnerability findings into Project '{active_project.name}'!",
        )

    def _export_to_csv(self):
        if not self.current_summary:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Results to CSV", "ad_password_audit.csv", "CSV Files (*.csv)"
        )
        if filepath:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Account Name", "Weak Pwd", "Shared Pwd", "Empty Pwd", "Cleartext",
                    "Not Required", "Never Expires", "LM Hash", "No AES", "DES Only", "Missing PreAuth"
                ])
                for acc in self.current_summary.accounts:
                    writer.writerow([
                        acc.account_name,
                        "YES" if acc.is_weak_password else "NO",
                        "YES" if acc.is_shared_password else "NO",
                        "YES" if acc.is_empty_password else "NO",
                        "YES" if acc.clear_text_password else "NO",
                        "YES" if acc.password_not_required else "NO",
                        "YES" if acc.password_never_expires else "NO",
                        "YES" if acc.is_lm_hash_present else "NO",
                        "YES" if not acc.aes_encryption_set else "NO",
                        "YES" if acc.des_only_encryption else "NO",
                        "YES" if acc.missing_preauth else "NO",
                    ])
            QMessageBox.information(self, "Export Complete", f"Exported {len(self.current_summary.accounts)} records to {filepath}")

