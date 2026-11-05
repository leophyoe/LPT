"""Strix-inspired finding triage and remediation dialog."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.strix_triage import StrixTriageEngine, TriagedFinding
from desktop.theme import CPENTTheme, get_badge_qss
from storage.db import Database
from storage.models import Finding, ValidationStatus


class StrixTriageDialog(QDialog):
    """Deep-dive triage dialog presenting CVSS v3.1 evaluation and remediation snippets."""

    def __init__(self, finding: Finding, db: Optional[Database] = None, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.db = db
        self.engine = StrixTriageEngine()
        self.triaged: TriagedFinding = self.engine.triage(finding)

        self.setWindowTitle(f"Strix AI Triage — {finding.title}")
        self.resize(780, 680)
        self.setObjectName("strixTriageDialog")
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        # Header with Title and Severity
        header_card = QFrame()
        header_card.setObjectName("dashboardPanel")
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(16, 14, 16, 14)

        top_row = QHBoxLayout()
        sev = self.finding.severity.value.upper()

        sev_badge = QLabel(f"  {sev}  ")
        sev_badge.setStyleSheet(get_badge_qss(sev))
        top_row.addWidget(sev_badge)

        cvss_badge = QLabel(f" CVSS v3.1: {self.triaged.cvss_score:.1f} ")
        cvss_badge.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.PRIMARY_TEXT}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 4px; font-weight: bold; font-size: 11px; padding: 3px 6px;"
        )
        top_row.addWidget(cvss_badge)

        owasp_badge = QLabel(f" {self.triaged.owasp_category} ")
        owasp_badge.setStyleSheet(
            f"background-color: {CPENTTheme.PANEL_BG}; color: {CPENTTheme.PRIMARY_BLUE}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 4px; font-size: 11px; padding: 3px 6px;"
        )
        top_row.addWidget(owasp_badge)
        top_row.addStretch()

        status_lbl = QLabel(f"Status: {self.finding.validation_status.value.upper()}")
        status_lbl.setStyleSheet(get_badge_qss(self.finding.validation_status.value))
        top_row.addWidget(status_lbl)
        header_layout.addLayout(top_row)

        title_lbl = QLabel(self.finding.title)
        title_lbl.setStyleSheet(f"font-size: 17px; font-weight: bold; color: {CPENTTheme.PRIMARY_TEXT}; font-family: {CPENTTheme.FONT_FAMILY_HEADING}; margin-top: 6px;")
        title_lbl.setWordWrap(True)
        header_layout.addWidget(title_lbl)

        meta_row = QHBoxLayout()
        target_info = QLabel(f"Target: {self.finding.affected_asset or 'N/A'}")
        target_info.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 12px;")
        meta_row.addWidget(target_info)

        if self.finding.source_tool:
            tool_info = QLabel(f"·  Source: {self.finding.source_tool}")
            tool_info.setStyleSheet("color: #a59cb8; font-size: 12px;")
            meta_row.addWidget(tool_info)
        meta_row.addStretch()

        fp_text = "⚠️ Likely False Positive" if self.triaged.is_likely_false_positive else "✓ Verified Vulnerability"
        fp_color = "#f87171" if self.triaged.is_likely_false_positive else "#4ade80"
        fp_lbl = QLabel(f"{fp_text} ({self.triaged.confidence} Confidence)")
        fp_lbl.setStyleSheet(f"color: {fp_color}; font-size: 12px; font-weight: 600;")
        meta_row.addWidget(fp_lbl)
        header_layout.addLayout(meta_row)

        root.addWidget(header_card)

        # Scrollable Content Area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(14)

        # CVSS Vector
        cvss_box = QFrame()
        cvss_box.setObjectName("dashboardPanel")
        cvss_l = QVBoxLayout(cvss_box)
        cvss_l.setContentsMargins(14, 10, 14, 10)
        cvss_title = QLabel("CVSS Vector & Metrics")
        cvss_title.setStyleSheet("font-weight: 600; color: #ded8ee;")
        cvss_val = QLabel(self.triaged.cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        cvss_val.setStyleSheet("font-family: monospace; color: #a5b4fc; font-size: 11px;")
        cvss_l.addWidget(cvss_title)
        cvss_l.addWidget(cvss_val)
        content_layout.addWidget(cvss_box)

        # Description
        desc_box = QFrame()
        desc_box.setObjectName("dashboardPanel")
        desc_l = QVBoxLayout(desc_box)
        desc_l.setContentsMargins(14, 12, 14, 12)
        desc_title = QLabel("Vulnerability Description & Impact")
        desc_title.setStyleSheet("font-weight: 600; color: #ded8ee;")
        desc_l.addWidget(desc_title)

        desc_text = QLabel(self.finding.description or "No extended description provided by scanner.")
        desc_text.setWordWrap(True)
        desc_text.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        desc_l.addWidget(desc_text)
        content_layout.addWidget(desc_box)

        # Remediation Guidance
        rem_box = QFrame()
        rem_box.setObjectName("dashboardPanel")
        rem_l = QVBoxLayout(rem_box)
        rem_l.setContentsMargins(14, 12, 14, 12)
        rem_title = QLabel("Strix Remediation Strategy")
        rem_title.setStyleSheet("font-weight: 600; color: #34d399;")
        rem_l.addWidget(rem_title)

        rem_summary = QLabel(self.triaged.remediation_summary)
        rem_summary.setWordWrap(True)
        rem_summary.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        rem_l.addWidget(rem_summary)

        # Remediation Snippet if available
        if self.triaged.remediation_snippet:
            snippet_title = QLabel("Recommended Fix Snippet:")
            snippet_title.setStyleSheet("color: #94a3b8; font-size: 11px; margin-top: 6px;")
            rem_l.addWidget(snippet_title)

            self.snippet_edit = QTextEdit()
            self.snippet_edit.setPlainText(self.triaged.remediation_snippet)
            self.snippet_edit.setReadOnly(True)
            self.snippet_edit.setStyleSheet(
                "background-color: #0b0718; color: #a5f3fc; font-family: monospace; "
                "font-size: 11px; border: 1px solid #332848; border-radius: 5px;"
            )
            self.snippet_edit.setMaximumHeight(140)
            rem_l.addWidget(self.snippet_edit)

            btn_copy = QPushButton("📋 Copy Snippet")
            btn_copy.setProperty("class", "action-secondary")
            btn_copy.clicked.connect(self._copy_snippet)
            rem_l.addWidget(btn_copy, alignment=Qt.AlignmentFlag.AlignRight)

        content_layout.addWidget(rem_box)
        scroll.setWidget(content_widget)
        root.addWidget(scroll, 1)

        # Footer Actions
        footer = QHBoxLayout()
        footer.setSpacing(10)

        self.btn_confirm = QPushButton("✓ Mark Confirmed")
        self.btn_confirm.setProperty("class", "action-primary")
        self.btn_confirm.clicked.connect(lambda: self._set_status(ValidationStatus.CONFIRMED))
        footer.addWidget(self.btn_confirm)

        self.btn_remediate = QPushButton("🛡️ Mark Remediated")
        self.btn_remediate.setProperty("class", "action-secondary")
        self.btn_remediate.clicked.connect(lambda: self._set_status(ValidationStatus.REMEDIATED))
        footer.addWidget(self.btn_remediate)

        self.btn_fp = QPushButton("✕ Mark False Positive")
        self.btn_fp.setProperty("class", "action-secondary")
        self.btn_fp.clicked.connect(lambda: self._set_status(ValidationStatus.FALSE_POSITIVE))
        footer.addWidget(self.btn_fp)

        footer.addStretch()

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        footer.addWidget(btn_close)

        root.addLayout(footer)

    def _copy_snippet(self):
        clipboard = QApplication.clipboard()
        if clipboard and self.triaged.remediation_snippet:
            clipboard.setText(self.triaged.remediation_snippet)
            QMessageBox.information(self, "Copied", "Remediation snippet copied to clipboard.")

    def _set_status(self, status: ValidationStatus):
        if self.db and self.finding.id is not None:
            self.db.update_finding_status(self.finding.id, status)
            self.finding.validation_status = status
            self.accept()
        else:
            self.finding.validation_status = status
            self.accept()
