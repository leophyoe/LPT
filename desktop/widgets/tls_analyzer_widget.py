"""TLS/SSL Security, Certificate, and Cipher Suite Analyzer Widget.

Professional assessment workspace embedded into CyberSecuritySuite:
- Target selection from active Engagement scope and discovered inventory.
- Hostname, port, and SNI configuration.
- X.509 Certificate Intelligence (Subject, Issuer, SANs, Validity, Key Length, Signature Alg).
- Certificate Chain trust path inspection.
- Protocol support matrix (SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3).
- Cipher suite security evaluation (NULL, EXPORT, Anonymous, RC4, 3DES, CBC, Forward Secrecy).
- Deduplicated security findings with technical remediation advice.
- Cryptographic evidence access with SHA-256 provenance.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
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
    QSplitter,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.base_adapter import SecurityToolResult
from core.scope import ScopeAuthorizationService
from modules.crypto.tls_adapter import TLSAssessmentAdapter
from modules.crypto.tls_analyzer import (
    TLSAssessmentEngine,
    TLSAssessmentReport,
    TLSCertificateInfo,
)
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project

logger = logging.getLogger(__name__)


class TLSWorkerThread(QThread):
    """Executes TLS assessment off the Qt GUI thread."""

    progress_signal = Signal(str, str)
    finished_signal = Signal(object, object)  # (SecurityToolResult, TLSAssessmentReport)

    def __init__(
        self,
        adapter: TLSAssessmentAdapter,
        project_id: int,
        target_host: str,
        port: int,
        timeout: float = 3.0,
    ):
        super().__init__()
        self.adapter = adapter
        self.project_id = project_id
        self.target_host = target_host
        self.port = port
        self.timeout = timeout
        self._is_cancelled = False

    def run(self):
        try:
            # 1. Run engine to get rich report
            self.progress_signal.emit(f"[*] Starting assessment on {self.target_host}:{self.port}...", "stdout")
            report = TLSAssessmentEngine.assess_target(
                project_id=self.project_id,
                target_host=self.target_host,
                port=self.port,
                timeout=self.timeout,
            )

            # 2. Run adapter for scope, evidence vaulting, and DB persistence
            tool_result = self.adapter.assess_target(
                project_id=self.project_id,
                target_host=self.target_host,
                port=self.port,
                timeout=self.timeout,
                output_callback=lambda msg, stream: self.progress_signal.emit(msg.strip(), stream),
            )

            self.finished_signal.emit(tool_result, report)
        except Exception as exc:
            logger.exception(f"TLSWorkerThread exception: {exc}")
            self.progress_signal.emit(f"[-] Execution failure: {exc}", "stderr")
            err_res = SecurityToolResult(
                tool_name="tls_analyzer",
                target=f"{self.target_host}:{self.port}",
                is_authorized=False,
                scope_reason=str(exc),
                execution_status=None,
                error_message=str(exc),
            )
            self.finished_signal.emit(err_res, None)


class TLSAnalyzerWidget(QWidget):
    """Interactive TLS/SSL Security & Cryptographic Cipher Suite Analyzer."""

    assessment_completed = Signal(object)  # Emits SecurityToolResult

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.adapter = TLSAssessmentAdapter(db=self.db)
        self.worker: Optional[TLSWorkerThread] = None
        self.last_report: Optional[TLSAssessmentReport] = None
        self.last_result: Optional[SecurityToolResult] = None

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        """Sets the active project context and updates candidate target assets."""
        self.active_project = project
        if project:
            self.lbl_project_badge.setText(f"Active Project: <b>{project.name}</b> (ID: {project.id})")
            self.lbl_project_badge.setStyleSheet("color: #38bdf8; font-size: 11px;")
        else:
            self.lbl_project_badge.setText("Active Project: <i>None selected</i>")
            self.lbl_project_badge.setStyleSheet("color: #f87171; font-size: 11px;")

        self._refresh_target_candidates()
        self._validate_scope_preview()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # 1. Top Header Bar
        header_bar = QHBoxLayout()
        self.lbl_project_badge = QLabel("Active Project: <i>None selected</i>")
        header_bar.addWidget(self.lbl_project_badge)
        header_bar.addStretch()

        badge_safe = QLabel("🔒 SAFE TLS ASSESSMENT — NON-DESTRUCTIVE")
        badge_safe.setStyleSheet(
            "font-size: 10px; font-weight: bold; padding: 2px 8px; border-radius: 4px; "
            "background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #059669;"
        )
        header_bar.addWidget(badge_safe)
        main_layout.addLayout(header_bar)

        # 2. Main Horizontal Splitter (Configuration vs Results)
        splitter = QSplitter(Qt.Horizontal)

        # -------------------------------------------------------------
        # Left Panel: Assessment Target & Configuration
        # -------------------------------------------------------------
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(4, 4, 4, 4)
        left_layout.setSpacing(6)

        config_group = QGroupBox("Target & Connection Settings")
        cfg_layout = QGridLayout(config_group)
        cfg_layout.setSpacing(6)

        cfg_layout.addWidget(QLabel("Select Authorized Asset:"), 0, 0)
        self.combo_assets = QComboBox()
        self.combo_assets.currentIndexChanged.connect(self._on_asset_selected)
        cfg_layout.addWidget(self.combo_assets, 0, 1)

        cfg_layout.addWidget(QLabel("Target Host / Domain:"), 1, 0)
        self.edit_host = QLineEdit()
        self.edit_host.setPlaceholderText("e.g. 192.168.1.10 or web.corp.local")
        self.edit_host.textChanged.connect(self._validate_scope_preview)
        cfg_layout.addWidget(self.edit_host, 1, 1)

        cfg_layout.addWidget(QLabel("TLS Service Port:"), 2, 0)
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(443)
        cfg_layout.addWidget(self.spin_port, 2, 1)

        cfg_layout.addWidget(QLabel("Connection Timeout (s):"), 3, 0)
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(1, 30)
        self.spin_timeout.setValue(3)
        cfg_layout.addWidget(self.spin_timeout, 3, 1)

        # Scope Preview
        self.lbl_scope_status = QLabel("Scope Status: Unchecked")
        self.lbl_scope_status.setStyleSheet("font-size: 11px; color: #94a3b8;")
        cfg_layout.addWidget(self.lbl_scope_status, 4, 0, 1, 2)

        left_layout.addWidget(config_group)

        # Action Buttons
        btn_box = QHBoxLayout()
        self.btn_run = QPushButton("🔒 Run TLS Assessment")
        self.btn_run.setStyleSheet(
            "QPushButton { background: #0284c7; color: white; font-weight: bold; padding: 6px 12px; border-radius: 4px; }"
            "QPushButton:hover { background: #0369a1; }"
            "QPushButton:disabled { background: #334155; color: #64748b; }"
        )
        self.btn_run.clicked.connect(self._start_assessment)
        btn_box.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_assessment)
        btn_box.addWidget(self.btn_stop)
        left_layout.addLayout(btn_box)

        # Execution Progress & Status
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)

        self.lbl_exec_status = QLabel("Ready for target assessment.")
        self.lbl_exec_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        left_layout.addWidget(self.lbl_exec_status)

        # Live Execution Log
        left_layout.addWidget(QLabel("Execution Activity Log:"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet(
            "QTextEdit { background-color: #0b0f19; color: #38bdf8; font-family: monospace; font-size: 11px; border: 1px solid #1e293b; }"
        )
        left_layout.addWidget(self.txt_log, 1)

        splitter.addWidget(left_widget)

        # -------------------------------------------------------------
        # Right Panel: Results & Intelligence Workspace
        # -------------------------------------------------------------
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(4, 4, 4, 4)
        right_layout.setSpacing(6)

        # Overview Banner
        self.banner = QFrame()
        self.banner.setStyleSheet(
            "QFrame { background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; }"
        )
        banner_layout = QHBoxLayout(self.banner)
        banner_layout.setContentsMargins(8, 4, 8, 4)

        self.lbl_posture = QLabel("Overall Posture: UNASSESSED")
        self.lbl_posture.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.lbl_posture.setStyleSheet("color: #94a3b8;")
        banner_layout.addWidget(self.lbl_posture)
        banner_layout.addStretch()

        self.lbl_cert_badge = QLabel("Cert Status: -")
        self.lbl_cert_badge.setStyleSheet(
            "font-size: 11px; padding: 3px 8px; background: #1e293b; color: #cbd5e1; border-radius: 4px;"
        )
        banner_layout.addWidget(self.lbl_cert_badge)
        right_layout.addWidget(self.banner)

        # Tabbed Workspace
        self.tabs = QTabWidget()

        # Tab 1: Certificate Intelligence
        self.tab_cert = QWidget()
        self._init_cert_tab()
        self.tabs.addTab(self.tab_cert, "📜 Certificate Intelligence")

        # Tab 2: Certificate Chain
        self.tab_chain = QWidget()
        self._init_chain_tab()
        self.tabs.addTab(self.tab_chain, "🔗 Certificate Chain")

        # Tab 3: Protocol Support Matrix
        self.tab_protocols = QWidget()
        self._init_protocols_tab()
        self.tabs.addTab(self.tab_protocols, "🌐 Protocol Support Matrix")

        # Tab 4: Cipher Suite Security
        self.tab_ciphers = QWidget()
        self._init_ciphers_tab()
        self.tabs.addTab(self.tab_ciphers, "🔐 Cipher Suite Security")

        # Tab 5: Security Findings
        self.tab_findings = QWidget()
        self._init_findings_tab()
        self.tabs.addTab(self.tab_findings, "🛡️ Security Findings")

        # Tab 6: Cryptographic Evidence
        self.tab_evidence = QWidget()
        self._init_evidence_tab()
        self.tabs.addTab(self.tab_evidence, "📋 Cryptographic Evidence")

        right_layout.addWidget(self.tabs, 1)
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 7)
        main_layout.addWidget(splitter, 1)

    # -----------------------------------------------------------------
    # Tab Initializers
    # -----------------------------------------------------------------
    def _init_cert_tab(self):
        layout = QVBoxLayout(self.tab_cert)
        layout.setContentsMargins(6, 6, 6, 6)

        grid = QGridLayout()
        grid.setSpacing(6)

        self.lbl_cn = QLabel("-")
        self.lbl_issuer = QLabel("-")
        self.lbl_validity = QLabel("-")
        self.lbl_days = QLabel("-")
        self.lbl_key = QLabel("-")
        self.lbl_sig_alg = QLabel("-")
        self.lbl_serial = QLabel("-")
        self.lbl_sans = QLabel("-")
        self.lbl_fingerprint = QLabel("-")

        for lbl in (self.lbl_cn, self.lbl_issuer, self.lbl_validity, self.lbl_days,
                    self.lbl_key, self.lbl_sig_alg, self.lbl_serial, self.lbl_sans, self.lbl_fingerprint):
            lbl.setStyleSheet("color: #f8fafc; font-weight: bold;")

        grid.addWidget(QLabel("Common Name (CN):"), 0, 0)
        grid.addWidget(self.lbl_cn, 0, 1)

        grid.addWidget(QLabel("Issuer:"), 1, 0)
        grid.addWidget(self.lbl_issuer, 1, 1)

        grid.addWidget(QLabel("Validity Dates:"), 2, 0)
        grid.addWidget(self.lbl_validity, 2, 1)

        grid.addWidget(QLabel("Days Remaining:"), 3, 0)
        grid.addWidget(self.lbl_days, 3, 1)

        grid.addWidget(QLabel("Public Key & Size:"), 4, 0)
        grid.addWidget(self.lbl_key, 4, 1)

        grid.addWidget(QLabel("Signature Algorithm:"), 5, 0)
        grid.addWidget(self.lbl_sig_alg, 5, 1)

        grid.addWidget(QLabel("Serial Number:"), 6, 0)
        grid.addWidget(self.lbl_serial, 6, 1)

        grid.addWidget(QLabel("Subject Alt Names (SAN):"), 7, 0)
        grid.addWidget(self.lbl_sans, 7, 1)

        grid.addWidget(QLabel("SHA-256 Fingerprint:"), 8, 0)
        grid.addWidget(self.lbl_fingerprint, 8, 1)

        layout.addLayout(grid)
        layout.addStretch()

    def _init_chain_tab(self):
        layout = QVBoxLayout(self.tab_chain)
        layout.setContentsMargins(6, 6, 6, 6)

        self.table_chain = QTableWidget()
        self.table_chain.setColumnCount(4)
        self.table_chain.setHorizontalHeaderLabels(["Tier", "Subject / Entity", "Issuer", "Trust State"])
        self.table_chain.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_chain.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.table_chain)

    def _init_protocols_tab(self):
        layout = QVBoxLayout(self.tab_protocols)
        layout.setContentsMargins(6, 6, 6, 6)

        self.table_protocols = QTableWidget()
        self.table_protocols.setColumnCount(4)
        self.table_protocols.setHorizontalHeaderLabels(["Protocol Version", "Support Status", "Negotiated Cipher", "Evaluation Notes"])
        self.table_protocols.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.table_protocols)

    def _init_ciphers_tab(self):
        layout = QVBoxLayout(self.tab_ciphers)
        layout.setContentsMargins(6, 6, 6, 6)

        self.table_ciphers = QTableWidget()
        self.table_ciphers.setColumnCount(4)
        self.table_ciphers.setHorizontalHeaderLabels(["Cipher Category", "Negotiation Status", "Sample Negotiated Cipher", "Security Impact"])
        self.table_ciphers.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.table_ciphers)

    def _init_findings_tab(self):
        layout = QVBoxLayout(self.tab_findings)
        layout.setContentsMargins(6, 6, 6, 6)

        self.table_findings = QTableWidget()
        self.table_findings.setColumnCount(5)
        self.table_findings.setHorizontalHeaderLabels(["Severity", "Vulnerability Title", "Affected Asset", "CVSS", "Remediation"])
        self.table_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_findings.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(self.table_findings)

    def _init_evidence_tab(self):
        layout = QVBoxLayout(self.tab_evidence)
        layout.setContentsMargins(6, 6, 6, 6)

        top_ev = QHBoxLayout()
        self.lbl_ev_hash = QLabel("Evidence SHA-256: None")
        self.lbl_ev_hash.setStyleSheet("font-family: monospace; color: #a855f7;")
        top_ev.addWidget(self.lbl_ev_hash)
        top_ev.addStretch()

        btn_copy = QPushButton("Copy Hash")
        btn_copy.clicked.connect(self._copy_evidence_hash)
        top_ev.addWidget(btn_copy)

        btn_export = QPushButton("Export Evidence JSON")
        btn_export.clicked.connect(self._export_evidence_json)
        top_ev.addWidget(btn_export)
        layout.addLayout(top_ev)

        self.txt_evidence = QTextEdit()
        self.txt_evidence.setReadOnly(True)
        self.txt_evidence.setStyleSheet(
            "QTextEdit { background-color: #0b0f19; color: #cbd5e1; font-family: monospace; font-size: 11px; border: 1px solid #1e293b; }"
        )
        layout.addWidget(self.txt_evidence, 1)

    # -----------------------------------------------------------------
    # Scope & Selection Helpers
    # -----------------------------------------------------------------
    def _refresh_target_candidates(self):
        """Populates combo_assets from active project nodes and scopes."""
        self.combo_assets.blockSignals(True)
        self.combo_assets.clear()
        self.combo_assets.addItem("-- Select Discovered Target --", "")

        if self.db and self.active_project:
            nodes = self.db.list_asset_nodes(self.active_project.id)
            candidates = set()
            for n in nodes:
                if n.node_type in ("ip", "domain", "subdomain", "computer", "domain_controller"):
                    candidates.add(n.value)

            for cand in sorted(candidates):
                self.combo_assets.addItem(cand, cand)

        self.combo_assets.blockSignals(False)

    def _on_asset_selected(self, index: int):
        val = self.combo_assets.currentData()
        if val:
            self.edit_host.setText(str(val))

    def _validate_scope_preview(self):
        """Checks scope for live target preview."""
        target = self.edit_host.text().strip()
        if not target:
            self.lbl_scope_status.setText("Scope Status: Target empty")
            self.lbl_scope_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.btn_run.setEnabled(False)
            return

        if not self.active_project or not self.db:
            self.lbl_scope_status.setText("Scope Status: No active project context")
            self.lbl_scope_status.setStyleSheet("color: #f59e0b; font-size: 11px;")
            self.btn_run.setEnabled(False)
            return

        scopes = self.db.list_scopes(self.active_project.id)
        res = ScopeAuthorizationService.is_target_authorized(target, scopes, project=self.active_project)

        if res.is_allowed:
            self.lbl_scope_status.setText(f"Scope Status: 🟢 AUTHORIZED ({res.reason})")
            self.lbl_scope_status.setStyleSheet("color: #10b981; font-size: 11px; font-weight: bold;")
            self.btn_run.setEnabled(True)
        else:
            self.lbl_scope_status.setText(f"Scope Status: 🔴 RESTRICTED ({res.reason})")
            self.lbl_scope_status.setStyleSheet("color: #f87171; font-size: 11px; font-weight: bold;")
            self.btn_run.setEnabled(False)

    # -----------------------------------------------------------------
    # Execution Triggers
    # -----------------------------------------------------------------
    def _start_assessment(self):
        """Launches assessment in background worker thread."""
        target_host = self.edit_host.text().strip()
        port = self.spin_port.value()
        timeout = float(self.spin_timeout.value())

        if not target_host or not self.active_project:
            return

        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.lbl_exec_status.setText(f"Connecting to {target_host}:{port}...")
        self.txt_log.clear()

        self.worker = TLSWorkerThread(
            adapter=self.adapter,
            project_id=self.active_project.id,
            target_host=target_host,
            port=port,
            timeout=timeout,
        )
        self.worker.progress_signal.connect(self._on_worker_progress)
        self.worker.finished_signal.connect(self._on_worker_finished)
        self.worker.start()

    def _stop_assessment(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
            self._on_worker_finished(None, None)
            self.lbl_exec_status.setText("Assessment aborted by user.")

    def _on_worker_progress(self, msg: str, stream: str):
        color = "#10b981" if stream == "success" else ("#f87171" if stream == "stderr" else "#38bdf8")
        self.txt_log.append(f"<span style='color:{color}'>{msg}</span>")

    def _on_worker_finished(
        self,
        tool_res: Optional[SecurityToolResult],
        report: Optional[TLSAssessmentReport],
    ):
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)

        self.last_result = tool_res
        self.last_report = report

        if report:
            self._render_report(report)
            self.lbl_exec_status.setText("Assessment concluded successfully.")
            if tool_res:
                self.assessment_completed.emit(tool_res)
        elif tool_res and not tool_res.is_authorized:
            self.lbl_exec_status.setText(f"Failed: {tool_res.scope_reason}")
            QMessageBox.warning(self, "Scope Violation", f"Target is outside authorized scope:\n{tool_res.scope_reason}")
        else:
            self.lbl_exec_status.setText("Assessment failed or returned no results.")

    # -----------------------------------------------------------------
    # UI Rendering
    # -----------------------------------------------------------------
    def _render_report(self, r: TLSAssessmentReport):
        # 1. Posture & Badges
        if r.overall_posture == "SECURE":
            self.lbl_posture.setText("🛡️ Overall Posture: SECURE (Compliant)")
            self.lbl_posture.setStyleSheet("color: #10b981; font-weight: bold;")
        elif r.overall_posture == "NEEDS_HARDENING":
            self.lbl_posture.setText("⚠️ Overall Posture: NEEDS HARDENING")
            self.lbl_posture.setStyleSheet("color: #f59e0b; font-weight: bold;")
        else:
            self.lbl_posture.setText("🚨 Overall Posture: INSECURE (High Risk)")
            self.lbl_posture.setStyleSheet("color: #f87171; font-weight: bold;")

        cert = r.certificate
        if cert:
            status_text = cert.validation_status.upper()
            color = "#10b981" if cert.validation_status == "valid" else "#f87171"
            self.lbl_cert_badge.setText(f"Cert Status: {status_text}")
            self.lbl_cert_badge.setStyleSheet(f"font-size: 11px; padding: 3px 8px; background: rgba(0,0,0,0.3); color: {color}; border-radius: 4px; border: 1px solid {color};")

            # 2. Certificate Details
            self.lbl_cn.setText(cert.subject.get("commonName", "-"))
            self.lbl_issuer.setText(f"{cert.issuer.get('commonName', '-')} ({cert.issuer.get('organizationName', '-')})")
            self.lbl_validity.setText(f"{cert.not_before or '-'} → {cert.not_after or '-'}")
            days_color = "#10b981" if cert.days_until_expiration > 30 else ("#f59e0b" if cert.days_until_expiration > 0 else "#f87171")
            self.lbl_days.setText(f"{cert.days_until_expiration} days" if not cert.is_expired else "EXPIRED")
            self.lbl_days.setStyleSheet(f"color: {days_color}; font-weight: bold;")

            self.lbl_key.setText(f"{cert.public_key_algorithm} ({cert.public_key_bits} bits)")
            self.lbl_sig_alg.setText(cert.signature_algorithm)
            self.lbl_serial.setText(cert.serial_number or "-")
            self.lbl_sans.setText(", ".join(cert.subject_alt_names) if cert.subject_alt_names else "None (Legacy CN only)")
            self.lbl_fingerprint.setText(cert.sha256_fingerprint or "-")

            # 3. Chain Table
            self.table_chain.setRowCount(0)
            self.table_chain.insertRow(0)
            self.table_chain.setItem(0, 0, QTableWidgetItem("Leaf (Entity)"))
            self.table_chain.setItem(0, 1, QTableWidgetItem(cert.subject.get("commonName", "-")))
            self.table_chain.setItem(0, 2, QTableWidgetItem(cert.issuer.get("commonName", "-")))
            trust_item = QTableWidgetItem(cert.validation_status.upper())
            trust_item.setForeground(QColor("#10b981" if cert.validation_status == "valid" else "#f87171"))
            self.table_chain.setItem(0, 3, trust_item)

            if not cert.is_self_signed:
                self.table_chain.insertRow(1)
                self.table_chain.setItem(1, 0, QTableWidgetItem("Issuer (CA)"))
                self.table_chain.setItem(1, 1, QTableWidgetItem(cert.issuer.get("commonName", "-")))
                self.table_chain.setItem(1, 2, QTableWidgetItem(cert.issuer.get("organizationName", "-")))
                self.table_chain.setItem(1, 3, QTableWidgetItem("ANCHOR"))

        # 4. Protocols Table
        self.table_protocols.setRowCount(0)
        for row, p in enumerate(r.protocols):
            self.table_protocols.insertRow(row)
            self.table_protocols.setItem(row, 0, QTableWidgetItem(p.protocol_version))

            st_item = QTableWidgetItem(p.status.upper())
            if p.status == "supported":
                st_item.setForeground(QColor("#f87171" if p.protocol_version in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") else "#10b981"))
            elif p.status == "rejected":
                st_item.setForeground(QColor("#94a3b8"))
            else:
                st_item.setForeground(QColor("#64748b"))
            self.table_protocols.setItem(row, 1, st_item)

            self.table_protocols.setItem(row, 2, QTableWidgetItem(p.negotiated_cipher or "-"))
            self.table_protocols.setItem(row, 3, QTableWidgetItem(p.notes or "-"))

        # 5. Ciphers Table
        self.table_ciphers.setRowCount(0)
        for row, c in enumerate(r.cipher_groups):
            self.table_ciphers.insertRow(row)
            self.table_ciphers.setItem(row, 0, QTableWidgetItem(c.category.upper()))

            st_item = QTableWidgetItem(c.status.upper())
            if c.status == "supported":
                st_item.setForeground(QColor("#10b981" if c.category == "forward_secrecy" else "#f87171"))
            elif c.status == "rejected":
                st_item.setForeground(QColor("#f87171" if c.category == "forward_secrecy" else "#10b981"))
            else:
                st_item.setForeground(QColor("#64748b"))
            self.table_ciphers.setItem(row, 1, st_item)

            self.table_ciphers.setItem(row, 2, QTableWidgetItem(", ".join(c.negotiated_ciphers) or "-"))
            self.table_ciphers.setItem(row, 3, QTableWidgetItem(c.description))

        # 6. Findings Table
        self.table_findings.setRowCount(0)
        for row, f in enumerate(r.findings):
            self.table_findings.insertRow(row)

            sev_item = QTableWidgetItem(f.severity.value.upper())
            if f.severity == FindingSeverity.CRITICAL:
                sev_item.setForeground(QColor("#dc2626"))
            elif f.severity == FindingSeverity.HIGH:
                sev_item.setForeground(QColor("#f87171"))
            elif f.severity == FindingSeverity.MEDIUM:
                sev_item.setForeground(QColor("#f59e0b"))
            else:
                sev_item.setForeground(QColor("#38bdf8"))
            self.table_findings.setItem(row, 0, sev_item)

            self.table_findings.setItem(row, 1, QTableWidgetItem(f.title))
            self.table_findings.setItem(row, 2, QTableWidgetItem(f.affected_asset))
            self.table_findings.setItem(row, 3, QTableWidgetItem(str(f.cvss_score or "-")))
            self.table_findings.setItem(row, 4, QTableWidgetItem(f.remediation))

        # 7. Evidence
        if self.last_result and self.last_result.evidence_hash:
            self.lbl_ev_hash.setText(f"Evidence SHA-256: {self.last_result.evidence_hash}")
        elif r.evidence_payload:
            import hashlib
            h = hashlib.sha256(r.evidence_payload.encode("utf-8")).hexdigest()
            self.lbl_ev_hash.setText(f"Evidence SHA-256: {h}")

        self.txt_evidence.setText(r.evidence_payload or "")

    def _copy_evidence_hash(self):
        text = self.lbl_ev_hash.text().replace("Evidence SHA-256: ", "").strip()
        if text and text != "None":
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", f"Copied evidence hash to clipboard:\n{text}")

    def _export_evidence_json(self):
        if not self.last_report or not self.last_report.evidence_payload:
            QMessageBox.warning(self, "No Evidence", "No assessment evidence available to export.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export TLS Cryptographic Evidence", "tls_evidence.json", "JSON Files (*.json)"
        )
        if filename:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.last_report.evidence_payload)
            QMessageBox.information(self, "Export Succeeded", f"Evidence vaulted to:\n{filename}")

