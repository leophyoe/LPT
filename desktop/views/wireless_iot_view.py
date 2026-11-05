"""Wireless & IoT / Embedded Firmware Security Analysis Workbench.

Provides interactive UI controls and telemetry inspectors for:
1. 802.11 Wireless PCAP dissection, Access Point inventory, and WPA 4-Way Handshake validation.
2. Hashcat mode 22000 crackable hash export.
3. Wireless anomaly detection (Evil Twin / Rogue AP and Deauth Floods).
4. IoT Firmware header analysis, filesystem component mapping, and architecture detection.
5. Deep static secret scanner (/etc/shadow hashes, private keys, hardcoded credentials, telnetd).
6. Evidence Vault registration with cryptographic SHA-256 integrity assurance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, Signal
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
from modules.iot.firmware_analyzer import (
    FirmwareAnalysisResult,
    FirmwareAnalyzer,
    FirmwareComponent,
    FirmwareSecretFinding,
)
from modules.wireless.wireless_analyzer import (
    AccessPointInfo,
    EAPOLHandshake,
    WirelessAnalysisResult,
    WirelessAnalyzer,
)
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project


class WirelessIoTView(QWidget):
    """Unified desktop workbench for 802.11 Wireless and IoT Firmware Security."""

    findings_updated = Signal()

    def __init__(self, db: Database, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.wireless_analyzer = WirelessAnalyzer(db=db)
        self.firmware_analyzer = FirmwareAnalyzer(db=db)

        self._last_wireless_result: Optional[WirelessAnalysisResult] = None
        self._last_firmware_result: Optional[FirmwareAnalysisResult] = None

        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        """Binds active project to workbench and updates scope status."""
        self.active_project = project
        self._update_scope_badge()

    def update_theme(self, mode: Optional[str] = None):
        """Refreshes high-contrast badges and table colors on theme change."""
        self._update_scope_badge()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 14, 16, 14)
        main_layout.setSpacing(10)

        # Header bar with Project Indicator and Scope Guard
        header_row = QHBoxLayout()
        title_lbl = QLabel("Wireless & IoT / Firmware Security Workbench")
        title_lbl.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {CPENTTheme.PRIMARY_TEXT};")
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        self.scope_badge = QLabel("● Scope: Unbound")
        self.scope_badge.setStyleSheet(
            "font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; "
            "background-color: #3f3f46; color: #ffffff;"
        )
        header_row.addWidget(self.scope_badge)
        main_layout.addLayout(header_row)

        # Workspace Tab Widget
        self.tabs = QTabWidget()
        self.wireless_tab = self._create_wireless_tab()
        self.firmware_tab = self._create_firmware_tab()

        self.tabs.addTab(self.wireless_tab, "📡 802.11 Wireless & Handshakes")
        self.tabs.addTab(self.firmware_tab, "🔬 IoT & Firmware Security")
        main_layout.addWidget(self.tabs, 1)

    def _update_scope_badge(self):
        if not self.active_project:
            self.scope_badge.setText("● Scope: No Active Project")
            self.scope_badge.setStyleSheet(
                "font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; "
                "background-color: #52525b; color: #ffffff;"
            )
        else:
            scopes = self.db.list_scopes(self.active_project.id)
            if scopes:
                self.scope_badge.setText(f"● Scope: Authorized ({len(scopes)} Rules)")
                self.scope_badge.setStyleSheet(
                    "font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; "
                    "background-color: #065f46; color: #a7f3d0; border: 1px solid #10b981;"
                )
            else:
                self.scope_badge.setText("● Scope: Warning (0 Rules Defined)")
                self.scope_badge.setStyleSheet(
                    "font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; "
                    "background-color: #854d0e; color: #fef08a; border: 1px solid #ca8a04;"
                )

    # =========================================================================
    # Tab 1: 802.11 Wireless & EAPOL Handshakes Tab
    # =========================================================================

    def _create_wireless_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Controller Card
        ctrl_card = QFrame()
        ctrl_card.setObjectName("wirelessCtrlCard")
        ctrl_card.setFrameShape(QFrame.Shape.StyledPanel)
        ctrl_layout = QVBoxLayout(ctrl_card)
        ctrl_layout.setContentsMargins(12, 10, 12, 10)
        ctrl_layout.setSpacing(8)

        ctrl_title = QLabel("📡 802.11 Capture File Ingestion & Analysis")
        ctrl_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        ctrl_layout.addWidget(ctrl_title)

        file_row = QHBoxLayout()
        file_lbl = QLabel("PCAP / CAP File:")
        file_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")
        file_row.addWidget(file_lbl)

        self.wireless_file_input = QLineEdit()
        self.wireless_file_input.setPlaceholderText("Select 802.11 capture file (.pcap, .cap, .pcapng)...")
        self.wireless_file_input.setStyleSheet("padding: 4px 8px; font-size: 11px;")
        file_row.addWidget(self.wireless_file_input, 1)

        self.btn_browse_wireless = QPushButton("📁 Browse PCAP")
        self.btn_browse_wireless.setFixedHeight(28)
        self.btn_browse_wireless.clicked.connect(self._browse_wireless_file)
        file_row.addWidget(self.btn_browse_wireless)

        self.btn_analyze_wireless = QPushButton("⚡ Analyze Wireless Capture")
        self.btn_analyze_wireless.setFixedHeight(28)
        self.btn_analyze_wireless.setStyleSheet("""
            QPushButton {
                background-color: #0284c7;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #38bdf8;
            }
        """)
        self.btn_analyze_wireless.clicked.connect(self._run_wireless_analysis)
        file_row.addWidget(self.btn_analyze_wireless)

        ctrl_layout.addLayout(file_row)

        # Stat Badges Row
        stat_row = QHBoxLayout()
        self.stat_w_packets = QLabel("Packets: 0")
        self.stat_w_dot11 = QLabel("802.11 Frames: 0")
        self.stat_w_aps = QLabel("Access Points: 0")
        self.stat_w_hs = QLabel("Crackable Handshakes: 0")
        self.stat_w_anom = QLabel("Anomalies: 0")

        for lbl in (self.stat_w_packets, self.stat_w_dot11, self.stat_w_aps, self.stat_w_hs, self.stat_w_anom):
            lbl.setStyleSheet("font-size: 11px; font-weight: 600; padding: 2px 8px; background: rgba(120,120,120,0.15); border-radius: 4px;")
            stat_row.addWidget(lbl)
        stat_row.addStretch()
        ctrl_layout.addLayout(stat_row)

        layout.addWidget(ctrl_card)

        # Splitter between Access Points and Handshakes/Anomalies
        splitter = QSplitter(Qt.Orientation.Vertical)

        # AP Table Box
        ap_box = QGroupBox("Discovered Wireless Access Points (BSSID Inventory)")
        ap_layout = QVBoxLayout(ap_box)
        ap_layout.setContentsMargins(6, 8, 6, 6)

        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(7)
        self.ap_table.setHorizontalHeaderLabels([
            "BSSID (MAC)", "ESSID (Network)", "Channel", "Encryption", "Cipher", "WPS", "Handshake Status"
        ])
        self.ap_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.ap_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.ap_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.ap_table.setAlternatingRowColors(True)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        ap_layout.addWidget(self.ap_table)
        splitter.addWidget(ap_box)

        # Handshake & Anomaly Bottom Box
        bottom_box = QGroupBox("WPA/WPA2 4-Way Handshakes & Security Anomalies")
        bottom_layout = QVBoxLayout(bottom_box)
        bottom_layout.setContentsMargins(6, 8, 6, 6)

        self.handshake_table = QTableWidget()
        self.handshake_table.setColumnCount(5)
        self.handshake_table.setHorizontalHeaderLabels([
            "AP BSSID", "Client Station MAC", "ESSID", "Validation Status", "Hashcat 22000 Export"
        ])
        self.handshake_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.handshake_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.handshake_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.handshake_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.handshake_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.handshake_table.setAlternatingRowColors(True)
        self.handshake_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        bottom_layout.addWidget(self.handshake_table)

        # Action Buttons
        hs_btn_row = QHBoxLayout()
        self.btn_copy_hashcat = QPushButton("📋 Copy Hashcat 22000 Format")
        self.btn_copy_hashcat.setFixedHeight(28)
        self.btn_copy_hashcat.clicked.connect(self._copy_selected_hashcat)
        hs_btn_row.addWidget(self.btn_copy_hashcat)

        self.btn_export_findings = QPushButton("📥 Commit Findings to Assessment Vault")
        self.btn_export_findings.setFixedHeight(28)
        self.btn_export_findings.setStyleSheet("""
            QPushButton {
                background-color: #059669;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #10b981;
            }
        """)
        self.btn_export_findings.clicked.connect(self._commit_wireless_findings)
        hs_btn_row.addWidget(self.btn_export_findings)
        hs_btn_row.addStretch()
        bottom_layout.addLayout(hs_btn_row)

        splitter.addWidget(bottom_box)
        layout.addWidget(splitter, 1)

        return container

    def _browse_wireless_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select 802.11 PCAP Capture",
            "",
            "PCAP Files (*.pcap *.cap *.pcapng);;All Files (*.*)",
        )
        if path:
            self.wireless_file_input.setText(path)

    def _run_wireless_analysis(self):
        path_str = self.wireless_file_input.text().strip()
        if not path_str or not Path(path_str).exists():
            QMessageBox.warning(self, "Invalid File", "Please select a valid 802.11 PCAP capture file.")
            return

        p_id = self.active_project.id if self.active_project else None
        try:
            res = self.wireless_analyzer.parse_pcap(Path(path_str), project_id=p_id)
            self._last_wireless_result = res
            self._display_wireless_results(res)
        except Exception as e:
            QMessageBox.critical(self, "Analysis Failed", f"Failed to analyze wireless capture:\n{e}")

    def _display_wireless_results(self, res: WirelessAnalysisResult):
        # Update Stats
        self.stat_w_packets.setText(f"Packets: {res.total_packets}")
        self.stat_w_dot11.setText(f"802.11 Frames: {res.dot11_packets}")
        self.stat_w_aps.setText(f"Access Points: {len(res.access_points)}")
        crackable_count = len([h for h in res.handshakes if h.is_crackable])
        self.stat_w_hs.setText(f"Crackable Handshakes: {crackable_count}")
        self.stat_w_anom.setText(f"Anomalies: {len(res.anomalies)}")

        # Populate AP Table
        self.ap_table.setRowCount(len(res.access_points))
        for row, ap in enumerate(res.access_points.values()):
            self.ap_table.setItem(row, 0, QTableWidgetItem(ap.bssid))
            self.ap_table.setItem(row, 1, QTableWidgetItem(ap.essid))
            self.ap_table.setItem(row, 2, QTableWidgetItem(str(ap.channel) if ap.channel else "N/A"))
            self.ap_table.setItem(row, 3, QTableWidgetItem(ap.encryption))
            self.ap_table.setItem(row, 4, QTableWidgetItem(ap.cipher))
            self.ap_table.setItem(row, 5, QTableWidgetItem("Yes" if ap.wps_enabled else "No"))

            status_item = QTableWidgetItem(ap.handshake_status)
            if "Full" in ap.handshake_status or "Valid" in ap.handshake_status:
                status_item.setForeground(QColor("#10b981"))
            self.ap_table.setItem(row, 6, status_item)

        # Populate Handshake Table
        crackable_hs = [h for h in res.handshakes if h.is_crackable]
        self.handshake_table.setRowCount(len(crackable_hs))
        for row, hs in enumerate(crackable_hs):
            self.handshake_table.setItem(row, 0, QTableWidgetItem(hs.bssid))
            self.handshake_table.setItem(row, 1, QTableWidgetItem(hs.client_mac))
            self.handshake_table.setItem(row, 2, QTableWidgetItem(hs.essid))
            status_text = "Full (M1-M4) Confirmed" if hs.is_complete else "Valid Half (M1+M2) Crackable"
            self.handshake_table.setItem(row, 3, QTableWidgetItem(status_text))
            self.handshake_table.setItem(row, 4, QTableWidgetItem(hs.hashcat_22000 or ""))

    def _copy_selected_hashcat(self):
        row = self.handshake_table.currentRow()
        if row >= 0:
            item = self.handshake_table.item(row, 4)
            if item and item.text():
                QApplication.clipboard().setText(item.text())
                QMessageBox.information(self, "Copied", "Hashcat mode 22000 hash copied to clipboard.")
                return
        QMessageBox.warning(self, "Selection Required", "Please select a handshake row with valid Hashcat hash.")

    def _commit_wireless_findings(self):
        if not self._last_wireless_result:
            QMessageBox.warning(self, "No Results", "Run an analysis before committing findings.")
            return
        if not self.active_project:
            QMessageBox.warning(self, "Project Required", "Please create or select an active project first.")
            return

        for f in self._last_wireless_result.findings:
            self.db.upsert_finding_deduplicated(f)
        self.findings_updated.emit()
        QMessageBox.information(
            self,
            "Findings Committed",
            f"Successfully added/updated {len(self._last_wireless_result.findings)} findings in project '{self.active_project.name}'.",
        )

    # =========================================================================
    # Tab 2: IoT & Firmware Security Tab
    # =========================================================================

    def _create_firmware_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Controller Card
        ctrl_card = QFrame()
        ctrl_card.setObjectName("firmwareCtrlCard")
        ctrl_card.setFrameShape(QFrame.Shape.StyledPanel)
        ctrl_layout = QVBoxLayout(ctrl_card)
        ctrl_layout.setContentsMargins(12, 10, 12, 10)
        ctrl_layout.setSpacing(8)

        ctrl_title = QLabel("🔬 Embedded IoT Firmware Binary & Filesystem Security Audit")
        ctrl_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        ctrl_layout.addWidget(ctrl_title)

        file_row = QHBoxLayout()
        file_lbl = QLabel("Firmware Image:")
        file_lbl.setStyleSheet("font-size: 11px; font-weight: 600;")
        file_row.addWidget(file_lbl)

        self.firmware_file_input = QLineEdit()
        self.firmware_file_input.setPlaceholderText("Select firmware binary (.bin, .img, .rom, .elf)...")
        self.firmware_file_input.setStyleSheet("padding: 4px 8px; font-size: 11px;")
        file_row.addWidget(self.firmware_file_input, 1)

        self.btn_browse_firmware = QPushButton("📁 Browse Image")
        self.btn_browse_firmware.setFixedHeight(28)
        self.btn_browse_firmware.clicked.connect(self._browse_firmware_file)
        file_row.addWidget(self.btn_browse_firmware)

        self.btn_analyze_firmware = QPushButton("🔬 Run Firmware Audit")
        self.btn_analyze_firmware.setFixedHeight(28)
        self.btn_analyze_firmware.setStyleSheet("""
            QPushButton {
                background-color: #7c3aed;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #8b5cf6;
            }
        """)
        self.btn_analyze_firmware.clicked.connect(self._run_firmware_analysis)
        file_row.addWidget(self.btn_analyze_firmware)

        ctrl_layout.addLayout(file_row)

        # Firmware Metadata Banner
        meta_row = QHBoxLayout()
        self.stat_f_arch = QLabel("Architecture: Unknown")
        self.stat_f_endian = QLabel("Endianness: Unknown")
        self.stat_f_size = QLabel("Size: 0 KB")
        self.stat_f_sections = QLabel("Filesystems / Headers: 0")
        self.stat_f_secrets = QLabel("Discovered Secrets: 0")

        for lbl in (self.stat_f_arch, self.stat_f_endian, self.stat_f_size, self.stat_f_sections, self.stat_f_secrets):
            lbl.setStyleSheet("font-size: 11px; font-weight: 600; padding: 2px 8px; background: rgba(120,120,120,0.15); border-radius: 4px;")
            meta_row.addWidget(lbl)
        meta_row.addStretch()
        ctrl_layout.addLayout(meta_row)

        layout.addWidget(ctrl_card)

        # Splitter between Discovered Components and Embedded Secrets
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Components & Partitions Box
        comp_box = QGroupBox("Discovered Firmware Filesystems & Compression Headers")
        comp_layout = QVBoxLayout(comp_box)
        comp_layout.setContentsMargins(6, 8, 6, 6)

        self.comp_table = QTableWidget()
        self.comp_table.setColumnCount(3)
        self.comp_table.setHorizontalHeaderLabels(["Offset (Hex / Dec)", "Component Type", "Description"])
        self.comp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.comp_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.comp_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.comp_table.setAlternatingRowColors(True)
        comp_layout.addWidget(self.comp_table)
        splitter.addWidget(comp_box)

        # Secrets & Misconfigurations Box
        secrets_box = QGroupBox("Embedded Secrets, Private Keys & Hardening Deficiencies")
        secrets_layout = QVBoxLayout(secrets_box)
        secrets_layout.setContentsMargins(6, 8, 6, 6)

        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(5)
        self.secrets_table.setHorizontalHeaderLabels([
            "Severity", "Category", "Target File / Path", "Vulnerability Finding", "Evidence Snippet"
        ])
        self.secrets_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.secrets_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.secrets_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.secrets_table.setAlternatingRowColors(True)
        self.secrets_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        secrets_layout.addWidget(self.secrets_table)

        # Action Buttons
        f_btn_row = QHBoxLayout()
        self.btn_commit_firmware = QPushButton("📥 Commit Firmware Findings to Vault")
        self.btn_commit_firmware.setFixedHeight(28)
        self.btn_commit_firmware.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                font-weight: bold;
                border-radius: 4px;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #ef4444;
            }
        """)
        self.btn_commit_firmware.clicked.connect(self._commit_firmware_findings)
        f_btn_row.addWidget(self.btn_commit_firmware)
        f_btn_row.addStretch()
        secrets_layout.addLayout(f_btn_row)

        splitter.addWidget(secrets_box)
        layout.addWidget(splitter, 1)

        return container

    def _browse_firmware_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Firmware Image",
            "",
            "Firmware Binaries (*.bin *.img *.rom *.elf *.squashfs);;All Files (*.*)",
        )
        if path:
            self.firmware_file_input.setText(path)

    def _run_firmware_analysis(self):
        path_str = self.firmware_file_input.text().strip()
        if not path_str or not Path(path_str).exists():
            QMessageBox.warning(self, "Invalid File", "Please select a valid firmware image binary.")
            return

        p_id = self.active_project.id if self.active_project else None
        try:
            res = self.firmware_analyzer.analyze_image(Path(path_str), project_id=p_id)
            self._last_firmware_result = res
            self._display_firmware_results(res)
        except Exception as e:
            QMessageBox.critical(self, "Audit Failed", f"Firmware audit encountered an error:\n{e}")

    def _display_firmware_results(self, res: FirmwareAnalysisResult):
        # Update Metadata Row
        self.stat_f_arch.setText(f"Architecture: {res.detected_architecture}")
        self.stat_f_endian.setText(f"Endianness: {res.endianness}")
        size_kb = round(res.file_size_bytes / 1024, 1)
        self.stat_f_size.setText(f"Size: {size_kb} KB")
        self.stat_f_sections.setText(f"Filesystems / Headers: {len(res.components)}")
        self.stat_f_secrets.setText(f"Discovered Secrets: {len(res.secrets)}")

        # Populate Components Table
        self.comp_table.setRowCount(len(res.components))
        for row, c in enumerate(res.components):
            offset_str = f"0x{c.offset:X} ({c.offset})"
            self.comp_table.setItem(row, 0, QTableWidgetItem(offset_str))
            self.comp_table.setItem(row, 1, QTableWidgetItem(c.component_type))
            self.comp_table.setItem(row, 2, QTableWidgetItem(c.description))

        # Populate Secrets Table
        self.secrets_table.setRowCount(len(res.secrets))
        for row, s in enumerate(res.secrets):
            sev_item = QTableWidgetItem(s.severity.value.upper())
            if s.severity == FindingSeverity.CRITICAL:
                sev_item.setForeground(QColor("#ef4444"))
            elif s.severity == FindingSeverity.HIGH:
                sev_item.setForeground(QColor("#f97316"))
            elif s.severity == FindingSeverity.MEDIUM:
                sev_item.setForeground(QColor("#eab308"))

            self.secrets_table.setItem(row, 0, sev_item)
            self.secrets_table.setItem(row, 1, QTableWidgetItem(s.category))
            self.secrets_table.setItem(row, 2, QTableWidgetItem(s.file_path))
            self.secrets_table.setItem(row, 3, QTableWidgetItem(s.title))
            self.secrets_table.setItem(row, 4, QTableWidgetItem(s.snippet))

    def _commit_firmware_findings(self):
        if not self._last_firmware_result:
            QMessageBox.warning(self, "No Results", "Run a firmware audit before committing findings.")
            return
        if not self.active_project:
            QMessageBox.warning(self, "Project Required", "Please create or select an active project first.")
            return

        for f in self._last_firmware_result.findings:
            self.db.upsert_finding_deduplicated(f)
        self.findings_updated.emit()
        QMessageBox.information(
            self,
            "Findings Committed",
            f"Successfully saved {len(self._last_firmware_result.findings)} firmware findings into project '{self.active_project.name}'.",
        )

