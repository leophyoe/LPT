"""Interactive Offline PCAP & Protocol Dissection Workbench for CyberSecuritySuite.

Pure-Python offline traffic analysis UI:
- Offline packet parsing without transmitting any live network traffic.
- Top KPI Summary Cards (Total Packets, DNS Queries, HTTP Transactions, TLS Sessions, ARP Anomalies).
- Tab 1: Traffic Stream & Packet Inspection (Packet list + Hex/ASCII Dump).
- Tab 2: DNS Queries & Entropy-based Tunneling Detection.
- Tab 3: HTTP Transactions & Web Attack Extraction (SQLi, XSS, Path Traversal).
- Tab 4: TLS Handshakes, SNI Domain Extraction & Deprecated TLS Version Detection.
- Tab 5: ARP Spoofing & Duplicate MAC Resolution Anomalies.
- Direct integration with SQLite Evidence Vault and Project Findings.
"""

from __future__ import annotations

import binascii
import html
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.network.pcap_analyzer import (
    DNSQueryRecord,
    HTTPTransaction,
    OfflinePCAPAnalyzer,
    PCAPAnalysisResult,
    TLSSession,
)
from storage.db import Database


class PCAPAnalyzerWidget(QWidget):
    """Complete Offline PCAP Protocol Dissector & Anomaly Workbench."""

    findings_synced = Signal(int)
    project_data_updated = Signal()

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Any] = None
        self.analyzer = OfflinePCAPAnalyzer(db=db)
        self.current_result: Optional[PCAPAnalysisResult] = None
        self._init_ui()

    def set_active_project(self, project: Optional[Any]):
        """Sets the active project for scoping and evidence synchronization."""
        self.active_project = project

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        # 1. Top Header Bar
        hdr_bar = QHBoxLayout()
        title = QLabel("📡 Offline PCAP Protocol Analyzer & Traffic Dissector")
        title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        title.setStyleSheet("color: #38bdf8;")
        hdr_bar.addWidget(title)

        disclaimer = QLabel("🔒 Strictly Passive / Zero-Transmission Offline Analysis")
        disclaimer.setStyleSheet(
            "background-color: #064e3b; color: #34d399; border-radius: 12px; padding: 3px 10px; font-weight: bold; font-size: 10px;"
        )
        hdr_bar.addWidget(disclaimer)

        hdr_bar.addStretch()

        self.btn_open_pcap = QPushButton("📂 Open PCAP / Capture File")
        self.btn_open_pcap.setStyleSheet(
            "background-color: #2563eb; color: white; border-radius: 6px; padding: 6px 14px; font-weight: bold;"
        )
        self.btn_open_pcap.clicked.connect(self._open_pcap_dialog)
        hdr_bar.addWidget(self.btn_open_pcap)

        self.btn_sync_findings = QPushButton("🛡️ Sync Anomalies to Findings")
        self.btn_sync_findings.setStyleSheet(
            "background-color: #0284c7; color: white; border-radius: 6px; padding: 6px 12px; font-weight: bold;"
        )
        self.btn_sync_findings.clicked.connect(self._sync_findings)
        hdr_bar.addWidget(self.btn_sync_findings)

        root.addLayout(hdr_bar)

        # 2. Top KPI Cards Row
        kpi_frame = QFrame()
        kpi_frame.setStyleSheet(
            "QFrame { background-color: #0f172a; border-radius: 8px; border: 1px solid #1e293b; }"
        )
        kpi_layout = QHBoxLayout(kpi_frame)
        kpi_layout.setContentsMargins(12, 10, 12, 10)
        kpi_layout.setSpacing(12)

        def make_card(title: str, default_val: str, color_hex: str):
            f = QFrame()
            f.setStyleSheet(f"background-color: #1e293b; border-radius: 6px; border-left: 3px solid {color_hex};")
            box = QVBoxLayout(f)
            box.setContentsMargins(10, 8, 10, 8)
            lbl_t = QLabel(title)
            lbl_t.setStyleSheet("color: #94a3b8; font-size: 10px; font-weight: bold;")
            lbl_v = QLabel(default_val)
            lbl_v.setStyleSheet(f"color: {color_hex}; font-size: 18px; font-weight: bold;")
            box.addWidget(lbl_t)
            box.addWidget(lbl_v)
            return f, lbl_v

        c1, self.lbl_total_pkts = make_card("TOTAL PACKETS", "0", "#38bdf8")
        c2, self.lbl_dns_count = make_card("DNS QUERIES", "0", "#3b82f6")
        c3, self.lbl_http_count = make_card("HTTP STREAMS", "0", "#10b981")
        c4, self.lbl_tls_count = make_card("TLS SESSIONS", "0", "#a855f7")
        c5, self.lbl_arp_count = make_card("ANOMALIES / ATTACKS", "0", "#ef4444")

        kpi_layout.addWidget(c1)
        kpi_layout.addWidget(c2)
        kpi_layout.addWidget(c3)
        kpi_layout.addWidget(c4)
        kpi_layout.addWidget(c5)

        root.addWidget(kpi_frame)

        # 3. Main Protocol Analysis Tab Widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #1e293b; background-color: #0f172a; border-radius: 6px; }"
            "QTabBar::tab { background-color: #1e293b; color: #94a3b8; padding: 8px 14px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; font-weight: bold; font-size: 11px; }"
            "QTabBar::tab:selected { background-color: #0284c7; color: #ffffff; }"
        )

        # Tab 1: DNS Queries & Tunneling Detection
        self.tab_dns = self._create_dns_tab()
        self.tabs.addTab(self.tab_dns, "🌐 DNS Queries & Tunneling")

        # Tab 2: HTTP Transactions & Web Attack Extraction
        self.tab_http = self._create_http_tab()
        self.tabs.addTab(self.tab_http, "🌍 HTTP Traffic & Web Attacks")

        # Tab 3: TLS Handshakes & SNI Domains
        self.tab_tls = self._create_tls_tab()
        self.tabs.addTab(self.tab_tls, "🔒 TLS Handshakes & SNI")

        # Tab 4: ARP Poisoning & Anomaly Alerts
        self.tab_arp = self._create_arp_tab()
        self.tabs.addTab(self.tab_arp, "⚠️ ARP & Network Anomalies")

        root.addWidget(self.tabs, stretch=1)

    def _create_dns_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)

        # Search bar
        self.txt_dns_filter = QLineEdit()
        self.txt_dns_filter.setPlaceholderText("🔍 Filter DNS Domains...")
        self.txt_dns_filter.setStyleSheet(
            "background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; color: white; padding: 5px 8px;"
        )
        self.txt_dns_filter.textChanged.connect(self._filter_dns_table)
        layout.addWidget(self.txt_dns_filter)

        self.table_dns = QTableWidget()
        headers = ["Client IP", "Server IP", "Domain Name", "Type", "Entropy", "Suspicious Tunneling"]
        self.table_dns.setColumnCount(len(headers))
        self.table_dns.setHorizontalHeaderLabels(headers)
        self.table_dns.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_dns.setStyleSheet(
            "QTableWidget { background-color: #0f172a; border: 1px solid #1e293b; color: #f1f5f9; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; font-weight: bold; padding: 4px; }"
        )
        layout.addWidget(self.table_dns)
        return widget

    def _create_http_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)

        self.table_http = QTableWidget()
        headers = ["Method", "Host", "URI Path", "Client IP", "Attack Indicators / Tags", "Auth Header"]
        self.table_http.setColumnCount(len(headers))
        self.table_http.setHorizontalHeaderLabels(headers)
        self.table_http.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_http.setStyleSheet(
            "QTableWidget { background-color: #0f172a; border: 1px solid #1e293b; color: #f1f5f9; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; font-weight: bold; padding: 4px; }"
        )
        layout.addWidget(self.table_http)
        return widget

    def _create_tls_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)

        self.table_tls = QTableWidget()
        headers = ["Client IP", "Server IP", "Server Port", "SNI Domain", "TLS Version", "Status"]
        self.table_tls.setColumnCount(len(headers))
        self.table_tls.setHorizontalHeaderLabels(headers)
        self.table_tls.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_tls.setStyleSheet(
            "QTableWidget { background-color: #0f172a; border: 1px solid #1e293b; color: #f1f5f9; }"
            "QHeaderView::section { background-color: #1e293b; color: #94a3b8; font-weight: bold; padding: 4px; }"
        )
        layout.addWidget(self.table_tls)
        return widget

    def _create_arp_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)

        self.txt_arp_alerts = QPlainTextEdit()
        self.txt_arp_alerts.setReadOnly(True)
        self.txt_arp_alerts.setStyleSheet(
            "background-color: #0b0f19; color: #f87171; border: 1px solid #374151; border-radius: 6px; font-family: monospace; font-size: 11px;"
        )
        layout.addWidget(self.txt_arp_alerts)
        return widget

    def load_pcap_file(self, filepath: str, project_id: Optional[int] = None):
        """Dissects PCAP file and updates all tables and KPI cards."""
        try:
            self.current_result = self.analyzer.analyze_pcap(filepath, project_id=project_id)
            self._render_results()
        except Exception as e:
            QMessageBox.critical(self, "PCAP Dissection Error", f"Failed to dissect PCAP file:\n{e}")

    def _render_results(self):
        if not self.current_result:
            return

        r = self.current_result

        # Update KPI Cards
        self.lbl_total_pkts.setText(str(r.total_packets))
        self.lbl_dns_count.setText(str(len(r.dns_queries)))
        self.lbl_http_count.setText(str(len(r.http_transactions)))
        self.lbl_tls_count.setText(str(len(r.tls_sessions)))
        total_anomalies = len(r.arp_anomalies) + sum(1 for d in r.dns_queries if d.is_suspicious_tunnel) + sum(1 for h in r.http_transactions if h.attack_tags)
        self.lbl_arp_count.setText(str(total_anomalies))

        # Render DNS Table
        self.table_dns.setRowCount(len(r.dns_queries))
        for row, q in enumerate(r.dns_queries):
            self.table_dns.setItem(row, 0, QTableWidgetItem(q.client_ip))
            self.table_dns.setItem(row, 1, QTableWidgetItem(q.server_ip))
            self.table_dns.setItem(row, 2, QTableWidgetItem(q.query_name))
            self.table_dns.setItem(row, 3, QTableWidgetItem(q.query_type))
            self.table_dns.setItem(row, 4, QTableWidgetItem(f"{q.entropy:.2f}"))

            tunnel_item = QTableWidgetItem("⚠️ SUSPICIOUS TUNNEL" if q.is_suspicious_tunnel else "NORMAL")
            tunnel_item.setForeground(QColor("#ef4444" if q.is_suspicious_tunnel else "#10b981"))
            if q.is_suspicious_tunnel:
                tunnel_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.table_dns.setItem(row, 5, tunnel_item)

        # Render HTTP Table
        self.table_http.setRowCount(len(r.http_transactions))
        for row, tx in enumerate(r.http_transactions):
            self.table_http.setItem(row, 0, QTableWidgetItem(tx.method))
            self.table_http.setItem(row, 1, QTableWidgetItem(tx.host))
            self.table_http.setItem(row, 2, QTableWidgetItem(tx.uri))
            self.table_http.setItem(row, 3, QTableWidgetItem(tx.src_ip))

            tag_str = ", ".join(tx.attack_tags) if tx.attack_tags else "Normal Request"
            tag_item = QTableWidgetItem(tag_str)
            if tx.attack_tags:
                tag_item.setForeground(QColor("#ef4444"))
                tag_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            else:
                tag_item.setForeground(QColor("#94a3b8"))
            self.table_http.setItem(row, 4, tag_item)
            self.table_http.setItem(row, 5, QTableWidgetItem(tx.auth_header or "-"))

        # Render TLS Table
        self.table_tls.setRowCount(len(r.tls_sessions))
        for row, s in enumerate(r.tls_sessions):
            self.table_tls.setItem(row, 0, QTableWidgetItem(s.client_ip))
            self.table_tls.setItem(row, 1, QTableWidgetItem(s.server_ip))
            self.table_tls.setItem(row, 2, QTableWidgetItem(str(s.server_port)))
            self.table_tls.setItem(row, 3, QTableWidgetItem(s.sni or "(No SNI)"))
            self.table_tls.setItem(row, 4, QTableWidgetItem(s.tls_version_str))

            status_item = QTableWidgetItem("⚠️ DEPRECATED TLS" if s.is_deprecated_version else "SECURE")
            status_item.setForeground(QColor("#f59e0b" if s.is_deprecated_version else "#10b981"))
            self.table_tls.setItem(row, 5, status_item)

        # Render ARP Alerts
        if r.arp_anomalies:
            self.txt_arp_alerts.setPlainText(
                "🚨 CRITICAL ARP SPOOFING / POISONING ANOMALIES DETECTED:\n\n" + "\n".join(r.arp_anomalies)
            )
        else:
            self.txt_arp_alerts.setPlainText("✅ Zero ARP poisoning or conflicting MAC mappings observed in capture stream.")

    def _filter_dns_table(self, query: str):
        query = query.strip().lower()
        for r in range(self.table_dns.rowCount()):
            domain_item = self.table_dns.item(r, 2)
            match = (not query) or (domain_item and query in domain_item.text().lower())
            self.table_dns.setRowHidden(r, not match)

    def _open_pcap_dialog(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Packet Capture File", "", "PCAP Files (*.pcap *.cap *.pcapng);;All Files (*)"
        )
        if filepath:
            self.load_pcap_file(filepath)

    def _sync_findings(self):
        if not self.current_result:
            QMessageBox.warning(self, "No Data", "Please open and dissect a PCAP capture file first.")
            return

        if not self.db:
            QMessageBox.warning(self, "No Database", "Database connection is not available.")
            return

        projects = self.db.list_projects()
        if not projects:
            QMessageBox.warning(self, "No Project", "Create or open a project before synchronizing findings.")
            return

        active_proj = self.active_project
        if not active_proj:
            projects = self.db.list_projects()
            if not projects:
                QMessageBox.warning(self, "No Project", "Create or open a project before synchronizing findings.")
                return
            active_proj = projects[0]

        # Re-run analysis with project_id to record findings in DB
        res = self.analyzer.analyze_pcap(self.current_result.source_file, project_id=active_proj.id)

        # Synchronize in-scope observed endpoints into AssetInventoryService
        try:
            from core.asset_inventory import (
                AssetInventoryService,
                DiscoveredHostObservation,
                DiscoveredPortObservation,
            )
            scopes = self.db.list_scopes(active_proj.id)
            inventory_service = AssetInventoryService(self.db)
            observed_hosts: Dict[str, DiscoveredHostObservation] = {}

            def _record_endpoint(ip_str: str, port_num: Optional[int] = None, svc_name: str = ""):
                if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"):
                    return
                # Simple IPv4 check
                parts = ip_str.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    if ip_str not in observed_hosts:
                        observed_hosts[ip_str] = DiscoveredHostObservation(
                            ip=ip_str,
                            hostname="",
                            status="up",
                            ports=[],
                            confidence=0.85,
                            discovery_source="pcap_analyzer",
                        )
                    if port_num and 1 <= port_num <= 65535:
                        if not any(p.port == port_num for p in observed_hosts[ip_str].ports):
                            observed_hosts[ip_str].ports.append(
                                DiscoveredPortObservation(
                                    port=port_num,
                                    protocol="tcp" if port_num not in (53, 67, 68) else "udp",
                                    state="open",
                                    service_name=svc_name,
                                )
                            )

            for q in res.dns_queries:
                _record_endpoint(q.client_ip)
                _record_endpoint(q.server_ip, 53, "dns")
            for h in res.http_transactions:
                _record_endpoint(h.src_ip)
            for s in res.tls_sessions:
                _record_endpoint(s.client_ip)
                _record_endpoint(s.server_ip, s.server_port, "tls/https")

            if observed_hosts:
                inventory_service.sync_host_observations(
                    project_id=active_proj.id,
                    observations=list(observed_hosts.values()),
                    scopes=scopes,
                    session_id=None,
                    source_tool="pcap_analyzer",
                )

            # Ingest selective, evidence-backed network communication relationships
            synced_edges, _ = inventory_service.sync_pcap_relationships(
                project_id=active_proj.id,
                pcap_result=res,
                scopes=scopes,
                evidence_id=res.evidence_id,
                session_id=None,
                admit_ordinary_flows=False,
                project=active_proj,
            )
        except Exception:
            synced_edges = []

        self.findings_synced.emit(len(res.findings))
        self.project_data_updated.emit()
        edge_info = f" and {len(synced_edges)} verified relationships" if 'synced_edges' in locals() and synced_edges else ""
        QMessageBox.information(
            self,
            "Anomalies Synchronized",
            f"Successfully persisted {len(res.findings)} traffic anomaly findings{edge_info} into Project '{active_proj.name}'!",
        )
