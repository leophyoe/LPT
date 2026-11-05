"""Tool Integration Dashboard and Execution Verification View.

Displays a comprehensive inventory of planned open-source security tools,
live executable status, version detection, integration maturity matrix,
and provides safe non-intrusive diagnostic verification and installation guidance.
"""

from __future__ import annotations

import html
from typing import List, Optional, Union

from PySide6.QtCore import Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
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

from core.registry import ToolMetadata, ToolRegistry
from desktop.theme import CPENTTheme, get_ui_font, ThemeManager, ThemeMode
from desktop.widgets.tool_execution_center import ToolExecutionCenterWidget
from modules.scanners_box.catalog import ScannersBoxCatalog, ScannersBoxItem
from storage.db import Database
from storage.models import Project


class ToolTestWorker(QThread):
    """Background worker to run non-intrusive tool diagnostic test without freezing GUI."""

    test_completed = Signal(str, bool, str, int)  # tool_name, success, output, exit_code

    def __init__(self, registry: ToolRegistry, tool_name: str):
        super().__init__()
        self.registry = registry
        self.tool_name = tool_name

    def run(self):
        success, output, exit_code = self.registry.test_tool(self.tool_name, timeout=8.0)
        self.test_completed.emit(self.tool_name, success, output, exit_code)


class ToolsDashboardView(QWidget):
    """Native PySide6 security tools integration inventory and diagnostic dashboard."""

    open_scanner_requested = Signal(str)  # Emits tool name to navigate in MainWindow
    open_shell_requested = Signal(str, str)  # Emits tool name and default command to load into shell

    STATUS_COLORS = {
        "Installed": QColor(CPENTTheme.SUCCESS_GREEN),
        "Missing": QColor(CPENTTheme.ERROR_RED),
        "Error": QColor(CPENTTheme.AMBER_ACCENT),
    }

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None, parent=None):
        super().__init__(parent)
        self.db = db
        self.registry = registry or ToolRegistry()
        self.active_project: Optional[Project] = None
        self.selected_tool: Optional[ToolMetadata] = None
        self.selected_sb_item: Optional[ScannersBoxItem] = None
        self._current_sb_items: List[ScannersBoxItem] = []
        self._test_worker: Optional[ToolTestWorker] = None

        self._init_ui()
        self.refresh_tools()
        ThemeManager.instance().theme_changed.connect(self._on_theme_changed)
        self._on_theme_changed(ThemeManager.instance().mode)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 1. Header Row
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        self.header_title = QLabel("Security Tool Integration Dashboard")
        self.header_title.setObjectName("viewHeader")
        self.header_title.setFont(get_ui_font(16, bold=True, heading=True))
        subtitle = QLabel("Real-time environment discovery, execution readiness, and installation diagnostics.")
        subtitle.setObjectName("viewSubtitle")
        title_box.addWidget(self.header_title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)
        header_row.addStretch()

        self.btn_refresh = QPushButton("🔄 Rescan All Tools")
        self.btn_refresh.setProperty("class", "action-primary")
        self.btn_refresh.clicked.connect(self.refresh_tools)
        header_row.addWidget(self.btn_refresh)
        layout.addLayout(header_row)

        self.tabs = QTabWidget()

        # Tab 1: Local Tool Integration Matrix
        tab_local = QWidget()
        tab_local_layout = QVBoxLayout(tab_local)
        tab_local_layout.setContentsMargins(0, 4, 0, 0)
        tab_local_layout.setSpacing(6)

        self.matrix_tabs = QTabWidget()

        # Sub-tab A: Inventory & Matrix
        matrix_subtab = QWidget()
        matrix_subtab_layout = QVBoxLayout(matrix_subtab)
        matrix_subtab_layout.setContentsMargins(0, 4, 0, 0)
        matrix_subtab_layout.setSpacing(10)

        # 2. Metrics Cards Row
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)

        self.card_total = self._create_metric_card("Total Planned", "0", "#38bdf8")
        self.card_installed = self._create_metric_card("Ready & Functional", "0", "#4ade80")
        self.card_missing = self._create_metric_card("Missing / Unbuilt", "0", "#f87171")
        self.card_integrated = self._create_metric_card("GUI Integrated", "0", "#a855f7")

        metrics_row.addWidget(self.card_total)
        metrics_row.addWidget(self.card_installed)
        metrics_row.addWidget(self.card_missing)
        metrics_row.addWidget(self.card_integrated)
        matrix_subtab_layout.addLayout(metrics_row)

        # 3. Filter and Search Toolbar
        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search tools by name, command, or category...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.search_input, 2)

        self.cat_filter = QComboBox()
        self.cat_filter.addItems([
            "All Categories",
            "Network",
            "Web",
            "System",
            "Code Security",
            "Vulnerability",
            "Cloud",
            "Mobile",
            "OSINT",
            "Forensics",
            "Crypto",
            "Identity",
        ])
        self.cat_filter.currentTextChanged.connect(self._apply_filters)
        filter_row.addWidget(self.cat_filter, 1)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "Installed", "Missing", "Available", "Update Available", "Error"])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        filter_row.addWidget(self.status_filter, 1)

        self.btn_filter_installed = QPushButton("⚡ Available Tools Only")
        self.btn_filter_installed.setFixedHeight(26)
        self.btn_filter_installed.setStyleSheet(
            f"QPushButton {{ background-color: {CPENTTheme.DEEP_NAVY}; color: {CPENTTheme.SUCCESS_GREEN}; "
            f"border: 1px solid {CPENTTheme.SUCCESS_GREEN}; border-radius: 4px; font-size: 11px; padding: 0 8px; font-weight: 500; }}"
            f"QPushButton:hover {{ background-color: {CPENTTheme.SUCCESS_GREEN}; color: #000000; }}"
        )
        self.btn_filter_installed.clicked.connect(self.show_available_tools_only)
        filter_row.addWidget(self.btn_filter_installed)

        self.btn_filter_missing = QPushButton("📥 Unavailable Tools && Guides")
        self.btn_filter_missing.setFixedHeight(26)
        self.btn_filter_missing.setStyleSheet(
            f"QPushButton {{ background-color: {CPENTTheme.PANEL_BG}; color: {CPENTTheme.AMBER_ACCENT}; "
            f"border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; font-size: 11px; padding: 0 8px; }}"
            f"QPushButton:hover {{ border-color: {CPENTTheme.AMBER_ACCENT}; }}"
        )
        self.btn_filter_missing.clicked.connect(self.show_unavailable_tools_only)
        filter_row.addWidget(self.btn_filter_missing)

        self.btn_filter_all = QPushButton("All Tools")
        self.btn_filter_all.setFixedHeight(26)
        self.btn_filter_all.setStyleSheet(
            f"QPushButton {{ background-color: {CPENTTheme.PANEL_BG}; color: {CPENTTheme.SECONDARY_TEXT}; "
            f"border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; font-size: 11px; padding: 0 8px; }}"
            f"QPushButton:hover {{ color: {CPENTTheme.PRIMARY_TEXT}; border-color: {CPENTTheme.PRIMARY_BLUE}; }}"
        )
        self.btn_filter_all.clicked.connect(lambda: self.status_filter.setCurrentText("All Statuses"))
        filter_row.addWidget(self.btn_filter_all)

        matrix_subtab_layout.addLayout(filter_row)

        # 4. Main Splitter (Left: Table, Right: Details & Safe Test)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Tools Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Tool Name",
            "Category",
            "Status",
            "Detected Version",
            "CLI",
            "Adapter",
            "GUI",
            "Parser",
        ])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 160)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(1, 110)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(2, 90)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(4, 55)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(5, 75)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(6, 55)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(7, 75)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_tool_selected)
        splitter.addWidget(self.table)

        # Right: Detail & Safe Test Panel
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setStyleSheet("QScrollArea { background: transparent; border: 1px solid #1e293b; border-radius: 6px; }")
        if detail_scroll.viewport():
            detail_scroll.viewport().setStyleSheet("background: #0f172a; border-radius: 6px;")
        self.detail_widget = QWidget()
        self.detail_widget.setStyleSheet("background: #0f172a; border-radius: 6px;")
        self.detail_layout = QVBoxLayout(self.detail_widget)
        self.detail_layout.setContentsMargins(12, 12, 12, 12)
        self.detail_layout.setSpacing(10)

        # Selected Tool Header
        self.lbl_tool_title = QLabel("Select a Tool")
        self.lbl_tool_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #38bdf8;")
        self.lbl_tool_desc = QLabel("Click any tool from the table to view integration status, verify safe diagnostics, or view install commands.")
        self.lbl_tool_desc.setWordWrap(True)
        self.lbl_tool_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")

        self.lbl_tool_path = QLabel("Executable: —")
        self.lbl_tool_path.setStyleSheet("color: #cbd5e1; font-family: monospace; font-size: 11px;")
        self.lbl_tool_path.setWordWrap(True)

        self.lbl_tool_caps = QLabel("Integration Capabilities: —")
        self.lbl_tool_caps.setStyleSheet("color: #cbd5e1; font-size: 12px;")

        self.detail_layout.addWidget(self.lbl_tool_title)
        self.detail_layout.addWidget(self.lbl_tool_desc)
        self.detail_layout.addWidget(self.lbl_tool_path)
        self.detail_layout.addWidget(self.lbl_tool_caps)

        # Action Buttons Row
        action_row = QHBoxLayout()
        self.btn_test = QPushButton("🧪 Run Safe Diagnostic")
        self.btn_test.setProperty("class", "action-primary")
        self.btn_test.setEnabled(False)
        self.btn_test.clicked.connect(self._run_tool_test)
        action_row.addWidget(self.btn_test)

        self.btn_open_execution = QPushButton("⚡ Launch Execution Center")
        self.btn_open_execution.setProperty("class", "action-primary")
        self.btn_open_execution.setEnabled(False)
        self.btn_open_execution.clicked.connect(self._on_open_execution_clicked)
        action_row.addWidget(self.btn_open_execution)

        self.btn_open_shell = QPushButton("⚡ Open in Shell")
        self.btn_open_shell.setProperty("class", "action-secondary")
        self.btn_open_shell.setEnabled(False)
        self.btn_open_shell.clicked.connect(self._on_open_shell_clicked)
        action_row.addWidget(self.btn_open_shell)

        self.btn_open_gui = QPushButton("🚀 Open in Scanner")
        self.btn_open_gui.setProperty("class", "action-secondary")
        self.btn_open_gui.setEnabled(False)
        self.btn_open_gui.clicked.connect(self._on_open_gui_clicked)
        action_row.addWidget(self.btn_open_gui)
        self.detail_layout.addLayout(action_row)

        # Diagnostic Output Area
        lbl_diag = QLabel("Diagnostic Execution Output:")
        lbl_diag.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        self.detail_layout.addWidget(lbl_diag)

        self.txt_output = QTextEdit()
        self.txt_output.setReadOnly(True)
        self.txt_output.setFont(QFont("Monospace", 9))
        self.txt_output.setPlaceholderText("Click 'Run Safe Diagnostic' to execute a non-intrusive version or help check...")
        self.txt_output.setStyleSheet("min-height: 120px;")
        self.detail_layout.addWidget(self.txt_output)

        # Installation & Guidance Box
        lbl_install = QLabel("Installation & Configuration Guide:")
        lbl_install.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        self.detail_layout.addWidget(lbl_install)

        self.txt_install = QTextEdit()
        self.txt_install.setReadOnly(True)
        self.txt_install.setFont(QFont("Monospace", 9))
        self.txt_install.setStyleSheet("max-height: 90px;")
        self.detail_layout.addWidget(self.txt_install)

        self.btn_copy_cmd = QPushButton("📋 Copy Install Command")
        self.btn_copy_cmd.setFixedHeight(26)
        self.btn_copy_cmd.clicked.connect(self._copy_install_command)
        self.detail_layout.addWidget(self.btn_copy_cmd)

        self.detail_layout.addStretch()
        detail_scroll.setWidget(self.detail_widget)
        splitter.addWidget(detail_scroll)

        # 60% Table, 40% Details
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)
        matrix_subtab_layout.addWidget(splitter)
        self.matrix_tabs.addTab(matrix_subtab, "🛠️ Inventory & Diagnostics")

        # Sub-tab B: Dedicated Tool Execution Center
        self.execution_center_tab = ToolExecutionCenterWidget(db=self.db, project=self.active_project)
        self.matrix_tabs.addTab(self.execution_center_tab, "⚡ Tool Execution Center")

        tab_local_layout.addWidget(self.matrix_tabs)
        self.tabs.addTab(tab_local, "🛠️ Tools Matrix")

        # Tab 2: Scanners-Box (12 Primary Domains)
        self.scanners_box_tab = self._create_scanners_box_tab()
        self.tabs.addTab(self.scanners_box_tab, "📦 Tools Catalog (Scanners-Box)")

        layout.addWidget(self.tabs)

    def _create_metric_card(self, title: str, value: str, color: str) -> QFrame:
        card = QFrame()
        card.setObjectName("metricCard")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(12, 8, 12, 8)
        c_layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("metricName")
        lbl_val = QLabel(value)
        lbl_val.setObjectName(f"val_{title.replace(' ', '_').lower()}")
        lbl_val.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")

        c_layout.addWidget(lbl_title)
        c_layout.addWidget(lbl_val)
        return card

    def _update_metric_card(self, card: QFrame, value: str):
        label = card.findChild(QLabel)
        for child in card.findChildren(QLabel):
            if child.text().isdigit() or "+" in child.text():
                child.setText(value)
                break

    @Slot()
    def show_available_tools_only(self):
        """Displays only verified functional tools detected on system."""
        self.status_filter.setCurrentText("Installed")

    @Slot()
    def show_unavailable_tools_only(self):
        """Displays uninstalled tools with installation instructions."""
        self.status_filter.setCurrentText("Missing")

    @Slot()
    def refresh_tools(self):
        """Refreshes tool status across system PATH and repository sources."""
        self.registry.refresh()
        self._apply_filters()
        self._update_metrics()

    def _update_metrics(self):
        all_tools = self.registry.list_tools()
        total = len(all_tools)
        installed = sum(1 for t in all_tools if t.is_installed)
        missing = total - installed
        integrated = sum(1 for t in all_tools if t.has_gui)

        for child in self.card_total.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(total))
        for child in self.card_installed.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(installed))
        for child in self.card_missing.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(missing))
        for child in self.card_integrated.findChildren(QLabel):
            if child.text().isdigit():
                child.setText(str(integrated))

    def _apply_filters(self):
        search = self.search_input.text().strip().lower()
        cat_sel = self.cat_filter.currentText().lower()
        status_sel = self.status_filter.currentText().lower()

        tools = self.registry.list_tools()
        filtered: List[ToolMetadata] = []

        for t in tools:
            # Category match
            if cat_sel != "all categories":
                category_key = cat_sel.replace(" ", "_")
                if category_key not in t.category.lower():
                    continue

            # Status match
            t_status = "installed" if t.is_installed else ("error" if t.error_message and "unbuilt" in t.error_message else "missing")
            if status_sel != "all statuses":
                if status_sel == "available" and not t.is_installed:
                    continue
                elif status_sel == "update available" and not (t.is_installed and t.version and "git" in str(t.version).lower()):
                    continue
                elif status_sel not in ("available", "update available") and t_status != status_sel:
                    continue

            # Search text match
            if search:
                haystack = f"{t.name} {t.display_name} {t.category} {t.binary_name} {t.description}".lower()
                if search not in haystack:
                    continue

            filtered.append(t)

        self._populate_table(filtered)

    def _populate_table(self, tools: List[ToolMetadata]):
        self.table.setRowCount(len(tools))
        for row, tool in enumerate(tools):
            # Tool Name
            item_name = QTableWidgetItem(tool.display_name)
            item_name.setData(Qt.ItemDataRole.UserRole, tool.name)
            self.table.setItem(row, 0, item_name)

            # Category
            item_cat = QTableWidgetItem(tool.category.replace("_", " ").title())
            item_cat.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 1, item_cat)

            # Status
            if tool.is_installed:
                status_text = "Installed"
                color = self.STATUS_COLORS["Installed"]
            elif tool.error_message and "unbuilt" in tool.error_message:
                status_text = "Source Unbuilt"
                color = self.STATUS_COLORS["Error"]
            else:
                status_text = "Missing"
                color = self.STATUS_COLORS["Missing"]

            item_status = QTableWidgetItem(status_text)
            item_status.setForeground(color)
            item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_status.setFont(QFont("Sans", 10, QFont.Weight.Bold))
            self.table.setItem(row, 2, item_status)

            # Version
            ver_text = tool.version or (tool.error_message or "Not Detected")
            item_ver = QTableWidgetItem(ver_text)
            self.table.setItem(row, 3, item_ver)

            # Capabilities: CLI, Adapter, GUI, Parser
            for col_idx, cap_val in enumerate([tool.has_cli, tool.has_adapter, tool.has_gui, tool.has_parser], start=4):
                item_cap = QTableWidgetItem("✅" if cap_val else "❌")
                item_cap.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col_idx, item_cap)

        self.table.clearSelection()
        if len(tools) > 0:
            self.table.selectRow(0)

    @Slot()
    def _on_tool_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.table.item(row, 0)
        if not item:
            return

        tool_name = item.data(Qt.ItemDataRole.UserRole)
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return

        self.selected_tool = tool
        self.lbl_tool_title.setText(f"{tool.display_name} ({tool.name})")
        self.lbl_tool_desc.setText(tool.description or "No description provided.")

        status_str = "Installed & Verified" if tool.is_installed else "Missing / Unavailable"
        color_hex = "#4ade80" if tool.is_installed else "#f87171"
        self.lbl_tool_path.setText(
            f"Path: {tool.binary_path or 'Not in PATH'}\n"
            f"Category: {tool.category.title()} | Status: {status_str}"
        )
        self.lbl_tool_path.setStyleSheet(f"color: {color_hex}; font-family: monospace; font-size: 11px;")

        caps = [
            f"CLI: {'✅ Yes' if tool.has_cli else '❌ No'}",
            f"Adapter: {'✅ Yes' if tool.has_adapter else '❌ No'}",
            f"GUI: {'✅ Yes' if tool.has_gui else '❌ No'}",
            f"Parser: {'✅ Yes' if tool.has_parser else '❌ No'}",
        ]
        self.lbl_tool_caps.setText(" | ".join(caps))

        self.btn_test.setEnabled(True)
        self.btn_open_execution.setEnabled(True)
        self.btn_open_gui.setEnabled(tool.has_gui)
        self.btn_open_shell.setEnabled(True)

        self.txt_install.setPlainText(tool.install_guide or "No installation instructions needed.")

    @Slot()
    def _on_open_execution_clicked(self):
        if self.selected_tool:
            self.open_tool_in_execution_center(self.selected_tool.name)

    def open_tool_in_execution_center(self, tool_name: str, preset_name: Optional[str] = None):
        """Switches to the Execution Center tab and pre-selects the requested tool and profile."""
        if hasattr(self, "execution_center_tab") and hasattr(self, "matrix_tabs"):
            self.tabs.setCurrentIndex(0)
            self.matrix_tabs.setCurrentWidget(self.execution_center_tab)
            self.execution_center_tab.select_tool(tool_name, preset_name)

    def set_active_project(self, project: Optional[Project]):
        """Synchronizes project context with Execution Center."""
        self.active_project = project
        if hasattr(self, "execution_center_tab"):
            self.execution_center_tab.set_active_project(project)

    @Slot()
    def _run_tool_test(self):
        if not self.selected_tool:
            return

        self.btn_test.setEnabled(False)
        self.txt_output.setPlainText(f"Running safe diagnostic check for '{self.selected_tool.name}'...\n")

        self._test_worker = ToolTestWorker(self.registry, self.selected_tool.name)
        self._test_worker.test_completed.connect(self._on_test_completed)
        self._test_worker.start()

    @Slot(str, bool, str, int)
    def _on_test_completed(self, tool_name: str, success: bool, output: str, exit_code: int):
        self.btn_test.setEnabled(True)
        status_label = "SUCCESS" if success else "FAILED / UNAVAILABLE"
        log = (
            f"=== Safe Tool Diagnostic: {tool_name} [{status_label}] ===\n"
            f"Exit Code: {exit_code}\n\n"
            f"{output}\n"
        )
        self.txt_output.setPlainText(log)

    @Slot()
    def _copy_install_command(self):
        cmd = self.txt_install.toPlainText().strip()
        if cmd:
            QApplication.clipboard().setText(cmd)
            QMessageBox.information(self, "Copied", "Installation command copied to clipboard.")

    @Slot()
    def _on_open_gui_clicked(self):
        if self.selected_tool and self.selected_tool.has_gui:
            self.open_scanner_requested.emit(self.selected_tool.name)

    @Slot()
    def _on_open_shell_clicked(self):
        if not self.selected_tool:
            return
        t = self.selected_tool
        default_commands = {
            "nmap": "nmap -sS -sV -sC -Pn -T4 127.0.0.1",
            "sqlmap": "sqlmap -u \"http://127.0.0.1:8080/\" --batch",
            "wafw00f": "wafw00f http://127.0.0.1:8080",
            "gobuster": "gobuster dir -u http://127.0.0.1:8080 -w /usr/share/dirb/wordlists/common.txt",
            "zaproxy": "zap.sh -dir /tmp/.ZAP",
            "burpsuite": "burpsuite",
            "hydra": "hydra -h",
            "hashcat": "hashcat -h",
            "volatility3": "vol -h",
            "bandit": "bandit -r .",
            "binwalk": "binwalk --help",
            "wireshark": "wireshark",
            "tshark": "tshark -D",
            "nikto": "nikto -h http://127.0.0.1:8080",
            "ffuf": "ffuf -u http://127.0.0.1:8080/FUZZ -w /usr/share/dirb/wordlists/common.txt",
        }
        cmd = default_commands.get(t.name, f"{t.binary_name} --help")
        self.open_shell_requested.emit(t.name, cmd)

    # -----------------------------------------------------------------------
    # Scanners-Box Arsenal Tab Methods
    # -----------------------------------------------------------------------

    def _create_scanners_box_tab(self) -> QWidget:
        widget = QWidget()
        vbox = QVBoxLayout(widget)
        vbox.setContentsMargins(0, 8, 0, 0)
        vbox.setSpacing(10)

        # Info Header
        info_frame = QFrame()
        info_frame.setObjectName("dashboardPanel")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(12, 10, 12, 10)
        lbl_h = QLabel("📦 Tools Catalog: Curated Open-Source Security Scanners")
        lbl_h.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        lbl_sub = QLabel(
            "Curated directory of 30+ open-source security scanners across 12 primary domains (OSINT, Network, Web, Fuzzing, SQLi, WAF, Password, Cloud, SAST, Mobile, Forensics, Active Directory). "
            "Real-time host binary detection indicates whether each tool is installed in your system PATH."
        )
        lbl_sub.setStyleSheet("font-size: 11px; color: #94a3b8;")
        lbl_sub.setWordWrap(True)
        info_layout.addWidget(lbl_h)
        info_layout.addWidget(lbl_sub)
        vbox.addWidget(info_frame)

        # Filters
        filter_row = QHBoxLayout()
        self.scanners_box_search = QLineEdit()
        self.scanners_box_search.setPlaceholderText("🔍 Search Scanners-Box tools by name, description, or tags...")
        self.scanners_box_search.textChanged.connect(self._apply_scanners_box_filters)
        filter_row.addWidget(self.scanners_box_search, 2)

        self.scanners_box_cat_filter = QComboBox()
        self.scanners_box_cat_filter.addItem("All Categories")
        self.scanners_box_cat_filter.addItems(ScannersBoxCatalog.CATEGORIES)
        self.scanners_box_cat_filter.currentTextChanged.connect(self._apply_scanners_box_filters)
        filter_row.addWidget(self.scanners_box_cat_filter, 1)

        vbox.addLayout(filter_row)

        # Splitter: Table on left, Details on right
        sb_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.scanners_box_table = QTableWidget()
        self.scanners_box_table.setColumnCount(4)
        self.scanners_box_table.setHorizontalHeaderLabels([
            "Tool Name",
            "Category",
            "Language",
            "Host Installed",
        ])
        self.scanners_box_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.scanners_box_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.scanners_box_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.scanners_box_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.scanners_box_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.scanners_box_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.scanners_box_table.setAlternatingRowColors(True)
        self.scanners_box_table.verticalHeader().setVisible(False)
        self.scanners_box_table.itemSelectionChanged.connect(self._on_scanners_box_item_selected)
        sb_splitter.addWidget(self.scanners_box_table)

        # Right side detail panel
        sb_detail_scroll = QScrollArea()
        sb_detail_scroll.setWidgetResizable(True)
        sb_detail_widget = QWidget()
        self.sb_detail_layout = QVBoxLayout(sb_detail_widget)
        self.sb_detail_layout.setContentsMargins(12, 12, 12, 12)
        self.sb_detail_layout.setSpacing(10)

        self.lbl_sb_title = QLabel("Select a Tool from Scanners-Box")
        self.lbl_sb_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #38bdf8;")
        self.lbl_sb_cat = QLabel("Category: —")
        self.lbl_sb_cat.setStyleSheet("color: #a855f7; font-size: 12px; font-weight: 500;")
        self.lbl_sb_desc = QLabel("Click any tool from the table to view capabilities, tags, and installation commands.")
        self.lbl_sb_desc.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        self.lbl_sb_desc.setWordWrap(True)
        self.lbl_sb_tags = QLabel("Tags: —")
        self.lbl_sb_tags.setStyleSheet(f"color: {CPENTTheme.MUTED_TEXT}; font-size: 11px;")
        self.lbl_sb_tags.setWordWrap(True)

        self.sb_detail_layout.addWidget(self.lbl_sb_title)
        self.sb_detail_layout.addWidget(self.lbl_sb_cat)
        self.sb_detail_layout.addWidget(self.lbl_sb_desc)
        self.sb_detail_layout.addWidget(self.lbl_sb_tags)

        # Buttons
        sb_action_row = QHBoxLayout()
        self.btn_sb_open_shell = QPushButton("⚡ Run in Shell")
        self.btn_sb_open_shell.setProperty("class", "action-primary")
        self.btn_sb_open_shell.setEnabled(False)
        self.btn_sb_open_shell.clicked.connect(self._on_sb_open_shell_clicked)
        sb_action_row.addWidget(self.btn_sb_open_shell)

        self.btn_sb_open_github = QPushButton("🌐 Open GitHub")
        self.btn_sb_open_github.setProperty("class", "action-secondary")
        self.btn_sb_open_github.setEnabled(False)
        self.btn_sb_open_github.clicked.connect(self._on_sb_open_github_clicked)
        sb_action_row.addWidget(self.btn_sb_open_github)
        self.sb_detail_layout.addLayout(sb_action_row)

        lbl_sb_inst = QLabel("Installation Command:")
        lbl_sb_inst.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        self.sb_detail_layout.addWidget(lbl_sb_inst)

        self.txt_sb_install = QTextEdit()
        self.txt_sb_install.setReadOnly(True)
        self.txt_sb_install.setFont(QFont("Monospace", 9))
        self.txt_sb_install.setStyleSheet("max-height: 80px;")
        self.sb_detail_layout.addWidget(self.txt_sb_install)

        self.btn_sb_copy_cmd = QPushButton("📋 Copy Install Command")
        self.btn_sb_copy_cmd.setFixedHeight(26)
        self.btn_sb_copy_cmd.clicked.connect(self._copy_sb_install_command)
        self.sb_detail_layout.addWidget(self.btn_sb_copy_cmd)

        self.sb_detail_layout.addStretch()
        sb_detail_scroll.setWidget(sb_detail_widget)
        sb_splitter.addWidget(sb_detail_scroll)

        sb_splitter.setStretchFactor(0, 6)
        sb_splitter.setStretchFactor(1, 4)
        vbox.addWidget(sb_splitter)

        self._populate_scanners_box_table(ScannersBoxCatalog.get_all_items())
        return widget

    def _populate_scanners_box_table(self, items: List[ScannersBoxItem]):
        self._current_sb_items = items
        self.scanners_box_table.setRowCount(len(items))

        for row, item in enumerate(items):
            self.scanners_box_table.setItem(row, 0, QTableWidgetItem(item.display_name))
            self.scanners_box_table.setItem(row, 1, QTableWidgetItem(item.category))
            self.scanners_box_table.setItem(row, 2, QTableWidgetItem(item.language))

            is_inst = item.is_installed_on_host
            status_item = QTableWidgetItem("✅ Installed" if is_inst else "❌ Missing")
            status_item.setForeground(QColor("#22c55e") if is_inst else QColor("#ef4444"))
            self.scanners_box_table.setItem(row, 3, status_item)

    @Slot()
    def _apply_scanners_box_filters(self):
        q = self.scanners_box_search.text().strip()
        cat = self.scanners_box_cat_filter.currentText()
        filtered = ScannersBoxCatalog.search(q, category=cat)
        self._populate_scanners_box_table(filtered)

    @Slot()
    def _on_scanners_box_item_selected(self):
        selected_rows = self.scanners_box_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row_idx = selected_rows[0].row()
        if 0 <= row_idx < len(self._current_sb_items):
            item = self._current_sb_items[row_idx]
            self.selected_sb_item = item

            self.lbl_sb_title.setText(item.display_name)
            self.lbl_sb_cat.setText(f"Domain: {item.category} ({item.language})")
            self.lbl_sb_desc.setText(item.description)
            self.lbl_sb_tags.setText(f"Tags: {' '.join('#' + t for t in item.tags)}")
            self.txt_sb_install.setPlainText(item.install_command)

            self.btn_sb_open_github.setEnabled(bool(item.github_url))
            self.btn_sb_open_shell.setEnabled(item.is_installed_on_host)

    @Slot()
    def _copy_sb_install_command(self):
        cmd = self.txt_sb_install.toPlainText().strip()
        if cmd:
            QApplication.clipboard().setText(cmd)
            QMessageBox.information(self, "Copied", "Install command copied to clipboard.")

    @Slot()
    def _on_sb_open_shell_clicked(self):
        if self.selected_sb_item and self.selected_sb_item.binary_name:
            self.open_shell_requested.emit(self.selected_sb_item.name, f"{self.selected_sb_item.binary_name} --help")

    @Slot()
    def _on_sb_open_github_clicked(self):
        if self.selected_sb_item and self.selected_sb_item.github_url:
            QDesktopServices.openUrl(QUrl(self.selected_sb_item.github_url))

    def _on_theme_changed(self, mode: Union[ThemeMode, str]):
        is_light = str(mode).strip().lower() == "light" or mode == ThemeMode.LIGHT
        if hasattr(self, "header_title"):
            self.header_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {'#0f172a' if is_light else '#f8fafc'};")
        if hasattr(self, "detail_widget"):
            bg = "#ffffff" if is_light else "#0f172a"
            border = "#e2e8f0" if is_light else "#1e293b"
            self.detail_widget.setStyleSheet(f"background: {bg}; border: 1px solid {border}; border-radius: 6px;")
        if hasattr(self, "table"):
            if is_light:
                self.table.setStyleSheet(
                    "QTableWidget { background-color: #ffffff; alternate-background-color: #f8fafc; border: 1px solid #e2e8f0; color: #0f172a; gridline-color: #e2e8f0; }"
                    "QTableWidget::item:selected { background-color: #dbeafe; color: #1e3a8a; }"
                    "QHeaderView::section { background-color: #f1f5f9; color: #0f172a; font-weight: bold; padding: 6px; border: none; border-bottom: 2px solid #cbd5e1; }"
                )
            else:
                self.table.setStyleSheet(
                    "QTableWidget { background-color: #0b1120; alternate-background-color: #111827; border: 1px solid #1e293b; color: #f8fafc; gridline-color: #1e293b; }"
                    "QTableWidget::item:selected { background-color: #1e3a8a; color: #ffffff; }"
                    "QHeaderView::section { background-color: #0f172a; color: #cbd5e1; font-weight: bold; padding: 6px; border: none; border-bottom: 2px solid #334155; }"
                )
        if hasattr(self, "execution_center_tab") and hasattr(self.execution_center_tab, "_on_theme_changed"):
            self.execution_center_tab._on_theme_changed(mode)

