"""Interactive Multi-Hop Pivoting & Tunneling Assistant for CPENT.

Provides automated Chisel SOCKS5 proxy setup, SSH dynamic port forwarding,
ProxyChains-ng configuration generation, multi-hop visual routing, local SOCKS port
health testing, and seamless terminal handoff for single and double pivot scenarios.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from desktop.theme import CPENTTheme
from storage.db import Database
from storage.models import Project, TargetScope


class PivotingAssistantWidget(QWidget):
    """Visual multi-hop pivoting, tunneling, and ProxyChains configurator."""

    command_to_shell_requested = Signal(str)
    config_saved = Signal(str)

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self._init_ui()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        self._validate_scope()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # 1. Header with description and scope indicator
        header_box = QHBoxLayout()
        header_text = QVBoxLayout()
        title = QLabel("🔀 Multi-Hop Pivoting & Tunneling Assistant")
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE};")
        subtitle = QLabel(
            "Configure Chisel SOCKS5 reverse proxies, SSH dynamic forwarding, and ProxyChains-ng "
            "for nested internal subnets and CPENT double-pivoting ranges."
        )
        subtitle.setStyleSheet(f"font-size: 11px; color: {CPENTTheme.SECONDARY_TEXT};")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header_box.addLayout(header_text)
        header_box.addStretch()

        self.btn_test_socks = QPushButton("🔄 Test SOCKS Listeners")
        self.btn_test_socks.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.PRIMARY_BLUE}; "
            f"border: 1px solid {CPENTTheme.PRIMARY_BLUE}; font-weight: bold; padding: 6px 14px;"
        )
        self.btn_test_socks.clicked.connect(self._test_socks_ports)
        header_box.addWidget(self.btn_test_socks)
        main_layout.addLayout(header_box)

        # Scope Warning Banner
        self.lbl_scope_banner = QLabel("Scope Status: Ready")
        self.lbl_scope_banner.setWordWrap(True)
        self.lbl_scope_banner.setStyleSheet(
            f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.SECONDARY_TEXT};"
        )
        main_layout.addWidget(self.lbl_scope_banner)

        # Scroll Area for main content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        scroll_content = QWidget()
        content_layout = QVBoxLayout(scroll_content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)

        # 2. Configuration Parameters (Top Box)
        config_group = QGroupBox("1. Pivot Architecture & Hop Parameters")
        cfg_layout = QVBoxLayout(config_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Tunnel Strategy:"))
        self.combo_strategy = QComboBox()
        self.combo_strategy.addItems([
            "Chisel Reverse SOCKS5 (Recommended for CPENT)",
            "SSH Dynamic Forwarding (ssh -D)",
            "Ligolo-ng (TUN Interface)",
            "Windows Netsh Portproxy",
        ])
        self.combo_strategy.currentIndexChanged.connect(self._on_parameters_changed)
        row1.addWidget(self.combo_strategy, 2)

        row1.addWidget(QLabel("Hop Depth:"))
        self.combo_hops = QComboBox()
        self.combo_hops.addItems([
            "Single Pivot (Attacker ➔ Pivot 1 ➔ Subnet 2)",
            "Double Pivot (Attacker ➔ Pivot 1 ➔ Pivot 2 ➔ Subnet 3)",
        ])
        self.combo_hops.currentIndexChanged.connect(self._on_parameters_changed)
        row1.addWidget(self.combo_hops, 2)
        cfg_layout.addLayout(row1)

        # Detailed IP/Port inputs
        grid = QHBoxLayout()

        # Attacker details
        box_att = QVBoxLayout()
        box_att.addWidget(QLabel("Attacker Kali IP:"))
        self.edit_attacker_ip = QLineEdit("192.168.1.100")
        self.edit_attacker_ip.textChanged.connect(self._on_parameters_changed)
        box_att.addWidget(self.edit_attacker_ip)
        box_att.addWidget(QLabel("Server Listener Port:"))
        self.spin_attacker_port = QSpinBox()
        self.spin_attacker_port.setRange(1024, 65535)
        self.spin_attacker_port.setValue(8000)
        self.spin_attacker_port.valueChanged.connect(self._on_parameters_changed)
        box_att.addWidget(self.spin_attacker_port)
        grid.addLayout(box_att)

        # Pivot 1 details
        box_p1 = QVBoxLayout()
        box_p1.addWidget(QLabel("Pivot Host 1 IP (Public/Faced):"))
        self.edit_pivot1_ip = QLineEdit("192.168.1.50")
        self.edit_pivot1_ip.textChanged.connect(self._on_parameters_changed)
        box_p1.addWidget(self.edit_pivot1_ip)
        box_p1.addWidget(QLabel("Hop 1 Local SOCKS Port:"))
        self.spin_p1_socks = QSpinBox()
        self.spin_p1_socks.setRange(1024, 65535)
        self.spin_p1_socks.setValue(1080)
        self.spin_p1_socks.valueChanged.connect(self._on_parameters_changed)
        box_p1.addWidget(self.spin_p1_socks)
        grid.addLayout(box_p1)

        # Pivot 2 details (for Double Pivot)
        self.box_p2 = QVBoxLayout()
        self.lbl_p2_title = QLabel("Pivot Host 2 IP (Internal):")
        self.box_p2.addWidget(self.lbl_p2_title)
        self.edit_pivot2_ip = QLineEdit("10.10.10.20")
        self.edit_pivot2_ip.textChanged.connect(self._on_parameters_changed)
        self.box_p2.addWidget(self.edit_pivot2_ip)
        self.lbl_p2_socks = QLabel("Hop 2 Local SOCKS Port:")
        self.box_p2.addWidget(self.lbl_p2_socks)
        self.spin_p2_socks = QSpinBox()
        self.spin_p2_socks.setRange(1024, 65535)
        self.spin_p2_socks.setValue(1090)
        self.spin_p2_socks.valueChanged.connect(self._on_parameters_changed)
        self.box_p2.addWidget(self.spin_p2_socks)
        grid.addLayout(self.box_p2)

        # Target Internal Subnet
        box_tgt = QVBoxLayout()
        box_tgt.addWidget(QLabel("Target Internal Subnet:"))
        self.edit_target_subnet = QLineEdit("10.10.10.0/24")
        self.edit_target_subnet.textChanged.connect(self._on_parameters_changed)
        box_tgt.addWidget(self.edit_target_subnet)
        box_tgt.addWidget(QLabel("ProxyChains Chaining:"))
        self.combo_chain_type = QComboBox()
        self.combo_chain_type.addItems(["strict_chain", "dynamic_chain"])
        self.combo_chain_type.currentIndexChanged.connect(self._on_parameters_changed)
        box_tgt.addWidget(self.combo_chain_type)
        grid.addLayout(box_tgt)

        cfg_layout.addLayout(grid)
        content_layout.addWidget(config_group)

        # 3. Visual Hop Diagram (Interactive Cards)
        diag_group = QGroupBox("2. Visual Network Tunnel Flow")
        diag_layout = QVBoxLayout(diag_group)

        self.cards_layout = QHBoxLayout()
        self.cards_layout.setSpacing(8)

        # Attacker Card
        self.card_att = self._create_hop_card("Kali Workstation", "192.168.1.100", "Attacker Box", CPENTTheme.PRIMARY_BLUE)
        self.cards_layout.addWidget(self.card_att)

        self.arrow1 = QLabel(" ──(Hop 1)──▶ ")
        self.arrow1.setStyleSheet("font-weight: bold; color: #8B95A3;")
        self.cards_layout.addWidget(self.arrow1)

        # Pivot 1 Card
        self.card_p1 = self._create_hop_card("Pivot 1 (Gateway)", "192.168.1.50", "SOCKS5: 127.0.0.1:1080", "#26A69A")
        self.cards_layout.addWidget(self.card_p1)

        self.arrow2 = QLabel(" ──(Hop 2)──▶ ")
        self.arrow2.setStyleSheet("font-weight: bold; color: #8B95A3;")
        self.cards_layout.addWidget(self.arrow2)

        # Pivot 2 Card
        self.card_p2 = self._create_hop_card("Pivot 2 (Internal)", "10.10.10.20", "SOCKS5: 127.0.0.1:1090", "#FFB74D")
        self.cards_layout.addWidget(self.card_p2)

        self.arrow3 = QLabel(" ──(Target)──▶ ")
        self.arrow3.setStyleSheet("font-weight: bold; color: #8B95A3;")
        self.cards_layout.addWidget(self.arrow3)

        # Target Subnet Card
        self.card_tgt = self._create_hop_card("Target Subnet", "10.10.10.0/24", "Isolated Crown Jewels", "#E57373")
        self.cards_layout.addWidget(self.card_tgt)

        diag_layout.addLayout(self.cards_layout)

        # Status row under diagram
        status_row = QHBoxLayout()
        self.lbl_p1_status = QLabel("● Hop 1 (1080): Not Tested")
        self.lbl_p1_status.setStyleSheet("color: #8B95A3; font-size: 11px;")
        status_row.addWidget(self.lbl_p1_status)

        self.lbl_p2_status = QLabel("● Hop 2 (1090): Not Tested")
        self.lbl_p2_status.setStyleSheet("color: #8B95A3; font-size: 11px;")
        status_row.addWidget(self.lbl_p2_status)
        status_row.addStretch()

        diag_layout.addLayout(status_row)
        content_layout.addWidget(diag_group)

        # 4. Command Generator & ProxyChains Config Tabs
        commands_group = QGroupBox("3. Generated Tunneling Commands & Configuration")
        cmd_box_layout = QVBoxLayout(commands_group)

        self.cmd_tabs = QTabWidget()

        # Subtab A: Chisel Server (Attacker Listener)
        tab_server = QWidget()
        ts_layout = QVBoxLayout(tab_server)
        ts_layout.addWidget(QLabel("Step 1: Start Chisel Reverse Server on Attacker Kali Box:"))
        self.txt_cmd_server = QPlainTextEdit()
        self.txt_cmd_server.setReadOnly(True)
        self.txt_cmd_server.setMaximumHeight(85)
        self.txt_cmd_server.setStyleSheet("font-family: monospace; font-size: 12px;")
        ts_layout.addWidget(self.txt_cmd_server)
        btn_row_s = QHBoxLayout()
        btn_copy_s = QPushButton("📋 Copy Server Command")
        btn_copy_s.clicked.connect(lambda: self._copy_to_clipboard(self.txt_cmd_server.toPlainText()))
        btn_shell_s = QPushButton("🖥️ Send to Command Shell")
        btn_shell_s.setStyleSheet(f"background-color: {CPENTTheme.PRIMARY_BLUE}; color: white; font-weight: bold;")
        btn_shell_s.clicked.connect(lambda: self.command_to_shell_requested.emit(self.txt_cmd_server.toPlainText()))
        btn_row_s.addWidget(btn_copy_s)
        btn_row_s.addWidget(btn_shell_s)
        btn_row_s.addStretch()
        ts_layout.addLayout(btn_row_s)
        self.cmd_tabs.addTab(tab_server, "🖥️ Attacker Server")

        # Subtab B: Pivot 1 Client
        tab_p1 = QWidget()
        tp1_layout = QVBoxLayout(tab_p1)
        tp1_layout.addWidget(QLabel("Step 2: Execute Chisel Client on Compromised Pivot Host 1:"))
        self.txt_cmd_p1 = QPlainTextEdit()
        self.txt_cmd_p1.setReadOnly(True)
        self.txt_cmd_p1.setMaximumHeight(85)
        self.txt_cmd_p1.setStyleSheet("font-family: monospace; font-size: 12px;")
        tp1_layout.addWidget(self.txt_cmd_p1)
        btn_row_p1 = QHBoxLayout()
        btn_copy_p1 = QPushButton("📋 Copy Pivot 1 Command")
        btn_copy_p1.clicked.connect(lambda: self._copy_to_clipboard(self.txt_cmd_p1.toPlainText()))
        btn_row_p1.addWidget(btn_copy_p1)
        btn_row_p1.addStretch()
        tp1_layout.addLayout(btn_row_p1)
        self.cmd_tabs.addTab(tab_p1, "🔀 Pivot 1 Client")

        # Subtab C: Pivot 2 (Double Pivot)
        tab_p2 = QWidget()
        tp2_layout = QVBoxLayout(tab_p2)
        tp2_layout.addWidget(QLabel("Step 3: Execute on Pivot 2 to Chain Through Pivot 1 (Double Pivot):"))
        self.txt_cmd_p2 = QPlainTextEdit()
        self.txt_cmd_p2.setReadOnly(True)
        self.txt_cmd_p2.setMaximumHeight(85)
        self.txt_cmd_p2.setStyleSheet("font-family: monospace; font-size: 12px;")
        tp2_layout.addWidget(self.txt_cmd_p2)
        btn_row_p2 = QHBoxLayout()
        btn_copy_p2 = QPushButton("📋 Copy Pivot 2 Command")
        btn_copy_p2.clicked.connect(lambda: self._copy_to_clipboard(self.txt_cmd_p2.toPlainText()))
        btn_row_p2.addWidget(btn_copy_p2)
        btn_row_p2.addStretch()
        tp2_layout.addLayout(btn_row_p2)
        self.cmd_tabs.addTab(tab_p2, "🔀 Pivot 2 (Double Pivot)")

        # Subtab D: ProxyChains Config (proxychains4.conf)
        tab_pc = QWidget()
        tpc_layout = QVBoxLayout(tab_pc)
        tpc_layout.addWidget(QLabel("ProxyChains-ng Configuration (`proxychains4.conf`):"))
        self.txt_proxychains_conf = QPlainTextEdit()
        self.txt_proxychains_conf.setReadOnly(True)
        self.txt_proxychains_conf.setMaximumHeight(140)
        self.txt_proxychains_conf.setStyleSheet("font-family: monospace; font-size: 11px;")
        tpc_layout.addWidget(self.txt_proxychains_conf)
        btn_row_pc = QHBoxLayout()
        btn_copy_pc = QPushButton("📋 Copy Config")
        btn_copy_pc.clicked.connect(lambda: self._copy_to_clipboard(self.txt_proxychains_conf.toPlainText()))
        btn_save_pc = QPushButton("💾 Save proxychains4.conf")
        btn_save_pc.clicked.connect(self._save_proxychains_file)
        btn_row_pc.addWidget(btn_copy_pc)
        btn_row_pc.addWidget(btn_save_pc)
        btn_row_pc.addStretch()
        tpc_layout.addLayout(btn_row_pc)
        self.cmd_tabs.addTab(tab_pc, "⚙️ proxychains4.conf")

        # Subtab E: Probing & Scanning via Proxy
        tab_probe = QWidget()
        tpr_layout = QVBoxLayout(tab_probe)
        tpr_layout.addWidget(QLabel("Ready-to-Run Scan Commands via Tunnel:"))
        self.txt_probe_cmd = QPlainTextEdit()
        self.txt_probe_cmd.setReadOnly(True)
        self.txt_probe_cmd.setMaximumHeight(140)
        self.txt_probe_cmd.setStyleSheet("font-family: monospace; font-size: 11px;")
        tpr_layout.addWidget(self.txt_probe_cmd)
        btn_row_pr = QHBoxLayout()
        btn_copy_pr = QPushButton("📋 Copy Scan Command")
        btn_copy_pr.clicked.connect(lambda: self._copy_to_clipboard(self.txt_probe_cmd.toPlainText()))
        btn_shell_pr = QPushButton("🖥️ Run via Command Shell")
        btn_shell_pr.setStyleSheet(f"background-color: {CPENTTheme.SUCCESS_GREEN}; color: white; font-weight: bold;")
        btn_shell_pr.clicked.connect(lambda: self.command_to_shell_requested.emit(self.txt_probe_cmd.toPlainText().splitlines()[0] if self.txt_probe_cmd.toPlainText() else ""))
        btn_row_pr.addWidget(btn_copy_pr)
        btn_row_pr.addWidget(btn_shell_pr)
        btn_row_pr.addStretch()
        tpr_layout.addLayout(btn_row_pr)
        self.cmd_tabs.addTab(tab_probe, "🚀 Scan via Tunnel")

        cmd_box_layout.addWidget(self.cmd_tabs)
        content_layout.addWidget(commands_group)

        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

        # Initial calculation
        self._update_ui_state()

    def _create_hop_card(self, title: str, ip: str, detail: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.color_hex = color_hex
        card.setStyleSheet(
            f"QFrame {{ background-color: {CPENTTheme.CARD_BG}; border: 1px solid {color_hex}; "
            f"border-radius: 6px; padding: 10px; }}"
        )
        card.setMinimumWidth(180)
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(6, 6, 6, 6)
        c_layout.setSpacing(4)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {color_hex};")
        lbl_ip = QLabel(f"IP: {ip}")
        lbl_ip.setStyleSheet("font-size: 11px; font-weight: bold;")
        lbl_d = QLabel(detail)
        lbl_d.setStyleSheet("font-size: 10px; color: #8B95A3;")

        c_layout.addWidget(lbl_t)
        c_layout.addWidget(lbl_ip)
        c_layout.addWidget(lbl_d)

        # Save refs for dynamic update
        card.lbl_t = lbl_t
        card.lbl_ip = lbl_ip
        card.lbl_d = lbl_d
        return card

    def update_theme(self, mode: Optional[str] = None):
        """Updates card backgrounds and text contrast for dark and light modes."""
        is_dark = (mode != "light")
        card_bg = "#20232B" if is_dark else "#F1F5F9"
        text_ip = "#F3F4F6" if is_dark else "#0F172A"
        text_d = "#8B95A3" if is_dark else "#475569"

        for card in [
            getattr(self, "card_att", None),
            getattr(self, "card_p1", None),
            getattr(self, "card_p2", None),
            getattr(self, "card_tgt", None),
        ]:
            if card:
                color_hex = getattr(card, "color_hex", CPENTTheme.PRIMARY_BLUE)
                card.setStyleSheet(
                    f"QFrame {{ background-color: {card_bg}; border: 1px solid {color_hex}; "
                    f"border-radius: 6px; padding: 10px; }}"
                )
                if hasattr(card, "lbl_ip"):
                    card.lbl_ip.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {text_ip};")
                if hasattr(card, "lbl_d"):
                    card.lbl_d.setStyleSheet(f"font-size: 10px; color: {text_d};")

    def _on_parameters_changed(self):
        self._update_ui_state()
        self._validate_scope()

    def _update_ui_state(self):
        is_double = "Double" in self.combo_hops.currentText()
        strategy = self.combo_strategy.currentText()

        # Update visibility of Hop 2 controls
        self.lbl_p2_title.setVisible(is_double)
        self.edit_pivot2_ip.setVisible(is_double)
        self.lbl_p2_socks.setVisible(is_double)
        self.spin_p2_socks.setVisible(is_double)
        self.arrow2.setVisible(is_double)
        self.card_p2.setVisible(is_double)
        self.lbl_p2_status.setVisible(is_double)

        # Update Card Visuals
        att_ip = self.edit_attacker_ip.text().strip() or "192.168.1.100"
        att_port = self.spin_attacker_port.value()
        p1_ip = self.edit_pivot1_ip.text().strip() or "192.168.1.50"
        p1_socks = self.spin_p1_socks.value()
        p2_ip = self.edit_pivot2_ip.text().strip() or "10.10.10.20"
        p2_socks = self.spin_p2_socks.value()
        target_subnet = self.edit_target_subnet.text().strip() or "10.10.10.0/24"

        self.card_att.lbl_ip.setText(f"IP: {att_ip}")
        self.card_att.lbl_d.setText(f"Listen Port: {att_port}")

        self.card_p1.lbl_ip.setText(f"IP: {p1_ip}")
        self.card_p1.lbl_d.setText(f"SOCKS5: 127.0.0.1:{p1_socks}")

        if is_double:
            self.card_p2.lbl_ip.setText(f"IP: {p2_ip}")
            self.card_p2.lbl_d.setText(f"SOCKS5: 127.0.0.1:{p2_socks}")

        self.card_tgt.lbl_ip.setText(f"Subnet: {target_subnet}")
        self.card_tgt.lbl_d.setText("Authorized Target Scope" if "Authorized" in self.lbl_scope_banner.text() else "Target Range")

        # Generate Commands
        chain_type = self.combo_chain_type.currentText()

        if "Chisel" in strategy:
            server_cmd = f"chisel server -p {att_port} --reverse"
            p1_cmd = f"./chisel client {att_ip}:{att_port} R:{p1_socks}:socks"
            if is_double:
                p2_cmd = (
                    f"# On Pivot 1: ./chisel server -p 9000 --reverse\n"
                    f"# On Pivot 2: ./chisel client {p1_ip}:9000 R:{p2_socks}:socks"
                )
            else:
                p2_cmd = "# Single pivot selected. Pivot 2 is not required."
        elif "SSH" in strategy:
            server_cmd = "# SSH Listener is managed by sshd on Pivot 1 (no Kali listener needed)"
            p1_cmd = f"ssh -D {p1_socks} -N -f -q root@{p1_ip}"
            p2_cmd = f"ssh -D {p2_socks} -o ProxyJump=root@{p1_ip} -N -f -q root@{p2_ip}" if is_double else "# Single pivot."
        else:
            server_cmd = f"# Start server for {strategy}"
            p1_cmd = f"# Route traffic through {p1_ip}"
            p2_cmd = f"# Double pivot via {p2_ip}"

        self.txt_cmd_server.setPlainText(server_cmd)
        self.txt_cmd_p1.setPlainText(p1_cmd)
        self.txt_cmd_p2.setPlainText(p2_cmd)

        # Generate proxychains4.conf
        conf_lines = [
            f"# CyberSecuritySuite Generated proxychains4.conf",
            f"{chain_type}",
            f"proxy_dns",
            f"tcp_read_time_out 15000",
            f"tcp_connect_time_out 8000",
            f"",
            f"[ProxyList]",
            f"socks5 127.0.0.1 {p1_socks}",
        ]
        if is_double:
            conf_lines.append(f"socks5 127.0.0.1 {p2_socks}")

        self.txt_proxychains_conf.setPlainText("\n".join(conf_lines))

        # Generate Sample Probing Commands
        target_example_ip = target_subnet.split("/")[0]
        if target_example_ip.endswith(".0"):
            target_example_ip = target_example_ip[:-1] + "10"

        scan_cmds = [
            f"proxychains4 -q nmap -sT -Pn -n -p 21,22,80,443,445,3389 {target_example_ip}",
            f"proxychains4 -q gobuster dir --url http://{target_example_ip} -w /usr/share/wordlists/dirb/common.txt",
            f"proxychains4 -q crackmapexec smb {target_subnet} -u 'admin' -p 'password'",
        ]
        self.txt_probe_cmd.setPlainText("\n".join(scan_cmds))

    def _validate_scope(self):
        target = self.edit_target_subnet.text().strip()
        if not target:
            self.lbl_scope_banner.setText("Scope Status: Please enter a target internal subnet.")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.MUTED_TEXT};"
            )
            return

        if not self.db or not self.active_project:
            self.lbl_scope_banner.setText(f"Scope Status: Target {target} entered (Project scope not loaded).")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.SECONDARY_TEXT};"
            )
            return

        scopes = self.db.list_scopes(self.active_project.id)
        from core.scope import ScopeAuthorizationService
        auth_check = ScopeAuthorizationService.is_target_authorized(target, scopes)

        if auth_check.is_allowed:
            self.lbl_scope_banner.setText(f"✓ Authorized Scope: '{target}' matches approved project scope rules.")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: rgba(38,166,154,0.15); color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold;"
            )
        else:
            self.lbl_scope_banner.setText(
                f"⚠ Out-of-Scope Warning: '{target}' is not in approved project scope! "
                "Pivoting traffic into unauthorized networks is strictly prohibited."
            )
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: rgba(229,115,115,0.15); color: {CPENTTheme.ERROR_RED}; font-weight: bold;"
            )

    def _test_socks_ports(self):
        """Tests whether local SOCKS5 proxy ports (e.g. 1080, 1090) are actively listening."""
        p1_socks = self.spin_p1_socks.value()
        p2_socks = self.spin_p2_socks.value()
        is_double = "Double" in self.combo_hops.currentText()

        # Test Hop 1 Port
        p1_active = self._check_port_listening("127.0.0.1", p1_socks)
        if p1_active:
            self.lbl_p1_status.setText(f"🟢 Hop 1 (127.0.0.1:{p1_socks}): Active & Listening")
            self.lbl_p1_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold; font-size: 11px;")
        else:
            self.lbl_p1_status.setText(f"🔴 Hop 1 (127.0.0.1:{p1_socks}): Inactive (Port Closed)")
            self.lbl_p1_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-size: 11px;")

        # Test Hop 2 Port
        if is_double:
            p2_active = self._check_port_listening("127.0.0.1", p2_socks)
            if p2_active:
                self.lbl_p2_status.setText(f"🟢 Hop 2 (127.0.0.1:{p2_socks}): Active & Listening")
                self.lbl_p2_status.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold; font-size: 11px;")
            else:
                self.lbl_p2_status.setText(f"🔴 Hop 2 (127.0.0.1:{p2_socks}): Inactive (Port Closed)")
                self.lbl_p2_status.setStyleSheet(f"color: {CPENTTheme.ERROR_RED}; font-size: 11px;")

    @staticmethod
    def _check_port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
        """Returns True if a TCP port is listening on the host."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((host, port))
            return result == 0
        except Exception:
            return False
        finally:
            s.close()

    def _copy_to_clipboard(self, text: str):
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "Copied", "Command copied to clipboard.")

    def _save_proxychains_file(self):
        conf_text = self.txt_proxychains_conf.toPlainText()
        if not conf_text:
            return

        default_dir = str(Path.cwd())
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save ProxyChains Configuration",
            str(Path(default_dir) / "proxychains4.conf"),
            "Config Files (*.conf);;All Files (*)",
        )
        if file_path:
            try:
                Path(file_path).write_text(conf_text, encoding="utf-8")
                self.config_saved.emit(file_path)
                QMessageBox.information(
                    self,
                    "Config Saved",
                    f"Successfully saved ProxyChains configuration to:\n{file_path}\n\n"
                    f"You can now run:\nproxychains4 -f {file_path} <tool_command>",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Save Failed", f"Could not write file: {exc}")
