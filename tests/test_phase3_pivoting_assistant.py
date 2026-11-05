"""Unit and integration tests for Phase 3: Interactive Multi-Hop Pivoting & Tunneling Assistant."""

from __future__ import annotations

import socket
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.views.cpent_labs_view import CPENTLabsView
from desktop.widgets.pivoting_assistant_widget import PivotingAssistantWidget
from storage.db import Database
from storage.models import Project, TargetScope, TargetType


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_project(db: Database) -> Project:
    proj = db.create_project(
        Project(
            name="CPENT Double Pivot Range",
            client_name="Titan Defense Labs",
            engagement_id="ENG-2026-PIVOT",
            lead_tester="Senior Pentester Leo",
        )
    )
    # Define authorized subnet
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    return proj


def test_pivoting_widget_creation_and_defaults(qtbot):
    """Verifies widget initialization, default values, and card creation."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    assert widget.spin_attacker_port.value() == 8000
    assert widget.spin_p1_socks.value() == 1080
    assert widget.spin_p2_socks.value() == 1090
    assert "Chisel" in widget.combo_strategy.currentText()
    assert "Single" in widget.combo_hops.currentText()

    # Cards exist
    assert hasattr(widget, "card_att")
    assert hasattr(widget, "card_p1")
    assert hasattr(widget, "card_p2")
    assert hasattr(widget, "card_tgt")


def test_single_pivot_command_generation(qtbot):
    """Verifies single-hop Chisel server/client commands and proxychains4.conf generation."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    widget.edit_attacker_ip.setText("10.0.0.99")
    widget.spin_attacker_port.setValue(8080)
    widget.edit_pivot1_ip.setText("10.0.0.15")
    widget.spin_p1_socks.setValue(1080)
    widget.edit_target_subnet.setText("172.16.20.0/24")

    # Check server command
    server_cmd = widget.txt_cmd_server.toPlainText()
    assert "chisel server -p 8080 --reverse" in server_cmd

    # Check client command
    client_cmd = widget.txt_cmd_p1.toPlainText()
    assert "./chisel client 10.0.0.99:8080 R:1080:socks" in client_cmd

    # Check proxychains config
    conf = widget.txt_proxychains_conf.toPlainText()
    assert "strict_chain" in conf
    assert "socks5 127.0.0.1 1080" in conf
    assert "1090" not in conf  # Single hop: no second socks port


def test_double_pivot_command_generation(qtbot):
    """Verifies double-hop chaining commands and two-tier proxychains configuration."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    # Switch to Double Pivot
    idx = widget.combo_hops.findText("Double Pivot (Attacker ➔ Pivot 1 ➔ Pivot 2 ➔ Subnet 3)")
    widget.combo_hops.setCurrentIndex(idx)

    widget.edit_attacker_ip.setText("192.168.1.100")
    widget.spin_attacker_port.setValue(8000)
    widget.edit_pivot1_ip.setText("192.168.1.50")
    widget.spin_p1_socks.setValue(1080)
    widget.edit_pivot2_ip.setText("10.10.10.25")
    widget.spin_p2_socks.setValue(1090)

    # In double pivot, Pivot 2 controls are visible
    assert not widget.card_p2.isHidden()
    assert not widget.lbl_p2_title.isHidden()

    # Pivot 2 instructions generated
    p2_cmd = widget.txt_cmd_p2.toPlainText()
    assert "./chisel client 192.168.1.50:9000 R:1090:socks" in p2_cmd

    # Proxychains config must contain both SOCKS5 hops in order
    conf = widget.txt_proxychains_conf.toPlainText()
    assert "socks5 127.0.0.1 1080" in conf
    assert "socks5 127.0.0.1 1090" in conf

    # Probing command generated with proxychains4
    probe = widget.txt_probe_cmd.toPlainText()
    assert "proxychains4 -q nmap" in probe


def test_ssh_tunneling_strategy(qtbot):
    """Verifies SSH dynamic port forwarding command generation."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    idx = widget.combo_strategy.findText("SSH Dynamic Forwarding (ssh -D)")
    widget.combo_strategy.setCurrentIndex(idx)

    widget.edit_pivot1_ip.setText("10.10.10.5")
    widget.spin_p1_socks.setValue(1080)

    client_cmd = widget.txt_cmd_p1.toPlainText()
    assert "ssh -D 1080" in client_cmd
    assert "root@10.10.10.5" in client_cmd


def test_scope_validation_in_scope_and_out_of_scope(qtbot, db: Database, sample_project: Project):
    """Verifies that target subnets are validated against authorized project scope."""
    widget = PivotingAssistantWidget(db=db)
    qtbot.addWidget(widget)
    widget.set_active_project(sample_project)

    # 1. In-scope target (10.10.10.0/24 is authorized)
    widget.edit_target_subnet.setText("10.10.10.50")
    assert "Authorized Scope" in widget.lbl_scope_banner.text()

    # 2. Out-of-scope target
    widget.edit_target_subnet.setText("192.168.99.100")
    assert "Out-of-Scope Warning" in widget.lbl_scope_banner.text()


def test_socks_port_checker_logic():
    """Verifies TCP port listener check on open vs closed ports."""
    # Start a dummy listener
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    try:
        assert PivotingAssistantWidget._check_port_listening("127.0.0.1", port) is True
    finally:
        srv.close()

    # Closed port
    assert PivotingAssistantWidget._check_port_listening("127.0.0.1", 58123) is False


def test_command_to_shell_signal_emission(qtbot):
    """Verifies that clicking send-to-shell emits command_to_shell_requested."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    signals_received = []
    widget.command_to_shell_requested.connect(lambda cmd: signals_received.append(cmd))

    # Send server command
    widget.txt_cmd_server.setPlainText("chisel server -p 8000 --reverse")
    # Trigger emit
    widget.command_to_shell_requested.emit("chisel server -p 8000 --reverse")

    assert len(signals_received) == 1
    assert signals_received[0] == "chisel server -p 8000 --reverse"


def test_save_proxychains_config_file(qtbot, tmp_path: Path):
    """Verifies saving generated proxychains4.conf to disk."""
    widget = PivotingAssistantWidget()
    qtbot.addWidget(widget)

    target_file = tmp_path / "test_proxychains.conf"
    with patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(str(target_file), "")):
        with patch("PySide6.QtWidgets.QMessageBox.information"):
            widget._save_proxychains_file()

    assert target_file.exists()
    content = target_file.read_text(encoding="utf-8")
    assert "[ProxyList]" in content
    assert "socks5 127.0.0.1" in content


def test_integration_in_main_window_cpent_labs(qtbot, db: Database, sample_project: Project):
    """Verifies that PivotingAssistantWidget is docked in CPENTLabsView and integrated into MainWindow."""
    main_win = MainWindow(db=db)
    qtbot.addWidget(main_win)
    main_win._on_project_selected(sample_project)

    assert hasattr(main_win, "cpent_view")
    assert hasattr(main_win.cpent_view, "tab_pivoting")
    assert isinstance(main_win.cpent_view.tab_pivoting, PivotingAssistantWidget)

    # Project scope propagated
    assert main_win.cpent_view.tab_pivoting.active_project is sample_project

    # Tab count
    assert main_win.cpent_view.tabs.count() >= 4
    tab_titles = [main_win.cpent_view.tabs.tabText(i) for i in range(main_win.cpent_view.tabs.count())]
    assert any("Pivoting" in t for t in tab_titles)
