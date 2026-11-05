"""Tests for Network Discovery and Network Map Synchronization.

Verifies:
1. Ping-sweep and zero-open-port hosts (e.g. 192.168.100.3) persist to SQLite and display in Master Grid and Network Map.
2. Multi-port hosts (e.g. 192.168.100.7 with 4 open ports, 192.168.100.40 with 1 open port) persist complete service telemetry.
3. Hostname deduplication: IP nodes and hostname alias nodes merge into single host items without duplicates.
4. User manual 2D drawings (is_observed == False) are preserved across discovery updates.
5. Inactive/archived project authorization prompt properly activates project and allows scan execution.
6. Project data refresh updates both MainWindow.topology_view and NetworkScanView.map_view.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from core.asset_inventory import AssetInventoryService
from desktop.main_window import MainWindow
from desktop.views.network_scan_view import NetworkScanView
from desktop.widgets.network_map_view import NetworkMapView
from desktop.widgets.topology_designer import (
    DeviceType,
    TopologyDesignerWidget,
)
from storage.db import Database
from storage.models import (
    AssetNode,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.ingest import TerminalIngestEngine


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_netmap_sync.db"
    return Database(db_file)


@pytest.fixture
def active_project(test_db: Database) -> Project:
    proj = test_db.create_project(
        Project(
            name="Network Discovery Audit",
            client_name="Test Enterprise",
            status=ProjectStatus.ACTIVE,
        )
    )
    # Authorize local /24 subnet
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.100.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_zero_open_port_host_persistence_and_display(qtbot, test_db: Database, active_project: Project):
    """Verifies hosts with 0 open ports (e.g. 192.168.100.3) persist and appear in Master Grid and Network Map."""
    # Console output where 100 ports were closed but host is UP
    nmap_closed_output = (
        "Starting Nmap 7.94 ( https://nmap.org )\n"
        "Nmap scan report for 192.168.100.3\n"
        "Host is up (0.0050s latency).\n"
        "All 100 scanned ports on 192.168.100.3 are in ignored states.\n"
        "Not shown: 100 closed tcp ports (reset)\n"
        "MAC Address: 00:11:22:33:44:55 (Vendor Inc)\n"
        "Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds\n"
    )

    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap -F 192.168.100.3",
        output=nmap_closed_output,
    )

    # 1. Verify live host observation was recorded
    findings = test_db.list_findings(active_project.id)
    assert any(f.affected_asset == "192.168.100.3" for f in findings), "192.168.100.3 must be recorded in findings"

    # 2. Verify Master Grid displays zero-open-port host as UP
    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(active_project)
    scan_view._refresh_erp_dashboard()

    assert scan_view.erp_master_table.rowCount() == 1
    assert scan_view.erp_master_table.item(0, 0).text() == "192.168.100.3"
    assert scan_view.erp_master_table.item(0, 1).text() == "UP (Discovered)"
    assert "None detected" in scan_view.erp_master_table.item(0, 5).text()

    # 3. Verify Network Map (Cyber Sentinel) loads the zero-port host
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.load_discovered_assets(test_db, active_project.id)
    assert map_view.list_devices.count() == 1
    assert "192.168.100.3" in map_view.list_devices.item(0).text()
    assert "0 ports" in map_view.list_devices.item(0).text()


def test_multi_port_hosts_services_telemetry(qtbot, test_db: Database, active_project: Project):
    """Verifies hosts with open ports (192.168.100.7 and 192.168.100.40) persist port and service details."""
    nmap_multi_output = (
        "Starting Nmap 7.94 ( https://nmap.org )\n"
        "Nmap scan report for leo (192.168.100.7)\n"
        "Host is up (0.00045s latency).\n"
        "PORT    STATE SERVICE VERSION\n"
        "21/tcp  open  ftp     vsftpd 3.0.5\n"
        "25/tcp  open  smtp    Postfix smtpd\n"
        "80/tcp  open  http    Apache httpd 2.4.58 (Ubuntu)\n"
        "111/tcp open  rpcbind 2-4 (RPC #100000)\n"
        "Service Info: Host: leo; OS: Unix\n"
        "\n"
        "Nmap scan report for web.local (192.168.100.40)\n"
        "Host is up (0.0012s latency).\n"
        "PORT   STATE SERVICE VERSION\n"
        "80/tcp open  http    nginx 1.18.0\n"
        "Nmap done: 2 IP addresses (2 hosts up) scanned in 2.50 seconds\n"
    )

    TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="pty_terminal",
        command="nmap -sV 192.168.100.7 192.168.100.40",
        output=nmap_multi_output,
    )

    # Verify both assets in database
    nodes = test_db.list_asset_nodes(active_project.id)
    ip_map = {n.value: n for n in nodes if n.node_type == "ip"}
    assert "192.168.100.7" in ip_map
    assert "192.168.100.40" in ip_map

    meta_7 = json.loads(ip_map["192.168.100.7"].metadata_json)
    assert meta_7["open_ports"] == [21, 25, 80, 111]
    assert len(meta_7["services"]) == 4

    # Verify ERP Master Grid displays both hosts with ports
    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(active_project)
    scan_view._refresh_erp_dashboard()

    displayed_rows = {
        scan_view.erp_master_table.item(r, 0).text(): scan_view.erp_master_table.item(r, 5).text()
        for r in range(scan_view.erp_master_table.rowCount())
    }
    assert "192.168.100.7" in displayed_rows
    assert "21/ftp" in displayed_rows["192.168.100.7"]
    assert "80/http" in displayed_rows["192.168.100.7"]
    assert "192.168.100.40" in displayed_rows
    assert "80/http" in displayed_rows["192.168.100.40"]


def test_hostname_deduplication_no_duplicate_nodes(qtbot, test_db: Database, active_project: Project):
    """Verifies that an IP node and a hostname node do not create duplicate nodes."""
    # 1. Create IP node
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.7",
            label="leo",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [21, 80], "services": [{"port": 80, "service": "http"}]}),
        )
    )
    # 2. Create Hostname node for the same device
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="hostname",
            value="leo",
            label="leo",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"ip": "192.168.100.7"}),
        )
    )

    # Test NetworkMapView (Cyber Sentinel scene)
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.load_discovered_assets(test_db, active_project.id)
    assert map_view.list_devices.count() == 1, "Expected 1 deduplicated device in NetworkMapView"

    # Test TopologyDesignerWidget (2D diagram designer)
    designer = TopologyDesignerWidget(db=test_db)
    qtbot.addWidget(designer)
    designer.set_active_project(active_project)
    designer.load_discovered_assets(test_db, active_project.id)
    devices = designer.scene.get_devices()
    assert len(devices) == 1, "Expected 1 deduplicated device on 2D TopologyDesigner canvas"
    assert devices[0].ip_address == "192.168.100.7"
    assert devices[0].hostname == "leo"


def test_manual_2d_drawing_preservation(qtbot, test_db: Database, active_project: Project):
    """Verifies manually drawn devices (is_observed == False) are preserved when discovered assets load."""
    designer = TopologyDesignerWidget(db=test_db)
    qtbot.addWidget(designer)
    designer.set_active_project(active_project)

    # User manually adds a firewall
    manual_fw = designer.scene.add_device(
        device_type=DeviceType.FIREWALL,
        label="Edge Perimeter FW",
        ip_address="192.168.100.254",
        notes="Manually drawn during scope kickoff",
        x=100.0,
        y=100.0,
    )
    manual_fw.is_observed = False

    assert len(designer.scene.get_devices()) == 1

    # Now simulate scanning adding 192.168.100.7
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.7",
            label="192.168.100.7",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [80]}),
        )
    )

    designer.load_discovered_assets(test_db, active_project.id)

    devices = designer.scene.get_devices()
    assert len(devices) == 2, "Expected 2 devices: 1 manual + 1 discovered"
    dev_labels = {d.label for d in devices}
    assert "Edge Perimeter FW" in dev_labels
    assert "192.168.100.7" in dev_labels

    # Manual node should still have is_observed == False
    manual_item = next(d for d in devices if d.label == "Edge Perimeter FW")
    assert manual_item.is_observed is False


def test_archived_project_fails_closed_and_blocks_scanning(qtbot, test_db: Database):
    """Verifies that an archived project strictly blocks scanning without silently activating."""
    archived_proj = test_db.create_project(
        Project(
            name="Archived Lab",
            client_name="Lab Corp",
            status=ProjectStatus.ARCHIVED,
        )
    )

    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(archived_proj)

    with patch("PySide6.QtWidgets.QMessageBox.critical") as mock_crit, \
         patch.object(scan_view.adapter, "execute_scan") as mock_exec:
        scan_view.erp_target_input.setText("192.168.100.7")
        scan_view.target_input.setText("192.168.100.7")
        scan_view._start_scan()

        # Must show critical error and block scan
        mock_crit.assert_called_once()
        mock_exec.assert_not_called()

    # Project MUST remain ARCHIVED in both memory and SQLite
    updated_proj = test_db.get_project(archived_proj.id)
    assert updated_proj.status == ProjectStatus.ARCHIVED
    assert scan_view.active_project.status == ProjectStatus.ARCHIVED


def test_paused_project_explicit_activation_workflow(qtbot, test_db: Database):
    """Verifies that paused/draft projects require explicit user confirmation to activate."""
    paused_proj = test_db.create_project(
        Project(
            name="Paused Engagement",
            client_name="Lab Corp",
            status=ProjectStatus.PAUSED,
        )
    )

    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(paused_proj)

    # 1. If user declines activation -> fails closed
    with patch("PySide6.QtWidgets.QMessageBox.question", return_value=pytest.importorskip("PySide6.QtWidgets").QMessageBox.StandardButton.No), \
         patch.object(scan_view.adapter, "execute_scan") as mock_exec:
        scan_view.target_input.setText("192.168.100.7")
        scan_view._start_scan()
        mock_exec.assert_not_called()
        assert test_db.get_project(paused_proj.id).status == ProjectStatus.PAUSED

    # 2. If user explicitly confirms activation -> transitions to ACTIVE and authorizes target
    with patch("PySide6.QtWidgets.QMessageBox.question", return_value=pytest.importorskip("PySide6.QtWidgets").QMessageBox.StandardButton.Yes), \
         patch.object(scan_view.adapter, "execute_scan", return_value=MagicMock(is_authorized=True, scan_result=None, findings=[], execution=None)):
        scan_view.target_input.setText("192.168.100.7")
        scan_view._start_scan()
        assert test_db.get_project(paused_proj.id).status == ProjectStatus.ACTIVE
        assert scan_view.active_project.status == ProjectStatus.ACTIVE


def test_main_window_refresh_syncs_both_network_maps(qtbot, test_db: Database, active_project: Project):
    """Verifies MainWindow._refresh_project_data() synchronizes both topology_view and network_view.map_view."""
    from desktop.main_window import MainWindow

    # Insert test assets
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.7",
            label="leo",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [21, 25, 80, 111], "services": [{"port": 80, "service": "http"}]}),
        )
    )

    win = MainWindow(db=test_db)
    qtbot.addWidget(win)
    win._on_project_selected(active_project)

    # 1. Verify MainWindow.topology_view (Sub-tab 4) loaded the asset
    assert len(win.topology_view.scene.get_devices()) == 1
    dev = win.topology_view.scene.get_devices()[0]
    assert dev.ip_address == "192.168.100.7"

    # 2. Verify NetworkScanView.map_view (Embedded Tab 6) loaded the asset
    assert win.network_view.map_view.list_devices.count() == 1
    assert "192.168.100.7" in win.network_view.map_view.list_devices.item(0).text()

    # 3. Add a second asset (e.g. 192.168.100.40) and trigger refresh
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.40",
            label="web.corp",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [80], "services": [{"port": 80, "service": "http"}]}),
        )
    )

    win._refresh_project_data(active_project.id)

    # Both views must now reflect 2 assets
    assert len(win.topology_view.scene.get_devices()) == 2
    assert win.network_view.map_view.list_devices.count() == 2
    assert win.network_view.erp_master_table.rowCount() == 2



    # Simulate user answering Yes to scope authorization dialog and mock scan execution
    with patch("PySide6.QtWidgets.QMessageBox.question", return_value=pytest.importorskip("PySide6.QtWidgets").QMessageBox.StandardButton.Yes), \
         patch.object(scan_view.adapter, "execute_scan", return_value=MagicMock(is_authorized=True, scan_result=None, findings=[], execution=None)):
        scan_view.erp_target_input.setText("192.168.100.7")
        # Run _start_scan directly
        scan_view.target_input.setText("192.168.100.7")
        scan_view._start_scan()

    # Verify project was transitioned to ACTIVE in both memory and SQLite
    updated_proj = test_db.get_project(archived_proj.id)
    assert updated_proj.status == ProjectStatus.ACTIVE
    assert scan_view.active_project.status == ProjectStatus.ACTIVE


def test_main_window_refresh_syncs_both_network_maps(qtbot, test_db: Database, active_project: Project):
    """Verifies MainWindow._refresh_project_data() synchronizes both topology_view and network_view.map_view."""
    from desktop.main_window import MainWindow

    # Insert test assets
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.7",
            label="leo",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [21, 25, 80, 111], "services": [{"port": 80, "service": "http"}]}),
        )
    )

    win = MainWindow(db=test_db)
    qtbot.addWidget(win)
    win._on_project_selected(active_project)

    # 1. Verify MainWindow.topology_view (Sub-tab 4) loaded the asset
    assert len(win.topology_view.scene.get_devices()) == 1
    dev = win.topology_view.scene.get_devices()[0]
    assert dev.ip_address == "192.168.100.7"

    # 2. Verify NetworkScanView.map_view (Embedded Tab 6) loaded the asset
    assert win.network_view.map_view.list_devices.count() == 1
    assert "192.168.100.7" in win.network_view.map_view.list_devices.item(0).text()

    # 3. Add a second asset (e.g. 192.168.100.40) and trigger refresh
    test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.40",
            label="web.corp",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [80], "services": [{"port": 80, "service": "http"}]}),
        )
    )

    win._refresh_project_data(active_project.id)

    # Both views must now reflect 2 assets
    assert len(win.topology_view.scene.get_devices()) == 2
    assert win.network_view.map_view.list_devices.count() == 2
    assert win.network_view.erp_master_table.rowCount() == 2

