"""Unit and integration tests for Phase 2: Live Nmap Scan to Network Map Automatic Sync.

Validates:
1. Real/structured Nmap XML parsing into normalized host and port records.
2. In-place deduplication: rescanning updates existing nodes without creating duplicates.
3. Addition of newly discovered hosts with clean grid placement.
4. Preservation of manually created nodes, links, coordinates, and notes.
5. Rejection of empty, malformed, or oversized (> 50MB) XML files with canvas preservation.
6. Qt signal wiring between NetworkScanView.scan_completed and TopologyDesignerWidget.
7. TopologyInspectorWidget telemetry display (ports, services, OS, MAC, timestamp).
8. Scope safety guard: out-of-scope hosts in raw scans or XML are blocked from the canvas.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from core.asset_inventory import AssetInventoryService
from desktop.main_window import MainWindow
from desktop.views.network_scan_view import NetworkScanView
from desktop.widgets.topology_designer import (
    DeviceType,
    TopologyDesignerWidget,
    TopologyDeviceItem,
    TopologyInspectorWidget,
)
from modules.network.nmap_parser import NmapParser
from storage.db import Database
from storage.models import (
    Project,
    TargetScope,
    TargetType,
)

SAMPLE_NMAP_XML_1 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O 192.168.1.50 192.168.1.100" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000010">
  <status state="up" reason="arp-response"/>
  <address addr="192.168.1.50" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell Inc."/>
  <hostnames>
    <hostname name="web-srv.internal" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.52" method="probed"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="OpenSSL" version="3.0.2" tunnel="ssl" method="probed"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.9p1" method="probed"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 - 5.15" accuracy="96"/>
  </os>
</host>
<host starttime="1700000000" endtime="1700000010">
  <status state="up" reason="arp-response"/>
  <address addr="192.168.1.100" addrtype="ipv4"/>
  <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="VMware Inc."/>
  <hostnames>
    <hostname name="db-srv.internal" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="3306">
      <state state="open" reason="syn-ack"/>
      <service name="mysql" product="MySQL" version="8.0.32" method="probed"/>
    </port>
  </ports>
  <os>
    <osmatch name="Ubuntu Linux 22.04" accuracy="98"/>
  </os>
</host>
</nmaprun>
"""

SAMPLE_NMAP_XML_RESCAN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.50" start="1700000100" version="7.94">
<host starttime="1700000100" endtime="1700000115">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.1.50" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell Inc."/>
  <hostnames>
    <hostname name="web-srv.internal" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.52" method="probed"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="OpenSSL" version="3.0.2" tunnel="ssl" method="probed"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="open" reason="syn-ack"/>
      <service name="http-proxy" product="Squid" version="5.7" method="probed"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4 - 5.15" accuracy="96"/>
  </os>
</host>
</nmaprun>
"""


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_project(db: Database) -> Project:
    proj = db.create_project(
        Project(
            name="Network Auto-Sync Test Project",
            client_name="Test Enterprise Corp",
            engagement_id="ENG-2026-AUTOSYNC",
            lead_tester="Senior Pentester Leo",
        )
    )
    # Define authorized subnet
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    return proj


def test_nmap_xml_parsing_to_normalized_host_records():
    """Requirement 1: Parses XML into structured normalized host records."""
    scan_result = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    assert len(scan_result.hosts) == 2

    host1 = scan_result.hosts[0]
    assert host1.ip == "192.168.1.50"
    assert host1.hostname == "web-srv.internal"
    assert host1.mac_address == "00:11:22:33:44:55"
    assert host1.vendor == "Dell Inc."
    assert host1.os_match == "Linux 5.4 - 5.15"
    assert len(host1.ports) == 3

    open_ports = [p.port_id for p in host1.ports if p.state == "open"]
    assert open_ports == [80, 443, 22]

    p80 = next(p for p in host1.ports if p.port_id == 80)
    assert p80.service_name == "http"
    assert p80.product == "Apache httpd"
    assert p80.version == "2.4.52"

    host2 = scan_result.hosts[1]
    assert host2.ip == "192.168.1.100"
    assert host2.hostname == "db-srv.internal"
    assert host2.os_match == "Ubuntu Linux 22.04"
    assert len(host2.ports) == 1
    assert host2.ports[0].port_id == 3306


def test_rescan_updates_node_inplace_without_duplicate(qtbot, db: Database, sample_project: Project):
    """Requirement 2: Rescanning an existing IP updates node in-place without duplicates."""
    widget = TopologyDesignerWidget(db=db)
    widget.set_active_project(sample_project)

    # 1. Initial Scan Sync (Ports: 80, 443, 22)
    scan1 = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    scopes = db.list_scopes(sample_project.id)
    asset_svc = AssetInventoryService(db)
    asset_svc.sync_scan_assets(sample_project.id, scan1, scopes)

    dev_added, _, dev_updated = widget.load_discovered_assets(db, sample_project.id)
    assert dev_added == 2
    assert dev_updated == 0

    devices_before = widget.scene.get_devices()
    assert len(devices_before) == 2

    target_node = next(d for d in devices_before if d.ip_address == "192.168.1.50")
    initial_pos = (target_node.pos().x(), target_node.pos().y())
    assert set(target_node.open_ports) == {80, 443, 22}

    # 2. Rescan with changed ports (Port 8080 added, port 22 closed/omitted)
    scan2 = NmapParser.parse_xml(SAMPLE_NMAP_XML_RESCAN)
    asset_svc.sync_scan_assets(sample_project.id, scan2, scopes)

    dev_added2, _, dev_updated2 = widget.load_discovered_assets(db, sample_project.id)
    assert dev_added2 == 0  # No new node added!
    assert dev_updated2 >= 1  # Node updated in-place!

    devices_after = widget.scene.get_devices()
    assert len(devices_after) == 2  # Total count unchanged (strictly no duplicate!)

    updated_node = next(d for d in devices_after if d.ip_address == "192.168.1.50")
    assert updated_node is target_node  # Exact same memory/canvas object
    assert set(updated_node.open_ports) == {80, 443, 8080}
    # Position preserved
    assert (updated_node.pos().x(), updated_node.pos().y()) == initial_pos


def test_newly_discovered_hosts_added_on_grid_preserving_existing(qtbot, db: Database, sample_project: Project):
    """Requirement 3: New hosts are added on non-overlapping grid without shifting existing nodes."""
    widget = TopologyDesignerWidget(db=db)
    widget.set_active_project(sample_project)

    # Place initial node
    node1 = widget.scene.add_device(
        device_type=DeviceType.SERVER,
        label="Host-1",
        ip_address="192.168.1.10",
        x=-300.0,
        y=-100.0,
    )
    initial_p1 = (node1.pos().x(), node1.pos().y())

    # Ingest scan with 2 new hosts
    scan = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    scopes = db.list_scopes(sample_project.id)
    AssetInventoryService(db).sync_scan_assets(sample_project.id, scan, scopes)

    added, _, _ = widget.load_discovered_assets(db, sample_project.id)
    assert added == 2

    all_devs = widget.scene.get_devices()
    assert len(all_devs) == 3

    # Existing node pos preserved
    assert (node1.pos().x(), node1.pos().y()) == initial_p1

    # Verify positions are distinct (no overlaps)
    positions = [(d.pos().x(), d.pos().y()) for d in all_devs]
    assert len(positions) == len(set(positions))


def test_preserves_manually_drawn_nodes_and_links(qtbot, db: Database, sample_project: Project):
    """Requirement 4: Manually drawn nodes, links, and notes are never overwritten or deleted."""
    widget = TopologyDesignerWidget(db=db)
    widget.set_active_project(sample_project)

    # Create manual firewall and switch
    fw = widget.scene.add_device(
        device_type=DeviceType.FIREWALL,
        label="Perimeter-FW",
        ip_address="192.168.1.1",
        notes="Custom engineered perimeter firewall for CPENT lab",
        x=200.0,
        y=160.0,
    )
    fw.is_observed = False

    sw = widget.scene.add_device(
        device_type=DeviceType.SWITCH,
        label="Core-Switch-01",
        ip_address="192.168.1.2",
        notes="L3 Core distribution switch",
        x=200.0,
        y=300.0,
    )
    sw.is_observed = False

    manual_link = widget.scene.add_link(
        source=fw,
        dest=sw,
        link_type="Trunk",
        label="VLAN-Trunk-10-20",
    )
    manual_link.is_observed = False

    # Ingest scan
    scan = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    scopes = db.list_scopes(sample_project.id)
    AssetInventoryService(db).sync_scan_assets(sample_project.id, scan, scopes)

    added, _, _ = widget.load_discovered_assets(db, sample_project.id)
    assert added == 2

    devices = widget.scene.get_devices()
    assert len(devices) == 4

    # Verify manual items still exist with their custom attributes intact
    fw_check = next(d for d in devices if d.label == "Perimeter-FW")
    assert fw_check.is_observed is False
    assert fw_check.notes == "Custom engineered perimeter firewall for CPENT lab"
    assert (fw_check.pos().x(), fw_check.pos().y()) == (200.0, 160.0)

    links = widget.scene.get_links()
    assert manual_link in links
    assert manual_link.is_observed is False
    assert manual_link.label == "VLAN-Trunk-10-20"


def test_empty_malformed_and_oversized_xml_handling(qtbot, db: Database, sample_project: Project, tmp_path: Path):
    """Requirement 5: Corrupt, empty, or oversized XML files fail safely with canvas intact."""
    widget = TopologyDesignerWidget(db=db)
    widget.set_active_project(sample_project)

    # Seed 1 device on canvas
    seed = widget.scene.add_device(device_type=DeviceType.ROUTER, label="Gateway", ip_address="192.168.1.254")
    assert len(widget.scene.get_devices()) == 1

    # 1. Empty file
    empty_file = tmp_path / "empty.xml"
    empty_file.write_text("", encoding="utf-8")
    ok, msg, added, _, _ = widget.import_nmap_xml(empty_file)
    assert ok is False
    assert "empty" in msg.lower()
    assert len(widget.scene.get_devices()) == 1  # Canvas preserved

    # 2. Malformed file
    malformed_file = tmp_path / "malformed.xml"
    malformed_file.write_text("<nmaprun><host><unclosed_tag></nmaprun>", encoding="utf-8")
    ok, msg, added, _, _ = widget.import_nmap_xml(malformed_file)
    assert ok is False
    assert "failed to parse" in msg.lower()
    assert len(widget.scene.get_devices()) == 1  # Canvas preserved

    # 3. Oversized file (> 50MB)
    oversized_file = tmp_path / "large.xml"
    oversized_file.write_text("x" * 1024, encoding="utf-8")
    with patch("pathlib.Path.stat") as mock_stat:
        mock_obj = MagicMock()
        mock_obj.st_size = 55 * 1024 * 1024  # 55MB
        mock_stat.return_value = mock_obj
        ok, msg, added, _, _ = widget.import_nmap_xml(oversized_file)
        assert ok is False
        assert "50mb" in msg.lower()
        assert len(widget.scene.get_devices()) == 1  # Canvas preserved


def test_qt_signal_connection_nmap_scan_to_topology(qtbot, db: Database, sample_project: Project):
    """Requirement 6: NetworkScanView.scan_completed signal updates Network Map."""
    main_win = MainWindow(db=db)
    qtbot.addWidget(main_win)
    main_win._on_project_selected(sample_project)

    assert hasattr(main_win.network_view, "scan_completed")
    assert hasattr(main_win, "_on_nmap_scan_completed")

    # Ingest scan in DB
    scan = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    scopes = db.list_scopes(sample_project.id)
    AssetInventoryService(db).sync_scan_assets(sample_project.id, scan, scopes)

    # Emit signal directly mimicking scanner thread completion
    main_win.network_view.scan_completed.emit(scan)

    # Topology view must have refreshed
    devices = main_win.topology_view.scene.get_devices()
    assert len(devices) >= 2
    ips = [d.ip_address for d in devices]
    assert "192.168.1.50" in ips
    assert "192.168.1.100" in ips
    assert main_win.reports_view._cached_report_data is not None


def test_topology_project_switch_isolated_and_manual_canvas_restored(
    qtbot, db: Database, sample_project: Project, tmp_path: Path
):
    widget = TopologyDesignerWidget(db=db)
    qtbot.addWidget(widget)
    widget.topologies_dir = tmp_path / "topologies"
    widget.topologies_dir.mkdir()
    widget.set_active_project(sample_project)

    manual = widget.scene.add_device(device_type=DeviceType.CLOUD, label="Manual cloud")
    scan = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    AssetInventoryService(db).sync_scan_assets(
        sample_project.id, scan, db.list_scopes(sample_project.id)
    )
    widget.load_discovered_assets(db, sample_project.id)
    assert len(widget.scene.get_devices()) == 3

    second_project = db.create_project(Project(name="Other topology project"))
    db.add_scope(
        TargetScope(
            project_id=second_project.id,
            target="10.10.0.0/16",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    widget.set_active_project(second_project)
    assert widget.scene.get_devices() == []

    widget.set_active_project(sample_project)
    devices = widget.scene.get_devices()
    assert len(devices) == 3
    assert any(device.label == "Manual cloud" for device in devices)
    assert next(device for device in devices if device.label == "Manual cloud") is not manual


def test_terminal_nmap_xml_refreshes_map_findings_evidence_and_report(
    qtbot, db: Database, sample_project: Project, tmp_path: Path
):
    from desktop.widgets.terminal_view import TerminalWidget
    from storage.models import ExecutionStatus
    from terminal.runner import ProcessExecutionResult

    main_win = MainWindow(db=db)
    qtbot.addWidget(main_win)
    main_win._on_project_selected(sample_project)
    db.add_scope(
        TargetScope(
            project_id=sample_project.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    terminal = main_win.terminal_widget
    terminal.evidence_dir = tmp_path / "evidence"

    now = "2026-10-28T00:00:00Z"
    xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 192.168.1.77" version="7.94">
<host><status state="up"/><address addr="192.168.1.77" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<hostnames><hostname name="lab-node.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="23"><state state="open"/>
<service name="telnet"/></port></ports></host></nmaprun>"""
    result = ProcessExecutionResult(
        command=["nmap", "-oX", "-", "192.168.1.77"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout=xml,
        stderr="",
        started_at=now,
        finished_at=now,
        duration_seconds=0.1,
    )

    terminal._save_command_result(result, "nmap -oX - 192.168.1.77", sample_project)

    nodes = db.list_asset_nodes(sample_project.id)
    assert {node.value for node in nodes} >= {"192.168.1.77", "lab-node.local"}
    assert len([device for device in main_win.topology_view.scene.get_devices() if device.is_observed]) == 1
    assert any("telnet" in finding.title.lower() for finding in db.list_findings(sample_project.id))
    assert len(db.list_evidence(sample_project.id)) == 1
    report = main_win.reports_view.report_builder.build_report_data(sample_project.id)
    assert report.metrics.total_findings >= 1
    assert report.metrics.total_evidence_files == 1


def test_inspector_displays_telemetry_fields(qtbot, db: Database, sample_project: Project):
    """Requirement 7: TopologyInspectorWidget reveals discovered telemetry, OS, and services."""
    widget = TopologyDesignerWidget(db=db)
    qtbot.addWidget(widget)
    widget.show()
    widget.set_active_project(sample_project)

    scan = NmapParser.parse_xml(SAMPLE_NMAP_XML_1)
    scopes = db.list_scopes(sample_project.id)
    AssetInventoryService(db).sync_scan_assets(sample_project.id, scan, scopes)
    widget.load_discovered_assets(db, sample_project.id)

    dev_item = next(d for d in widget.scene.get_devices() if d.ip_address == "192.168.1.50")

    # Inspect device
    widget.inspector.inspect_device(dev_item)

    # Telemetry group must be visible
    assert not widget.inspector.telemetry_group.isHidden()
    telemetry_text = widget.inspector.lbl_telemetry_info.text()
    assert "Linux 5.4 - 5.15" in telemetry_text
    assert "00:11:22:33:44:55" in telemetry_text
    assert "Open Ports (3):" in telemetry_text
    assert "80, 443, 22" in telemetry_text
    assert "Apache httpd" in telemetry_text
    assert "2.4.52" in telemetry_text

    # Now inspect a manual device without scan telemetry
    manual_dev = widget.scene.add_device(device_type=DeviceType.CLOUD, label="Manual-Cloud")
    widget.inspector.inspect_device(manual_dev)
    assert widget.inspector.telemetry_group.isHidden()


def test_scope_safety_guard_blocks_unauthorized_assets(qtbot, db: Database, sample_project: Project, tmp_path: Path):
    """Requirement 8: Scope guard prevents out-of-scope targets from appearing on canvas."""
    xml_with_unauthorized_targets = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap 192.168.1.50 10.99.99.99" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000010">
  <status state="up"/>
  <address addr="192.168.1.50" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
</host>
<host starttime="1700000000" endtime="1700000010">
  <status state="up"/>
  <address addr="10.99.99.99" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
</host>
</nmaprun>
"""
    xml_file = tmp_path / "mixed_scope.xml"
    xml_file.write_text(xml_with_unauthorized_targets, encoding="utf-8")

    widget = TopologyDesignerWidget(db=db)
    widget.set_active_project(sample_project)

    ok, msg, dev_added, _, _ = widget.import_nmap_xml(xml_file)
    assert ok is True
    assert dev_added == 1  # Only 192.168.1.50 added!

    canvas_ips = [d.ip_address for d in widget.scene.get_devices()]
    assert "192.168.1.50" in canvas_ips
    assert "10.99.99.99" not in canvas_ips  # Unauthorized IP blocked from canvas!
