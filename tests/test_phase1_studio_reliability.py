"""Comprehensive Reliability Verification Suite for Cyber Sentinel Infrastructure Studio.

Verifies:
- Phase 1 Step 2: Database-to-GUI Asset Synchronization, Telemetry, and Idempotence.
- Phase 1 Step 3: Strict Multi-Project Isolation and Scope Guard Fail-Closed Bounds.
- Phase 1 Step 4: Topology Persistence, Node Position Preservation, and Safe Merge.
"""

import json
from pathlib import Path
import pytest
from PySide6.QtCore import Qt, QPointF
from PySide6.QtWidgets import QApplication

from core.scope import ScopeAuthorizationService
from desktop.widgets.topology_designer import (
    TopologyDesignerWidget,
    DeviceType,
    ZoneType,
    TopologyDeviceItem,
    TopologyZoneItem,
)
from storage.db import Database
from storage.models import (
    AssetNode,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    TargetScope,
)
from terminal.ingest import TerminalIngestEngine


@pytest.fixture
def isolated_db(tmp_path: Path) -> Database:
    """Provides a pristine, isolated SQLite database for reliability tests."""
    db_file = tmp_path / "studio_reliability_test.db"
    return Database(str(db_file))


@pytest.fixture
def project_alpha(isolated_db: Database) -> Project:
    """Creates authorized Project Alpha."""
    p = isolated_db.create_project(
        Project(
            name="Project Alpha Engagement",
            client_name="Alpha Corp",
            description="Engagement Alpha for studio testing",
            status=ProjectStatus.ACTIVE,
        )
    )
    isolated_db.add_scope(TargetScope(project_id=p.id, target="192.168.10.0/24", is_authorized=True))
    isolated_db.add_scope(TargetScope(project_id=p.id, target="192.168.10.250", is_authorized=False))  # Excluded
    return p


@pytest.fixture
def project_beta(isolated_db: Database) -> Project:
    """Creates authorized Project Beta."""
    p = isolated_db.create_project(
        Project(
            name="Project Beta Engagement",
            client_name="Beta Systems",
            description="Engagement Beta for isolation testing",
            status=ProjectStatus.ACTIVE,
        )
    )
    isolated_db.add_scope(TargetScope(project_id=p.id, target="10.20.0.0/24", is_authorized=True))
    return p


# ===========================================================================
# 1. Asset Synchronization & Telemetry Tests (Step 2)
# ===========================================================================

def test_sync_zero_open_port_host_visible_and_persisted(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 2.1 & 2.2: Zero-open-port host (e.g. ICMP ping sweep) remains visible on canvas and drawer."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # Ingest ping sweep host
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.5",
            label="quiet-host",
            source_tool="nmap_sn",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [], "host_status": "up", "device_type": "Workstation"}),
        )
    )

    designer.load_discovered_assets(isolated_db, project_alpha.id)

    # 1. Check canvas node
    devs = [d for d in designer.scene.get_devices() if d.ip_address == "192.168.10.5"]
    assert len(devs) == 1
    assert devs[0].is_observed is True
    assert devs[0].open_ports == []

    # 2. Check left drawer item
    assert designer.list_devices.count() == 1
    drawer_text = designer.list_devices.item(0).text()
    assert "192.168.10.5" in drawer_text
    assert "0 ports" in drawer_text


def test_sync_rescan_updates_same_asset_without_duplicate(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 2.3 & 2.4: Subsequent scan with ports updates same node and refreshes inspector without duplicate."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # First scan: host discovered with no ports
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.20",
            label="app-server",
            source_tool="nmap_sn",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": []}),
        )
    )
    designer.load_discovered_assets(isolated_db, project_alpha.id)
    assert len(designer.scene.get_devices()) == 1

    # Second scan: ports 80, 443 discovered
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.20",
            label="app-server",
            source_tool="nmap_sV",
            confidence=1.0,
            metadata_json=json.dumps({
                "open_ports": [80, 443],
                "services": [
                    {"port": 80, "proto": "tcp", "service": "http", "product": "nginx"},
                    {"port": 443, "proto": "tcp", "service": "https", "product": "nginx"},
                ],
                "os_match": "Linux 6.1 Debian",
            }),
        )
    )
    designer.load_discovered_assets(isolated_db, project_alpha.id)

    # Exactly 1 device must exist (no duplicate)
    devs = designer.scene.get_devices()
    assert len(devs) == 1
    dev = devs[0]
    assert dev.ip_address == "192.168.10.20"
    assert dev.open_ports == [80, 443]
    assert dev.os_match == "Linux 6.1 Debian"
    assert len(dev.services) == 2

    # Drawer must also display 2 ports
    assert designer.list_devices.count() == 1
    assert "2 ports" in designer.list_devices.item(0).text()


def test_sync_drawer_click_centers_canvas_and_inspects_device(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 2.5: Clicking asset in left drawer selects canvas node, centers view, and populates right inspector."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # Add two hosts
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.1",
            label="gw-alpha",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [22], "device_type": "Router"}),
        )
    )
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.50",
            label="dc-alpha",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [88, 389], "device_type": "Server"}),
        )
    )
    designer.load_discovered_assets(isolated_db, project_alpha.id)
    assert designer.list_devices.count() == 2

    # Click dc-alpha in drawer
    dc_item = None
    for i in range(designer.list_devices.count()):
        it = designer.list_devices.item(i)
        if "192.168.10.50" in it.text():
            dc_item = it
            break
    assert dc_item is not None

    designer._on_drawer_device_clicked(dc_item)

    # Verify canvas selection
    selected_items = designer.scene.selectedItems()
    assert len(selected_items) == 1
    selected_dev = selected_items[0]
    assert selected_dev.ip_address == "192.168.10.50"

    # Verify right inspector
    assert designer.inspector.current_item == selected_dev
    assert designer.inspector.edit_ip.text() == "192.168.10.50"
    assert "Server" in designer.inspector.title_lbl.text()


def test_sync_preserves_manually_adjusted_coordinates(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 2.6: Subsequent scan updates telemetry but strictly preserves user-moved node coordinates."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # Initial host
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.15",
            label="host-moved",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [80]}),
        )
    )
    designer.load_discovered_assets(isolated_db, project_alpha.id)

    dev = designer.scene.get_devices()[0]
    # User manually drags node to custom grid-aligned position
    custom_pos = QPointF(760.0, 520.0)
    dev.setPos(custom_pos)

    # Rescan updates telemetry (e.g. port 443 added)
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.15",
            label="host-moved",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [80, 443]}),
        )
    )
    designer.load_discovered_assets(isolated_db, project_alpha.id)

    dev_after = designer.scene.get_devices()[0]
    assert dev_after.pos() == custom_pos, "Node coordinates must not be overwritten by rescan"
    assert dev_after.open_ports == [80, 443], "Telemetry must be updated in-place"


def test_sync_idempotence(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 2.8: Repeated synchronization calls produce identical output without duplicate nodes or links."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.100",
            label="fixed-node",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [22, 80]}),
        )
    )

    # Sync 3 times in a row
    for _ in range(3):
        designer.load_discovered_assets(isolated_db, project_alpha.id)

    assert len(designer.scene.get_devices()) == 1
    assert designer.list_devices.count() == 1


# ===========================================================================
# 2. Project Isolation Tests (Step 3)
# ===========================================================================

def test_project_isolation_assets_never_leak(qtbot, isolated_db: Database, project_alpha: Project, project_beta: Project, tmp_path: Path):
    """Step 3.1 & 3.2: Project Alpha assets never appear in Project Beta, and switching projects resets state."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)

    # Insert assets into Project Alpha
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.11",
            label="alpha-workstation",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [445]}),
        )
    )

    # Insert assets into Project Beta
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_beta.id,
            node_type="ip",
            value="10.20.0.99",
            label="beta-database",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [3306]}),
        )
    )

    # 1. Load Project Alpha
    designer.set_active_project(project_alpha)
    assert len(designer.scene.get_devices()) == 1
    assert designer.scene.get_devices()[0].ip_address == "192.168.10.11"
    assert designer.list_devices.count() == 1
    assert "192.168.10.11" in designer.list_devices.item(0).text()

    # 2. Switch to Project Beta
    designer.set_active_project(project_beta)
    assert len(designer.scene.get_devices()) == 1
    assert designer.scene.get_devices()[0].ip_address == "10.20.0.99"
    assert designer.list_devices.count() == 1
    assert "10.20.0.99" in designer.list_devices.item(0).text()
    assert "192.168.10.11" not in designer.list_devices.item(0).text()

    # 3. Switch to None (Standalone Mode)
    designer.set_active_project(None)
    assert len(designer.scene.get_devices()) == 0
    assert designer.list_devices.count() == 0
    assert "None" in designer.lbl_project.text()


def test_project_isolation_resets_selected_device_and_inspector(qtbot, isolated_db: Database, project_alpha: Project, project_beta: Project, tmp_path: Path):
    """Step 3.3: A previously selected device cannot remain selected or inspected after switching projects."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)

    # Add Alpha host and select it
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.77",
            label="alpha-target",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [22]}),
        )
    )
    designer.set_active_project(project_alpha)
    dev_alpha = designer.scene.get_devices()[0]
    dev_alpha.setSelected(True)
    designer.inspector.inspect_device(dev_alpha)
    assert designer.inspector.edit_ip.text() == "192.168.10.77"

    # Switch to Project Beta
    designer.set_active_project(project_beta)

    # Verification: Previous item must not remain inspected or selected
    assert len(designer.scene.selectedItems()) == 0
    assert designer.inspector.current_item is None
    assert not designer.inspector.overview_group.isHidden()
    assert designer.inspector.device_group.isHidden()


def test_scope_guard_blocks_out_of_scope_and_excluded_assets(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 3.6: Assets outside scope or explicitly excluded (e.g. .250) are blocked fail-closed."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # 1. In-scope host (192.168.10.55) -> ALLOWED
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.55",
            label="allowed-host",
            source_tool="nmap",
            confidence=1.0,
        )
    )
    # 2. Explicitly excluded host (192.168.10.250) -> BLOCKED
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.250",
            label="excluded-vip",
            source_tool="nmap",
            confidence=1.0,
        )
    )
    # 3. Completely out of scope host (172.16.0.1) -> BLOCKED
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="172.16.0.1",
            label="foreign-host",
            source_tool="nmap",
            confidence=1.0,
        )
    )

    designer.load_discovered_assets(isolated_db, project_alpha.id)

    # Only 1 in-scope host must be admitted
    dev_ips = {d.ip_address for d in designer.scene.get_devices()}
    assert dev_ips == {"192.168.10.55"}
    assert "192.168.10.250" not in dev_ips
    assert "172.16.0.1" not in dev_ips


# ===========================================================================
# 3. Topology Persistence & Safe Merge Tests (Step 4)
# ===========================================================================

def test_topology_persistence_full_lifecycle(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 4: Load topology, edit/move nodes, save, reload in new widget, confirm all details preserved."""
    topos_dir = tmp_path / "topologies"
    topos_dir.mkdir(parents=True, exist_ok=True)

    # Instance 1: Create diagram with custom items and positions
    designer_1 = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer_1)
    designer_1.topologies_dir = topos_dir
    designer_1.set_active_project(project_alpha)

    # Add custom zone
    zone = designer_1.scene.add_zone(
        name="DMZ Perimeter",
        zone_type=ZoneType.DMZ,
        x=100.0,
        y=100.0,
        width=400.0,
        height=300.0,
    )
    # Add custom device
    dev = designer_1.scene.add_device(
        device_type=DeviceType.FIREWALL,
        label="Edge-FW-01",
        ip_address="192.168.10.1",
        hostname="fw01.alpha.corp",
        notes="Primary perimeter firewall with IDS enabled",
        x=250.0,
        y=200.0,
    )
    dev.open_ports = [443, 8443]
    dev.services = [{"port": 443, "service": "https"}]
    dev.os_match = "PFSense 2.7"

    # Save to project topology file
    proj_file = topos_dir / f"project_{project_alpha.id}_topology.json"
    saved = designer_1.save_topology_to_file(str(proj_file))
    assert saved is True
    assert proj_file.exists()

    # Instance 2: Recreate widget completely and reload project
    designer_2 = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer_2)
    designer_2.topologies_dir = topos_dir
    designer_2.set_active_project(project_alpha)

    # Verify all entities and coordinates preserved
    devs = designer_2.scene.get_devices()
    zones = designer_2.scene.get_zones()

    assert len(devs) == 1
    assert len(zones) == 1

    d = devs[0]
    assert d.label == "Edge-FW-01"
    assert d.ip_address == "192.168.10.1"
    assert d.hostname == "fw01.alpha.corp"
    assert d.notes == "Primary perimeter firewall with IDS enabled"
    assert d.pos() == QPointF(240.0, 200.0)
    assert d.open_ports == [443, 8443]
    assert d.os_match == "PFSense 2.7"

    z = zones[0]
    assert z.name == "DMZ Perimeter"
    assert z.zone_type == ZoneType.DMZ
    assert z.pos() == QPointF(100.0, 100.0)
    assert z.width == 400.0
    assert z.height == 300.0


def test_import_assets_merges_without_erasing_manual_design(qtbot, isolated_db: Database, project_alpha: Project, tmp_path: Path):
    """Step 4.7: Loading discovered assets safely merges into canvas without erasing existing manual zones or nodes."""
    designer = TopologyDesignerWidget(db=isolated_db)
    qtbot.addWidget(designer)
    designer.topologies_dir = tmp_path / "topologies"
    designer.topologies_dir.mkdir(parents=True, exist_ok=True)
    designer.set_active_project(project_alpha)

    # 1. Manually add architectural zone and custom unscanned cloud item
    designer.scene.add_zone(name="Planned AWS VPC", zone_type=ZoneType.CLOUD_VPC, x=50.0, y=50.0)
    designer.scene.add_device(
        device_type=DeviceType.CLOUD,
        label="AWS-DirectConnect",
        notes="Planned direct connect link",
        x=120.0,
        y=120.0,
    )
    assert len(designer.scene.get_devices()) == 1
    assert len(designer.scene.get_zones()) == 1

    # 2. Ingest a newly discovered live scan host
    isolated_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value="192.168.10.88",
            label="live-target",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"open_ports": [22]}),
        )
    )

    # 3. Load discovered assets (merge operation)
    designer.load_discovered_assets(isolated_db, project_alpha.id)

    # Canvas must contain BOTH the manual cloud node AND the newly discovered host
    dev_labels = {d.label for d in designer.scene.get_devices()}
    assert "AWS-DirectConnect" in dev_labels, "Manual node must not be erased during merge"
    assert "live-target" in dev_labels, "Discovered asset must be merged into canvas"

    zone_names = {z.name for z in designer.scene.get_zones()}
    assert "Planned AWS VPC" in zone_names, "Manual zone must not be erased during merge"
