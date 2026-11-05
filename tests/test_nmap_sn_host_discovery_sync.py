"""Regression tests for Nmap -sn live host discovery and Network Map synchronization.

Tests verifying:
1. Parser extracts all four IP addresses (_gateway, 192.168.100.10, 192.168.100.40, leo).
2. Host-up records without port information are persisted into database.
3. Database contains all eligible in-scope records after terminal ingestion.
4. The Devices panel data source (NetworkMapView) populates all live hosts.
5. The Live Topology (TopologyDesignerView) receives and displays the same records.
6. Re-ingesting the same output does not create duplicate nodes or devices.
7. Project and assessment isolation (hosts do not leak across projects).
8. Out-of-scope targets fail closed and are not admitted.
"""

import json
from pathlib import Path
from typing import Generator
import pytest
from PySide6.QtCore import Qt

from core.asset_inventory import AssetInventoryService
from core.scope import ScopeAuthorizationService
from desktop.widgets.network_map_view import NetworkMapView
from desktop.widgets.topology_designer import TopologyDesignerView
from modules.network.nmap_parser import NmapParser
from storage.db import Database
from storage.models import (
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.ingest import TerminalIngestEngine

REPRO_NMAP_SN_OUTPUT = """
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-28 21:40 +0630
Stats: 0:00:19 elapsed; 0 hosts completed (0 up), 255 undergoing ARP Ping Scan
ARP Ping Scan Timing: About 49.80% done; ETC: 21:40 (0:00:20 remaining)
Nmap scan report for _gateway (192.168.100.1)
Host is up (0.0073s latency).
MAC Address: 2C:94:52:03:5E:58 (Huawei Technologies)
Nmap scan report for 192.168.100.10
Host is up (0.11s latency).
MAC Address: 62:20:3E:5B:DB:27 (Unknown)
Nmap scan report for 192.168.100.40
Host is up (0.022s latency).
MAC Address: 40:2A:8F:FF:8E:24 (Unknown)
Nmap scan report for leo (192.168.100.7)
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 28.36 seconds
"""


@pytest.fixture
def fresh_db(tmp_path: Path) -> Generator[Database, None, None]:
    db_path = str(tmp_path / "test_nmap_sn.db")
    db = Database(db_path)
    yield db


@pytest.fixture
def test_project(fresh_db: Database) -> Project:
    proj = fresh_db.create_project(
        Project(
            name="CPENT Engagement",
            description="Testing live host discovery",
            status=ProjectStatus.ACTIVE,
        )
    )
    # Add authorized CIDR scope: 192.168.100.0/24
    fresh_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.100.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_nmap_sn_parser_extracts_all_four_hosts():
    """Verify parser extracts the exact 4 reported hosts and excludes CIDR command arguments."""
    scan_res = NmapParser.parse_text(REPRO_NMAP_SN_OUTPUT, command="nmap -sn 192.168.100.0/24")

    assert len(scan_res.hosts) == 4
    host_ips = {h.ip for h in scan_res.hosts}
    assert host_ips == {"192.168.100.1", "192.168.100.10", "192.168.100.40", "192.168.100.7"}

    # Verify metadata extraction on ping sweep
    gateway = next(h for h in scan_res.hosts if h.ip == "192.168.100.1")
    assert gateway.hostname == "_gateway"
    assert gateway.mac_address == "2C:94:52:03:5E:58"
    assert gateway.vendor == "Huawei Technologies"
    assert gateway.status == "up"
    assert gateway.latency_ms == 7.3

    leo = next(h for h in scan_res.hosts if h.ip == "192.168.100.7")
    assert leo.hostname == "leo"
    assert leo.status == "up"

    h10 = next(h for h in scan_res.hosts if h.ip == "192.168.100.10")
    assert h10.mac_address == "62:20:3E:5B:DB:27"
    assert h10.status == "up"

    h40 = next(h for h in scan_res.hosts if h.ip == "192.168.100.40")
    assert h40.mac_address == "40:2A:8F:FF:8E:24"
    assert h40.status == "up"


def test_host_up_records_persisted_without_ports(fresh_db: Database, test_project: Project):
    """Verify that zero-port host discovery scans persist AssetNode rows and Observations."""
    scopes = fresh_db.list_scopes(test_project.id)
    scan_res = NmapParser.parse_text(REPRO_NMAP_SN_OUTPUT, command="nmap -sn 192.168.100.0/24")

    asset_svc = AssetInventoryService(fresh_db)
    synced_nodes, obs = asset_svc.sync_scan_assets(
        project_id=test_project.id,
        scan_result=scan_res,
        scopes=scopes,
        source_tool="nmap",
    )

    # 4 IP nodes + 2 hostname nodes (_gateway, leo)
    ip_nodes = [n for n in synced_nodes if n.node_type == "ip"]
    assert len(ip_nodes) == 4
    assert {n.value for n in ip_nodes} == {"192.168.100.1", "192.168.100.10", "192.168.100.40", "192.168.100.7"}

    # Verify observations created without database errors
    assert len(obs) == 4
    persisted_nodes = fresh_db.list_asset_nodes(test_project.id)
    assert any(n.value == "192.168.100.1" for n in persisted_nodes)
    assert any(n.value == "192.168.100.10" for n in persisted_nodes)
    assert any(n.value == "192.168.100.40" for n in persisted_nodes)
    assert any(n.value == "192.168.100.7" for n in persisted_nodes)


def test_terminal_ingestion_syncs_nmap_sn_to_database(fresh_db: Database, test_project: Project):
    """Verify TerminalIngestEngine ingests nmap -sn session output into inventory."""
    ingest_res = TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
        tool_name="pty_terminal",
        command="pty_session",
    )

    assert "nmap" in ingest_res.tools_detected
    assert ingest_res.hosts_synced == 6  # 4 IPs + 2 hostnames
    assert len(ingest_res.findings) == 4  # 4 Live Host Discovered findings

    nodes = fresh_db.list_asset_nodes(test_project.id)
    node_ips = {n.value for n in nodes if n.node_type == "ip"}
    assert {"192.168.100.1", "192.168.100.10", "192.168.100.40", "192.168.100.7"}.issubset(node_ips)


def test_devices_panel_and_cyber_sentinel_display_all_hosts(qtbot, fresh_db: Database, test_project: Project):
    """Verify the Devices panel (list_devices) displays all 4 discovered hosts."""
    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.load_discovered_assets(fresh_db, test_project.id)

    # Devices panel verification
    count = map_view.list_devices.count()
    assert count == 4

    displayed_ips = set()
    for idx in range(count):
        item = map_view.list_devices.item(idx)
        host = item.data(Qt.ItemDataRole.UserRole)
        displayed_ips.add(host.ip)

    assert displayed_ips == {"192.168.100.1", "192.168.100.10", "192.168.100.40", "192.168.100.7"}


def test_live_topology_designer_receives_all_hosts(qtbot, fresh_db: Database, test_project: Project):
    """Verify the 2D Designer mode receives and draws all 4 discovered hosts."""
    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )

    designer = TopologyDesignerView(db=fresh_db)
    qtbot.addWidget(designer)
    designer.set_active_project(test_project)

    devices = designer.scene.get_devices()
    device_ips = {d.ip_address for d in devices if d.ip_address}
    assert device_ips == {"192.168.100.1", "192.168.100.10", "192.168.100.40", "192.168.100.7"}


def test_re_ingesting_same_output_does_not_create_duplicates(fresh_db: Database, test_project: Project):
    """Verify that multiple consecutive ingestion calls are idempotent."""
    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )
    initial_nodes = fresh_db.list_asset_nodes(test_project.id)
    initial_count = len(initial_nodes)

    # Ingest again
    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )
    after_nodes = fresh_db.list_asset_nodes(test_project.id)
    assert len(after_nodes) == initial_count


def test_project_isolation_hosts_do_not_leak(fresh_db: Database, test_project: Project):
    """Verify discovered hosts in Project A do not leak into Project B."""
    proj_b = fresh_db.create_project(
        Project(name="Other Project", status=ProjectStatus.ACTIVE)
    )

    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=test_project.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )

    nodes_a = fresh_db.list_asset_nodes(test_project.id)
    nodes_b = fresh_db.list_asset_nodes(proj_b.id)

    assert len(nodes_a) > 0
    assert len(nodes_b) == 0


def test_out_of_scope_hosts_fail_closed_and_are_not_admitted(fresh_db: Database):
    """Verify strict fail-closed behavior for hosts outside engagement scope."""
    proj = fresh_db.create_project(Project(name="Restricted Project", status=ProjectStatus.ACTIVE))
    # Scope ONLY allows 10.0.0.0/24 (not 192.168.100.0/24)
    fresh_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.0.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )

    TerminalIngestEngine.ingest_session(
        db=fresh_db,
        project_id=proj.id,
        execution_id=None,
        output=REPRO_NMAP_SN_OUTPUT,
    )

    nodes = fresh_db.list_asset_nodes(proj.id)
    assert len(nodes) == 0  # Zero out-of-scope nodes admitted
