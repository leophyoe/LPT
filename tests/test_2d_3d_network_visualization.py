"""Tests for Unified 2D Fortinet Topology and 3D WebGL Network Visualization.

Verifies:
1. NetworkWANNodeItem and NetworkGatewayNodeItem instantiate with correct geometry, labels, and paint without errors.
2. NetworkConnectionItem supports Bézier curve, straight line, and orthogonal edge styles without regression.
3. WebGL3DNetworkView initializes cleanly, registers QWebChannel bridge, and processes database assets into 3D coordinates.
4. VisualizationWorkspace seamlessly toggles between 2D Fortinet Topology and 3D WebGL Mesh modes.
5. TopologyDesignerWidget mode switcher includes 3D Cyber Mesh (WebGL) and synchronizes assets across modes.
6. Zero fabricated nodes rule: All rendered nodes are derived strictly from real database assets.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import QApplication

from desktop.views.assets_view import AssetsView
from desktop.views.visualization_workspace import VisualizationWorkspace
from desktop.widgets.network_map_view import (
    NetworkConnectionItem,
    NetworkGatewayNodeItem,
    NetworkHostNodeItem,
    NetworkMapView,
    NetworkSubnetHubItem,
    NetworkWANNodeItem,
)
from desktop.widgets.topology_designer import TopologyDesignerWidget
from desktop.widgets.webgl_3d_network_view import WebGL3DNetworkView
from modules.network.nmap_parser import HostResult, NmapScanResult, PortResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture
def vis_test_db(tmp_path: Path) -> Database:
    """Creates isolated temporary SQLite database populated with real asset nodes and findings."""
    db_file = tmp_path / "vis_test.db"
    db = Database(db_file)
    project = db.create_project(Project(name="Vis Engagement", client_name="client-x", description="Visual Topology Test"))
    db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.168.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )

    # Insert 3 real discovered asset nodes
    node_gw = db.upsert_asset_node(
        AssetNode(
            project_id=project.id,
            node_type="ip",
            value="192.168.10.1",
            label="perimeter-gw",
            source_tool="nmap",
            metadata_json=json.dumps({"open_ports": [22, 80], "os_match": "Linux 5.15"}),
        )
    )
    node_web = db.upsert_asset_node(
        AssetNode(
            project_id=project.id,
            node_type="ip",
            value="192.168.10.50",
            label="web-app-01",
            source_tool="nmap",
            metadata_json=json.dumps({"open_ports": [80, 443], "os_match": "Ubuntu 22.04"}),
        )
    )
    node_db = db.upsert_asset_node(
        AssetNode(
            project_id=project.id,
            node_type="ip",
            value="192.168.10.100",
            label="db-master",
            source_tool="nmap",
            metadata_json=json.dumps({"open_ports": [5432], "os_match": "Debian 12"}),
        )
    )

    # Real relationship edge
    db.upsert_asset_edge(
        AssetEdge(
            project_id=project.id,
            source_node_id=node_web.id,
            target_node_id=node_db.id,
            relation_type="routes_to",
            source_tool="nmap",
        )
    )

    # Critical vulnerability on web app
    db.create_finding(
        Finding(
            project_id=project.id,
            title="SQL Injection on Auth Endpoint",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.10.50",
            description="Unsanitized query in login endpoint",
            validation_status=ValidationStatus.CONFIRMED,
        )
    )
    return db


def test_fortinet_wan_and_gateway_nodes(qtbot):
    """Verifies Fortinet root WAN and central Gateway firewall node items paint cleanly."""
    wan = NetworkWANNodeItem(0, -280)
    gw = NetworkGatewayNodeItem(0, -140, "FGT-XS-01")

    assert wan.boundingRect().width() > 0
    assert gw.boundingRect().width() > 0
    assert "FGT-XS-01" in gw.toolTip()
    assert "INTERNET" in wan.label

    # Verify paint execution onto QImage canvas
    img = QImage(300, 300, QImage.Format_ARGB32)
    img.fill(Qt.black)
    painter = QPainter(img)
    wan.paint(painter, None, None)
    gw.paint(painter, None, None)
    painter.end()


def test_network_connection_bezier_curve_and_styles(qtbot):
    """Verifies NetworkConnectionItem draws smooth Bézier curves, straight lines, and orthogonal paths."""
    p1 = QPointF(0, 0)
    p2 = QPointF(200, 150)

    conn_curve = NetworkConnectionItem(p1, p2, edge_style="curve", color="#0ea5e9")
    conn_line = NetworkConnectionItem(p1, p2, edge_style="line", color="#10b981")
    conn_ortho = NetworkConnectionItem(p1, p2, edge_style="ortho", color="#8b5cf6")

    assert conn_curve.boundingRect().isValid()
    assert conn_line.boundingRect().isValid()
    assert conn_ortho.boundingRect().isValid()

    # Paint all three edge styles to ensure no exceptions
    img = QImage(300, 300, QImage.Format_ARGB32)
    painter = QPainter(img)
    conn_curve.paint(painter, None, None)
    conn_line.paint(painter, None, None)
    conn_ortho.paint(painter, None, None)
    painter.end()


def test_webgl_3d_network_view_asset_processing(qtbot, vis_test_db):
    """Verifies WebGL3DNetworkView extracts database assets and prepares 3D coordinates."""
    view_3d = WebGL3DNetworkView()
    qtbot.addWidget(view_3d)

    projects = vis_test_db.list_projects()
    assert len(projects) == 1
    project_id = projects[0].id

    # Load assets from database into 3D view
    view_3d.load_discovered_assets(vis_test_db, project_id)
    assert view_3d._pending_payload is not None or view_3d._is_page_loaded

    # Simulate load finished to verify safe pending payload flush
    view_3d._on_load_finished(True)
    assert view_3d._pending_payload is None

    # Test bridge signal handling
    received_ips = []
    view_3d.host_selected.connect(received_ips.append)
    view_3d._on_node_selected("node_web", "192.168.10.50")

    assert len(received_ips) == 1
    assert received_ips[0] == "192.168.10.50"


def test_visualization_workspace_mode_toggling(qtbot, vis_test_db):
    """Verifies VisualizationWorkspace toggles between 2D Fortinet view and 3D WebGL mesh."""
    ws = VisualizationWorkspace(vis_test_db)
    qtbot.addWidget(ws)
    ws.show()

    projects = vis_test_db.list_projects()
    ws.set_active_project(projects[0])

    # Initial mode: 2D Fortinet Topology (index 0)
    assert ws.canvas_stack.currentIndex() == 0
    assert ws.btn_mode_2d.isChecked() is True
    assert ws.btn_mode_3d.isChecked() is False

    # Switch to 3D mode
    ws.btn_mode_3d.click()
    assert ws.canvas_stack.currentIndex() == 1
    assert ws.btn_mode_3d.isChecked() is True
    assert ws.btn_mode_2d.isChecked() is False

    # Switch back to 2D mode
    ws.btn_mode_2d.click()
    assert ws.canvas_stack.currentIndex() == 0
    assert ws.btn_mode_2d.isChecked() is True

    # Search filter propagation
    ws.txt_search.setText("192.168.10.50")
    assert ws.map_2d.txt_dev_search.text() == "192.168.10.50"


def test_topology_designer_3d_mode_switching(qtbot, vis_test_db):
    """Verifies TopologyDesignerWidget includes 3D Cyber Mesh and switches cleanly."""
    designer = TopologyDesignerWidget(db=vis_test_db)
    qtbot.addWidget(designer)

    projects = vis_test_db.list_projects()
    designer.set_active_project(projects[0])

    assert hasattr(designer, "btn_mode_3d")
    assert hasattr(designer, "mesh_3d_view")

    # Initial: 2D Studio (index 0)
    assert designer.map_stack.currentIndex() == 0

    # Switch to Radial Sentinel (index 1)
    designer.btn_mode_sentinel.click()
    assert designer.map_stack.currentIndex() == 1
    assert designer.btn_mode_sentinel.isChecked() is True

    # Switch to 3D Mesh (index 2)
    designer.btn_mode_3d.click()
    assert designer.map_stack.currentIndex() == 2
    assert designer.btn_mode_3d.isChecked() is True
    assert designer.btn_mode_sentinel.isChecked() is False
    assert designer.btn_mode_designer.isChecked() is False


def test_assets_view_database_inventory_and_inspection(qtbot, vis_test_db):
    """Verifies AssetsView renders strictly real database assets without demo data."""
    assets_view = AssetsView(vis_test_db)
    qtbot.addWidget(assets_view)
    assets_view.show()

    projects = vis_test_db.list_projects()
    assets_view.set_active_project(projects[0])

    # 3 real asset nodes inserted into vis_test_db
    assert assets_view.asset_table.rowCount() == 3
    assert "3 Total Assets" in assets_view.lbl_count_badge.text()

    # Verify search filtering
    assets_view.txt_search.setText("db-master")
    assert assets_view.asset_table.rowCount() == 1
    assert assets_view.asset_table.item(0, 0).text() == "192.168.10.100"

    # Reset search
    assets_view.txt_search.setText("")
    assert assets_view.asset_table.rowCount() == 3

    # Inspect web server with critical vulnerability
    assets_view.txt_search.setText("192.168.10.50")
    assert assets_view.asset_table.rowCount() == 1
    assets_view.asset_table.selectRow(0)

    assert "web-app-01" in assets_view.lbl_insp_title.text()
    assert "192.168.10.50" in assets_view.lbl_insp_ip.text()
    assert assets_view.findings_table.rowCount() >= 1
    assert assets_view.findings_table.item(0, 0).text() == "CRITICAL"


def test_network_map_view_auspex_radial_mode(qtbot):
    """Verifies NetworkMapView Auspex radial layout and risk filtering."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    # Build test scan with 3 hosts
    h1 = HostResult(ip="10.0.0.1", status="up", hostname="gw", ports=[PortResult(port_id=80, protocol="tcp", state="open", service_name="http")])
    h2 = HostResult(ip="10.0.0.5", status="up", hostname="web", ports=[PortResult(port_id=443, protocol="tcp", state="open", service_name="https")])
    h3 = HostResult(ip="10.0.0.9", status="up", hostname="db", ports=[PortResult(port_id=5432, protocol="tcp", state="open", service_name="postgresql")])
    scan = NmapScanResult(command_args="-sV", hosts=[h1, h2, h3], scanner="nmap", summary="3 hosts")

    findings = [
        Finding(project_id=1, title="SQLi", severity=FindingSeverity.CRITICAL, affected_asset="10.0.0.5", description="Critical SQLi", validation_status=ValidationStatus.CONFIRMED)
    ]

    map_view.load_scan(scan, findings)

    # Test layout mode switching
    map_view._set_layout_mode("radial")
    assert map_view.layout_mode == "radial"
    assert map_view.btn_layout_radial.isChecked() is True

    # Test edge style switching
    map_view._set_edge_style("curve")
    assert map_view.edge_style == "curve"
    assert map_view.btn_edge_curve.isChecked() is True

    # Test risk filter
    map_view._on_risk_filter_changed(50)
    visible_hosts = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem) and it.isVisible()]
    # Only the high-risk host with finding (10.0.0.5, risk=72) should remain visible
    assert len(visible_hosts) == 1
    assert visible_hosts[0].host.ip == "10.0.0.5"

    # Reset risk filter
    map_view._on_risk_filter_changed(0)
    all_visible = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem) and it.isVisible()]
    assert len(all_visible) == 3


def test_mainwindow_assets_and_visualization_integration(qtbot, vis_test_db: Database):
    """Verifies MainWindow cleanly wires AssetsView and VisualizationWorkspace with sidebar routing."""
    from desktop.main_window import MainWindow

    window = MainWindow(db=vis_test_db)
    qtbot.addWidget(window)
    window.show()

    assert hasattr(window, "assets_view")
    assert isinstance(window.assets_view, AssetsView)
    assert hasattr(window, "visualization_workspace")
    assert isinstance(window.visualization_workspace, VisualizationWorkspace)

    # Route: assets
    window.sidebar_nav.nav_items["assets"].click()
    assert window.view_stack.currentIndex() == 0
    assert window.scope_tabs.currentWidget() == window.assets_view

    # Select project and verify synchronization
    proj = vis_test_db.list_projects()[0]
    window._on_project_selected(proj)
    assert window.assets_view.asset_table.rowCount() == 3

    # Route: studio
    window.sidebar_nav.nav_items["studio"].click()
    assert window.view_stack.currentIndex() == 1
    assert window.security_tabs.currentWidget() == window.topology_view


def test_network_map_view_radial_single_and_multi_subnet_geometry(qtbot):
    """Verifies single-subnet places hub at (0,0) with no collision, and multi-subnet positions gateway at center."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    # 1. Test header toggling
    assert map_view.sentinel_bar.isVisible() is True
    map_view.hide_sentinel_header()
    assert map_view.sentinel_bar.isVisible() is False
    map_view.show_sentinel_header()
    assert map_view.sentinel_bar.isVisible() is True

    # 2. Single subnet: 192.168.100.0/24 with 4 hosts
    h1 = HostResult(ip="192.168.100.1", status="up", hostname="_gateway", ports=[PortResult(port_id=80, protocol="tcp", state="open", service_name="http")])
    h2 = HostResult(ip="192.168.100.7", status="up", hostname="leo", ports=[PortResult(port_id=22, protocol="tcp", state="open", service_name="ssh")])
    h3 = HostResult(ip="192.168.100.10", status="up", hostname="", ports=[PortResult(port_id=445, protocol="tcp", state="open", service_name="microsoft-ds")])
    h4 = HostResult(ip="192.168.100.35", status="up", hostname="", ports=[])
    scan_single = NmapScanResult(command_args="-sn", hosts=[h1, h2, h3, h4], scanner="nmap", summary="4 hosts")

    map_view.load_scan(scan_single)
    map_view._set_layout_mode("radial")

    # In single-subnet radial mode:
    # - Subnet hub is positioned at (0, 0)
    # - Dummy gateway item is hidden (preventing collision)
    hubs = [it for it in map_view.scene.items() if isinstance(it, NetworkSubnetHubItem)]
    assert len(hubs) == 1
    assert hubs[0].pos().x() == 0.0
    assert hubs[0].pos().y() == 0.0
    assert hubs[0].isVisible() is True

    gateways = [it for it in map_view.scene.items() if isinstance(it, NetworkGatewayNodeItem)]
    for gw in gateways:
        assert gw.isVisible() is False

    # Member hosts radiate out around (0, 0)
    host_nodes = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem)]
    assert len(host_nodes) == 4
    for hn in host_nodes:
        dist = math.hypot(hn.pos().x(), hn.pos().y())
        assert 220.0 <= dist <= 260.0

    # 3. Multi-subnet: 10.0.0.0/24 and 192.168.1.0/24
    m1 = HostResult(ip="10.0.0.10", status="up", ports=[])
    m2 = HostResult(ip="192.168.1.20", status="up", ports=[])
    scan_multi = NmapScanResult(command_args="-sn", hosts=[m1, m2], scanner="nmap", summary="2 subnets")

    map_view.load_scan(scan_multi)
    map_view._set_layout_mode("radial")

    gateways_multi = [it for it in map_view.scene.items() if isinstance(it, NetworkGatewayNodeItem)]
    assert len(gateways_multi) == 1
    assert gateways_multi[0].isVisible() is True
    assert gateways_multi[0].pos().x() == 0.0
    assert gateways_multi[0].pos().y() == 0.0

    hubs_multi = [it for it in map_view.scene.items() if isinstance(it, NetworkSubnetHubItem)]
    assert len(hubs_multi) == 2
    for h in hubs_multi:
        dist = math.hypot(h.pos().x(), h.pos().y())
        assert 260.0 <= dist <= 300.0


def test_fixture_1_empty_topology(qtbot):
    """Fixture 1: Empty topology handling in 2D and 3D."""
    from PySide6.QtWidgets import QGraphicsTextItem

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()
    map_view.load_scan(None)

    empty_texts = [it for it in map_view.scene.items() if isinstance(it, QGraphicsTextItem)]
    assert len(empty_texts) >= 1
    assert "No Discovered Network Assets" in empty_texts[0].toPlainText()

    # 3D view with empty DB
    web_view = WebGL3DNetworkView()
    qtbot.addWidget(web_view)
    web_view.show()
    empty_db = Database(":memory:")
    web_view.load_discovered_assets(empty_db, project_id=1)
    if web_view._pending_payload:
        data = json.loads(web_view._pending_payload)
        assert data["nodes"] == []
        assert data["links"] == []


def test_fixture_2_one_gateway_one_subnet(qtbot):
    """Fixture 2: Single gateway and single subnet with zero center node overlap."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    h_gw = HostResult(ip="192.168.1.1", status="up", hostname="gw01", ports=[PortResult(port_id=80, protocol="tcp", state="open")])
    h_host = HostResult(ip="192.168.1.10", status="up", hostname="node1", ports=[])
    scan = NmapScanResult(command_args="-sn", hosts=[h_gw, h_host], scanner="nmap", summary="2 hosts")

    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")

    # Center must have only 1 visible hub and no visible dummy gateway
    hubs = [it for it in map_view.scene.items() if isinstance(it, NetworkSubnetHubItem) and it.isVisible()]
    assert len(hubs) == 1
    assert hubs[0].pos().x() == 0.0
    assert hubs[0].pos().y() == 0.0

    gw_items = [it for it in map_view.scene.items() if isinstance(it, NetworkGatewayNodeItem) and it.isVisible()]
    assert len(gw_items) == 0


def test_fixture_3_one_subnet_five_hosts(qtbot):
    """Fixture 3: Single subnet with 5 hosts radiating evenly."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    hosts = [HostResult(ip=f"10.0.0.{i+1}", status="up", ports=[]) for i in range(5)]
    scan = NmapScanResult(command_args="-sn", hosts=hosts, scanner="nmap", summary="5 hosts")

    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")

    host_items = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem) and it.isVisible()]
    assert len(host_items) == 5

    # Check pairwise distance
    for i in range(len(host_items)):
        for j in range(i + 1, len(host_items)):
            p1 = host_items[i].pos()
            p2 = host_items[j].pos()
            dist = math.hypot(p1.x() - p2.x(), p1.y() - p2.y())
            assert dist > 100.0, f"Distance {dist} too small between host {i} and {j}"


def test_fixture_4_one_subnet_thirty_hosts_collision_free(qtbot):
    """Fixture 4: Single subnet with 30 hosts distributed into multi-tier orbits with zero collisions."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    hosts = [HostResult(ip=f"192.168.1.{i+1}", status="up", ports=[]) for i in range(30)]
    scan = NmapScanResult(command_args="-sn", hosts=hosts, scanner="nmap", summary="30 hosts")

    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")

    host_items = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem) and it.isVisible()]
    assert len(host_items) == 30

    # Verify multi-tier orbits
    radii = [round(math.hypot(it.pos().x(), it.pos().y())) for it in host_items]
    unique_tiers = sorted(set(radii))
    assert len(unique_tiers) >= 2

    # Verify all pairwise distances are greater than 45px
    min_dist = float("inf")
    for i in range(len(host_items)):
        for j in range(i + 1, len(host_items)):
            p1 = host_items[i].pos()
            p2 = host_items[j].pos()
            dist = math.hypot(p1.x() - p2.x(), p1.y() - p2.y())
            if dist < min_dist:
                min_dist = dist
    assert min_dist > 45.0, f"Min distance {min_dist} shows collision!"


def test_fixture_5_multi_subnets_mixed_hosts(qtbot):
    """Fixture 5: Multiple subnets with mixed host counts."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    sub1 = [HostResult(ip=f"10.0.1.{i+1}", status="up", ports=[]) for i in range(4)]
    sub2 = [HostResult(ip=f"192.168.10.{i+1}", status="up", ports=[]) for i in range(12)]
    scan = NmapScanResult(command_args="-sn", hosts=sub1 + sub2, scanner="nmap", summary="16 hosts")

    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")

    gw_items = [it for it in map_view.scene.items() if isinstance(it, NetworkGatewayNodeItem) and it.isVisible()]
    assert len(gw_items) == 1
    assert gw_items[0].pos().x() == 0.0
    assert gw_items[0].pos().y() == 0.0

    hubs = [it for it in map_view.scene.items() if isinstance(it, NetworkSubnetHubItem) and it.isVisible()]
    assert len(hubs) == 2
    for h in hubs:
        assert 260.0 <= math.hypot(h.pos().x(), h.pos().y()) <= 300.0


def test_fixture_6_ipv4_and_ipv6_assets(qtbot):
    """Fixture 6: Support for both IPv4 and IPv6 assets in distinct broadcast domains."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    h_v4 = HostResult(ip="192.168.1.50", status="up", hostname="v4-host", ports=[])
    h_v6 = HostResult(ip="2001:db8::1", status="up", hostname="v6-host", ports=[])
    scan = NmapScanResult(command_args="-sn", hosts=[h_v4, h_v6], scanner="nmap", summary="Dual stack")

    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")

    hubs = [it for it in map_view.scene.items() if isinstance(it, NetworkSubnetHubItem) and it.isVisible()]
    assert len(hubs) == 2
    hub_cidrs = {h.subnet_cidr for h in hubs}
    assert "192.168.1.0/24" in hub_cidrs
    assert any("2001:db8" in c for c in hub_cidrs)


def test_fixture_7_active_directory_relationships(qtbot, tmp_path: Path):
    """Fixture 7: Active Directory Domain, DC, and Computer nodes with purple relationship links."""
    db = Database(tmp_path / "ad_test.db")
    project = db.create_project(Project(name="AD Engagement", client_name="client-ad", description="AD Test"))

    n_dom = db.upsert_asset_node(AssetNode(project_id=project.id, node_type="domain", value="corp.local", label="corp.local", source_tool="ldap"))
    n_dc = db.upsert_asset_node(AssetNode(project_id=project.id, node_type="domain_controller", value="10.0.0.2", label="DC01", source_tool="ldap", metadata_json=json.dumps({"ip": "10.0.0.2"})))
    n_pc = db.upsert_asset_node(AssetNode(project_id=project.id, node_type="computer", value="10.0.0.100", label="WS01$", source_tool="ldap", metadata_json=json.dumps({"ip": "10.0.0.100"})))

    db.upsert_asset_edge(AssetEdge(project_id=project.id, source_node_id=n_dom.id, target_node_id=n_dc.id, relation_type="domain_controller_of", source_tool="ldap"))
    db.upsert_asset_edge(AssetEdge(project_id=project.id, source_node_id=n_dom.id, target_node_id=n_pc.id, relation_type="member_of", source_tool="ldap"))

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()
    map_view.load_discovered_assets(db, project.id)

    # Verify 2D purple relationship links exist
    conns = [it for it in map_view.scene.items() if isinstance(it, NetworkConnectionItem)]
    purple_conns = [c for c in conns if c.link_color.name() == "#a855f7"]
    assert len(purple_conns) >= 2


def test_fixture_8_assets_without_ip_addresses(qtbot, tmp_path: Path):
    """Fixture 8: Non-IP assets like root domain contexts and named workstations handled gracefully."""
    db = Database(tmp_path / "non_ip_test.db")
    project = db.create_project(Project(name="NonIP Test", client_name="client-nip", description="Non IP"))

    db.upsert_asset_node(AssetNode(project_id=project.id, node_type="domain", value="DC=corp,DC=local", label="corp.local", source_tool="ldap"))
    db.upsert_asset_node(AssetNode(project_id=project.id, node_type="computer", value="LAPTOP-DEV$", label="LAPTOP-DEV$", source_tool="ldap"))

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()
    # Must not raise ValueError or crash
    map_view.load_discovered_assets(db, project.id)

    host_items = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem)]
    assert len(host_items) >= 2


def test_fixture_9_missing_relationship_endpoints(qtbot, tmp_path: Path):
    """Fixture 9: Missing relationship endpoints gracefully handled in 2D and 3D without crashing."""
    db = Database(tmp_path / "dangling_test.db")
    project = db.create_project(Project(name="Dangling Test", client_name="client-d", description="Dangling"))

    n1 = db.upsert_asset_node(AssetNode(project_id=project.id, node_type="ip", value="10.0.0.1", label="gw", source_tool="nmap"))
    n2 = db.upsert_asset_node(AssetNode(project_id=project.id, node_type="ip", value="10.0.0.2", label="srv", source_tool="nmap"))
    db.upsert_asset_edge(AssetEdge(project_id=project.id, source_node_id=n1.id, target_node_id=n2.id, relation_type="routes_to", source_tool="nmap"))

    # Simulate an orphaned edge where target node n2 was removed
    with db.session() as conn:
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute("DELETE FROM asset_nodes WHERE id = ?", (n2.id,))

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()
    map_view.load_discovered_assets(db, project.id)

    web_view = WebGL3DNetworkView()
    qtbot.addWidget(web_view)
    web_view.show()
    web_view.load_discovered_assets(db, project.id)

    # 3D payload must have skipped the dangling link
    if web_view._pending_payload:
        data = json.loads(web_view._pending_payload)
        links = data["links"]
        assert not any(l["target"] == f"node_{n2.id}" for l in links)


def test_fixture_10_projection_mode_switching(qtbot):
    """Fixture 10: Seamless projection switching between Radial, Tree Hierarchy, and Subnet Matrix."""
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    h1 = HostResult(ip="10.0.0.1", status="up", hostname="gw", ports=[])
    h2 = HostResult(ip="10.0.0.2", status="up", hostname="srv", ports=[])
    scan = NmapScanResult(command_args="-sn", hosts=[h1, h2], scanner="nmap", summary="2 hosts")
    map_view.load_scan(scan)

    # Radial
    map_view._set_layout_mode("radial")
    assert map_view.layout_mode == "radial"
    assert map_view.radar_item.isVisible() is True

    # Tree
    map_view._set_layout_mode("tree")
    assert map_view.layout_mode == "tree"
    assert map_view.radar_item.isVisible() is False
    wan_items = [it for it in map_view.scene.items() if isinstance(it, NetworkWANNodeItem) and it.isVisible()]
    assert len(wan_items) == 1

    # Grid
    map_view._set_layout_mode("grid")
    assert map_view.layout_mode == "grid"
    assert map_view.radar_item.isVisible() is False


@pytest.mark.parametrize("host_count", [10, 50, 100, 250])
def test_performance_and_clearance_scaling(qtbot, host_count: int):
    """Scalability test verifying zero collisions and high performance up to 250 nodes."""
    import time

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    hosts = [HostResult(ip=f"10.0.0.{i+1}", status="up", ports=[]) for i in range(host_count)]
    scan = NmapScanResult(command_args="-sn", hosts=hosts, scanner="nmap", summary=f"{host_count} hosts")

    t0 = time.perf_counter()
    map_view.load_scan(scan)
    map_view._set_layout_mode("radial")
    elapsed = time.perf_counter() - t0

    assert elapsed < 2.0, f"Render took too long: {elapsed:.2f}s for {host_count} nodes"

    host_items = [it for it in map_view.scene.items() if isinstance(it, NetworkHostNodeItem) and it.isVisible()]
    assert len(host_items) == host_count

    # Verify clearance between consecutive nodes on orbits
    min_dist = float("inf")
    for i in range(len(host_items)):
        for j in range(i + 1, min(i + 15, len(host_items))):
            p1 = host_items[i].pos()
            p2 = host_items[j].pos()
            d = math.hypot(p1.x() - p2.x(), p1.y() - p2.y())
            if d < min_dist:
                min_dist = d

    assert min_dist > 35.0, f"Clearance too small ({min_dist:.1f}px) for {host_count} nodes!"


def test_export_svg_png_and_header_suppression(qtbot, tmp_path: Path):
    """Verifies SVG and PNG export, projection switching preservation, and hidden header suppression."""
    from unittest.mock import patch
    from PySide6.QtWidgets import QFileDialog, QMessageBox

    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    h1 = HostResult(ip="192.168.100.1", status="up", hostname="_gateway", ports=[PortResult(port_id=80, protocol="tcp", state="open")])
    h2 = HostResult(ip="192.168.100.10", status="up", hostname="node10", ports=[])
    scan = NmapScanResult(command_args="-sn", hosts=[h1, h2], scanner="nmap", summary="2 hosts")
    map_view.load_scan(scan)

    # 1. When sentinel bar is visible, SVG contains Cyber Sentinel
    map_view.show_sentinel_header()
    svg_visible = map_view.to_svg()
    assert "CYBER SENTINEL" in svg_visible
    assert "192.168.100.1" in svg_visible

    # 2. When sentinel bar is hidden, SVG suppresses Cyber Sentinel banner
    map_view.hide_sentinel_header()
    svg_hidden = map_view.to_svg()
    assert "CYBER SENTINEL" not in svg_hidden
    assert "Enterprise Cyber Terrain Architecture" in svg_hidden

    # 3. Export works across projection modes (Tree, Grid, Radial)
    for mode in ("tree", "grid", "radial"):
        map_view._set_layout_mode(mode)
        png_file = tmp_path / f"export_{mode}.png"
        svg_file = tmp_path / f"export_{mode}.svg"

        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(png_file), "PNG (*.png)")), \
             patch.object(QMessageBox, "information"):
            map_view.export_png()

        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(svg_file), "SVG (*.svg)")), \
             patch.object(QMessageBox, "information"):
            map_view.export_svg()

        assert png_file.exists() and png_file.stat().st_size > 5000
        assert svg_file.exists() and svg_file.stat().st_size > 500


