"""Unit and integration tests for the 2D Network Topology Designer.

Tests:
- All 9 required device types and their vector iconography
- Canvas interactions: item addition, drag, snap-to-grid, dynamic connection links
- Property inspector updates: label, hostname, IP annotation, notes, device type
- Explicit safe deletion guards
- Standalone JSON serialization / deserialization & SVG/PNG export
- Fail-closed scope safety: canvas IPs do not alter Scope Guard rules or live DB
- MainWindow workspace integration
"""

import json
import os
import tempfile
from unittest.mock import patch

import pytest
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtWidgets import QGraphicsItem, QMessageBox

from desktop.main_window import MainWindow
from desktop.widgets.topology_designer import (
    ALL_DEVICE_TYPES,
    DEVICE_TYPE_COLORS,
    DEVICE_TYPE_ICONS,
    DeviceType,
    TopologyDesignerWidget,
    TopologyDeviceItem,
    TopologyInspectorWidget,
    TopologyLinkItem,
    TopologyScene,
    TopologyView,
    draw_device_vector_icon,
)
from storage.db import Database
from storage.models import Project, TargetScope


@pytest.fixture
def test_db():
    return Database(":memory:")


def test_all_9_device_types_defined():
    """Verifies that all 9 required device types are canonically defined and mapped."""
    expected = [
        "Router",
        "Firewall",
        "Switch",
        "Server",
        "Workstation",
        "Database",
        "Cloud",
        "Internet",
        "Security appliance",
    ]
    for dt in expected:
        assert dt in ALL_DEVICE_TYPES
        assert dt in DEVICE_TYPE_COLORS
        assert dt in DEVICE_TYPE_ICONS


def test_topology_device_item_creation_and_bounds(qtbot):
    """Verifies device node creation, flags, dimensions, and tooltips."""
    for dt in ALL_DEVICE_TYPES:
        item = TopologyDeviceItem(device_type=dt, label=f"Test-{dt}", ip_address="10.0.0.1")
        assert item.device_type == dt
        assert item.label == f"Test-{dt}"
        assert item.ip_address == "10.0.0.1"
        assert item.flags() & QGraphicsItem.ItemIsMovable
        assert item.flags() & QGraphicsItem.ItemIsSelectable
        assert item.flags() & QGraphicsItem.ItemSendsGeometryChanges

        rect = item.boundingRect()
        assert rect.width() >= 100.0
        assert rect.height() >= 86.0
        assert "Documentation Only" in item.toolTip()
        assert dt in item.toolTip()


def test_vector_icon_painting_for_all_types(qtbot):
    """Verifies vector drawing for all 9 device types without rendering errors."""
    img = QImage(200, 200, QImage.Format_ARGB32)
    painter = QPainter(img)

    try:
        for dt in ALL_DEVICE_TYPES:
            item = TopologyDeviceItem(device_type=dt, label=dt, ip_address="192.168.1.1")
            # Call paint directly
            item.paint(painter, None, None)
    finally:
        painter.end()


def test_snap_to_grid_on_movement(qtbot):
    """Verifies snap-to-grid rounding logic when moving items."""
    scene = TopologyScene()
    scene.snap_to_grid = True
    scene.grid_size = 20

    item = scene.add_device(DeviceType.ROUTER, x=13.0, y=28.0)
    # Initial add should be snapped
    assert item.pos().x() == 20.0
    assert item.pos().y() == 20.0 or item.pos().y() == 40.0

    # Test programmatic position changes with snap
    item.setPos(54.0, 71.0)
    assert item.pos().x() == 60.0
    assert item.pos().y() == 80.0

    # Disable snap to grid
    scene.snap_to_grid = False
    item.setPos(54.0, 71.0)
    assert item.pos().x() == 54.0
    assert item.pos().y() == 71.0


def test_topology_link_item_connection_and_dynamic_update(qtbot):
    """Verifies connecting devices with lines and dynamic update on move."""
    scene = TopologyScene()
    dev1 = scene.add_device(DeviceType.ROUTER, x=0.0, y=0.0, label="R1")
    dev2 = scene.add_device(DeviceType.FIREWALL, x=100.0, y=100.0, label="FW1")

    # Connect dev1 and dev2
    link = scene.add_link(dev1, dev2, link_type="Standard LAN", label="LAN-Trunk")
    assert link is not None
    assert link in dev1.connected_links
    assert link in dev2.connected_links

    # Line endpoints match device positions
    assert link.line().p1().x() == 0.0
    assert link.line().p1().y() == 0.0
    assert link.line().p2().x() == 100.0
    assert link.line().p2().y() == 100.0

    # Move dev1 -> link endpoints must dynamically update
    dev1.setPos(40.0, 60.0)
    assert link.line().p1().x() == 40.0
    assert link.line().p1().y() == 60.0

    # Self connection should be rejected
    self_link = scene.add_link(dev1, dev1)
    assert self_link is None

    # Duplicate link should return existing link
    dup_link = scene.add_link(dev1, dev2)
    assert dup_link == link


def test_property_inspector_device_and_link_updates(qtbot):
    """Verifies that selecting and editing items via the property inspector updates the canvas."""
    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    # Add a device
    dev = widget.scene.add_device(
        device_type=DeviceType.WORKSTATION,
        x=50.0,
        y=50.0,
        label="WS-01",
        ip_address="192.168.1.50",
        hostname="finance-pc",
        notes="Finance department",
    )

    # Select device
    widget.scene.clearSelection()
    dev.setSelected(True)
    widget.inspector.inspect_device(dev)

    assert widget.inspector.edit_label.text() == "WS-01"
    assert widget.inspector.edit_ip.text() == "192.168.1.50"
    assert widget.inspector.edit_hostname.text() == "finance-pc"

    # Modify properties via inspector
    widget.inspector.edit_label.setText("WS-Finance-01")
    widget.inspector.edit_ip.setText("192.168.1.55")
    widget.inspector.combo_type.setCurrentIndex(widget.inspector.combo_type.findData(DeviceType.SERVER))

    assert dev.label == "WS-Finance-01"
    assert dev.ip_address == "192.168.1.55"
    assert dev.device_type == DeviceType.SERVER


def test_safe_deletion_guards(qtbot):
    """Verifies that deletion requires explicit action and confirmation."""
    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    dev1 = widget.scene.add_device(DeviceType.ROUTER, x=0.0, y=0.0, label="R1")
    dev2 = widget.scene.add_device(DeviceType.SWITCH, x=100.0, y=100.0, label="SW1")
    link = widget.scene.add_link(dev1, dev2)

    assert len(widget.scene.get_devices()) == 2
    assert len(widget.scene.get_links()) == 1

    # Select dev1
    dev1.setSelected(True)

    # If user cancels deletion in confirmation dialog, item remains
    with patch.object(QMessageBox, "question", return_value=QMessageBox.No):
        widget._prompt_delete_selected()
        assert len(widget.scene.get_devices()) == 2
        assert len(widget.scene.get_links()) == 1

    # If user confirms deletion, item and its connected links are removed
    with patch.object(QMessageBox, "question", return_value=QMessageBox.Yes):
        widget._prompt_delete_selected()
        assert len(widget.scene.get_devices()) == 1
        assert len(widget.scene.get_links()) == 0
        assert dev2 in widget.scene.get_devices()


def test_topology_json_serialization_and_deserialization(qtbot):
    """Verifies roundtrip JSON serialization (to_dict / from_dict)."""
    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    dev1 = widget.scene.add_device(
        device_type=DeviceType.FIREWALL,
        x=40.0,
        y=40.0,
        label="Edge-FW",
        ip_address="10.0.0.1",
        hostname="edge-fw.corp",
        notes="Border firewall",
    )
    dev2 = widget.scene.add_device(
        device_type=DeviceType.DATABASE,
        x=200.0,
        y=200.0,
        label="Prod-DB",
        ip_address="10.0.10.5",
        hostname="db01.corp",
        notes="PostgreSQL cluster",
    )
    widget.scene.add_link(dev1, dev2, link_type="VPN Tunnel", label="Encrypted-Tunnel")

    data = widget.to_dict()
    assert len(data["devices"]) == 2
    assert len(data["links"]) == 1
    device_types = {d["type"] for d in data["devices"]}
    assert DeviceType.FIREWALL in device_types
    assert DeviceType.DATABASE in device_types
    assert data["links"][0]["link_type"] == "VPN Tunnel"

    # Clear canvas and restore from dict
    widget.clear_canvas()
    assert len(widget.scene.get_devices()) == 0
    assert len(widget.scene.get_links()) == 0

    widget.from_dict(data)
    devices = widget.scene.get_devices()
    links = widget.scene.get_links()

    assert len(devices) == 2
    assert len(links) == 1
    labels = [d.label for d in devices]
    assert "Edge-FW" in labels
    assert "Prod-DB" in labels


def test_topology_file_save_and_load(qtbot, tmp_path):
    """Verifies file saving and loading to disk."""
    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    widget.scene.add_device(DeviceType.CLOUD, x=60.0, y=60.0, label="AWS-VPC")
    save_file = str(tmp_path / "test_topology.json")

    assert widget.save_topology_to_file(save_file)
    assert os.path.exists(save_file)

    widget.clear_canvas()
    assert len(widget.scene.get_devices()) == 0

    assert widget.load_topology_from_file(save_file)
    assert len(widget.scene.get_devices()) == 1
    assert widget.scene.get_devices()[0].label == "AWS-VPC"


def test_export_svg_and_png(qtbot, tmp_path):
    """Verifies exporting diagram to SVG and PNG formats."""
    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    widget.scene.add_device(DeviceType.INTERNET, x=0.0, y=0.0, label="WAN")
    widget.scene.add_device(DeviceType.SECURITY_APPLIANCE, x=100.0, y=0.0, label="SIEM")

    svg_file = str(tmp_path / "diagram.svg")
    png_file = str(tmp_path / "diagram.png")

    assert widget.export_svg(svg_file)
    assert os.path.exists(svg_file)
    assert os.path.getsize(svg_file) > 0

    assert widget.export_png(png_file)
    assert os.path.exists(png_file)
    assert os.path.getsize(png_file) > 0


def test_scope_safety_isolation(qtbot, test_db):
    """Verifies that adding devices with IPs on canvas NEVER alters TargetScope or database."""
    initial_scopes = test_db.list_scopes(project_id=1)

    widget = TopologyDesignerWidget()
    qtbot.addWidget(widget)

    # Add devices with sensitive/internal IPs
    widget.scene.add_device(DeviceType.ROUTER, ip_address="192.168.1.1", label="Gateway")
    widget.scene.add_device(DeviceType.SERVER, ip_address="10.10.10.10", label="Domain-Controller")
    widget.scene.add_device(DeviceType.DATABASE, ip_address="172.16.0.5", label="Core-DB")

    # Scopes in database must remain completely unchanged
    post_scopes = test_db.list_scopes(project_id=1)
    assert len(post_scopes) == len(initial_scopes)


def test_main_window_topology_integration(qtbot, test_db):
    """Verifies that Topology Designer is integrated into MainWindow Security Workspace."""
    project = test_db.create_project(Project(name="Red Team Engagement", client_name="FinCorp"))
    assert project.id is not None

    window = MainWindow(db=test_db)
    qtbot.addWidget(window)
    window.show()

    # Verify widget is instantiated and attached to security tabs
    assert hasattr(window, "topology_view")
    assert isinstance(window.topology_view, TopologyDesignerWidget)
    assert window.topology_view in [
        window.security_tabs.widget(i) for i in range(window.security_tabs.count())
    ]

    # Verify switching project updates topology designer's active project
    window._on_project_selected(project)
    assert window.topology_view.active_project == project
    assert "Red Team Engagement" in window.topology_view.lbl_project.text()
