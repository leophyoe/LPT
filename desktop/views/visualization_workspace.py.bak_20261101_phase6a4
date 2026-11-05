"""Unified 2D and 3D Network Visualization Workspace for CyberSecuritySuite.

Provides enterprise-grade attack surface visualization matching modern cybersecurity platforms:
- 2D Canvas: Fortinet FortiGate-style network topology with external WAN root,
  perimeter gateway firewall, interface ports, logical subnet domains, curved Bézier links,
  and layout modes (Tree, Radial, Grid).
- 3D Canvas: Hardware-accelerated 3D WebGL cyber mesh with 360-degree OrbitControls,
  severity-coded glowing spheres, orbital subnet planes, and bidirectional PySide6 inspection.
- Segmented mode switcher allowing seamless one-click toggling between 2D and 3D perspectives.
- Sourcing rule: All nodes, subnets, open ports, and edges are strictly backed by actual stored
  database evidence (AssetNode, AssetEdge, PortResult, Finding). Zero fabricated nodes.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from desktop.theme import CPENTTheme
from desktop.widgets.network_map_view import NetworkMapView
from desktop.widgets.webgl_3d_network_view import WebGL3DNetworkView
from storage.db import Database
from storage.models import Finding, Project

logger = logging.getLogger(__name__)


class VisualizationWorkspace(QWidget):
    """Unified Workspace offering 2D Fortinet Topology and 3D WebGL Cyber Mesh."""

    host_selected = Signal(object)  # Emits HostResult or host IP

    def __init__(self, db: Database, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.setObjectName("visualizationWorkspace")
        self._init_ui()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Control Bar (SentinelX & Fortinet Style)
        top_bar = QFrame()
        top_bar.setStyleSheet(
            "QFrame { background-color: #0b0f19; border-bottom: 1px solid #1e293b; padding: 6px 12px; }"
        )
        bar_layout = QHBoxLayout(top_bar)
        bar_layout.setContentsMargins(8, 6, 8, 6)
        bar_layout.setSpacing(12)

        # Title / Brand Icon
        lbl_title = QLabel("🗺️  ENTERPRISE INFRASTRUCTURE & ATTACK SURFACE STUDIO")
        lbl_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_title.setStyleSheet("color: #38bdf8;")
        bar_layout.addWidget(lbl_title)

        # Segmented View Mode Switcher: Perimeter vs Spatial Attack Surface
        mode_box = QFrame()
        mode_box.setStyleSheet(
            "QFrame { background-color: #111827; border: 1px solid #334155; border-radius: 6px; padding: 2px; }"
        )
        mode_layout = QHBoxLayout(mode_box)
        mode_layout.setContentsMargins(2, 2, 2, 2)
        mode_layout.setSpacing(4)

        self.btn_mode_2d = QPushButton("🛡️ Perimeter & Segment Architecture")
        self.btn_mode_2d.setToolTip("Enterprise Perimeter, Firewalls, VLANs & Subnet Segments")
        self.btn_mode_2d.setCheckable(True)
        self.btn_mode_2d.setChecked(True)
        self.btn_mode_2d.setCursor(Qt.PointingHandCursor)
        self.btn_mode_2d.setStyleSheet(
            "QPushButton { background: transparent; color: #94a3b8; border: none; padding: 4px 10px; font-weight: 600; font-size: 11px; border-radius: 4px; }"
            "QPushButton:checked { background: #0284c7; color: #ffffff; }"
        )
        mode_layout.addWidget(self.btn_mode_2d)

        self.btn_mode_3d = QPushButton("🌐 Spatial Attack Surface")
        self.btn_mode_3d.setToolTip("Multi-Dimensional Spatial Threat Surface & Lateral Movement Graph")
        self.btn_mode_3d.setCheckable(True)
        self.btn_mode_3d.setChecked(False)
        self.btn_mode_3d.setCursor(Qt.PointingHandCursor)
        self.btn_mode_3d.setStyleSheet(
            "QPushButton { background: transparent; color: #94a3b8; border: none; padding: 4px 10px; font-weight: 600; font-size: 11px; border-radius: 4px; }"
            "QPushButton:checked { background: #0284c7; color: #ffffff; }"
        )
        mode_layout.addWidget(self.btn_mode_3d)

        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.btn_mode_2d, 0)
        self.mode_group.addButton(self.btn_mode_3d, 1)
        self.mode_group.idClicked.connect(self._on_mode_switched)

        bar_layout.addWidget(mode_box)
        bar_layout.addStretch()

        # Search Bar
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍  Filter by IP, hostname, port...")
        self.txt_search.setFixedWidth(200)
        self.txt_search.setStyleSheet(
            "QLineEdit { background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; border-radius: 4px; padding: 4px 8px; font-size: 11px; }"
        )
        self.txt_search.textChanged.connect(self._on_search_changed)
        bar_layout.addWidget(self.txt_search)

        # Refresh Button
        self.btn_sync = QPushButton("↻  Sync Database Assets")
        self.btn_sync.setCursor(Qt.PointingHandCursor)
        self.btn_sync.setStyleSheet(
            "QPushButton { background-color: #1e293b; color: #38bdf8; border: 1px solid #334155; border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px; }"
            "QPushButton:hover { background-color: #334155; color: #ffffff; }"
        )
        self.btn_sync.clicked.connect(self.refresh)
        bar_layout.addWidget(self.btn_sync)

        root_layout.addWidget(top_bar)

        # 2. Main Stacked Canvas: Page 0 = 2D Fortinet Map, Page 1 = 3D WebGL Map
        self.canvas_stack = QStackedWidget(self)

        # Page 0: 2D Fortinet Map View
        self.map_2d = NetworkMapView(self)
        self.map_2d.hide_sentinel_header()
        self.map_2d.host_selected.connect(self._on_2d_host_selected)
        self.canvas_stack.addWidget(self.map_2d)

        # Page 1: 3D WebGL Network View
        self.map_3d = WebGL3DNetworkView(self)
        self.map_3d.host_selected.connect(self._on_3d_host_selected)
        self.canvas_stack.addWidget(self.map_3d)

        root_layout.addWidget(self.canvas_stack, stretch=1)

    def _on_mode_switched(self, mode_id: int):
        self.canvas_stack.setCurrentIndex(mode_id)
        if mode_id == 1:
            # Sync data to 3D WebGL canvas
            pid = self.active_project.id if self.active_project else None
            self.map_3d.load_discovered_assets(self.db, pid)

    def _on_search_changed(self, text: str):
        if hasattr(self.map_2d, "txt_dev_search"):
            self.map_2d.txt_dev_search.setText(text)

    def _on_2d_host_selected(self, host):
        self.host_selected.emit(host)

    def _on_3d_host_selected(self, ip: str):
        # Forward to 2D view inspector if available
        if hasattr(self.map_2d, "list_devices"):
            for i in range(self.map_2d.list_devices.count()):
                item = self.map_2d.list_devices.item(i)
                h = item.data(Qt.UserRole)
                if h and h.ip == ip:
                    self.map_2d._on_device_list_clicked(item)
                    break
        self.host_selected.emit(ip)

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        self.refresh()

    def load_discovered_assets(self, db: Database, project_id: Optional[int] = None):
        """Loads discovered assets for the given project into both 2D and 3D canvases."""
        self.db = db
        try:
            self.map_2d.load_discovered_assets(db, project_id)
            self.map_3d.load_discovered_assets(db, project_id)
        except Exception as exc:
            logger.debug("Failed loading discovered assets in visualization workspace: %s", exc)

    def refresh(self):
        """Reloads all discovered network assets and topology nodes from SQLite."""
        pid = self.active_project.id if self.active_project else None
        try:
            self.map_2d.load_discovered_assets(self.db, pid)
            self.map_3d.load_discovered_assets(self.db, pid)
        except Exception as exc:
            logger.debug("Failed refreshing visualization workspace: %s", exc)

    def load_scan(self, scan_result, findings=None):
        """Passes external scan results to both 2D and 3D renderers."""
        self.map_2d.load_scan(scan_result, findings)
        pid = self.active_project.id if self.active_project else None
        self.map_3d.load_discovered_assets(self.db, pid)

    def to_svg(self) -> str:
        return self.map_2d.to_svg()

