"""High-Performance 3D WebGL Network Map Widget for CyberSecuritySuite.

Provides an immersive 360-degree 3D cyber mesh topology powered by WebGL:
- Embedded in PySide6 via QtWebEngineWidgets.QWebEngineView.
- 100% offline, self-contained Pure WebGL rendering engine.
- 360° interactive OrbitControls: rotate, pan, and zoom.
- 3D spherical host nodes color-coded by vulnerability severity (Critical/High/Medium/Clean).
- Subnet orbital planes and dynamic connection links.
- Bidirectional QWebChannel bridge connecting 3D click interactions to native PySide6 inspector.
- Backed strictly by real database assets (AssetNode, AssetEdge, PortResult, Finding).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if "QTWEBENGINE_CHROMIUM_FLAGS" not in os.environ:
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu"

from PySide6.QtCore import QObject, QUrl, Signal, Slot
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

try:
    from PySide6.QtWebChannel import QWebChannel
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEB_ENGINE_AVAILABLE = True
except Exception as _web_exc:
    WEB_ENGINE_AVAILABLE = False
    QWebChannel = None
    QWebEngineView = None

from storage.db import Database
from storage.models import AssetEdge, AssetNode, Finding
from modules.network.nmap_parser import PortResult

logger = logging.getLogger(__name__)

HTML_PATH = Path(__file__).resolve().parent.parent / "resources" / "visualization" / "3d_map.html"


class PyBridge(QObject):
    """Bridge object exposed to JavaScript inside QWebEngineView via QWebChannel."""

    node_selected = Signal(str, str)  # node_id, ip

    @Slot(str, str)
    def onNodeSelected(self, node_id: str, ip: str):
        logger.debug("3D Mesh Node clicked: %s (IP: %s)", node_id, ip)
        self.node_selected.emit(node_id, ip)


class WebGL3DNetworkView(QWidget):
    """3D WebGL Network Map widget embedding interactive 3D topology."""

    host_selected = Signal(str)  # Emits IP address

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("webgl3DNetworkView")
        self._is_page_loaded = False
        self._pending_payload: Optional[str] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        if not WEB_ENGINE_AVAILABLE or QWebEngineView is None:
            fallback = QLabel("Spatial 3D acceleration is unavailable in this environment.\nSwitch to Perimeter & Segment Architecture above.")
            fallback.setStyleSheet("color: #94a3b8; font-size: 13px; padding: 24px; text-align: center;")
            layout.addWidget(fallback)
            self.web_view = None
            return

        try:
            # WebEngine View
            self.web_view = QWebEngineView(self)
            self.web_view.setStyleSheet("background-color: #080c14; border: none;")
            self.web_view.loadFinished.connect(self._on_load_finished)

            # Set up QWebChannel bridge
            self.bridge = PyBridge(self)
            self.bridge.node_selected.connect(self._on_node_selected)

            self.channel = QWebChannel(self.web_view.page())
            self.channel.registerObject("pyBridge", self.bridge)
            self.web_view.page().setWebChannel(self.channel)

            # Load local HTML file
            if HTML_PATH.exists():
                self.web_view.setUrl(QUrl.fromLocalFile(HTML_PATH.as_posix()))
            else:
                logger.error("3D Map HTML file not found at %s", HTML_PATH)

            layout.addWidget(self.web_view)
        except Exception as exc:
            logger.warning("Failed initializing QWebEngineView for 3D map: %s", exc)
            fallback = QLabel(f"3D WebGL renderer initialized in compatibility mode: {exc}")
            fallback.setStyleSheet("color: #94a3b8; font-size: 12px; padding: 20px;")
            layout.addWidget(fallback)
            self.web_view = None

    def _on_load_finished(self, ok: bool):
        self._is_page_loaded = bool(ok)
        if self._is_page_loaded and self._pending_payload and self.web_view:
            try:
                js_cmd = (
                    f"if (typeof window.updateGraphData === 'function') {{ "
                    f"window.updateGraphData({self._pending_payload}); "
                    f"}}"
                )
                self.web_view.page().runJavaScript(js_cmd)
                self._pending_payload = None
            except Exception as exc:
                logger.debug("Failed sending pending payload to WebGL: %s", exc)

    def _on_node_selected(self, node_id: str, ip: str):
        if ip and ip != "0.0.0.0/0":
            self.host_selected.emit(ip)

    def load_discovered_assets(self, db: Database, project_id: Optional[int] = None):
        """Builds 3D coordinates from real persisted database assets and passes them to WebGL."""
        try:
            nodes_db: List[AssetNode] = db.list_asset_nodes(project_id) if hasattr(db, "list_asset_nodes") else []
            edges_db: List[AssetEdge] = db.list_asset_edges(project_id) if hasattr(db, "list_asset_edges") else []
            findings: List[Finding] = db.list_findings(project_id) if hasattr(db, "list_findings") else []
            ports: List[PortResult] = db.list_port_results(project_id) if hasattr(db, "list_port_results") else []
        except Exception as exc:
            logger.warning("Failed querying assets for 3D map: %s", exc)
            return

        if not nodes_db:
            if self.web_view:
                try:
                    payload = json.dumps({"nodes": [], "links": []})
                    if self._is_page_loaded:
                        js_cmd = (
                            "if (typeof window.updateGraphData === 'function') { "
                            "window.updateGraphData({'nodes': [], 'links': []}); "
                            "}"
                        )
                        self.web_view.page().runJavaScript(js_cmd)
                    else:
                        self._pending_payload = payload
                except Exception:
                    pass
            return

        # Map findings by target IP / host
        finding_severities: Dict[str, str] = {}
        for f in findings:
            asset = (f.affected_asset or "").strip()
            if not asset:
                continue
            cur_sev = finding_severities.get(asset, "clean")
            new_sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 1, "clean": 0}
            if order.get(new_sev, 0) > order.get(cur_sev, 0):
                finding_severities[asset] = new_sev

        # Map ports count by IP
        ports_count: Dict[str, int] = {}
        for p in ports:
            pip = getattr(p, "ip", None) or getattr(p, "host_ip", None)
            if pip:
                ports_count[pip] = ports_count.get(pip, 0) + 1

        # Build 3D Graph Nodes
        mesh_nodes = []
        mesh_links = []

        # Real or detected Gateway check
        gw_node = next((n for n in nodes_db if "gateway" in (n.label or "").lower() or n.value.endswith(".1")), None)
        gw_label = f"Gateway ({gw_node.value})" if gw_node else "Assessment Pivot"
        gw_ip = gw_node.value if gw_node else "Assessment Horizon"

        # Central Root Perimeter and Pivot Gateway
        mesh_nodes.append({
            "id": "wan_root",
            "label": "External Network Perimeter",
            "ip": "0.0.0.0/0",
            "type": "Perimeter",
            "sev": "info",
            "x": 0.0,
            "y": 14.0,
            "z": 0.0,
            "scale": 2.2,
        })
        mesh_nodes.append({
            "id": "gw_firewall",
            "label": gw_label,
            "ip": gw_ip,
            "type": "Assessment Pivot",
            "sev": "info",
            "x": 0.0,
            "y": 7.0,
            "z": 0.0,
            "scale": 2.0,
        })
        mesh_links.append({"source": "wan_root", "target": "gw_firewall"})

        # Helper to resolve and validate IPv4/IPv6 addresses from AssetNode models
        def _resolve_asset_ip_and_subnet(node: AssetNode) -> Tuple[Optional[str], str, str, str]:
            """Extracts (valid_ip_str, subnet_cidr, display_ip, display_name)."""
            raw_val = getattr(node, "value", "").strip()
            label = getattr(node, "label", "").strip()

            meta_ip = ""
            if getattr(node, "metadata_json", ""):
                try:
                    m = json.loads(node.metadata_json)
                    meta_ip = str(m.get("ip") or m.get("host_ip") or m.get("ipv4") or "").strip()
                except Exception:
                    meta_ip = ""

            candidates = [c for c in (raw_val, meta_ip, label) if c]
            parsed_ip = None
            for cand in candidates:
                try:
                    parsed_ip = ipaddress.ip_address(cand)
                    break
                except ValueError:
                    continue

            name = label or raw_val or "Asset"

            if parsed_ip:
                ip_str = str(parsed_ip)
                if parsed_ip.version == 4:
                    octs = ip_str.split(".")
                    subnet = f"{octs[0]}.{octs[1]}.{octs[2]}.0/24"
                else:
                    exp = parsed_ip.exploded.split(":")
                    subnet = f"{exp[0]}:{exp[1]}:{exp[2]}:{exp[3]}::/64"
                return ip_str, subnet, ip_str, name
            else:
                # Group for non-IP assets (e.g. Domain naming contexts, named computers)
                return None, "Active Directory & Enterprise Directory", raw_val or name, name

        # Group assets by validated subnets
        subnets: Dict[str, List[Tuple[AssetNode, str, str]]] = {}
        for node in nodes_db:
            _, subnet_cidr, display_ip, display_name = _resolve_asset_ip_and_subnet(node)
            subnets.setdefault(subnet_cidr, []).append((node, display_ip, display_name))

        # Distribute subnets in concentric circular orbits
        subnet_index = 0
        total_subnets = max(1, len(subnets))
        for subnet_cidr, subnet_entries in subnets.items():
            sub_id = f"sub_{subnet_index}"
            sub_angle = (subnet_index / total_subnets) * (2 * math.pi)
            sub_dist = 18.0
            sub_x = math.cos(sub_angle) * sub_dist
            sub_z = math.sin(sub_angle) * sub_dist
            sub_y = 0.0

            mesh_nodes.append({
                "id": sub_id,
                "label": f"Subnet {subnet_cidr}",
                "ip": subnet_cidr,
                "type": "Subnet Domain",
                "sev": "info",
                "x": sub_x,
                "y": sub_y,
                "z": sub_z,
                "scale": 1.6,
            })
            mesh_links.append({"source": "gw_firewall", "target": sub_id})

            # Place hosts around the subnet hub
            host_count = len(subnet_entries)
            for h_idx, (h_node, h_ip, h_name) in enumerate(subnet_entries):
                h_id = f"node_{h_node.id}" if hasattr(h_node, "id") and h_node.id else f"node_s{subnet_index}_{h_idx}"

                h_angle = sub_angle - 0.5 + (h_idx / max(1, host_count)) * 1.0
                h_dist = sub_dist + 8.0
                h_x = math.cos(h_angle) * h_dist
                h_z = math.sin(h_angle) * h_dist
                h_y = -4.0 - (h_idx % 3) * 2.0

                sev = finding_severities.get(h_ip, "clean")
                num_ports = ports_count.get(h_ip, 0)

                device_type = getattr(h_node, "node_type", "Host").replace("_", " ").title()

                mesh_nodes.append({
                    "id": h_id,
                    "label": h_name,
                    "ip": h_ip,
                    "type": device_type,
                    "sev": sev,
                    "ports": num_ports,
                    "x": h_x,
                    "y": h_y,
                    "z": h_z,
                    "scale": 1.3,
                })
                mesh_links.append({"source": sub_id, "target": h_id})

            subnet_index += 1

        # Also add explicit database edges with safe endpoint validation
        node_ids = {n["id"] for n in mesh_nodes}
        for edge in edges_db:
            src_nid = getattr(edge, "source_node_id", getattr(edge, "source_id", None))
            tgt_nid = getattr(edge, "target_node_id", getattr(edge, "target_id", None))
            if src_nid and tgt_nid:
                s_id = f"node_{src_nid}"
                t_id = f"node_{tgt_nid}"
                if s_id in node_ids and t_id in node_ids:
                    mesh_links.append({"source": s_id, "target": t_id})

        # Send updated JSON to WebGL page
        if self.web_view:
            try:
                payload = json.dumps({"nodes": mesh_nodes, "links": mesh_links})
                if self._is_page_loaded:
                    js_cmd = (
                        f"if (typeof window.updateGraphData === 'function') {{ "
                        f"window.updateGraphData({payload}); "
                        f"}}"
                    )
                    self.web_view.page().runJavaScript(js_cmd)
                else:
                    self._pending_payload = payload
            except Exception as js_exc:
                logger.debug("Failed injecting graph data to WebEngine: %s", js_exc)
