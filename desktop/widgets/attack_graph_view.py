"""Native Attack Surface Relationship Graph Widget for CyberSecuritySuite.

Renders interactive network topology (Domains, Subdomains, IPs, ASNs, Certificates)
using QGraphicsScene & QGraphicsView, and provides one-click Maltego CSV and GraphML export/import.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from desktop.theme import CPENTTheme, ThemeManager
from modules.osint.maltego_graph import MaltegoGraphEngine
from storage.db import Database
from storage.models import AssetEdge, AssetNode, Project


# Node styling constants adhering to the CPENT theme palette
NODE_COLORS = {
    "domain": {"bg": QColor(CPENTTheme.DEEP_NAVY), "border": QColor(CPENTTheme.PRIMARY_BLUE)},
    "subdomain": {"bg": QColor(CPENTTheme.ELEVATED_PANEL), "border": QColor(CPENTTheme.PRIMARY_BLUE)},
    "ip": {"bg": QColor("#0E3320"), "border": QColor(CPENTTheme.SUCCESS_GREEN)},
    "asn": {"bg": QColor(CPENTTheme.PANEL_BG), "border": QColor(CPENTTheme.INFO_CYAN)},
    "dns_record": {"bg": QColor("#383010"), "border": QColor(CPENTTheme.AMBER_ACCENT)},
    "cert": {"bg": QColor("#3D1014"), "border": QColor(CPENTTheme.ERROR_RED)},
}
DEFAULT_NODE_COLOR = {"bg": QColor(CPENTTheme.ELEVATED_PANEL), "border": QColor(CPENTTheme.SECONDARY_TEXT)}


class GraphNodeItem(QGraphicsItem):
    """Visual circular node with label and tooltip."""

    def __init__(self, node: AssetNode, x: float, y: float, radius: float = 24.0):
        super().__init__()
        self.node = node
        self.radius = radius
        self.setPos(x, y)
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setToolTip(
            f"Type: {node.node_type.upper()}\n"
            f"Value: {node.value}\n"
            f"Label: {node.label}\n"
            f"Source Tool: {node.source_tool}\n"
            f"Confidence: {node.confidence * 100:.0f}%"
        )

    def boundingRect(self) -> QRectF:
        return QRectF(-self.radius, -self.radius, self.radius * 2, self.radius * 2 + 18)

    def paint(self, painter: QPainter, option, widget=None):
        del option, widget
        painter.setRenderHint(QPainter.Antialiasing)

        style = NODE_COLORS.get(self.node.node_type.lower(), DEFAULT_NODE_COLOR)
        pen = QPen(style["border"], 2)
        brush = QBrush(style["bg"])

        painter.setPen(pen)
        painter.setBrush(brush)
        painter.drawEllipse(-self.radius, -self.radius, self.radius * 2, self.radius * 2)

        # Draw icon initial
        painter.setPen(QColor("#ffffff"))
        font = QFont("sans-serif", 10, QFont.Bold)
        painter.setFont(font)
        initial = self.node.node_type[:2].upper()
        painter.drawText(QRectF(-self.radius, -self.radius, self.radius * 2, self.radius * 2), Qt.AlignCenter, initial)

        # Draw text label underneath
        painter.setPen(QColor("#e2e8f0"))
        lbl_font = QFont("sans-serif", 8)
        painter.setFont(lbl_font)
        display_text = self.node.value
        if len(display_text) > 18:
            display_text = display_text[:16] + ".."
        painter.drawText(QRectF(-50, self.radius + 2, 100, 16), Qt.AlignCenter, display_text)


class AttackGraphView(QWidget):
    """Interactive visual topology for attack surface relationships and Maltego data."""

    graph_updated = Signal()

    def __init__(self, db: Database, parent=None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.engine = MaltegoGraphEngine(db)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Top Action Bar
        top_bar_scroll = QScrollArea()
        top_bar_scroll.setWidgetResizable(True)
        top_bar_scroll.setFixedHeight(42)
        top_bar_scroll.setFrameShape(QFrame.NoFrame)
        top_bar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        top_bar_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        top_container = QWidget()
        top_bar = QHBoxLayout(top_container)
        top_bar.setContentsMargins(0, 0, 0, 0)
        top_bar.setSpacing(6)

        self.lbl_stats = QLabel("Attack Surface Graph: 0 Nodes · 0 Relationships")
        self.lbl_stats.setStyleSheet(f"font-weight: bold; color: {CPENTTheme.PRIMARY_BLUE}; font-size: 12px;")
        top_bar.addWidget(self.lbl_stats)
        top_bar.addStretch()

        self.btn_import_csv = QPushButton("📥 Import Maltego CSV")
        self.btn_import_csv.setFixedHeight(26)
        self.btn_import_csv.clicked.connect(self._on_import_csv)
        top_bar.addWidget(self.btn_import_csv)

        self.btn_export_csv = QPushButton("📤 Export CSV")
        self.btn_export_csv.setFixedHeight(26)
        self.btn_export_csv.clicked.connect(self._on_export_csv)
        top_bar.addWidget(self.btn_export_csv)

        self.btn_export_graphml = QPushButton("📤 Export GraphML")
        self.btn_export_graphml.setFixedHeight(26)
        self.btn_export_graphml.clicked.connect(self._on_export_graphml)
        top_bar.addWidget(self.btn_export_graphml)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setFixedHeight(26)
        self.btn_refresh.clicked.connect(self.load_graph)
        top_bar.addWidget(self.btn_refresh)

        self.btn_clear = QPushButton("🗑️ Clear")
        self.btn_clear.setFixedHeight(26)
        self.btn_clear.clicked.connect(self._on_clear_graph)
        top_bar.addWidget(self.btn_clear)

        top_bar_scroll.setWidget(top_container)
        layout.addWidget(top_bar_scroll)

        # Graphics Scene & View
        self.scene = QGraphicsScene(self)
        theme_mgr = ThemeManager.instance()
        tokens = theme_mgr.get_tokens()
        self.scene.setBackgroundBrush(QBrush(QColor(tokens.canvas_bg)))
        theme_mgr.theme_changed.connect(self._on_theme_changed)

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        layout.addWidget(self.view, 1)

    def _on_theme_changed(self, mode: str):
        tokens = ThemeManager.instance().get_tokens()
        self.scene.setBackgroundBrush(QBrush(QColor(tokens.canvas_bg)))
        self.load_graph()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        self.load_graph()

    def load_graph(self):
        """Builds and lays out graph entities on the canvas."""
        self.scene.clear()
        if not self.active_project or not self.active_project.id:
            self.lbl_stats.setText("Attack Surface Graph: No Project Selected")
            return

        project_id = self.active_project.id
        nodes = self.db.list_asset_nodes(project_id)
        edges = self.db.list_asset_edges(project_id)

        self.lbl_stats.setText(f"Attack Surface Graph: {len(nodes)} Nodes · {len(edges)} Relationships")

        if not nodes:
            txt = self.scene.addText("No attack surface relationships discovered yet.\nRun OWASP Amass or import a Maltego CSV to populate the graph.", QFont("sans-serif", 11))
            txt.setDefaultTextColor(QColor(CPENTTheme.MUTED_TEXT))
            txt.setPos(50, 50)
            return

        # Layout nodes in radial rings based on type
        node_items: Dict[int, GraphNodeItem] = {}
        type_groups: Dict[str, List[AssetNode]] = {}
        for n in nodes:
            type_groups.setdefault(n.node_type.lower(), []).append(n)

        # Center: Domains
        center_x, center_y = 400.0, 300.0
        rings = [
            ("domain", 0.0),
            ("subdomain", 140.0),
            ("ip", 260.0),
            ("asn", 380.0),
            ("dns_record", 480.0),
            ("cert", 560.0),
        ]

        for n_type, radius in rings:
            group = type_groups.get(n_type, [])
            if not group:
                continue
            count = len(group)
            angle_step = (2 * math.pi) / max(1, count)
            for idx, node in enumerate(group):
                if radius == 0.0:
                    px = center_x + (idx * 60) - (count * 30)
                    py = center_y
                else:
                    angle = idx * angle_step
                    px = center_x + radius * math.cos(angle)
                    py = center_y + radius * math.sin(angle)

                item = GraphNodeItem(node, px, py)
                self.scene.addItem(item)
                if node.id is not None:
                    node_items[node.id] = item

        # Draw directed relationship edges
        for edge in edges:
            src = node_items.get(edge.source_node_id)
            tgt = node_items.get(edge.target_node_id)
            if src and tgt:
                p1 = src.pos()
                p2 = tgt.pos()
                line = QGraphicsLineItem(p1.x(), p1.y(), p2.x(), p2.y())
                line_pen = QPen(QColor("#475569"), 1.5, Qt.DashLine if edge.relation_type == "BELONGS_TO_ASN" else Qt.SolidLine)
                line.setPen(line_pen)
                line.setToolTip(f"{src.node.value} --[{edge.relation_type}]--> {tgt.node.value}")
                self.scene.addItem(line)

    def _on_export_csv(self):
        if not self.active_project:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Maltego CSV", f"attack_surface_{self.active_project.name}.csv", "CSV Files (*.csv)")
        if path:
            csv_data = self.engine.export_csv(self.active_project.id)
            with open(path, "w", encoding="utf-8") as f:
                f.write(csv_data)
            QMessageBox.information(self, "Export Successful", f"Attack surface graph exported to {path}")

    def _on_export_graphml(self):
        if not self.active_project:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export GraphML", f"attack_surface_{self.active_project.name}.graphml", "GraphML Files (*.graphml)")
        if path:
            xml_data = self.engine.export_graphml(self.active_project.id)
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml_data)
            QMessageBox.information(self, "Export Successful", f"GraphML exported to {path}")

    def _on_import_csv(self):
        if not self.active_project:
            QMessageBox.warning(self, "No Project", "Select an active engagement project first.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import Maltego CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            scopes = self.db.list_scopes(self.active_project.id)
            res = self.engine.import_csv(self.active_project.id, content, scopes=scopes)
            self.load_graph()
            self.graph_updated.emit()
            msg = f"Successfully imported {len(res.imported_nodes)} in-scope entities."
            if res.quarantined_nodes:
                msg += f"\n\n[Scope Quarantine]: {len(res.quarantined_nodes)} out-of-scope entities were quarantined."
            QMessageBox.information(self, "Import Complete", msg)

    def _on_clear_graph(self):
        if not self.active_project:
            return
        confirm = QMessageBox.question(
            self,
            "Clear Graph",
            "Are you sure you want to delete all discovered asset relationships for this project?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self.engine.db.delete_asset_graph(self.active_project.id)
            self.load_graph()
            self.graph_updated.emit()
