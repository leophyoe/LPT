"""Maltego Attack Surface Graph Interoperability & Topology Engine.

Supports bidirectional export and import of Maltego tabular CSVs, open GraphML XML,
and structured JSON graph models with untrusted input sanitization and scope revalidation.
"""

from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import AssetEdge, AssetNode, TargetScope


# Maltego standard entity type mappings
MALTEGO_ENTITY_MAP: Dict[str, str] = {
    "domain": "maltego.Domain",
    "subdomain": "maltego.DNSName",
    "ip": "maltego.IPv4Address",
    "netblock": "maltego.Netblock",
    "asn": "maltego.AS",
    "dns_record": "maltego.NSRecord",
    "cert": "maltego.X509Certificate",
    "service": "maltego.Service",
}

REVERSE_MALTEGO_MAP: Dict[str, str] = {v.lower(): k for k, v in MALTEGO_ENTITY_MAP.items()}
REVERSE_MALTEGO_MAP.update({
    "maltego.domain": "domain",
    "maltego.dnsname": "subdomain",
    "maltego.ipv4address": "ip",
    "maltego.ipv6address": "ip",
    "maltego.netblock": "netblock",
    "maltego.as": "asn",
    "maltego.nsrecord": "dns_record",
    "maltego.mxrecord": "dns_record",
    "maltego.x509certificate": "cert",
})


@dataclass
class GraphImportResult:
    imported_nodes: List[AssetNode] = field(default_factory=list)
    imported_edges: List[AssetEdge] = field(default_factory=list)
    quarantined_nodes: List[Dict[str, Any]] = field(default_factory=list)
    total_parsed: int = 0
    errors: List[str] = field(default_factory=list)


class MaltegoGraphEngine:
    """Manages attack surface relationship topology and Maltego interoperability."""

    def __init__(self, db: Database):
        self.db = db

    # -------------------------------------------------------------
    # 1. Export Formats
    # -------------------------------------------------------------
    def export_csv(self, project_id: int) -> str:
        """Exports project attack surface graph to Maltego-compatible Tabular CSV format."""
        nodes = self.db.list_asset_nodes(project_id)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Entity Type", "Value", "Label", "Source Tool", "Confidence", "Metadata"])

        for n in nodes:
            maltego_type = MALTEGO_ENTITY_MAP.get(n.node_type.lower(), "maltego.Unknown")
            writer.writerow([
                maltego_type,
                n.value,
                n.label or n.value,
                n.source_tool or "cybersecuritysuite",
                n.confidence,
                n.metadata_json,
            ])

        return output.getvalue()

    def export_graphml(self, project_id: int) -> str:
        """Exports graph to standard GraphML XML supported by Maltego, Gephi, and Cytoscape."""
        nodes = self.db.list_asset_nodes(project_id)
        edges = self.db.list_asset_edges(project_id)

        root = ET.Element("graphml", {
            "xmlns": "http://graphml.graphdrawing.org/xmlns",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
        })

        # Define attribute keys
        key_type = ET.SubElement(root, "key", {"id": "d0", "for": "node", "attr.name": "node_type", "attr.type": "string"})
        key_label = ET.SubElement(root, "key", {"id": "d1", "for": "node", "attr.name": "label", "attr.type": "string"})
        key_tool = ET.SubElement(root, "key", {"id": "d2", "for": "node", "attr.name": "source_tool", "attr.type": "string"})
        key_relation = ET.SubElement(root, "key", {"id": "d3", "for": "edge", "attr.name": "relation", "attr.type": "string"})

        graph = ET.SubElement(root, "graph", {"id": f"Project_{project_id}_AttackSurface", "edgedefault": "directed"})

        for n in nodes:
            node_el = ET.SubElement(graph, "node", {"id": f"n{n.id}"})
            data_type = ET.SubElement(node_el, "data", {"key": "d0"})
            data_type.text = n.node_type
            data_label = ET.SubElement(node_el, "data", {"key": "d1"})
            data_label.text = n.label or n.value
            data_tool = ET.SubElement(node_el, "data", {"key": "d2"})
            data_tool.text = n.source_tool

        for idx, e in enumerate(edges):
            edge_el = ET.SubElement(graph, "edge", {
                "id": f"e{idx}_{e.source_node_id}_{e.target_node_id}",
                "source": f"n{e.source_node_id}",
                "target": f"n{e.target_node_id}",
            })
            data_rel = ET.SubElement(edge_el, "data", {"key": "d3"})
            data_rel.text = e.relation_type

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def export_json(self, project_id: int) -> str:
        """Exports graph to normalized JSON format."""
        nodes = self.db.list_asset_nodes(project_id)
        edges = self.db.list_asset_edges(project_id)

        payload = {
            "project_id": project_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type,
                    "value": n.value,
                    "label": n.label,
                    "source_tool": n.source_tool,
                    "confidence": n.confidence,
                }
                for n in nodes
            ],
            "edges": [
                {
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "relation": e.relation_type,
                    "source_tool": e.source_tool,
                }
                for e in edges
            ],
        }
        return json.dumps(payload, indent=2)

    # -------------------------------------------------------------
    # 2. Untrusted Import & Scope Sanitization
    # -------------------------------------------------------------
    def import_csv(
        self,
        project_id: int,
        csv_content: str,
        scopes: Optional[List[TargetScope]] = None,
    ) -> GraphImportResult:
        """Imports entities from Maltego-compatible CSV, validating targets against project scope."""
        result = GraphImportResult()
        reader = csv.reader(io.StringIO(csv_content))
        header = None

        for row in reader:
            if not row or not any(row):
                continue

            if header is None:
                header = [c.strip().lower() for c in row]
                continue

            result.total_parsed += 1
            type_val = row[0].strip() if len(row) > 0 else ""
            val = row[1].strip() if len(row) > 1 else ""
            label = row[2].strip() if len(row) > 2 else val
            source = row[3].strip() if len(row) > 3 else "maltego_csv"

            if not val:
                continue

            # Normalize type
            internal_type = REVERSE_MALTEGO_MAP.get(type_val.lower(), "domain" if "." in val else "ip")

            # Scope Validation
            if scopes is not None:
                scope_check = ScopeAuthorizationService.is_target_authorized(val, scopes)
                if not scope_check.is_allowed:
                    result.quarantined_nodes.append({
                        "node_type": internal_type,
                        "value": val,
                        "reason": scope_check.reason,
                    })
                    continue

            node = AssetNode(
                project_id=project_id,
                node_type=internal_type,
                value=val,
                label=label or val,
                source_tool=source,
                confidence=1.0,
            )
            saved = self.db.upsert_asset_node(node)
            result.imported_nodes.append(saved)

        return result

