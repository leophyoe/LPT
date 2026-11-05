"""Unit and integration tests for Maltego Graph interoperability.

Tests:
1. Maltego CSV export (entity type mapping, column structure).
2. GraphML XML export (standard GraphML schema with node/edge data).
3. JSON export format.
4. Untrusted CSV import with Scope Authorization Service re-validation.
5. Quarantine of out-of-scope targets from imported CSV.
6. Database node upsert and edge persistence.
"""

import xml.etree.ElementTree as ET

import pytest
from modules.osint.maltego_graph import MALTEGO_ENTITY_MAP, MaltegoGraphEngine
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def engine(db):
    return MaltegoGraphEngine(db=db)


@pytest.fixture
def populated_graph_project(db):
    project = db.create_project(Project(name="Maltego Test Project", status=ProjectStatus.ACTIVE))
    p_id = project.id

    # Add Scopes
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="*.example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )

    # Add Nodes
    n1 = db.upsert_asset_node(
        AssetNode(
            project_id=p_id,
            node_type="domain",
            value="example.com",
            label="example.com",
            source_tool="amass",
        )
    )
    n2 = db.upsert_asset_node(
        AssetNode(
            project_id=p_id,
            node_type="subdomain",
            value="api.example.com",
            label="api.example.com",
            source_tool="amass",
        )
    )
    n3 = db.upsert_asset_node(
        AssetNode(
            project_id=p_id,
            node_type="ip",
            value="93.184.216.34",
            label="93.184.216.34",
            source_tool="amass",
        )
    )

    # Add Edges
    db.add_asset_edge(
        AssetEdge(
            project_id=p_id,
            source_node_id=n2.id,
            target_node_id=n1.id,
            relation_type="SUBDOMAIN_OF",
            source_tool="amass",
        )
    )
    db.add_asset_edge(
        AssetEdge(
            project_id=p_id,
            source_node_id=n2.id,
            target_node_id=n3.id,
            relation_type="RESOLVES_TO",
            source_tool="amass",
        )
    )

    return p_id


# ---------------------------------------------------------------------------
# 1. Export Tests
# ---------------------------------------------------------------------------

def test_maltego_export_csv(engine, populated_graph_project):
    csv_str = engine.export_csv(populated_graph_project)
    lines = csv_str.strip().splitlines()

    # Check header
    assert lines[0] == "Entity Type,Value,Label,Source Tool,Confidence,Metadata"
    # Check rows contain mapped Maltego types
    assert any("maltego.Domain,example.com" in line for line in lines)
    assert any("maltego.DNSName,api.example.com" in line for line in lines)
    assert any("maltego.IPv4Address,93.184.216.34" in line for line in lines)


def test_maltego_export_graphml(engine, populated_graph_project):
    xml_str = engine.export_graphml(populated_graph_project)
    assert xml_str.startswith("<?xml")

    # Parse XML to verify valid GraphML
    root = ET.fromstring(xml_str)
    assert "graphml" in root.tag

    # Check namespaces and keys
    keys = root.findall("{http://graphml.graphdrawing.org/xmlns}key")
    assert len(keys) == 4

    graph = root.find("{http://graphml.graphdrawing.org/xmlns}graph")
    assert graph is not None

    nodes = graph.findall("{http://graphml.graphdrawing.org/xmlns}node")
    assert len(nodes) == 3

    edges = graph.findall("{http://graphml.graphdrawing.org/xmlns}edge")
    assert len(edges) == 2


def test_maltego_export_json(engine, populated_graph_project):
    import json
    json_str = engine.export_json(populated_graph_project)
    data = json.loads(json_str)

    assert data["project_id"] == populated_graph_project
    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 2
    assert any(n["value"] == "api.example.com" for n in data["nodes"])


# ---------------------------------------------------------------------------
# 2. Import & Scope Quarantine Tests
# ---------------------------------------------------------------------------

def test_maltego_import_csv_with_scope_validation(engine, db, populated_graph_project):
    p_id = populated_graph_project
    scopes = db.list_scopes(p_id)

    # CSV containing one in-scope item and one out-of-scope item
    incoming_csv = """Entity Type,Value,Label,Source Tool,Confidence,Metadata
maltego.DNSName,portal.example.com,portal.example.com,external_osint,1.0,{}
maltego.Domain,unauthorized-thirdparty.org,unauthorized-thirdparty.org,external_osint,1.0,{}
"""

    result = engine.import_csv(p_id, incoming_csv, scopes=scopes)

    assert result.total_parsed == 2
    # portal.example.com is in scope (*.example.com)
    assert len(result.imported_nodes) == 1
    assert result.imported_nodes[0].value == "portal.example.com"
    assert result.imported_nodes[0].node_type == "subdomain"

    # unauthorized-thirdparty.org must be quarantined
    assert len(result.quarantined_nodes) == 1
    assert result.quarantined_nodes[0]["value"] == "unauthorized-thirdparty.org"
    assert "NOT in the authorized scope list" in result.quarantined_nodes[0]["reason"]

    # Verify portal.example.com was persisted to DB
    persisted = db.list_asset_nodes(p_id)
    assert any(n.value == "portal.example.com" for n in persisted)
    assert not any(n.value == "unauthorized-thirdparty.org" for n in persisted)

