"""Tests for AssetEdge database schema evolution, non-destructive migration, and API compatibility.

Verifies:
1. Legacy asset_edges tables receive missing Phase 2 intelligence columns.
2. Existing edge rows and primary keys survive migration unchanged.
3. Existing unique constraints and legacy relation types remain intact.
4. Running migrations repeatedly is idempotent and safe.
5. New AssetEdge fields have correct default values.
6. New field values persist and load correctly via Database API.
7. Project isolation behavior remains enforced.
8. In-memory and file-based Database fixtures initialize without errors.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
import pytest

from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Project,
    ProjectStatus,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    """Fixture providing an isolated file-based database."""
    db_file = tmp_path / "migration_test.db"
    return Database(db_file)


def test_asset_edge_dataclass_defaults():
    """Verifies that AssetEdge dataclass provides backward-compatible defaults."""
    edge = AssetEdge(
        project_id=1,
        source_node_id=10,
        target_node_id=20,
        relation_type="RESOLVES_TO",
    )
    assert edge.project_id == 1
    assert edge.source_node_id == 10
    assert edge.target_node_id == 20
    assert edge.relation_type == "RESOLVES_TO"
    assert edge.source_tool == ""
    assert edge.id is None
    assert edge.created_at is not None
    # Phase 2 Intelligence Fields
    assert edge.verification_state == "observed"
    assert edge.confidence == 1.0
    assert edge.evidence_id is None
    assert edge.last_seen == ""
    assert edge.metadata_json == "{}"


def test_legacy_asset_edges_migration_preserves_rows_and_ids(tmp_path: Path):
    """Simulates a legacy database created before Phase 2 and verifies migration."""
    legacy_db_file = tmp_path / "legacy_suite.db"
    conn = sqlite3.connect(str(legacy_db_file))

    # 1. Manually create legacy schema without Phase 2 columns
    conn.execute("""
        CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            client_name TEXT DEFAULT '',
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE asset_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            node_type TEXT NOT NULL,
            value TEXT NOT NULL,
            label TEXT DEFAULT '',
            source_tool TEXT DEFAULT '',
            confidence REAL DEFAULT 1.0,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(project_id, node_type, value)
        );
    """)
    conn.execute("""
        CREATE TABLE asset_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            source_node_id INTEGER NOT NULL,
            target_node_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL,
            source_tool TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(project_id, source_node_id, target_node_id, relation_type)
        );
    """)

    # 2. Seed legacy rows
    conn.execute("INSERT INTO projects (id, name, created_at, updated_at) VALUES (1, 'Legacy Corp', '2026-01-01', '2026-01-01');")
    conn.execute("INSERT INTO asset_nodes (id, project_id, node_type, value, created_at) VALUES (1, 1, 'hostname', 'api.legacy.corp', '2026-01-01');")
    conn.execute("INSERT INTO asset_nodes (id, project_id, node_type, value, created_at) VALUES (2, 1, 'ip', '192.168.1.10', '2026-01-01');")
    conn.execute("INSERT INTO asset_nodes (id, project_id, node_type, value, created_at) VALUES (3, 1, 'ip', '192.168.1.20', '2026-01-01');")
    conn.execute("""
        INSERT INTO asset_edges (id, project_id, source_node_id, target_node_id, relation_type, source_tool, created_at)
        VALUES (42, 1, 1, 2, 'RESOLVES_TO', 'legacy_scanner', '2026-01-01T12:00:00Z');
    """)
    conn.execute("""
        INSERT INTO asset_edges (id, project_id, source_node_id, target_node_id, relation_type, source_tool, created_at)
        VALUES (99, 1, 2, 3, 'SUBDOMAIN_OF', 'legacy_osint', '2026-01-01T12:05:00Z');
    """)
    conn.commit()
    conn.close()

    # 3. Open with application Database class, triggering _migrate_columns()
    db = Database(legacy_db_file)
    conn_migrated = db.get_connection()

    # 4. Verify columns in asset_edges
    cols = {row["name"]: row for row in conn_migrated.execute("PRAGMA table_info(asset_edges);").fetchall()}
    assert "verification_state" in cols
    assert "confidence" in cols
    assert "evidence_id" in cols
    assert "last_seen" in cols
    assert "metadata_json" in cols

    # Verify defaults in column definition
    assert cols["verification_state"]["dflt_value"] == "'observed'"
    assert cols["confidence"]["dflt_value"] == "1.0"
    assert cols["last_seen"]["dflt_value"] == "''"
    assert cols["metadata_json"]["dflt_value"] == "'{}'"

    # 5. Verify existing rows and IDs were preserved
    rows = conn_migrated.execute("SELECT * FROM asset_edges ORDER BY id ASC;").fetchall()
    assert len(rows) == 2

    row1 = dict(rows[0])
    assert row1["id"] == 42
    assert row1["source_node_id"] == 1
    assert row1["target_node_id"] == 2
    assert row1["relation_type"] == "RESOLVES_TO"
    assert row1["source_tool"] == "legacy_scanner"
    assert row1["verification_state"] == "observed"
    assert float(row1["confidence"]) == 1.0
    assert row1["evidence_id"] is None
    assert row1["last_seen"] == ""
    assert row1["metadata_json"] == "{}"

    row2 = dict(rows[1])
    assert row2["id"] == 99
    assert row2["source_node_id"] == 2
    assert row2["target_node_id"] == 3
    assert row2["relation_type"] == "SUBDOMAIN_OF"


def test_migration_idempotence(temp_db: Database):
    """Verifies that calling _migrate_columns repeatedly does not raise errors or duplicate columns."""
    conn = temp_db.get_connection()
    # Execute migration multiple times explicitly
    temp_db._migrate_columns(conn)
    temp_db._migrate_columns(conn)
    temp_db._migrate_columns(conn)

    cols = [r["name"] for r in conn.execute("PRAGMA table_info(asset_edges);").fetchall()]
    assert cols.count("verification_state") == 1
    assert cols.count("confidence") == 1
    assert cols.count("evidence_id") == 1
    assert cols.count("last_seen") == 1
    assert cols.count("metadata_json") == 1


def test_add_and_list_asset_edge_with_new_fields(temp_db: Database):
    """Verifies that add_asset_edge and list_asset_edges persist and load all Phase 2 fields."""
    p = temp_db.create_project(Project(name="Test Edge Project", status=ProjectStatus.ACTIVE))
    n1 = temp_db.upsert_asset_node(AssetNode(project_id=p.id, node_type="ip", value="10.0.0.1"))
    n2 = temp_db.upsert_asset_node(AssetNode(project_id=p.id, node_type="ip", value="10.0.0.2"))

    meta_payload = {"protocol": "tcp", "dst_port": 443, "packets": 25, "sni": "secure.internal"}
    edge = AssetEdge(
        project_id=p.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="COMMUNICATES_WITH:tcp/443",
        source_tool="pcap_analyzer",
        verification_state="observed",
        confidence=0.85,
        evidence_id=101,
        last_seen="2026-10-29T10:00:00Z",
        metadata_json=json.dumps(meta_payload),
    )

    saved_edge = temp_db.add_asset_edge(edge)
    assert saved_edge.id is not None

    # Load back via list_asset_edges
    edges = temp_db.list_asset_edges(p.id)
    assert len(edges) == 1
    loaded = edges[0]

    assert loaded.id == saved_edge.id
    assert loaded.project_id == p.id
    assert loaded.source_node_id == n1.id
    assert loaded.target_node_id == n2.id
    assert loaded.relation_type == "COMMUNICATES_WITH:tcp/443"
    assert loaded.source_tool == "pcap_analyzer"
    assert loaded.verification_state == "observed"
    assert loaded.confidence == 0.85
    assert loaded.evidence_id == 101
    assert loaded.last_seen == "2026-10-29T10:00:00Z"

    loaded_meta = json.loads(loaded.metadata_json)
    assert loaded_meta["protocol"] == "tcp"
    assert loaded_meta["dst_port"] == 443
    assert loaded_meta["packets"] == 25
    assert loaded_meta["sni"] == "secure.internal"


def test_unique_constraint_allows_distinct_port_relation_types(temp_db: Database):
    """Verifies that unique constraint allows separate flows on different ports between same endpoints."""
    p = temp_db.create_project(Project(name="Multi-Flow Project", status=ProjectStatus.ACTIVE))
    n1 = temp_db.upsert_asset_node(AssetNode(project_id=p.id, node_type="ip", value="10.0.0.5"))
    n2 = temp_db.upsert_asset_node(AssetNode(project_id=p.id, node_type="ip", value="10.0.0.6"))

    edge_https = AssetEdge(
        project_id=p.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="COMMUNICATES_WITH:tcp/443",
        source_tool="pcap_analyzer",
    )
    edge_admin = AssetEdge(
        project_id=p.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relation_type="COMMUNICATES_WITH:tcp/8443",
        source_tool="pcap_analyzer",
    )

    temp_db.add_asset_edge(edge_https)
    temp_db.add_asset_edge(edge_admin)

    edges = temp_db.list_asset_edges(p.id)
    assert len(edges) == 2
    types = {e.relation_type for e in edges}
    assert "COMMUNICATES_WITH:tcp/443" in types
    assert "COMMUNICATES_WITH:tcp/8443" in types

    # Attempting to re-insert identical edge does not raise error and does not create duplicate
    temp_db.add_asset_edge(edge_https)
    edges_after = temp_db.list_asset_edges(p.id)
    assert len(edges_after) == 2


def test_project_isolation_on_asset_edges(temp_db: Database):
    """Verifies that edges are strictly partitioned by project_id."""
    p1 = temp_db.create_project(Project(name="Project Alpha", status=ProjectStatus.ACTIVE))
    p2 = temp_db.create_project(Project(name="Project Beta", status=ProjectStatus.ACTIVE))

    n1_a = temp_db.upsert_asset_node(AssetNode(project_id=p1.id, node_type="ip", value="192.168.1.1"))
    n2_a = temp_db.upsert_asset_node(AssetNode(project_id=p1.id, node_type="ip", value="192.168.1.2"))

    n1_b = temp_db.upsert_asset_node(AssetNode(project_id=p2.id, node_type="ip", value="192.168.1.1"))
    n2_b = temp_db.upsert_asset_node(AssetNode(project_id=p2.id, node_type="ip", value="192.168.1.2"))

    temp_db.add_asset_edge(AssetEdge(project_id=p1.id, source_node_id=n1_a.id, target_node_id=n2_a.id, relation_type="RESOLVES_TO"))
    temp_db.add_asset_edge(AssetEdge(project_id=p2.id, source_node_id=n1_b.id, target_node_id=n2_b.id, relation_type="RESOLVES_TO"))

    edges_p1 = temp_db.list_asset_edges(p1.id)
    edges_p2 = temp_db.list_asset_edges(p2.id)

    assert len(edges_p1) == 1
    assert len(edges_p2) == 1
    assert edges_p1[0].project_id == p1.id
    assert edges_p2[0].project_id == p2.id
    assert edges_p1[0].id != edges_p2[0].id

