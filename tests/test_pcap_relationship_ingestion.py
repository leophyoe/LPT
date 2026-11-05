"""Tests for Phase 3: Selective PCAP Relationship Ingestion.

Validates:
1. Admission of eligible Nmap-confirmed service flows.
2. Rejection of unselected ordinary flows.
3. Admission of supported security-anomaly flows.
4. Out-of-scope endpoint rejection.
5. Distinct destination ports generating distinct relationships.
6. Repeated imports preserving original created_at and historical Evidence/Observation references.
7. last_seen and metadata updates.
8. Legacy records and missing optional metadata.
9. Failure handling and transaction integrity.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
import pytest

from core.activity_logger import ActivityLogger
from core.asset_inventory import (
    AssetInventoryService,
    DiscoveredHostObservation,
    DiscoveredPortObservation,
)
from core.scope import ScopeAuthorizationService
from modules.network.pcap_analyzer import (
    DNSQueryRecord,
    HTTPTransaction,
    PCAPAnalysisResult,
    TLSSession,
)
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Evidence,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    _utc_now_iso,
)


@pytest.fixture
def isolated_db(tmp_path: Path) -> Database:
    """Creates a temporary isolated SQLite database for testing."""
    db_file = tmp_path / "test_pcap_ingest.db"
    return Database(db_file)


@pytest.fixture
def project_with_nmap_inventory(isolated_db: Database) -> Project:
    """Sets up an authorized project with existing Nmap host & open port inventory."""
    proj = isolated_db.create_project(
        Project(name="Test Engagement", client_name="Acme Corp", status=ProjectStatus.ACTIVE)
    )
    # Authorized CIDR: 192.168.1.0/24
    isolated_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    # Excluded IP: 192.168.1.99
    isolated_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.99",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )

    # Add Nmap-discovered target with open ports: 80, 443, 53
    inventory = AssetInventoryService(isolated_db)
    inventory.sync_host_observations(
        project_id=proj.id,
        observations=[
            DiscoveredHostObservation(
                ip="192.168.1.50",
                hostname="web-server.local",
                status="up",
                confidence=1.0,
                discovery_source="nmap",
                ports=[
                    DiscoveredPortObservation(port=80, protocol="tcp", state="open", service_name="http"),
                    DiscoveredPortObservation(port=443, protocol="tcp", state="open", service_name="https"),
                    DiscoveredPortObservation(port=53, protocol="udp", state="open", service_name="domain"),
                ],
            ),
            DiscoveredHostObservation(
                ip="192.168.1.10",
                hostname="workstation.local",
                status="up",
                confidence=1.0,
                discovery_source="nmap",
                ports=[],
            ),
        ],
    )
    return proj


def test_admission_of_nmap_confirmed_service_flow(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 1: Ordinary service flow targeting Nmap-confirmed open port is admitted as observed relationship."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Ordinary HTTP flow to 192.168.1.50:80 (verified open by Nmap)
    pcap_res = PCAPAnalysisResult(
        source_file="sample.pcap",
        total_packets=10,
        ip_packets=10,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=80,
                method="GET",
                uri="/index.html",
                host="web-server.local",
                attack_tags=[],  # No anomaly: ordinary traffic
            )
        ],
    )

    edges, observations = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admit_ordinary_flows=False,  # default: only admit if Nmap-confirmed open
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge.relation_type == "COMMUNICATES_WITH:tcp/80"
    assert edge.verification_state == "observed"
    assert edge.confidence >= 0.85

    meta = json.loads(edge.metadata_json)
    assert meta["nmap_confirmed"] is True
    assert meta["is_anomaly"] is False
    assert meta["destination_port"] == 80

    assert len(observations) == 1
    assert "COMMUNICATES_WITH" in edge.relation_type or "COMMUNICATES_WITH:tcp/80" == edge.relation_type


def test_rejection_of_unselected_ordinary_flow(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 2: Ordinary flow targeting a port NOT verified open by Nmap is rejected when admit_ordinary_flows=False."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Ordinary flow to 192.168.1.50 on port 8080 (NOT open in Nmap inventory)
    pcap_res = PCAPAnalysisResult(
        source_file="sample.pcap",
        total_packets=5,
        ip_packets=5,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=8080,
                method="GET",
                uri="/admin",
                host="web-server.local",
                attack_tags=[],
            )
        ],
    )

    edges, observations = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admit_ordinary_flows=False,
    )

    assert len(edges) == 0
    assert len(observations) == 0


def test_admission_of_explicitly_configured_service_ports(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 2b: Ordinary flow targeting an explicitly configured port is admitted even if not in Nmap."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Ordinary flow to port 8080
    pcap_res = PCAPAnalysisResult(
        source_file="sample.pcap",
        total_packets=5,
        ip_packets=5,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=8080,
                method="GET",
                uri="/api",
                host="web-server.local",
                attack_tags=[],
            )
        ],
    )

    # Admit via explicit port tuple
    edges, _ = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admitted_service_ports={("tcp", 8080)},
    )

    assert len(edges) == 1
    assert edges[0].relation_type == "COMMUNICATES_WITH:tcp/8080"


def test_admission_of_supported_security_anomaly_flow(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 3: Security-anomaly flows (e.g. SQLi or DNS Tunneling) are admitted even on unverified ports."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # HTTP flow with SQL Injection attack payload targeting unverified port 8080
    pcap_res = PCAPAnalysisResult(
        source_file="attack.pcap",
        total_packets=5,
        ip_packets=5,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=8080,
                method="POST",
                uri="/login",
                host="web-server.local",
                attack_tags=["SQL Injection (CWE-89)"],
            )
        ],
        dns_queries=[
            DNSQueryRecord(
                timestamp=1700000001.0,
                client_ip="192.168.1.10",
                server_ip="192.168.1.50",
                query_name="aGVsbG8td29ybGQ.exfil.domain.com",
                query_type="TXT",
                is_suspicious_tunnel=True,
            )
        ],
    )

    edges, observations = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admit_ordinary_flows=False,
    )

    assert len(edges) == 2
    relation_types = {e.relation_type for e in edges}
    assert "COMMUNICATES_WITH:tcp/8080" in relation_types
    assert "COMMUNICATES_WITH:udp/53" in relation_types

    for e in edges:
        meta = json.loads(e.metadata_json)
        assert meta["is_anomaly"] is True
        assert len(meta["attack_tags"]) > 0


def test_out_of_scope_and_excluded_endpoint_rejection(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 4: Flows to/from out-of-scope or explicitly excluded endpoints are rejected and logged."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Flow from authorized IP to excluded IP 192.168.1.99
    pcap_res = PCAPAnalysisResult(
        source_file="sample.pcap",
        total_packets=5,
        ip_packets=5,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.99",  # Excluded!
                dst_port=80,
                method="GET",
                uri="/",
                host="excluded.local",
                attack_tags=[],
            ),
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="10.99.99.99",  # Completely out of 192.168.1.0/24 scope!
                dst_ip="192.168.1.50",
                dst_port=80,
                method="GET",
                uri="/",
                host="web-server.local",
                attack_tags=[],
            ),
        ],
    )

    edges, _ = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admit_ordinary_flows=True,
    )

    assert len(edges) == 0

    # Verify audit log recorded exclusion
    audit_logger = ActivityLogger(isolated_db)
    logs = audit_logger.list_logs(proj.id)
    scope_exclusions = [log for log in logs if log.action == "pcap_scope_exclusion"]
    assert len(scope_exclusions) >= 2


def test_distinct_destination_ports_generate_distinct_relationships(
    isolated_db: Database, project_with_nmap_inventory: Project
):
    """Test 5: Distinct destination ports create distinct relationships satisfying UNIQUE constraint."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Flows to both port 80 and port 443 (both verified open by Nmap)
    pcap_res = PCAPAnalysisResult(
        source_file="sample.pcap",
        total_packets=10,
        ip_packets=10,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=80,
                method="GET",
                uri="/",
                host="web-server.local",
            )
        ],
        tls_sessions=[
            TLSSession(
                timestamp=1700000001.0,
                client_ip="192.168.1.10",
                server_ip="192.168.1.50",
                server_port=443,
                sni="web-server.local",
                tls_version_str="TLSv1.3",
            )
        ],
    )

    edges, _ = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        admit_ordinary_flows=False,
    )

    assert len(edges) == 2
    types = {e.relation_type for e in edges}
    assert "COMMUNICATES_WITH:tcp/80" in types
    assert "COMMUNICATES_WITH:tcp/443" in types

    comm_edges = [e for e in isolated_db.list_asset_edges(proj.id) if e.relation_type.startswith("COMMUNICATES_WITH")]
    assert len(comm_edges) == 2


def test_repeated_imports_preserve_created_at_and_evidence_ids(
    isolated_db: Database, project_with_nmap_inventory: Project
):
    """Test 6 & 7: Repeated imports update last_seen, merge metadata, and preserve original created_at & evidence_ids."""
    proj = project_with_nmap_inventory
    inventory = AssetInventoryService(isolated_db)

    # Evidence 1
    ev1 = isolated_db.add_evidence(
        Evidence(project_id=proj.id, file_path="/tmp/capture1.pcap", file_hash="sha256_11111")
    )
    # Evidence 2
    ev2 = isolated_db.add_evidence(
        Evidence(project_id=proj.id, file_path="/tmp/capture2.pcap", file_hash="sha256_22222")
    )

    pcap_res = PCAPAnalysisResult(
        source_file="capture1.pcap",
        total_packets=5,
        ip_packets=5,
        http_transactions=[
            HTTPTransaction(
                timestamp=1700000000.0,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                dst_port=80,
                method="GET",
                uri="/",
                host="web-server.local",
            )
        ],
    )

    # First import
    edges1, obs1 = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        evidence_id=ev1.id,
    )
    assert len(edges1) == 1
    original_edge = edges1[0]
    orig_created_at = original_edge.created_at

    # Second import with new evidence_id
    edges2, obs2 = inventory.sync_pcap_relationships(
        project_id=proj.id,
        pcap_result=pcap_res,
        evidence_id=ev2.id,
    )
    assert len(edges2) == 1
    updated_edge = edges2[0]

    # Verify ID and created_at preserved
    assert updated_edge.id == original_edge.id
    assert updated_edge.created_at == orig_created_at
    assert updated_edge.evidence_id == ev2.id

    # Verify both evidence IDs aggregated in metadata
    meta = json.loads(updated_edge.metadata_json)
    assert ev1.id in meta["evidence_ids"]
    assert ev2.id in meta["evidence_ids"]

    # Verify historical observations preserved
    flow_obs = [o for o in isolated_db.list_observations(proj.id) if o.method == "pcap_flow_dissection"]
    assert len(flow_obs) == 2


def test_legacy_records_and_missing_optional_metadata(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 8: Database handles legacy records with null/missing phase 2 columns seamlessly."""
    proj = project_with_nmap_inventory

    # Get existing node IDs from project setup
    nodes = isolated_db.list_asset_nodes(proj.id)
    n1_id, n2_id = nodes[0].id, nodes[1].id

    # Insert a raw edge directly without new fields
    with isolated_db.session() as conn:
        conn.execute(
            """
            INSERT INTO asset_edges (project_id, source_node_id, target_node_id, relation_type, source_tool, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (proj.id, n1_id, n2_id, "RESOLVES_TO", "manual", _utc_now_iso()),
        )

    edges = isolated_db.list_asset_edges(proj.id)
    legacy_edge = next(e for e in edges if e.relation_type == "RESOLVES_TO")
    assert legacy_edge.verification_state == "observed"
    assert legacy_edge.confidence == 1.0
    assert legacy_edge.metadata_json == "{}"


def test_transaction_integrity_on_error(isolated_db: Database, project_with_nmap_inventory: Project):
    """Test 9: Invalid operations fail cleanly without corrupting the database."""
    proj = project_with_nmap_inventory

    # Attempt to insert an edge referencing non-existent nodes in strict mode or with invalid values
    with pytest.raises(Exception):
        with isolated_db.session() as conn:
            conn.execute("INSERT INTO asset_edges (project_id) VALUES (?)", (proj.id,))

    # Database still healthy and intact
    edges = isolated_db.list_asset_edges(proj.id)
    assert isinstance(edges, list)
