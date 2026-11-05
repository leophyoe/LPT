"""Unit and integration tests for OWASP Amass Adapter & Parser.

Tests:
1. AmassParser JSON-lines streaming parsing.
2. AmassParser plain text parsing fallback.
3. Scope quarantine for out-of-scope discoveries.
4. Asset graph node & edge mapping.
5. AmassAdapter command generation (passive-by-default vs active).
6. Scope guard and RoE gating before execution.
7. End-to-end mocked execution with evidence vaulting and SQLite persistence.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from core.registry import ToolMetadata, ToolRegistry
from modules.network.amass_adapter import AmassAdapter, AmassOptions
from modules.network.amass_parser import AmassParser, AmassResult
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def mock_registry():
    amass_tool = ToolMetadata(
        name="amass",
        display_name="OWASP Amass OSINT & Asset Mapping",
        binary_name="amass",
        category="network",
        fallback_source_path="bin/amass",
        is_installed=True,
        binary_path="bin/amass",
    )
    reg = ToolRegistry(tools=[amass_tool])
    return reg


SAMPLE_AMASS_JSON = """
{"name": "example.com", "domain": "example.com", "addresses": [{"ip": "93.184.216.34", "cidr": "93.184.216.0/24", "asn": 15133, "desc": "EDGECAST"}], "tag": "dns", "sources": ["DNS", "CertSpotter"]}
{"name": "api.example.com", "domain": "example.com", "addresses": [{"ip": "93.184.216.35", "cidr": "93.184.216.0/24", "asn": 15133, "desc": "EDGECAST"}], "tag": "cert", "sources": ["crtsh"]}
{"name": "unauthorized.partner.com", "domain": "partner.com", "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 9999, "desc": "OTHER"}], "tag": "dns", "sources": ["DNS"]}
"""

SAMPLE_AMASS_TEXT = """
[DNS]   example.com                  93.184.216.34
[Cert]  admin.example.com            93.184.216.40
"""


# ---------------------------------------------------------------------------
# 1. AmassParser Tests
# ---------------------------------------------------------------------------

def test_amass_parser_json_lines_with_scope_quarantine():
    scopes = [
        TargetScope(
            project_id=1,
            target="*.example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
    ]

    res = AmassParser.parse_json_lines(SAMPLE_AMASS_JSON, scopes=scopes)
    assert len(res.records) == 2
    assert len(res.quarantined) == 1
    assert res.quarantined[0].name == "unauthorized.partner.com"
    assert "NOT in the authorized scope list" in res.quarantined[0].quarantine_reason

    # Validate parsed record fields
    rec = next(r for r in res.records if r.name == "api.example.com")
    assert rec.domain == "example.com"
    assert len(rec.addresses) == 1
    assert rec.addresses[0].ip == "93.184.216.35"
    assert rec.addresses[0].asn == 15133


def test_amass_parser_text():
    res = AmassParser.parse_text(SAMPLE_AMASS_TEXT)
    assert len(res.records) >= 2
    names = [r.name for r in res.records]
    assert "example.com" in names
    assert "admin.example.com" in names


def test_amass_parser_graph_conversion():
    res = AmassParser.parse_json_lines(SAMPLE_AMASS_JSON, scopes=None)
    nodes, edges = AmassParser.to_asset_graph(res, project_id=1)

    node_values = [n.value for n in nodes]
    assert "example.com" in node_values
    assert "api.example.com" in node_values
    assert "93.184.216.34" in node_values
    assert "15133" in node_values

    # Check relationships
    edge_types = [e.relation_type for e in edges]
    assert "SUBDOMAIN_OF" in edge_types
    assert "RESOLVES_TO" in edge_types
    assert "BELONGS_TO_ASN" in edge_types


# ---------------------------------------------------------------------------
# 2. AmassAdapter Command Generation
# ---------------------------------------------------------------------------

def test_amass_adapter_build_command_passive_by_default(db, mock_registry):
    adapter = AmassAdapter(db=db, registry=mock_registry)
    opts = AmassOptions(target_domain="example.com", passive_only=True)
    cmd = adapter.build_command(opts, json_out_path="/tmp/amass.json")

    assert "enum" in cmd
    assert "-passive" in cmd
    assert "-active" not in cmd
    assert "-d" in cmd
    assert "example.com" in cmd
    assert "-json" in cmd
    assert "/tmp/amass.json" in cmd


def test_amass_adapter_build_command_active_recon(db, mock_registry):
    adapter = AmassAdapter(db=db, registry=mock_registry)
    opts = AmassOptions(target_domain="example.com", passive_only=False, active_recon=True)
    cmd = adapter.build_command(opts)

    assert "enum" in cmd
    assert "-active" in cmd
    assert "-brute" in cmd
    assert "-passive" not in cmd


# ---------------------------------------------------------------------------
# 3. Scope Guard & RoE Gating
# ---------------------------------------------------------------------------

def test_amass_adapter_rejects_out_of_scope_target(db, mock_registry):
    adapter = AmassAdapter(db=db, registry=mock_registry)
    project = db.create_project(Project(name="Amass Project", status=ProjectStatus.ACTIVE))
    scopes = [
        TargetScope(
            project_id=project.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    ]

    opts = AmassOptions(target_domain="forbidden-target.com")
    success, reason, findings, exec_rec, res = adapter.execute_scan(project, opts, scopes)

    assert not success
    assert "Target out of scope" in reason
    assert findings == []
    assert exec_rec is None


def test_amass_adapter_blocks_active_recon_when_prohibited_by_roe(db, mock_registry):
    adapter = AmassAdapter(db=db, registry=mock_registry)
    # Project with allow_active_recon = False
    project = db.create_project(
        Project(
            name="Passive-Only Engagement",
            status=ProjectStatus.ACTIVE,
            allow_active_recon=False,
        )
    )
    scopes = [
        TargetScope(
            project_id=project.id,
            target="example.com",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        )
    ]

    opts = AmassOptions(target_domain="example.com", active_recon=True, passive_only=False)
    success, reason, findings, exec_rec, res = adapter.execute_scan(project, opts, scopes)

    assert not success
    assert "Active brute-force enumeration is prohibited" in reason


# ---------------------------------------------------------------------------
# 4. End-to-End Execution with Evidence Vaulting (Mocked ProcessRunner)
# ---------------------------------------------------------------------------

def test_amass_adapter_successful_execution_and_persistence(db, mock_registry, tmp_path):
    adapter = AmassAdapter(db=db, registry=mock_registry)
    project = db.create_project(Project(name="Amass Active Test", status=ProjectStatus.ACTIVE))
    p_id = project.id
    scopes = [
        TargetScope(
            project_id=p_id,
            target="example.com",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
        TargetScope(
            project_id=p_id,
            target="*.example.com",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
    ]

    # Mock process execution
    mock_proc = ProcessExecutionResult(
        command=["amass", "enum", "-passive", "-d", "example.com"],
        exit_code=0,
        status=ExecutionStatus.COMPLETED,
        stdout="[DNS] example.com 93.184.216.34\n",
        stderr="",
        started_at="2026-10-22T10:00:00Z",
        finished_at="2026-10-22T10:00:05Z",
        duration_seconds=5.0,
    )

    def fake_run(command, timeout, on_output):
        # Write mock json to the json output path if present
        for i, arg in enumerate(command):
            if arg == "-json" and i + 1 < len(command):
                Path(command[i + 1]).write_text(SAMPLE_AMASS_JSON, encoding="utf-8")
        return mock_proc

    adapter.runner.run = MagicMock(side_effect=fake_run)

    opts = AmassOptions(target_domain="example.com", passive_only=True)
    evidence_dir = tmp_path / "evidence_vault"
    logs = []

    success, msg, findings, exec_rec, amass_res = adapter.execute_scan(
        project=project,
        options=opts,
        scopes=scopes,
        on_output=lambda line, stream: logs.append((line, stream)),
        evidence_dir=evidence_dir,
    )

    assert success
    assert "2 assets discovered" in msg
    assert exec_rec is not None
    assert exec_rec.status == ExecutionStatus.COMPLETED

    # Check evidence file and SHA-256 hash in SQLite
    evidences = db.list_evidence(p_id)
    assert len(evidences) == 1
    assert evidences[0].sha256_hash != ""
    assert Path(evidences[0].file_path).exists()

    # Check findings created in SQLite
    db_findings = db.list_findings(p_id)
    assert len(db_findings) >= 1

    # Check AssetNodes & AssetEdges in SQLite
    nodes = db.list_asset_nodes(p_id)
    assert len(nodes) >= 3
    edges = db.list_asset_edges(p_id)
    assert len(edges) >= 2
