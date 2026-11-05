"""Comprehensive Unit and Integration Tests for the OSINT Intelligence Workspace.

Tests:
1. OSINTCase and Observation database persistence and retrieval.
2. Scope enforcement at execution boundary for OSINT adapters.
3. Passive Certificate Transparency discovery and subdomain mapping.
4. Quarantining of out-of-scope discoveries.
5. Maltego Graph interoperability (CSV, GraphML, JSON).
6. Promoting discovered assets to TargetScope.
7. OSINTView PySide6 widget initialization, tab navigation, and UI callbacks.
"""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from core.scope import ScopeAuthorizationService
from desktop.views.osint_view import OSINTView
from modules.osint.amass_osint_adapter import AmassOSINTAdapter
from modules.osint.cert_transparency_adapter import CertTransparencyAdapter
from modules.osint.maltego_graph import MaltegoGraphEngine
from modules.osint.recon_ng_adapter import ReconNgAdapter
from modules.osint.theharvester_adapter import TheHarvesterAdapter
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    OSINTCase,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def test_db(tmp_path: Path):
    return Database(str(tmp_path / "osint_test.db"))


@pytest.fixture
def authorized_project(test_db: Database):
    proj = test_db.create_project(
        Project(
            name="MegaCorp OSINT Engagement",
            client_name="MegaCorp International",
            status=ProjectStatus.ACTIVE,
            allow_active_recon=False,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="megacorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="*.megacorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="unauthorized.megacorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )
    return proj


def test_osint_case_and_observation_db_lifecycle(test_db: Database, authorized_project: Project):
    """Verifies that OSINT cases and observations persist correctly and independently of findings."""
    case = OSINTCase(
        project_id=authorized_project.id,
        title="Perimeter OSINT Investigation",
        target_domain="megacorp.com",
        objective="Find all internet-exposed domains and certificates",
        authorization_reference="AUTH-2026-MC",
        analyst_notes="Initial passive survey phase.",
    )
    created_case = test_db.create_osint_case(case)
    assert created_case.id is not None

    cases = test_db.list_osint_cases(authorized_project.id)
    assert len(cases) == 1
    assert cases[0].title == "Perimeter OSINT Investigation"

    # Add Observation
    obs = Observation(
        project_id=authorized_project.id,
        case_id=created_case.id,
        source_tool="cert_transparency",
        method="passive_san",
        title="Observed SAN: portal.megacorp.com",
        raw_data="DNS:portal.megacorp.com, Issuer: Let's Encrypt",
        confidence=0.98,
        verification_status="verified",
    )
    created_obs = test_db.create_observation(obs)
    assert created_obs.id is not None

    obs_list = test_db.list_observations(authorized_project.id)
    assert len(obs_list) == 1
    assert obs_list[0].title == "Observed SAN: portal.megacorp.com"

    # Ensure observations are not stored as findings
    findings = test_db.list_findings(authorized_project.id)
    assert len(findings) == 0


def test_cert_transparency_adapter_passive_and_quarantine(test_db: Database, authorized_project: Project):
    """Verifies CT adapter records in-scope assets and quarantines excluded targets."""
    adapter = CertTransparencyAdapter(db=test_db)
    scopes = test_db.list_scopes(authorized_project.id)

    # Mock TLS socket response to return 2 subdomains (one allowed, one excluded)
    with patch("socket.create_connection"), patch("ssl.create_default_context") as mock_ctx:
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subjectAltName": [
                ("DNS", "portal.megacorp.com"),
                ("DNS", "unauthorized.megacorp.com"),  # Excluded by scope
                ("DNS", "external-partner.com"),        # Out of scope
            ]
        }
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        res = adapter.run_discovery(
            target_domain="megacorp.com",
            project=authorized_project,
            scopes=scopes,
            passive_only=True,
        )

        assert res.status == "completed"
        # megacorp.com and portal.megacorp.com are allowed
        node_vals = [n.value for n in res.discovered_assets]
        assert "megacorp.com" in node_vals
        assert "portal.megacorp.com" in node_vals

        # unauthorized.megacorp.com and external-partner.com should be quarantined
        quarantine_names = [q["name"] for q in res.quarantined_assets]
        assert "unauthorized.megacorp.com" in quarantine_names
        assert "external-partner.com" in quarantine_names


def test_adapter_availability_and_scope_boundary_gating(test_db: Database, authorized_project: Project):
    """Verifies that out-of-scope root targets are immediately blocked before execution."""
    adapter = CertTransparencyAdapter(db=test_db)
    scopes = test_db.list_scopes(authorized_project.id)

    res = adapter.run_discovery(
        target_domain="completely-unauthorized-target.org",
        project=authorized_project,
        scopes=scopes,
    )
    assert res.status == "scope_rejected"
    assert "out of scope" in res.error_message.lower()

    # Test optional adapter availability checks
    harvester = TheHarvesterAdapter(db=test_db)
    recon = ReconNgAdapter(db=test_db)
    assert harvester.requires_api_key is True
    assert recon.requires_api_key is True


def test_maltego_export_and_untrusted_import(test_db: Database, authorized_project: Project):
    """Verifies Maltego CSV/GraphML exports and untrusted CSV imports with scope re-validation."""
    engine = MaltegoGraphEngine(db=test_db)

    # Insert test node
    n = AssetNode(
        project_id=authorized_project.id,
        node_type="domain",
        value="megacorp.com",
        label="megacorp.com",
        source_tool="unit_test",
    )
    test_db.upsert_asset_node(n)

    csv_data = engine.export_csv(authorized_project.id)
    assert "maltego.Domain" in csv_data
    assert "megacorp.com" in csv_data

    graphml_data = engine.export_graphml(authorized_project.id)
    assert "<graphml" in graphml_data
    assert "megacorp.com" in graphml_data

    json_data = engine.export_json(authorized_project.id)
    parsed = json.loads(json_data)
    assert len(parsed["nodes"]) == 1

    # Test untrusted CSV import
    untrusted_csv = (
        "Entity Type,Value,Label,Source Tool\n"
        "maltego.DNSName,api.megacorp.com,API,import\n"
        "maltego.Domain,unauthorized.megacorp.com,Blocked,import\n"
    )
    scopes = test_db.list_scopes(authorized_project.id)
    import_res = engine.import_csv(authorized_project.id, untrusted_csv, scopes=scopes)
    assert len(import_res.imported_nodes) == 1
    assert import_res.imported_nodes[0].value == "api.megacorp.com"
    assert len(import_res.quarantined_nodes) == 1
    assert import_res.quarantined_nodes[0]["value"] == "unauthorized.megacorp.com"


def test_osint_view_ui_components(qtbot, test_db: Database, authorized_project: Project, monkeypatch):
    """Verifies that OSINTView loads, switches tabs, creates cases, and updates asset inventory."""
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    view = OSINTView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    view.set_active_project(authorized_project)
    assert "MegaCorp OSINT Engagement" in view.lbl_project_status.text()
    assert view.tabs.count() == 6

    # Create Case via UI
    view.txt_case_title.setText("Web Footprint Analysis")
    view.txt_case_domain.setText("megacorp.com")
    view.txt_case_auth.setText("AUTH-MC-1")
    view.txt_case_notes.setText("Active intelligence gathering.")
    view._on_create_case()

    assert view.cases_table.rowCount() == 1
    assert view.cases_table.item(0, 1).text() == "Web Footprint Analysis"

    # Add mock node and verify inventory table
    node = AssetNode(
        project_id=authorized_project.id,
        node_type="subdomain",
        value="login.megacorp.com",
        label="login.megacorp.com",
        source_tool="amass",
    )
    test_db.upsert_asset_node(node)
    view.load_assets()
    assert view.assets_table.rowCount() == 1
    assert "login.megacorp.com" in view.assets_table.item(0, 2).text()

    # Promote to Scope
    view.assets_table.selectRow(0)
    view._on_promote_to_scope()
    scopes = test_db.list_scopes(authorized_project.id)
    assert any(s.target == "login.megacorp.com" for s in scopes)

