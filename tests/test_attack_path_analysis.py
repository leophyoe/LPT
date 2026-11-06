"""Regression and Integration Tests for Phase 5.3.1: Attack Path Analysis Integration (GAP-5.3-01).

Covers:
1. Attack Path signal connection to workspace handlers.
2. Real analysis workflow invocation via Analyse Attack Path button.
3. Active project context and boundary respect.
4. Informative empty state on insufficient data.
5. Safe handling of analysis errors.
6. Anti-hallucination verification (zero fabricated attack paths).
7. Target scope boundary verification (in-scope vs out-of-scope).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import QApplication, QFrame, QLabel

from core.ai_data_analyst import AIDataAnalystEngine, AttackPathChain
from core.parsers.normalized_models import NormalizedFinding
from desktop.dialogs.attack_path_dialog import (
    AttackPathAnalysisDialog,
    check_target_scope,
    extract_clean_host,
    parse_target_identity,
)
from desktop.views.visualization_workspace import VisualizationWorkspace
from desktop.widgets.network_map_view import NetworkHostNodeItem, NetworkMapView
from desktop.widgets.topology_designer import TopologyDesignerWidget
from modules.network.nmap_parser import HostResult, NmapScanResult, PortResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ValidationStatus,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    """Provides a fresh isolated SQLite database."""
    db_file = tmp_path / "test_attack_path.db"
    return Database(str(db_file))


@pytest.fixture
def sample_project(test_db: Database) -> Project:
    """Creates a sample project with authorized scope."""
    proj = test_db.create_project(
        Project(
            name="Alpha Assessment",
            client_name="Acme Corp",
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            is_authorized=True,
        )
    )
    return proj


def test_attack_path_signal_connection_and_emission(qtbot):
    """1. Verifies analyse_path_requested signal is emitted by NetworkMapView without mock popups."""
    view = NetworkMapView()
    qtbot.addWidget(view)

    # Mock host selection
    host = HostResult(ip="192.168.1.25", status="up")
    view._selected_host = host

    received_ips = []
    view.analyse_path_requested.connect(lambda ip: received_ips.append(ip))

    # Trigger action
    view._trigger_analyse_path()

    assert received_ips == ["192.168.1.25"]


def test_workspace_connects_analyse_path_requested_to_handler(qtbot, test_db, sample_project):
    """2. Verifies VisualizationWorkspace connects map_2d.analyse_path_requested to real dialog."""
    workspace = VisualizationWorkspace(test_db)
    qtbot.addWidget(workspace)
    workspace.set_active_project(sample_project)

    with patch.object(AttackPathAnalysisDialog, "exec", return_value=0) as mock_exec:
        workspace.map_2d.analyse_path_requested.emit("192.168.1.50")
        assert mock_exec.called
        assert hasattr(workspace, "_last_attack_path_dialog")
        assert workspace._last_attack_path_dialog.target_ip == "192.168.1.50"
        assert workspace._last_attack_path_dialog.project.id == sample_project.id


def test_topology_designer_connects_sentinel_analyse_path_requested(qtbot, test_db, sample_project):
    """3. Verifies TopologyDesignerWidget connects sentinel_view.analyse_path_requested."""
    designer = TopologyDesignerWidget(db=test_db)
    qtbot.addWidget(designer)
    designer.active_project = sample_project

    with patch.object(AttackPathAnalysisDialog, "exec", return_value=0) as mock_exec:
        designer.sentinel_view.analyse_path_requested.emit("192.168.1.99")
        assert mock_exec.called
        assert hasattr(designer, "_last_attack_path_dialog")
        assert designer._last_attack_path_dialog.target_ip == "192.168.1.99"


def test_clicking_analyse_attack_path_invokes_real_analysis(qtbot, test_db, sample_project):
    """4. Verifies clicking Analyse Attack Path executes AIDataAnalystEngine with real findings."""
    # Seed a real critical vulnerability on target
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection in user authentication parameter",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://192.168.1.50/login.php",
            description="Unsanitized POST parameter leads to database extraction.",
            source_tool="sqlmap",
            validation_status=ValidationStatus.CONFIRMED,
        )
    )

    workspace = VisualizationWorkspace(test_db)
    qtbot.addWidget(workspace)
    workspace.set_active_project(sample_project)

    host = HostResult(ip="192.168.1.50", status="up")
    scan = NmapScanResult(command_args="nmap -sV 192.168.1.50", hosts=[host])
    workspace.map_2d.load_scan(scan)
    workspace.map_2d._selected_host = host

    with patch.object(AttackPathAnalysisDialog, "exec", return_value=0) as mock_exec:
        workspace.map_2d.btn_analyse_path.click()
        assert mock_exec.called

        dlg = workspace._last_attack_path_dialog
        assert dlg is not None
        assert dlg.target_ip == "192.168.1.50"
        assert dlg.report is not None

        # Check real analysis report content
        assert len(dlg.report.attack_paths) >= 1
        sqli_chain = dlg.report.attack_paths[0]
        assert "SQL Injection" in sqli_chain.chain_name
        assert sqli_chain.likelihood == "HIGH"
        assert sqli_chain.impact == "CRITICAL"
        assert len(sqli_chain.supporting_citations) >= 1
        assert sqli_chain.supporting_citations[0].source_tool == "sqlmap"
        assert sqli_chain.supporting_citations[0].finding_title == "SQL Injection in user authentication parameter"


def test_active_project_context_is_respected(qtbot, test_db):
    """5. Verifies attack path analysis respects active project context and prevents cross-project leakage."""
    proj_a = test_db.create_project(Project(name="Project A"))
    proj_b = test_db.create_project(Project(name="Project B"))

    # Finding belongs only to Project B
    test_db.create_finding(
        Finding(
            project_id=proj_b.id,
            title="Remote Code Execution on Web Server",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.80",
            source_tool="nuclei",
        )
    )

    # Analyze target under Project A context
    dlg_a = AttackPathAnalysisDialog(
        target_ip="192.168.1.80",
        project=proj_a,
        db=test_db,
    )
    qtbot.addWidget(dlg_a)

    # Project A has 0 findings and must not display Project B's RCE chain
    assert len(dlg_a.target_findings) == 0
    assert len(dlg_a.report.attack_paths) == 0


def test_empty_data_produces_informative_empty_state(qtbot, test_db, sample_project):
    """6. Verifies targets with zero findings or exposures render a clean informative empty state."""
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.200",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 0
    assert len(dlg.report.attack_paths) == 0
    assert "No multi-stage attack chains identified" in dlg.lbl_summary.text()


def test_analysis_errors_handled_safely(qtbot, sample_project):
    """7. Verifies unexpected database or engine exceptions do not crash the UI and display error card."""
    broken_db = MagicMock()
    broken_db.list_scopes.side_effect = RuntimeError("Database connection corrupted")

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.10",
        project=sample_project,
        db=broken_db,
    )
    qtbot.addWidget(dlg)

    assert "Analysis Error" in dlg.lbl_summary.text()
    assert "Check the application log" in dlg.lbl_summary.text()
    assert "Database connection corrupted" not in dlg.lbl_summary.text()


def test_no_fabricated_attack_paths_on_benign_findings(qtbot, test_db, sample_project):
    """8. Verifies zero hallucinated attack paths when findings do not meet exploit prerequisites."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="OpenSSH Deprecated Cipher Suites",
            severity=FindingSeverity.LOW,
            affected_asset="192.168.1.30:22",
            source_tool="nmap",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.30",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    # Must NOT hallucinate SQLi or RCE attack paths
    assert not any("sql" in p.chain_name.lower() for p in dlg.report.attack_paths)
    assert not any("rce" in p.chain_name.lower() for p in dlg.report.attack_paths)


def test_target_scope_boundary_classification():
    """9. Verifies check_target_scope accurately distinguishes authorized vs out-of-scope targets."""
    scopes = [
        TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True),
        TargetScope(project_id=1, target="10.0.0.5", is_authorized=True),
        TargetScope(project_id=1, target="172.16.0.0/16", is_authorized=False),
    ]

    status, token = check_target_scope("192.168.1.55", scopes)
    assert "Authorized In-Scope" in status
    assert token == "CONFIRMED"

    status, token = check_target_scope("10.0.0.5", scopes)
    assert "Authorized In-Scope" in status
    assert token == "CONFIRMED"

    status, token = check_target_scope("172.16.1.1", scopes)
    assert "Out-of-Scope" in status
    assert token == "CRITICAL"

    status, token = check_target_scope("8.8.8.8", scopes)
    assert "Out-of-Scope" in status
    assert token == "CRITICAL"

    status, token = check_target_scope("192.168.1.1", [])
    assert "Scope Unassigned" in status
    assert token == "WARNING"


# ==============================================================================
# Phase 5.3.1.2 Scope Authorization Regression Tests (Tests 1-10)
# ==============================================================================

def test_scope_auth_authorized_ipv4():
    """1. Authorized IPv4 target."""
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True)]
    status, token = check_target_scope("192.168.1.55", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def test_scope_auth_authorized_cidr():
    """2. Authorized CIDR target."""
    scopes = [TargetScope(project_id=1, target="10.0.0.0/16", is_authorized=True)]
    status, token = check_target_scope("10.0.1.0/24", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def test_scope_auth_out_of_scope_ipv4():
    """3. Out-of-scope IPv4 target."""
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True)]
    status, token = check_target_scope("8.8.8.8", scopes)
    assert status == "Out-of-Scope / Quarantine Target"
    assert token == "CRITICAL"


def test_scope_auth_exact_authorized_domain():
    """4. Exact authorized domain."""
    scopes = [TargetScope(project_id=1, target="api.target.com", is_authorized=True)]
    status, token = check_target_scope("api.target.com", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def test_scope_auth_invalid_domain_substring():
    """5. Invalid domain substring must NOT be authorized."""
    scopes = [TargetScope(project_id=1, target="target.com", is_authorized=True)]
    status, token = check_target_scope("not-target.com", scopes)
    assert status == "Out-of-Scope / Quarantine Target"
    assert token == "CRITICAL"

    status2, token2 = check_target_scope("target.com.attacker.org", scopes)
    assert status2 == "Out-of-Scope / Quarantine Target"
    assert token2 == "CRITICAL"


def test_scope_auth_hostname_with_port():
    """6. Hostname with port authorized if hostname is in scope."""
    scopes = [TargetScope(project_id=1, target="api.target.com", is_authorized=True)]
    status, token = check_target_scope("api.target.com:8443", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def test_scope_auth_url_target():
    """7. URL target authorized by extracting host."""
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True)]
    status, token = check_target_scope("https://192.168.1.50:8080/login", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def test_scope_auth_missing_scope():
    """8. Missing scope fails closed to Scope Unassigned."""
    status, token = check_target_scope("192.168.1.50", [])
    assert status == "Scope Unassigned"
    assert token == "WARNING"


def test_scope_auth_malformed_target():
    """9. Malformed target fails closed."""
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True)]
    status, token = check_target_scope("malformed://%%%invalid", scopes)
    assert status == "Out-of-Scope / Quarantine Target"
    assert token == "CRITICAL"

    status_empty, token_empty = check_target_scope("", scopes)
    assert status_empty == "Out-of-Scope / Quarantine Target"
    assert token_empty == "CRITICAL"


def test_scope_auth_analysis_must_not_run_when_authorization_fails(qtbot, test_db, sample_project):
    """10. Analysis must not run when authorization fails (target findings 0, report empty, quarantine card rendered)."""
    # Create findings in DB for out-of-scope target
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Critical SQL Injection on Out-of-Scope Target",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.200.5.50",
            source_tool="sqlmap",
        )
    )

    # 10.200.5.50 is NOT in sample_project's 192.168.1.0/24 scope
    dlg = AttackPathAnalysisDialog(
        target_ip="10.200.5.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Must be blocked fail-closed
    assert "Quarantine" in dlg.lbl_scope_badge.text() or "Out-of-Scope" in dlg.lbl_scope_badge.text()
    assert "Blocked" in dlg.lbl_posture_badge.text()
    assert len(dlg.target_findings) == 0
    assert len(dlg.report.attack_paths) == 0
    # Must render quarantine card
    quarantine_card = dlg.findChild(QFrame, "quarantineCard")
    assert quarantine_card is not None


# ==============================================================================
# Phase 5.3.1.2 Exact Asset Matching Regression Tests (Tests 11-19)
# ==============================================================================

def test_exact_asset_matching_ipv4(qtbot, test_db, sample_project):
    """11. Exact IPv4 match."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Vulnerability on 192.168.1.50",
            severity=FindingSeverity.HIGH,
            affected_asset="192.168.1.50",
            source_tool="nmap",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    assert dlg.target_findings[0].affected_asset == "192.168.1.50"


def test_exact_asset_matching_ip_substring_collision_prevention(qtbot, test_db, sample_project):
    """12. IP substring collision prevention (192.168.1.5 must NOT match 192.168.1.50)."""
    # Seed finding specifically for 192.168.1.50
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQLi on Host 50",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )

    # Analyze 192.168.1.5
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.5",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # 192.168.1.5 must NOT correlate the finding from 192.168.1.50!
    assert len(dlg.target_findings) == 0
    assert len(dlg.report.attack_paths) == 0


def test_exact_asset_matching_hostname(qtbot, test_db):
    """13. Exact hostname matching."""
    proj = test_db.create_project(Project(name="Domain Assessment"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="web-srv.corp.local", is_authorized=True))

    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Exposed Admin on web-srv",
            severity=FindingSeverity.HIGH,
            affected_asset="web-srv.corp.local",
            source_tool="gobuster",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="web-srv.corp.local",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    assert dlg.target_findings[0].title == "Exposed Admin on web-srv"


def test_exact_asset_matching_domain_boundary(qtbot, test_db):
    """14. Domain boundary validation."""
    proj = test_db.create_project(Project(name="Boundary Proj"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="app.corp.local", is_authorized=True))

    # Finding on other.corp.local
    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Flaw on other.corp.local",
            severity=FindingSeverity.HIGH,
            affected_asset="other.corp.local",
            source_tool="nmap",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="app.corp.local",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # app.corp.local must NOT match other.corp.local
    assert len(dlg.target_findings) == 0


def test_exact_asset_matching_short_label_collision_prevention(qtbot, test_db):
    """15. Short-label collision prevention (app must not match apple.internal)."""
    proj = test_db.create_project(Project(name="Short Label Proj"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="app", is_authorized=True))

    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Flaw on Apple Internal",
            severity=FindingSeverity.HIGH,
            affected_asset="apple.internal",
            source_tool="nuclei",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="app",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 0


def test_exact_asset_matching_url_hostname_extraction(qtbot, test_db, sample_project):
    """16. URL hostname extraction correlates correctly."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQLi on URL",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://192.168.1.50:8080/path/to/login.php?user=1",
            source_tool="sqlmap",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    assert "SQLi on URL" in dlg.target_findings[0].title


def test_exact_asset_matching_port_qualified_target(qtbot, test_db, sample_project):
    """17. Port-qualified target matching (192.168.1.50:443 matches 192.168.1.50, not 192.168.1.5)."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SSL Vulnerability",
            severity=FindingSeverity.MEDIUM,
            affected_asset="192.168.1.50",
            source_tool="testssl",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50:443",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1

    # But does NOT match finding for 192.168.1.5:443
    dlg2 = AttackPathAnalysisDialog(
        target_ip="192.168.1.5:443",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg2)
    assert len(dlg2.target_findings) == 0


def test_exact_asset_matching_ipv6(qtbot, test_db):
    """18. IPv6 matching."""
    proj = test_db.create_project(Project(name="IPv6 Proj"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="2001:db8::/64", is_authorized=True))

    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Flaw on IPv6",
            severity=FindingSeverity.HIGH,
            affected_asset="http://[2001:db8::1]:8080/admin",
            source_tool="nikto",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="2001:db8::1",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1

    # Does not match 2001:db8::2
    dlg2 = AttackPathAnalysisDialog(
        target_ip="2001:db8::2",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg2)
    assert len(dlg2.target_findings) == 0


def test_exact_asset_matching_no_cross_project_leakage(qtbot, test_db):
    """19. No cross-project finding leakage even with identical IP."""
    proj_a = test_db.create_project(Project(name="Client Alpha"))
    proj_b = test_db.create_project(Project(name="Client Beta"))

    test_db.add_scope(TargetScope(project_id=proj_a.id, target="192.168.1.0/24", is_authorized=True))
    test_db.add_scope(TargetScope(project_id=proj_b.id, target="192.168.1.0/24", is_authorized=True))

    # Finding belongs only to Project B
    test_db.create_finding(
        Finding(
            project_id=proj_b.id,
            title="Confidential RCE on Project B",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.100",
            source_tool="metasploit",
        )
    )

    # Analyze under Project A
    dlg_a = AttackPathAnalysisDialog(
        target_ip="192.168.1.100",
        project=proj_a,
        db=test_db,
    )
    qtbot.addWidget(dlg_a)

    assert len(dlg_a.target_findings) == 0
    assert len(dlg_a.report.attack_paths) == 0


# ==============================================================================
# Phase 5.3.1.3 Attack Path Relationship Regression Tests (Tests 20-29)
# ==============================================================================

def test_relationship_direct_target_findings_remain_visible(qtbot, test_db, sample_project):
    """20. Direct target findings remain visible as Direct Attack Chains."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection on Target Server",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    assert len(dlg.report.attack_paths) >= 1
    assert "Direct Attack Chain" in dlg.lbl_summary.text() or "direct attack path" in dlg.lbl_summary.text()


def test_relationship_valid_asset_edge_accepted(qtbot, test_db, sample_project):
    """21. Valid AssetEdge relationship is accepted as a Verified Pivot Path."""
    # Node A (Jump Host with RCE)
    node_a = test_db.add_asset_node(
        AssetNode(
            project_id=sample_project.id,
            node_type="ip",
            value="192.168.1.10",
            label="jump-host",
        )
    )
    # Node B (Target Server with zero findings)
    node_b = test_db.add_asset_node(
        AssetNode(
            project_id=sample_project.id,
            node_type="ip",
            value="192.168.1.50",
            label="internal-db",
        )
    )

    # Valid observed AssetEdge connecting Node A and Node B
    test_db.add_asset_edge(
        AssetEdge(
            project_id=sample_project.id,
            source_node_id=node_a.id,
            target_node_id=node_b.id,
            relation_type="COMMUNICATES_WITH",
            verification_state="observed",
            confidence=1.0,
        )
    )

    # Finding belongs to Node A
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Remote Code Execution on Jump Host",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.10",
            source_tool="nuclei",
        )
    )

    # Analyze Node B (192.168.1.50)
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Node B has 0 direct findings, but has a verified lateral movement pivot from Node A!
    assert len(dlg.target_findings) == 0
    assert "verified lateral movement path" in dlg.lbl_summary.text()


def test_relationship_unconnected_asset_rejected_as_pivot(qtbot, test_db):
    """22. Unconnected asset with attack chain is rejected as a pivot for target."""
    proj = test_db.create_project(Project(name="Airgap Proj 2"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="10.0.1.5", is_authorized=True))
    test_db.add_scope(TargetScope(project_id=proj.id, target="172.16.2.20", is_authorized=True))

    # Node A (Jump Host with RCE)
    test_db.add_asset_node(
        AssetNode(
            project_id=proj.id,
            node_type="ip",
            value="10.0.1.5",
            label="jump-host",
        )
    )
    # Node B (Target Server)
    test_db.add_asset_node(
        AssetNode(
            project_id=proj.id,
            node_type="ip",
            value="172.16.2.20",
            label="isolated-db",
        )
    )
    # Finding on Node A
    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Remote Code Execution on Jump Host",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.0.1.5",
            source_tool="nuclei",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="172.16.2.20",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Node B must NOT show Node A's RCE chain!
    assert len(dlg.target_findings) == 0
    assert "no verified topology relationships" in dlg.lbl_summary.text()


def test_relationship_project_wide_chain_without_target_relationship_rejected(qtbot, test_db):
    """23. Project-wide chain without target relationship is rejected (empty state shown)."""
    proj = test_db.create_project(Project(name="Airgap Proj"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="10.0.1.5", is_authorized=True))
    test_db.add_scope(TargetScope(project_id=proj.id, target="192.168.20.99", is_authorized=True))

    # Node A (10.0.1.5 with SQLi)
    test_db.add_asset_node(AssetNode(project_id=proj.id, node_type="ip", value="10.0.1.5", label="web-app"))
    # Node B (192.168.20.99 target with zero findings, totally different subnet)
    test_db.add_asset_node(AssetNode(project_id=proj.id, node_type="ip", value="192.168.20.99", label="printer"))

    # Finding on Node A
    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="SQL Injection on Web App",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.0.1.5",
            source_tool="sqlmap",
        )
    )

    # Analyze Node B (192.168.20.99)
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.20.99",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Node B must NOT show Node A's SQLi chain!
    assert len(dlg.target_findings) == 0
    assert "No multi-stage attack chains identified on this asset" in dlg.lbl_summary.text()
    assert "no verified topology relationships" in dlg.lbl_summary.text()


def test_relationship_shared_subnet_accepted_only_when_supported_by_valid_stored_data(qtbot, test_db):
    """24. Shared subnet relationship accepted only when supported by valid stored data in active project."""
    proj = test_db.create_project(Project(name="Subnet Proj"))
    # Explicit recorded netblock node in active project
    test_db.add_asset_node(
        AssetNode(
            project_id=proj.id,
            node_type="netblock",
            value="172.16.50.0/24",
            label="VLAN-50",
        )
    )
    test_db.add_scope(TargetScope(project_id=proj.id, target="172.16.50.0/24", is_authorized=True))

    # Two nodes in same subnet
    test_db.add_asset_node(AssetNode(project_id=proj.id, node_type="ip", value="172.16.50.5", label="server-a"))
    test_db.add_asset_node(AssetNode(project_id=proj.id, node_type="ip", value="172.16.50.20", label="server-b"))

    # Server A has Critical RCE
    test_db.create_finding(
        Finding(
            project_id=proj.id,
            title="Remote Code Execution on Server A",
            severity=FindingSeverity.CRITICAL,
            affected_asset="172.16.50.5",
            source_tool="nuclei",
        )
    )

    # Analyze Server B
    dlg = AttackPathAnalysisDialog(
        target_ip="172.16.50.20",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Accepted as verified pivot via shared subnet
    assert len(dlg.target_findings) == 0
    assert "verified lateral movement path" in dlg.lbl_summary.text()


def test_relationship_cross_project_asset_edge_rejected(qtbot, test_db):
    """25. Cross-project AssetEdge is strictly rejected."""
    proj_1 = test_db.create_project(Project(name="Project 1"))
    proj_2 = test_db.create_project(Project(name="Project 2"))

    test_db.add_scope(TargetScope(project_id=proj_1.id, target="10.0.0.1", is_authorized=True))
    test_db.add_scope(TargetScope(project_id=proj_2.id, target="10.0.0.2", is_authorized=True))

    node_1 = test_db.add_asset_node(AssetNode(project_id=proj_1.id, node_type="ip", value="10.0.0.1", label="n1"))
    node_2 = test_db.add_asset_node(AssetNode(project_id=proj_2.id, node_type="ip", value="10.0.0.2", label="n2"))

    # Edge belongs to Project 2 (cross-project)
    test_db.add_asset_edge(
        AssetEdge(
            project_id=proj_2.id,
            source_node_id=node_2.id,
            target_node_id=node_1.id,
            relation_type="COMMUNICATES_WITH",
        )
    )

    # Finding on node 2 in Project 2
    test_db.create_finding(
        Finding(
            project_id=proj_2.id,
            title="SQL Injection on Node 2",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.0.0.2",
            source_tool="sqlmap",
        )
    )

    # Analyze node 1 under Project 1 context
    dlg = AttackPathAnalysisDialog(
        target_ip="10.0.0.1",
        project=proj_1,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    # Must reject cross-project edge!
    assert len(dlg.target_findings) == 0
    assert "no verified topology relationships" in dlg.lbl_summary.text()


def test_relationship_missing_endpoint_handled_safely(qtbot, test_db, sample_project):
    """26. Edge with missing endpoint node handled safely without error."""
    # Create target node
    node_t = test_db.add_asset_node(AssetNode(project_id=sample_project.id, node_type="ip", value="192.168.1.50"))

    # Edge pointing to non-existent node 99999 (mocked to bypass sqlite FK constraint)
    fake_edge = AssetEdge(
        id=999,
        project_id=sample_project.id,
        source_node_id=99999,
        target_node_id=node_t.id,
        relation_type="ROUTED_VIA",
    )
    with patch.object(test_db, "list_asset_edges", return_value=[fake_edge]):
        dlg = AttackPathAnalysisDialog(
            target_ip="192.168.1.50",
            project=sample_project,
            db=test_db,
        )
        qtbot.addWidget(dlg)

        # Handled safely, does not crash, ignores missing endpoint
        assert dlg is not None
        assert len(dlg.target_findings) == 0


def test_relationship_empty_relationship_data_produces_clear_unverified_state(qtbot, test_db):
    """27. Empty relationship data produces clear unverified/no evidence state."""
    proj = test_db.create_project(Project(name="Empty Proj"))
    test_db.add_scope(TargetScope(project_id=proj.id, target="192.168.1.50", is_authorized=True))

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=proj,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 0
    assert "no verified topology relationships" in dlg.lbl_summary.text()


def test_relationship_no_synthetic_attack_paths(qtbot, test_db, sample_project):
    """28. No synthetic attack paths generated for benign findings."""
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="TLS 1.0 Supported",
            severity=FindingSeverity.LOW,
            affected_asset="192.168.1.50",
            source_tool="testssl",
        )
    )

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
    )
    qtbot.addWidget(dlg)

    assert len(dlg.target_findings) == 1
    assert len(dlg.report.attack_paths) == 0


def test_relationship_existing_scope_auth_tests_remain_passing():
    """29. Verifies existing scope check contract remains intact."""
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", is_authorized=True)]
    status, token = check_target_scope("192.168.1.50", scopes)
    assert status == "Authorized In-Scope Target"
    assert token == "CONFIRMED"


def _dialog_label_text(dialog: AttackPathAnalysisDialog) -> str:
    return "\n".join(label.text() for label in dialog.findChildren(QLabel))


def test_evidence_citation_displays_genuine_id_and_sha256(qtbot, test_db, sample_project):
    finding = test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection in authentication",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    evidence_hash = "a" * 64
    evidence = test_db.add_evidence(
        Evidence(
            project_id=sample_project.id,
            finding_id=finding.id,
            file_path="evidence/sqli.txt",
            sha256_hash=evidence_hash,
        )
    )

    normalized = NormalizedFinding.from_finding(finding, db=test_db)
    assert normalized.evidence_id == evidence.id
    assert normalized.raw_evidence_hash == evidence_hash

    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    rendered = _dialog_label_text(dlg)
    assert f"#{evidence.id}" in rendered
    assert evidence_hash in rendered


def test_evidence_missing_record_displays_empty_state(qtbot, test_db, sample_project):
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection without linked proof",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    assert "No linked evidence" in _dialog_label_text(dlg)


def test_evidence_for_another_finding_is_excluded(qtbot, test_db, sample_project):
    sqli = test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection on target",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    unrelated = test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Informational observation",
            severity=FindingSeverity.INFORMATIONAL,
            affected_asset="192.168.1.50",
            source_tool="scanner",
        )
    )
    evidence = test_db.add_evidence(
        Evidence(
            project_id=sample_project.id,
            finding_id=unrelated.id,
            file_path="evidence/unrelated.txt",
            sha256_hash="b" * 64,
        )
    )

    normalized = NormalizedFinding.from_finding(sqli, db=test_db)
    assert normalized.evidence_id is None
    assert normalized.raw_evidence_hash == ""
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    rendered = _dialog_label_text(dlg)
    assert f"Evidence ID: <code>#{evidence.id}</code>" not in rendered
    assert "No linked evidence" in rendered


def test_cross_project_evidence_is_excluded(qtbot, test_db, sample_project):
    other_project = test_db.create_project(Project(name="Evidence Isolated Project"))
    other_finding = test_db.create_finding(
        Finding(
            project_id=other_project.id,
            title="SQL Injection in other project",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    evidence = test_db.add_evidence(
        Evidence(
            project_id=other_project.id,
            finding_id=other_finding.id,
            file_path="evidence/other-project.txt",
            sha256_hash="c" * 64,
        )
    )
    target_finding = test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection in current project",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )

    assert AttackPathAnalysisDialog._resolve_evidence_for_finding(
        target_finding, test_db, sample_project.id
    ) is None
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)
    rendered = _dialog_label_text(dlg)
    assert evidence.sha256_hash not in rendered
    assert "No linked evidence" in rendered


def test_malformed_evidence_hash_is_not_displayed_as_sha256(qtbot, test_db, sample_project):
    finding = test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection with malformed digest",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    evidence = test_db.add_evidence(
        Evidence(
            project_id=sample_project.id,
            finding_id=finding.id,
            file_path="evidence/malformed.txt",
            sha256_hash="not-a-sha256",
        )
    )
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    rendered = _dialog_label_text(dlg)
    assert f"#{evidence.id}" in rendered
    assert "No verified hash" in rendered
    assert "not-a-sha256" not in rendered


def test_existing_finding_citation_fields_remain_correct(qtbot, test_db, sample_project):
    test_db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection in login parameter",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.1.50",
            source_tool="sqlmap",
        )
    )
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    rendered = _dialog_label_text(dlg)
    assert "SQL Injection in login parameter" in rendered
    assert "192.168.1.50" in rendered
    assert "sqlmap" in rendered


def test_analysis_runs_off_qt_main_thread(qtbot, test_db, sample_project):
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=False,
    )
    qtbot.addWidget(dlg)
    main_thread_id = threading.get_ident()

    qtbot.waitUntil(lambda: not dlg.is_analyzing, timeout=5000)
    assert dlg._worker is not None
    assert dlg._worker.wait(1000)
    assert dlg._worker.worker_thread_id != main_thread_id


def test_worker_ui_slot_runs_on_qt_main_thread(qtbot, test_db, sample_project):
    main_thread_id = threading.get_ident()

    class ThreadRecordingDialog(AttackPathAnalysisDialog):
        @Slot(object, int)
        def _on_analysis_completed(self, result, generation_id):
            self.slot_thread_id = threading.get_ident()
            super()._on_analysis_completed(result, generation_id)

    dlg = ThreadRecordingDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=False,
    )
    qtbot.addWidget(dlg)
    qtbot.waitUntil(lambda: not dlg.is_analyzing, timeout=5000)
    assert dlg._worker.wait(1000)

    assert dlg.slot_thread_id == main_thread_id
    assert dlg._worker.worker_thread_id != dlg.slot_thread_id


def test_duplicate_analysis_request_is_ignored(qtbot, test_db, sample_project):
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=False,
    )
    qtbot.addWidget(dlg)
    worker = dlg._worker
    generation = dlg._current_generation_id

    dlg.run_analysis(sync=False)

    assert dlg._worker is worker
    assert dlg._current_generation_id == generation
    assert worker.wait(1000)
    QApplication.processEvents()


def test_worker_error_displays_safe_error_state(qtbot, sample_project):
    broken_db = MagicMock()
    broken_db.db_path = "/virtual/database.sqlite"
    broken_db.list_scopes.side_effect = RuntimeError("sensitive database detail")
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=broken_db,
        sync=True,
    )
    qtbot.addWidget(dlg)

    assert "Analysis Error" in dlg.lbl_summary.text()
    assert "Check the application log" in dlg.lbl_summary.text()
    assert "sensitive database detail" not in _dialog_label_text(dlg)


def test_closing_dialog_prevents_late_worker_ui_updates(
    qtbot, test_db, sample_project, monkeypatch
):
    entered_analysis = threading.Event()
    release_analysis = threading.Event()
    original_analyze = AIDataAnalystEngine.analyze_project

    def blocked_analysis(engine, *args, **kwargs):
        entered_analysis.set()
        release_analysis.wait(timeout=2)
        return original_analyze(engine, *args, **kwargs)

    monkeypatch.setattr(AIDataAnalystEngine, "analyze_project", blocked_analysis)
    dlg = AttackPathAnalysisDialog(
        target_ip="192.168.1.50",
        project=sample_project,
        db=test_db,
        sync=False,
    )
    qtbot.addWidget(dlg)
    assert entered_analysis.wait(timeout=2)
    summary_before_close = dlg.lbl_summary.text()
    timer = threading.Timer(0.05, release_analysis.set)
    timer.start()

    dlg.close()
    timer.join(timeout=1)

    assert dlg._is_closed
    assert dlg.lbl_summary.text() == summary_before_close
