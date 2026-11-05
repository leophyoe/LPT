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
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from core.ai_data_analyst import AIDataAnalystEngine, AttackPathChain
from desktop.dialogs.attack_path_dialog import (
    AttackPathAnalysisDialog,
    check_target_scope,
)
from desktop.views.visualization_workspace import VisualizationWorkspace
from desktop.widgets.network_map_view import NetworkHostNodeItem, NetworkMapView
from desktop.widgets.topology_designer import TopologyDesignerWidget
from modules.network.nmap_parser import HostResult, NmapScanResult, PortResult
from storage.db import Database
from storage.models import (
    AssetNode,
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
    assert "Database connection corrupted" in dlg.lbl_summary.text()


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
