"""Tests verifying real Nmap scanning execution, down-host feedback, and -Pn options."""

import pytest
from unittest.mock import MagicMock, patch
from PySide6.QtCore import Qt

from storage.db import Database
from storage.models import (
    Project,
    TargetScope,
    TargetType,
    ScopeRuleType,
    ToolExecution,
    ExecutionStatus,
)
from modules.network.nmap_adapter import (
    NmapAdapter,
    NmapScanOptions,
    ScanProfile,
    NmapExecutionResult,
)
from modules.network.nmap_parser import NmapScanResult
from desktop.views.network_scan_view import NetworkScanView


@pytest.fixture
def db():
    database = Database(":memory:")
    return database


@pytest.fixture
def active_project(db: Database):
    proj = db.create_project(Project(name="Pentest Engagement Alpha", client_name="MegaCorp"))
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.100.7",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_nmap_adapter_skip_host_discovery_flag(db: Database):
    adapter = NmapAdapter(db)
    opts = NmapScanOptions(
        target="192.168.100.7",
        profile=ScanProfile.SERVICE_VERSION,
        skip_host_discovery=True,
    )
    cmd = adapter.build_command(opts)
    assert "-Pn" in cmd
    assert "-sV" in cmd
    assert cmd[-1] == "192.168.100.7"


def test_nmap_adapter_unprivileged_os_scan_graceful_fallback(db: Database):
    adapter = NmapAdapter(db)
    opts = NmapScanOptions(
        target="127.0.0.1",
        profile=ScanProfile.OS_FINGERPRINT,
    )
    with patch("os.geteuid", return_value=1000):
        cmd = adapter.build_command(opts)
        # Should not include -O which causes immediate exit code 1 when unprivileged
        assert "-O" not in cmd
        assert "-sV" in cmd
        assert "--version-all" in cmd


def test_network_scan_view_down_host_feedback(qtbot, db: Database, active_project: Project):
    view = NetworkScanView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(active_project)

    # Simulate completed scan where host dropped ping packets (0 hosts up)
    zero_hosts_result = NmapExecutionResult(
        is_authorized=True,
        scope_reason="Authorized target in active scope",
        execution=ToolExecution(
            project_id=active_project.id,
            tool_name="nmap",
            command="nmap -sn -oX - 192.168.100.7",
            status=ExecutionStatus.COMPLETED,
            duration_seconds=0.05,
        ),
        scan_result=NmapScanResult(
            command_args="nmap -sn -oX - 192.168.100.7",
            raw_xml='<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>',
            hosts=[],
        ),
        findings=[],
    )

    view.target_input.setText("192.168.100.7")
    view._on_scan_completed(zero_hosts_result)

    # 1. Status label must NOT be stuck in "Probing..."
    assert "0 hosts up" in view.erp_scan_status_label.text()
    assert "Skip Ping" in view.erp_scan_status_label.text() or "-Pn" in view.erp_scan_status_label.text()

    # 2. Progress bar must be 100% completed
    assert view.erp_progress_bar.value() == 100

    # 3. Discovered hosts table must show the scanned target marked as DOWN rather than empty or old DB entries
    assert view.hosts_table.rowCount() == 1
    assert view.hosts_table.item(0, 0).text() == "192.168.100.7"
    assert "DOWN" in view.hosts_table.item(0, 1).text()

    # 4. ERP Master table must show target status
    assert view.erp_master_table.rowCount() >= 1
    assert view.erp_master_table.item(0, 0).text() == "192.168.100.7"
    assert "DOWN" in view.erp_master_table.item(0, 1).text()


def test_network_scan_view_pn_checkbox_exists(qtbot, db: Database, active_project: Project):
    view = NetworkScanView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(active_project)

    assert hasattr(view, "erp_pn_checkbox")
    assert view.erp_pn_checkbox.text() == "Skip Ping (-Pn)"
    view.erp_pn_checkbox.setChecked(True)
    assert view.erp_pn_checkbox.isChecked() is True

