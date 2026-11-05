"""Unit tests for Phase 3B Enumeration, WAF, CT, and Firewall Scanning enhancements.

Verifies:
1. NmapAdapter FIREWALL_DETECTION profile construction (-sA -T4 -Pn).
2. Behind24 AssetsView 1-Click CT Subdomain Harvest action.
3. Behind24 AssetsView 1-Click WAF Detection action.
4. PassiveRecon resolve_ip_asn function safety and parsing.
"""

from __future__ import annotations

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtCore import Qt

from desktop.views.assets_view import AssetsView
from modules.network.nmap_adapter import (
    NmapAdapter,
    NmapScanOptions,
    ScanProfile,
)
from modules.osint.passive_recon import resolve_ip_asn
from storage.db import Database
from storage.models import (
    AssetNode,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "enum_test.db"
    return Database(str(db_file))


@pytest.fixture
def sample_project(test_db: Database) -> Project:
    proj = test_db.create_project(
        Project(
            name="Alpha Corp Penetration Test",
            client_name="Alpha Corp",
            status=ProjectStatus.ACTIVE,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="alphacorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_nmap_firewall_detection_command(test_db: Database):
    """Verify that FIREWALL_DETECTION profile builds -sA -T4 -Pn command."""
    adapter = NmapAdapter(test_db)
    options = NmapScanOptions(
        target="10.10.10.50",
        profile=ScanProfile.FIREWALL_DETECTION,
    )
    cmd = adapter.build_command(options)
    assert "-sA" in cmd
    assert "-T4" in cmd
    assert "-Pn" in cmd
    assert cmd[-1] == "10.10.10.50"


def test_assets_view_has_recon_actions_toolbar(qtbot, test_db: Database, sample_project: Project):
    """Verify that Behind24 AssetsView contains the 1-Click CT and WAF buttons."""
    view = AssetsView(test_db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    assert hasattr(view, "btn_harvest_ct")
    assert hasattr(view, "btn_check_waf")
    assert hasattr(view, "lbl_recon_target")
    assert "alphacorp.com" in view.lbl_recon_target.text()


def test_assets_view_run_ct_harvest(qtbot, test_db: Database, sample_project: Project):
    """Verify that 1-Click CT harvest triggers discovery and updates status."""
    view = AssetsView(test_db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    # Click the CT harvest button
    with patch("modules.osint.cert_transparency_adapter.CertTransparencyAdapter.run_discovery") as mock_disc:
        mock_disc.return_value = MagicMock(discovered_assets=[AssetNode(project_id=sample_project.id, node_type="subdomain", value="vpn.alphacorp.com", label="vpn.alphacorp.com")])
        view._run_ct_harvest()
        assert "Querying crt.sh" in view.lbl_recon_status.text()


def test_assets_view_run_waf_detection(qtbot, test_db: Database, sample_project: Project):
    """Verify that 1-Click WAF detection triggers execution and updates status."""
    view = AssetsView(test_db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    # Click the WAF button
    with patch("modules.web.wafw00f_adapter.WAFW00FAdapter.execute_scan") as mock_scan:
        mock_scan.return_value = (True, "OK", [], None)
        view._run_waf_detection()
        assert "Detecting WAF" in view.lbl_recon_status.text()


def test_resolve_ip_asn_private_ip():
    """Verify resolve_ip_asn skips RFC 1918 private IPs."""
    res = resolve_ip_asn("192.168.1.1")
    assert res == {}
    res = resolve_ip_asn("10.0.0.1")
    assert res == {}
    res = resolve_ip_asn("127.0.0.1")
    assert res == {}


def test_nmap_udp_scan_profile(test_db: Database):
    """Verify that UDP_SCAN profile builds -sU -F -T4 command."""
    adapter = NmapAdapter(test_db)
    options = NmapScanOptions(
        target="10.10.10.50",
        profile=ScanProfile.UDP_SCAN,
    )
    cmd = adapter.build_command(options)
    assert "-sU" in cmd
    assert "-F" in cmd
    assert "-T4" in cmd
    assert cmd[-1] == "10.10.10.50"


def test_socket_port_scanner_initialization(test_db: Database):
    """Verify SocketPortScanner initialization and port mapping constants."""
    from modules.network.socket_scanner import SocketPortScanner, TOP_PENTEST_PORTS, SERVICE_PORT_NAMES
    scanner = SocketPortScanner(test_db)
    assert scanner.db == test_db
    assert 80 in TOP_PENTEST_PORTS
    assert 443 in TOP_PENTEST_PORTS
    assert 22 in TOP_PENTEST_PORTS
    assert SERVICE_PORT_NAMES[22] == "ssh"
    assert SERVICE_PORT_NAMES[443] == "https"


