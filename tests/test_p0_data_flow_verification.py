"""Comprehensive Regression Tests for Phase P0: Data Flow & GUI Synchronization.

Tests:
1. Nmap XML ingestion.
2. Nmap console-output ingestion.
3. PTY evidence ingestion (with bash prompts & pty_terminal tool name).
4. Duplicate prevention across repeated ingestions.
5. Asset Inventory -> Master Grid and Network Map synchronization.
6. Scope denial and strict exclusion precedence.
7. Invalid or unrecognized terminal output (unparsed evidence, no bogus findings).
8. Process failures and timeouts with clean UI status updates.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.asset_inventory import AssetInventoryService
from core.scope import ScopeAuthorizationService
from modules.network.nmap_adapter import NmapExecutionResult
from modules.network.nmap_parser import NmapParser
from storage.db import Database
from storage.models import (
    AssetNode,
    Assessment,
    AssessmentStatus,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Observation,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)
from terminal.ingest import TerminalIngestEngine, TerminalIngestResult
from terminal.recorder import TerminalSessionRecorder
from terminal.runner import ProcessExecutionResult, ProcessRunner


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.100.50" start="1700000000" version="7.94SVN">
<host starttime="1700000000" endtime="1700000010">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.100.50" addrtype="ipv4"/>
    <hostnames>
        <hostname name="target-web.corp" type="user"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.52" method="probed" conf="10"/>
        </port>
    </ports>
    <os>
        <osmatch name="Linux 5.15" accuracy="98"/>
    </os>
</host>
<runstats>
    <finished time="1700000010" timestr="Sun Oct 28 12:00:00 2026" summary="Nmap done: 1 IP address (1 host up) scanned in 10.00 seconds"/>
    <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

SAMPLE_NMAP_TEXT = """
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-28 12:00 +0630
Nmap scan report for fileserver (192.168.100.60)
Host is up (0.00012s latency).
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.5
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: Host: fileserver; OS: Unix

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
"""

SAMPLE_PTY_SESSION = """
(base) leo@leo:~/Desktop/cybersecuritysuite$ nmap -sV 192.168.100.70
21/tcp open ftp vsftpd 3.0.5
25/tcp open smtp Postfix smtpd
80/tcp open http Apache httpd 2.4.58 ((Ubuntu))
111/tcp open rpcbind 2-4 (RPC #100000)
Service Info: Host: leo-server; OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.42 seconds
(base) leo@leo:~/Desktop/cybersecuritysuite$
"""


@pytest.fixture
def test_db():
    return Database(":memory:")


@pytest.fixture
def authorized_project(test_db):
    project = test_db.create_project(Project(name="P0 Test Engagement", status=ProjectStatus.ACTIVE))
    # Add /24 subnet as allowed
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.168.100.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return project


# ---------------------------------------------------------------------------
# Test 1: Nmap XML Ingestion
# ---------------------------------------------------------------------------
def test_p0_nmap_xml_ingestion(test_db, authorized_project):
    """Test 1: Ingesting Nmap XML output creates AssetNode, Port, and Observation."""
    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap -sV -oX - 192.168.100.50",
        output=SAMPLE_NMAP_XML,
    )

    nodes = test_db.list_asset_nodes(authorized_project.id)
    ip_node = next((n for n in nodes if n.node_type == "ip" and n.value == "192.168.100.50"), None)
    assert ip_node is not None
    assert ip_node.label == "target-web.corp"

    meta = json.loads(ip_node.metadata_json)
    assert 22 in meta["open_ports"]
    assert 80 in meta["open_ports"]
    assert meta["os_match"] == "Linux 5.15"

    observations = test_db.list_observations(authorized_project.id)
    assert len(observations) >= 1
    assert "192.168.100.50" in observations[0].title


# ---------------------------------------------------------------------------
# Test 2: Nmap Console Output Ingestion
# ---------------------------------------------------------------------------
def test_p0_nmap_console_output_ingestion(test_db, authorized_project):
    """Test 2: Console text output creates asset nodes and open port records."""
    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap -sV 192.168.100.60",
        output=SAMPLE_NMAP_TEXT,
    )

    nodes = test_db.list_asset_nodes(authorized_project.id)
    ip_node = next((n for n in nodes if n.node_type == "ip" and n.value == "192.168.100.60"), None)
    assert ip_node is not None

    meta = json.loads(ip_node.metadata_json)
    assert 21 in meta["open_ports"]
    assert 139 in meta["open_ports"]
    assert 445 in meta["open_ports"]


# ---------------------------------------------------------------------------
# Test 3: PTY Evidence Ingestion
# ---------------------------------------------------------------------------
def test_p0_pty_evidence_ingestion(test_db, authorized_project):
    """Test 3: PTY session output with pty_terminal tool name correctly parses and syncs."""
    ingest_res = TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        output=SAMPLE_PTY_SESSION,
        tool_name="pty_terminal",
        command="pty_session",
    )

    assert "nmap" in ingest_res.tools_detected
    assert ingest_res.hosts_synced >= 1
    assert ingest_res.ports_synced >= 4
    assert not ingest_res.is_unparsed_evidence

    nodes = test_db.list_asset_nodes(authorized_project.id)
    ip_node = next((n for n in nodes if n.node_type == "ip" and n.value == "192.168.100.70"), None)
    assert ip_node is not None
    meta = json.loads(ip_node.metadata_json)
    assert 21 in meta["open_ports"]
    assert 25 in meta["open_ports"]
    assert 80 in meta["open_ports"]
    assert 111 in meta["open_ports"]


# ---------------------------------------------------------------------------
# Test 4: Duplicate Prevention
# ---------------------------------------------------------------------------
def test_p0_duplicate_prevention(test_db, authorized_project):
    """Test 4: Repeated ingestion of identical scans does not duplicate assets or findings."""
    res1 = TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        output=SAMPLE_PTY_SESSION,
    )
    nodes_count_1 = len(test_db.list_asset_nodes(authorized_project.id))
    findings_count_1 = len(test_db.list_findings(authorized_project.id))

    # Ingest the exact same session a second time
    res2 = TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        output=SAMPLE_PTY_SESSION,
    )
    nodes_count_2 = len(test_db.list_asset_nodes(authorized_project.id))
    findings_count_2 = len(test_db.list_findings(authorized_project.id))

    assert nodes_count_1 == nodes_count_2, "Asset nodes must be deduplicated on repeated ingestion"
    assert findings_count_1 == findings_count_2, "Findings must be deduplicated on repeated ingestion"


# ---------------------------------------------------------------------------
# Test 5: Asset Inventory -> Master Grid / Network Map Synchronization
# ---------------------------------------------------------------------------
def test_p0_asset_inventory_to_master_grid_and_map_sync(qtbot, test_db, authorized_project):
    """Test 5: Persisted AssetNodes in DB populate both the ERP Master Grid and Network Map."""
    from desktop.views.network_scan_view import NetworkScanView
    from desktop.widgets.topology_designer import TopologyDesignerWidget

    # Ingest scan to populate DB
    TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        output=SAMPLE_PTY_SESSION,
    )

    # 1. Test NetworkScanView ERP Master Grid
    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(authorized_project)
    scan_view._refresh_erp_dashboard()

    # Verify ERP master table has the discovered host
    erp_table = scan_view.erp_master_table
    assert erp_table.rowCount() >= 1

    row_ips = [erp_table.item(r, 0).text() for r in range(erp_table.rowCount()) if erp_table.item(r, 0)]
    assert "192.168.100.70" in row_ips

    # Verify ports column has the open ports
    row_idx = row_ips.index("192.168.100.70")
    ports_cell = erp_table.item(row_idx, 5).text()
    assert "21/" in ports_cell or "21" in ports_cell
    assert "80/" in ports_cell or "80" in ports_cell

    # 2. Test TopologyDesignerWidget
    topo = TopologyDesignerWidget(db=test_db)
    qtbot.addWidget(topo)
    topo.set_active_project(authorized_project)
    devs_added, _, devs_updated = topo.load_discovered_assets(test_db, authorized_project.id)
    assert (devs_added + devs_updated) >= 1


# ---------------------------------------------------------------------------
# Test 6: Scope Denial and Strict Exclusion Precedence
# ---------------------------------------------------------------------------
def test_p0_scope_denial_and_strict_exclusion_precedence(test_db):
    """Test 6: Exclusions strictly override inclusions; out-of-scope scans are not ingested."""
    project = test_db.create_project(Project(name="Scope Test", status=ProjectStatus.ACTIVE))

    # Allowed subnet: 192.168.100.0/24
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.168.100.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    # Strictly EXCLUDED target: 192.168.100.99
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.168.100.99",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )

    scopes = test_db.list_scopes(project.id)

    # 1. Allowed target in subnet
    allowed_check = ScopeAuthorizationService.is_target_authorized("192.168.100.5", scopes)
    assert allowed_check.is_allowed is True

    # 2. Excluded target inside the allowed subnet (Exclusion Precedence)
    excluded_check = ScopeAuthorizationService.is_target_authorized("192.168.100.99", scopes)
    assert excluded_check.is_allowed is False
    assert "EXCLUDED" in excluded_check.reason.upper()

    # 3. Completely out of scope target
    out_scope_check = ScopeAuthorizationService.is_target_authorized("10.50.50.1", scopes)
    assert out_scope_check.is_allowed is False

    # 4. Attempt to ingest scan of excluded host via terminal
    excluded_scan = """
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-28 12:00
    Nmap scan report for 192.168.100.99
    Host is up (0.0001s latency).
    PORT   STATE SERVICE
    80/tcp open  http
    Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
    """
    TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=project.id,
        execution_id=None,
        output=excluded_scan,
    )
    # Excluded host must NEVER be added to asset nodes
    nodes = test_db.list_asset_nodes(project.id)
    assert not any(n.value == "192.168.100.99" for n in nodes)


# ---------------------------------------------------------------------------
# Test 7: Invalid or Unrecognized Terminal Output
# ---------------------------------------------------------------------------
def test_p0_unrecognized_terminal_output_handled_safely(test_db, authorized_project):
    """Test 7: Generic shell commands (ls, pwd, whoami) do NOT generate fake findings or assets."""
    generic_output = """
    (base) leo@leo:~/Desktop/cybersecuritysuite$ ls -la
    total 40
    drwxr-xr-x  6 leo leo 4096 Oct 28 12:00 .
    drwxr-xr-x 24 leo leo 4096 Oct 27 14:00 ..
    -rw-r--r--  1 leo leo 1234 Oct 28 12:00 README.md
    (base) leo@leo:~/Desktop/cybersecuritysuite$ pwd
    /home/leo/Desktop/cybersecuritysuite
    (base) leo@leo:~/Desktop/cybersecuritysuite$ whoami
    leo
    (base) leo@leo:~/Desktop/cybersecuritysuite$ cat /etc/issue
    Ubuntu 24.04 LTS \\n \\l
    """

    res = TerminalIngestEngine.ingest_session(
        db=test_db,
        project_id=authorized_project.id,
        execution_id=None,
        output=generic_output,
        tool_name="pty_terminal",
        command="pty_session",
    )

    assert res.is_unparsed_evidence is True
    assert len(res.tools_detected) == 0
    assert len(res.findings) == 0
    assert res.hosts_synced == 0
    assert res.ports_synced == 0

    # Assert no assets or findings were created in SQLite
    assert len(test_db.list_asset_nodes(authorized_project.id)) == 0
    assert len(test_db.list_findings(authorized_project.id)) == 0


# ---------------------------------------------------------------------------
# Test 8: Process Failures and Error Handling in Scan Controller
# ---------------------------------------------------------------------------
def test_p0_process_failure_and_scan_controller_error_handling(qtbot, test_db, authorized_project):
    """Test 8: ProcessRunner failure creates failed execution, and scan controller handles error cleanly."""
    runner = ProcessRunner()
    # Execute non-existent command
    res = runner.run(["non_existent_binary_xyz_12345"])
    assert res.status == ExecutionStatus.FAILED
    assert res.exit_code != 0

    from desktop.views.network_scan_view import NetworkScanView
    scan_view = NetworkScanView(db=test_db)
    qtbot.addWidget(scan_view)
    scan_view.set_active_project(authorized_project)

    # Simulate completed scan with FAILED execution
    err_exec = ToolExecution(
        project_id=authorized_project.id,
        tool_name="nmap",
        command="nmap 192.168.100.5",
        status=ExecutionStatus.FAILED,
        exit_code=1,
    )
    fail_res = NmapExecutionResult(
        is_authorized=True,
        execution=err_exec,
        scan_result=None,
        findings=[],
        scope_reason="Process returned exit code 1",
    )

    # Emit scan completed with failure
    scan_view._on_scan_completed(fail_res)

    # Verify UI handles failure cleanly
    assert scan_view.scan_btn.isEnabled() is True
    assert scan_view.cancel_btn.isEnabled() is False
    assert "FAILED" in scan_view.status_label.text().upper()
    assert "FAILED" in scan_view.erp_scan_status_label.text().upper()
    assert scan_view.erp_progress_bar.value() == 0
