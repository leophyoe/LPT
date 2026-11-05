"""Tests for Data Flow and GUI Synchronization across Terminal, Database, and Views.

Verifies that terminal tool executions (Nmap, Gobuster, Nikto, etc.) correctly
propagate through:
1. Process execution & exit code handling
2. Text & XML output parsing (NmapParser)
3. Asset inventory deduplication (AssetInventoryService / AssetNode)
4. Finding extraction with assessment ID linkage
5. Database persistence
6. Topology Designer / Network Map visualization
7. Network Recon Master Discovered Assets & Identified Ports table
"""

import json
import tempfile
from pathlib import Path
from typing import List

import pytest
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.views.network_scan_view import NetworkScanView
from desktop.widgets.terminal_view import TerminalWidget
from desktop.widgets.topology_designer import TopologyDesignerWidget
from modules.network.nmap_parser import NmapParser
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.ingest import TerminalIngestEngine
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db = Database(tmp.name)
        yield db


@pytest.fixture
def active_project(test_db):
    proj = test_db.create_project(Project(name="Engagement Alpha", client_name="Alpha Corp"))
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.100",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_nmap_parser_parse_text_structured_model():
    """Verify NmapParser.parse_text extracts hosts, ports, services, latency, and OS from console text."""
    sample_text = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-28 10:00 UTC
Nmap scan report for filesrv.corp (192.168.1.100)
Host is up (0.0012s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.18.0
445/tcp  open  netbios-ssn Samba 4.15
MAC Address: 00:0C:29:4F:8E:1A (VMware)
Device type: general purpose
Running: Linux 5.X
Service Info: Host: filesrv; OS: Linux; CPE: cpe:/o:linux:linux_kernel:5

Nmap done: 1 IP address (1 host up) scanned in 4.15 seconds
"""
    result = NmapParser.parse_text(sample_text, command="nmap -sV 192.168.1.100")
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "192.168.1.100"
    assert host.hostname == "filesrv.corp"
    assert host.latency_ms == 1.2
    assert host.mac_address == "00:0C:29:4F:8E:1A"
    assert host.vendor == "VMware"
    assert host.device_type == "general purpose"
    assert "Linux" in (host.os_match or "")

    assert len(host.ports) == 3
    ports_map = {p.port_id: p for p in host.ports}
    assert 22 in ports_map
    assert ports_map[22].service_name == "ssh"
    assert 80 in ports_map
    assert ports_map[80].product == "nginx"
    assert 445 in ports_map
    assert ports_map[445].state == "open"


def test_terminal_nmap_text_ingestion_creates_asset_nodes_and_topology_devices(app, test_db, active_project):
    """Verify that terminal Nmap text output creates AssetNode in SQLite and loads into TopologyDesignerWidget."""
    sample_text = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-28 10:00 UTC
Nmap scan report for filesrv.corp (192.168.1.100)
Host is up (0.0012s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.18.0
Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds
"""
    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap 192.168.1.100",
        output=sample_text,
    )

    assert len(findings) >= 2

    # Verify AssetNode created in database
    asset_nodes = test_db.list_asset_nodes(active_project.id)
    ip_nodes = [n for n in asset_nodes if n.node_type == "ip"]
    assert len(ip_nodes) >= 1
    ip_node = next(n for n in ip_nodes if n.value == "192.168.1.100")
    meta = json.loads(ip_node.metadata_json)
    assert 22 in meta["open_ports"]
    assert 80 in meta["open_ports"]

    # Verify TopologyDesignerWidget loads device onto canvas
    topo = TopologyDesignerWidget(db=test_db)
    topo.set_active_project(active_project)
    topo.load_discovered_assets(test_db, active_project.id)

    devices = list(topo.scene.get_devices())
    assert len(devices) >= 1
    device_ips = [d.ip_address for d in devices]
    assert "192.168.1.100" in device_ips


def test_terminal_ingestion_preserves_assessment_id(test_db, active_project):
    """Verify that assessment_id is correctly propagated and attached to findings."""
    assessment = test_db.create_assessment(
        Assessment(
            project_id=active_project.id,
            name="Quarterly CPENT Audit",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )

    sample_text = """
Nmap scan report for 192.168.1.100
Host is up (0.001s latency).
PORT    STATE SERVICE
80/tcp  open  http
"""
    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap 192.168.1.100",
        output=sample_text,
        assessment_id=assessment.id,
    )

    assert len(findings) >= 1
    for f in findings:
        assert f.assessment_id == assessment.id

    # Verify persisted findings in DB have assessment_id
    db_findings = test_db.list_findings(active_project.id)
    assert len(db_findings) >= 1
    assert all(f.assessment_id == assessment.id for f in db_findings)


def test_network_view_master_erp_table_synchronizes_terminal_assets(app, test_db, active_project):
    """Verify NetworkScanView._refresh_erp_dashboard populates table with assets discovered in terminal."""
    sample_text = """
Nmap scan report for dc01.corp (192.168.1.100)
Host is up (0.0005s latency).
PORT    STATE SERVICE
53/tcp  open  domain
88/tcp  open  kerberos-sec
"""
    TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap 192.168.1.100",
        output=sample_text,
    )

    view = NetworkScanView(db=test_db)
    view.set_active_project(active_project)
    view._refresh_erp_dashboard()

    assert view.erp_master_table.rowCount() >= 1
    first_ip = view.erp_master_table.item(0, 0).text()
    assert first_ip == "192.168.1.100"
    ports_str = view.erp_master_table.item(0, 5).text()
    assert "53" in ports_str or "88" in ports_str


def test_web_tools_register_in_scope_assets_and_findings(test_db, active_project):
    """Verify web scanner runs (e.g. gobuster) register in-scope asset nodes into inventory."""
    gobuster_output = """
===============================================================
Gobuster v3.6
===============================================================
[+] Url: http://192.168.1.100/
===============================================================
/admin (Status: 301) [Size: 180]
/login (Status: 200) [Size: 950]
Finished
"""
    findings = TerminalIngestEngine.ingest_command_output(
        db=test_db,
        project_id=active_project.id,
        execution_id=None,
        tool_name="gobuster",
        command="gobuster dir -u http://192.168.1.100/ -w words.txt",
        output=gobuster_output,
    )

    assert len(findings) >= 2
    asset_nodes = test_db.list_asset_nodes(active_project.id)
    assert any(n.value == "192.168.1.100" for n in asset_nodes)


def test_terminal_widget_save_command_result_flow(app, test_db, active_project):
    """Verify that TerminalWidget._save_command_result triggers ingestion and emits update signal."""
    widget = TerminalWidget(db=test_db)
    widget.set_active_project(active_project, test_db)

    assessment = test_db.create_assessment(
        Assessment(
            project_id=active_project.id,
            name="Sprint Assessment",
            status=AssessmentStatus.IN_PROGRESS,
        )
    )

    signal_emitted = []
    widget.project_data_updated.connect(lambda: signal_emitted.append(True))

    mock_result = ProcessExecutionResult(
        command=["nmap", "192.168.1.100"],
        exit_code=0,
        stdout="Nmap scan report for 192.168.1.100\nHost is up.\nPORT 80/tcp open http\n",
        stderr="",
        started_at="2026-10-28T10:00:00Z",
        finished_at="2026-10-28T10:00:01Z",
        duration_seconds=1.2,
        status=ExecutionStatus.COMPLETED,
    )

    widget._save_command_result(mock_result, "nmap 192.168.1.100", active_project)

    assert len(signal_emitted) == 1
    # Verify execution, evidence, and findings in DB
    executions = test_db.list_executions(active_project.id)
    assert len(executions) >= 1
    evidence = test_db.list_evidence(active_project.id)
    assert len(evidence) >= 1
    findings = test_db.list_findings(active_project.id)
    assert len(findings) >= 1
    assert findings[0].assessment_id == assessment.id
