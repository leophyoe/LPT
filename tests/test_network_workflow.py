"""Comprehensive unit and integration tests for Network Penetration Testing Workflow.

Covers:
1. Host discovery with zero open ports (ping sweep -sn visibility)
2. Multiple hosts, multiple services, IPv4, IPv6, MAC, and vendor parsing
3. Missing fields (hostname, MAC, OS, CPE) handled safely without inventing data
4. OS fingerprint and accuracy parsing
5. External Nmap XML import with SHA-256 provenance and scope validation
6. Finding validation semantics: open ports are OBSERVED, never CONFIRMED
7. NetworkMapView interactive rendering, node selection, and SVG export
8. Report generation with network inventory and topology diagram
"""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import hashlib
import json
from pathlib import Path

import pytest
from desktop.views.network_scan_view import NetworkScanView
from desktop.widgets.network_map_view import (
    NetworkConnectionItem,
    NetworkHostNodeItem,
    NetworkMapView,
    NetworkSubnetHubItem,
)
from modules.network.nmap_adapter import (
    NmapAdapter,
    NmapExecutionResult,
    NmapScanOptions,
    ScanProfile,
)
from modules.network.nmap_parser import NmapParser, NmapScanResult
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)
from modules.network.pentest_workflow import StageStatus, WorkflowStage

# Deterministic XML Fixtures

PING_SWEEP_ZERO_PORTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.10" start="1600000000" startstr="Mon Sep 20 00:00:00 2026" version="7.94">
<host starttime="1600000000" endtime="1600000001">
<status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="00:50:56:C0:00:08" addrtype="mac" vendor="VMware"/>
<hostnames>
<hostname name="gateway.corp.internal" type="PTR"/>
</hostnames>
<times srtt="1500" rttvar="500" to="100000"/>
</host>
<runstats>
<finished time="1600000001" timestr="Mon Sep 20 00:00:01 2026" elapsed="1.0" summary="Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds" exit="success"/>
</runstats>
</nmaprun>
"""

MULTIPLE_HOSTS_AND_SERVICES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -p 22,80,443 192.168.1.50 2001:db8::10" version="7.94">
<host starttime="1600000000" endtime="1600000005">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell Inc"/>
<hostnames>
<hostname name="web01.corp.internal" type="PTR"/>
</hostnames>
<os>
<osmatch name="Linux 5.4 - 5.15" accuracy="96">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/>
</osmatch>
</os>
<uptime seconds="86400" lastboot="Sun Sep 19 00:00:00 2026"/>
<times srtt="2340" rttvar="400" to="100000"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.2p1" method="probed" conf="10">
<cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
</service>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0" method="probed" conf="10">
<cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
</service>
<script id="http-title" output="Corp Web Portal - Login"/>
</port>
<port protocol="tcp" portid="443">
<state state="filtered" reason="no-response"/>
</port>
</ports>
</host>
<host starttime="1600000000" endtime="1600000005">
<status state="up" reason="syn-ack"/>
<address addr="2001:db8::10" addrtype="ipv6"/>
<ports>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="Apache httpd" version="2.4.52" method="probed" conf="10"/>
</port>
</ports>
</host>
<host starttime="1600000000" endtime="1600000005">
<status state="down" reason="no-response"/>
<address addr="192.168.1.99" addrtype="ipv4"/>
</host>
</nmaprun>
"""


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def project(db: Database) -> Project:
    p = db.create_project(Project(name="Network Test Lab", client_name="Lab Client"))
    db.add_scope(
        TargetScope(
            project_id=p.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p.id,
            target="2001:db8::/32",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    return p


# ---------------------------------------------------------------------------
# 1. Host Discovery with Zero Open Ports (-sn Ping Sweep)
# ---------------------------------------------------------------------------

def test_zero_open_ports_ping_sweep_parsed():
    """Verify that ping sweep XML with 0 ports extracts host data correctly."""
    result = NmapParser.parse_xml(PING_SWEEP_ZERO_PORTS_XML)
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "192.168.1.10"
    assert host.status == "up"
    assert host.status_reason == "echo-reply"
    assert host.hostname == "gateway.corp.internal"
    assert host.mac_address == "00:50:56:C0:00:08"
    assert host.vendor == "VMware"
    assert host.latency_ms == 1.5
    assert len(host.ports) == 0  # 0 open ports


def test_zero_open_ports_visible_in_ui(qtbot, db: Database, project: Project):
    """Verify that host discovery results are rendered in UI even when 0 ports exist."""
    view = NetworkScanView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(project)

    # Simulate completed scan with 0 ports
    scan_result = NmapParser.parse_xml(PING_SWEEP_ZERO_PORTS_XML)
    from modules.network.nmap_adapter import NmapExecutionResult
    exec_res = NmapExecutionResult(
        is_authorized=True,
        scope_reason="Authorized target",
        scan_result=scan_result,
        findings=[],
    )

    view._on_scan_completed(exec_res)

    # 1. Hosts Table MUST show the discovered host
    assert view.hosts_table.rowCount() == 1
    assert view.hosts_table.item(0, 0).text() == "192.168.1.10"
    assert view.hosts_table.item(0, 1).text() == "UP"
    assert view.hosts_table.item(0, 2).text() == "gateway.corp.internal"
    assert "VMware" in view.hosts_table.item(0, 4).text()
    assert view.hosts_table.item(0, 5).text() == "0"  # 0 open ports

    # 2. Results / Services Table shows an informative alive record
    assert view.results_table.rowCount() == 1
    assert view.results_table.item(0, 0).text() == "192.168.1.10"
    assert "Ping Sweep" in view.results_table.item(0, 4).text()


def test_failed_scan_does_not_complete_discovery_stage(qtbot, db: Database, project: Project):
    view = NetworkScanView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(project)

    failed_execution = ToolExecution(
        project_id=project.id,
        tool_name="nmap",
        command="nmap -sn 127.0.0.1",
        status=ExecutionStatus.FAILED,
        exit_code=127,
    )
    view._on_scan_completed(
        NmapExecutionResult(
            is_authorized=True,
            scope_reason="Authorized target",
            execution=failed_execution,
        )
    )

    assert "Scan failed" in view.status_label.text()
    assert view.workflow.get_stage(WorkflowStage.STAGE_2_DISCOVERY).status == StageStatus.FAILED


def test_scan_button_converts_qt_profile_data_to_scan_profile(qtbot, db: Database, project: Project, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    view = NetworkScanView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(project)
    view.target_input.setText("192.168.1.10")
    view.profile_combo.setCurrentIndex(view.profile_combo.findData(ScanProfile.PING_DISCOVERY))

    captured = {}

    def fake_execute_scan(**kwargs):
        captured.update(kwargs)
        return NmapExecutionResult(is_authorized=True, scope_reason="authorized")

    monkeypatch.setattr(view.adapter, "execute_scan", fake_execute_scan)
    monkeypatch.setattr(
        QMessageBox, "question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes
    )

    view._start_scan()
    qtbot.waitUntil(lambda: view.scan_btn.isEnabled(), timeout=3000)

    assert captured["options"].profile is ScanProfile.PING_DISCOVERY


# ---------------------------------------------------------------------------
# 2. Multi-Host, OS Fingerprint, IPv6, CPE, and Script Extraction
# ---------------------------------------------------------------------------

def test_multiple_hosts_and_fingerprints_parsed():
    result = NmapParser.parse_xml(MULTIPLE_HOSTS_AND_SERVICES_XML)
    assert len(result.hosts) == 3

    # Host 1: 192.168.1.50
    h1 = result.hosts[0]
    assert h1.ip == "192.168.1.50"
    assert h1.address_type == "ipv4"
    assert h1.mac_address == "00:11:22:33:44:55"
    assert h1.vendor == "Dell Inc"
    assert h1.os_match == "Linux 5.4 - 5.15"
    assert h1.os_accuracy == 96
    assert h1.device_type == "general purpose"
    assert h1.os_summary == "Linux 5.4 - 5.15 (96%)"
    assert h1.latency_ms == 2.34
    assert len(h1.ports) == 3

    p22 = next(p for p in h1.ports if p.port_id == 22)
    assert p22.state == "open"
    assert p22.product == "OpenSSH"
    assert "cpe:/a:openbsd:openssh:8.2p1" in p22.cpe_list

    p80 = next(p for p in h1.ports if p.port_id == 80)
    assert p80.state == "open"
    assert p80.scripts.get("http-title") == "Corp Web Portal - Login"

    p443 = next(p for p in h1.ports if p.port_id == 443)
    assert p443.state == "filtered"

    # Host 2: IPv6 (Missing hostname, MAC, OS, CPE handled safely)
    h2 = result.hosts[1]
    assert h2.ip == "2001:db8::10"
    assert h2.address_type == "ipv6"
    assert h2.hostname is None
    assert h2.mac_address is None
    assert h2.os_match is None
    assert h2.os_summary == "Unknown OS"
    assert len(h2.ports) == 1
    assert h2.ports[0].cpe_list == []

    # Host 3: Down
    h3 = result.hosts[2]
    assert h3.status == "down"


# ---------------------------------------------------------------------------
# 3. Validation Status Semantics: Open Ports are OBSERVED, Never CONFIRMED
# ---------------------------------------------------------------------------

def test_open_ports_are_observed_not_confirmed():
    scan_result = NmapParser.parse_xml(MULTIPLE_HOSTS_AND_SERVICES_XML)
    findings = NmapParser.to_findings(scan_result, project_id=1, execution_id=10)

    # 3 open ports across the up hosts (22, 80 on host 1; 443 on host 2)
    assert len(findings) >= 3

    for f in findings:
        # Crucial CPENT rule: Raw scanner discoveries are never pre-confirmed exploits
        assert f.validation_status in (ValidationStatus.OBSERVED, ValidationStatus.NEEDS_VALIDATION)
        assert f.validation_status != ValidationStatus.CONFIRMED


# ---------------------------------------------------------------------------
# 4. External Nmap XML Import with Cryptographic Provenance and Scope Check
# ---------------------------------------------------------------------------

def test_import_nmap_xml_provenance_and_scope(db: Database, project: Project, tmp_path: Path):
    adapter = NmapAdapter(db)
    scopes = db.list_scopes(project.id)

    res = adapter.import_nmap_xml(
        project_id=project.id,
        xml_content=MULTIPLE_HOSTS_AND_SERVICES_XML,
        scopes=scopes,
        source_filename="external_nmap_run.xml",
        evidence_dir=tmp_path / "evidence",
    )

    assert res.is_authorized is True
    assert res.execution is not None
    assert res.execution.tool_name == "nmap_import"
    assert "external_nmap_run.xml" in res.execution.command

    # Check evidence record
    evidence_list = db.list_evidence(project.id)
    assert len(evidence_list) >= 1
    ev = next(e for e in evidence_list if "external_nmap_run.xml" in e.description)
    assert ev.mime_type == "application/xml"
    assert ev.sha256_hash == hashlib.sha256(MULTIPLE_HOSTS_AND_SERVICES_XML.encode("utf-8")).hexdigest()

    # Check findings created
    db_findings = db.list_findings(project.id)
    assert len(db_findings) >= 3

    # Check asset inventory sync
    nodes = db.list_asset_nodes(project.id)
    assert any(n.value == "192.168.1.50" for n in nodes)
    assert any(n.value == "web01.corp.internal" for n in nodes)


def test_import_nmap_xml_quarantines_out_of_scope(db: Database, tmp_path: Path):
    """Importing XML targeting unauthorized networks must be rejected."""
    adapter = NmapAdapter(db)
    proj = db.create_project(Project(name="Strict Scope Lab"))
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    scopes = db.list_scopes(proj.id)

    res = adapter.import_nmap_xml(
        project_id=proj.id,
        xml_content=MULTIPLE_HOSTS_AND_SERVICES_XML,
        scopes=scopes,
        source_filename="unauthorized_scan.xml",
    )

    assert res.is_authorized is False
    assert "outside authorized scope" in res.scope_reason


def test_import_nmap_xml_empty_or_malformed_rejected(db: Database, project: Project):
    adapter = NmapAdapter(db)
    scopes = db.list_scopes(project.id)

    with pytest.raises(ValueError, match="empty"):
        adapter.import_nmap_xml(project.id, "", scopes)

    with pytest.raises(ValueError, match="Invalid Nmap XML"):
        adapter.import_nmap_xml(project.id, "<malformed><xml", scopes)


# ---------------------------------------------------------------------------
# 5. Network Asset Map (Canvas Rendering & SVG Export)
# ---------------------------------------------------------------------------

def test_network_map_view_rendering_and_svg(qtbot):
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)
    map_view.show()

    scan_result = NmapParser.parse_xml(MULTIPLE_HOSTS_AND_SERVICES_XML)
    findings = NmapParser.to_findings(scan_result, project_id=1)

    map_view.load_scan(scan_result, findings)

    items = map_view.scene.items()
    host_items = [it for it in items if isinstance(it, NetworkHostNodeItem)]
    hub_items = [it for it in items if isinstance(it, NetworkSubnetHubItem)]
    conn_items = [it for it in items if isinstance(it, NetworkConnectionItem)]

    # 3 hosts in scan
    assert len(host_items) == 3
    # Subnet hubs created (at least 1 for 192.168.1.0/24)
    assert len(hub_items) >= 1
    assert len(conn_items) >= 2

    # SVG export verification
    svg_str = map_view.to_svg()
    assert "<svg" in svg_str
    assert "</svg>" in svg_str
    assert "192.168.1.50" in svg_str
    assert "Logical Subnet Clustering" in svg_str


# ---------------------------------------------------------------------------
# 6. Report Integration (Markdown, HTML, JSON)
# ---------------------------------------------------------------------------

def test_report_builder_includes_network_pentest_section(db: Database, project: Project, tmp_path: Path):
    adapter = NmapAdapter(db)
    scopes = db.list_scopes(project.id)

    # Import deterministic scan to populate evidence and findings
    adapter.import_nmap_xml(
        project_id=project.id,
        xml_content=MULTIPLE_HOSTS_AND_SERVICES_XML,
        scopes=scopes,
        source_filename="report_test_scan.xml",
        evidence_dir=tmp_path / "evidence",
    )

    builder = ReportBuilder(db)

    # 1. JSON Report
    json_str = builder.generate_json(project.id)
    report_json = json.loads(json_str)
    assert "network_inventory" in report_json
    assert len(report_json["network_inventory"]) >= 2
    assert any(h["ip"] == "192.168.1.50" for h in report_json["network_inventory"])

    # 2. Markdown Report
    md_str = builder.generate_markdown(project.id)
    assert "## Network Penetration Testing & Discovered Endpoints" in md_str
    assert "Topological Integrity Notice" in md_str
    assert "| `192.168.1.50` |" in md_str
    assert "OpenSSH" in md_str

    # 3. HTML Report
    html_str = builder.generate_html(project.id)
    assert "Network Penetration Testing & Asset Inventory" in html_str
    assert "Topological Integrity Notice" in html_str
    assert "<svg" in html_str
    assert "192.168.1.50" in html_str
