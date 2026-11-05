"""Comprehensive tests for Phase 11 — Assessment Automation.

Covers:
1. Assessment Session lifecycle and storage persistence
2. Nmap XML parsing, safe import, and malformed input handling
3. Asset inventory normalization and deduplication
4. Historical observations preservation (non-destructive)
5. Fail-closed scope enforcement during import (never auto-authorizes scanning)
6. Duplicate findings prevention and OBSERVED validation status
7. Activity logging with secret and credential scrubbing
8. Network Map integration with clear distinction between observed and manual elements
"""

import json
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from core.activity_logger import ActivityLogger, sanitize_data, sanitize_text
from core.asset_inventory import AssetInventoryService, normalize_asset_value
from core.scope import ScopeAuthorizationService
from desktop.widgets.topology_designer import (
    DeviceType,
    TopologyDesignerWidget,
    TopologyDeviceItem,
    TopologyLinkItem,
)
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions, ScanProfile
from modules.network.nmap_parser import HostResult, NmapParser, NmapScanResult, PortResult
from storage.db import Database
from storage.models import (
    AssessmentSession,
    AssetEdge,
    AssetNode,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Observation,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
    _utc_now_iso,
)

SAMPLE_VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -F 192.168.1.100" version="7.94">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<hostnames>
<hostname name="web.internal.corp" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="Apache httpd" version="2.4.41" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>
"""

SAMPLE_MULTIHOST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.100 10.0.0.1" version="7.94">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4" method="probed" conf="10"/></port>
</ports>
</host>
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="echo-reply"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2" method="probed" conf="10"/></port>
</ports>
</host>
</nmaprun>
"""


@pytest.fixture
def test_db():
    return Database(":memory:")


@pytest.fixture
def active_project(test_db: Database) -> Project:
    p = test_db.create_project(
        Project(
            name="Alpha Corp Penetration Test",
            client_name="Alpha Corp",
            description="Authorized internal network test only.",
        )
    )
    assert p.id is not None
    test_db.create_target_scope(
        TargetScope(
            project_id=p.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
            notes="Corporate internal subnet",
        )
    )
    return p


# 1. Assessment Session Persistence
def test_assessment_session_lifecycle(test_db: Database, active_project: Project):
    """Verifies creation, retrieval, status update, and session listing."""
    session = AssessmentSession(
        project_id=active_project.id,
        session_id="SESS-2026-001",
        authorized_scope="192.168.1.0/24",
        selected_tools=["nmap", "nikto"],
        status="running",
        started_at=_utc_now_iso(),
        metadata_json=json.dumps({"operator": "analyst-1", "lead": "Senior Tester"}),
    )
    created = test_db.create_assessment_session(session)
    assert created.id is not None
    assert created.session_id == "SESS-2026-001"
    assert created.status == "running"

    # Fetch by session ID
    fetched = test_db.get_assessment_session("SESS-2026-001")
    assert fetched is not None
    assert fetched.project_id == active_project.id
    assert fetched.selected_tools == ["nmap", "nikto"]

    # Update session status
    fetched.status = "completed"
    fetched.ended_at = _utc_now_iso()
    test_db.update_assessment_session(fetched)

    updated = test_db.get_assessment_session("SESS-2026-001")
    assert updated is not None
    assert updated.status == "completed"
    assert updated.ended_at is not None

    # List sessions by project
    sessions = test_db.list_assessment_sessions(active_project.id)
    assert len(sessions) == 1
    assert sessions[0].session_id == "SESS-2026-001"


# 2. Nmap XML Parsing & Safe Import
def test_nmap_xml_import_success_and_provenance(test_db: Database, active_project: Project, tmp_path: Path):
    """Verifies successful Nmap XML import, session linkage, and SHA-256 evidence recording."""
    adapter = NmapAdapter(test_db)
    scopes = test_db.list_target_scopes(active_project.id)

    res = adapter.import_nmap_xml(
        project_id=active_project.id,
        xml_content=SAMPLE_VALID_XML,
        scopes=scopes,
        source_filename="scan_results.xml",
        evidence_dir=tmp_path / "evidence",
        session_id="SESS-2026-001",
    )

    assert res.is_authorized is True
    assert res.execution is not None
    assert res.execution.status == ExecutionStatus.COMPLETED

    # Verify SHA-256 evidence record was saved
    evidence_list = test_db.list_evidence(active_project.id)
    assert len(evidence_list) == 1
    assert len(evidence_list[0].sha256_hash) == 64
    assert evidence_list[0].mime_type == "application/xml"

    # Verify findings are OBSERVED and linked
    findings = test_db.list_findings(active_project.id)
    assert len(findings) == 2  # 80/tcp and 443/tcp
    for f in findings:
        assert f.validation_status == ValidationStatus.OBSERVED
        assert f.source_tool == "nmap"

    # Verify activity audit log was created with session_id
    logs = test_db.get_audit_logs(active_project.id)
    import_logs = [log for log in logs if log.action == "nmap_xml_imported"]
    assert len(import_logs) == 1
    details = json.loads(import_logs[0].details)
    assert details["session_id"] == "SESS-2026-001"
    assert details["in_scope_count"] == 1
    assert details["quarantined_count"] == 0


def test_nmap_xml_import_malformed_and_empty_xml_handling(test_db: Database, active_project: Project):
    """Verifies that empty, malformed, or incomplete XML files are rejected safely without crashing."""
    adapter = NmapAdapter(test_db)
    scopes = test_db.list_target_scopes(active_project.id)

    # 1. Empty string
    with pytest.raises(ValueError, match="empty"):
        adapter.import_nmap_xml(
            project_id=active_project.id,
            xml_content="",
            scopes=scopes,
            session_id="SESS-ERR-1",
        )

    # 2. Malformed XML
    with pytest.raises(ValueError, match="Malformed or incomplete"):
        adapter.import_nmap_xml(
            project_id=active_project.id,
            xml_content="<nmaprun><host><bad syntax>>>",
            scopes=scopes,
            session_id="SESS-ERR-2",
        )

    # 3. XML with no hosts
    with pytest.raises(ValueError, match="No hosts found"):
        adapter.import_nmap_xml(
            project_id=active_project.id,
            xml_content='<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>',
            scopes=scopes,
            session_id="SESS-ERR-3",
        )

    # Verify failure actions logged to audit trail
    logs = test_db.get_audit_logs(active_project.id)
    failure_logs = [log for log in logs if log.action == "scan_import_failed"]
    assert len(failure_logs) == 3


# 3. Asset Normalization & Deduplication
def test_asset_normalization_rules():
    """Verifies asset identifier normalization for IPv4, IPv6, Hostname, URL, and MAC."""
    assert normalize_asset_value("ip", "  192.168.1.100  ") == "192.168.1.100"
    assert normalize_asset_value("ip", "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_asset_value("hostname", "WEB.CORP.LOCAL.") == "web.corp.local"
    assert normalize_asset_value("url", "HTTPS://App.Corp.Local:8443/api/v1/") == "https://app.corp.local:8443/api/v1"
    assert normalize_asset_value("mac", "AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_asset_deduplication_and_observation_preservation(test_db: Database, active_project: Project):
    """Verifies that discovering the same asset multiple times updates/deduplicates the node
    while strictly preserving separate historical observation records."""
    service = AssetInventoryService(test_db)
    scopes = test_db.list_target_scopes(active_project.id)

    # First Scan: 192.168.1.100 has port 80
    scan1 = NmapScanResult(
        command_args="nmap -p80 192.168.1.100",
        hosts=[
            HostResult(
                ip="192.168.1.100",
                hostname="web.corp.local",
                status="up",
                ports=[PortResult(80, "tcp", "open", "http", "Apache", "2.4.41")],
            )
        ],
    )
    nodes1, obs1 = service.sync_scan_assets(
        project_id=active_project.id,
        scan_result=scan1,
        scopes=scopes,
        session_id="SESS-A",
        source_tool="nmap",
    )
    assert len(nodes1) == 2  # IP node + Hostname node
    assert len(obs1) == 1

    ip_node_id = next(n.id for n in nodes1 if n.node_type == "ip")

    # Second Scan (later): 192.168.1.100 has port 80 and port 443
    scan2 = NmapScanResult(
        command_args="nmap -p80,443 192.168.1.100",
        hosts=[
            HostResult(
                ip="192.168.1.100",
                hostname="web.corp.local",
                status="up",
                ports=[
                    PortResult(80, "tcp", "open", "http", "Apache", "2.4.41"),
                    PortResult(443, "tcp", "open", "https", "Apache", "2.4.41"),
                ],
            )
        ],
    )
    nodes2, obs2 = service.sync_scan_assets(
        project_id=active_project.id,
        scan_result=scan2,
        scopes=scopes,
        session_id="SESS-B",
        source_tool="nmap",
    )

    # Database check: IP node must NOT be duplicated!
    all_ip_nodes = [n for n in test_db.list_asset_nodes(active_project.id) if n.node_type == "ip"]
    assert len(all_ip_nodes) == 1
    assert all_ip_nodes[0].id == ip_node_id

    # Historical observations check: Must preserve BOTH scan observations (newest first)
    history = service.get_asset_history(active_project.id, ip_node_id)
    assert len(history) == 2
    assert "2 open port(s)" in history[0].title
    assert "1 open port(s)" in history[1].title

    # Verify session provenance preserved in observation raw_data
    raw0 = json.loads(history[0].raw_data)
    raw1 = json.loads(history[1].raw_data)
    assert raw0["session_id"] == "SESS-B"
    assert raw1["session_id"] == "SESS-A"


# 4. Fail-Closed Scope Quarantine During Import
def test_import_scope_guard_quarantines_out_of_scope(test_db: Database, active_project: Project):
    """Verifies that out-of-scope targets in imported scans are quarantined and NEVER auto-authorized."""
    adapter = NmapAdapter(test_db)
    scopes = test_db.list_target_scopes(active_project.id)

    # SAMPLE_MULTIHOST_XML contains:
    # 192.168.1.100 (in scope 192.168.1.0/24)
    # 10.0.0.1 (out of scope)
    res = adapter.import_nmap_xml(
        project_id=active_project.id,
        xml_content=SAMPLE_MULTIHOST_XML,
        scopes=scopes,
        session_id="SESS-MULTI",
    )

    assert res.is_authorized is True

    # Check asset nodes in DB
    asset_nodes = test_db.list_asset_nodes(active_project.id)
    ip_values = [n.value for n in asset_nodes if n.node_type == "ip"]
    assert "192.168.1.100" in ip_values
    assert "10.0.0.1" not in ip_values  # Quarantined

    # Check findings in DB
    findings = test_db.list_findings(active_project.id)
    finding_assets = [f.affected_asset for f in findings]
    assert "192.168.1.100" in finding_assets
    assert "10.0.0.1" not in finding_assets  # Quarantined

    # CRITICAL: Confirm that imported 10.0.0.1 does NOT authorize future scans
    auth_check = ScopeAuthorizationService.is_target_authorized("10.0.0.1", scopes)
    assert auth_check.is_allowed is False
    assert "not in the authorized scope" in auth_check.reason.lower()


# 5. Duplicate Findings Prevention & Validation Status
def test_duplicate_findings_prevention(test_db: Database, active_project: Project):
    """Verifies finding deduplication and preservation of OBSERVED status."""
    f1 = Finding(
        project_id=active_project.id,
        title="Open Service: 80/tcp (http)",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="192.168.1.100",
        affected_port_service="80/tcp",
        description="Apache httpd 2.4.41 detected on port 80",
        remediation="Ensure only authorized services are accessible.",
        validation_status=ValidationStatus.OBSERVED,
        source_tool="nmap",
    )
    test_db.upsert_finding_deduplicated(f1)

    initial_findings = test_db.list_findings(active_project.id)
    assert len(initial_findings) == 1
    fid = initial_findings[0].id

    # Second import/scan of same port
    f2 = Finding(
        project_id=active_project.id,
        title="Open Service: 80/tcp (http)",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="192.168.1.100",
        affected_port_service="80/tcp",
        description="Apache httpd 2.4.41 updated notes",
        remediation="Ensure only authorized services are accessible.",
        validation_status=ValidationStatus.OBSERVED,
        source_tool="nmap",
    )
    test_db.upsert_finding_deduplicated(f2)

    updated_findings = test_db.list_findings(active_project.id)
    assert len(updated_findings) == 1  # Deduplicated!
    assert updated_findings[0].id == fid
    assert updated_findings[0].description == "Apache httpd 2.4.41 detected on port 80"


# 6. Activity Logging & Secret Scrubbing
def test_activity_logger_secret_scrubbing(test_db: Database, active_project: Project):
    """Verifies that API keys, passwords, bearer tokens, and credentials are scrubbed from logs."""
    logger = ActivityLogger(test_db)

    # Test raw text scrubbing
    raw_str = "nmap --script http-vuln --password SuperSecretPass123! with token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"
    scrubbed_str = sanitize_text(raw_str)
    assert "SuperSecretPass123!" not in scrubbed_str
    assert "Bearer eyJhbGci" not in scrubbed_str
    assert "[REDACTED]" in scrubbed_str

    # Test structured dict scrubbing
    sensitive_details = {
        "target": "192.168.1.100",
        "api_key": "sk-ant-api03-abcdef1234567890abcdef1234567890",
        "secret": "db_master_password_999",
        "nested": {
            "token": "sk-proj-xyz1234567890abcdef",
            "safe_param": "aggressive_scan",
        },
    }
    logger.log(
        project_id=active_project.id,
        action="scan_config_applied",
        outcome="success",
        session_id="SESS-SAFE-01",
        details=sensitive_details,
    )

    logs = test_db.get_audit_logs(active_project.id)
    assert len(logs) == 1
    log_entry = logs[0]
    parsed = json.loads(log_entry.details)
    assert parsed["session_id"] == "SESS-SAFE-01"
    assert parsed["target"] == "192.168.1.100"
    assert parsed["api_key"] == "[REDACTED]"
    assert parsed["secret"] == "[REDACTED]"
    assert parsed["nested"]["token"] == "[REDACTED]"
    assert parsed["nested"]["safe_param"] == "aggressive_scan"


# 7. Network Map Discovered Asset Loading & Visual Distinction
def test_network_map_loads_discovered_assets_with_provenance(qtbot, test_db: Database, active_project: Project):
    """Verifies that discovered assets and relationships load into the Network Map
    with clear visual badges and distinction from manual links."""
    # Setup database assets
    node1 = test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.1.1",
            label="Gateway Router",
            source_tool="nmap",
            confidence=1.0,
            metadata_json=json.dumps({"device_type": "router"}),
        )
    )
    node2 = test_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.1.100",
            label="Web Server",
            source_tool="nmap",
            confidence=1.0,
            metadata_json={"device_type": "server"},
        )
    )
    test_db.add_asset_edge(
        AssetEdge(
            project_id=active_project.id,
            source_node_id=node1.id,
            target_node_id=node2.id,
            relation_type="ROUTES_TO",
            source_tool="nmap",
        )
    )

    # Initialize Topology Designer
    designer = TopologyDesignerWidget(db=test_db)
    qtbot.addWidget(designer)
    loaded_nodes, loaded_edges = designer.load_discovered_assets(test_db, active_project.id)
    assert loaded_nodes == 2
    assert loaded_edges == 1

    # Check observed device items
    devices = [i for i in designer.scene.items() if isinstance(i, TopologyDeviceItem)]
    assert len(devices) == 2
    for d in devices:
        assert d.is_observed is True
        assert d.source_tool == "nmap"
        assert "Observed via nmap" in d.toolTip()

    # Check observed link items
    links = [i for i in designer.scene.items() if isinstance(i, TopologyLinkItem)]
    assert len(links) == 1
    assert links[0].is_observed is True
    assert "Observed" in links[0].label
    assert "Observed via" in links[0].toolTip()

    # Add a manual device and manual link
    manual_device = designer.scene.add_device(
        device_type=DeviceType.WORKSTATION,
        label="Manual Lab Box",
        x=100.0,
        y=100.0,
    )
    assert manual_device.is_observed is False
    assert manual_device.source_tool == ""

    manual_link = designer.scene.add_link(source=devices[0], dest=manual_device)
    assert manual_link is not None
    assert manual_link.is_observed is False
    assert "Manually Drawn" in manual_link.toolTip()
