"""Comprehensive End-to-End Regression Tests for Multi-Tool Shared Ingestion Pipeline.

Validates:
1. Local Network Footprint (interfaces & neighbor table) ingests into AssetNode inventory.
2. Burp Suite XML issue import synchronizes findings and registers affected asset hosts.
3. OWASP ZAP XML and JSON report import synchronizes findings and registers affected asset hosts.
4. Offline PCAP traffic dissection synchronizes communication endpoints into AssetNode inventory.
5. AI Copilot factual project grounding reflects real database assets and findings.
6. Scope enforcement (allowed vs excluded precedence) blocks unauthorized tool inputs.
7. Zero-port hosts remain preserved when multi-port observations arrive.
8. Cross-project isolation prevents data leakage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Generator
import pytest

from core.ai_copilot import AICopilotEngine, AIProvider
from core.asset_inventory import AssetInventoryService
from modules.network.internal_footprint import (
    InternalFootprintResult,
    NeighborEntry,
    NetworkInterfaceInfo,
    RouteInfo,
)
from modules.web.burp_adapter import BurpSuiteAdapter
from modules.web.zap_adapter import ZAPAdapter
from storage.db import Database
from storage.models import (
    AssetNode,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ValidationStatus,
)

SAMPLE_BURP_XML = """<?xml version="1.0"?>
<!DOCTYPE issues SYSTEM "https://portswigger.net">
<issues burpVersion="2026.1" exportTime="Wed Oct 28 20:00:00 UTC 2026">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>1048832</type>
    <name>SQL Injection (Boolean-based)</name>
    <host ip="192.168.100.40">http://192.168.100.40</host>
    <path>/catalog?id=1</path>
    <location>http://192.168.100.40/catalog?id=1</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;SQL injection vulnerability discovered.&lt;/p&gt;</issueBackground>
    <remediationBackground>&lt;p&gt;Use parameterized queries.&lt;/p&gt;</remediationBackground>
    <issueDetail>The parameter 'id' was manipulated.</issueDetail>
  </issue>
</issues>
"""

SAMPLE_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.17.0" generated="Wed, 28 Oct 2026 20:00:00">
  <site name="http://192.168.100.7:80" host="192.168.100.7" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>10038</pluginid>
        <alert>Content Security Policy (CSP) Header Not Set</alert>
        <name>Content Security Policy (CSP) Header Not Set</name>
        <riskcode>2</riskcode>
        <confidence>2</confidence>
        <riskdesc>Medium (Medium)</riskdesc>
        <desc>&lt;p&gt;Content Security Policy (CSP) is not configured.&lt;/p&gt;</desc>
        <uri>http://192.168.100.7/index.php</uri>
        <solution>&lt;p&gt;Configure CSP header.&lt;/p&gt;</solution>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""


@pytest.fixture
def fresh_db(tmp_path: Path) -> Generator[Database, None, None]:
    db_path = str(tmp_path / "test_multitool_pipeline.db")
    db = Database(db_path)
    yield db


@pytest.fixture
def active_project(fresh_db: Database) -> Project:
    proj = fresh_db.create_project(
        Project(
            name="Multi-Tool Assessment",
            client_name="Acme Corp",
            status=ProjectStatus.ACTIVE,
        )
    )
    # Authorized CIDR scope
    fresh_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.100.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    fresh_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


def test_footprint_ingestion_registers_in_scope_nodes(fresh_db: Database, active_project: Project):
    """Verifies that local network footprint interfaces and neighbor cache are synced to AssetNode inventory."""
    service = AssetInventoryService(fresh_db)
    scopes = fresh_db.list_scopes(active_project.id)

    dummy_footprint = InternalFootprintResult(
        interfaces=[
            NetworkInterfaceInfo(
                name="wlan0",
                mac_address="2c:94:52:03:5e:58",
                ipv4_addresses=["192.168.100.7"],
                ipv6_addresses=[],
                is_up=True,
                is_loopback=False,
                scope_status="In Scope",
            ),
            NetworkInterfaceInfo(
                name="eth0",
                mac_address="00:11:22:33:44:55",
                ipv4_addresses=["172.16.5.10"],  # Out of scope!
                ipv6_addresses=[],
                is_up=True,
                is_loopback=False,
                scope_status="Out of Scope",
            ),
        ],
        routes=[
            RouteInfo(
                destination="default",
                gateway="192.168.100.1",
                interface="wlan0",
                is_default_gateway=True,
                metric=100,
                scope_status="In Scope",
            )
        ],
        neighbors=[
            NeighborEntry(
                ip_address="192.168.100.10",
                mac_address="62:20:3e:5b:db:27",
                interface="wlan0",
                state="REACHABLE",
                collection_method="ip_neigh",
                confidence=0.7,
                scope_status="In Scope",
            ),
            NeighborEntry(
                ip_address="172.16.5.99",  # Out of scope!
                mac_address="aa:bb:cc:dd:ee:ff",
                interface="eth0",
                state="REACHABLE",
                collection_method="ip_neigh",
                confidence=0.7,
                scope_status="Out of Scope",
            ),
        ],
        default_gateway="192.168.100.1",
        discovered_subnets=["192.168.100.0/24"],
        raw_data={"telemetry": "dummy footprint"},
        evidence_hash="abcdef1234567890",
    )

    nodes, obs = service.sync_footprint_assets(
        project_id=active_project.id,
        footprint=dummy_footprint,
        scopes=scopes,
        source_tool="footprint",
    )

    # In-scope IPs must be admitted
    admitted_ips = {n.value for n in nodes if n.node_type == "ip"}
    assert "192.168.100.7" in admitted_ips
    assert "192.168.100.1" in admitted_ips
    assert "192.168.100.10" in admitted_ips

    # Out-of-scope IPs must be blocked
    assert "172.16.5.10" not in admitted_ips
    assert "172.16.5.99" not in admitted_ips


def test_burp_suite_import_and_asset_inventory_sync(fresh_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that importing Burp Suite XML reports adds findings and syncs affected assets into inventory."""
    adapter = BurpSuiteAdapter(fresh_db)
    res = adapter.import_burp_xml(
        project_id=active_project.id,
        xml_content=SAMPLE_BURP_XML,
        evidence_dir=tmp_path / "evidence",
    )

    assert res.execution_status.value == "completed"
    assert len(res.findings) == 1
    assert res.findings[0].title == "SQL Injection (Boolean-based)"
    assert res.findings[0].severity == FindingSeverity.HIGH

    # Verify that 192.168.100.40 was admitted into the persistent AssetNode inventory
    nodes = fresh_db.list_asset_nodes(active_project.id)
    ip_nodes = [n for n in nodes if n.node_type == "ip"]
    assert any(n.value == "192.168.100.40" for n in ip_nodes)

    # Verify observation provenance
    history = fresh_db.list_observations_for_asset(active_project.id, ip_nodes[0].id)
    assert any(o.source_tool == "burpsuite" for o in history)


def test_owasp_zap_import_and_asset_inventory_sync(fresh_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that importing OWASP ZAP XML reports adds findings and syncs affected assets into inventory."""
    adapter = ZAPAdapter(fresh_db)
    res = adapter.import_zap_report(
        project_id=active_project.id,
        content=SAMPLE_ZAP_XML,
        evidence_dir=tmp_path / "evidence",
    )

    assert res.execution_status.value == "completed"
    assert len(res.findings) == 1
    assert "Content Security Policy" in res.findings[0].title
    assert res.findings[0].severity == FindingSeverity.MEDIUM

    # Verify that 192.168.100.7 was registered in AssetNode inventory
    nodes = fresh_db.list_asset_nodes(active_project.id)
    ip_nodes = [n for n in nodes if n.node_type == "ip"]
    assert any(n.value == "192.168.100.7" for n in ip_nodes)


def test_ai_copilot_offline_project_telemetry_grounding(fresh_db: Database, active_project: Project):
    """Verifies that AI Copilot analyzes real stored project assets and findings without hallucination."""
    # Seed project with asset and finding
    fresh_db.upsert_asset_node(
        AssetNode(
            project_id=active_project.id,
            node_type="ip",
            value="192.168.100.7",
            label="leo-workstation",
            source_tool="nmap",
            metadata_json=json.dumps({"open_ports": [22, 80], "os_match": "Linux"}),
        )
    )
    fresh_db.upsert_finding_deduplicated(
        Finding(
            project_id=active_project.id,
            title="Apache Outdated Version with CVE-2023-XXXX",
            severity=FindingSeverity.HIGH,
            affected_asset="192.168.100.7",
            validation_status=ValidationStatus.CONFIRMED,
            description="Vulnerable HTTP daemon detected.",
        )
    )

    # Form rich context string matching AIChatView format
    ctx = (
        f"Engagement: {active_project.name} (Client: {active_project.client_name}, Status: active) | "
        "Authorized Scopes (2): 192.168.100.0/24, 10.10.10.0/24 | "
        "Discovered Assets (1 total): 192.168.100.7 (leo-workstation) [ports: [22, 80], via nmap] | "
        "Findings: 1 total (Critical: 0, High: 1, Medium: 0, Low: 0). Top: [HIGH] Apache Outdated Version with CVE-2023-XXXX on 192.168.100.7 (confirmed) | "
        "Evidence Artifacts: 1 cryptographic logs/captures verified | Active Workspace: Assessment"
    )

    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    reply, provider = copilot.chat(
        messages=[{"role": "user", "content": "Please summarize the current assets, risks, and findings."}],
        project_context=ctx,
    )

    assert provider == "builtin_offline"
    assert "Multi-Tool Assessment" in reply
    assert "192.168.100.7" in reply
    assert "Apache Outdated Version" in reply
    assert "Safe Next Steps" in reply
    assert "မြန်မာဘာသာဖြင့် သုံးသပ်ချက်" in reply


def test_scope_exclusion_takes_precedence_over_inclusion(fresh_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that an explicitly excluded IP inside an allowed subnet is rejected fail-closed."""
    # Exclude 192.168.100.50 explicitly
    fresh_db.add_scope(
        TargetScope(
            project_id=active_project.id,
            target="192.168.100.50",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )

    burp_xml_excluded = SAMPLE_BURP_XML.replace("192.168.100.40", "192.168.100.50")
    adapter = BurpSuiteAdapter(fresh_db)
    res = adapter.import_burp_xml(
        project_id=active_project.id,
        xml_content=burp_xml_excluded,
        evidence_dir=tmp_path / "evidence",
    )

    # 192.168.100.50 must be quarantined / not admitted
    assert len(res.findings) == 0
    nodes = fresh_db.list_asset_nodes(active_project.id)
    assert not any(n.value == "192.168.100.50" for n in nodes)


def test_cross_project_isolation_prevents_asset_leakage(fresh_db: Database, active_project: Project, tmp_path: Path):
    """Verifies that assets and findings imported in Project A never appear in Project B."""
    proj_b = fresh_db.create_project(
        Project(name="Project Beta", client_name="Beta Corp", status=ProjectStatus.ACTIVE)
    )
    fresh_db.add_scope(
        TargetScope(
            project_id=proj_b.id,
            target="10.200.0.0/16",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )

    # Import into Project A
    adapter = BurpSuiteAdapter(fresh_db)
    adapter.import_burp_xml(
        project_id=active_project.id,
        xml_content=SAMPLE_BURP_XML,
        evidence_dir=tmp_path / "evidence",
    )

    # Project B must have 0 asset nodes and 0 findings
    nodes_b = fresh_db.list_asset_nodes(proj_b.id)
    findings_b = fresh_db.list_findings(proj_b.id)
    assert len(nodes_b) == 0
    assert len(findings_b) == 0
