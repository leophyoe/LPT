"""Phase 3 Test Suite: Universal Parser Architecture, Evidence Intelligence & Correlation.

Covers:
1. Multi-project isolation and DB enforcement.
2. Universal Parser across Nmap XML/text, Nikto, SQLMap, WAFW00F, Gobuster, FFUF.
3. Resilient partial/corrupted output error handling.
4. Evidence Intelligence & 'Zero unbacked confirmed findings' policy.
5. Asset & service correlation with observation preservation.
6. Cross-tool finding correlation with multi-tool provenance.
7. Curated offline CVE & CVSS enrichment and status demarcation.
8. Historical scan comparison (NEW, PERSISTENT, RESOLVED, CHANGED).
9. AI Data Analyst citations and anti-hallucination guard.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
import pytest

from core.analysis.historical_comparator import (
    FindingDeltaStatus,
    HistoricalComparator,
)
from core.ai_data_analyst import AIDataAnalystEngine
from core.correlation.asset_service_correlator import AssetServiceCorrelator
from core.correlation.finding_correlator import FindingCorrelator
from core.enrichment.cve_enrichment import CVEEnrichmentService
from core.evidence_intelligence import EvidenceIntelligenceService
from core.parsers.normalized_models import (
    NormalizedFinding,
    NormalizedParserResult,
    NormalizedService,
)
from core.parsers.universal_parser import UniversalParser
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def isolated_db(tmp_path: Path) -> Database:
    """Creates a temporary isolated SQLite database for testing."""
    db_path = tmp_path / "test_phase3.db"
    db = Database(str(db_path))
    return db


@pytest.fixture
def test_project(isolated_db: Database) -> Project:
    return isolated_db.create_project(
        Project(
            name="Alpha Bank Pentest",
            client_name="Alpha Corp",
            description="Authorized External Pentest",
        )
    )


@pytest.fixture
def second_project(isolated_db: Database) -> Project:
    return isolated_db.create_project(
        Project(
            name="Beta Logistics Pentest",
            client_name="Beta Corp",
            description="Isolated Engagement",
        )
    )


# =============================================================================
# 1. Multi-Project Isolation & DB Enforcement
# =============================================================================
def test_multi_project_caller_isolation_and_db_enforcement(
    isolated_db: Database,
    test_project: Project,
    second_project: Project,
):
    # Create finding in project 1
    f1 = isolated_db.create_finding(
        Finding(
            project_id=test_project.id,
            title="Alpha Exposed Config",
            severity=FindingSeverity.HIGH,
            affected_asset="10.0.0.1",
        )
    )
    # Create finding in project 2
    f2 = isolated_db.create_finding(
        Finding(
            project_id=second_project.id,
            title="Beta Debug Mode",
            severity=FindingSeverity.MEDIUM,
            affected_asset="10.0.0.2",
        )
    )

    # Cross-project get_finding must fail closed
    assert isolated_db.get_finding(f1.id, project_id=test_project.id) is not None
    assert isolated_db.get_finding(f1.id, project_id=second_project.id) is None
    assert isolated_db.get_finding(f2.id, project_id=second_project.id) is not None
    assert isolated_db.get_finding(f2.id, project_id=test_project.id) is None

    # Cross-project delete_finding must fail closed
    assert isolated_db.delete_finding(f1.id, project_id=second_project.id) is False
    assert isolated_db.get_finding(f1.id, project_id=test_project.id) is not None

    # Authorized delete_finding succeeds
    assert isolated_db.delete_finding(f1.id, project_id=test_project.id) is True
    assert isolated_db.get_finding(f1.id, project_id=test_project.id) is None


# =============================================================================
# 2. Universal Parser: Nmap XML & Text
# =============================================================================
def test_universal_parser_nmap_xml_and_text():
    nmap_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -sC 10.0.0.5" version="7.94">
<host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="app.target.local"/></hostnames>
  <ports>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="Apache httpd" version="2.4.49"/>
      <script id="ssl-enum-ciphers" output="TLSv1.0: Weak cipher DES-CBC3-SHA"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2p1"/>
    </port>
  </ports>
</host>
</nmaprun>"""

    result = UniversalParser.parse(nmap_xml, "nmap", "10.0.0.5")
    assert result.success is True
    assert len(result.services) == 2
    assert len(result.raw_evidence_hash) == 64

    # Verify service attributes
    s443 = next(s for s in result.services if s.port == 443)
    assert s443.product == "Apache httpd"
    assert s443.version == "2.4.49"

    # Verify script finding
    assert len(result.findings) >= 1
    f_ssl = next(f for f in result.findings if "ssl-enum-ciphers" in f.title)
    assert f_ssl.port == 443
    assert f_ssl.validation_status == ValidationStatus.OBSERVED

    # Test plain text fallback
    nmap_text = """
Nmap scan report for test.target.local (10.0.0.10)
Host is up (0.001s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
"""
    r_text = UniversalParser.parse(nmap_text, "nmap", "10.0.0.10")
    assert len(r_text.services) == 1
    assert r_text.services[0].port == 80


# =============================================================================
# 3. Universal Parser: Nikto JSON & Text
# =============================================================================
def test_universal_parser_nikto_json_and_text():
    nikto_json = {
        "host": "10.0.0.5",
        "port": "8080",
        "banner": "Apache-Coyote/1.1",
        "items": [
            {
                "msg": "OSVDB-3092: /admin/login.jsp: Admin portal found without authentication.",
                "uri": "/admin/login.jsp",
                "method": "GET",
            },
            {
                "msg": "Retrieved x-frame-options header is missing.",
                "uri": "/",
                "method": "HEAD",
            },
        ],
    }

    result = UniversalParser.parse(json.dumps(nikto_json), "nikto", "10.0.0.5")
    assert result.success is True
    assert len(result.services) == 1
    assert result.services[0].banner == "Apache-Coyote/1.1"
    assert len(result.findings) == 2

    admin_f = next(f for f in result.findings if "admin" in f.title.lower())
    assert admin_f.severity == FindingSeverity.HIGH
    assert admin_f.port == 8080


# =============================================================================
# 4. Universal Parser: SQLMap Output
# =============================================================================
def test_universal_parser_sqlmap_output():
    sqlmap_stdout = """
[10:15:30] [INFO] GET parameter 'user_id' is vulnerable.
Parameter: user_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: user_id=1 AND 8821=8821
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: user_id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x717078,0x44)
back-end DBMS: PostgreSQL 14.1
"""

    result = UniversalParser.parse(sqlmap_stdout, "sqlmap", "http://10.0.0.5/api/users")
    assert result.success is True
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == FindingSeverity.CRITICAL
    assert f.cwe_id == "CWE-89"
    assert f.validation_status == ValidationStatus.CONFIRMED
    assert "PostgreSQL" in f.description
    assert "user_id" in f.title


# =============================================================================
# 5. Universal Parser: WAFW00F, Gobuster, FFUF
# =============================================================================
def test_universal_parser_waf_gobuster_ffuf():
    # WAFW00F
    waf_out = "The site https://target.com is behind AWS WAF (Amazon)"
    r_waf = UniversalParser.parse(waf_out, "wafw00f", "https://target.com")
    assert len(r_waf.findings) == 1
    assert "AWS WAF" in r_waf.findings[0].title

    # Gobuster
    gobuster_out = """
/login (Status: 200) [Size: 2048]
/.git/HEAD (Status: 200) [Size: 42]
/secret (Status: 301) [Size: 180] [--> http://target.com/secret/]
"""
    r_gob = UniversalParser.parse(gobuster_out, "gobuster", "http://target.com")
    assert len(r_gob.findings) == 3
    git_f = next(f for f in r_gob.findings if ".git" in f.affected_asset)
    assert git_f.severity == FindingSeverity.MEDIUM
    assert git_f.validation_status == ValidationStatus.NEEDS_VALIDATION

    # FFUF
    ffuf_out = {
        "results": [
            {"url": "http://target.com/.env", "status": 200, "length": 512, "words": 20},
        ]
    }
    r_ffuf = UniversalParser.parse(json.dumps(ffuf_out), "ffuf", "http://target.com")
    assert len(r_ffuf.findings) == 1
    assert ".env" in r_ffuf.findings[0].title


# =============================================================================
# 6. Parser Error Resilience on Corrupted Input
# =============================================================================
def test_universal_parser_error_resilience_and_corrupted_output():
    # Malformed XML should not crash; it logs warning and recovers partials
    corrupted_xml = """<nmaprun args="nmap -sV target"><host><status state="up"/><ports>
    <port portid="80" protocol="tcp"><state state="open"/></port>"""
    r = UniversalParser.parse(corrupted_xml, "nmap", "target")
    assert r.raw_evidence_hash != ""
    assert len(r.services) >= 1
    assert len(r.parser_warnings) == 0 or any("falling back" in w.lower() or "error" in w.lower() for w in r.parser_warnings)


# =============================================================================
# 7. Evidence Intelligence: Zero Unbacked Confirmed Findings Guard
# =============================================================================
def test_evidence_intelligence_zero_unbacked_confirmed_findings(
    isolated_db: Database,
    test_project: Project,
    tmp_path: Path,
):
    ev_service = EvidenceIntelligenceService(isolated_db)

    # 1. Finding claiming CONFIRMED but without evidence record
    unbacked_finding = isolated_db.create_finding(
        Finding(
            project_id=test_project.id,
            title="Unbacked RCE Claim",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.0.0.1",
            validation_status=ValidationStatus.CONFIRMED,
        )
    )

    allowed, msg = ev_service.enforce_confirmed_evidence_guard(unbacked_finding, project_id=test_project.id)
    assert allowed is False
    assert unbacked_finding.validation_status == ValidationStatus.NEEDS_VALIDATION
    assert "UNBACKED DOWNGRADE" in unbacked_finding.severity_rationale

    # 2. Finding with authentic, verified evidence file
    ev_file = tmp_path / "valid_proof.txt"
    payload = "HTTP/1.1 200 OK\n\nConfirmed SQL Injection payload response"
    ev_file.write_text(payload, encoding="utf-8")
    sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    evidence = isolated_db.add_evidence(
        Evidence(
            project_id=test_project.id,
            file_path=str(ev_file),
            sha256_hash=sha256,
            description="Verified HTTP probe output",
        )
    )

    backed_finding = isolated_db.create_finding(
        Finding(
            project_id=test_project.id,
            title="Backed SQL Injection",
            severity=FindingSeverity.CRITICAL,
            affected_asset="10.0.0.1",
            validation_status=ValidationStatus.CONFIRMED,
        )
    )
    # Associate evidence
    with isolated_db.session() as conn:
        conn.execute("UPDATE evidence SET finding_id = ? WHERE id = ?", (backed_finding.id, evidence.id))

    allowed2, msg2 = ev_service.enforce_confirmed_evidence_guard(backed_finding, project_id=test_project.id)
    assert allowed2 is True
    assert backed_finding.validation_status == ValidationStatus.CONFIRMED


# =============================================================================
# 8. Asset & Service Correlation with Provenance & Observations
# =============================================================================
def test_asset_service_correlation_deduplication_and_provenance(
    isolated_db: Database,
    test_project: Project,
):
    # Add authorized scope for engagement
    isolated_db.add_scope(
        TargetScope(
            project_id=test_project.id,
            target="192.168.1.0/24",
            is_authorized=True,
        )
    )

    correlator = AssetServiceCorrelator(isolated_db)

    # Ingest Nmap scan results
    services_nmap = [
        NormalizedService(
            host="192.168.1.100",
            port=80,
            protocol="tcp",
            service_name="http",
            product="Apache httpd",
            version="2.4.41",
            source_tool="nmap",
        ),
        NormalizedService(
            host="192.168.1.100",
            port=22,
            protocol="tcp",
            service_name="ssh",
            product="OpenSSH",
            version="8.2p1",
            source_tool="nmap",
        ),
    ]

    summary1 = correlator.correlate_services(
        project_id=test_project.id,
        services=services_nmap,
        source_tool="nmap",
    )

    assert summary1.hosts_updated == 1
    assert len(summary1.nodes) == 1
    node = summary1.nodes[0]
    assert node.value == "192.168.1.100"

    # Ingest Nikto findings on the same host
    services_nikto = [
        NormalizedService(
            host="192.168.1.100",
            port=80,
            protocol="tcp",
            service_name="http",
            banner="Apache/2.4.41 (Ubuntu)",
            source_tool="nikto",
        ),
    ]

    summary2 = correlator.correlate_services(
        project_id=test_project.id,
        services=services_nikto,
        source_tool="nikto",
    )

    # AssetNode must be deduplicated, not duplicated
    all_nodes = isolated_db.list_asset_nodes(test_project.id)
    assert len(all_nodes) == 1

    # Node metadata must preserve multi-tool provenance
    meta = json.loads(all_nodes[0].metadata_json)
    assert "nmap" in meta.get("sources", [])
    assert "nikto" in meta.get("sources", [])

    # Observations must preserve historical scan timeline
    obs = isolated_db.list_observations(test_project.id)
    assert len(obs) >= 2


# =============================================================================
# 9. Cross-Tool Finding Correlation & Deduplication
# =============================================================================
def test_cross_tool_finding_correlation_and_consensus():
    correlator = FindingCorrelator()

    # Tool 1: Nmap reports weak TLS
    f1 = NormalizedFinding(
        title="Nmap: ssl-enum-ciphers on 10.0.0.1:443 (TLSv1.0 weak ciphers)",
        severity=FindingSeverity.MEDIUM,
        affected_asset="10.0.0.1",
        affected_service="443/tcp",
        port=443,
        source_tool="nmap",
        confidence=0.9,
        validation_status=ValidationStatus.OBSERVED,
    )

    # Tool 2: Nikto reports deprecated TLSv1.0
    f2 = NormalizedFinding(
        title="Nikto: Deprecated TLSv1.0 protocol enabled on 10.0.0.1:443",
        severity=FindingSeverity.LOW,
        affected_asset="10.0.0.1",
        affected_service="443/tcp",
        port=443,
        source_tool="nikto",
        confidence=0.85,
        validation_status=ValidationStatus.OBSERVED,
    )

    # Distinct finding on different port
    f3 = NormalizedFinding(
        title="Nmap: SSH weak MAC algorithms on 10.0.0.1:22",
        severity=FindingSeverity.LOW,
        affected_asset="10.0.0.1",
        affected_service="22/tcp",
        port=22,
        source_tool="nmap",
        confidence=0.9,
    )

    correlated = correlator.correlate_findings([f1, f2, f3])
    # f1 and f2 should merge because they address the exact same TLS issue on port 443
    assert len(correlated) == 2

    tls_merged = next(f for f in correlated if f.port == 443)
    assert tls_merged.severity == FindingSeverity.MEDIUM
    assert "nmap" in tls_merged.source_tool
    assert "nikto" in tls_merged.source_tool
    assert "Cross-Tool Corroboration" in tls_merged.description
    assert tls_merged.confidence > 0.9


# =============================================================================
# 10. Curated Offline CVE & CVSS Enrichment
# =============================================================================
def test_cve_enrichment_deterministic_matching_and_status_demarcation():
    # 1. Apache 2.4.49 -> CVE-2021-41773
    svc_apache = NormalizedService(
        host="10.0.0.1",
        port=80,
        product="Apache httpd",
        version="2.4.49",
    )
    findings = CVEEnrichmentService.enrich_service(svc_apache)
    assert len(findings) >= 1
    f = findings[0]
    assert "CVE-2021-41773" in f.cve_ids
    assert f.cvss_score == 9.8
    assert f.severity == FindingSeverity.CRITICAL
    # Crucial rule: Software version banner matching is heuristic; MUST NOT be CONFIRMED
    assert f.validation_status == ValidationStatus.NEEDS_VALIDATION
    assert f.confidence <= 0.70

    # 2. OpenSSH regreSSHion
    svc_ssh = NormalizedService(
        host="10.0.0.1",
        port=22,
        product="OpenSSH",
        version="9.6p1",
    )
    ssh_findings = CVEEnrichmentService.enrich_service(svc_ssh)
    assert len(ssh_findings) >= 1
    assert "CVE-2024-6387" in ssh_findings[0].cve_ids


# =============================================================================
# 11. Historical Scan Comparison & Delta Classification
# =============================================================================
def test_historical_scan_comparison_delta_report():
    comparator = HistoricalComparator()

    f_old1 = NormalizedFinding(
        title="Directory Indexing /icons",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="10.0.0.1",
        affected_service="80/tcp",
        port=80,
    )
    f_old2 = NormalizedFinding(
        title="Apache Path Traversal",
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        affected_asset="10.0.0.1",
        affected_service="80/tcp",
        port=80,
        cve_ids=["CVE-2021-41773"],
    )

    # Current scan:
    # 1. f_old1 is still present -> PERSISTENT
    # 2. f_old2 escalated to CRITICAL -> CHANGED
    # 3. SQLi discovered -> NEW
    # 4. Old service on port 21 is gone -> RESOLVED
    f_curr1 = NormalizedFinding(
        title="Directory Indexing /icons",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="10.0.0.1",
        affected_service="80/tcp",
        port=80,
    )
    f_curr2 = NormalizedFinding(
        title="Apache Path Traversal",
        severity=FindingSeverity.CRITICAL,  # changed severity
        cvss_score=9.8,                     # changed cvss
        affected_asset="10.0.0.1",
        affected_service="80/tcp",
        port=80,
        cve_ids=["CVE-2021-41773"],
    )
    f_curr3 = NormalizedFinding(
        title="SQL Injection on login",
        severity=FindingSeverity.CRITICAL,
        affected_asset="10.0.0.1",
        affected_service="80/tcp",
        port=80,
    )
    f_old_resolved = NormalizedFinding(
        title="vsftpd Anonymous Login",
        severity=FindingSeverity.MEDIUM,
        affected_asset="10.0.0.1",
        affected_service="21/tcp",
        port=21,
    )

    prior = [f_old1, f_old2, f_old_resolved]
    current = [f_curr1, f_curr2, f_curr3]

    report = comparator.compare_executions(
        project_id=1,
        prior_findings=prior,
        current_findings=current,
        rescanned_assets={"10.0.0.1"},
    )

    assert len(report.persistent_findings) == 1
    assert len(report.changed_findings) == 1
    assert len(report.new_findings) == 1
    assert len(report.resolved_findings) == 1
    assert report.risk_trend == "DEGRADING"  # new critical findings added


# =============================================================================
# 12. AI Data Analyst: Mandatory Citations & Anti-Hallucination Guard
# =============================================================================
def test_ai_data_analyst_evidence_citations_and_anti_hallucination():
    engine = AIDataAnalystEngine()

    findings = [
        NormalizedFinding(
            title="SQL Injection on Parameter id",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://10.0.0.1/search.php",
            evidence_id=101,
            raw_evidence_hash="hash_sqlmap_proof_123",
            source_tool="sqlmap",
            validation_status=ValidationStatus.CONFIRMED,
        ),
        NormalizedFinding(
            title="Potential CVE-2021-41773 Apache Path Traversal",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://10.0.0.1",
            evidence_id=102,
            raw_evidence_hash="hash_nmap_proof_456",
            source_tool="cve_enrichment",
            validation_status=ValidationStatus.NEEDS_VALIDATION,
        ),
    ]

    report = engine.analyze_project(project_id=1, findings=findings)

    # 1. Every finding must have a corresponding citation with evidence ID
    assert len(report.citations) == 2
    cit_sql = next(c for c in report.citations if "SQL" in c.finding_title)
    assert cit_sql.evidence_id == 101
    assert cit_sql.evidence_hash == "hash_sqlmap_proof_123"

    # 2. Unconfirmed finding must be explicitly tagged as NEEDS_VALIDATION
    assert len(report.unvalidated_inferences) >= 1
    assert "NEEDS_VALIDATION" in report.unvalidated_inferences[0]

    # 3. Attack path chain must be generated from confirmed SQLi
    assert len(report.attack_paths) >= 1
    assert any("SQL Injection" in p.chain_name for p in report.attack_paths)

    # 4. Remediation roadmap generated
    assert len(report.prioritized_remediations) >= 1
    assert any("P0" in r for r in report.prioritized_remediations)
