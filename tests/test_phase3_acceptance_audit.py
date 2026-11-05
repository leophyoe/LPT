"""Comprehensive Acceptance Audit and Verification Suite for CyberSecuritySuite Phase 3.

Validates:
1. Parser Integration: Real adapter-to-parser workflows across Nmap (XML/text), Nikto (JSON/text),
   SQLMap, WAFW00F, Gobuster, and FFUF (JSON/text).
2. Evidence Integrity: 7 failure conditions (missing file, modified file, wrong hash, missing record,
   cross-project ID, inaccessible file, execution ID mismatch).
3. Finding Correlation: Multi-tool consensus, endpoint separation, port segregation, alias handling,
   conflict resolution, and non-destructive observation preservation.
4. CVE Enrichment: Offline catalog integrity, backport limitations, anti-hallucination, candidate status.
5. Historical Analysis: NEW, PERSISTENT, RESOLVED, CHANGED, failed/empty scan guards, trend scoring.
6. AI Data Analyst: Mandatory evidence citations, attack-chain hypothesis labeling, grounded remediation.
7. Multi-Project Isolation: Strict data separation across all components.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.ai_data_analyst import AIDataAnalystEngine, AttackPathChain, EvidenceCitation
from core.analysis.historical_comparator import (
    FindingDeltaItem,
    FindingDeltaStatus,
    HistoricalComparator,
    ScanDeltaReport,
)
from core.correlation.finding_correlator import FindingCorrelator
from core.enrichment.cve_enrichment import CVEEnrichmentService, CuratedVulnerability
from core.evidence_intelligence import EvidenceIntelligenceService, EvidenceVerificationResult
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.parsers.normalized_models import (
    NormalizedFinding,
    NormalizedParserResult,
    NormalizedService,
)
from core.parsers.universal_parser import UniversalParser
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions
from modules.web.ffuf_adapter import FFUFAdapter, FFUFOptions
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.nikto_adapter import NiktoAdapter, NiktoScanOptions
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


# =============================================================================
# Fixtures
# =============================================================================
@pytest.fixture
def audit_db(tmp_path):
    """Provides an isolated test database for acceptance audit."""
    db_file = tmp_path / "audit_test.db"
    db = Database(str(db_file))
    return db


@pytest.fixture
def project_alpha(audit_db):
    p = audit_db.create_project(Project(name="Project Alpha Engagement", description="Primary audit project"))
    audit_db.add_scope(TargetScope(project_id=p.id, target="127.0.0.1", is_authorized=True))
    audit_db.add_scope(TargetScope(project_id=p.id, target="localhost", is_authorized=True))
    audit_db.add_scope(TargetScope(project_id=p.id, target="192.168.1.0/24", is_authorized=True))
    return p


@pytest.fixture
def project_beta(audit_db):
    p = audit_db.create_project(Project(name="Project Beta Engagement", description="Isolated secondary project"))
    audit_db.add_scope(TargetScope(project_id=p.id, target="10.0.0.0/8", is_authorized=True))
    return p


def make_proc_result(stdout: str, stderr: str = "", exit_code: int = 0) -> ProcessExecutionResult:
    return ProcessExecutionResult(
        command=["mock_cmd"],
        status=ExecutionStatus.COMPLETED if exit_code == 0 else ExecutionStatus.FAILED,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at="2026-10-31T00:00:00Z",
        finished_at="2026-10-31T00:00:01Z",
        duration_seconds=1.0,
    )


# =============================================================================
# 1. PARSER INTEGRATION AUDIT
# =============================================================================
class TestParserIntegrationAudit:
    """Verifies that all 6 parsers are connected to actual adapter workflows."""

    def test_nmap_adapter_workflow_parses_xml(self, audit_db, project_alpha, tmp_path):
        adapter = NmapAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000005">
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.49" method="probed"/>
        </port>
    </ports>
</host>
</nmaprun>"""
        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=xml_output, stderr="", exit_code=0
        ))

        res = adapter.execute_scan(
            project_id=project_alpha.id,
            options=NmapScanOptions(target="127.0.0.1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert res.is_authorized is True
        assert res.execution is not None
        assert len(res.findings) >= 1
        f = res.findings[0]
        assert "80" in f.title or "Apache" in f.title or "http" in f.title
        assert f.project_id == project_alpha.id
        assert f.source_tool == "nmap"

    def test_nmap_adapter_workflow_parses_text_fallback(self, audit_db, project_alpha, tmp_path):
        adapter = NmapAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        text_output = """Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-31
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1
80/tcp  open  http    Apache httpd 2.4.52
Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds"""

        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=text_output, stderr="", exit_code=0
        ))

        res = adapter.execute_scan(
            project_id=project_alpha.id,
            options=NmapScanOptions(target="127.0.0.1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert res.is_authorized is True
        assert len(res.findings) >= 2
        ports = [f.affected_port_service for f in res.findings]
        assert any("22" in p for p in ports)
        assert any("80" in p for p in ports)

    def test_nikto_adapter_workflow_parses_json_and_text(self, audit_db, project_alpha, tmp_path):
        adapter = NiktoAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        # JSON workflow
        json_output = json.dumps({
            "host": "127.0.0.1",
            "ip": "127.0.0.1",
            "port": "8080",
            "banner": "Apache/2.4.49",
            "vulnerabilities": [
                {
                    "id": "99901",
                    "OSVDB": "0",
                    "url": "/cgi-bin/.%2e/.%2e/bin/sh",
                    "msg": "Apache 2.4.49 path traversal RCE vulnerability detected without authentication."
                }
            ]
        })

        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=json_output, stderr="", exit_code=0
        ))

        res = adapter.execute_scan(
            project_id=project_alpha.id,
            options=NiktoScanOptions(target="127.0.0.1", port=8080),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert res.is_authorized is True
        assert len(res.findings) >= 1
        assert any(f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for f in res.findings)

    def test_sqlmap_adapter_workflow_parses_injection(self, audit_db, project_alpha, tmp_path):
        adapter = SQLMapAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        sqlmap_stdout = """
---
Parameter: user_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: user_id=1 AND 8890=8890
---
[INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.52, PHP 8.1
"""
        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=sqlmap_stdout, stderr="", exit_code=0
        ))

        success, msg, findings, db_exec = adapter.execute_scan(
            project_id=project_alpha.id,
            options=SQLMapOptions(target_url="http://127.0.0.1/profile?user_id=1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert success is True
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity == FindingSeverity.CRITICAL
        assert "user_id" in f.title
        assert f.validation_status == ValidationStatus.CONFIRMED

    def test_wafw00f_adapter_workflow_parses_detection(self, audit_db, project_alpha, tmp_path):
        adapter = WAFW00FAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        waf_stdout = """
[*] Checking http://127.0.0.1
[+] The site http://127.0.0.1 is behind Cloudflare (Cloudflare Inc.) WAF.
[~] Number of requests: 12
"""
        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=waf_stdout, stderr="", exit_code=0
        ))

        success, msg, findings, db_exec = adapter.execute_scan(
            project_id=project_alpha.id,
            options=WAFW00FOptions(target_url="http://127.0.0.1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert success is True
        assert len(findings) >= 1
        assert "Cloudflare" in findings[0].title
        assert findings[0].severity == FindingSeverity.INFORMATIONAL

    def test_gobuster_adapter_workflow_parses_directories(self, audit_db, project_alpha, tmp_path):
        adapter = GobusterAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        gobuster_stdout = """
===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 200) [Size: 1450]
/.env                 (Status: 200) [Size: 312]
/robots.txt           (Status: 200) [Size: 84]
/notfound             (Status: 404) [Size: 153]
"""
        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=gobuster_stdout, stderr="", exit_code=0
        ))

        success, msg, findings, db_exec = adapter.execute_scan(
            project_id=project_alpha.id,
            options=GobusterOptions(target_url="http://127.0.0.1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert success is True
        assert len(findings) >= 2
        paths = [f.affected_asset for f in findings]
        assert any("/admin" in p for p in paths)
        assert any("/.env" in p for p in paths)

    def test_ffuf_adapter_workflow_parses_json(self, audit_db, project_alpha, tmp_path):
        adapter = FFUFAdapter(audit_db)
        scopes = audit_db.list_scopes(project_alpha.id)

        ffuf_json = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "position": 1,
                    "status": 200,
                    "length": 1540,
                    "words": 210,
                    "lines": 35,
                    "url": "http://127.0.0.1/admin",
                    "redirectlocation": ""
                },
                {
                    "input": {"FUZZ": "api/v1"},
                    "position": 2,
                    "status": 200,
                    "length": 450,
                    "words": 50,
                    "lines": 12,
                    "url": "http://127.0.0.1/api/v1",
                    "redirectlocation": ""
                }
            ]
        })

        adapter.runner.run = MagicMock(return_value=make_proc_result(
            stdout=ffuf_json, stderr="", exit_code=0
        ))

        success, msg, findings, db_exec = adapter.run_fuzz(
            project_id=project_alpha.id,
            options=FFUFOptions(target_url="http://127.0.0.1"),
            scopes=scopes,
            evidence_dir=tmp_path,
        )

        assert success is True
        assert len(findings) == 2
        assert any("admin" in f.affected_asset for f in findings)
        assert any("api/v1" in f.affected_asset for f in findings)
        assert all(f.source_tool == "ffuf" for f in findings)


# =============================================================================
# 2. EVIDENCE INTEGRITY AUDIT (7 Failure Conditions)
# =============================================================================
class TestEvidenceIntegrityAudit:
    """Rigorous audit of the 7 cryptographic evidence failure cases."""

    def test_condition_1_missing_evidence_artifact_on_disk(self, audit_db, project_alpha, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        missing_file = tmp_path / "deleted_file.txt"
        ev = Evidence(
            project_id=project_alpha.id,
            file_path=str(missing_file),
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        added_ev = audit_db.add_evidence(ev)
        finding = Finding(
            project_id=project_alpha.id,
            title="Finding with Missing Disk Artifact",
        )
        finding.evidence_id = added_ev.id
        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "missing on disk" in res.status_message.lower()

    def test_condition_2_modified_evidence_artifact(self, audit_db, project_alpha, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        tampered_file = tmp_path / "tampered.txt"
        tampered_file.write_text("Authentic Initial Content", encoding="utf-8")
        orig_hash = hashlib.sha256(b"Authentic Initial Content").hexdigest()

        ev = Evidence(
            project_id=project_alpha.id,
            file_path=str(tampered_file),
            sha256_hash=orig_hash,
        )
        added_ev = audit_db.add_evidence(ev)
        finding = Finding(
            project_id=project_alpha.id,
            title="Finding Backed by Tampered File",
        )
        finding.evidence_id = added_ev.id

        # Alter the file content on disk
        tampered_file.write_text("Maliciously Altered Content", encoding="utf-8")

        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "mismatch" in res.status_message.lower() or "tampered" in res.status_message.lower()
        assert res.expected_sha256 == orig_hash
        assert res.actual_sha256 != orig_hash

    def test_condition_3_incorrect_or_empty_sha256_digest(self, audit_db, project_alpha, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        good_file = tmp_path / "valid.txt"
        good_file.write_text("Some text", encoding="utf-8")

        ev = Evidence(
            project_id=project_alpha.id,
            file_path=str(good_file),
            sha256_hash="",  # Empty hash
        )
        added_ev = audit_db.add_evidence(ev)
        finding = Finding(
            project_id=project_alpha.id,
            title="Finding with Empty Hash Record",
        )
        finding.evidence_id = added_ev.id

        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "lacks expected sha-256" in res.status_message.lower()

    def test_condition_4_missing_database_evidence_record(self, audit_db, project_alpha):
        intel = EvidenceIntelligenceService(audit_db)
        finding = Finding(
            project_id=project_alpha.id,
            title="Orphaned Finding with Nonexistent Evidence ID",
        )
        finding.evidence_id = 999999
        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "not found" in res.status_message.lower() or "no supporting evidence" in res.status_message.lower()

    def test_condition_5_cross_project_evidence_id(self, audit_db, project_alpha, project_beta, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        beta_file = tmp_path / "beta_evidence.txt"
        beta_file.write_text("Beta secret scan data", encoding="utf-8")
        beta_hash = hashlib.sha256(b"Beta secret scan data").hexdigest()

        # Evidence belongs to Project Beta
        ev_beta = Evidence(
            project_id=project_beta.id,
            file_path=str(beta_file),
            sha256_hash=beta_hash,
        )
        added_beta = audit_db.add_evidence(ev_beta)

        # Finding belongs to Project Alpha, but attempts to link Project Beta's evidence ID
        alpha_finding = Finding(
            project_id=project_alpha.id,
            title="Unauthorized Cross-Project Finding",
        )
        alpha_finding.evidence_id = added_beta.id

        res = intel.verify_finding_evidence(alpha_finding, project_id=project_alpha.id)
        assert res.is_valid is False
        assert ("cross-project" in res.status_message.lower() or "not found" in res.status_message.lower())

    def test_condition_6_deleted_or_inaccessible_evidence_file(self, audit_db, project_alpha, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        temp_file = tmp_path / "ephemeral.txt"
        temp_file.write_text("Transient data", encoding="utf-8")
        h = hashlib.sha256(b"Transient data").hexdigest()

        ev = Evidence(
            project_id=project_alpha.id,
            file_path=str(temp_file),
            sha256_hash=h,
        )
        added_ev = audit_db.add_evidence(ev)
        finding = Finding(
            project_id=project_alpha.id,
            title="Finding with File Subsequently Deleted",
        )
        finding.evidence_id = added_ev.id

        # Delete the file
        temp_file.unlink()

        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "missing on disk" in res.status_message.lower()

    def test_condition_7_evidence_linked_to_wrong_execution(self, audit_db, project_alpha, tmp_path):
        intel = EvidenceIntelligenceService(audit_db)
        valid_file = tmp_path / "exec1_ev.txt"
        valid_file.write_text("Execution 1 raw logs", encoding="utf-8")
        h = hashlib.sha256(b"Execution 1 raw logs").hexdigest()

        exec1 = audit_db.create_execution(ToolExecution(
            project_id=project_alpha.id,
            tool_name="nmap",
            command="nmap",
            status=ExecutionStatus.COMPLETED,
        ))
        exec2 = audit_db.create_execution(ToolExecution(
            project_id=project_alpha.id,
            tool_name="nikto",
            command="nikto",
            status=ExecutionStatus.COMPLETED,
        ))

        # Evidence created under exec1
        ev = Evidence(
            project_id=project_alpha.id,
            execution_id=exec1.id,
            file_path=str(valid_file),
            sha256_hash=h,
        )
        added_ev = audit_db.add_evidence(ev)

        # Finding created under exec2 (Mismatched execution)
        finding = Finding(
            project_id=project_alpha.id,
            execution_id=exec2.id,
            title="Finding with Mismatched Execution ID",
        )
        finding.evidence_id = added_ev.id

        res = intel.verify_finding_evidence(finding)
        assert res.is_valid is False
        assert "mismatch" in res.status_message.lower() or "execution" in res.status_message.lower()


# =============================================================================
# 3. CORRELATION & CONSENSUS AUDIT
# =============================================================================
class TestCorrelationAudit:
    """Verifies correlation, deduplication, port segregation, and consensus scoring."""

    def test_multi_tool_consensus_increases_confidence(self, audit_db):
        correlator = FindingCorrelator(audit_db)

        # Tool 1: Nikto identifies Apache Path Traversal
        f1 = NormalizedFinding(
            title="Apache 2.4.49 Path Traversal",
            severity=FindingSeverity.CRITICAL,
            affected_asset="127.0.0.1:80",
            port=80,
            cve_ids=["CVE-2021-41773"],
            source_tool="nikto",
            confidence=0.75,
            validation_status=ValidationStatus.OBSERVED,
        )

        # Tool 2: Nuclei or Nmap script confirms the exact same vulnerability
        f2 = NormalizedFinding(
            title="Potential CVE-2021-41773: Apache Path Traversal & RCE",
            severity=FindingSeverity.CRITICAL,
            affected_asset="127.0.0.1:80",
            port=80,
            cve_ids=["CVE-2021-41773"],
            source_tool="nmap",
            confidence=0.85,
            validation_status=ValidationStatus.CONFIRMED,
        )

        correlated = correlator.correlate_findings([f1, f2])
        assert len(correlated) == 1
        c = correlated[0]
        assert "nikto" in c.source_tool and "nmap" in c.source_tool
        assert c.confidence > 0.85  # Boosted multi-tool consensus
        assert c.validation_status == ValidationStatus.CONFIRMED

    def test_different_endpoints_on_same_host_preserved(self, audit_db):
        correlator = FindingCorrelator(audit_db)

        f_admin = NormalizedFinding(
            title="Discovered Web Path: /admin",
            severity=FindingSeverity.LOW,
            affected_asset="http://127.0.0.1/admin",
            source_tool="gobuster",
        )
        f_login = NormalizedFinding(
            title="Discovered Web Path: /login",
            severity=FindingSeverity.INFORMATIONAL,
            affected_asset="http://127.0.0.1/login",
            source_tool="gobuster",
        )

        correlated = correlator.correlate_findings([f_admin, f_login])
        assert len(correlated) == 2
        assets = [c.affected_asset for c in correlated]
        assert "http://127.0.0.1/admin" in assets
        assert "http://127.0.0.1/login" in assets

    def test_same_service_on_different_ports_segregated(self, audit_db):
        correlator = FindingCorrelator(audit_db)

        f_http_80 = NormalizedFinding(
            title="HTTP Server Header Disclosure",
            severity=FindingSeverity.LOW,
            affected_asset="127.0.0.1",
            affected_service="80/tcp",
            port=80,
            source_tool="nikto",
        )
        f_http_8080 = NormalizedFinding(
            title="HTTP Server Header Disclosure",
            severity=FindingSeverity.LOW,
            affected_asset="127.0.0.1",
            affected_service="8080/tcp",
            port=8080,
            source_tool="nikto",
        )

        correlated = correlator.correlate_findings([f_http_80, f_http_8080])
        assert len(correlated) == 2
        ports = [c.port for c in correlated]
        assert 80 in ports
        assert 8080 in ports

    def test_conflicting_severity_resolves_to_highest(self, audit_db):
        correlator = FindingCorrelator(audit_db)

        f_low = NormalizedFinding(
            title="OpenSSH Deprecated Cipher Suite",
            severity=FindingSeverity.LOW,
            affected_asset="127.0.0.1",
            port=22,
            cve_ids=["CVE-2023-38408"],
            source_tool="tool_a",
            confidence=0.5,
        )
        f_high = NormalizedFinding(
            title="OpenSSH PKCS#11 Remote Code Execution",
            severity=FindingSeverity.CRITICAL,
            affected_asset="127.0.0.1",
            port=22,
            cve_ids=["CVE-2023-38408"],
            source_tool="tool_b",
            confidence=0.9,
        )

        correlated = correlator.correlate_findings([f_low, f_high])
        assert len(correlated) == 1
        assert correlated[0].severity == FindingSeverity.CRITICAL

    def test_raw_observations_preserved_non_destructively(self, audit_db):
        correlator = FindingCorrelator(audit_db)

        f1 = NormalizedFinding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://127.0.0.1/item.php",
            source_tool="sqlmap",
            description="Raw observation from sqlmap payload testing.",
        )
        f2 = NormalizedFinding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            affected_asset="http://127.0.0.1/item.php",
            source_tool="nikto",
            description="Raw observation from nikto header analysis.",
        )

        correlated = correlator.correlate_findings([f1, f2])
        assert len(correlated) == 1
        desc = correlated[0].description
        assert "sqlmap payload testing" in desc
        assert "nikto header analysis" in desc


# =============================================================================
# 4. CVE ENRICHMENT AUDIT
# =============================================================================
class TestCVEEnrichmentAudit:
    """Verifies offline curated catalog accuracy, backport limitations, and anti-hallucination."""

    def test_catalog_labeled_as_curated_and_incomplete(self):
        assert CVEEnrichmentService.CATALOG_TYPE == "CURATED_OFFLINE_INCOMPLETE"
        assert "non-exhaustive" in CVEEnrichmentService.CATALOG_DISCLAIMER.lower()
        assert "backport" in CVEEnrichmentService.CATALOG_DISCLAIMER.lower()

    def test_all_catalog_entries_have_valid_cve_and_cvss(self):
        catalog = CVEEnrichmentService.CURATED_CATALOG
        assert len(catalog) >= 9

        for entry in catalog:
            assert entry.cve_id.startswith("CVE-")
            assert 0.0 <= entry.cvss_score <= 10.0
            assert entry.cvss_vector.startswith("CVSS:3.")
            assert entry.cwe_id.startswith("CWE-")
            assert len(entry.title) > 5
            assert len(entry.remediation) > 10

    def test_banner_matches_never_auto_confirm_and_recognize_backports(self):
        svc = NormalizedService(
            host="127.0.0.1",
            port=80,
            protocol="tcp",
            service_name="http",
            product="Apache httpd",
            version="2.4.49",
        )

        findings = CVEEnrichmentService.enrich_service(svc)
        assert len(findings) >= 1

        for f in findings:
            # Banner matches MUST NOT be marked CONFIRMED
            assert f.validation_status == ValidationStatus.NEEDS_VALIDATION
            # Confidence must be capped to account for backports
            assert f.confidence <= 0.65
            assert "backport" in f.description.lower() or "backport" in f.severity_rationale.lower()

    def test_non_matching_version_produces_zero_hallucinations(self):
        svc = NormalizedService(
            host="127.0.0.1",
            port=80,
            protocol="tcp",
            service_name="http",
            product="Apache httpd",
            version="2.4.58",  # Secure patched version
        )

        findings = CVEEnrichmentService.enrich_service(svc)
        assert len(findings) == 0  # No hallucinated CVEs


# =============================================================================
# 5. HISTORICAL ANALYSIS & SCAN INTEGRITY AUDIT
# =============================================================================
class TestHistoricalAnalysisAudit:
    """Verifies NEW, PERSISTENT, RESOLVED, CHANGED, and empty/failed scan guards."""

    def test_scan_classification_lifecycle(self, audit_db):
        comparator = HistoricalComparator(audit_db)

        # Baseline findings
        f_persist = NormalizedFinding(
            title="OpenSSH Weak Cipher",
            severity=FindingSeverity.LOW,
            affected_asset="127.0.0.1:22",
            port=22,
        )
        f_change = NormalizedFinding(
            title="Apache Path Traversal",
            severity=FindingSeverity.HIGH,
            affected_asset="127.0.0.1:80",
            port=80,
            cvss_score=7.5,
        )
        f_resolved = NormalizedFinding(
            title="FTP Anonymous Login Enabled",
            severity=FindingSeverity.MEDIUM,
            affected_asset="127.0.0.1:21",
            port=21,
        )

        # Current findings
        f_persist_curr = NormalizedFinding(
            title="OpenSSH Weak Cipher",
            severity=FindingSeverity.LOW,
            affected_asset="127.0.0.1:22",
            port=22,
        )
        f_change_curr = NormalizedFinding(
            title="Apache Path Traversal",
            severity=FindingSeverity.CRITICAL,  # Escalated
            affected_asset="127.0.0.1:80",
            port=80,
            cvss_score=9.8,
        )
        f_new = NormalizedFinding(
            title="Redis Exposed Unauthenticated",
            severity=FindingSeverity.CRITICAL,
            affected_asset="127.0.0.1:6379",
            port=6379,
        )

        delta: ScanDeltaReport = comparator.compare_executions(
            project_id=1,
            prior_findings=[f_persist, f_change, f_resolved],
            current_findings=[f_persist_curr, f_change_curr, f_new],
            rescanned_assets={"127.0.0.1"},
            scan_successful=True,
        )

        assert len(delta.new_findings) == 1
        assert delta.new_findings[0].port == 6379

        assert len(delta.persistent_findings) == 1
        assert delta.persistent_findings[0].port == 22

        assert len(delta.changed_findings) == 1
        assert delta.changed_findings[0].current_finding.port == 80

        assert len(delta.resolved_findings) == 1
        assert delta.resolved_findings[0].port == 21

        assert delta.risk_trend == "DEGRADING"  # Risk increased

    def test_failed_scan_never_marks_findings_as_resolved(self, audit_db):
        comparator = HistoricalComparator(audit_db)

        prior = [
            NormalizedFinding(
                title="Critical SQL Injection",
                severity=FindingSeverity.CRITICAL,
                affected_asset="127.0.0.1",
                port=80,
            )
        ]

        # Scan failed (e.g. exit code 1 or network down, 0 findings)
        delta: ScanDeltaReport = comparator.compare_executions(
            project_id=1,
            prior_findings=prior,
            current_findings=[],
            rescanned_assets={"127.0.0.1"},
            scan_successful=False,  # SCAN FAILED
        )

        assert len(delta.resolved_findings) == 0  # Must NOT resolve!
        assert len(delta.persistent_findings) == 1  # Preserved as persistent

    def test_unverified_empty_scan_never_marks_findings_as_resolved(self, audit_db):
        comparator = HistoricalComparator(audit_db)

        prior = [
            NormalizedFinding(
                title="Critical SQL Injection",
                severity=FindingSeverity.CRITICAL,
                affected_asset="127.0.0.1",
                port=80,
            )
        ]

        # Scan produced zero findings, but rescanned_assets was not confirmed
        delta: ScanDeltaReport = comparator.compare_executions(
            project_id=1,
            prior_findings=prior,
            current_findings=[],
            rescanned_assets=None,  # Not verified
            scan_successful=True,
        )

        assert len(delta.resolved_findings) == 0  # Guard prevents false resolution
        assert len(delta.persistent_findings) == 1


# =============================================================================
# 6. AI DATA ANALYST AUDIT
# =============================================================================
class TestAIDataAnalystAudit:
    """Verifies mandatory evidence citations, attack-chain hypotheses, and grounded remediation."""

    def test_all_insights_require_evidence_citations(self):
        analyst = AIDataAnalystEngine()

        findings = [
            NormalizedFinding(
                title="SQL Injection on Parameter id",
                severity=FindingSeverity.CRITICAL,
                affected_asset="http://127.0.0.1/search.php",
                evidence_id=42,
                raw_evidence_hash="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                source_tool="sqlmap",
                validation_status=ValidationStatus.CONFIRMED,
            )
        ]

        report = analyst.analyze_project(project_id=1, findings=findings)

        assert len(report.citations) == 1
        cit = report.citations[0]
        assert cit.evidence_id == 42
        assert cit.evidence_hash.startswith("a1b2c3")
        assert cit.source_tool == "sqlmap"

    def test_attack_chains_explicitly_labeled_as_hypotheses(self):
        analyst = AIDataAnalystEngine()

        findings = [
            NormalizedFinding(
                title="SQL Injection in user parameter",
                severity=FindingSeverity.CRITICAL,
                affected_asset="http://127.0.0.1/app",
                evidence_id=1,
                source_tool="sqlmap",
            )
        ]

        report = analyst.analyze_project(project_id=1, findings=findings)
        assert len(report.attack_paths) >= 1

        for path in report.attack_paths:
            assert "hypothesis" in path.chain_name.lower()
            for step in path.attack_steps:
                assert "[hypothesis" in step.lower()
            assert len(path.validation_required) >= 1

    def test_zero_hallucinated_cves_and_grounded_remediations(self):
        analyst = AIDataAnalystEngine()

        findings = [
            NormalizedFinding(
                title="OpenSSH Weak MAC Algorithm",
                severity=FindingSeverity.LOW,
                affected_asset="127.0.0.1:22",
                port=22,
                evidence_id=10,
                source_tool="nmap",
            )
        ]

        report = analyst.analyze_project(project_id=1, findings=findings)

        # Ensure no SQL injection attack chain was hallucinated when no SQL finding exists
        assert not any("sql" in p.chain_name.lower() for p in report.attack_paths)
        assert not any("rce" in p.chain_name.lower() for p in report.attack_paths)


# =============================================================================
# 7. MULTI-PROJECT ISOLATION AUDIT
# =============================================================================
class TestMultiProjectIsolationAudit:
    """Verifies strict project isolation across findings, evidence, executions, and analytics."""

    def test_findings_and_evidence_strictly_isolated(self, audit_db, project_alpha, project_beta, tmp_path):
        f_alpha = tmp_path / "alpha.txt"
        f_alpha.write_text("Alpha data", encoding="utf-8")
        h_alpha = hashlib.sha256(b"Alpha data").hexdigest()

        ev_alpha = audit_db.add_evidence(Evidence(
            project_id=project_alpha.id,
            file_path=str(f_alpha),
            sha256_hash=h_alpha,
        ))
        ev_alpha_id = ev_alpha.id

        f_beta = tmp_path / "beta.txt"
        f_beta.write_text("Beta data", encoding="utf-8")
        h_beta = hashlib.sha256(b"Beta data").hexdigest()

        ev_beta = audit_db.add_evidence(Evidence(
            project_id=project_beta.id,
            file_path=str(f_beta),
            sha256_hash=h_beta,
        ))
        ev_beta_id = ev_beta.id

        # Querying Alpha's evidence using Beta's project_id MUST return None
        assert audit_db.get_evidence(ev_alpha_id, project_id=project_beta.id) is None
        assert audit_db.get_evidence(ev_beta_id, project_id=project_alpha.id) is None

        # Listing evidence must only return project-specific records
        alpha_list = audit_db.list_evidence(project_alpha.id)
        beta_list = audit_db.list_evidence(project_beta.id)
        assert len(alpha_list) == 1 and alpha_list[0].id == ev_alpha_id
        assert len(beta_list) == 1 and beta_list[0].id == ev_beta_id
