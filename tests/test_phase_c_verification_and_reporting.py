"""Tests for Phase C: Verification, Lab Simulator & Reporting Alignment.

Verifies:
1. VulnerabilityVerifier scope boundary enforcement (fail-closed check).
2. VulnerabilityVerifier protocol-aware non-destructive probes (HTTP headers, TLS, FTP, MySQL).
3. VulnerabilityVerifier SHA-256 evidence vault artifact creation and DB persistence.
4. NetworkScanView Step 5 Candidate Findings table & verification workflow.
5. NetworkScanView Step 6 CPENT engagement pack & PDF/HTML export connectivity.
6. ReportBuilder alignment with asset_nodes, observations, and verified exploit proofs.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from core.scope import ScopeAuthorizationService
from desktop.views.network_scan_view import NetworkScanView
from modules.vuln.verifier import VulnerabilityVerifier, VerificationResult
from reports.builder import ReportBuilder
from reports.cpent_engagement_pack import CPENTEngagementPackGenerator
from storage.db import Database
from storage.models import (
    AssetNode,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_phase_c.db"
    return Database(str(db_file))


@pytest.fixture
def sample_project(temp_db: Database) -> Project:
    proj = temp_db.create_project(
        Project(
            name="Phase C Verification Project",
            client_name="Test Client Corp",
            description="Engagement testing verification and reporting alignment",
        )
    )
    # Add authorized scope
    temp_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    temp_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.0.0.10",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


# =======================================================================
# 1. VulnerabilityVerifier Tests
# =======================================================================

def test_verifier_scope_enforcement_fail_closed(temp_db: Database, sample_project: Project, tmp_path: Path):
    """Test 1: VulnerabilityVerifier rejects targets outside authorized project scope."""
    verifier = VulnerabilityVerifier(db=temp_db, evidence_dir=tmp_path / "evidence")

    # Target 8.8.8.8 is NOT in sample_project scope (192.168.1.0/24 and 10.0.0.10)
    unauthorized_finding = Finding(
        project_id=sample_project.id,
        title="Unauthorized Finding (CWE-693)",
        affected_asset="8.8.8.8:80",
        validation_status=ValidationStatus.OBSERVED,
    )

    res = verifier.verify_finding(unauthorized_finding, project=sample_project)
    assert res.is_verified is False
    assert "rejected by Scope Guard" in res.error_message
    assert res.validation_status == ValidationStatus.OBSERVED


def test_verifier_http_headers_non_destructive(temp_db: Database, sample_project: Project, tmp_path: Path):
    """Test 2: Verifier accurately detects missing CSP and records proof without crashing."""
    verifier = VulnerabilityVerifier(db=temp_db, evidence_dir=tmp_path / "evidence")

    finding = Finding(
        project_id=sample_project.id,
        title="Missing Content Security Policy (CSP) (CWE-693)",
        affected_asset="10.0.0.10:80",
        validation_status=ValidationStatus.OBSERVED,
        description="Candidate observation: Missing CSP header.",
    )
    saved = temp_db.create_finding(finding)

    # Mock HTTP response with missing CSP
    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.headers = {
        "Server": "Apache/2.4.41",
        "Content-Type": "text/html",
    }
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = verifier.verify_finding(saved, project=sample_project)

    assert res.is_verified is True
    assert res.validation_status == ValidationStatus.CONFIRMED
    assert "Content-Security-Policy" in res.proof
    assert len(res.sha256_hash) == 64
    assert res.evidence_file is not None
    assert res.evidence_file.exists()

    # Verify DB finding was updated to CONFIRMED
    updated_finding = temp_db.get_finding(saved.id)
    assert updated_finding is not None
    assert updated_finding.validation_status == ValidationStatus.CONFIRMED
    assert "CONTROLLED VERIFICATION EVIDENCE PROOF" in updated_finding.reproduction_steps

    # Verify Evidence record was added to DB
    evidence_list = temp_db.list_evidence(sample_project.id)
    assert len(evidence_list) == 1
    assert evidence_list[0].sha256_hash == res.sha256_hash


def test_verifier_deprecated_tls_verification(temp_db: Database, sample_project: Project, tmp_path: Path):
    """Test 3: Verifier checks deprecated TLS protocols and records cryptographic details."""
    verifier = VulnerabilityVerifier(db=temp_db, evidence_dir=tmp_path / "evidence")

    finding = Finding(
        project_id=sample_project.id,
        title="Deprecated TLS 1.0/1.1 Protocol Supported (CWE-326)",
        affected_asset="10.0.0.10:443",
        validation_status=ValidationStatus.OBSERVED,
    )
    saved = temp_db.create_finding(finding)

    # Mock ssl wrap_socket to simulate TLS 1.0 acceptance
    mock_ssock = MagicMock()
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-SHA", "TLSv1.0", 128)
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = None

    with patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
        res = verifier.verify_finding(saved, project=sample_project)

    assert res.is_verified is True
    assert res.validation_status == ValidationStatus.CONFIRMED
    assert "TLSv1.0" in res.proof
    assert "ECDHE-RSA-AES128-SHA" in res.proof


def test_verifier_anonymous_ftp(temp_db: Database, sample_project: Project, tmp_path: Path):
    """Test 4: Verifier checks anonymous FTP login non-destructively."""
    verifier = VulnerabilityVerifier(db=temp_db, evidence_dir=tmp_path / "evidence")

    finding = Finding(
        project_id=sample_project.id,
        title="Anonymous FTP Login Permitted (CWE-287)",
        affected_asset="192.168.1.50:21",
        validation_status=ValidationStatus.OBSERVED,
    )
    saved = temp_db.create_finding(finding)

    mock_ftp = MagicMock()
    mock_ftp.getwelcome.return_value = "220 ProFTPD Server ready."
    mock_ftp.login.return_value = "230 User anonymous logged in."
    mock_ftp.pwd.return_value = "/pub"

    with patch("ftplib.FTP", return_value=mock_ftp):
        res = verifier.verify_finding(saved, project=sample_project)

    assert res.is_verified is True
    assert "230 User anonymous logged in" in res.proof
    assert "/pub" in res.proof


# =======================================================================
# 2. NetworkScanView UI Step 5 & Step 6 Integration Tests
# =======================================================================

def test_network_scan_view_step5_table_and_buttons(qtbot, temp_db: Database, sample_project: Project):
    """Test 5: NetworkScanView Step 5 displays candidate findings table and verification controls."""
    # Seed candidate finding
    f = Finding(
        project_id=sample_project.id,
        title="Missing Content Security Policy (CSP)",
        severity=FindingSeverity.MEDIUM,
        cvss_score=6.1,
        affected_asset="10.0.0.10:80",
        validation_status=ValidationStatus.OBSERVED,
    )
    temp_db.create_finding(f)

    view = NetworkScanView(db=temp_db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    # Verify Step 5 candidate findings table exists
    assert hasattr(view, "step5_findings_table")
    assert view.step5_findings_table.rowCount() == 1
    assert view.step5_findings_table.item(0, 3).text() == "Missing Content Security Policy (CSP)"
    assert view.step5_findings_table.item(0, 5).text() == "OBSERVED"

    # Verify Step 5 buttons exist
    assert hasattr(view, "verify_finding_btn")
    assert hasattr(view, "mark_false_positive_btn")
    assert hasattr(view, "btn_open_exam_sim")


def test_network_scan_view_step6_export_buttons(qtbot, temp_db: Database, sample_project: Project):
    """Test 6: NetworkScanView Step 6 provides HTML, Markdown, JSON, PDF and CPENT Pack export buttons."""
    view = NetworkScanView(db=temp_db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    assert hasattr(view, "export_html_btn")
    assert hasattr(view, "export_md_btn")
    assert hasattr(view, "export_json_btn")
    assert hasattr(view, "export_pdf_btn")
    assert hasattr(view, "export_cpent_pack_btn")


# =======================================================================
# 3. Report Alignment & CPENT Pack Generator Tests
# =======================================================================

def test_report_builder_aligns_asset_nodes_and_verified_findings(temp_db: Database, sample_project: Project):
    """Test 7: ReportBuilder incorporates asset nodes and verified findings into stage metrics."""
    # Seed asset node with port metadata
    node = AssetNode(
        project_id=sample_project.id,
        node_type="host",
        value="10.0.0.10",
        label="web-prod-01",
        metadata_json=json.dumps({"ports": [80, 443]}),
        source_tool="socket_scanner",
    )
    temp_db.upsert_asset_node(node)

    # Seed verified finding
    f = Finding(
        project_id=sample_project.id,
        title="Web Server Version Information Disclosure (CWE-200)",
        severity=FindingSeverity.LOW,
        cvss_score=3.1,
        affected_asset="10.0.0.10:80",
        validation_status=ValidationStatus.CONFIRMED,
        validation_method="Pure-Python Non-Destructive Interrogation Protocol",
    )
    temp_db.create_finding(f)

    builder = ReportBuilder(temp_db)
    report_data = builder.build_report_data(sample_project.id)

    # Check stage summaries
    wf = report_data.workflow_summary
    assert wf is not None
    stages = wf.get("stages", {})

    # Stage 2 (Discovery) and Stage 3 (Fingerprinting) should be completed from asset_nodes
    assert stages.get("network_scanning_live_discovery", {}).get("status") == "completed"
    assert stages.get("os_service_fingerprinting", {}).get("status") == "completed"
    assert stages.get("vulnerability_assessment", {}).get("status") == "completed"
    assert stages.get("exploit_verification", {}).get("status") == "completed"
    assert stages.get("reporting_retesting", {}).get("status") == "completed"

    # Markdown report output contains topology and confirmed finding
    md = builder.generate_markdown(sample_project.id)
    assert "10.0.0.10" in md
    assert "Web Server Version Information Disclosure" in md
    assert "CONFIRMED" in md


def test_cpent_engagement_pack_zip_generation(temp_db: Database, sample_project: Project, tmp_path: Path):
    """Test 8: CPENTEngagementPackGenerator builds official 16-folder zip archive."""
    generator = CPENTEngagementPackGenerator(temp_db)
    target_zip = tmp_path / "test_cpent_pack.zip"

    out_zip = generator.generate_pack_zip(sample_project.id, target_zip)
    assert out_zip.exists()
    assert out_zip.stat().st_size > 0
