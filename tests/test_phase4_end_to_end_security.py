"""Phase 4 Security Tests: Complete End-to-End Workflow Integration.

Verifies the complete assessment pipeline:
Authorized Engagement
  -> Scope Validation
  -> Tool Execution (ProcessRunner / ToolExecutionService)
  -> Output Parsing (NmapParser)
  -> Asset Discovery & Node Persistence
  -> Finding Deduplication & Classification
  -> Evidence Vault (SHA-256 Verification)
  -> Report Generation (ReportBuilder)
  -> Project Data Isolation & Out-of-Scope Rejection
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.asset_inventory import AssetInventoryService
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.scope import ScopeAuthorizationService
from modules.network.nmap_parser import HostResult, NmapParser, PortResult
from reports.builder import ReportBuilder
from storage.db import Database
from storage.models import (
    AssetNode,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


@pytest.fixture
def test_db(tmp_path):
    db_path = tmp_path / "e2e_security.db"
    return Database(str(db_path))


@pytest.fixture
def project_alpha(test_db):
    proj = Project(
        name="Project Alpha Assessment",
        client_name="Alpha Enterprises",
        status=ProjectStatus.ACTIVE,
        start_date="2026-01-01",
        end_date="2026-12-31",
    )
    return test_db.create_project(proj)


@pytest.fixture
def project_beta(test_db):
    proj = Project(
        name="Project Beta Assessment",
        client_name="Beta Corp",
        status=ProjectStatus.ACTIVE,
        start_date="2026-01-01",
        end_date="2026-12-31",
    )
    return test_db.create_project(proj)


def test_end_to_end_assessment_workflow(test_db, project_alpha, project_beta, tmp_path):
    """Executes and verifies full security assessment lifecycle from scope to reporting."""
    # -------------------------------------------------------------
    # 1. Scope Definition & Authorization
    # -------------------------------------------------------------
    scope_in = test_db.add_scope(TargetScope(
        project_id=project_alpha.id,
        target="192.168.10.0/24",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.ALLOWED,
        is_authorized=True,
    ))
    scope_ex = test_db.add_scope(TargetScope(
        project_id=project_alpha.id,
        target="192.168.10.254",
        target_type=TargetType.IP_ADDRESS,
        rule_type=ScopeRuleType.EXCLUDED,
        is_authorized=False,
    ))

    scopes_alpha = test_db.list_scopes(project_alpha.id)

    # -------------------------------------------------------------
    # 2. Scope Validation: Authorized vs Out-of-Scope vs Excluded
    # -------------------------------------------------------------
    auth_check = ScopeAuthorizationService.is_target_authorized("192.168.10.50", scopes_alpha, project=project_alpha)
    assert auth_check.is_allowed is True

    excluded_check = ScopeAuthorizationService.is_target_authorized("192.168.10.254", scopes_alpha, project=project_alpha)
    assert excluded_check.is_allowed is False
    assert "EXCLUDED" in excluded_check.reason

    out_of_scope_check = ScopeAuthorizationService.is_target_authorized("10.99.99.1", scopes_alpha, project=project_alpha)
    assert out_of_scope_check.is_allowed is False

    # -------------------------------------------------------------
    # 3. Tool Execution with Scope Rejection
    # -------------------------------------------------------------
    exec_service = ToolExecutionService(db=test_db)

    # Attempt out-of-scope target: Must be blocked immediately
    job_blocked = ExecutionJob(
        tool_name="nmap",
        target="10.99.99.1",
        command=["nmap", "10.99.99.1"],
        project_id=project_alpha.id,
    )
    res_blocked = exec_service.execute_job_sync(job_blocked)
    assert res_blocked.state == JobState.BLOCKED

    # -------------------------------------------------------------
    # 4. Valid Tool Execution with Synthetic Nmap Output
    # -------------------------------------------------------------
    synthetic_nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="192.168.10.50" addrtype="ipv4"/>
        <hostnames><hostname name="srv-app01.corp" type="user"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
          <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port>
        </ports>
      </host>
    </nmaprun>
    """
    mock_runner = MagicMock()
    mock_runner.run.return_value = ProcessExecutionResult(
        command=["nmap", "-sV", "192.168.10.50"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout=synthetic_nmap_xml,
        stderr="",
        started_at="2026-11-05T00:00:00Z",
        finished_at="2026-11-05T00:00:05Z",
        duration_seconds=5.0,
    )

    evidence_dir = tmp_path / "evidence_vault"
    job_valid = ExecutionJob(
        tool_name="nmap",
        target="192.168.10.50",
        command=["nmap", "-sV", "192.168.10.50"],
        project_id=project_alpha.id,
        evidence_dir=evidence_dir,
        runner=mock_runner,
    )
    res_valid = exec_service.execute_job_sync(job_valid)
    assert res_valid.state == JobState.COMPLETED
    assert res_valid.exit_code == 0
    assert res_valid.evidence_id is not None
    assert res_valid.evidence_hash is not None

    # Verify Cryptographic Evidence Hash
    ev_record = test_db.get_evidence(res_valid.evidence_id)
    assert ev_record is not None
    assert Path(ev_record.file_path).is_file()
    actual_disk_hash = hashlib.sha256(Path(ev_record.file_path).read_bytes()).hexdigest()
    assert ev_record.sha256_hash == actual_disk_hash

    # -------------------------------------------------------------
    # 5. Output Parsing & Asset Discovery
    # -------------------------------------------------------------
    parsed_scan = NmapParser.parse_xml(synthetic_nmap_xml)
    assert len(parsed_scan.hosts) == 1
    host = parsed_scan.hosts[0]
    assert host.ip == "192.168.10.50"
    assert host.hostname == "srv-app01.corp"
    assert len(host.ports) == 2

    # Persist AssetNode using upsert_asset_node
    asset_node = test_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value=host.ip,
            label=host.hostname,
            source_tool="nmap",
        )
    )
    assert asset_node.id is not None
    assert asset_node.value == "192.168.10.50"

    # Re-inserting the same host must prevent duplicate records
    dup_node = test_db.upsert_asset_node(
        AssetNode(
            project_id=project_alpha.id,
            node_type="ip",
            value=host.ip,
            label=host.hostname,
            source_tool="nmap",
        )
    )
    assert dup_node.id == asset_node.id
    all_assets_alpha = test_db.list_asset_nodes(project_alpha.id)
    assert len(all_assets_alpha) == 1

    # -------------------------------------------------------------
    # 6. Finding Creation & Deduplication
    # -------------------------------------------------------------
    finding_1 = Finding(
        project_id=project_alpha.id,
        title="Apache 2.4.52 Outdated Web Server",
        description="Apache httpd 2.4.52 contains known security vulnerabilities.",
        severity=FindingSeverity.MEDIUM,
        affected_asset="192.168.10.50",
        affected_port_service="80/tcp",
        validation_status=ValidationStatus.SUSPECTED,
    )
    created_f1 = test_db.upsert_finding_deduplicated(finding_1)
    assert created_f1.id is not None

    # Re-importing identical finding updates rather than duplicating
    created_f1_dup = test_db.upsert_finding_deduplicated(finding_1)
    assert created_f1_dup.id == created_f1.id

    findings_alpha = test_db.list_findings(project_alpha.id)
    assert len(findings_alpha) == 1

    # -------------------------------------------------------------
    # 7. Project Isolation Verification
    # -------------------------------------------------------------
    # Project Beta must see 0 assets and 0 findings
    assets_beta = test_db.list_asset_nodes(project_beta.id)
    findings_beta = test_db.list_findings(project_beta.id)
    assert len(assets_beta) == 0
    assert len(findings_beta) == 0

    # -------------------------------------------------------------
    # 8. Report Generation
    # -------------------------------------------------------------
    builder = ReportBuilder(test_db)
    report_data = builder.build_report_data(project_alpha.id)
    assert report_data.project.name == "Project Alpha Assessment"
    assert len(report_data.findings) == 1
    assert len(report_data.evidence) >= 1

    # Export report to JSON and Markdown
    md_report = builder.generate_markdown(project_alpha.id)
    assert "Project Alpha Assessment" in md_report
    assert "Apache 2.4.52" in md_report
    assert "192.168.10.50" in md_report

    json_report = builder.generate_json(project_alpha.id)
    assert "Apache 2.4.52 Outdated Web Server" in json_report
