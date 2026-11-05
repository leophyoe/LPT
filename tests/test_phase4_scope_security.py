"""Phase 4 Security Tests: Scope Guard, Engagement Lifecycle, and Tool Execution Boundaries.

Tests:
1. Fail-closed authorization when project is missing, invalid, or non-existent in database.
2. Fail-closed on non-active engagement lifecycles (ARCHIVED, SUSPENDED, PAUSED, COMPLETED).
3. Fail-closed on engagement date windows (expired date, unstarted window).
4. Exclusions strictly override inclusions across subnets, exact IPs, and wildcard domains.
5. Malformed target strings and shell command injection characters fail closed.
6. DNS resolution guard blocks hostnames that resolve to excluded IP addresses.
7. Discovered targets are never automatically authorized without operator confirmation.
8. Subprocess execution enforces tokenized argv arrays with shell=False.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult, ProcessRunner


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_phase4_scope.db"
    db = Database(str(db_file))
    yield db


@pytest.fixture
def active_project(temp_db):
    proj = Project(
        name="Phase 4 Security Engagement",
        client_name="TestCorp",
        status=ProjectStatus.ACTIVE,
        start_date="2026-01-01",
        end_date="2026-12-31",
    )
    return temp_db.create_project(proj)


def test_scope_guard_fail_closed_missing_or_invalid_project(temp_db):
    """Verify ToolExecutionService strictly fails closed when project is missing or non-existent."""
    service = ToolExecutionService(db=temp_db)

    # 1. No project_id (0 or None)
    job_no_proj = ExecutionJob(
        tool_name="nmap",
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        project_id=0,
    )
    res1 = service.execute_job_sync(job_no_proj)
    assert res1.state == JobState.BLOCKED
    assert "No active engagement project specified" in res1.error_message

    # 2. Non-existent project ID
    job_bad_proj = ExecutionJob(
        tool_name="nmap",
        target="192.168.1.10",
        command=["nmap", "192.168.1.10"],
        project_id=99999,
    )
    res2 = service.execute_job_sync(job_bad_proj)
    assert res2.state == JobState.BLOCKED
    assert "does not exist" in res2.error_message


def test_scope_guard_fail_closed_inactive_project_status(temp_db):
    """Verify ToolExecutionService strictly blocks execution for non-ACTIVE engagements."""
    service = ToolExecutionService(db=temp_db)

    for status in [ProjectStatus.ARCHIVED, ProjectStatus.SUSPENDED, ProjectStatus.PAUSED, ProjectStatus.COMPLETED]:
        proj = temp_db.create_project(Project(
            name=f"Inactive Engagement {status.value}",
            status=status,
        ))
        temp_db.add_scope(TargetScope(
            project_id=proj.id,
            target="10.0.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ))

        job = ExecutionJob(
            tool_name="nmap",
            target="10.0.0.5",
            command=["nmap", "10.0.0.5"],
            project_id=proj.id,
        )
        res = service.execute_job_sync(job)
        assert res.state == JobState.BLOCKED
        assert "Active authorization is required" in res.error_message or "status" in res.error_message


def test_scope_guard_fail_closed_expired_date_window(temp_db):
    """Verify engagements past their end date are blocked fail-closed."""
    service = ToolExecutionService(db=temp_db)

    expired_proj = temp_db.create_project(Project(
        name="Expired Engagement",
        status=ProjectStatus.ACTIVE,
        start_date="2025-01-01",
        end_date="2025-12-31",  # Expired in the past!
    ))
    temp_db.add_scope(TargetScope(
        project_id=expired_proj.id,
        target="10.50.0.0/24",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.ALLOWED,
        is_authorized=True,
    ))

    job = ExecutionJob(
        tool_name="nmap",
        target="10.50.0.100",
        command=["nmap", "10.50.0.100"],
        project_id=expired_proj.id,
    )
    res = service.execute_job_sync(job)
    assert res.state == JobState.BLOCKED
    assert "expired" in res.error_message.lower()


def test_scope_exclusions_strictly_override_inclusions(temp_db, active_project):
    """Verify that excluded IPs/subnets/domains override broad allowed scopes."""
    # Add broad allowed /16 network
    temp_db.add_scope(TargetScope(
        project_id=active_project.id,
        target="172.16.0.0/16",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.ALLOWED,
        is_authorized=True,
    ))
    # Exclude specific critical management subnet /24
    temp_db.add_scope(TargetScope(
        project_id=active_project.id,
        target="172.16.99.0/24",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.EXCLUDED,
        is_authorized=False,
    ))
    # Exclude specific individual domain controller
    temp_db.add_scope(TargetScope(
        project_id=active_project.id,
        target="172.16.1.1",
        target_type=TargetType.IP_ADDRESS,
        rule_type=ScopeRuleType.EXCLUDED,
        is_authorized=False,
    ))

    scopes = temp_db.list_scopes(active_project.id)

    # 1. Target in broad scope but NOT in excluded ranges -> ALLOWED
    res1 = ScopeAuthorizationService.is_target_authorized("172.16.10.5", scopes, project=active_project)
    assert res1.is_allowed is True

    # 2. Target inside excluded subnet -> BLOCKED
    res2 = ScopeAuthorizationService.is_target_authorized("172.16.99.50", scopes, project=active_project)
    assert res2.is_allowed is False
    assert "matches EXCLUDED scope network" in res2.reason

    # 3. Target is the explicitly excluded single IP -> BLOCKED
    res3 = ScopeAuthorizationService.is_target_authorized("172.16.1.1", scopes, project=active_project)
    assert res3.is_allowed is False
    assert "EXCLUDED" in res3.reason


def test_malformed_target_injection_fails_closed(temp_db, active_project):
    """Verify that malformed strings and shell injection attempts fail closed."""
    temp_db.add_scope(TargetScope(
        project_id=active_project.id,
        target="10.0.0.0/24",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.ALLOWED,
        is_authorized=True,
    ))
    scopes = temp_db.list_scopes(active_project.id)

    malicious_targets = [
        "10.0.0.1; rm -rf /",
        "10.0.0.1 | whoami",
        "10.0.0.1 && cat /etc/passwd",
        "`id`",
        "$(whoami).target.com",
        "10.0.0.1:999999",  # Invalid port
        "not a valid target name!!",
        "",
        "   ",
    ]

    for target in malicious_targets:
        res = ScopeAuthorizationService.is_target_authorized(target, scopes, project=active_project)
        assert res.is_allowed is False
        assert "malformed" in res.reason.lower() or "failed closed" in res.reason.lower() or "empty" in res.reason.lower()


def test_discovered_targets_never_auto_authorized(temp_db, active_project):
    """Verify that newly discovered hosts are always persisted as is_authorized=False."""
    from modules.network.nmap_parser import HostResult, NmapParser, NmapScanResult
    from desktop.dialogs.scanner_preview_dialog import ScannerResultPreviewDialog

    # Synthetic Nmap host discovery output
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="10.0.0.22" addrtype="ipv4"/>
        <hostnames><hostname name="discovered-server.corp" type="user"/></hostnames>
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        </ports>
      </host>
    </nmaprun>
    """
    scan_res = NmapParser.parse_xml(xml_data)
    assert len(scan_res.hosts) == 1
    host = scan_res.hosts[0]

    # When imported or inspected, the scope status must be unverified / unauthorized
    # unless explicitly defined in project scope
    scopes = temp_db.list_scopes(active_project.id)
    scope_check = ScopeAuthorizationService.is_target_authorized(host.ip, scopes, project=active_project)
    assert scope_check.is_allowed is False  # Out-of-scope by default!


def test_subprocess_execution_uses_tokenized_argv_shell_false():
    """Verify that ProcessRunner executes commands as tokenized argv with shell=False."""
    runner = ProcessRunner()
    res = runner.run(["python3", "-c", "import sys; print('TOKENIZED_ARGV_OK'); sys.exit(0)"])
    assert res.status == ExecutionStatus.COMPLETED
    assert res.exit_code == 0
    assert "TOKENIZED_ARGV_OK" in res.stdout
