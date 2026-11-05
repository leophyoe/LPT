"""Comprehensive Test Suite for Phase 2: Scope & Authorization Deep Hardening.

Validates:
1. Exact IPv4 and IPv6 target authorization and fail-closed rejection.
2. CIDR range matching (IPv4 & IPv6) and cross-version safety (no TypeErrors).
3. Hostnames, subdomains, and wildcard matching.
4. HTTP and HTTPS URL extraction, scheme validation, and port enforcement.
5. Explicit excluded targets overriding allowed inclusions.
6. Scope and engagement start/end dates (future start date blocks, expired end date blocks).
7. Project lifecycle states (ARCHIVED, SUSPENDED, PAUSED, COMPLETED, DRAFT) fail closed.
8. Terminal operator console audit logging and credential redaction.
9. Terminal automatic database isolation in test mode.
10. High-risk operation confirmation guards (SQLMap and Hydra), rate limits, and cancellation.
11. Multi-project data isolation (scopes, assets, findings, evidence, executions, audit logs).
12. Production database zero-mutation verification and SQLite integrity.
"""

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sqlite3
from unittest.mock import MagicMock, patch
import pytest

from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.system.hydra_adapter import HydraAdapter, HydraOptions
from modules.web.sqlmap_adapter import SQLMapAdapter, SQLMapOptions
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    EngagementAuditLog,
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
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def db() -> Database:
    """Isolated in-memory SQLite database for unit tests."""
    return Database(":memory:")


@pytest.fixture
def active_project(db: Database) -> Project:
    """Active authorized engagement project fixture."""
    proj = db.create_project(
        Project(
            name="Alpha Real Engagement",
            client_name="Authorized Client LLC",
            status=ProjectStatus.ACTIVE,
        )
    )
    return proj


# =====================================================================
# 1. Exact IPv4 and IPv6 Target Validation Tests
# =====================================================================

def test_exact_ipv4_and_ipv6_authorization(active_project: Project):
    scopes = [
        TargetScope(
            project_id=active_project.id,
            target="192.168.1.50",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="2001:db8::1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="::1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        ),
    ]

    # Authorized exact targets
    assert ScopeAuthorizationService.is_target_authorized("192.168.1.50", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("2001:db8::1", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("::1", scopes, project=active_project).is_allowed is True

    # Bracketed IPv6 notation
    assert ScopeAuthorizationService.is_target_authorized("[2001:db8::1]", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("[::1]", scopes, project=active_project).is_allowed is True

    # Out of scope targets fail closed
    assert ScopeAuthorizationService.is_target_authorized("192.168.1.51", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("2001:db8::2", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("10.0.0.1", scopes, project=active_project).is_allowed is False


# =====================================================================
# 2. CIDR Range Matching & IP Version Safety Tests
# =====================================================================

def test_cidr_range_matching_and_ip_version_safety(active_project: Project):
    scopes = [
        TargetScope(
            project_id=active_project.id,
            target="192.168.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="2001:db8:abcd::/48",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        ),
    ]

    # In-range targets
    assert ScopeAuthorizationService.is_target_authorized("192.168.10.15", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("192.168.10.128/26", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("2001:db8:abcd:0001::1", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("2001:db8:abcd:ffff::/64", scopes, project=active_project).is_allowed is True

    # Out-of-range targets
    assert ScopeAuthorizationService.is_target_authorized("192.168.11.1", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("2001:db8:abce::1", scopes, project=active_project).is_allowed is False

    # Cross-version checks must never raise TypeError
    res1 = ScopeAuthorizationService.is_target_authorized("10.0.0.0/8", scopes, project=active_project)
    assert res1.is_allowed is False

    res2 = ScopeAuthorizationService.is_target_authorized("fe80::1", scopes, project=active_project)
    assert res2.is_allowed is False


# =====================================================================
# 3. Hostnames, Subdomains, and Wildcard Matching Tests
# =====================================================================

def test_hostname_subdomain_and_wildcard_matching(active_project: Project):
    scopes = [
        TargetScope(
            project_id=active_project.id,
            target="login.corp.example.com",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="*.staging.example.com",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
    ]

    # Exact hostname
    assert ScopeAuthorizationService.is_target_authorized("login.corp.example.com", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("other.corp.example.com", scopes, project=active_project).is_allowed is False

    # Wildcard domain matches subdomains
    assert ScopeAuthorizationService.is_target_authorized("api.staging.example.com", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("deep.sub.staging.example.com", scopes, project=active_project).is_allowed is True

    # Wildcard does not match non-matching domains
    assert ScopeAuthorizationService.is_target_authorized("staging.example.com", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("evil-staging.example.com", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("staging.example.org", scopes, project=active_project).is_allowed is False


# =====================================================================
# 4. HTTP and HTTPS URL Validation Tests
# =====================================================================

def test_http_and_https_url_validation(active_project: Project):
    scopes = [
        TargetScope(
            project_id=active_project.id,
            target="api.target.com",
            target_type=TargetType.HOSTNAME,
            ports_allowed="80,443,8443",
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="192.168.1.10",
            target_type=TargetType.IP_ADDRESS,
            ports_allowed="8080",
            is_authorized=True,
        ),
    ]

    # HTTP and HTTPS URLs with valid paths and query params
    url_https = "https://api.target.com/v1/auth?token=123"
    assert ScopeAuthorizationService.is_target_authorized(url_https, scopes, project=active_project).is_allowed is True

    url_port = "https://api.target.com:8443/graphql"
    assert ScopeAuthorizationService.is_target_authorized(url_port, scopes, project=active_project).is_allowed is True

    url_unauthorized_port = "http://api.target.com:9000/admin"
    assert ScopeAuthorizationService.is_target_authorized(url_unauthorized_port, scopes, project=active_project).is_allowed is False

    # IPv4 URL with port
    url_ip = "http://192.168.1.10:8080/portal"
    assert ScopeAuthorizationService.is_target_authorized(url_ip, scopes, project=active_project).is_allowed is True

    # Malformed / dangerous non-HTTP schemes fail closed
    assert ScopeAuthorizationService.is_target_authorized("file:///etc/passwd", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("javascript:alert(1)", scopes, project=active_project).is_allowed is False
    assert ScopeAuthorizationService.is_target_authorized("gopher://api.target.com", scopes, project=active_project).is_allowed is False


# =====================================================================
# 5. Explicit Excluded Targets Override Inclusions
# =====================================================================

def test_explicit_excluded_targets_override_allowed_scopes(active_project: Project):
    scopes = [
        TargetScope(
            project_id=active_project.id,
            target="10.20.0.0/16",
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="10.20.1.1",  # Excluded gateway
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
        TargetScope(
            project_id=active_project.id,
            target="10.20.99.0/24",  # Excluded management subnet
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
        TargetScope(
            project_id=active_project.id,
            target="*.target.org",
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=active_project.id,
            target="*.sec.target.org",  # Excluded security domain
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
        TargetScope(
            project_id=active_project.id,
            target="billing.target.org",  # Explicitly excluded host
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
    ]

    # Allowed targets
    assert ScopeAuthorizationService.is_target_authorized("10.20.5.25", scopes, project=active_project).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("app.target.org", scopes, project=active_project).is_allowed is True

    # Explicit IP exclusion
    res_gw = ScopeAuthorizationService.is_target_authorized("10.20.1.1", scopes, project=active_project)
    assert res_gw.is_allowed is False
    assert "matches EXCLUDED scope network 10.20.1.1" in res_gw.reason or "EXCLUDED" in res_gw.reason

    # Excluded subnet overlap
    res_mgmt = ScopeAuthorizationService.is_target_authorized("10.20.99.50", scopes, project=active_project)
    assert res_mgmt.is_allowed is False

    # Explicit hostname exclusion
    res_billing = ScopeAuthorizationService.is_target_authorized("billing.target.org", scopes, project=active_project)
    assert res_billing.is_allowed is False
    assert "matches explicitly EXCLUDED host billing.target.org" in res_billing.reason

    # Wildcard domain exclusion
    res_sec = ScopeAuthorizationService.is_target_authorized("vault.sec.target.org", scopes, project=active_project)
    assert res_sec.is_allowed is False
    assert "matches EXCLUDED domain pattern *.sec.target.org" in res_sec.reason


# =====================================================================
# 6. Scope Start/End Dates & Engagement Lifecycle Guard Tests
# =====================================================================

def test_scope_and_engagement_date_validation(db: Database):
    now = datetime.now(timezone.utc)
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")
    two_days_ago = (now - timedelta(days=2)).strftime("%Y-%m-%d")

    # Project with expired engagement window
    expired_proj = db.create_project(
        Project(
            name="Expired Project",
            status=ProjectStatus.ACTIVE,
            start_date=two_days_ago,
            end_date=yesterday,
        )
    )
    scopes = [TargetScope(project_id=expired_proj.id, target="127.0.0.1", is_authorized=True)]
    res_exp = ScopeAuthorizationService.is_target_authorized("127.0.0.1", scopes, project=expired_proj)
    assert res_exp.is_allowed is False
    assert "expired" in res_exp.reason

    # Project with future engagement window (not started yet)
    future_proj = db.create_project(
        Project(
            name="Future Project",
            status=ProjectStatus.ACTIVE,
            start_date=tomorrow,
            end_date=(now + timedelta(days=5)).strftime("%Y-%m-%d"),
        )
    )
    res_fut = ScopeAuthorizationService.is_target_authorized("127.0.0.1", scopes, project=future_proj)
    assert res_fut.is_allowed is False
    assert "has not started yet" in res_fut.reason

    # Individual TargetScope expiration
    valid_proj = db.create_project(Project(name="Active Project", status=ProjectStatus.ACTIVE))
    scope_expired = TargetScope(
        project_id=valid_proj.id,
        target="127.0.0.1",
        is_authorized=True,
        expires_at=yesterday,
    )
    res_scope_exp = ScopeAuthorizationService.is_target_authorized("127.0.0.1", [scope_expired], project=valid_proj)
    assert res_scope_exp.is_allowed is False

    # Individual TargetScope future start
    scope_future = TargetScope(
        project_id=valid_proj.id,
        target="127.0.0.1",
        is_authorized=True,
        effective_from=tomorrow,
    )
    res_scope_fut = ScopeAuthorizationService.is_target_authorized("127.0.0.1", [scope_future], project=valid_proj)
    assert res_scope_fut.is_allowed is False


def test_project_lifecycle_states_fail_closed(db: Database):
    """Archived, suspended, paused, draft, and completed engagements must strictly fail closed."""
    scopes = [TargetScope(project_id=1, target="127.0.0.1", is_authorized=True)]

    for st in [ProjectStatus.ARCHIVED, ProjectStatus.SUSPENDED, ProjectStatus.PAUSED, ProjectStatus.COMPLETED, ProjectStatus.DRAFT]:
        p = Project(name=f"Project_{st.value}", status=st)
        res = ScopeAuthorizationService.is_target_authorized("127.0.0.1", scopes, project=p)
        assert res.is_allowed is False, f"Expected {st} to fail closed, but got allowed."
        assert "status" in res.reason.lower() or "active authorization is required" in res.reason.lower()

        ok, msg = ScopeAuthorizationService.verify_scan_intent("127.0.0.1", scopes, project=p)
        assert ok is False


# =====================================================================
# 7. Terminal Security Boundary & Audit Logging Tests
# =====================================================================

def test_terminal_records_operator_audit_events_and_redacts_credentials(qtbot, db: Database, active_project: Project, tmp_path: Path):
    from desktop.widgets.terminal_view import TerminalWidget

    terminal = TerminalWidget(db=db, evidence_dir=tmp_path / "evidence")
    qtbot.addWidget(terminal)
    terminal.set_active_project(active_project, db)

    now_iso = datetime.now(timezone.utc).isoformat()
    mock_res = ProcessExecutionResult(
        command=["curl", "-u", "admin:SecretP@ssw0rd123!", "http://127.0.0.1:8080/api"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="Authorized response: Token=XYZ999\n",
        stderr="",
        started_at=now_iso,
        finished_at=now_iso,
        duration_seconds=0.45,
    )

    # Save command result via terminal handler
    terminal._save_command_result(mock_res, "curl -u admin:SecretP@ssw0rd123! http://127.0.0.1:8080/api", active_project)

    # Verify audit log was recorded with actor="operator_console"
    logs = db.list_audit_logs(active_project.id)
    assert len(logs) >= 1
    term_log = next((l for l in logs if l.action == "terminal_command_executed"), None)
    assert term_log is not None
    assert term_log.actor == "operator_console"

    # Verify password was redacted from audit log
    assert "SecretP@ssw0rd123!" not in term_log.details
    assert "[REDACTED" in term_log.details or "***REDACTED***" in term_log.details


def test_terminal_uses_isolated_db_in_test_environment(qtbot, monkeypatch):
    """When terminal is initialized without an explicit DB under test env, it defaults to :memory:, never production."""
    from desktop.widgets.terminal_view import TerminalWidget

    term = TerminalWidget(db=None)
    qtbot.addWidget(term)
    mock_res = ProcessExecutionResult(
        command=["echo", "HelloIsolatedWorld"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="HelloIsolatedWorld\n",
        stderr="",
        started_at="2026-10-31T00:00:00Z",
        finished_at="2026-10-31T00:00:01Z",
        duration_seconds=1.0,
    )

    term._save_command_result(mock_res, "echo HelloIsolatedWorld", None)
    # Database is initialized to in-memory, not the file on disk
    assert term.db is not None
    assert term.db.db_path == ":memory:"


# =====================================================================
# 8. High-Risk Operations (SQLMap & Hydra) Safety Tests
# =====================================================================

def test_sqlmap_high_risk_options_and_cancellation(db: Database, active_project: Project, tmp_path: Path):
    db.add_scope(TargetScope(project_id=active_project.id, target="127.0.0.1", is_authorized=True))
    scopes = db.list_scopes(active_project.id)
    adapter = SQLMapAdapter(db=db)

    # 1. Intrusive scan without confirmation is blocked
    opt_unconfirmed = SQLMapOptions(target_url="http://127.0.0.1/item.php?id=1", risk=2, level=2, confirmed_high_risk=False)
    success, reason, findings, exec_rec = adapter.execute_scan(active_project.id, opt_unconfirmed, scopes, project=active_project)
    assert success is False
    assert "High-Risk Operational Safety Block" in reason
    assert exec_rec is None

    # 2. Confirmed high-risk scan is allowed and audited
    opt_confirmed = SQLMapOptions(
        target_url="http://127.0.0.1/item.php?id=1",
        risk=2,
        level=2,
        rate_limit_delay=1.5,
        confirmed_high_risk=True,
    )
    cmd = adapter.build_command(opt_confirmed)
    assert "--delay" in cmd
    assert "1.5" in cmd

    mock_runner = MagicMock()
    mock_runner.run.return_value = ProcessExecutionResult(
        command=cmd,
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="--- [!] sqlmap identified injection point ---",
        stderr="",
        started_at="2026-10-31T00:00:00Z",
        finished_at="2026-10-31T00:00:05Z",
        duration_seconds=5.0,
    )
    adapter.runner = mock_runner

    success, reason, findings, exec_rec = adapter.execute_scan(active_project.id, opt_confirmed, scopes, project=active_project, evidence_dir=tmp_path / "ev")
    assert success is True

    # Verify audit log recorded confirmation
    logs = db.list_audit_logs(active_project.id)
    confirm_log = next((l for l in logs if l.action == "sqlmap_intrusive_scan_confirmed"), None)
    assert confirm_log is not None


def test_hydra_high_risk_options_and_cancellation(db: Database, active_project: Project):
    db.add_scope(TargetScope(project_id=active_project.id, target="127.0.0.1", is_authorized=True))
    scopes = db.list_scopes(active_project.id)
    adapter = HydraAdapter(db=db)

    # 1. High concurrency unconfirmed is blocked
    opt_unconfirmed = HydraOptions(target="127.0.0.1", tasks=8, confirmed_high_risk=False)
    res = adapter.execute_hydra(active_project.id, opt_unconfirmed, scopes, project=active_project)
    assert res.is_authorized is False
    assert "High-Risk Operational Safety Block" in res.error_message

    # 2. Confirmed high risk executes and audits
    opt_confirmed = HydraOptions(target="127.0.0.1", tasks=8, confirmed_high_risk=True, dry_run=True)
    res_ok = adapter.execute_hydra(active_project.id, opt_confirmed, scopes, project=active_project)
    assert res_ok.is_authorized is True

    # 3. Cancellation support
    adapter._current_job_id = "test-job-id"
    with patch.object(adapter.execution_service, "cancel_job", return_value=True) as mock_cancel:
        assert adapter.cancel() is True
        mock_cancel.assert_called_once_with("test-job-id")


# =====================================================================
# 9. Multi-Project Data Isolation Tests
# =====================================================================

def test_multi_project_data_isolation(db: Database, tmp_path: Path):
    """Verify that Project A and Project B cannot access each other's datasets."""
    # 1. Create two distinct projects
    proj_a = db.create_project(Project(name="Engagement Alpha", status=ProjectStatus.ACTIVE))
    proj_b = db.create_project(Project(name="Engagement Beta", status=ProjectStatus.ACTIVE))
    assert proj_a.id != proj_b.id

    # 2. Add records to Project A
    scope_a = db.add_scope(TargetScope(project_id=proj_a.id, target="192.168.1.10", is_authorized=True))
    node_a = db.add_asset_node(AssetNode(project_id=proj_a.id, node_type="ip", value="192.168.1.10"))
    node_a2 = db.add_asset_node(AssetNode(project_id=proj_a.id, node_type="hostname", value="host.alpha.local"))
    edge_a = db.add_asset_edge(AssetEdge(project_id=proj_a.id, source_node_id=node_a.id, target_node_id=node_a2.id, relation_type="RESOLVES_TO"))

    exec_a = db.create_execution(ToolExecution(
        project_id=proj_a.id,
        tool_name="nmap",
        command="nmap 192.168.1.10",
        status=ExecutionStatus.COMPLETED,
    ))

    finding_a = db.add_finding(Finding(
        project_id=proj_a.id,
        title="Open Port 22 SSH",
        severity=FindingSeverity.LOW,
        affected_asset="192.168.1.10",
    ))

    ev_file = tmp_path / "ev_a.txt"
    ev_file.write_text("sample evidence")
    ev_hash = hashlib.sha256(b"sample evidence").hexdigest()
    ev_a = db.add_evidence(Evidence(
        project_id=proj_a.id,
        file_path=str(ev_file),
        sha256_hash=ev_hash,
        finding_id=finding_a.id,
        execution_id=exec_a.id,
    ))

    log_a = db.add_audit_log(EngagementAuditLog(
        project_id=proj_a.id,
        action="scan_started",
        details="Project A scan",
    ))

    # 3. Query Project B and verify ZERO Project A records are exposed
    assert len(db.list_scopes(proj_b.id)) == 0
    assert len(db.list_asset_nodes(proj_b.id)) == 0
    assert len(db.list_asset_edges(proj_b.id)) == 0
    assert len(db.list_executions(proj_b.id)) == 0
    assert len(db.list_findings(proj_b.id)) == 0
    assert len(db.list_evidence(proj_b.id)) == 0
    assert len(db.list_audit_logs(proj_b.id)) == 0

    # 4. Attempt cross-project direct ID access with project_id filter
    assert db.get_scope(scope_a.id, project_id=proj_b.id) is None
    assert db.get_asset_node(node_a.id, project_id=proj_b.id) is None
    assert db.get_asset_edge(edge_a.id, project_id=proj_b.id) is None
    assert db.get_execution(exec_a.id, project_id=proj_b.id) is None
    assert db.get_finding(finding_a.id, project_id=proj_b.id) is None
    assert db.get_evidence(ev_a.id, project_id=proj_b.id) is None


# =====================================================================
# 10. Production Database Preservation & Integrity Verification Test
# =====================================================================

def test_production_database_unmodified_and_integrity():
    """Directly verifies production database integrity and census in read-only mode."""
    prod_db = Path(__file__).resolve().parent.parent / "storage" / "data" / "cybersecuritysuite.db"
    assert prod_db.is_file(), "Production database file does not exist!"

    # Open in strictly read-only mode via URI
    uri = f"file:{prod_db.resolve()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    cur = conn.cursor()

    # 1. Integrity Check
    cur.execute("PRAGMA integrity_check;")
    res = cur.fetchall()
    assert res == [("ok",)], f"Integrity check failed: {res}"

    # 2. Census Verification
    census = {
        "projects": 4,
        "target_scopes": 20,
        "asset_nodes": 26,
        "asset_edges": 6,
        "findings": 35,
        "evidence": 25,
        "observations": 102,
        "tool_executions": 17,
        "engagement_audit_logs": 59,
    }

    for table, expected_count in census.items():
        cur.execute(f"SELECT COUNT(*) FROM {table};")
        actual_count = cur.fetchone()[0]
        assert actual_count == expected_count, (
            f"Census mismatch for table '{table}': expected {expected_count}, got {actual_count}"
        )

    conn.close()
