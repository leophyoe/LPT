"""Unit tests for Scoping & Engagement Management safeguards.

Tests:
1. Engagement lifecycle state machine & fail-closed execution boundary.
2. Authorization testing date window checks (start_date, end_date).
3. Exclusion precedence over inclusions (EXCLUDED rule blocks target).
4. Pre-execution DNS resolution against excluded IP subnets.
5. Port boundaries enforcement.
6. Scope conflict and overlap detection.
7. Engagement audit logging.
"""

import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import (
    EngagementAuditLog,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def scope_service():
    return ScopeAuthorizationService()


# ---------------------------------------------------------------------------
# 1. Engagement Lifecycle & Date Window Gating
# ---------------------------------------------------------------------------

def test_engagement_lifecycle_fails_closed_when_not_active(scope_service):
    """Execution must strictly fail closed if engagement is not in ACTIVE state."""
    target = "192.168.1.50"
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True)]

    inactive_statuses = [
        ProjectStatus.DRAFT,
        ProjectStatus.AWAITING_APPROVAL,
        ProjectStatus.AUTHORIZED,
        ProjectStatus.PAUSED,
        ProjectStatus.COMPLETED,
        ProjectStatus.ARCHIVED,
    ]

    for status in inactive_statuses:
        project = Project(name="Test Engagement", status=status)
        is_auth, reason = scope_service.is_target_authorized(target, scopes, project=project)
        assert not is_auth, f"Failed for status: {status}"
        label = status.value.replace("_", " ").title()
        assert f"is in '{label}' status" in reason


def test_engagement_lifecycle_active_succeeds(scope_service):
    """Execution succeeds when engagement is ACTIVE and in valid date window."""
    target = "192.168.1.50"
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True)]
    project = Project(name="Active Engagement", status=ProjectStatus.ACTIVE)

    is_auth, reason = scope_service.is_target_authorized(target, scopes, project=project)
    assert is_auth
    assert "192.168.1.0/24" in reason


def test_engagement_testing_window_date_gating(scope_service):
    """Execution fails closed outside the approved date window."""
    target = "192.168.1.50"
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True)]

    now = datetime.now(timezone.utc)
    yesterday = (now - timedelta(days=2)).date().isoformat()
    two_days_ago = (now - timedelta(days=3)).date().isoformat()
    tomorrow = (now + timedelta(days=1)).date().isoformat()
    next_week = (now + timedelta(days=7)).date().isoformat()

    # Expired engagement
    expired_project = Project(
        name="Expired Project",
        status=ProjectStatus.ACTIVE,
        start_date=two_days_ago,
        end_date=yesterday,
    )
    is_auth, reason = scope_service.is_target_authorized(target, scopes, project=expired_project)
    assert not is_auth
    assert "authorization window expired" in reason

    # Future engagement (not started yet)
    future_project = Project(
        name="Future Project",
        status=ProjectStatus.ACTIVE,
        start_date=tomorrow,
        end_date=next_week,
    )
    is_auth, reason = scope_service.is_target_authorized(target, scopes, project=future_project)
    assert not is_auth
    assert "window has not started yet" in reason


def test_invalid_engagement_dates_fail_closed(scope_service):
    scopes = [TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE)]
    project = Project(name="Bad Date", status=ProjectStatus.ACTIVE, start_date="not-a-date")
    result = scope_service.is_target_authorized("192.168.1.10", scopes, project=project)
    assert not result.is_allowed
    assert "Invalid engagement start date" in result.reason


def test_wildcard_domain_requires_label_boundary(scope_service):
    scopes = [TargetScope(project_id=1, target="*.example.com", target_type=TargetType.HOSTNAME)]
    assert scope_service.is_target_authorized("a.example.com", scopes).is_allowed
    assert not scope_service.is_target_authorized("badexample.com", scopes).is_allowed


def test_dns_failure_fails_closed_when_exclusions_must_be_checked(scope_service):
    scopes = [
        TargetScope(project_id=1, target="service.example.com", target_type=TargetType.HOSTNAME),
        TargetScope(project_id=1, target="10.0.0.0/8", target_type=TargetType.CIDR_RANGE,
                    rule_type=ScopeRuleType.EXCLUDED, is_authorized=False),
    ]
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS unavailable")):
        result = scope_service.is_target_authorized("service.example.com", scopes, resolve_dns=True)
    assert not result.is_allowed
    assert "Could not resolve" in result.reason


# ---------------------------------------------------------------------------
# 2. Exclusion Precedence over Inclusion
# ---------------------------------------------------------------------------

def test_scope_exclusion_takes_precedence_over_cidr_allow(scope_service):
    """An explicit EXCLUDED IP rule inside an ALLOWED CIDR must be strictly blocked."""
    scopes = [
        TargetScope(
            project_id=1,
            target="10.0.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="10.0.0.50",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
            notes="Production billing gateway - strictly excluded",
        ),
    ]
    project = Project(name="Scope Test", status=ProjectStatus.ACTIVE)

    # In-scope general host
    is_auth, reason = scope_service.is_target_authorized("10.0.0.12", scopes, project=project)
    assert is_auth

    # Excluded target
    is_auth, reason = scope_service.is_target_authorized("10.0.0.50", scopes, project=project)
    assert not is_auth
    assert "matches EXCLUDED scope network 10.0.0.50" in reason


def test_scope_exclusion_for_subdomain(scope_service):
    """Excluded hostnames or wildcard domains must block matching targets."""
    scopes = [
        TargetScope(
            project_id=1,
            target="*.example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="payment.example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
    ]
    project = Project(name="Domain Scope Test", status=ProjectStatus.ACTIVE)

    is_auth, reason = scope_service.is_target_authorized("api.example.com", scopes, project=project)
    assert is_auth
    assert "matches domain pattern *.example.com" in reason

    is_auth, reason = scope_service.is_target_authorized("payment.example.com", scopes, project=project)
    assert not is_auth
    assert "matches explicitly EXCLUDED host payment.example.com" in reason


# ---------------------------------------------------------------------------
# 3. Pre-execution DNS Resolution Check
# ---------------------------------------------------------------------------

def test_pre_execution_dns_resolution_detects_excluded_ip(scope_service):
    """Domain targets resolving to an excluded IP subnet must fail closed."""
    scopes = [
        TargetScope(
            project_id=1,
            target="partner.example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="172.16.0.0/16",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
    ]
    project = Project(name="DNS Scope Test", status=ProjectStatus.ACTIVE)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.5.10", 0))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        is_auth, reason = scope_service.is_target_authorized(
            "partner.example.com",
            scopes,
            project=project,
            resolve_dns=True,
        )
        assert not is_auth
        assert "resolves to 172.16.5.10, which matches EXCLUDED scope 172.16.0.0/16" in reason


# ---------------------------------------------------------------------------
# 4. Port Restrictions Enforcement
# ---------------------------------------------------------------------------

def test_scope_port_boundaries(scope_service):
    """When ports_allowed is specified, targets with unauthorized ports fail."""
    scopes = [
        TargetScope(
            project_id=1,
            target="192.168.1.10",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
            ports_allowed="80,443",
        ),
    ]
    project = Project(name="Port Scope Test", status=ProjectStatus.ACTIVE)

    # Port 443 -> allowed
    is_auth, reason = scope_service.is_target_authorized("192.168.1.10:443", scopes, project=project)
    assert is_auth

    # Port 8080 -> rejected
    is_auth, reason = scope_service.is_target_authorized("192.168.1.10:8080", scopes, project=project)
    assert not is_auth
    assert "is not in the authorized ports list (80,443)" in reason


# ---------------------------------------------------------------------------
# 5. Scope Conflict & Overlap Detection
# ---------------------------------------------------------------------------

def test_detect_scope_conflicts(scope_service):
    """detect_scope_conflicts flags overlapping subnets and excluded IPs."""
    scopes = [
        TargetScope(
            project_id=1,
            target="10.0.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="10.0.0.5",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        ),
    ]

    conflicts = scope_service.detect_scope_conflicts(scopes)
    assert len(conflicts) >= 1
    assert any("Allowed CIDR '10.0.0.0/24' contains Excluded IP '10.0.0.5'" in c["message"] for c in conflicts)


# ---------------------------------------------------------------------------
# 6. Database Audit Logging
# ---------------------------------------------------------------------------

def test_engagement_audit_logging(db):
    """Engagement actions, RoE updates, and status changes are recorded in audit log."""
    project = db.create_project(Project(name="Audit Test Project", status=ProjectStatus.DRAFT))
    p_id = project.id

    db.add_audit_log(
        EngagementAuditLog(
            project_id=p_id,
            action="STATUS_CHANGED",
            actor="compliance_lead",
            details="Changed status from draft to active",
        )
    )
    db.add_audit_log(
        EngagementAuditLog(
            project_id=p_id,
            action="ROE_UPDATED",
            actor="lead_tester",
            details="Updated allowed techniques and rate limits",
        )
    )

    logs = db.list_audit_logs(p_id)
    assert len(logs) == 2
    # Ordered DESC by id (newest first)
    assert logs[0].action == "ROE_UPDATED"
    assert logs[0].actor == "lead_tester"
    assert logs[1].action == "STATUS_CHANGED"
    assert logs[1].actor == "compliance_lead"

