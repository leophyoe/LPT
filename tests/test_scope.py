"""Unit tests for ScopeAuthorizationService."""

from core.scope import ScopeAuthorizationService
from storage.models import TargetScope, TargetType


def test_ip_within_cidr_authorized():
    scopes = [
        TargetScope(
            project_id=1,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    ]

    result = ScopeAuthorizationService.is_target_authorized("192.168.1.100", scopes)
    assert result.is_allowed is True
    assert "falls within authorized network" in result.reason


def test_ip_outside_cidr_blocked():
    scopes = [
        TargetScope(
            project_id=1,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    ]

    result = ScopeAuthorizationService.is_target_authorized("10.0.0.1", scopes)
    assert result.is_allowed is False
    assert "NOT in the authorized scope list" in result.reason


def test_unauthorized_scope_ignored():
    scopes = [
        TargetScope(
            project_id=1,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=False,  # Explicitly deauthorized
        )
    ]

    result = ScopeAuthorizationService.is_target_authorized("10.10.10.5", scopes)
    assert result.is_allowed is False


def test_domain_and_url_authorization():
    scopes = [
        TargetScope(
            project_id=1,
            target="lab.internal.local",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
        TargetScope(
            project_id=1,
            target="*.targetlab.corp",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        ),
    ]

    # Exact hostname
    assert ScopeAuthorizationService.is_target_authorized("lab.internal.local", scopes).is_allowed is True
    # URL targeting host
    assert ScopeAuthorizationService.is_target_authorized("https://lab.internal.local:8443/api", scopes).is_allowed is True
    # Wildcard domain
    assert ScopeAuthorizationService.is_target_authorized("app.targetlab.corp", scopes).is_allowed is True
    # Non-matching domain
    assert ScopeAuthorizationService.is_target_authorized("evil.com", scopes).is_allowed is False
