"""Unit tests for the deterministic FindingValidationEngine."""

import pytest

from core.finding_validator import FindingValidationEngine, ValidatorRuleCode
from storage.models import Finding, FindingSeverity, ValidationStatus


def test_open_port_is_never_confirmed_vulnerability():
    """Rule VR-001: Open network ports represent observations, not confirmed vulnerabilities."""
    f = Finding(
        project_id=1,
        title="TCP Port 80/http Open",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="192.168.1.50",
        description="Nmap connect scan observed open port 80 running Apache.",
    )
    assessment = FindingValidationEngine.evaluate(f)
    assert assessment.status == ValidationStatus.OBSERVED
    assert assessment.validator_rule == ValidatorRuleCode.VR_001_PORT_EXPOSURE_ONLY
    assert assessment.is_confirmed is False
    assert "legitimate network service reachability" in assessment.severity_rationale


def test_ai_suggestion_cannot_auto_confirm():
    """Rule VR-003: AI suggestions are strictly advisory and require empirical retest."""
    f = Finding(
        project_id=1,
        title="Possible SQL Injection in /api/v1/search",
        severity=FindingSeverity.HIGH,
        affected_asset="api.example.com",
        description="LLM heuristic suggests query parameter might be vulnerable.",
    )
    assessment = FindingValidationEngine.evaluate(f, source="ai_copilot_assistant")
    assert assessment.status == ValidationStatus.NEEDS_VALIDATION
    assert assessment.validator_rule == ValidatorRuleCode.VR_003_AI_ADVISORY_ONLY
    assert assessment.is_confirmed is False
    assert "AI suggestions provide advisory hypotheses only" in assessment.severity_rationale


def test_soft_404_detected_as_false_positive():
    """Rule VR-007: Endpoints returning 200 with soft-404 body content are marked false positive."""
    f = Finding(
        project_id=1,
        title="Admin Panel Discovered at /super_admin",
        severity=FindingSeverity.MEDIUM,
        affected_asset="web.example.com",
        description="Endpoint returned HTTP 200 OK.",
    )
    raw_body = "<html><body><h1>404 Not Found</h1><p>The page you requested cannot be found.</p></body></html>"
    assessment = FindingValidationEngine.evaluate(f, raw_evidence=raw_body)
    assert assessment.status == ValidationStatus.FALSE_POSITIVE
    assert assessment.validator_rule == ValidatorRuleCode.VR_007_SOFT_404_FALSE_POSITIVE
    assert assessment.is_confirmed is False


def test_exploitable_cors_with_credentials_confirmed():
    """Rule VR-005: CORS reflection with Access-Control-Allow-Credentials: true is confirmed."""
    f = Finding(
        project_id=1,
        title="CORS Misconfiguration with Credentials Allowed",
        severity=FindingSeverity.HIGH,
        affected_asset="api.example.com",
        description="The endpoint reflects arbitrary Origin headers with credentials allowed.",
        reproduction_steps="curl -H 'Origin: https://attacker.com' -I https://api.example.com\nAccess-Control-Allow-Origin: https://attacker.com\nAccess-Control-Allow-Credentials: true",
    )
    assessment = FindingValidationEngine.evaluate(f)
    assert assessment.status == ValidationStatus.CONFIRMED
    assert assessment.validator_rule == ValidatorRuleCode.VR_005_CORS_EXPLOITABLE_CONFIRMED
    assert assessment.is_confirmed is True


def test_high_entropy_aws_secret_confirmed():
    """Rule VR-004: High-entropy verifiable secret formats are confirmed."""
    f = Finding(
        project_id=1,
        title="Hardcoded AWS Access Key Discovered",
        severity=FindingSeverity.CRITICAL,
        affected_asset="app.example.com",
        description="JavaScript bundle discloses API key string.",
    )
    raw_evidence = "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';"
    assessment = FindingValidationEngine.evaluate(f, raw_evidence=raw_evidence)
    assert assessment.status == ValidationStatus.CONFIRMED
    assert assessment.validator_rule == ValidatorRuleCode.VR_004_SECRET_ENTROPY_CONFIRMED
    assert assessment.is_confirmed is True


def test_world_writable_shadow_file_confirmed():
    """Rule VR-006: World-writable sensitive system files are confirmed."""
    f = Finding(
        project_id=1,
        title="World-Writable Sensitive File: /etc/shadow",
        severity=FindingSeverity.CRITICAL,
        affected_asset="127.0.0.1",
        description="Local permission check indicates file is world-writable (mode 0o666).",
    )
    assessment = FindingValidationEngine.evaluate(f)
    assert assessment.status == ValidationStatus.CONFIRMED
    assert assessment.validator_rule == ValidatorRuleCode.VR_006_FILE_PERM_EXPLOITABLE
    assert assessment.is_confirmed is True


def test_apply_to_finding_updates_model():
    """Verifies that apply_to_finding updates finding attributes in-place."""
    f = Finding(
        project_id=1,
        title="TCP Port 443/https Open",
        severity=FindingSeverity.INFORMATIONAL,
        affected_asset="10.0.0.1",
        validation_status=ValidationStatus.CONFIRMED,  # Erroneous initial state
    )
    updated = FindingValidationEngine.apply_to_finding(f)
    assert updated.validation_status == ValidationStatus.OBSERVED
    assert "VR-001-PORT-EXPOSURE" in updated.validation_method
    assert len(updated.severity_rationale) > 0
