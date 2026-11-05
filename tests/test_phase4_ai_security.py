"""Phase 4 Security Tests: AI Copilot Security, Redaction, Fallback, and Classification.

Tests:
1. Sensitive Data Redaction: Masks JWTs, AWS keys, GCP keys, GitHub PATs, OpenAI/Gemini keys,
   private keys, URL credentials, and passwords before external transmission.
2. AI Provider 3-Tier Fallback Chain: Primary failover to Secondary, and Secondary to Final Heuristics.
3. Timeout, 429 Rate Limiting, and 401 Authentication Failure handling.
4. AI Classification Integrity: AI cannot independently confirm findings without operator validation.
5. Usage Tracking Hygiene: Records token counts and reference costs without persisting raw prompts.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.ai_copilot import AICopilotEngine, AIProvider
from core.ai_model_router import (
    AIModelRouter,
    AIResponse,
    ModelTierConfig,
    redact_sensitive_ai_data,
)
from storage.models import Finding, FindingSeverity, ValidationStatus


def test_sensitive_data_redaction_comprehensive():
    """Verify that sensitive credentials and secrets are scrubbed before transmission."""
    raw_prompt = (
        "Found endpoint with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
        "Standalone token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.randomsig1234567890\n"
        "AWS credentials: AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz and github_pat_11AAAAAAA0123456789012345678901234567890123456789012345678901234567890123456789012\n"
        "OpenAI Key: sk-proj-1234567890abcdef1234567890 and Gemini: AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q\n"
        "URL credentials: https://admin:SuperSecretPass123!@intranet.corp/login\n"
        "CLI param: --password SuperSecretPass123! and password='AnotherSecretPassword'\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----\n"
    )

    clean = redact_sensitive_ai_data(raw_prompt)

    # Assert no secrets survived redaction
    assert "SuperSecretPass123!" not in clean
    assert "AnotherSecretPassword" not in clean
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in clean
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in clean
    assert "sk-proj-1234567890abcdef1234567890" not in clean
    assert "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q" not in clean
    assert "MIIEowIBAAKCAQEA0Y" not in clean

    # Assert redaction tags are present
    assert "[REDACTED_JWT]" in clean
    assert "[REDACTED_AWS_KEY]" in clean
    assert "[REDACTED_GITHUB_TOKEN]" in clean
    assert "[REDACTED_OPENAI_KEY]" in clean
    assert "[REDACTED_GEMINI_KEY]" in clean
    assert "[REDACTED_PRIVATE_KEY]" in clean
    assert "[REDACTED_PASSWORD]" in clean
    assert "[REDACTED_SECRET]" in clean


def test_ai_model_router_fallback_on_primary_failure():
    """Verify router automatically fails over from Primary (Gemini) to Secondary (OpenAI) when Primary fails."""
    router = AIModelRouter(
        primary=ModelTierConfig(provider=AIProvider.GEMINI_API, model_name="gemini-1.5-flash"),
        secondary=ModelTierConfig(provider=AIProvider.OPENAI_API, model_name="gpt-4o-mini"),
        final_fallback=ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="offline-expert-rules"),
    )

    # Mock primary to fail with HTTP 429 (quota exhausted)
    def mock_invoke(config, prompt, system_prompt, max_tokens, temperature):
        if config.provider == AIProvider.GEMINI_API:
            raise RuntimeError("HTTP 429 Quota Exceeded")
        elif config.provider == AIProvider.OPENAI_API:
            return "Secondary OpenAI response succeeded.", 100, 50
        return "Offline response", 20, 20

    with patch.object(router, "_invoke_tier", side_effect=mock_invoke):
        resp = router.route_completion("Analyze open ports on 10.0.0.1")
        assert resp.success is True
        assert resp.provider_used == AIProvider.OPENAI_API
        assert resp.fallback_occurred is True
        assert len(resp.failover_history) == 1
        assert resp.failover_history[0]["tier"] == "Primary"
        assert "429" in resp.failover_history[0]["error"]
        assert "Secondary OpenAI response succeeded." in resp.content


def test_ai_model_router_fallback_to_final_heuristics_when_all_cloud_fails():
    """Verify router falls back to Built-in Offline Heuristics when all cloud providers fail."""
    router = AIModelRouter(
        primary=ModelTierConfig(provider=AIProvider.GEMINI_API, model_name="gemini-1.5-flash"),
        secondary=ModelTierConfig(provider=AIProvider.OPENAI_API, model_name="gpt-4o-mini"),
        final_fallback=ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="offline-expert-rules"),
    )

    def mock_invoke(config, prompt, system_prompt, max_tokens, temperature):
        if config.provider == AIProvider.GEMINI_API:
            raise ConnectionError("Network timeout connecting to Gemini")
        elif config.provider == AIProvider.OPENAI_API:
            raise PermissionError("HTTP 401 Unauthorized invalid OpenAI key")
        return "Heuristic Expert Analysis: 80/tcp open indicates HTTP web server.", 50, 30

    with patch.object(router, "_invoke_tier", side_effect=mock_invoke):
        resp = router.route_completion("Review Nmap results for 80/tcp open")
        assert resp.success is True
        assert resp.provider_used == AIProvider.BUILTIN_OFFLINE
        assert resp.fallback_occurred is True
        assert len(resp.failover_history) == 2
        assert "Heuristic Expert Analysis" in resp.content


def test_ai_cannot_independently_confirm_findings():
    """Verify that automated AI classification strictly requires operator validation to confirm findings."""
    copilot = AICopilotEngine()

    f_critical = Finding(
        project_id=1,
        title="Critical Remote Code Execution Discovered in Apache Log4j",
        description="JNDI lookup exploitation demonstrated via CVE-2021-44228.",
        severity=FindingSeverity.CRITICAL,
        affected_asset="10.0.0.50",
        validation_status=ValidationStatus.SUSPECTED,
    )

    # 1. Without operator validation: AI cannot confirm, returns 'Suspected'
    ai_status_unverified = copilot.classify_finding_confidence(f_critical, operator_confirmed=False)
    assert ai_status_unverified != "Confirmed"
    assert ai_status_unverified == "Suspected"

    # 2. Even if raw evidence claims proof, AI classification alone cannot return Confirmed
    evidence_text = "Exploit payload executed successfully, root shell spawned."
    ai_status_with_evidence = copilot.classify_finding_confidence(f_critical, raw_evidence=evidence_text, operator_confirmed=False)
    assert ai_status_with_evidence != "Confirmed"
    assert ai_status_with_evidence == "Suspected"

    # 3. Only explicit operator validation confers Confirmed status
    ai_status_confirmed = copilot.classify_finding_confidence(f_critical, operator_confirmed=True)
    assert ai_status_confirmed == "Confirmed"


def test_ai_usage_tracking_preserves_privacy():
    """Verify AI usage records track token counts and cost without persisting sensitive prompts."""
    from core.ai_model_router import AIUsageTracker

    tracker = AIUsageTracker()
    tracker.record_usage(
        provider=AIProvider.GEMINI_API,
        model="gemini-1.5-flash",
        prompt_tokens=250,
        completion_tokens=80,
        cost_usd=0.000042,
    )

    summary = tracker.get_summary()
    assert summary["session_requests"] >= 1
    assert summary["session_prompt_tokens"] >= 250
    assert summary["session_completion_tokens"] >= 80

    # Inspect recorded records: Must NOT contain raw prompt text
    for rec in tracker._session_records:
        assert "prompt" not in rec
        assert "content" not in rec
        assert "prompt_tokens" in rec
        assert "cost_usd" in rec

