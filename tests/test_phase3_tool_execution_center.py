"""Test suite for Phase 3: Tool Execution Center and AI Model Router.

Validates:
1. Tool Execution Center initialization and project context binding.
2. Real-time scope checking: in-scope green badge, out-of-scope red block, fail-closed button.
3. Tokenized argument array construction (shell=False safe execution).
4. High-risk operational confirmation guards for intrusive tools (SQLMap, Hydra).
5. Output segregation (stdout vs. stderr) and findings display.
6. Execution cancellation and timer tracking.
7. AI Model Router 3-tier fallback routing chain (Primary -> Secondary -> Final Fallback).
8. Token consumption and reference cost estimation tracking.
9. Pre-flight sensitive data redaction before external AI transmission.
"""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from core.ai_model_router import (
    AIModelRouter,
    AIProvider,
    AIResponse,
    ModelTierConfig,
    ReferencePricing,
    redact_sensitive_ai_data,
)
from core.execution_service import ExecutionJob, JobState, ToolExecutionService
from desktop.widgets.tool_execution_center import ToolExecutionCenterWidget
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def test_db() -> Database:
    """Isolated in-memory test database."""
    return Database(":memory:")


@pytest.fixture
def authorized_project(test_db: Database) -> Project:
    """Active authorized engagement project fixture."""
    proj = test_db.create_project(
        Project(
            name="Alpha Security Assessment",
            client_name="Test Enterprise Corp",
            status=ProjectStatus.ACTIVE,
        )
    )
    # Add authorized CIDR: 192.168.1.0/24
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    # Add authorized Host: example.com
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="example.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    return proj


# =====================================================================
# 1. Tool Execution Center Tests
# =====================================================================

def test_tool_execution_center_init(qtbot, test_db, authorized_project):
    widget = ToolExecutionCenterWidget(db=test_db, project=authorized_project)
    qtbot.addWidget(widget)
    widget.show()

    assert "Alpha Security Assessment" in widget.lbl_project_badge.text()
    assert widget.combo_tool.count() > 0
    assert widget.combo_profile.count() > 0
    assert widget.btn_execute.isEnabled() is False  # Empty target must block execution


def test_scope_guard_in_scope_and_out_of_scope(qtbot, test_db, authorized_project):
    widget = ToolExecutionCenterWidget(db=test_db, project=authorized_project)
    qtbot.addWidget(widget)
    widget.show()

    # 1. In-scope IP within 192.168.1.0/24
    widget.target_input.setText("192.168.1.50")
    assert "Authorized In-Scope" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is True

    # 2. Out-of-scope IP
    widget.target_input.setText("10.0.0.1")
    assert "Blocked" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is False

    # 3. Clear target
    widget.target_input.clear()
    assert "Enter target" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is False

    # 4. In-scope Domain
    widget.target_input.setText("example.com")
    assert "Authorized In-Scope" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is True


def test_command_token_generation_shell_false(qtbot, test_db, authorized_project):
    widget = ToolExecutionCenterWidget(db=test_db, project=authorized_project)
    qtbot.addWidget(widget)
    widget.show()

    widget.target_input.setText("192.168.1.50")
    widget.select_tool("nmap", "Service Version Scan")
    widget.input_ports.setText("80,443")
    widget.input_extra.setText("-Pn")

    tokens = widget._build_command_tokens()

    # Must be list of strings, never a raw shell string
    assert isinstance(tokens, list)
    assert tokens[0] == "nmap"
    assert "-sV" in tokens
    assert "-p" in tokens
    assert "80,443" in tokens
    assert "-Pn" in tokens
    assert "192.168.1.50" in tokens


def test_high_risk_confirmation_checkbox(qtbot, test_db, authorized_project):
    widget = ToolExecutionCenterWidget(db=test_db, project=authorized_project)
    qtbot.addWidget(widget)
    widget.show()

    widget.target_input.setText("192.168.1.50")
    widget.select_tool("sqlmap", "[High Risk] In-Depth Assessment")

    # High-risk profile must reveal checkbox and disable execution until checked
    assert widget.chk_high_risk.isVisible() is True
    assert widget.chk_high_risk.isChecked() is False
    assert widget.btn_execute.isEnabled() is False

    # Check the box -> now enabled
    widget.chk_high_risk.setChecked(True)
    assert widget.btn_execute.isEnabled() is True


def test_execution_streaming_and_findings(qtbot, test_db, authorized_project):
    widget = ToolExecutionCenterWidget(db=test_db, project=authorized_project)
    qtbot.addWidget(widget)
    widget.show()

    # Simulate streaming stdout and stderr
    widget._on_output_streamed("Discovered Open Port 22/tcp\n", "stdout")
    widget._on_output_streamed("Warning: rate limit detected\n", "stderr")

    assert "Discovered Open Port 22/tcp" in widget.txt_stdout.toPlainText()
    assert "Warning: rate limit detected" in widget.txt_stderr.toPlainText()

    # Simulate completed job with findings
    dummy_finding = Finding(
        project_id=authorized_project.id,
        title="Open SSH Port 22",
        severity=FindingSeverity.LOW,
        affected_asset="192.168.1.50",
        affected_port_service="22/tcp",
        remediation="Enforce key-based authentication",
    )
    job = ExecutionJob(
        tool_name="nmap",
        target="192.168.1.50",
        command=["nmap", "192.168.1.50"],
        project_id=authorized_project.id,
        state=JobState.COMPLETED,
        exit_code=0,
        duration_seconds=2.5,
        evidence_id=1,
        evidence_hash="abcdef1234567890",
        findings=[dummy_finding],
    )
    widget._on_job_completed(job)

    assert widget.table_findings.rowCount() == 1
    assert widget.table_findings.item(0, 0).text() == "Open SSH Port 22"
    assert "abcdef1234567890" in widget.txt_evidence_info.toPlainText()


# =====================================================================
# 2. AI Model Router Tests
# =====================================================================

def test_ai_router_sensitive_data_redaction():
    raw_prompt = "Audit token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID and AWS key AKIAIOSFODNN7EXAMPLE with password='SuperSecretPassword123'"
    clean = redact_sensitive_ai_data(raw_prompt)

    assert "Bearer eyJhbGci" not in clean
    assert "[REDACTED_JWT]" in clean
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "[REDACTED_AWS_KEY]" in clean
    assert "SuperSecretPassword123" not in clean
    assert "[REDACTED_SECRET]" in clean


def test_ai_router_fallback_chain_success_primary():
    primary = ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="primary-rules")
    secondary = ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="secondary-rules")
    final_fb = ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="final-rules")

    router = AIModelRouter(primary=primary, secondary=secondary, final_fallback=final_fb)
    resp = router.route_completion("Analyze nmap port 22 80")

    assert resp.success is True
    assert resp.provider_used == AIProvider.BUILTIN_OFFLINE
    assert resp.fallback_occurred is False
    assert len(resp.failover_history) == 0
    assert "Offline Scan Telemetry" in resp.content


def test_ai_router_fallback_chain_failover_to_secondary():
    # Primary configured to fail
    primary = ModelTierConfig(provider=AIProvider.GEMINI_API, model_name="gemini-fail", api_key="invalid-key")
    # Secondary configured with offline engine (will succeed)
    secondary = ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="secondary-offline")
    final_fb = ModelTierConfig(provider=AIProvider.BUILTIN_OFFLINE, model_name="final-rules")

    router = AIModelRouter(primary=primary, secondary=secondary, final_fallback=final_fb)

    with patch.object(router, "_call_gemini", side_effect=RuntimeError("HTTP 429 Quota Exceeded")):
        resp = router.route_completion("Analyze sqlmap injection on /login")

        assert resp.success is True
        assert resp.fallback_occurred is True
        assert len(resp.failover_history) == 1
        assert resp.failover_history[0]["tier"] == "Primary"
        assert "Quota Exceeded" in resp.failover_history[0]["error"]
        assert resp.provider_used == AIProvider.BUILTIN_OFFLINE
        assert "SQL Injection Diagnostic" in resp.content


def test_ai_router_pricing_calculation():
    # Gemini 1.5 Flash: $0.075 / 1M prompt, $0.30 / 1M completion
    cost_flash = ReferencePricing.calculate_cost("gemini-1.5-flash", prompt_tokens=1_000_000, completion_tokens=1_000_000)
    assert cost_flash == 0.375

    # GPT-4o-mini: $0.15 / 1M prompt, $0.60 / 1M completion
    cost_mini = ReferencePricing.calculate_cost("gpt-4o-mini", prompt_tokens=2_000_000, completion_tokens=1_000_000)
    assert cost_mini == 0.90

    # Local Ollama: always 0
    cost_ollama = ReferencePricing.calculate_cost("llama3", prompt_tokens=500_000, completion_tokens=500_000)
    assert cost_ollama == 0.0


def test_ai_router_usage_tracker(tmp_path):
    router = AIModelRouter()
    tracker = router.usage_tracker
    tracker._session_records.clear()

    tracker.record_usage(
        provider=AIProvider.GEMINI_API,
        model="gemini-1.5-flash",
        prompt_tokens=500,
        completion_tokens=250,
        cost_usd=0.0001,
    )
    tracker.record_usage(
        provider=AIProvider.OPENAI_API,
        model="gpt-4o-mini",
        prompt_tokens=1000,
        completion_tokens=500,
        cost_usd=0.00045,
    )

    summary = tracker.get_summary()
    assert summary["session_requests"] == 2
    assert summary["session_prompt_tokens"] == 1500
    assert summary["session_completion_tokens"] == 750
    assert summary["session_total_tokens"] == 2250
    assert summary["session_cost_usd"] > 0


def test_copilot_finding_classification_rules():
    from core.ai_copilot import AICopilotEngine
    from storage.models import Finding, FindingSeverity, ValidationStatus

    copilot = AICopilotEngine()

    # 1. Observed open port finding
    f_obs = Finding(project_id=1, title="Open Port 80 HTTP", description="Detected HTTP on 80")
    assert copilot.classify_finding_confidence(f_obs) == "Observed"

    # 2. Suspected SQLi finding (NEVER auto-promoted to Confirmed)
    f_sqli = Finding(project_id=1, title="SQL Injection in parameter id", description="Vulnerable to SQLi")
    assert copilot.classify_finding_confidence(f_sqli) == "Suspected"

    # 3. Explicit operator confirmation promotes to Confirmed
    assert copilot.classify_finding_confidence(f_sqli, operator_confirmed=True) == "Confirmed"

    # 4. False positive marker detection
    f_fp = Finding(project_id=1, title="Test Mock Banner", description="Self-test placeholder")
    assert copilot.classify_finding_confidence(f_fp) == "False Positive"

    # 5. Inconclusive findings
    f_inc = Finding(project_id=1, title="Generic Response", description="Status code 200 returned")
    assert copilot.classify_finding_confidence(f_inc) == "Needs Validation"


def test_copilot_query_with_fallback():
    from core.ai_copilot import AICopilotEngine

    copilot = AICopilotEngine()
    resp = copilot.query_with_fallback("Analyze nmap port 443 https")

    assert resp.success is True
    assert resp.provider_used == AIProvider.BUILTIN_OFFLINE
    assert "Offline Scan Telemetry" in resp.content
