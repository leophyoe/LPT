"""Unit and integration tests for advanced orchestration and triage modules.

Covers:
1. We5ter/Scanners-Box: ScannersBoxCatalog (categories, search, metadata, host check)
2. 1N3/Sn1per: Sn1perOrchestrator (scope gating, stage chaining, cancellation)
3. 0x4m4/hexstrike-ai & CyberStrikeAI: AIToolRouter (intent mapping, safety classification)
4. usestrix/strix: StrixTriageEngine (CVSS v3.1 calculation, OWASP mapping, false positive heuristics, remediation playbooks)
"""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from core.ai_tool_router import AIToolRouter, ToolSafetyLevel
from core.strix_triage import StrixTriageEngine, TriagedFinding
from modules.orchestration.sn1per_orchestrator import (
    Sn1perOrchestrator,
    Sn1perScanMode,
)
from modules.scanners_box.catalog import ScannersBoxCatalog, ScannersBoxItem
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project, TargetScope, ValidationStatus


@pytest.fixture
def test_db():
    return Database(":memory:")


# ---------------------------------------------------------------------------
# 1. Scanners-Box Catalog Tests (We5ter/Scanners-Box)
# ---------------------------------------------------------------------------

def test_scanners_box_catalog_categories():
    assert len(ScannersBoxCatalog.CATEGORIES) == 12
    assert "Subdomain & OSINT" in ScannersBoxCatalog.CATEGORIES
    assert "Port & Network Scanners" in ScannersBoxCatalog.CATEGORIES
    assert "Web Application Scanners" in ScannersBoxCatalog.CATEGORIES
    assert "Database & SQL Injection" in ScannersBoxCatalog.CATEGORIES
    assert "Memory Forensics & Reverse Eng" in ScannersBoxCatalog.CATEGORIES


def test_scanners_box_catalog_items_and_search():
    items = ScannersBoxCatalog.get_all_items()
    assert len(items) >= 25

    # Check known tools
    names = [i.name for i in items]
    assert "nmap" in names
    assert "sqlmap" in names
    assert "zaproxy" in names
    assert "ptk" in names
    assert "volatility3" in names
    assert "bandit" in names
    assert "hashcat" in names
    assert "amass" in names

    # Filter by category
    db_tools = ScannersBoxCatalog.get_by_category("Database & SQL Injection")
    assert any(t.name == "sqlmap" for t in db_tools)

    # Search by keyword
    search_res = ScannersBoxCatalog.search("injection")
    assert any(t.name == "sqlmap" for t in search_res)

    # Search with category filter
    web_res = ScannersBoxCatalog.search("proxy", category="Web Application Scanners")
    assert any(t.name == "zaproxy" for t in web_res)

    # Item property check
    nmap_item = next(i for i in items if i.name == "nmap")
    assert nmap_item.language == "C/C++"
    assert "https://github.com/nmap/nmap" in nmap_item.github_url
    assert isinstance(nmap_item.is_installed_on_host, bool)


# ---------------------------------------------------------------------------
# 2. Sn1per Orchestrator Tests (1N3/Sn1per)
# ---------------------------------------------------------------------------

def test_sn1per_orchestrator_scope_guard_blocking(test_db):
    """Ensure Sn1per blocks out-of-scope targets and logs violation without launching tools."""
    project = test_db.create_project(Project(name="Sn1per Scope Test"))
    test_db.add_scope(TargetScope(project_id=project.id, target="192.168.1.0/24", notes="Local subnet"))

    orchestrator = Sn1perOrchestrator(db=test_db)
    logs = []

    # Probing unauthorized target
    res = orchestrator.run_pipeline(
        target="http://evil-external-target.com",
        mode=Sn1perScanMode.RECON,
        project=project,
        on_log=lambda msg: logs.append(msg),
    )

    assert not res.is_authorized
    assert "Scope Guard Violation" in (res.error or "")
    assert len(res.stages) == 0
    assert any("SCOPE VIOLATION" in l for l in logs)


def test_sn1per_orchestrator_authorized_recon_execution(test_db):
    """Test authorized passive recon pipeline."""
    project = test_db.create_project(Project(name="Sn1per Authorized Test"))
    test_db.add_scope(TargetScope(project_id=project.id, target="127.0.0.1", notes="Localhost"))

    orchestrator = Sn1perOrchestrator(db=test_db)
    progress_updates = []
    logs = []

    res = orchestrator.run_pipeline(
        target="http://127.0.0.1:8080",
        mode=Sn1perScanMode.RECON,
        project=project,
        on_progress=lambda txt, pct: progress_updates.append((txt, pct)),
        on_log=lambda msg: logs.append(msg),
    )

    assert res.is_authorized
    assert res.error is None
    assert len(res.stages) == 1
    assert res.stages[0].tool_name == "c0desec"
    assert len(progress_updates) >= 1


def test_sn1per_orchestrator_cancellation(test_db):
    orchestrator = Sn1perOrchestrator(db=test_db)
    orchestrator.cancel()
    assert orchestrator._is_cancelled


# ---------------------------------------------------------------------------
# 3. AI Tool Router Tests (0x4m4/hexstrike-ai & AIPentest/CyberStrikeAI)
# ---------------------------------------------------------------------------

def test_ai_tool_router_sqlmap_intent():
    router = AIToolRouter()
    plan = router.route_intent("Find sql injection vulnerabilities on http://127.0.0.1:8080/products?id=1")
    assert plan.tool_name == "sqlmap"
    assert plan.safety_level == ToolSafetyLevel.INTRUSIVE
    assert "sqlmap" in plan.command_str
    assert "http://127.0.0.1:8080/products?id=1" in plan.target


def test_ai_tool_router_gobuster_intent():
    router = AIToolRouter()
    plan = router.route_intent("Fuzz hidden directories and secret routes on http://127.0.0.1:3000/")
    assert plan.tool_name == "gobuster"
    assert plan.safety_level == ToolSafetyLevel.INTRUSIVE
    assert "gobuster" in plan.command_str


def test_ai_tool_router_waf_intent():
    router = AIToolRouter()
    plan = router.route_intent("Detect if there is a Cloudflare or Imperva WAF firewall on https://target.corp")
    assert plan.tool_name == "wafw00f"
    assert plan.safety_level == ToolSafetyLevel.PASSIVE


def test_ai_tool_router_nikto_intent():
    router = AIToolRouter()
    plan = router.route_intent("Run nikto web server vulnerability scan against http://127.0.0.1:8080")
    assert plan.tool_name == "nikto"
    assert plan.safety_level == ToolSafetyLevel.ACTIVE_SAFE
    assert "nikto" in plan.command_str
    assert "127.0.0.1" in plan.target
    assert plan.suggested_ui_view == "web"


def test_ai_tool_router_ptk_jwt_intent():
    router = AIToolRouter()
    plan = router.route_intent("Analyze this JWT token and test for alg none vulnerability")
    assert plan.tool_name == "ptk"
    assert "ptk" in plan.command_str


def test_ai_tool_router_forensics_intent():
    router = AIToolRouter()
    plan = router.route_intent("Examine memory dump ram.raw with volatility for hidden processes")
    assert plan.tool_name == "volatility3"
    assert plan.safety_level == ToolSafetyLevel.PASSIVE


def test_ai_tool_router_sast_bandit_intent():
    router = AIToolRouter()
    plan = router.route_intent("Run SAST source code security review on this python repository using bandit")
    assert plan.tool_name == "bandit"
    assert plan.safety_level == ToolSafetyLevel.PASSIVE


def test_ai_tool_router_scope_checking(test_db):
    project = test_db.create_project(Project(name="Router Scope Test"))
    test_db.add_scope(TargetScope(project_id=project.id, target="10.0.0.0/8", notes="Internal Corp"))

    router = AIToolRouter()
    # Out of scope target
    plan_out = router.route_intent("Run nmap scan on 192.168.1.1", project=project, db=test_db)
    assert not plan_out.is_authorized

    # In scope target
    plan_in = router.route_intent("Run nmap scan on 10.1.2.3", project=project, db=test_db)
    assert plan_in.is_authorized


def test_ai_command_suggestion_fails_closed_without_scope():
    from core.ai_copilot import AICopilotEngine
    suggestion = AICopilotEngine().generate_command("scan 192.0.2.10 with nmap")
    assert not suggestion.is_in_scope


def test_ai_tool_router_quotes_generated_arguments():
    router = AIToolRouter()
    plan = router.route_intent('Run nikto scan against "https://example.com/a path?x=1"')
    assert "'https://example.com/a path?x=1'" in plan.command_str


# ---------------------------------------------------------------------------
# 4. Strix AI Triage Engine Tests (usestrix/strix)
# ---------------------------------------------------------------------------

def test_strix_triage_cvss_and_owasp_mapping():
    finding_sqli = Finding(
        project_id="test-proj",
        title="SQL Injection in /api/users endpoint",
        severity=FindingSeverity.CRITICAL,
        affected_asset="http://127.0.0.1:8080",
        description="Unsanitized id parameter passed directly to database cursor query.",
        remediation="Use parameterized queries.",
        validation_status=ValidationStatus.CONFIRMED,
        source_tool="sqlmap",
    )

    triaged = StrixTriageEngine.triage_finding(finding_sqli)
    assert triaged.cvss_score == 9.8
    assert "CVSS:3.1" in triaged.cvss_vector
    assert triaged.owasp_category == "A03:2021 - Injection"
    assert not triaged.is_likely_false_positive
    assert "parameterized" in triaged.remediation_summary.lower()
    assert "cursor.execute" in triaged.remediation_snippet


def test_strix_triage_false_positive_heuristics():
    finding_mock = Finding(
        project_id="test-proj",
        title="Information Disclosure in headers",
        severity=FindingSeverity.LOW,
        affected_asset="http://127.0.0.1:8080",
        description="This was found in a test mock environment response.",
        remediation="Check headers.",
        validation_status=ValidationStatus.UNVERIFIED,
        source_tool="c0desec",
    )

    triaged = StrixTriageEngine.triage_finding(finding_mock)
    assert triaged.is_likely_false_positive
    assert triaged.confidence == "Low"


def test_strix_triage_all_sorting():
    f_low = Finding(
        project_id="p1",
        title="Missing Header",
        severity=FindingSeverity.LOW,
        affected_asset="127.0.0.1",
        description="Header issue",
        remediation="Add header",
    )
    f_crit = Finding(
        project_id="p1",
        title="SQL Injection",
        severity=FindingSeverity.CRITICAL,
        affected_asset="127.0.0.1",
        description="Database flaw",
        remediation="Fix query",
    )
    f_med = Finding(
        project_id="p1",
        title="CORS Wildcard",
        severity=FindingSeverity.MEDIUM,
        affected_asset="127.0.0.1",
        description="CORS issue",
        remediation="Restrict origin",
    )

    sorted_triaged = StrixTriageEngine.triage_all([f_low, f_crit, f_med])
    assert len(sorted_triaged) == 3
    assert sorted_triaged[0].cvss_score == 9.8  # Critical first
    assert sorted_triaged[1].cvss_score == 5.3  # Medium second
    assert sorted_triaged[2].cvss_score == 3.1  # Low third


# ---------------------------------------------------------------------------
# 5. UI Integration Tests (ToolsDashboard & WebScanView)
# ---------------------------------------------------------------------------

def test_tools_dashboard_scanners_box_tab(qtbot, test_db):
    """Verify ToolsDashboardView displays the Scanners-Box tab, filters, and item details."""
    from desktop.views.tools_view import ToolsDashboardView

    view = ToolsDashboardView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    assert view.tabs.count() == 2
    assert "Scanners-Box" in view.tabs.tabText(1)

    # Scanners-Box table population
    assert view.scanners_box_table.rowCount() >= 25

    # Filter by category
    view.scanners_box_cat_filter.setCurrentText("Database & SQL Injection")
    assert view.scanners_box_table.rowCount() >= 1

    # Reset category to All
    view.scanners_box_cat_filter.setCurrentText("All Categories")

    # Search by keyword
    view.scanners_box_search.setText("amass")
    assert view.scanners_box_table.rowCount() >= 1

    # Select row and verify detail panel
    view.scanners_box_table.selectRow(0)
    assert view.selected_sb_item is not None
    assert "amass" in view.selected_sb_item.name.lower()
    assert len(view.txt_sb_install.toPlainText()) > 5


def test_web_scan_sn1per_profiles_and_strix_triage_ui(qtbot, test_db):
    """Verify WebScanView Sn1per profile selectors and Strix AI triage finding display."""
    from desktop.views.web_scan_view import WebScanView

    project = test_db.create_project(Project(name="Web Sn1per UI Test"))
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(project)

    # 1. Test Sn1per Recon profile
    view._set_sn1per_profile("recon")
    assert view.cb_headers.isChecked()
    assert view.cb_cors.isChecked()
    assert not view.cb_waf.isChecked()
    assert not view.cb_sqlmap.isChecked()
    assert not view.cb_gobuster.isChecked()

    # 2. Test Sn1per Stealth profile
    view._set_sn1per_profile("stealth")
    assert view.cb_headers.isChecked()
    assert not view.cb_cors.isChecked()
    assert view.cb_waf.isChecked()
    assert not view.cb_sqlmap.isChecked()

    # 3. Test Sn1per Web Full profile
    view._set_sn1per_profile("web_full")
    assert view.cb_waf.isChecked()
    assert view.cb_gobuster.isChecked()
    assert not view.cb_sqlmap.isChecked()

    # 4. Test Sn1per Airstrike profile
    view._set_sn1per_profile("airstrike")
    assert view.cb_headers.isChecked()
    assert view.cb_waf.isChecked()
    assert view.cb_sqlmap.isChecked()
    assert view.cb_gobuster.isChecked()

    # 5. Strix AI Triage Finding Selection UI
    sqli_finding = Finding(
        project_id=project.id,
        title="SQL Injection vulnerability in login",
        severity=FindingSeverity.HIGH,
        cvss_score=8.1,
        affected_asset="http://127.0.0.1:8080/login",
        description="Vulnerable to UNION injection.",
        remediation="Use parameterized queries.",
        validation_status=ValidationStatus.CONFIRMED,
        source_tool="sqlmap",
    )
    view._current_findings = [sqli_finding]
    view.findings_table.setRowCount(1)
    from PySide6.QtWidgets import QTableWidgetItem
    view.findings_table.setItem(0, 0, QTableWidgetItem("HIGH"))
    view.findings_table.setItem(0, 1, QTableWidgetItem(sqli_finding.affected_asset))
    view.findings_table.setItem(0, 2, QTableWidgetItem(sqli_finding.title))
    view.findings_table.setItem(0, 3, QTableWidgetItem(sqli_finding.remediation))

    view.findings_table.selectRow(0)
    view._on_finding_selected()
    details = view.finding_details_text.toPlainText()

    assert "SQL Injection" in details
    assert "Strix AI" in details
    assert "A03:2021 - Injection" in details
    assert "Parameterized Query" in details

