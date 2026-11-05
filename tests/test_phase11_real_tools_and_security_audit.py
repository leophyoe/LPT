"""Comprehensive Verification Test Suite for Phase 11:
- Real Tool Execution Engine (core/execution_service.py)
- THC-Hydra Credential Auditor Adapter (modules/system/hydra_adapter.py)
- Active Directory & Weak Password Auditor (core/ad_password_auditor.py & widget)
- Bob Findings & Code Security SAST Workbench (desktop/widgets/code_security_workbench.py)
- Cyber Sentinel & Modern Network Topology (desktop/widgets/network_map_view.py)
"""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from pathlib import Path

from core.execution_service import (
    ExecutionJob,
    JobState,
    ToolExecutionService,
)
from core.ad_password_auditor import (
    ADAccountRecord,
    ADAuditSummary,
    ADPasswordAuditor,
)
from desktop.widgets.academy_widget import AcademyWidget
from desktop.widgets.ad_password_auditor_widget import ADPasswordAuditorWidget
from desktop.widgets.code_security_workbench import CodeSecurityWorkbenchWidget
from desktop.widgets.network_map_view import NetworkMapView
from desktop.widgets.pcap_analyzer_widget import PCAPAnalyzerWidget
from modules.academy.academy_service import AcademyService
from modules.network.nmap_parser import HostResult, NmapScanResult, PortResult
from modules.system.hydra_adapter import HydraAdapter, HydraOptions
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
)


@pytest.fixture
def temp_db():
    return Database(":memory:")


@pytest.fixture
def test_project(temp_db):
    proj = temp_db.create_project(Project(name="Phase 11 Pentest Lab", client_name="Acme Corp"))
    scope = TargetScope(
        project_id=proj.id,
        target="127.0.0.1",
        target_type=TargetType.IP_ADDRESS,
        is_authorized=True,
    )
    temp_db.add_scope(scope)
    return proj


# ===========================================================================
# 1. Real Tool Execution Service Tests
# ===========================================================================

def test_execution_service_state_machine_and_redaction(temp_db, test_project, tmp_path):
    service = ToolExecutionService(db=temp_db)

    # Verify sensitive flag redaction
    raw_args = ["hydra", "-l", "admin", "-p", "SuperSecret123!", "ssh://127.0.0.1"]
    redacted = service.redact_sensitive_args(raw_args)
    assert "SuperSecret123!" not in redacted
    assert "***REDACTED***" in redacted

    # Run real safe command through service (echo)
    job = ExecutionJob(
        tool_name="test_tool",
        target="127.0.0.1",
        command=["echo", "CyberSecuritySuite Operational Engine"],
        project_id=test_project.id,
        timeout=10.0,
        evidence_dir=tmp_path / "evidence",
    )

    finished_job = service.execute_job_sync(job)
    assert finished_job.state == JobState.COMPLETED
    assert finished_job.exit_code == 0
    assert "CyberSecuritySuite Operational Engine" in finished_job.stdout
    assert finished_job.evidence_id is not None
    assert finished_job.evidence_hash is not None


def test_execution_service_blocks_unauthorized_target(temp_db, test_project):
    service = ToolExecutionService(db=temp_db)

    job = ExecutionJob(
        tool_name="nmap",
        target="192.168.99.99",  # Not in scope!
        command=["echo", "should not run"],
        project_id=test_project.id,
    )

    finished_job = service.execute_job_sync(job)
    assert finished_job.state == JobState.BLOCKED
    assert "Scope Blocked" in finished_job.error_message


# ===========================================================================
# 2. THC-Hydra Password Auditor Tests
# ===========================================================================

def test_hydra_adapter_command_building_and_scope(temp_db, test_project):
    adapter = HydraAdapter(db=temp_db)
    scopes = temp_db.list_scopes(test_project.id)

    opts = HydraOptions(
        target="127.0.0.1",
        service="ssh",
        username="root",
        password="toor",
        tasks=4,
        dry_run=True,
    )

    cmd = adapter.build_command(opts)
    assert "ssh://127.0.0.1" in cmd[-1]
    assert "-t" in cmd
    assert "-f" in cmd

    # Test Dry-Run Execution
    res = adapter.execute_audit(
        project_id=test_project.id,
        options=opts,
        scopes=scopes,
    )
    assert res.is_authorized is True
    assert "Dry Run" in res.raw_output

    # Test Out-of-Scope Rejection
    opts_bad = HydraOptions(target="10.200.200.200", service="ssh")
    res_bad = adapter.execute_audit(
        project_id=test_project.id,
        options=opts_bad,
        scopes=scopes,
    )
    assert res_bad.is_authorized is False
    assert "Scope Authorization Blocked" in res_bad.error_message


def test_hydra_output_parser():
    sample_output = """
    Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
    [DATA] max 4 tasks per 1 server, overall 4 tasks, 1 login tries (l:1/p:1), ~1 tries per task
    [22][ssh] host: 127.0.0.1   login: admin   password: Password123!
    1 of 1 target successfully completed, 1 valid password found
    """
    creds = HydraAdapter.parse_hydra_output(sample_output, "127.0.0.1", "ssh", 22)
    assert len(creds) == 1
    assert creds[0].username == "admin"
    assert creds[0].password == "Password123!"
    assert creds[0].service == "ssh"
    assert creds[0].port == 22


# ===========================================================================
# 3. Active Directory Weak Password Auditor Tests (KnowBe4 Style)
# ===========================================================================

def test_ad_password_auditor_rules_and_findings(temp_db, test_project):
    auditor = ADPasswordAuditor(db=temp_db)
    dataset = auditor.get_sample_enterprise_dataset()

    summary: ADAuditSummary = auditor.audit_accounts(dataset)
    assert summary.total_accounts > 0
    assert summary.vulnerable_accounts > 0
    assert summary.weak_password_count > 0
    assert summary.shared_password_count > 0
    assert summary.missing_preauth_count > 0

    # Verify Findings generation and database persistence
    findings = auditor.generate_findings_for_project(
        summary=summary,
        project_id=test_project.id,
        domain_name="CORP.LOCAL",
    )
    assert len(findings) >= 3
    db_findings = temp_db.list_findings(test_project.id)
    assert len(db_findings) >= 3

    # Check for AS-REP Roasting finding
    asrep_finding = next((f for f in db_findings if "AS-REP" in f.title), None)
    assert asrep_finding is not None
    assert asrep_finding.severity == FindingSeverity.HIGH


def test_ad_password_auditor_widget(temp_db, qtbot):
    widget = ADPasswordAuditorWidget(db=temp_db)
    qtbot.addWidget(widget)

    assert widget.current_summary is not None
    assert widget.table_accounts.rowCount() > 0
    assert widget.list_categories.count() > 0

    # Filter by Weak Password category
    for i in range(widget.list_categories.count()):
        item = widget.list_categories.item(i)
        if "Weak Password" in item.text():
            widget.list_categories.setCurrentItem(item)
            break
    assert widget.current_filter_category == "Weak Password"


# ===========================================================================
# 4. Bob Findings & Code Security SAST Workbench Tests
# ===========================================================================

def test_code_security_workbench_ast_detection(temp_db, qtbot, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)

    widget = CodeSecurityWorkbenchWidget(db=temp_db)
    qtbot.addWidget(widget)

    # Initial sample code loaded in widget
    assert len(widget.current_issues) > 0

    # Ensure SQL Injection (CWE-89) was caught by pure-Python AST engine
    sqli_issue = next((iss for iss in widget.current_issues if "89" in iss.cwe_id), None)
    assert sqli_issue is not None
    assert "SQL" in sqli_issue.title

    # Test "Go To Location" navigation
    widget._select_issue(sqli_issue)
    widget._goto_location()
    assert widget.editor.vulnerable_line == sqli_issue.line_number

    # Test AI chat investigation signal emission
    with qtbot.waitSignal(widget.send_to_ai_chat, timeout=1000) as blocker:
        widget._investigate_in_chat()
    assert "CWE-89" in blocker.args[0]


# ===========================================================================
# 5. Cyber Sentinel & Modern Network Topology Map Tests
# ===========================================================================

def test_network_map_cyber_sentinel_view(qtbot):
    map_view = NetworkMapView()
    qtbot.addWidget(map_view)

    # Construct sample scan result
    scan = NmapScanResult(
        command_args="nmap -sV 192.168.1.0/24",
        hosts=[
            HostResult(
                ip="192.168.1.10",
                hostname="DC-Alpha.corp.local",
                status="up",
                os_match="Windows Server 2022",
                ports=[
                    PortResult(port_id=88, protocol="tcp", state="open", service_name="kerberos"),
                    PortResult(port_id=389, protocol="tcp", state="open", service_name="ldap"),
                    PortResult(port_id=445, protocol="tcp", state="open", service_name="microsoft-ds"),
                ],
            ),
            HostResult(
                ip="192.168.1.20",
                hostname="Web-Server01",
                status="up",
                os_match="Linux 6.1 Ubuntu",
                ports=[
                    PortResult(port_id=80, protocol="tcp", state="open", service_name="http"),
                    PortResult(port_id=443, protocol="tcp", state="open", service_name="https"),
                ],
            ),
        ],
    )

    sample_finding = Finding(
        project_id=1,
        title="Active Directory Kerberos Pre-Auth Disabled",
        severity=FindingSeverity.HIGH,
        affected_asset="192.168.1.10",
    )

    map_view.load_scan(scan, [sample_finding])

    # Verify device drawer and graphics items
    assert map_view.list_devices.count() == 2
    items = map_view.scene.items()
    assert len(items) >= 4  # Hub, 2 nodes, 2 lines

    # Verify SVG generation contains Cyber Sentinel header
    svg = map_view.to_svg()
    assert "CYBER SENTINEL" in svg
    assert "192.168.1.10" in svg
    assert "192.168.1.20" in svg


# ===========================================================================
# 6. Offline PCAP Protocol Analyzer Tests
# ===========================================================================

def test_pcap_analyzer_widget_creation_and_tabs(temp_db, qtbot):
    widget = PCAPAnalyzerWidget(db=temp_db)
    qtbot.addWidget(widget)

    assert widget.tabs.count() == 4
    assert "DNS" in widget.tabs.tabText(0)
    assert "HTTP" in widget.tabs.tabText(1)
    assert "TLS" in widget.tabs.tabText(2)
    assert "ARP" in widget.tabs.tabText(3)


# ===========================================================================
# 7. Python Security Academy Tests
# ===========================================================================

def test_academy_service_verification_and_widget(temp_db, qtbot, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)

    service = AcademyService(db=temp_db)
    tracks = service.get_tracks()
    assert len(tracks) >= 3

    # Test SQLi Verification
    sqli_lesson = service.lessons.get("sqli_101")
    assert sqli_lesson is not None

    # Insecure attempt fails
    bad_res = service.verify_solution("sqli_101", "cursor.execute(f'SELECT * FROM users WHERE u = {user}')")
    assert not bad_res.is_passed

    # Secure attempt passes
    good_res = service.verify_solution("sqli_101", "cursor.execute('SELECT * FROM users WHERE u = ?', (user,))")
    assert good_res.is_passed
    assert "CPENT{" in good_res.flag

    # Test AcademyWidget UI
    widget = AcademyWidget(db=temp_db)
    qtbot.addWidget(widget)

    assert widget.list_lessons.count() >= 4
    assert widget.active_lesson is not None
    assert widget.editor.toPlainText() != ""

    # Test Verify button in widget
    widget.editor.setPlainText("cursor.execute('SELECT * FROM users WHERE u = ?', (user,))")
    widget._verify_solution()
    assert "FLAG" in widget.lbl_feedback.text()

