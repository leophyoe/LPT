"""Comprehensive tests for Executive Security Analytics & Attack Surface Dashboard."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from desktop.dialogs.strix_triage_dialog import StrixTriageDialog
from desktop.views.dashboard_view import DashboardView, RiskGauge
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ToolExecution,
    ExecutionStatus,
    ValidationStatus,
)


@pytest.fixture
def test_db():
    db = Database(":memory:")
    return db


@pytest.fixture
def populated_db(test_db):
    proj = test_db.create_project(Project(name="Acme Corp Pentest", client_name="Acme Corp"))
    assert proj.id is not None

    # Scopes
    test_db.add_scope(TargetScope(project_id=proj.id, target="acme.corp", target_type=TargetType.HOSTNAME))
    test_db.add_scope(TargetScope(project_id=proj.id, target="api.acme.corp", target_type=TargetType.HOSTNAME))
    test_db.add_scope(TargetScope(project_id=proj.id, target="192.168.1.50", target_type=TargetType.IP_ADDRESS))
    test_db.add_scope(TargetScope(project_id=proj.id, target="https://acme.corp/app", target_type=TargetType.URL))

    # Findings
    f1 = Finding(
        project_id=proj.id,
        title="Log4j Remote Code Execution (CVE-2021-44228)",
        severity=FindingSeverity.CRITICAL,
        affected_asset="192.168.1.50",
        affected_port_service="8080/tcp",
        description="JNDI lookup injection allows unauthenticated remote code execution.",
        validation_status=ValidationStatus.CONFIRMED,
        source_tool="nikto",
    )
    test_db.create_finding(f1)

    f2 = Finding(
        project_id=proj.id,
        title="SQL Injection in /api/v1/user endpoint",
        severity=FindingSeverity.HIGH,
        affected_asset="https://acme.corp/app",
        affected_port_service="443/tcp",
        description="Blind Boolean SQL injection detected in 'id' parameter.",
        validation_status=ValidationStatus.UNVERIFIED,
        source_tool="sqlmap",
    )
    test_db.create_finding(f2)

    f3 = Finding(
        project_id=proj.id,
        title="Missing Strict-Transport-Security Header",
        severity=FindingSeverity.LOW,
        affected_asset="acme.corp",
        affected_port_service="80/tcp",
        description="HSTS header is absent from HTTP response.",
        validation_status=ValidationStatus.UNVERIFIED,
        source_tool="nikto",
    )
    test_db.create_finding(f3)

    f4 = Finding(
        project_id=proj.id,
        title="Weak JWT Signing Key With Low Entropy",
        severity=FindingSeverity.MEDIUM,
        affected_asset="api.acme.corp",
        affected_port_service="443/tcp",
        description="JWT token signed with weak secret.",
        validation_status=ValidationStatus.REMEDIATED,
        source_tool="ptk",
    )
    test_db.create_finding(f4)

    # Executions
    exec1 = ToolExecution(
        project_id=proj.id,
        tool_name="nmap",
        command="nmap -sV 192.168.1.50",
        status=ExecutionStatus.COMPLETED,
    )
    test_db.create_execution(exec1)

    return test_db, proj


def test_dashboard_initialization_empty(qtbot, test_db):
    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Empty baseline checks
    assert view.card_threat.value_label.text() == "NOT ASSESSED"
    assert view.gauge.score == 0
    assert view.gauge.grade == "—"
    assert view.findings_table.rowCount() == 0


def test_dashboard_with_populated_project(qtbot, populated_db):
    db, project = populated_db
    view = DashboardView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(project)
    view.show()

    # Metric checks
    assert "CRITICAL RISK" in view.card_threat.value_label.text()
    assert view.metric_assets.value_label.text() == "4"
    # Open findings: f1 (crit), f2 (high), f3 (low) = 3 open (f4 is remediated)
    assert view.metric_findings.value_label.text() == "3"

    # Gauge checks (Critical + High exposure triggers grade F)
    assert view.gauge.grade == "F"
    assert view.gauge.score > 0

    # Severity labels in gauge card
    assert "1" in view.severity_labels["critical"].text()
    assert "1" in view.severity_labels["high"].text()
    assert "1" in view.severity_labels["low"].text()

    # Table contains rows for open findings
    assert view.findings_table.rowCount() == 3

    # Activity list contains nmap execution
    assert view.activity_list.count() > 0


def test_dashboard_table_filtering(qtbot, populated_db):
    db, project = populated_db
    view = DashboardView(db=db)
    qtbot.addWidget(view)
    view.set_active_project(project)
    view.show()

    # Initial open count: 3
    assert view.findings_table.rowCount() == 3

    # Filter by search text
    view.search_input.setText("Log4j")
    assert view.findings_table.rowCount() == 1

    # Clear search
    view.search_input.clear()
    assert view.findings_table.rowCount() == 3

    # Filter by severity
    view.sev_filter_combo.setCurrentText("High")
    assert view.findings_table.rowCount() == 1


def test_strix_triage_dialog_and_status_update(qtbot, populated_db):
    db, project = populated_db
    findings = db.list_findings(project.id)
    sqli = [f for f in findings if "SQL" in f.title][0]

    dlg = StrixTriageDialog(finding=sqli, db=db)
    qtbot.addWidget(dlg)
    dlg.show()

    assert dlg.triaged.cvss_score >= 7.0
    assert "Injection" in dlg.triaged.owasp_category
    assert "parameterized" in dlg.triaged.remediation_summary.lower()
    assert dlg.triaged.remediation_snippet != ""

    # Mark as Confirmed
    dlg._set_status(ValidationStatus.CONFIRMED)
    updated_finding = db.get_finding(sqli.id)
    assert updated_finding is not None
    assert updated_finding.validation_status == ValidationStatus.CONFIRMED


def test_dashboard_navigation_signals(qtbot, test_db):
    view = DashboardView(db=test_db)
    qtbot.addWidget(view)

    received_indices = []
    view.navigate_requested.connect(lambda idx: received_indices.append(idx))

    # Click Quick Scan Pipeline button (navigates to web scan view: index 3)
    view.btn_quick_scan.click()
    assert 3 in received_indices


def test_dashboard_metric_cards_click_navigation(qtbot, test_db):
    """Verify clicking metric cards navigates to real, relevant views."""
    view = DashboardView(db=test_db)
    qtbot.addWidget(view)

    signals_received = []
    view.navigate_requested.connect(lambda idx: signals_received.append(idx))

    # Click Threat Card -> Findings (index 4)
    qtbot.mouseClick(view.card_threat, Qt.MouseButton.LeftButton)
    assert signals_received[-1] == 4

    # Click Attack Surface Card -> Asset Inventory (index 9)
    qtbot.mouseClick(view.metric_assets, Qt.MouseButton.LeftButton)
    assert signals_received[-1] == 9

    # Click Open Risks Card -> Findings (index 4)
    qtbot.mouseClick(view.metric_findings, Qt.MouseButton.LeftButton)
    assert signals_received[-1] == 4

    # Click Tool Runs Card -> Tools Integration (index 5)
    qtbot.mouseClick(view.card_arsenal, Qt.MouseButton.LeftButton)
    assert signals_received[-1] == 5

    # Click Remediation Card -> Findings (index 4)
    qtbot.mouseClick(view.card_remediation, Qt.MouseButton.LeftButton)
    assert signals_received[-1] == 4


def test_dashboard_metric_card_supports_keyboard_activation(qtbot, test_db):
    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    received_indices = []
    view.navigate_requested.connect(received_indices.append)

    view.metric_assets.setFocus()
    qtbot.keyClick(view.metric_assets, Qt.Key.Key_Space)
    assert received_indices == [9]


def test_dashboard_does_not_claim_hardened_without_security_assessment(qtbot, test_db):
    project = test_db.create_project(Project(name="No Findings Project"))
    assert project.id is not None
    test_db.add_scope(
        TargetScope(project_id=project.id, target="example.test", target_type=TargetType.HOSTNAME)
    )

    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(project)

    assert view.card_threat.value_label.text() == "NO FINDINGS"
    assert "not proof of security" in view.card_threat.hint_label.text()
    assert view.gauge.grade == "—"


def test_dashboard_uses_no_open_findings_instead_of_hardened(qtbot, test_db):
    project = test_db.create_project(Project(name="Closed Findings Project"))
    assert project.id is not None
    test_db.create_finding(
        Finding(
            project_id=project.id,
            title="Resolved test finding",
            severity=FindingSeverity.HIGH,
            validation_status=ValidationStatus.REMEDIATED,
        )
    )

    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(project)

    assert view.card_threat.value_label.text() == "NO OPEN FINDINGS"
    assert view.gauge.grade == "—"


def test_dashboard_empty_telemetry_honest_counts(qtbot, test_db):
    """Ensure empty dashboard shows honest zero metrics without fabricated demo percentages."""
    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # All impact bars and weakness bars should be 0% and 0 (0%)
    for key, (bar, count_lbl) in view.impact_bars.items():
        assert bar.value() == 0
        assert "0 (0%)" in count_lbl.text()

    for key, (bar, count_lbl) in view.weakness_bars.items():
        assert bar.value() == 0
        assert "0 (0%)" in count_lbl.text()


def test_dashboard_asset_nodes_inclusion_and_unique_counting(qtbot, test_db):
    """Verify discovered AssetNode entries are counted alongside TargetScope without double-counting."""
    proj = test_db.create_project(Project(name="Recon Project", client_name="ClientX"))
    assert proj.id is not None

    # Scope target
    test_db.add_scope(TargetScope(project_id=proj.id, target="192.168.1.100", target_type=TargetType.IP_ADDRESS))

    # AssetNode with same IP (should be deduplicated)
    from storage.models import AssetNode
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            node_type="ip",
            value="192.168.1.100",
            label="Gateway",
            source_tool="nmap",
        )
    )

    # Discovered new AssetNode (different host)
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            node_type="domain",
            value="vault.corp.internal",
            label="Internal Vault",
            source_tool="amass",
        )
    )

    view = DashboardView(db=test_db)
    qtbot.addWidget(view)
    view.set_active_project(proj)

    # 192.168.1.100 (in both scope and node) + vault.corp.internal = 2 unique assets
    assert view.metric_assets.value_label.text() == "2"
    assert "1 FQDNs" in view.metric_assets.hint_label.text()
    assert "1 IPs" in view.metric_assets.hint_label.text()


def test_dashboard_navigation_routes_to_correct_workspace_subtabs():
    """Regression: dashboard shortcut indices must match the actual workspace tab order."""
    from desktop.main_window import MainWindow

    class NavigationRecorder:
        def __init__(self):
            self.destination = None
            self.ai_focused = False

        def _navigate_to_workspace_subtab(self, workspace_index, tab_index):
            self.destination = (workspace_index, tab_index)

        def _focus_ai_panel(self):
            self.ai_focused = True

    expected = {
        0: (0, 1),  # Dashboard
        1: (0, 0),  # Projects / Scope
        2: (1, 0),  # Network Discovery
        3: (1, 1),  # Web Testing
        4: (2, 1),  # Findings Triage
        5: (1, 3),  # Tools
        6: (3, 0),  # CPENT
        8: (1, 2),  # OSINT
        9: (0, 2),  # Asset Inventory
    }
    for shortcut_index, destination in expected.items():
        recorder = NavigationRecorder()
        MainWindow._on_dashboard_navigation(recorder, shortcut_index)
        assert recorder.destination == destination

    recorder = NavigationRecorder()
    MainWindow._on_dashboard_navigation(recorder, 7)
    assert recorder.ai_focused is True
    assert recorder.destination is None


def test_scanner_launcher_routes_to_matching_workspace_subtabs():
    """Regression: scanner launch shortcuts must open the matching tool workspace."""
    from desktop.main_window import MainWindow

    class NavigationRecorder:
        def __init__(self):
            self.destinations = []
            self.web_view = type("WebViewRecorder", (), {"set_proxy_tab_visible": lambda self, visible: setattr(self, "proxy_visible", visible)})()

        def _navigate_to_workspace_subtab(self, workspace_index, tab_index):
            self.destinations.append((workspace_index, tab_index))

    expected = {
        "nmap": (1, 0),
        "sqlmap": (1, 1),
        "c0desec": (1, 1),
        "wafw00f": (1, 1),
        "gobuster": (1, 1),
        "ptk": (1, 1),
        "zaproxy": (1, 1),
        "burpsuite": (1, 1),
        "volatility3": (2, 0),
        "bandit": (2, 0),
        "amass": (1, 2),
        "recon-ng": (1, 2),
        "theharvester": (1, 2),
    }
    for tool_name, destination in expected.items():
        recorder = NavigationRecorder()
        MainWindow._on_open_scanner_requested(recorder, tool_name)
        assert recorder.destinations == [destination]
