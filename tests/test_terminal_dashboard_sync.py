"""Comprehensive tests for Terminal-to-Dashboard live telemetry and finding synchronization."""

from __future__ import annotations

import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from unittest.mock import MagicMock
import pytest

from core.strix_triage import StrixTriageEngine
from desktop.views.dashboard_view import DashboardView
from desktop.widgets.terminal_view import TerminalWidget
from storage.db import Database
from storage.models import ExecutionStatus, FindingSeverity, Project, TargetScope, TargetType
from terminal.ingest import TerminalIngestEngine
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def sync_db():
    return Database(":memory:")


@pytest.fixture
def sync_project(sync_db):
    return sync_db.create_project(
        Project(
            name="Bank Corp Engagement",
            client_name="BankCorp Global",
            description="Production penetration test and attack surface assessment",
        )
    )


def test_terminal_ingest_target_extraction():
    """Verify target discovery extracts IPs, CIDRs, Hostnames, and URLs while ignoring vendor links."""
    cmd = "nmap -sV -p 80,443 scanme.nmap.org"
    output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2026-10-21 00:00 UTC
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.050s latency).
PORT    STATE SERVICE REASON  VERSION
80/tcp  open  http    syn-ack Apache httpd 2.4.7
443/tcp open  ssl/ssl syn-ack OpenSSL 1.0.1
"""
    targets = TerminalIngestEngine.extract_targets(cmd, output)
    target_map = {t[0]: t[1] for t in targets}

    # scanme.nmap.org and 45.33.32.156 should be extracted
    assert "scanme.nmap.org" in target_map
    assert target_map["scanme.nmap.org"] == TargetType.HOSTNAME
    assert "45.33.32.156" in target_map
    assert target_map["45.33.32.156"] == TargetType.IP_ADDRESS

    # https://nmap.org should be filtered out (vendor documentation link)
    assert "https://nmap.org" not in target_map


def test_terminal_ingest_nmap_and_strix_triage(sync_db, sync_project):
    """Verify Nmap scan output creates findings enriched with Strix CVSS approximations."""
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE)
    )
    output = """
Nmap scan report for internal-router.corp (192.168.1.1)
23/tcp   open  telnet
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
"""
    findings = TerminalIngestEngine.ingest_command_output(
        db=sync_db,
        project_id=sync_project.id,
        execution_id=None,
        tool_name="nmap",
        command="nmap 192.168.1.1",
        output=output,
    )

    assert len(findings) == 3
    # Check Telnet finding has High severity and Telnet remediation
    telnet_finding = next((f for f in findings if "telnet" in f.title.lower()), None)
    assert telnet_finding is not None
    assert telnet_finding.severity == FindingSeverity.HIGH
    assert telnet_finding.cvss_score >= 7.0
    assert "SSH" in telnet_finding.remediation

    # Discovery output must never grant authorization or expand scope.
    scopes = sync_db.list_scopes(sync_project.id)
    scope_targets = {s.target for s in scopes}
    assert scope_targets == {"192.168.1.0/24"}


def test_terminal_output_never_authorizes_discovered_targets(sync_db, sync_project):
    targets = [("192.0.2.10", TargetType.IP_ADDRESS)]
    assert TerminalIngestEngine.register_targets(
        sync_db, sync_project.id, targets, "nmap"
    ) == []
    assert sync_db.list_scopes(sync_project.id) == []


def test_terminal_ingest_nikto_and_sqlmap(sync_db, sync_project):
    """Verify Nikto web scan and SQLMap outputs create structured findings in DB."""
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="app.bankcorp.local", target_type=TargetType.HOSTNAME)
    )
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="bankcorp.com", target_type=TargetType.HOSTNAME)
    )
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="10.10.10.0/24", target_type=TargetType.CIDR_RANGE)
    )
    # 1. Nikto
    nikto_out = """
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.50
+ Target Hostname:    app.bankcorp.local
+ Target Port:        443
---------------------------------------------------------------------------
+ /admin/: Admin directory found (OSVDB-3268)
+ The anti-clickjacking X-Frame-Options header is not present.
"""
    nikto_findings = TerminalIngestEngine.ingest_command_output(
        db=sync_db,
        project_id=sync_project.id,
        execution_id=None,
        tool_name="nikto",
        command="nikto -h https://app.bankcorp.local",
        output=nikto_out,
    )
    assert len(nikto_findings) >= 2

    # 2. SQLMap
    sqlmap_out = """
sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=admin' AND 3821=3821 AND 'qWbK'='qWbK
---
[INFO] the back-end DBMS is PostgreSQL
"""
    sqlmap_findings = TerminalIngestEngine.ingest_command_output(
        db=sync_db,
        project_id=sync_project.id,
        execution_id=None,
        tool_name="sqlmap",
        command="sqlmap -u https://app.bankcorp.local/login --data='username=admin&pass=123'",
        output=sqlmap_out,
    )
    assert len(sqlmap_findings) == 1
    sqli = sqlmap_findings[0]
    assert sqli.severity == FindingSeverity.CRITICAL
    assert sqli.cvss_score == 9.8
    assert "SQL Injection" in sqli.title


def test_terminal_ingest_wafw00f_and_gobuster(sync_db, sync_project):
    """Verify WAFW00F and Gobuster outputs create proper findings and register targets."""
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="bankcorp.com", target_type=TargetType.HOSTNAME)
    )
    # 1. WAFW00F
    waf_out = "[+] The site https://bankcorp.com is behind Cloudflare (Cloudflare Inc.) WAF."
    waf_findings = TerminalIngestEngine.ingest_command_output(
        db=sync_db,
        project_id=sync_project.id,
        execution_id=None,
        tool_name="wafw00f",
        command="wafw00f https://bankcorp.com",
        output=waf_out,
    )
    assert len(waf_findings) == 1
    assert "Cloudflare" in waf_findings[0].title

    # 2. Gobuster
    gobuster_out = """
/admin                (Status: 301) [Size: 178] [--> /admin/]
/.env                 (Status: 200) [Size: 320]
/images               (Status: 301) [Size: 120]
/login                (Status: 200) [Size: 1540]
"""
    gobuster_findings = TerminalIngestEngine.ingest_command_output(
        db=sync_db,
        project_id=sync_project.id,
        execution_id=None,
        tool_name="gobuster",
        command="gobuster dir -u https://bankcorp.com -w common.txt",
        output=gobuster_out,
    )
    assert len(gobuster_findings) >= 2  # /.env and /admin sensitive, /images and /login general


def test_terminal_to_dashboard_live_sync(qtbot, sync_db, sync_project):
    """End-to-End integration test: command execution in terminal directly updates DashboardView."""
    # 1. Instantiate DashboardView and TerminalWidget
    dashboard = DashboardView(db=sync_db)
    qtbot.addWidget(dashboard)
    dashboard.set_active_project(sync_project)

    terminal = TerminalWidget(db=sync_db)
    qtbot.addWidget(terminal)
    terminal.set_active_project(sync_project, sync_db)
    sync_db.add_scope(
        TargetScope(project_id=sync_project.id, target="10.0.0.0/8", target_type=TargetType.CIDR_RANGE)
    )

    # Connect terminal signal to dashboard refresh
    terminal.project_data_updated.connect(dashboard.refresh)

    # Initial state verification
    assert dashboard.metric_assets.value_label.text() == "0"
    assert dashboard.metric_findings.value_label.text() == "0"
    assert dashboard.card_arsenal.value_label.text() == "0"

    # 2. Simulate running a security tool command in terminal
    now_iso = "2026-10-21T00:00:00Z"
    mock_result = ProcessExecutionResult(
        command=["nmap", "10.0.0.1"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 10.0.0.1" version="7.94">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<hostnames><hostname name="dc01.bankcorp.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
</ports></host></nmaprun>
""",
        stderr="",
        started_at=now_iso,
        finished_at=now_iso,
        duration_seconds=1.45,
    )

    # 3. Deliver result to terminal
    terminal._save_command_result(mock_result, "nmap 10.0.0.1", sync_project)

    # 4. Verify Dashboard updated automatically!
    # Assets should now reflect 10.0.0.1 and dc01.bankcorp.local
    assert int(dashboard.metric_assets.value_label.text()) >= 2
    # Findings should reflect kerberos, ldap, smb
    assert int(dashboard.metric_findings.value_label.text()) >= 3
    # Arsenal execution count should now be 1
    assert dashboard.card_arsenal.value_label.text() == "1"

    # Check findings table populated
    assert dashboard.findings_table.rowCount() >= 3

    # Check asset list populated
    assert dashboard.assets_list.count() >= 2

    # Check activity list populated
    assert dashboard.activity_list.count() >= 1


def test_failed_terminal_scan_saves_evidence_without_ingesting_assets_or_findings(
    qtbot, sync_db, sync_project, tmp_path
):
    terminal = TerminalWidget(db=sync_db, evidence_dir=tmp_path / "evidence")
    qtbot.addWidget(terminal)
    terminal.set_active_project(sync_project, sync_db)
    sync_db.add_scope(
        TargetScope(
            project_id=sync_project.id,
            target="10.0.0.0/8",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    now = "2026-10-28T00:00:00Z"
    failed = ProcessExecutionResult(
        command=["nmap", "-oX", "-", "10.0.0.5"],
        status=ExecutionStatus.FAILED,
        exit_code=2,
        stdout='<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>',
        stderr="invalid option",
        started_at=now,
        finished_at=now,
        duration_seconds=0.1,
    )

    terminal._save_command_result(failed, "nmap -oX - 10.0.0.5", sync_project)

    assert sync_db.list_asset_nodes(sync_project.id) == []
    assert sync_db.list_findings(sync_project.id) == []
    assert len(sync_db.list_evidence(sync_project.id)) == 1
    assert sync_db.list_executions(sync_project.id)[0].status == ExecutionStatus.FAILED


def test_terminal_auto_binds_project_if_none_selected(qtbot, sync_db):
    """If user executes commands before selecting a project, terminal notifies user and does not auto-create dummy projects."""
    terminal = TerminalWidget(db=sync_db)
    qtbot.addWidget(terminal)
    assert terminal.active_project is None

    now_iso = "2026-10-21T00:00:00Z"
    mock_result = ProcessExecutionResult(
        command=["ping", "-c", "1", "127.0.0.1"],
        status=ExecutionStatus.COMPLETED,
        exit_code=0,
        stdout="64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.03 ms",
        stderr="",
        started_at=now_iso,
        finished_at=now_iso,
        duration_seconds=0.1,
    )

    # Execute with project=None
    terminal._save_command_result(mock_result, "ping -c 1 127.0.0.1", None)

    # Verify terminal did not auto-create an unauthorized dummy project
    assert terminal.active_project is None
    assert len(sync_db.list_projects()) == 0
