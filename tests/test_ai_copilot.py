"""Tests for AICopilotEngine: output diagnosis, command generation, and finding extraction."""

import pytest
from core.ai_copilot import AICopilotEngine, AIProvider
from storage.models import FindingSeverity, TargetScope, TargetType


@pytest.fixture
def copilot():
    return AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)


def test_copilot_diagnose_permission_denied(copilot):
    sample = "nmap: socket: Permission denied (13)\nYou need to be root to perform raw socket scans."
    res = copilot.diagnose_output(sample, exit_code=1)
    assert "elevated root" in res.analysis.lower() or "root" in res.root_cause.lower()
    assert "sudo" in res.suggested_fix.lower()


def test_copilot_diagnose_connection_refused(copilot):
    sample = "Failed to establish a new connection: [Errno 111] Connection refused"
    res = copilot.diagnose_output(sample, exit_code=1)
    assert "offline" in res.analysis.lower() or "unreachable" in res.analysis.lower()
    assert "target" in res.suggested_fix.lower()


def test_copilot_diagnose_missing_module(copilot):
    sample = "ModuleNotFoundError: No module named 'yaml'"
    res = copilot.diagnose_output(sample, exit_code=1)
    assert "dependency" in res.analysis.lower()
    assert "pip install yaml" in res.suggested_command.lower()


def test_copilot_diagnose_sqlmap_vulnerability(copilot):
    sample = "[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N]"
    res = copilot.diagnose_output(sample, exit_code=0)
    assert "sql injection" in res.analysis.lower()
    assert res.severity == "CRITICAL"


def test_copilot_generate_nmap_command(copilot):
    scopes = [
        TargetScope(project_id=1, target="192.168.1.50", target_type=TargetType.IP_ADDRESS, is_authorized=True)
    ]
    # Fast top ports
    res_fast = copilot.generate_command("run fast top ports scan on 192.168.1.50", scopes=scopes)
    assert "nmap" in res_fast.command
    assert "-F" in res_fast.command
    assert res_fast.is_in_scope is True

    # Full port scan
    res_full = copilot.generate_command("full port scan on 192.168.1.50", scopes=scopes)
    assert "-p-" in res_full.command
    assert res_full.is_in_scope is True


def test_copilot_generate_command_scope_guard(copilot):
    scopes = [
        TargetScope(project_id=1, target="192.168.1.50", target_type=TargetType.IP_ADDRESS, is_authorized=True)
    ]
    # Out of scope target
    res_out = copilot.generate_command("scan ports on 10.0.0.99", scopes=scopes)
    assert res_out.is_in_scope is False
    assert any(k in res_out.scope_reason.lower() for k in ["not in", "not authorized", "out of scope"])


def test_copilot_generate_gobuster_command(copilot):
    scopes = [
        TargetScope(project_id=1, target="targetlab.corp", target_type=TargetType.HOSTNAME, is_authorized=True)
    ]
    res = copilot.generate_command("find hidden web directories on targetlab.corp", scopes=scopes)
    assert "gobuster" in res.command
    assert "dir" in res.command
    assert res.is_in_scope is True


def test_copilot_extract_findings_from_nmap(copilot):
    nmap_output = """
    PORT     STATE SERVICE VERSION
    21/tcp   open  ftp     vsftpd 2.0.8
    80/tcp   open  http    Apache httpd 2.4.41
    445/tcp  open  netbios-ssn Samba
    3306/tcp open  mysql   MySQL 5.7.33
    """
    findings = copilot.extract_findings_from_terminal(nmap_output, target="192.168.1.100", project_id=1)
    assert len(findings) == 4

    titles = [f.title for f in findings]
    assert any("FTP" in t for t in titles)
    assert any("SMB" in t for t in titles)
    assert any("Database" in t or "MYSQL" in t.upper() for t in titles)

    # Check database severity is HIGH
    db_finding = next(f for f in findings if "3306" in f.affected_port_service)
    assert db_finding.severity == FindingSeverity.HIGH


def test_copilot_extract_findings_from_gobuster(copilot):
    gobuster_output = """
    /admin                (Status: 200) [Size: 1240]
    /.git                 (Status: 301) [Size: 178]
    /contact              (Status: 200) [Size: 840]
    """
    findings = copilot.extract_findings_from_terminal(gobuster_output, target="http://127.0.0.1:8080", project_id=1)
    assert len(findings) == 2  # admin and .git
    assert any(".git" in f.title for f in findings)
    assert any("admin" in f.title for f in findings)
