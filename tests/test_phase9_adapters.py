"""Phase 9 Security Tool Integration Audit and Completion Tests.

Tests adapter interfaces, availability checks, configuration validation,
ZAP XML/JSON report parsing, Burp XML issue parsing, scope filtering,
cryptographic SHA-256 evidence integrity, finding deduplication,
and assessment linkage across the security tool pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication

from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from modules.network.nmap_adapter import NmapAdapter
from modules.web.burp_adapter import BurpReportParser, BurpSuiteAdapter
from modules.web.c0desec_adapter import WebSecurityAdapter
from modules.web.zap_adapter import ZAPAdapter, ZAPReportParser
from storage.db import Database
from storage.models import (
    Assessment,
    AssessmentStatus,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture
def test_db(tmp_path):
    """Creates a temporary isolated SQLite test database."""
    db_file = tmp_path / "test_phase9.db"
    db = Database(str(db_file))
    return db


@pytest.fixture
def project_with_scope(test_db):
    """Sets up a test project with authorized and restricted scopes, and an active assessment."""
    proj = test_db.create_project(Project(name="Phase9 Audit Lab", client_name="Acme Security"))
    
    # Authorized scopes
    test_db.add_scope(TargetScope(
        project_id=proj.id,
        target="192.168.1.10",
        target_type=TargetType.IP_ADDRESS,
        is_authorized=True,
    ))
    test_db.add_scope(TargetScope(
        project_id=proj.id,
        target="app.target.lab",
        target_type=TargetType.HOSTNAME,
        is_authorized=True,
    ))

    # Assessment
    asm = test_db.create_assessment(Assessment(
        project_id=proj.id,
        name="Phase 9 AppSec Review",
        authorized_scope="app.target.lab and 192.168.1.10",
        status=AssessmentStatus.IN_PROGRESS,
    ))

    return proj, asm


# Sample OWASP ZAP XML Report
SAMPLE_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="Tue, 27 Oct 2026 10:00:00">
  <site name="http://app.target.lab" host="app.target.lab" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alert>Cross Site Scripting (Reflected)</alert>
        <name>Cross Site Scripting (Reflected)</name>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <riskdesc>High (Medium)</riskdesc>
        <desc>&lt;p&gt;Cross-site Scripting (XSS) is an attack where scripts are executed in a user's browser.&lt;/p&gt;</desc>
        <uri>http://app.target.lab/search.php?q=test</uri>
        <param>q</param>
        <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
        <evidence>&lt;script&gt;alert(1)&lt;/script&gt;</evidence>
        <solution>&lt;p&gt;Context-encode all user input before outputting into HTML.&lt;/p&gt;</solution>
        <cweid>79</cweid>
        <wascid>8</wascid>
      </alertitem>
      <alertitem>
        <pluginid>10038</pluginid>
        <alert>Content Security Policy (CSP) Header Not Set</alert>
        <name>Content Security Policy (CSP) Header Not Set</name>
        <riskcode>1</riskcode>
        <confidence>2</confidence>
        <riskdesc>Low (Medium)</riskdesc>
        <desc>Content Security Policy header is missing.</desc>
        <uri>http://app.target.lab/</uri>
        <param></param>
        <solution>Ensure CSP header is properly configured.</solution>
        <cweid>693</cweid>
      </alertitem>
    </alerts>
  </site>
  <site name="http://malicious-external.com" host="malicious-external.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <alert>Out of scope alert</alert>
        <name>Out of scope alert</name>
        <riskcode>2</riskcode>
        <desc>Should be filtered by scope guard</desc>
        <uri>http://malicious-external.com/admin</uri>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

# Sample OWASP ZAP JSON Report
SAMPLE_ZAP_JSON = json.dumps({
    "@version": "2.14.0",
    "site": [
        {
            "@name": "http://app.target.lab",
            "@host": "app.target.lab",
            "@port": "80",
            "alerts": [
                {
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "2",
                    "desc": "SQL injection vulnerability detected in user parameter.",
                    "uri": "http://app.target.lab/items?id=1",
                    "param": "id",
                    "solution": "Use parameterized prepared statements.",
                    "cweid": "89"
                }
            ]
        }
    ]
})

# Sample Burp Suite Scanner XML Report
SAMPLE_BURP_XML = """<?xml version="1.0"?>
<issues burpVersion="2026.1" exportTime="Tue Oct 27 10:00:00 2026">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>1048832</type>
    <name>SQL injection</name>
    <host ip="192.168.1.10">http://app.target.lab</host>
    <path>/api/users</path>
    <location>/api/users [param: filter]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;SQL injection vulnerabilities arise when user input is concatenated into SQL queries.&lt;/p&gt;</issueBackground>
    <remediationBackground>&lt;p&gt;Use parameterized queries or ORM frameworks.&lt;/p&gt;</remediationBackground>
    <issueDetail>The parameter 'filter' appeared to be vulnerable to SQL injection.</issueDetail>
    <vulnerabilityClassifications>&lt;ul&gt;&lt;li&gt;&lt;a href="https://cwe.mitre.org/data/definitions/89.html"&gt;CWE-89: SQL Injection&lt;/a&gt;&lt;/li&gt;&lt;/ul&gt;</vulnerabilityClassifications>
  </issue>
  <issue>
    <serialNumber>1002</serialNumber>
    <type>1048833</type>
    <name>Password field with autocomplete enabled</name>
    <host ip="192.168.1.10">http://app.target.lab</host>
    <path>/login</path>
    <location>/login</location>
    <severity>Information</severity>
    <confidence>Firm</confidence>
    <issueBackground>Autocomplete attribute is not set to off.</issueBackground>
    <remediationBackground>Add autocomplete="off" or "current-password".</remediationBackground>
    <vulnerabilityClassifications>&lt;ul&gt;&lt;li&gt;CWE-522: Insufficiently Protected Credentials&lt;/li&gt;&lt;/ul&gt;</vulnerabilityClassifications>
  </issue>
  <issue>
    <serialNumber>1003</serialNumber>
    <name>Out of Scope Burp Vulnerability</name>
    <host ip="10.99.99.99">http://unauthorized-domain.com</host>
    <path>/secret</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>Host not in authorization scope.</issueBackground>
  </issue>
</issues>
"""


# =============================================================================
# 1. Base Security Adapter Tests
# =============================================================================

def test_all_adapters_subclass_base_security_adapter(test_db):
    """Verifies all primary security adapters implement BaseSecurityAdapter interface."""
    adapters = [
        NmapAdapter(test_db),
        WebSecurityAdapter(test_db),
        ZAPAdapter(test_db),
        BurpSuiteAdapter(test_db),
    ]
    for adapter in adapters:
        assert isinstance(adapter, BaseSecurityAdapter)
        assert bool(adapter.tool_name)
        assert bool(adapter.display_name)
        
        # Test availability check returns 3-tuple (bool, version, path)
        avail, ver, path = adapter.check_availability()
        assert isinstance(avail, bool)


def test_base_adapter_scope_authorization(test_db, project_with_scope):
    """Verifies validate_target_scope properly validates in-scope and blocks out-of-scope."""
    proj, asm = project_with_scope
    adapter = ZAPAdapter(test_db)

    # In-scope targets
    res_in_scope = adapter.validate_target_scope("app.target.lab", proj.id)
    assert res_in_scope.is_allowed

    res_in_scope_ip = adapter.validate_target_scope("192.168.1.10", proj.id)
    assert res_in_scope_ip.is_allowed

    # Out-of-scope targets
    res_out_scope = adapter.validate_target_scope("evil.com", proj.id)
    assert not res_out_scope.is_allowed


# =============================================================================
# 2. OWASP ZAP Adapter & Parser Tests
# =============================================================================

def test_zap_xml_parser(project_with_scope):
    """Tests ZAP XML parser converts alertitems into normalized Finding instances."""
    proj, asm = project_with_scope
    findings = ZAPReportParser.parse_xml(
        SAMPLE_ZAP_XML,
        project_id=proj.id,
        execution_id=1,
        assessment_id=asm.id,
    )
    assert len(findings) == 3

    # Check XSS finding
    xss = findings[0]
    assert "CWE-79" in xss.title
    assert xss.severity == FindingSeverity.HIGH
    assert xss.affected_asset == "app.target.lab"
    assert xss.source_tool == "zaproxy"
    assert xss.assessment_id == asm.id
    assert "Context-encode" in xss.remediation
    assert "<p>" not in xss.description  # HTML stripped

    # Check CSP finding
    csp = findings[1]
    assert "CWE-693" in csp.title
    assert csp.severity == FindingSeverity.LOW


def test_zap_json_parser(project_with_scope):
    """Tests ZAP JSON parser correctly converts JSON alerts."""
    proj, asm = project_with_scope
    findings = ZAPReportParser.parse_json(
        SAMPLE_ZAP_JSON,
        project_id=proj.id,
        execution_id=2,
        assessment_id=asm.id,
    )
    assert len(findings) == 1
    sqli = findings[0]
    assert "CWE-89" in sqli.title
    assert sqli.severity == FindingSeverity.HIGH
    assert sqli.affected_asset == "app.target.lab"
    assert sqli.assessment_id == asm.id


def test_zap_import_with_scope_deduplication_and_provenance(test_db, project_with_scope, tmp_path):
    """Tests full ZAP import workflow with scope enforcement, SHA-256 evidence, and deduplication."""
    proj, asm = project_with_scope
    adapter = ZAPAdapter(test_db)
    ev_dir = tmp_path / "evidence"

    # First import
    res1 = adapter.import_zap_report(
        project_id=proj.id,
        content=SAMPLE_ZAP_XML,
        assessment_id=asm.id,
        source_filename="zap_test.xml",
        evidence_dir=ev_dir,
    )
    assert res1.execution_status == ExecutionStatus.COMPLETED
    assert res1.evidence_hash is not None
    assert len(res1.evidence_hash) == 64  # SHA-256 hex length
    assert len(res1.findings) == 2  # Only the 2 in-scope findings, out-of-scope filtered!

    # Check evidence file saved on disk
    ev_files = list(ev_dir.glob("zap_import_*.xml"))
    assert len(ev_files) == 1

    # Second import of identical report (Deduplication test!)
    res2 = adapter.import_zap_report(
        project_id=proj.id,
        content=SAMPLE_ZAP_XML,
        assessment_id=asm.id,
        source_filename="zap_test.xml",
        evidence_dir=ev_dir,
    )
    assert res2.execution_status == ExecutionStatus.COMPLETED

    # Total findings in database should still be 2, not 4!
    all_findings = test_db.list_findings(proj.id)
    assert len(all_findings) == 2


def test_zap_malformed_xml_handling(test_db, project_with_scope):
    """Tests graceful handling when an invalid/corrupt XML string is imported."""
    proj, asm = project_with_scope
    adapter = ZAPAdapter(test_db)

    res = adapter.import_zap_report(
        project_id=proj.id,
        content="<malformed><unclosed_tag>",
        assessment_id=asm.id,
    )
    assert res.execution_status == ExecutionStatus.FAILED
    assert "Failed to parse ZAP report" in res.error_message


# =============================================================================
# 3. Burp Suite Adapter & Parser Tests
# =============================================================================

def test_burp_xml_parser(project_with_scope):
    """Tests Burp Suite XML issue parser extracts severity, confidence, CWE, and text."""
    proj, asm = project_with_scope
    findings = BurpReportParser.parse_xml(
        SAMPLE_BURP_XML,
        project_id=proj.id,
        execution_id=1,
        assessment_id=asm.id,
    )
    assert len(findings) == 3

    # Check SQL injection issue
    sqli = findings[0]
    assert "CWE-89" in sqli.title
    assert sqli.severity == FindingSeverity.HIGH
    assert sqli.validation_status == ValidationStatus.CONFIRMED  # Certain -> CONFIRMED
    assert sqli.affected_asset == "app.target.lab"
    assert sqli.source_tool == "burpsuite"
    assert sqli.assessment_id == asm.id
    assert "<p>" not in sqli.description  # HTML stripped

    # Check Info issue
    info = findings[1]
    assert "CWE-522" in info.title
    assert info.severity == FindingSeverity.INFORMATIONAL
    assert info.validation_status == ValidationStatus.OBSERVED  # Firm -> OBSERVED


def test_burp_import_with_scope_deduplication_and_provenance(test_db, project_with_scope, tmp_path):
    """Tests full Burp import workflow with scope filtering, SHA-256 evidence, and deduplication."""
    proj, asm = project_with_scope
    adapter = BurpSuiteAdapter(test_db)
    ev_dir = tmp_path / "evidence"

    # First import
    res1 = adapter.import_burp_xml(
        project_id=proj.id,
        xml_content=SAMPLE_BURP_XML,
        assessment_id=asm.id,
        source_filename="burp_test.xml",
        evidence_dir=ev_dir,
    )
    assert res1.execution_status == ExecutionStatus.COMPLETED
    assert res1.evidence_hash is not None
    assert len(res1.evidence_hash) == 64
    assert len(res1.findings) == 2  # 2 authorized, 1 out-of-scope rejected!

    # Check evidence file saved on disk
    ev_files = list(ev_dir.glob("burp_import_*.xml"))
    assert len(ev_files) == 1

    # Second import (Deduplication test!)
    res2 = adapter.import_burp_xml(
        project_id=proj.id,
        xml_content=SAMPLE_BURP_XML,
        assessment_id=asm.id,
        source_filename="burp_test.xml",
        evidence_dir=ev_dir,
    )
    assert res2.execution_status == ExecutionStatus.COMPLETED

    # Total findings in DB must still be 2!
    all_findings = test_db.list_findings(proj.id)
    assert len(all_findings) == 2


def test_burp_malformed_xml_handling(test_db, project_with_scope):
    """Tests graceful failure on malformed Burp XML."""
    proj, asm = project_with_scope
    adapter = BurpSuiteAdapter(test_db)

    res = adapter.import_burp_xml(
        project_id=proj.id,
        xml_content="<issues><issue><name>Truncated...",
        assessment_id=asm.id,
    )
    assert res.execution_status == ExecutionStatus.FAILED
    assert "Failed to parse Burp Suite XML report" in res.error_message


# =============================================================================
# 4. Proxy Daemon Health Checks
# =============================================================================

def test_daemon_health_checks(test_db):
    """Verifies socket check handles non-listening ports cleanly without crashing."""
    zap = ZAPAdapter(test_db)
    burp = BurpSuiteAdapter(test_db)

    # Port 59999 should not be listening
    assert zap.check_daemon_health("127.0.0.1", port=59999, timeout=0.1) is False
    assert burp.check_daemon_health("127.0.0.1", port=59999, timeout=0.1) is False


# =============================================================================
# 5. UI Integration in WebScanView
# =============================================================================

def test_web_scan_view_has_import_buttons_and_adapters(qtbot, test_db):
    """Verifies WebScanView initializes ZAP and Burp adapters and import buttons."""
    from desktop.views.web_scan_view import WebScanView
    view = WebScanView(test_db)
    qtbot.addWidget(view)

    # Adapters present
    assert hasattr(view, "zap_adapter")
    assert isinstance(view.zap_adapter, ZAPAdapter)
    assert hasattr(view, "burp_adapter")
    assert isinstance(view.burp_adapter, BurpSuiteAdapter)

    # Buttons present
    assert hasattr(view, "btn_import_zap")
    assert hasattr(view, "btn_import_burp")
    assert view.btn_import_zap.text() == "📥 Import ZAP Report (XML/JSON)"
    assert view.btn_import_burp.text() == "📥 Import Burp XML Report"
