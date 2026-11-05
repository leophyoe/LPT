"""Unit and integration tests for Phase 8 Web Security Suite.

Covers:
1. OWASP ZAP XML and JSON report parsing, alert normalization, and evidence generation.
2. Burp Suite XML issue export parsing and severity mapping.
3. ModSecurity WAF audit log ingestion and OWASP CRS rule matching.
4. Scope Authorization Guard isolation for external web reports.
5. WebScanView GUI import actions and finding table population.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication

from modules.web.burp_adapter import BurpReportParser, BurpSuiteAdapter
from modules.web.modsec_parser import ModSecurityParser
from modules.web.zap_adapter import ZAPAdapter, ZAPReportParser
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture
def app():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def test_project(db: Database) -> Project:
    p = db.create_project(
        Project(
            name="Web Security Testing Lab",
            client_name="Acme Corp",
            description="Testing OWASP ZAP, Burp, and ModSecurity WAF integrations.",
        )
    )
    db.add_scope(TargetScope(project_id=p.id, target="192.168.1.50", target_type=TargetType.IP_ADDRESS))
    db.add_scope(TargetScope(project_id=p.id, target="shop.acme.local", target_type=TargetType.HOSTNAME))
    return p


SAMPLE_ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="Tue, 27 Oct 2026 14:00:00">
  <site name="http://shop.acme.local" host="shop.acme.local" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alert>Cross Site Scripting (Reflected)</alert>
        <name>Cross Site Scripting (Reflected)</name>
        <riskcode>3</riskcode>
        <confidence>3</confidence>
        <riskdesc>High (High)</riskdesc>
        <desc>&lt;p&gt;Cross-site Scripting (XSS) is possible via query parameter q.&lt;/p&gt;</desc>
        <instances>
          <instance>
            <uri>http://shop.acme.local/search?q=%3Cscript%3Ealert(1)%3C/script%3E</uri>
            <method>GET</method>
            <param>q</param>
            <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
          </instance>
        </instances>
        <solution>&lt;p&gt;Context-encode all user input before outputting.&lt;/p&gt;</solution>
        <reference>&lt;p&gt;https://owasp.org/www-community/attacks/xss/&lt;/p&gt;</reference>
        <cweid>79</cweid>
        <wascid>8</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

SAMPLE_BURP_XML = """<?xml version="1.0"?>
<!DOCTYPE issues SYSTEM "burp.dtd">
<issues burpVersion="2026.1">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>1048832</type>
    <name>SQL injection (Boolean-based)</name>
    <host ip="192.168.1.50">http://192.168.1.50</host>
    <path>/catalog.php</path>
    <location>/catalog.php [id]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries without validation.&lt;/p&gt;</issueBackground>
    <remediationBackground>&lt;p&gt;Use parameterized queries or prepared statements.&lt;/p&gt;</remediationBackground>
    <vulnerabilityClassifications>&lt;ul&gt;&lt;li&gt;CWE-89&lt;/li&gt;&lt;/ul&gt;</vulnerabilityClassifications>
    <issueDetail>The parameter 'id' appears to be vulnerable to boolean-based SQL injection.</issueDetail>
  </issue>
</issues>
"""

SAMPLE_MODSEC_LOG = """--a1b2c3d4-A--
[27/Oct/2026:14:15:30 +0000] 10.10.10.200 48123 192.168.1.50 80
--a1b2c3d4-B--
GET /search?query=' UNION SELECT 1,username,password FROM users-- HTTP/1.1
Host: shop.acme.local
User-Agent: Mozilla/5.0
Accept: */*

--a1b2c3d4-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 202

--a1b2c3d4-H--
Message: Access denied with code 403 (phase 2). Pattern match "union.*select" at ARGS:query. [file "/etc/modsecurity/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "145"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: union select found within ARGS:query: ' UNION SELECT"] [severity "CRITICAL"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"]
Message: Inbound Anomaly Score Exceeded (Total Score: 10) [id "949110"] [msg "Inbound Anomaly Score Exceeded"] [severity "CRITICAL"]
--a1b2c3d4-Z--
"""


def test_zap_report_parsing(db: Database, test_project: Project, tmp_path: Path):
    adapter = ZAPAdapter(db=db)

    res = adapter.import_zap_report(
        project_id=test_project.id,
        content=SAMPLE_ZAP_XML,
        source_filename="zap_scan.xml",
        evidence_dir=tmp_path,
    )

    assert res.execution_status == ExecutionStatus.COMPLETED
    assert res.is_authorized is True
    assert len(res.findings) == 1

    finding = res.findings[0]
    assert finding.severity == FindingSeverity.HIGH
    assert "Cross Site Scripting" in finding.title
    assert "shop.acme.local" in finding.affected_asset
    assert "CWE-79" in finding.title
    assert res.evidence_id is not None
    assert res.evidence_hash != ""


def test_burp_xml_parsing(db: Database, test_project: Project, tmp_path: Path):
    adapter = BurpSuiteAdapter(db=db)

    res = adapter.import_burp_xml(
        project_id=test_project.id,
        xml_content=SAMPLE_BURP_XML,
        source_filename="burp_issues.xml",
        evidence_dir=tmp_path,
    )

    assert res.execution_status == ExecutionStatus.COMPLETED
    assert res.is_authorized is True
    assert len(res.findings) == 1

    finding = res.findings[0]
    assert finding.severity == FindingSeverity.HIGH
    assert "SQL injection" in finding.title
    assert "192.168.1.50" in finding.affected_asset
    assert finding.validation_status == ValidationStatus.CONFIRMED
    assert res.evidence_id is not None
    assert res.evidence_hash != ""


def test_modsec_waf_log_parsing(db: Database, test_project: Project, tmp_path: Path):
    scopes = db.list_scopes(test_project.id)

    findings, evidence, scope_res = ModSecurityParser.import_modsec_log(
        db=db,
        project_id=test_project.id,
        log_content=SAMPLE_MODSEC_LOG,
        scopes=scopes,
        source_filename="audit.log",
        evidence_dir=tmp_path,
    )

    assert scope_res.is_allowed is True
    assert len(findings) == 2  # Rule 942100 and Rule 949110
    assert len(evidence) == 1

    # First finding: SQLi
    f_sqli = [f for f in findings if "942100" in f.title][0]
    assert f_sqli.severity == FindingSeverity.CRITICAL
    assert "SQL Injection Attack" in f_sqli.title
    assert "shop.acme.local" in f_sqli.affected_asset
    assert "union select" in f_sqli.description


def test_scope_authorization_blocks_unauthorized_web_targets(db: Database, test_project: Project):
    # Only 192.168.1.50 and shop.acme.local are in scope
    out_of_scope_zap = SAMPLE_ZAP_XML.replace("shop.acme.local", "evil-unauthorized.target.com")
    adapter = ZAPAdapter(db=db)

    res = adapter.import_zap_report(
        project_id=test_project.id,
        content=out_of_scope_zap,
        source_filename="out_of_scope.xml",
    )
    # Target was filtered out by scope guard
    assert len(res.findings) == 0
    assert "0 authorized" in res.scope_reason


def test_web_scan_view_import_modsec_gui(app, db: Database, test_project: Project, tmp_path: Path):
    from desktop.views.web_scan_view import WebScanView

    view = WebScanView(db=db)
    view.set_active_project(test_project)

    log_file = tmp_path / "test_modsec.log"
    log_file.write_text(SAMPLE_MODSEC_LOG, encoding="utf-8")

    with patch("PySide6.QtWidgets.QFileDialog.getOpenFileName", return_value=(str(log_file), "")), \
         patch("PySide6.QtWidgets.QMessageBox.information"), \
         patch("PySide6.QtWidgets.QMessageBox.warning"):
        view._import_modsec_log()
        app.processEvents()

    # Verify findings loaded into table
    assert view.findings_table.rowCount() >= 2
    top_title = view.findings_table.item(0, 2).text()
    assert "WAF Block" in top_title or "SQL Injection" in top_title
