"""Unit and GUI tests for Phase 6 Reporting Service."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from reports.builder import AssessmentReportData, ReportBuilder
from storage.db import Database
from storage.models import (
    AssessmentPlan,
    AssessmentStatus,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    TestCategory,
    TerminalSessionRecord,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def populated_project(db: Database) -> int:
    """Creates a realistic assessment project with scopes, executions, findings, and evidence."""
    project = db.create_project(
        Project(
            name="Alpha Corp Penetration Test",
            client_name="Alpha Corp Ltd",
            description="External network and web API penetration testing engagement.",
        )
    )
    p_id = project.id
    assert p_id is not None

    # 1. Scopes
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
            notes="Corporate subnet",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="api.alphacorp.internal",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
            notes="Internal API gateway",
        )
    )

    # 2. Tool Executions
    exec1 = db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="nmap",
            command="nmap -sV -p 22,80,443 192.168.1.50",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            duration_seconds=4.2,
        )
    )
    exec2 = db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="c0desec",
            command="c0desec-web-assessment https://api.alphacorp.internal",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            duration_seconds=3.1,
        )
    )

    # 3. Findings
    f1 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Insecure Cross-Origin Resource Sharing (CORS) Misconfiguration",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            affected_asset="api.alphacorp.internal",
            affected_port_service="443/https",
            description="The API reflects arbitrary origin headers with credentials allowed.",
            reproduction_steps="curl -H 'Origin: https://evil.corp' -I https://api.alphacorp.internal",
            remediation="Enforce an explicit whitelist of trusted origins.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="c0desec",
            execution_id=exec2.id,
        )
    )

    f2 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Remote Code Execution via Apache Log4j",
            severity=FindingSeverity.CRITICAL,
            cvss_score=10.0,
            affected_asset="192.168.1.50",
            affected_port_service="8080/http",
            description="JNDI lookup evaluation in log messages enables unauthenticated RCE.",
            remediation="Upgrade Log4j to version 2.17.1 or higher.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="nmap",
            execution_id=exec1.id,
        )
    )

    f3 = db.create_finding(
        Finding(
            project_id=p_id,
            title="Missing Content-Security-Policy (CSP) Header",
            severity=FindingSeverity.MEDIUM,
            cvss_score=4.3,
            affected_asset="api.alphacorp.internal",
            affected_port_service="443/https",
            description="Absence of CSP reduces defense against XSS.",
            remediation="Implement a strict CSP header.",
            validation_status=ValidationStatus.UNVERIFIED,
            source_tool="c0desec",
            execution_id=exec2.id,
        )
    )

    # 4. Evidence
    db.add_evidence(
        Evidence(
            project_id=p_id,
            finding_id=f1.id,
            execution_id=exec2.id,
            file_path="storage/evidence/cors_capture.json",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            description="Captured HTTP OPTIONS response headers",
            mime_type="application/json",
        )
    )

    return p_id


def test_report_builder_empty_project(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Empty Project Assessment"))
    builder = ReportBuilder(db)

    # JSON
    json_path = tmp_path / "empty.json"
    json_res = builder.generate_json(project.id, output_path=json_path)
    parsed = json.loads(json_res)
    assert parsed["project"]["name"] == "Empty Project Assessment"
    assert parsed["metrics"]["total_findings"] == 0
    assert json_path.exists()

    # Markdown
    md_path = tmp_path / "empty.md"
    md_res = builder.generate_markdown(project.id, output_path=md_path)
    assert "Empty Project Assessment" in md_res
    assert "*No security vulnerabilities identified*" in md_res
    assert md_path.exists()

    # HTML
    html_path = tmp_path / "empty.html"
    html_res = builder.generate_html(project.id, output_path=html_path)
    assert "<!DOCTYPE html>" in html_res
    assert "Empty Project Assessment" in html_res
    assert html_path.exists()


def test_report_builder_with_populated_project(db: Database, populated_project: int, tmp_path: Path):
    builder = ReportBuilder(db)
    p_id = populated_project

    # 1. Test ReportData aggregation
    data = builder.build_report_data(p_id)
    assert isinstance(data, AssessmentReportData)
    assert data.project.name == "Alpha Corp Penetration Test"
    assert data.metrics.total_findings == 3
    assert data.metrics.critical_count == 1
    assert data.metrics.high_count == 1
    assert data.metrics.medium_count == 1
    assert data.metrics.max_cvss == 10.0
    assert data.metrics.total_targets == 2
    assert data.metrics.total_evidence_files == 1
    assert data.metrics.confirmed_findings == 2
    assert data.metrics.unverified_findings == 1

    # 2. Test JSON Generation
    json_str = builder.generate_json(p_id)
    report_json = json.loads(json_str)
    assert report_json["generator"] == "CyberSecuritySuite Assessment Engine"
    assert report_json["metrics"]["confirmed_findings"] == 2
    assert report_json["metrics"]["unverified_findings"] == 1
    assert "Verify target authorization" in report_json["sample_data_notice"]
    assert len(report_json["findings"]) == 3
    assert len(report_json["scopes"]) == 2
    assert len(report_json["evidence"]) == 1
    assert report_json["evidence"][0]["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert "cpent_framework" in report_json
    assert "rating_levels" in report_json["cpent_framework"]
    assert "strategic_recommendations" in report_json["cpent_framework"]

    # 3. Test Markdown Generation
    md_str = builder.generate_markdown(p_id)
    assert "# Security Assessment & Penetration Testing Report" in md_str
    assert "Alpha Corp Ltd" in md_str
    assert "Sample data notice" in md_str
    assert "Remote Code Execution via Apache Log4j" in md_str
    assert "EC-Council CPENT" in md_str
    assert "Risk Assessment Matrix" in md_str
    assert "Summary of Strategic Recommendations" in md_str
    assert "Appendix A: References" in md_str
    assert "Appendix B: CPENT Security Terminology Glossary" in md_str
    assert "| Confirmed Vulnerabilities | 2 |" in md_str
    assert "| Unverified Observations | 1 |" in md_str
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in md_str

    # 4. Test HTML Generation
    html_str = builder.generate_html(p_id)
    assert "<!DOCTYPE html>" in html_str
    assert "Alpha Corp Penetration Test" in html_str
    assert "CONFIDENTIAL" in html_str.upper()
    assert "Sample data notice" in html_str
    assert "CRITICAL" in html_str
    assert "JNDI lookup evaluation" in html_str
    assert "Risk Assessment Matrix" in html_str
    assert "Strategic Recommendations" in html_str
    assert "Appendix A: Standards & Authoritative References" in html_str
    assert "Appendix B: CPENT Security Terminology Glossary" in html_str
    assert "@media print" in html_str
    assert "2</strong> vulnerabilities were confirmed with evidence" in html_str
    assert "1</strong> observations remain unverified" in html_str


def test_report_exports_redact_sensitive_assessment_text(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Redaction Assessment"))
    execution = db.create_execution(
        ToolExecution(
            project_id=project.id,
            tool_name="scanner",
            command="scanner --password command-secret-123 api_key=command-api-secret-123",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
        )
    )
    db.create_finding(
        Finding(
            project_id=project.id,
            title="Credential exposure",
            description="api_key=finding-api-secret-123",
            reproduction_steps="Authorization: Basic dXNlcjpwYXNzd29yZA==",
            remediation="Set client_secret=remediation-secret-123",
            execution_id=execution.id,
        )
    )
    builder = ReportBuilder(db)

    exports = {
        "json": builder.generate_json(project.id),
        "markdown": builder.generate_markdown(project.id),
        "html": builder.generate_html(project.id),
        "csv": builder.generate_csv(project.id, output_path=tmp_path / "findings.csv").read_text(encoding="utf-8"),
    }
    for report_format, contents in exports.items():
        assert "command-secret-123" not in contents, report_format
        assert "command-api-secret-123" not in contents, report_format
        assert "finding-api-secret-123" not in contents, report_format
        assert "dXNlcjpwYXNzd29yZA==" not in contents, report_format
        assert "remediation-secret-123" not in contents, report_format
        assert "[REDACTED" in contents, report_format


def test_cpent_methodology_report_uses_linked_records_and_is_read_only(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Methodology Assessment"))
    db.add_scope(
        TargetScope(
            project_id=project.id,
            target="192.0.2.10",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    )
    execution = db.create_execution(
        ToolExecution(
            project_id=project.id,
            tool_name="inventory-tool",
            command="inventory-tool --password report-secret-123 192.0.2.10",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            raw_output_path="/tmp/inventory-output.xml",
        )
    )
    plan = db.create_assessment_plan(
        AssessmentPlan(
            project_id=project.id,
            title="Host inventory review",
            target="192.0.2.10",
            test_category=TestCategory.NETWORK_DISCOVERY,
            description="Document the observed host inventory.",
            acceptance_criteria="Record only verified observations.",
            status=AssessmentStatus.COMPLETED,
            execution_id=execution.id,
        )
    )
    finding = db.create_finding(
        Finding(
            project_id=project.id,
            title="Service configuration observation",
            severity=FindingSeverity.MEDIUM,
            validation_status=ValidationStatus.OBSERVED,
            remediation="Review the service configuration.",
            execution_id=execution.id,
        )
    )
    artifact = tmp_path / "evidence.xml"
    artifact.write_text("<evidence/>", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    evidence = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(artifact),
            sha256_hash=digest,
            finding_id=finding.id,
            execution_id=execution.id,
            description="Observed service output",
        )
    )
    before_status = db.get_assessment_plan(plan.id).status
    builder = ReportBuilder(db)

    json_text = builder.generate_cpent_methodology_json(project.id)
    report = json.loads(json_text)
    assert report["report_type"] == "original_cpent_methodology_and_evidence"
    test_record = report["tests"][0]
    assert test_record["test_id"] == "not_recorded"
    assert test_record["plan_id"] == plan.id
    assert test_record["scope_match"] == "exact_match"
    assert test_record["execution"]["tool"] == "inventory-tool"
    assert test_record["execution"]["command"].endswith("[REDACTED_PASSWORD] 192.0.2.10")
    assert test_record["results_analysis"][0]["finding_id"] == finding.id
    assert test_record["evidence"][0]["id"] == evidence.id
    assert test_record["evidence"][0]["sha256"] == digest
    assert "report-secret-123" not in json_text

    markdown_path = tmp_path / "cpent-methodology.md"
    markdown = builder.generate_cpent_methodology_markdown(project.id, output_path=markdown_path)
    assert markdown_path.read_text(encoding="utf-8") == markdown
    assert "# CPENT Methodology & Evidence Report" in markdown
    assert "CPENT Test ID:** not_recorded" in markdown
    assert "Scope Match:** exact_match" in markdown
    assert "SHA-256" in markdown
    assert "report-secret-123" not in markdown
    assert db.get_assessment_plan(plan.id).status == before_status


def test_reports_verify_evidence_integrity(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Evidence Integrity Report"))

    intact_file = tmp_path / "intact.txt"
    intact_file.write_bytes(b"original evidence")
    intact = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(intact_file),
            sha256_hash=hashlib.sha256(b"original evidence").hexdigest(),
            description="Untampered artifact",
        )
    )

    changed_file = tmp_path / "changed.txt"
    changed_file.write_bytes(b"modified evidence")
    changed = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(changed_file),
            sha256_hash=hashlib.sha256(b"original evidence").hexdigest(),
            description="Modified artifact",
        )
    )

    missing = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(tmp_path / "missing.txt"),
            sha256_hash=hashlib.sha256(b"missing evidence").hexdigest(),
            description="Missing artifact",
        )
    )
    unverified_file = tmp_path / "unverified.txt"
    unverified_file.write_text("No digest recorded", encoding="utf-8")
    unverified = db.add_evidence(
        Evidence(
            project_id=project.id,
            file_path=str(unverified_file),
            description="Artifact without digest",
        )
    )

    session_file = tmp_path / "session.raw"
    session_file.write_bytes(b"raw terminal output")
    session = db.create_terminal_session(
        TerminalSessionRecord(
            project_id=project.id,
            session_id="integrity-session",
            raw_output_path=str(session_file),
            sha256_hash=hashlib.sha256(b"raw terminal output").hexdigest(),
        )
    )

    builder = ReportBuilder(db)
    report = json.loads(builder.generate_json(project.id))
    integrity_by_id = {item["id"]: item["integrity_status"] for item in report["evidence"]}
    assert integrity_by_id == {
        intact.id: "verified",
        changed.id: "mismatch",
        missing.id: "missing",
        unverified.id: "unverified",
    }
    session_report = next(
        item for item in report["terminal_sessions"]
        if item["session_id"] == session.session_id
    )
    assert session_report["integrity_status"] == "verified"

    markdown = builder.generate_markdown(project.id)
    html_report = builder.generate_html(project.id)
    for status in ("verified", "mismatch", "missing", "unverified"):
        assert f"`{status}`" in markdown
        assert f"<td>{status}</td>" in html_report
    assert "A stored hash alone does not establish" in markdown
    assert "Integrity Status | Commands" in markdown
    assert "`verified`" in markdown


def test_report_builder_generate_pdf_valid_header(db: Database, populated_project: int, tmp_path: Path):
    builder = ReportBuilder(db)
    pdf_path = tmp_path / "test_report.pdf"
    result_path = builder.generate_pdf(populated_project, output_path=pdf_path)

    assert result_path == pdf_path
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000
    content = pdf_path.read_bytes()
    assert content.startswith(b"%PDF-"), f"Expected %PDF- magic signature, got {content[:10]}"


def test_report_builder_generate_pdf_empty_project(db: Database, tmp_path: Path):
    project = db.create_project(Project(name="Empty Assessment For PDF"))
    builder = ReportBuilder(db)
    pdf_path = tmp_path / "empty_report.pdf"
    result_path = builder.generate_pdf(project.id, output_path=pdf_path)

    assert result_path == pdf_path
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
    content = pdf_path.read_bytes()
    assert content.startswith(b"%PDF-")


def test_report_builder_generate_all(db: Database, populated_project: int, tmp_path: Path):
    builder = ReportBuilder(db)
    out_dict = builder.generate_all(populated_project, output_dir=tmp_path / "reports_out")

    assert "pdf" in out_dict
    assert "html" in out_dict
    assert "markdown" in out_dict
    assert "json" in out_dict

    assert out_dict["pdf"].exists()
    assert out_dict["html"].exists()
    assert out_dict["markdown"].exists()
    assert out_dict["json"].exists()

    assert out_dict["pdf"].suffix == ".pdf"
    assert out_dict["html"].suffix == ".html"
    assert out_dict["markdown"].suffix == ".md"
    assert out_dict["json"].suffix == ".json"

    # Verify PDF signature
    assert out_dict["pdf"].read_bytes().startswith(b"%PDF-")

    latest_index = tmp_path / "reports_out" / "LATEST_REPORTS.md"
    assert latest_index.exists()
    assert out_dict["markdown"].name in latest_index.read_text(encoding="utf-8")


def test_report_builder_nonexistent_project_raises(db: Database):
    builder = ReportBuilder(db)
    with pytest.raises(ValueError, match="does not exist"):
        builder.build_report_data(99999)


def test_findings_view_report_export_gui(qtbot, db: Database, populated_project: int, monkeypatch, tmp_path: Path):
    from desktop.views.findings_view import FindingsView
    from PySide6.QtWidgets import QMessageBox

    view = FindingsView(db=db)
    qtbot.addWidget(view)
    view.show()

    # 1. Without active project: export warns user
    warn_calls = []
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, msg: warn_calls.append((title, msg)))
    view._export_report("html")
    assert len(warn_calls) == 1
    assert "No Project Selected" in warn_calls[0][0]

    # 2. With loaded project: export generates file
    info_calls = []
    monkeypatch.setattr(QMessageBox, "information", lambda parent, title, msg: info_calls.append((title, msg)))

    view.load_findings(populated_project)
    assert view.active_project_id == populated_project
    assert view.table.rowCount() == 3

    # Click export HTML
    view._export_report("html")
    assert len(info_calls) == 1
    assert "Report Generated Successfully" in info_calls[0][0]
    assert "HTML report" in view.export_status.text()

    # Click export Markdown
    view._export_report("markdown")
    assert len(info_calls) == 2
    assert "MARKDOWN report" in view.export_status.text()

    # Click export JSON
    view._export_report("json")
    assert len(info_calls) == 3
    assert "JSON report" in view.export_status.text()

    # Click export PDF
    view._export_report("pdf")
    assert len(info_calls) == 4
    assert "PDF report" in view.export_status.text()
