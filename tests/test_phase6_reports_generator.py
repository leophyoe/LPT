"""Unit and GUI tests for Phase 6: CPENT Multi-Format Professional Report Generator.

Verifies:
1. ReportBuilder CSV Matrix Export (RFC-4180 compliance, header validation, data integrity).
2. ReportBuilder generate_all() 5-format bundle (PDF, HTML, Markdown, JSON, CSV).
3. ReportsView GUI Component:
   - 4-Tab structure (Executive Posture, Findings Matrix, Remediation Roadmap, Live Preview).
   - Posture Score & Letter Grade computation.
   - Severity KPI counts & CPENT 5-Pillars classification.
   - High-density matrix table filtering (search text, severity filter, status filter).
   - Finding inspector drawer telemetry and cryptographic evidence verification.
   - Multi-format export handlers (PDF, HTML, CSV, MD, JSON, CPENT Pack ZIP).
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QFileDialog, QMessageBox

from desktop.views.reports_view import ReportsView
from reports.builder import AssessmentReportData, ReportBuilder
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_cpent_project(db: Database) -> int:
    """Creates a comprehensive assessment project across CPENT domains."""
    project = db.create_project(
        Project(
            name="MegaCorp CPENT Assessment",
            client_name="MegaCorp Global",
            description="Enterprise internal & external penetration test.",
        )
    )
    p_id = project.id
    assert p_id is not None

    # Scopes
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
            notes="Internal network subnet",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="corp.megacorp.internal",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
            notes="Web application portal",
        )
    )

    # Tool Execution
    db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="nmap",
            command="nmap -sV 10.10.10.10",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            duration_seconds=5.0,
        )
    )

    # Findings across pillars
    # 1. Web SQL Injection (Critical)
    f1 = db.create_finding(
        Finding(
            project_id=p_id,
            title="SQL Injection in User Search Parameter (CWE-89)",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_asset="corp.megacorp.internal",
            affected_port_service="443/https",
            description="Direct string concatenation in SQL queries allows database dump.",
            reproduction_steps="curl -X POST https://corp.megacorp.internal/search -d \"q=' OR 1=1--\"",
            remediation="Use parameterized queries with SQLAlchemy prepared statements.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="semgrep",
        )
    )

    # 2. Evidence linked to f1
    db.create_evidence(
        Evidence(
            project_id=p_id,
            finding_id=f1.id,
            file_path="evidence/semgrep_finding.txt",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            description="Vulnerable SQL query detected at user_repository.py:114",
        )
    )

    # 2. Active Directory Kerberoasting (High)
    db.create_finding(
        Finding(
            project_id=p_id,
            title="Kerberoasting Weak SPN Accounts in Active Directory",
            severity=FindingSeverity.HIGH,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            affected_asset="10.10.10.5",
            affected_port_service="88/kerberos",
            description="Service Principal Names configured with weak RC4 encryption.",
            reproduction_steps="GetUserSPNs.py megacorp.internal/user:pass -request",
            remediation="Enforce AES-256 for Kerberos tickets and 25+ character passwords.",
            validation_status=ValidationStatus.CONFIRMED,
            source_tool="mimikatz",
        )
    )

    # 3. Network SMB Signing Disabled (Medium)
    db.create_finding(
        Finding(
            project_id=p_id,
            title="SMB Signing Not Enforced on Workstations",
            severity=FindingSeverity.MEDIUM,
            cvss_score=5.9,
            cvss_vector="CVSS:3.1/AV:N/AC:M/PR:N/UI:N/S:U/C:L/I:L/A:N",
            affected_asset="10.10.10.100",
            affected_port_service="445/smb",
            description="SMB signing is disabled, allowing NTLM relay attacks.",
            reproduction_steps="nmap --script smb2-security-mode -p 445 10.10.10.100",
            remediation="Enable 'RequireSecuritySignature' via Active Directory GPO.",
            validation_status=ValidationStatus.OBSERVED,
            source_tool="nmap",
        )
    )

    return p_id


# =============================================================================
# 1. ReportBuilder CSV Export Tests
# =============================================================================

def test_report_builder_generate_csv(db: Database, sample_cpent_project: int, tmp_path: Path):
    """Verifies RFC-4180 CSV matrix generation with headers and finding rows."""
    builder = ReportBuilder(db)
    csv_file = tmp_path / "findings_matrix.csv"

    out_path = builder.generate_csv(sample_cpent_project, output_path=csv_file)
    assert out_path == csv_file
    assert csv_file.exists()
    assert csv_file.stat().st_size > 0

    with open(csv_file, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Check header
    header = rows[0]
    expected_cols = [
        "Finding ID",
        "Title",
        "Severity",
        "CVSS Score",
        "CVSS Vector",
        "Affected Asset",
        "Port / Service",
        "Validation Status",
        "Source Tool",
        "Assessment ID",
        "Evidence SHA-256",
        "Description",
        "Remediation Guidance",
    ]
    assert header == expected_cols

    # Check finding rows count
    assert len(rows) == 4  # Header + 3 findings

    # Check row titles
    row_titles = [r[1] for r in rows[1:]]
    assert any("SQL Injection" in t for t in row_titles)
    assert any("Kerberoasting" in t for t in row_titles)
    assert any("SMB Signing" in t for t in row_titles)

    # Check specific fields
    sqli_row = next(r for r in rows[1:] if "SQL Injection" in r[1])
    assert sqli_row[2] == "CRITICAL"
    assert sqli_row[3] == "9.8"
    assert sqli_row[5] == "corp.megacorp.internal"
    assert sqli_row[6] == "443/https"
    assert sqli_row[7] == "CONFIRMED"
    assert sqli_row[8] == "semgrep"
    assert len(sqli_row[10]) == 64  # SHA-256 hash length


def test_report_builder_generate_all_includes_csv(db: Database, sample_cpent_project: int, tmp_path: Path):
    """Verifies generate_all() produces 5 formats: PDF, HTML, Markdown, JSON, and CSV."""
    builder = ReportBuilder(db)
    out_dir = tmp_path / "multi_reports"
    out_dict = builder.generate_all(sample_cpent_project, output_dir=out_dir)

    for fmt in ["pdf", "html", "markdown", "json", "csv"]:
        assert fmt in out_dict, f"Format {fmt} missing from generate_all output"
        assert out_dict[fmt].exists(), f"File for {fmt} does not exist"
        assert out_dict[fmt].stat().st_size > 0, f"File for {fmt} is empty"

    assert out_dict["csv"].suffix == ".csv"
    assert out_dict["pdf"].read_bytes().startswith(b"%PDF-")


# =============================================================================
# 2. ReportsView GUI Tests
# =============================================================================

def test_reports_view_tabs_and_structure(qtbot, db: Database):
    """Verifies ReportsView initializes with 4 tabs and expected header controls."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    assert view.tabs.count() == 4
    tab_titles = [view.tabs.tabText(i) for i in range(4)]
    assert "📊 Executive Posture & Analytics" in tab_titles[0]
    assert "📑 Findings Matrix & Evidence Vault" in tab_titles[1]
    assert "🛣️ 5-Pillar Remediation Roadmap" in tab_titles[2]
    assert "👁️ Live Report Document Preview" in tab_titles[3]

    # Verify buttons
    assert view.btn_pdf is not None
    assert view.btn_html is not None
    assert view.btn_csv is not None
    assert view.btn_md is not None
    assert view.btn_json is not None
    assert view.btn_pack is not None


def test_reports_view_load_project_and_metrics(qtbot, db: Database, sample_cpent_project: int):
    """Verifies that loading a project updates posture score, KPI cards, and matrix table."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    project = db.get_project(sample_cpent_project)
    view.set_active_project(project)

    # Penalties: Critical(20) + High(8) + Med(3) = 31 penalty -> Score = 69% (Grade C)
    assert view.lbl_posture_val.text() == "69%"
    assert "Grade C" in view.lbl_posture_grade.text()
    assert view.pbar_posture.value() == 69

    # KPI counts
    assert view.kpi_cards["CRITICAL"][0].text() == "1"
    assert view.kpi_cards["HIGH"][0].text() == "1"
    assert view.kpi_cards["MEDIUM"][0].text() == "1"
    assert view.kpi_cards["LOW"][0].text() == "0"
    assert view.kpi_cards["INFO"][0].text() == "0"

    # Matrix table rows
    assert view.matrix_table.rowCount() == 3

    # CPENT 5-Pillar labels
    assert "1 Findings" in view.pillar_labels["Web Applications"].text()
    assert "1 Findings" in view.pillar_labels["Active Directory"].text()
    assert "1 Findings" in view.pillar_labels["Network & Infrastructure"].text()


def test_reports_view_matrix_filtering(qtbot, db: Database, sample_cpent_project: int):
    """Verifies matrix search bar and severity combo filtering."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    project = db.get_project(sample_cpent_project)
    view.set_active_project(project)

    # Search for 'SQL' -> 1 visible row
    view.matrix_search_input.setText("SQL")
    visible_count = sum(1 for r in range(view.matrix_table.rowCount()) if not view.matrix_table.isRowHidden(r))
    assert visible_count == 1

    # Clear search -> all 3 visible
    view.matrix_search_input.setText("")
    visible_count = sum(1 for r in range(view.matrix_table.rowCount()) if not view.matrix_table.isRowHidden(r))
    assert visible_count == 3

    # Filter by 'Critical' -> 1 visible row
    idx = view.combo_matrix_severity.findText("Critical")
    view.combo_matrix_severity.setCurrentIndex(idx)
    visible_count = sum(1 for r in range(view.matrix_table.rowCount()) if not view.matrix_table.isRowHidden(r))
    assert visible_count == 1


def test_reports_view_selection_inspector(qtbot, db: Database, sample_cpent_project: int):
    """Verifies selecting a row displays CWE/CVSS and evidence proof in inspector drawer."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    project = db.get_project(sample_cpent_project)
    view.set_active_project(project)

    # Find and select row for SQL Injection
    for r in range(view.matrix_table.rowCount()):
        if "SQL Injection" in view.matrix_table.item(r, 2).text():
            view.matrix_table.selectRow(r)
            break

    inspector_text = view.inspector_edit.toPlainText()
    assert "SQL Injection" in inspector_text
    assert "corp.megacorp.internal" in inspector_text
    assert "SHA-256" in inspector_text
    assert "Remediation" in inspector_text


def test_reports_view_export_actions(qtbot, db: Database, sample_cpent_project: int, monkeypatch, tmp_path: Path):
    """Verifies export handlers (CSV, PDF, HTML, MD, JSON, CPENT Pack) without hanging GUI dialogs."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    project = db.get_project(sample_cpent_project)
    view.set_active_project(project)

    # Mock dialogs
    monkeypatch.setattr(QMessageBox, "information", lambda parent, title, msg: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, msg: None)
    monkeypatch.setattr(QMessageBox, "critical", lambda parent, title, msg: None)

    # Test CSV Export
    csv_out = tmp_path / "gui_export.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(csv_out), "CSV"))
    view._export_format("csv")
    assert csv_out.exists()
    assert "✓ Exported CSV report" in view.export_status_lbl.text()

    # Test HTML Export
    html_out = tmp_path / "gui_export.html"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(html_out), "HTML"))
    view._export_format("html")
    assert html_out.exists()
    assert "✓ Exported HTML report" in view.export_status_lbl.text()

    # Test PDF Export
    pdf_out = tmp_path / "gui_export.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(pdf_out), "PDF"))
    view._export_format("pdf")
    assert pdf_out.exists()
    assert "✓ Exported PDF report" in view.export_status_lbl.text()

    # Test Markdown Export
    md_out = tmp_path / "gui_export.md"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(md_out), "MD"))
    view._export_format("markdown")
    assert md_out.exists()
    assert "✓ Exported MARKDOWN report" in view.export_status_lbl.text()

    # Test JSON Export
    json_out = tmp_path / "gui_export.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(json_out), "JSON"))
    view._export_format("json")
    assert json_out.exists()
    assert "✓ Exported JSON report" in view.export_status_lbl.text()

    # Test CPENT Pack Export
    zip_out = tmp_path / "gui_cpent_pack.zip"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(zip_out), "ZIP"))
    view._export_cpent_pack()
    assert zip_out.exists()
    assert "✓ Exported CPENT Engagement Pack" in view.export_status_lbl.text()


def test_reports_view_live_preview(qtbot, db: Database, sample_cpent_project: int):
    """Verifies live Markdown preview tab content rendering."""
    view = ReportsView(db=db)
    qtbot.addWidget(view)
    view.show()

    project = db.get_project(sample_cpent_project)
    view.set_active_project(project)

    # Check live preview text
    preview_text = view.preview_edit.toPlainText()
    assert "MegaCorp CPENT Assessment" in preview_text
    assert "Executive Summary" in preview_text
    assert "SQL Injection" in preview_text
