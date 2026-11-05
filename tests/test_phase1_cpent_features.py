"""Unit tests for Phase 1: ERP Dashboard, CPENT Engagement Pack Export & Screenshot POC Engine."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.views.findings_view import FindingsView
from desktop.views.network_scan_view import NetworkScanView
from reports.builder import ReportBuilder
from reports.cpent_engagement_pack import CPENTEngagementPackGenerator
from storage.db import Database
from storage.models import (
    AssetNode,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_project(db: Database) -> Project:
    return db.create_project(
        Project(
            name="Alpha Corp CPENT Exam",
            client_name="Alpha Corp",
            engagement_id="ENG-2026-ALPHA",
            lead_tester="Senior Pentester Leo",
        )
    )


def test_main_window_clean_assessment_workspace(qtbot, db: Database):
    """Verifies that Assessment workspace does not have redundant AI assistant dummy tab."""
    window = MainWindow(db)
    qtbot.addWidget(window)

    # In security_tabs, tab 0 must be Network Discovery
    sec_tabs = window.security_tabs
    assert sec_tabs.count() >= 6
    assert "Network Discovery" in sec_tabs.tabText(0)
    assert "Web Testing" in sec_tabs.tabText(1)
    assert "OSINT" in sec_tabs.tabText(2)
    assert "Tools" in sec_tabs.tabText(3)
    assert "Network Map" in sec_tabs.tabText(4)
    assert "Wireless && IoT" in sec_tabs.tabText(5)

    # Ensure right-side AI panel is the designated persistent AI interface
    assert hasattr(window, "right_ai_panel")
    assert window.right_ai_panel is not None


def test_network_scan_view_erp_dashboard_page(qtbot, db: Database, sample_project: Project):
    """Verifies NetworkScanView initializes with ERP Single-Page Dashboard as default."""
    view = NetworkScanView(db)
    qtbot.addWidget(view)

    # Page 0 is ERP single-page dashboard
    assert view.main_stack.currentIndex() == 0
    assert view.btn_view_erp.isChecked() is True
    assert view.btn_view_wizard.isChecked() is False

    # Check KPI cards exist
    assert hasattr(view, "erp_kpi_scope_val")
    assert hasattr(view, "erp_kpi_hosts_val")
    assert hasattr(view, "erp_kpi_vulns_val")
    assert hasattr(view, "erp_kpi_ports_val")

    # Check Quick scan controls exist
    assert hasattr(view, "erp_target_input")
    assert hasattr(view, "erp_profile_combo")
    assert hasattr(view, "btn_erp_start_scan")
    assert hasattr(view, "btn_erp_footprint")
    assert hasattr(view, "btn_erp_import_xml")

    # Check Master Assets Table exists
    assert hasattr(view, "erp_master_table")
    assert view.erp_master_table.columnCount() == 7

    # Add sample asset and verify refresh
    db.add_scope(
        TargetScope(
            project_id=sample_project.id,
            target="192.168.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    db.upsert_asset_node(
        AssetNode(
            project_id=sample_project.id,
            node_type="ip",
            value="192.168.10.50",
            label="dc01.alpha.lab",
            source_tool="nmap",
            metadata_json=json.dumps({
                "os_match": "Windows Server 2022",
                "open_ports": [53, 88, 389, 445],
            }),
        )
    )

    view.set_active_project(sample_project)
    assert "1 Targets" in view.erp_kpi_scope_val.text()
    assert "1 Hosts" in view.erp_kpi_hosts_val.text()
    assert "4 Services" in view.erp_kpi_ports_val.text()
    assert view.erp_master_table.rowCount() == 1
    assert view.erp_master_table.item(0, 0).text() == "192.168.10.50"


def test_network_scan_view_mode_toggle(qtbot, db: Database, sample_project: Project):
    """Verifies seamless switching between ERP 1-Page Dashboard and CPENT 6-Step Wizard."""
    view = NetworkScanView(db)
    qtbot.addWidget(view)
    view.set_active_project(sample_project)

    # Initial mode: ERP Dashboard (Page 0)
    assert view.main_stack.currentIndex() == 0

    # Switch to 6-Step Wizard
    view._set_view_mode("wizard")
    assert view.main_stack.currentIndex() == 1
    assert view.btn_view_wizard.isChecked() is True
    assert view.btn_view_erp.isChecked() is False

    # Switch back to ERP Dashboard
    view._set_view_mode("erp")
    assert view.main_stack.currentIndex() == 0
    assert view.btn_view_erp.isChecked() is True
    assert view.btn_view_wizard.isChecked() is False


def test_findings_view_buttons_and_actions(qtbot, db: Database, sample_project: Project):
    """Verifies FindingsView contains CPENT pack export and Screenshot POC buttons."""
    view = FindingsView(db)
    qtbot.addWidget(view)
    view.load_findings(sample_project.id)

    assert hasattr(view, "btn_export_cpent")
    assert hasattr(view, "btn_attach_poc")
    assert "CPENT Pack" in view.btn_export_cpent.text()
    assert "Attach POC" in view.btn_attach_poc.text()


def test_findings_view_poc_attachment_and_evidence(qtbot, db: Database, sample_project: Project, tmp_path: Path):
    """Verifies attaching a screenshot POC creates evidence linked to the finding."""
    view = FindingsView(db)
    qtbot.addWidget(view)

    # 1. Create a finding
    finding = db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="SQL Injection on Login Portal",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.10.50",
            affected_port_service="80/http",
            description="Time-based blind SQLi discovered in login parameter.",
        )
    )

    # 2. Create a mock image file
    fake_png = tmp_path / "sqli_proof.png"
    fake_png.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4")
    expected_hash = hashlib.sha256(fake_png.read_bytes()).hexdigest()

    # 3. Simulate attach
    ev = Evidence(
        project_id=sample_project.id,
        finding_id=finding.id,
        file_path=str(fake_png.resolve()),
        sha256_hash=expected_hash,
        mime_type="image/png",
        description="SQLMap blind injection proof",
    )
    db.add_evidence(ev)

    # 4. Reload findings view and check details
    view.load_findings(sample_project.id)
    view.table.selectRow(0)
    details_md = view.details_edit.toPlainText()
    assert "Screenshot POC attached" in details_md
    assert expected_hash in details_md


def test_report_builder_embeds_poc_image_figures(db: Database, sample_project: Project, tmp_path: Path):
    """Verifies ReportBuilder embeds POC screenshots as Figure X in Markdown and HTML reports."""
    finding = db.create_finding(
        Finding(
            project_id=sample_project.id,
            title="Remote Code Execution via SMB",
            severity=FindingSeverity.CRITICAL,
            affected_asset="192.168.10.50",
            affected_port_service="445/smb",
            description="EternalBlue exploit execution demonstrated system shell.",
            reproduction_steps="msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; run'",
        )
    )

    # Create image file
    img_file = tmp_path / "eternalblue_poc.png"
    img_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4")
    img_hash = hashlib.sha256(img_file.read_bytes()).hexdigest()

    db.add_evidence(
        Evidence(
            project_id=sample_project.id,
            finding_id=finding.id,
            file_path=str(img_file.resolve()),
            sha256_hash=img_hash,
            mime_type="image/png",
            description="EternalBlue NT AUTHORITY SYSTEM shell confirmation",
        )
    )

    builder = ReportBuilder(db)

    # 1. Test Markdown Report
    md_path = tmp_path / "report.md"
    builder.generate_markdown(sample_project.id, output_path=md_path)
    md_content = md_path.read_text(encoding="utf-8")
    assert "#### Proof-of-Concept (POC) Evidence" in md_content
    assert f"Figure {finding.id}.1" in md_content
    assert img_hash in md_content

    # 2. Test HTML Report
    html_path = tmp_path / "report.html"
    builder.generate_html(sample_project.id, output_path=html_path)
    html_content = html_path.read_text(encoding="utf-8")
    assert "Proof-of-Concept (POC) Evidence" in html_content
    assert f"Figure {finding.id}.1" in html_content
    assert "data:image/png;base64," in html_content


def test_cpent_engagement_pack_zip(db: Database, sample_project: Project, tmp_path: Path):
    """Verifies CPENTEngagementPackGenerator creates a valid ZIP file with complete structure."""
    generator = CPENTEngagementPackGenerator(db)
    out_zip = tmp_path / "CPENT_Pack.zip"
    generator.generate_pack_zip(sample_project.id, out_zip)

    assert out_zip.exists()
    assert out_zip.stat().st_size > 0

    with zipfile.ZipFile(out_zip, "r") as zf:
        names = zf.namelist()
        assert "README.md" in names
        assert "00_Administration/00A_EL/Engagement_Letter.md" in names
        assert "00_Administration/00F__ROE/Rules_of_Engagement.md" in names
        assert "00_Administration/00G_TP/Test_Plan_and_Scope.md" in names
        assert "00_Administration/00H_LTA/Letter_of_Technical_Authorization.md" in names
        assert "00_Administration/00L_ECL/Master_Engagement_Control_List.md" in names
        assert "01_SISGCA/01A_OSIA/OSINT_Activity_Log.md" in names
        assert "01_SISGCA/01C_EVD&A/Evidence_Manifest.json" in names
        assert "02_SEVA_Tools/Tool_Inventory.md" in names
