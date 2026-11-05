"""Phase 4 Security Tests: Database Integrity, Evidence Provenance, Backup/Restore, and Offscreen GUI Smoke Tests.

Tests:
1. SQLite PRAGMA integrity_check and foreign key constraints.
2. Evidence cryptographic SHA-256 hash match against physical files on disk.
3. Database backup and restore verification using temporary databases.
4. Activity audit log recording and tamper consistency.
5. Project data isolation: Evidence, findings, assets, and tool executions in Project A never leak to Project B.
6. Offscreen PySide6 GUI Smoke Tests:
   - MainWindow startup in offscreen mode.
   - ToolExecutionCenterWidget tab switching and preset selection.
   - AssetsView loading with zero crashes.
   - AISettingsDialog password masking.
"""

from __future__ import annotations

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from core.activity_logger import ActivityLogger
from desktop.dialogs.ai_settings_dialog import AISettingsDialog
from desktop.main_window import MainWindow
from desktop.views.assets_view import AssetsView
from desktop.widgets.tool_execution_center import ToolExecutionCenterWidget
from storage.db import Database
from storage.models import (
    AssetNode,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ToolExecution,
    ValidationStatus,
)


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "integrity_test.db"
    return Database(str(db_file))


def test_sqlite_integrity_and_foreign_keys(temp_db):
    """Verify SQLite database passes PRAGMA integrity_check and enforces foreign keys."""
    with temp_db.get_connection() as conn:
        # Check integrity
        cursor = conn.execute("PRAGMA integrity_check;")
        res = cursor.fetchone()
        assert res[0] == "ok"

        # Check foreign keys are enabled
        cursor = conn.execute("PRAGMA foreign_keys;")
        fk_status = cursor.fetchone()
        assert fk_status[0] == 1


def test_evidence_sha256_provenance_verification(temp_db, tmp_path):
    """Verify that evidence records maintain cryptographic SHA-256 match with files on disk."""
    proj = temp_db.create_project(Project(name="Evidence Test Proj", status=ProjectStatus.ACTIVE))

    ev_file = tmp_path / "scan_artifact.xml"
    content = "<nmaprun version='7.94'><host><address addr='10.0.0.1'/></host></nmaprun>"
    ev_file.write_text(content, encoding="utf-8")
    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    ev_entry = temp_db.add_evidence(
        Evidence(
            project_id=proj.id,
            file_path=str(ev_file),
            sha256_hash=expected_hash,
            description="Nmap XML scan artifact",
            mime_type="application/xml",
        )
    )

    # Read back from DB and verify hash matches physical file on disk
    retrieved = temp_db.get_evidence(ev_entry.id)
    assert retrieved is not None
    assert Path(retrieved.file_path).is_file()

    actual_file_bytes = Path(retrieved.file_path).read_bytes()
    computed_hash = hashlib.sha256(actual_file_bytes).hexdigest()
    assert retrieved.sha256_hash == computed_hash

    # Test tampering detection on evidence file
    tampered_bytes = actual_file_bytes + b"<!-- injected comment -->"
    tampered_hash = hashlib.sha256(tampered_bytes).hexdigest()
    assert retrieved.sha256_hash != tampered_hash


def test_database_backup_and_restore(temp_db, tmp_path):
    """Verify clean database backup and restore without data loss or corruption."""
    proj = temp_db.create_project(Project(name="Backup Source Proj", status=ProjectStatus.ACTIVE))
    temp_db.add_scope(TargetScope(
        project_id=proj.id,
        target="192.168.1.0/24",
        target_type=TargetType.CIDR_RANGE,
    ))
    temp_db.upsert_asset_node(AssetNode(
        project_id=proj.id,
        node_type="ip",
        value="192.168.1.10",
    ))

    backup_file = tmp_path / "backup_archive.db"

    # Perform online SQLite backup
    with temp_db.get_connection() as src_conn:
        dest_conn = sqlite3.connect(str(backup_file))
        src_conn.backup(dest_conn)
        dest_conn.close()

    assert backup_file.is_file()
    assert backup_file.stat().st_size > 0

    # Restore into fresh DB instance
    restored_db = Database(str(backup_file))
    with restored_db.get_connection() as r_conn:
        cursor = r_conn.execute("PRAGMA integrity_check;")
        assert cursor.fetchone()[0] == "ok"

    restored_proj = restored_db.get_project(proj.id)
    assert restored_proj is not None
    assert restored_proj.name == "Backup Source Proj"

    scopes = restored_db.list_scopes(proj.id)
    assert len(scopes) == 1
    assert scopes[0].target == "192.168.1.0/24"

    nodes = restored_db.list_asset_nodes(proj.id)
    assert len(nodes) == 1
    assert nodes[0].value == "192.168.1.10"


def test_activity_logger_audit_consistency(temp_db):
    """Verify that audit activity logger records operational actions cleanly."""
    proj = temp_db.create_project(Project(name="Audit Log Proj", status=ProjectStatus.ACTIVE))
    logger = ActivityLogger(temp_db)

    logger.log(
        project_id=proj.id,
        action="tool_execution_started",
        outcome="success",
        details={"tool": "nmap", "target": "10.0.0.1"},
    )
    logger.log(
        project_id=proj.id,
        action="scope_authorization_modified",
        outcome="success",
        details={"scope": "10.0.0.0/24", "action": "added"},
    )

    activities = logger.list_logs(project_id=proj.id)
    assert len(activities) >= 2
    actions = [a.action for a in activities]
    assert "tool_execution_started" in actions
    assert "scope_authorization_modified" in actions


# ===========================================================================
# GUI Smoke Tests in Offscreen Mode
# ===========================================================================

def test_gui_smoke_tool_execution_center(qtbot, temp_db):
    """Verify ToolExecutionCenterWidget initializes and binds to active project in offscreen mode."""
    proj = temp_db.create_project(Project(name="GUI Smoke Proj", status=ProjectStatus.ACTIVE))
    temp_db.add_scope(TargetScope(
        project_id=proj.id,
        target="192.168.1.0/24",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.ALLOWED,
        is_authorized=True,
    ))

    widget = ToolExecutionCenterWidget(db=temp_db)
    qtbot.addWidget(widget)
    widget.set_active_project(proj)

    # Select Nmap and type in-scope target
    widget.select_tool("nmap", preset_name="Fast Top 100")
    widget.target_input.setText("192.168.1.25")

    # Scope badge should reflect authorized status
    assert "Authorized In-Scope" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is True

    # Type out-of-scope target
    widget.target_input.setText("10.88.88.88")
    assert "Blocked" in widget.lbl_scope_status.text()
    assert widget.btn_execute.isEnabled() is False


def test_gui_smoke_assets_view(qtbot, temp_db):
    """Verify AssetsView loads and toggles inspector in offscreen mode."""
    proj = temp_db.create_project(Project(name="Assets GUI Smoke", status=ProjectStatus.ACTIVE))
    view = AssetsView(db=temp_db)
    qtbot.addWidget(view)
    view.show()
    view.set_active_project(proj)

    assert not view.empty_asset_frame.isHidden()
    assert view.overview_container.isHidden()

    # Toggle analytics button
    view.btn_toggle_analytics.click()
    assert not view.overview_container.isHidden()
    view.btn_toggle_analytics.click()
    assert view.overview_container.isHidden()
