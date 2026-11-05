"""Unit & Integration tests for GoogleDorkWidget and Information Gathering Methodology."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from desktop.views.assets_view import AssetsView
from desktop.widgets.google_dork_widget import PREBUILT_DORKS, GoogleDorkWidget
from storage.db import Database
from storage.models import Project, ProjectStatus, TargetScope, TargetType


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_dork.db"
    db = Database(str(db_file))
    return db


def test_google_dork_widget_initialization(qtbot, test_db):
    widget = GoogleDorkWidget(db=test_db)
    qtbot.addWidget(widget)
    widget.show()

    assert widget.table.rowCount() == len(PREBUILT_DORKS)
    assert widget.table.rowCount() >= 25
    assert "Showing" in widget.lbl_stats.text()
    assert widget.current_domain == "example.com"


def test_google_dork_widget_domain_binding(qtbot, test_db):
    widget = GoogleDorkWidget(db=test_db)
    qtbot.addWidget(widget)
    widget.show()

    # Set active project with scope
    proj = test_db.create_project(Project(name="Acme Security Audit", status=ProjectStatus.ACTIVE))
    test_db.add_scope(TargetScope(project_id=proj.id, target="targetcorp.com", target_type=TargetType.HOSTNAME))

    widget.set_active_project(proj)
    assert widget.current_domain == "targetcorp.com"
    assert "targetcorp.com" in widget.lbl_project_badge.text()

    # Verify queries in table contain targetcorp.com
    item_query = widget.table.item(0, 3)
    assert "targetcorp.com" in item_query.text()


def test_google_dork_category_and_text_filtering(qtbot, test_db):
    widget = GoogleDorkWidget(db=test_db)
    qtbot.addWidget(widget)
    widget.show()

    # Filter by category: Sensitive Files
    idx = widget.combo_category.findData("Sensitive Files")
    assert idx != -1
    widget.combo_category.setCurrentIndex(idx)
    assert widget.table.rowCount() > 0
    assert widget.table.rowCount() < len(PREBUILT_DORKS)

    # Filter by text: "env"
    widget.txt_filter.setText("env")
    assert widget.table.rowCount() >= 1
    found_env = False
    for r in range(widget.table.rowCount()):
        if "env" in widget.table.item(r, 2).text().lower() or "env" in widget.table.item(r, 3).text().lower():
            found_env = True
            break
    assert found_env


def test_custom_dork_builder(qtbot, test_db):
    widget = GoogleDorkWidget(db=test_db)
    qtbot.addWidget(widget)
    widget.show()

    widget.bld_site.setText("testcorp.io")
    widget.bld_filetype.setText("sql")
    widget.bld_intext.setText("root_password")

    preview = widget.txt_custom_preview.text()
    assert "site:testcorp.io" in preview
    assert "filetype:sql" in preview
    assert 'intext:"root_password"' in preview


def test_dork_actions_signals(qtbot, test_db):
    widget = GoogleDorkWidget(db=test_db)
    qtbot.addWidget(widget)
    widget.show()

    with qtbot.waitSignal(widget.dork_copied, timeout=1000):
        widget._copy_custom_query()

    copied_text = QApplication.clipboard().text()
    assert "site:" in copied_text


def test_assets_view_subview_switching(qtbot, test_db):
    proj = test_db.create_project(Project(name="FinCorp Recon", status=ProjectStatus.ACTIVE))
    test_db.add_scope(TargetScope(project_id=proj.id, target="fincorp.local", target_type=TargetType.HOSTNAME))

    assets_view = AssetsView(db=test_db)
    qtbot.addWidget(assets_view)
    assets_view.show()
    assets_view.set_active_project(proj)

    # Initially at Behind24 Digital Assets Inventory (index 0)
    assert assets_view.main_stack.currentIndex() == 0
    assert assets_view.btn_sub_assets.isChecked()
    assert not assets_view.btn_sub_dorks.isChecked()

    # Switch to Passive Recon & Google Dorks (index 1)
    assets_view.btn_sub_dorks.click()
    assert assets_view.main_stack.currentIndex() == 1
    assert not assets_view.btn_sub_assets.isChecked()
    assert assets_view.btn_sub_dorks.isChecked()
    assert assets_view.dork_widget.current_domain == "fincorp.local"

    # Switch back to Behind24 Assets (index 0)
    assets_view.btn_sub_assets.click()
    assert assets_view.main_stack.currentIndex() == 0
    assert assets_view.btn_sub_assets.isChecked()
