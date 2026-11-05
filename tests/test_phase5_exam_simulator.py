"""Automated tests for Phase 5: 24-Hour CPENT Exam Range Simulator & Flag Scoreboard Tracker.

Verifies:
- 6 Exam Enclaves, 30 Challenge Flags, and 3,000 total available points.
- Cryptographic SHA-256 flag verification and duplicate protection.
- CPENT Certification (2,100 pts / 70%) and LPT Master (2,700 pts / 90%) milestones.
- 24-Hour continuous timer, 2x12h split mode, start, pause, resume, and tick logic.
- Gap analysis recommendations and tactical advice.
- Scope authorization guard cross-checking target IP against TargetScope.
- Syncing captured flags into verified Finding and Evidence database records.
- State persistence (JSON save/load).
- Interactive shell handoff signal emission.
- Integration into CPENTLabsView (Tab 6) and MainWindow.
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from PySide6.QtWidgets import QMessageBox

from desktop.main_window import MainWindow
from desktop.views.cpent_labs_view import CPENTLabsView
from desktop.widgets.cpent_exam_simulator_widget import CPENTExamSimulatorWidget
from labs.cpent.exam_simulator import (
    ExamFlag,
    ExamRange,
    ExamSession,
    calculate_exam_milestones,
    export_exam_markdown_report,
    generate_gap_analysis,
    get_default_exam_ranges,
    load_exam_state,
    save_exam_state,
    verify_flag_submission,
)
from storage.db import Database
from storage.models import (
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
    proj = Project(
        name="CPENT Exam Lab Simulation",
        client_name="EC-Council Practical Cyber Range",
        description="24-Hour CPENT Penetration Testing Practice Range",
    )
    saved = db.create_project(proj)
    # Authorize range 1 and range 3 subnets in scope
    db.add_scope(TargetScope(project_id=saved.id, target="10.10.1.0/24", target_type=TargetType.CIDR_RANGE))
    db.add_scope(TargetScope(project_id=saved.id, target="10.10.3.0/24", target_type=TargetType.CIDR_RANGE))
    return saved


def test_exam_ranges_and_flags_initialization():
    """Verifies official 6 CPENT challenge enclaves, 30 flags, and 3,000 total points."""
    ranges = get_default_exam_ranges()
    assert len(ranges) == 6

    expected_enclaves = [
        ("range_1", "CTF & Web Applications", 500, 5),
        ("range_2", "Multi-Hop Pivoting & Tunneling", 500, 5),
        ("range_3", "Active Directory Forest", 600, 6),
        ("range_4", "Binary Analysis & 32-bit Exploitation", 500, 5),
        ("range_5", "IoT & Firmware Analysis", 400, 4),
        ("range_6", "OT / SCADA & Industrial Systems", 500, 5),
    ]

    total_pts = 0
    total_flags = 0

    for i, (rid, name, pts, flag_cnt) in enumerate(expected_enclaves):
        r = ranges[i]
        assert r.range_id == rid
        assert r.name == name
        assert r.total_points == pts
        assert len(r.flags) == flag_cnt
        total_pts += pts
        total_flags += flag_cnt

        for f in r.flags:
            assert f.points == 100
            assert f.raw_flag_sample.startswith("CPENT{")
            assert len(f.flag_hash) == 64  # SHA-256 hex string

    assert total_pts == 3000
    assert total_flags == 30


def test_widget_creation_and_defaults(qtbot, tmp_path: Path):
    """Verifies CPENTExamSimulatorWidget instantiates with correct timer and scoreboard defaults."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(state_file=str(state_file))
    qtbot.addWidget(widget)

    assert widget.session.state == "not_started"
    assert widget.session.score == 0
    assert widget.lbl_clock.text() == "24:00:00"
    assert "NOT STARTED" in widget.lbl_session_status.text()
    assert widget.progress_score.value() == 0
    assert widget.list_ranges.count() == 6
    assert "2,100" in widget.lbl_cpent_status.text()
    assert "2,700" in widget.lbl_lpt_status.text()


def test_flag_submission_engine_valid_and_invalid(qtbot, tmp_path: Path):
    """Verifies submitting wrong flag rejects, correct flag awards points, and duplicates are blocked."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(state_file=str(state_file))
    qtbot.addWidget(widget)

    # Select Range 1, Flag 1 (Blind SQLi)
    widget.list_ranges.setCurrentRow(0)
    widget.table_flags.selectRow(0)
    flag = widget.selected_flag
    assert flag is not None
    assert flag.flag_id == "R1-FLAG-01"

    # 1. Invalid submission
    widget.edit_flag.setText("WRONG_FLAG_CANDIDATE")
    widget._submit_flag()
    assert not flag.captured
    assert widget.session.score == 0
    assert "INCORRECT" in widget.lbl_submit_feedback.text()

    # 2. Correct submission
    signals_received = []
    widget.flag_captured.connect(lambda fid, sc: signals_received.append((fid, sc)))

    widget.edit_flag.setText(flag.raw_flag_sample)
    widget._submit_flag()

    assert flag.captured is True
    assert widget.session.score == 100
    assert len(signals_received) == 1
    assert signals_received[0] == ("R1-FLAG-01", 100)
    assert "CORRECT" in widget.lbl_submit_feedback.text()
    assert widget.progress_score.value() == 100

    # 3. Duplicate submission attempt
    widget.edit_flag.setText(flag.raw_flag_sample)
    widget._submit_flag()
    assert widget.session.score == 100  # Score remains 100, no duplicate points
    assert "already captured" in widget.lbl_submit_feedback.text()


def test_milestone_thresholds_cpent_and_lpt_master(qtbot, tmp_path: Path):
    """Verifies that reaching 2,100 pts unlocks CPENT Pass and 2,700 pts unlocks LPT Master."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(state_file=str(state_file))
    qtbot.addWidget(widget)

    milestones_unlocked = []
    widget.milestone_unlocked.connect(lambda m: milestones_unlocked.append(m))

    with patch("PySide6.QtWidgets.QMessageBox.information"):
        # Manually set score right below CPENT threshold (2,000 pts)
        widget.session.score = 2000
        widget._update_score_gauges()
        assert "Pending" in widget.lbl_cpent_status.text()
        assert "Pending" in widget.lbl_lpt_status.text()

        # Submit flag to cross 2,100 pts
        widget.list_ranges.setCurrentRow(0)
        widget.table_flags.selectRow(0)
        widget.edit_flag.setText(widget.selected_flag.raw_flag_sample)
        widget._submit_flag()

        assert widget.session.score == 2100
        assert "cpent_pass" in milestones_unlocked
        assert "QUALIFIED (CPENT Certified!)" in widget.lbl_cpent_status.text()
        assert "Pending" in widget.lbl_lpt_status.text()

        # Now simulate crossing LPT Master threshold (2,700 pts)
        widget.session.score = 2600
        widget.list_ranges.setCurrentRow(0)
        widget.table_flags.selectRow(1)
        widget.edit_flag.setText(widget.selected_flag.raw_flag_sample)
        widget._submit_flag()

        assert widget.session.score == 2700
        assert "lpt_master" in milestones_unlocked
        assert "ACHIEVED (LPT Master Honor!)" in widget.lbl_lpt_status.text()


def test_timer_controller_start_pause_resume_tick(qtbot, tmp_path: Path):
    """Verifies timer state machine: start, tick, pause, resume, and split mode."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(state_file=str(state_file))
    qtbot.addWidget(widget)

    # Change to 2x12h mode
    widget.combo_mode.setCurrentIndex(1)
    assert widget.session.mode == "2x12h"
    assert widget.session.session_part == 1
    assert widget.session.total_allowed_seconds == 43200
    assert widget.lbl_clock.text() == "12:00:00"

    # Start
    widget._start_exam()
    assert widget.session.state == "running"
    assert widget.timer.isActive()
    assert "RUNNING" in widget.lbl_session_status.text()

    # Simulate 5 ticks
    for _ in range(5):
        widget._on_timer_tick()
    assert widget.session.elapsed_seconds == 5
    assert widget.session.remaining_seconds == 43195

    # Pause
    widget._toggle_pause_resume()
    assert widget.session.state == "paused"
    assert not widget.timer.isActive()
    assert "PAUSED" in widget.lbl_session_status.text()

    # Resume
    widget._toggle_pause_resume()
    assert widget.session.state == "running"
    assert widget.timer.isActive()
    assert "RUNNING" in widget.lbl_session_status.text()

    # Finalize
    with patch("PySide6.QtWidgets.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes):
        with patch("PySide6.QtWidgets.QMessageBox.information"):
            widget._finalize_exam()

    assert widget.session.state == "completed"
    assert not widget.timer.isActive()
    assert "FINALIZED" in widget.lbl_session_status.text()


def test_tactical_gap_analysis():
    """Verifies dynamic gap calculations and priority enclave advice."""
    ranges = get_default_exam_ranges()
    gap = generate_gap_analysis(ranges, 500)

    assert gap["milestones"]["cpent_needed"] == 1600
    assert gap["milestones"]["lpt_master_needed"] == 2200
    assert len(gap["best_enclaves"]) > 0
    # Range 3 (AD Forest) has 600 points, highest uncaptured
    assert any("Active Directory" in name for name, _ in gap["best_enclaves"])
    assert any("Priority Enclave" in line or "Recommended Focus" in line for line in gap["advice_lines"])


def test_scope_validation_guard(qtbot, db: Database, sample_project: Project, tmp_path: Path):
    """Verifies that challenge target IPs are checked against project scope rules."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(db=db, state_file=str(state_file))
    qtbot.addWidget(widget)
    widget.set_active_project(sample_project)

    # Range 1 Target (10.10.1.50) is authorized (10.10.1.0/24 in scope)
    widget.list_ranges.setCurrentRow(0)
    widget.table_flags.selectRow(0)
    assert "Authorized Scope" in widget.lbl_scope_banner.text()

    # Range 2 Target (10.10.2.10) is out of scope (only 10.10.1.0/24 and 10.10.3.0/24 in scope)
    widget.list_ranges.setCurrentRow(1)
    widget.table_flags.selectRow(0)
    assert "Out-of-Scope Warning" in widget.lbl_scope_banner.text()


def test_sync_captured_flags_to_findings_and_evidence(qtbot, db: Database, sample_project: Project, tmp_path: Path):
    """Verifies that captured flags can be synced into verified Finding and Evidence records."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(db=db, state_file=str(state_file))
    qtbot.addWidget(widget)
    widget.set_active_project(sample_project)

    # Capture 2 flags
    widget.list_ranges.setCurrentRow(0)
    widget.table_flags.selectRow(0)
    widget.edit_flag.setText(widget.selected_flag.raw_flag_sample)
    widget._submit_flag()

    widget.table_flags.selectRow(1)
    widget.edit_flag.setText(widget.selected_flag.raw_flag_sample)
    widget._submit_flag()

    # Sync to findings
    with patch("PySide6.QtWidgets.QMessageBox.information"):
        widget._sync_flags_to_findings()

    findings = db.list_findings(sample_project.id)
    assert len(findings) >= 2
    f_titles = [f.title for f in findings]
    assert any("Blind SQL Injection" in t for t in f_titles)
    assert any("Cloud Metadata Leak" in t for t in f_titles)

    # Verify evidence records exist
    all_evs = db.list_evidence(sample_project.id)
    assert len(all_evs) >= 2
    for f in findings:
        if "Blind SQL Injection" in f.title:
            evs = [ev for ev in all_evs if ev.finding_id == f.id]
            assert len(evs) == 1
            assert evs[0].sha256_hash != ""

    # Re-sync should not duplicate
    with patch("PySide6.QtWidgets.QMessageBox.information"):
        widget._sync_flags_to_findings()
    findings_after = db.list_findings(sample_project.id)
    assert len(findings_after) == len(findings)


def test_state_persistence_save_and_load(tmp_path: Path):
    """Verifies JSON serialization and restoration of exam state."""
    state_file = tmp_path / "exam_saved_state.json"
    ranges = get_default_exam_ranges()
    session = ExamSession(session_id="EXAM-TEST-99", mode="24h", score=300, elapsed_seconds=1200)

    # Mark 3 flags captured
    ranges[0].flags[0].captured = True
    ranges[0].flags[0].captured_at = "2026-10-27T12:00:00Z"
    ranges[0].flags[1].captured = True
    ranges[1].flags[0].captured = True

    save_exam_state(session, ranges, state_file)
    assert state_file.exists()

    restored_session, restored_ranges = load_exam_state(state_file)
    assert restored_session.session_id == "EXAM-TEST-99"
    assert restored_session.elapsed_seconds == 1200
    assert restored_session.score == 300
    assert restored_ranges[0].flags[0].captured is True
    assert restored_ranges[0].flags[1].captured is True
    assert restored_ranges[1].flags[0].captured is True
    assert restored_ranges[2].flags[0].captured is False


def test_command_to_shell_signal_emission(qtbot, tmp_path: Path):
    """Verifies that clicking Send Target to Console emits command_to_shell_requested."""
    state_file = tmp_path / "exam_test_state.json"
    widget = CPENTExamSimulatorWidget(state_file=str(state_file))
    qtbot.addWidget(widget)

    signals_received = []
    widget.command_to_shell_requested.connect(lambda cmd: signals_received.append(cmd))

    widget.list_ranges.setCurrentRow(0)
    widget.table_flags.selectRow(0)
    widget._send_target_to_shell()

    assert len(signals_received) == 1
    assert "10.10.1.50" in signals_received[0]
    assert "nmap" in signals_received[0]


def test_markdown_report_export(tmp_path: Path):
    """Verifies generation of complete Markdown exam debrief report."""
    ranges = get_default_exam_ranges()
    ranges[0].flags[0].captured = True
    session = ExamSession(score=100, elapsed_seconds=3665)

    md = export_exam_markdown_report(session, ranges, project_name="CPENT Mock Exam")
    assert "# EC-Council CPENT / LPT Master Exam Simulator Debrief" in md
    assert "CPENT Mock Exam" in md
    assert "01h 01m 05s" in md
    assert "R1-FLAG-01" in md
    assert "CTF & Web Applications" in md


def test_integration_in_main_window_cpent_labs(qtbot, db: Database, sample_project: Project):
    """Verifies that CPENTExamSimulatorWidget is docked as Tab 6 in CPENTLabsView and MainWindow."""
    main_win = MainWindow(db=db)
    qtbot.addWidget(main_win)
    main_win._on_project_selected(sample_project)

    assert hasattr(main_win.cpent_view, "tab_exam_sim")
    assert isinstance(main_win.cpent_view.tab_exam_sim, CPENTExamSimulatorWidget)

    # 6 or more tabs total now
    assert main_win.cpent_view.tabs.count() >= 6
    tab_titles = [main_win.cpent_view.tabs.tabText(i) for i in range(main_win.cpent_view.tabs.count())]
    assert any("24-Hour Exam Range Simulator" in t for t in tab_titles)

    # Test theme updates
    main_win.cpent_view.update_theme("light")
    main_win.cpent_view.update_theme("dark")
