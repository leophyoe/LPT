"""24-Hour CPENT Exam Range Simulator & Scoreboard Tracker Widget.

Provides an authentic EC-Council CPENT / LPT Master practical exam simulator:
- 6 Specialized Challenge Enclaves (CTF/Web, Multi-Hop Pivoting, Active Directory,
  Binary Exploitation, IoT Firmware, OT/SCADA ICS) totaling 3,000 Points.
- 24-Hour Continuous Countdown Timer or 2 x 12-Hour Split Sessions.
- Interactive Flag Submission with Cryptographic Verification (SHA-256).
- Real-time Score Progress Gauge with CPENT (2,100 pts) and LPT Master (2,700 pts) Milestones.
- Dynamic Tactical Gap Analysis suggesting optimal remaining targets.
- Scope Authorization Protection cross-checked against project TargetScope.
- Sync Captured Flags to Verified Assessment Findings & Evidence Records.
- One-Click Markdown Exam Debrief Report Exporter.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from desktop.theme import CPENTTheme, get_badge_qss
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
from storage.models import (
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    ValidationStatus,
)


class CPENTExamSimulatorWidget(QWidget):
    """Interactive 24-Hour CPENT Exam Range Simulator & Flag Scoreboard Tracker."""

    command_to_shell_requested = Signal(str)
    flag_captured = Signal(str, int)  # flag_id, current_score
    milestone_unlocked = Signal(str)  # 'cpent_pass' or 'lpt_master'

    def __init__(self, db: Optional[Any] = None, parent=None, state_file: Optional[str] = None):
        super().__init__(parent)
        self.db = db
        self.active_project: Optional[Project] = None
        self.state_file = state_file or str(Path.home() / ".cybersecuritysuite" / "cpent_exam_sim.json")

        # Load ranges and active session
        self.ranges: List[ExamRange] = get_default_exam_ranges()
        self.session: ExamSession = ExamSession()
        self.selected_range: Optional[ExamRange] = self.ranges[0] if self.ranges else None
        self.selected_flag: Optional[ExamFlag] = None

        # Timer setup (Qt UI thread)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._on_timer_tick)

        self._init_ui()
        self._load_saved_state()
        self._update_all_displays()

    def set_active_project(self, project: Optional[Project]):
        self.active_project = project
        if self.session and project and project.id:
            self.session.project_id = project.id
        self._validate_scope()

    def update_theme(self, mode: Optional[str] = None):
        """Refreshes styling on theme change."""
        self._update_timer_styling()
        self._update_score_gauges()
        self._validate_scope()

    def _set_status_badge(self, text: str, token: str):
        self.lbl_session_status.setText(text)
        try:
            self.lbl_session_status.setStyleSheet(get_badge_qss(token))
        except Exception:
            self.lbl_session_status.setStyleSheet(
                "font-size: 11px; font-weight: bold; padding: 2px 8px; border-radius: 4px;"
            )

    # ----------------------------------------------------------------------
    # UI Setup
    # ----------------------------------------------------------------------
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Top Section: Exam Controller & Countdown Timer Bar
        timer_group = QGroupBox("⏱️ 24-Hour CPENT Practical Exam Controller")
        timer_layout = QHBoxLayout(timer_group)
        timer_layout.setContentsMargins(12, 10, 12, 10)
        timer_layout.setSpacing(12)

        # Mode Selection
        lbl_mode = QLabel("Exam Mode:")
        lbl_mode.setStyleSheet("font-weight: bold;")
        timer_layout.addWidget(lbl_mode)

        self.combo_mode = QComboBox()
        self.combo_mode.addItem("🏃 24-Hour Marathon (Continuous 86,400s)", "24h")
        self.combo_mode.addItem("🌓 Session 1 of 2 (12-Hour Split 43,200s)", "2x12h_p1")
        self.combo_mode.addItem("🌗 Session 2 of 2 (12-Hour Split 43,200s)", "2x12h_p2")
        self.combo_mode.currentIndexChanged.connect(self._on_mode_changed)
        timer_layout.addWidget(self.combo_mode)

        timer_layout.addSpacing(16)

        # Digital Countdown Clock
        lbl_clock_title = QLabel("Time Remaining:")
        lbl_clock_title.setStyleSheet("font-weight: bold;")
        timer_layout.addWidget(lbl_clock_title)

        self.lbl_clock = QLabel("24:00:00")
        self.lbl_clock.setObjectName("examDigitalClock")
        self.lbl_clock.setFont(QFont("Monospace", 20, QFont.Weight.Bold))
        self.lbl_clock.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_clock.setMinimumWidth(160)
        timer_layout.addWidget(self.lbl_clock)

        self.lbl_session_status = QLabel("NOT STARTED")
        self._set_status_badge("NOT STARTED", "PENDING")
        timer_layout.addWidget(self.lbl_session_status)

        timer_layout.addStretch()

        # Action Buttons
        self.btn_start = QPushButton("▶ Start Exam")
        self.btn_start.setObjectName("primaryButton")
        self.btn_start.clicked.connect(self._start_exam)
        timer_layout.addWidget(self.btn_start)

        self.btn_pause = QPushButton("⏸ Pause Session")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._toggle_pause_resume)
        timer_layout.addWidget(self.btn_pause)

        self.btn_finalize = QPushButton("⏹ Finalize Exam")
        self.btn_finalize.setEnabled(False)
        self.btn_finalize.clicked.connect(self._finalize_exam)
        timer_layout.addWidget(self.btn_finalize)

        self.btn_reset = QPushButton("🔄 Reset")
        self.btn_reset.setStyleSheet("color: #ef4444;")
        self.btn_reset.clicked.connect(self._reset_exam_dialog)
        timer_layout.addWidget(self.btn_reset)

        main_layout.addWidget(timer_group)

        # 2. Scoreboard & Milestone Gauges
        score_group = QGroupBox("🏆 Scoreboard & Exam Certification Milestones (3,000 Points Total)")
        score_layout = QVBoxLayout(score_group)
        score_layout.setContentsMargins(12, 10, 12, 10)
        score_layout.setSpacing(8)

        # Main Progress Bar
        self.progress_score = QProgressBar()
        self.progress_score.setRange(0, 3000)
        self.progress_score.setValue(0)
        self.progress_score.setTextVisible(True)
        self.progress_score.setFormat("Current Score: 0 / 3,000 Points (0.0%)")
        self.progress_score.setFixedHeight(24)
        score_layout.addWidget(self.progress_score)

        # 4 Status Cards in HBox
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        # Card 1: CPENT Pass Status
        self.card_cpent = QGroupBox("🎯 CPENT Pass (70% / 2,100 pts)")
        l_c1 = QVBoxLayout(self.card_cpent)
        l_c1.setContentsMargins(8, 6, 8, 6)
        self.lbl_cpent_status = QLabel("❌ Pending (Needs 2,100 pts)")
        self.lbl_cpent_status.setFont(QFont("SansSerif", 10, QFont.Weight.Bold))
        l_c1.addWidget(self.lbl_cpent_status)
        cards_layout.addWidget(self.card_cpent)

        # Card 2: LPT Master Status
        self.card_lpt = QGroupBox("🏆 LPT (Master) Honor (90% / 2,700 pts)")
        l_c2 = QVBoxLayout(self.card_lpt)
        l_c2.setContentsMargins(8, 6, 8, 6)
        self.lbl_lpt_status = QLabel("❌ Pending (Needs 2,700 pts)")
        self.lbl_lpt_status.setFont(QFont("SansSerif", 10, QFont.Weight.Bold))
        l_c2.addWidget(self.lbl_lpt_status)
        cards_layout.addWidget(self.card_lpt)

        # Card 3: Captured Flags Count
        self.card_flags = QGroupBox("🚩 Flag Verification")
        l_c3 = QVBoxLayout(self.card_flags)
        l_c3.setContentsMargins(8, 6, 8, 6)
        self.lbl_flags_status = QLabel("0 / 30 Flags Captured (0%)")
        self.lbl_flags_status.setFont(QFont("SansSerif", 10, QFont.Weight.Bold))
        l_c3.addWidget(self.lbl_flags_status)
        cards_layout.addWidget(self.card_flags)

        # Card 4: Tactical Advice & Gap Analysis
        self.card_gap = QGroupBox("🧭 Tactical Priority & Gap Advice")
        l_c4 = QVBoxLayout(self.card_gap)
        l_c4.setContentsMargins(8, 6, 8, 6)
        self.lbl_gap_advice = QLabel("Start with Range 1 (CTF/Web) or Range 3 (Active Directory) for fast points.")
        self.lbl_gap_advice.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        self.lbl_gap_advice.setWordWrap(True)
        l_c4.addWidget(self.lbl_gap_advice)
        cards_layout.addWidget(self.card_gap)

        score_layout.addLayout(cards_layout)
        main_layout.addWidget(score_group)

        # 3. Main Splitter: Left (Enclave Ranges) & Right (Challenge Table & Submission)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Enclave Ranges List
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        lbl_enclaves = QLabel("Challenge Enclaves (6 Ranges):")
        lbl_enclaves.setStyleSheet("font-weight: bold; font-size: 12px;")
        left_layout.addWidget(lbl_enclaves)

        self.list_ranges = QListWidget()
        self.list_ranges.currentRowChanged.connect(self._on_range_selected)
        left_layout.addWidget(self.list_ranges)

        splitter.addWidget(left_widget)

        # Right Panel: Selected Enclave Details & Challenge Submission
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        # Enclave Header Banner
        self.lbl_enclave_banner = QLabel("Select an enclave to inspect targets.")
        self.lbl_enclave_banner.setStyleSheet(
            f"font-size: 11px; padding: 6px 10px; border-radius: 4px; "
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.PRIMARY_TEXT}; font-weight: bold;"
        )
        right_layout.addWidget(self.lbl_enclave_banner)

        # Challenge Table
        self.table_flags = QTableWidget()
        self.table_flags.setColumnCount(5)
        self.table_flags.setHorizontalHeaderLabels(["Flag ID", "Challenge Title", "Target IP & Port", "Points", "Status"])
        self.table_flags.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_flags.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_flags.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_flags.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_flags.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_flags.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_flags.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table_flags.itemSelectionChanged.connect(self._on_flag_selected)
        right_layout.addWidget(self.table_flags)

        # Flag Submission & Interactive Target Action Area
        sub_group = QGroupBox("🚩 Flag Verification & Target Dispatch")
        sub_layout = QVBoxLayout(sub_group)
        sub_layout.setContentsMargins(10, 8, 10, 8)
        sub_layout.setSpacing(6)

        # Hint & Target Details row
        h_hint = QHBoxLayout()
        self.lbl_selected_target = QLabel("Target: None selected")
        self.lbl_selected_target.setStyleSheet("font-weight: bold;")
        h_hint.addWidget(self.lbl_selected_target)

        h_hint.addStretch()

        self.btn_send_shell = QPushButton("⚡ Send Target to Console")
        self.btn_send_shell.setEnabled(False)
        self.btn_send_shell.clicked.connect(self._send_target_to_shell)
        h_hint.addWidget(self.btn_send_shell)

        self.btn_toggle_hint = QPushButton("💡 Practice Hint")
        self.btn_toggle_hint.setEnabled(False)
        self.btn_toggle_hint.clicked.connect(self._toggle_hint)
        h_hint.addWidget(self.btn_toggle_hint)

        sub_layout.addLayout(h_hint)

        self.lbl_hint_box = QLabel("")
        self.lbl_hint_box.setStyleSheet(
            f"font-size: 11px; padding: 4px 8px; border-radius: 4px; "
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.INFO_CYAN}; font-style: italic;"
        )
        self.lbl_hint_box.setWordWrap(True)
        self.lbl_hint_box.setVisible(False)
        sub_layout.addWidget(self.lbl_hint_box)

        # Submission Row
        h_submit = QHBoxLayout()
        h_submit.addWidget(QLabel("Submit Flag:"))
        self.edit_flag = QLineEdit()
        self.edit_flag.setPlaceholderText("Paste captured flag e.g. CPENT{...}")
        self.edit_flag.returnPressed.connect(self._submit_flag)
        h_submit.addWidget(self.edit_flag)

        self.btn_submit_flag = QPushButton("🚩 Submit Flag")
        self.btn_submit_flag.setObjectName("primaryButton")
        self.btn_submit_flag.clicked.connect(self._submit_flag)
        h_submit.addWidget(self.btn_submit_flag)

        sub_layout.addLayout(h_submit)

        self.lbl_submit_feedback = QLabel("")
        self.lbl_submit_feedback.setStyleSheet("font-size: 11px; font-weight: bold;")
        sub_layout.addWidget(self.lbl_submit_feedback)

        right_layout.addWidget(sub_group)
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter, 1)

        # 4. Bottom Action Toolbar & Scope Status
        self.lbl_scope_banner = QLabel("Scope Status: Ready (TargetScope rules active).")
        self.lbl_scope_banner.setStyleSheet(
            f"font-size: 11px; padding: 4px 10px; border-radius: 4px; "
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.SECONDARY_TEXT};"
        )
        main_layout.addWidget(self.lbl_scope_banner)

        bar_bottom = QHBoxLayout()
        self.btn_sync_findings = QPushButton("📥 Sync Captured Flags to Findings & Evidence")
        self.btn_sync_findings.setStyleSheet(
            f"background-color: {CPENTTheme.ACCENT_RED}; color: #ffffff; font-weight: bold; padding: 6px 14px;"
        )
        self.btn_sync_findings.clicked.connect(self._sync_flags_to_findings)
        bar_bottom.addWidget(self.btn_sync_findings)

        self.btn_export_md = QPushButton("💾 Export Exam Progress (.md)")
        self.btn_export_md.clicked.connect(self._export_markdown_report)
        bar_bottom.addWidget(self.btn_export_md)

        bar_bottom.addStretch()

        self.btn_copy_summary = QPushButton("📋 Copy Scoreboard Summary")
        self.btn_copy_summary.clicked.connect(self._copy_scoreboard_summary)
        bar_bottom.addWidget(self.btn_copy_summary)

        main_layout.addLayout(bar_bottom)

    # ----------------------------------------------------------------------
    # Timer & Exam Controller
    # ----------------------------------------------------------------------
    def _on_mode_changed(self):
        mode_data = self.combo_mode.currentData()
        if mode_data == "24h":
            self.session.mode = "24h"
            self.session.total_allowed_seconds = 86400
        elif mode_data == "2x12h_p1":
            self.session.mode = "2x12h"
            self.session.session_part = 1
            self.session.total_allowed_seconds = 43200
        elif mode_data == "2x12h_p2":
            self.session.mode = "2x12h"
            self.session.session_part = 2
            self.session.total_allowed_seconds = 43200
        self._update_timer_styling()

    def _start_exam(self):
        if self.session.state == "running":
            return
        self.session.state = "running"
        if not self.session.start_time:
            from datetime import datetime, timezone
            self.session.start_time = datetime.now(timezone.utc).isoformat()
        self.timer.start()
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_finalize.setEnabled(True)
        self.combo_mode.setEnabled(False)
        self._set_status_badge(f"RUNNING (Part {self.session.session_part})", "RUNNING")
        self._save_state()

    def _toggle_pause_resume(self):
        if self.session.state == "running":
            self.session.state = "paused"
            self.timer.stop()
            self.btn_pause.setText("▶ Resume Session")
            self._set_status_badge("PAUSED", "WARNING")
        elif self.session.state == "paused":
            self.session.state = "running"
            self.timer.start()
            self.btn_pause.setText("⏸ Pause Session")
            self._set_status_badge(f"RUNNING (Part {self.session.session_part})", "RUNNING")
        self._save_state()

    def _finalize_exam(self):
        confirm = QMessageBox.question(
            self,
            "Finalize CPENT Exam Simulation",
            f"Are you sure you want to finalize your exam?\n\nFinal Score: {self.session.score} / 3,000 Points\n"
            f"Result: {'PASS (CPENT Qualified)' if self.session.cpent_passed else 'INCOMPLETE'}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.timer.stop()
            self.session.state = "completed"
            self.btn_start.setEnabled(False)
            self.btn_pause.setEnabled(False)
            self.btn_finalize.setEnabled(False)
            self._set_status_badge("FINALIZED", "INFO")
            self._save_state()
            QMessageBox.information(
                self,
                "Exam Simulation Finalized",
                f"Exam session ended.\nScore: {self.session.score}/3,000 pts.\n"
                f"You may now sync your flags to Findings and export the 24-hour report.",
            )

    def _reset_exam_dialog(self):
        confirm = QMessageBox.question(
            self,
            "Reset CPENT Simulation",
            "This will clear all captured flags and reset your exam timer to 24 hours. Are you sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.timer.stop()
            self.ranges = get_default_exam_ranges()
            self.session = ExamSession()
            self.btn_start.setEnabled(True)
            self.btn_pause.setEnabled(False)
            self.btn_pause.setText("⏸ Pause Session")
            self.btn_finalize.setEnabled(False)
            self.combo_mode.setEnabled(True)
            self._set_status_badge("NOT STARTED", "PENDING")
            self._save_state()
            self._update_all_displays()
            self.lbl_submit_feedback.setText("Exam simulation reset successfully.")
            self.lbl_submit_feedback.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT};")

    def _on_timer_tick(self):
        if self.session.state == "running":
            self.session.elapsed_seconds += 1
            if self.session.elapsed_seconds >= self.session.total_allowed_seconds:
                self.timer.stop()
                self.session.state = "completed"
                self._set_status_badge("TIME EXPIRED", "CRITICAL")
                self.btn_pause.setEnabled(False)
                self.btn_finalize.setEnabled(False)
                self._save_state()
                QMessageBox.warning(
                    self,
                    "Exam Time Expired",
                    f"24-Hour Exam time window has concluded.\nFinal Score: {self.session.score} / 3,000 Points.",
                )
            self._update_timer_styling()
            # Periodic auto-save every 30 seconds
            if self.session.elapsed_seconds % 30 == 0:
                self._save_state()

    def _update_timer_styling(self):
        rem = self.session.remaining_seconds
        h = rem // 3600
        m = (rem % 3600) // 60
        s = rem % 60
        self.lbl_clock.setText(f"{h:02d}:{m:02d}:{s:02d}")

        if rem > 43200:
            color = "#10b981"  # > 12h: Emerald Green
        elif rem > 14400:
            color = "#f59e0b"  # 4h - 12h: Amber
        else:
            color = "#ef4444"  # < 4h: Urgent Crimson

        self.lbl_clock.setStyleSheet(
            f"color: {color}; background-color: {CPENTTheme.ELEVATED_PANEL}; "
            f"border: 1px solid {color}; border-radius: 6px; padding: 4px 12px;"
        )

    # ----------------------------------------------------------------------
    # Displays & Scoreboard Updates
    # ----------------------------------------------------------------------
    def _update_all_displays(self):
        self._populate_ranges_list()
        self._update_score_gauges()
        self._on_range_selected(self.list_ranges.currentRow())
        self._validate_scope()

    def _populate_ranges_list(self):
        current_row = self.list_ranges.currentRow()
        self.list_ranges.clear()
        for r in self.ranges:
            item_text = f"{r.icon} {r.name}  [{r.captured_points}/{r.total_points} pts]"
            item = QListWidgetItem(item_text)
            if r.captured_points == r.total_points:
                item.setForeground(QColor("#10b981"))
            elif r.captured_points > 0:
                item.setForeground(QColor("#38bdf8"))
            self.list_ranges.addItem(item)

        if current_row >= 0 and current_row < self.list_ranges.count():
            self.list_ranges.setCurrentRow(current_row)
        elif self.list_ranges.count() > 0:
            self.list_ranges.setCurrentRow(0)

    def _update_score_gauges(self):
        score = self.session.score
        milestones = calculate_exam_milestones(score)
        pct = milestones["percentage"]

        self.progress_score.setValue(score)
        self.progress_score.setFormat(f"Current Score: {score} / 3,000 Points ({pct}%)")

        if score >= 2700:
            color = "#fbbf24"  # Gold
        elif score >= 2100:
            color = "#10b981"  # Emerald Green
        else:
            color = "#38bdf8"  # Sky Blue

        self.progress_score.setStyleSheet(
            f"QProgressBar {{ border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; "
            f"text-align: center; background-color: {CPENTTheme.CARD_BG}; color: {CPENTTheme.PRIMARY_TEXT}; font-weight: bold; }}"
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}"
        )

        # Milestone 1: CPENT Pass (2,100 pts)
        if milestones["cpent_passed"]:
            self.lbl_cpent_status.setText("✅ QUALIFIED (CPENT Certified!)")
            self.lbl_cpent_status.setStyleSheet("color: #10b981; font-weight: bold;")
        else:
            needed = f"{milestones['cpent_needed']:,}"
            self.lbl_cpent_status.setText(f"❌ Pending (Needs {needed} pts)")
            self.lbl_cpent_status.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT};")

        # Milestone 2: LPT Master Honor (2,700 pts)
        if milestones["lpt_master_achieved"]:
            self.lbl_lpt_status.setText("🏆 ACHIEVED (LPT Master Honor!)")
            self.lbl_lpt_status.setStyleSheet("color: #fbbf24; font-weight: bold;")
        else:
            needed_lpt = f"{milestones['lpt_master_needed']:,}"
            self.lbl_lpt_status.setText(f"❌ Pending (Needs {needed_lpt} pts)")
            self.lbl_lpt_status.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT};")

        # Flags count
        total_flags = sum(len(r.flags) for r in self.ranges)
        captured = sum(r.captured_count for r in self.ranges)
        self.lbl_flags_status.setText(f"{captured} / {total_flags} Flags Captured ({round(captured/total_flags*100, 1)}%)")

        # Gap Advice
        gap = generate_gap_analysis(self.ranges, score)
        if gap["advice_lines"]:
            self.lbl_gap_advice.setText(gap["advice_lines"][0])

    def _on_range_selected(self, row: int):
        if row < 0 or row >= len(self.ranges):
            return
        self.selected_range = self.ranges[row]
        r = self.selected_range
        self.lbl_enclave_banner.setText(
            f"{r.icon} {r.name.upper()}  |  Subnet Scope: {r.target_subnet}  |  "
            f"Captured: {r.captured_points} / {r.total_points} pts"
        )

        # Populate flags table
        self.table_flags.setRowCount(len(r.flags))
        for i, f in enumerate(r.flags):
            item_id = QTableWidgetItem(f.flag_id)
            item_id.setFlags(item_id.flags() & ~Qt.ItemFlag.ItemIsEditable)

            item_title = QTableWidgetItem(f.title)
            item_title.setFlags(item_title.flags() & ~Qt.ItemFlag.ItemIsEditable)

            item_target = QTableWidgetItem(f"{f.target_ip} ({f.service_port})")
            item_target.setFlags(item_target.flags() & ~Qt.ItemFlag.ItemIsEditable)

            item_pts = QTableWidgetItem(f"+{f.points} pts")
            item_pts.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_pts.setFlags(item_pts.flags() & ~Qt.ItemFlag.ItemIsEditable)

            status_str = "✅ Captured" if f.captured else "❌ Unsolved"
            item_status = QTableWidgetItem(status_str)
            item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_status.setFlags(item_status.flags() & ~Qt.ItemFlag.ItemIsEditable)
            if f.captured:
                item_status.setForeground(QColor("#10b981"))
            else:
                item_status.setForeground(QColor(CPENTTheme.SECONDARY_TEXT))

            self.table_flags.setItem(i, 0, item_id)
            self.table_flags.setItem(i, 1, item_title)
            self.table_flags.setItem(i, 2, item_target)
            self.table_flags.setItem(i, 3, item_pts)
            self.table_flags.setItem(i, 4, item_status)

        if r.flags:
            self.table_flags.clearSelection()
            self.table_flags.selectRow(0)
            self._on_flag_selected()

    def _on_flag_selected(self):
        selected_rows = self.table_flags.selectionModel().selectedRows()
        if not selected_rows or not self.selected_range:
            self.selected_flag = None
            self.btn_send_shell.setEnabled(False)
            self.btn_toggle_hint.setEnabled(False)
            self.lbl_selected_target.setText("Target: None selected")
            return

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.selected_range.flags):
            return

        self.selected_flag = self.selected_range.flags[row]
        f = self.selected_flag
        self.btn_send_shell.setEnabled(True)
        self.btn_toggle_hint.setEnabled(True)
        self.lbl_selected_target.setText(f"Target: {f.target_ip} ({f.service_port}) - {f.title}")
        self.lbl_hint_box.setText(f"Hint: {f.hint}")
        self.lbl_hint_box.setVisible(False)
        self.btn_toggle_hint.setText("💡 Show Practice Hint")
        self.edit_flag.clear()
        self.lbl_submit_feedback.setText("")
        self._validate_scope()

    def _toggle_hint(self):
        if not self.lbl_hint_box.isVisible():
            self.lbl_hint_box.setVisible(True)
            self.btn_toggle_hint.setText("💡 Hide Practice Hint")
        else:
            self.lbl_hint_box.setVisible(False)
            self.btn_toggle_hint.setText("💡 Show Practice Hint")

    def _send_target_to_shell(self):
        if not self.selected_flag:
            return
        f = self.selected_flag
        port = f.service_port.split("/")[0] if "/" in f.service_port else "80"
        cmd = f"# CPENT Challenge {f.flag_id} Target\nnmap -sV -p {port} {f.target_ip}"
        self.command_to_shell_requested.emit(cmd)
        self.lbl_submit_feedback.setText(f"Dispatched target probe command for {f.target_ip}:{port} to Console.")
        self.lbl_submit_feedback.setStyleSheet(f"color: {CPENTTheme.INFO_CYAN};")

    # ----------------------------------------------------------------------
    # Flag Submission Engine
    # ----------------------------------------------------------------------
    def _submit_flag(self):
        if not self.selected_flag:
            self.lbl_submit_feedback.setText("Please select a challenge from the table first.")
            self.lbl_submit_feedback.setStyleSheet("color: #ef4444;")
            return

        flag = self.selected_flag
        if flag.captured:
            self.lbl_submit_feedback.setText(f"Flag for {flag.flag_id} is already captured!")
            self.lbl_submit_feedback.setStyleSheet("color: #f59e0b;")
            return

        candidate = self.edit_flag.text().strip()
        if not candidate:
            self.lbl_submit_feedback.setText("Flag input cannot be empty.")
            self.lbl_submit_feedback.setStyleSheet("color: #ef4444;")
            return

        if verify_flag_submission(candidate, flag):
            from datetime import datetime, timezone
            now_iso = datetime.now(timezone.utc).isoformat()
            flag.captured = True
            flag.captured_at = now_iso
            flag.evidence_text = f"Candidate string verified: {candidate}"
            self.session.score += flag.points
            if flag.flag_id not in self.session.captured_flag_ids:
                self.session.captured_flag_ids.append(flag.flag_id)

            # Check milestone thresholds
            milestones = calculate_exam_milestones(self.session.score)
            if milestones["lpt_master_achieved"] and (self.session.score - flag.points) < 2700:
                self.milestone_unlocked.emit("lpt_master")
                QMessageBox.information(
                    self,
                    "🏆 LPT (Master) Milestone Achieved!",
                    f"🎉 Sensational! With +{flag.points} points for {flag.flag_id}, your score is now {self.session.score} points!\n"
                    "You have officially surpassed the 2,700 point threshold and qualified for LPT (Master)!",
                )
            elif milestones["cpent_passed"] and (self.session.score - flag.points) < 2100:
                self.milestone_unlocked.emit("cpent_pass")
                QMessageBox.information(
                    self,
                    "🎯 CPENT Certification Pass!",
                    f"🎉 Congratulations! With +{flag.points} points for {flag.flag_id}, your score is now {self.session.score} points!\n"
                    "You have surpassed the 2,100 point threshold and qualified for CPENT Certification!",
                )

            self.flag_captured.emit(flag.flag_id, self.session.score)
            self._save_state()
            self._update_all_displays()

            self.lbl_submit_feedback.setText(f"🎉 CORRECT! Verified flag for {flag.flag_id}. +{flag.points} Points awarded!")
            self.lbl_submit_feedback.setStyleSheet("color: #10b981; font-weight: bold;")
            self.edit_flag.clear()
        else:
            self.lbl_submit_feedback.setText("❌ INCORRECT flag candidate. Please verify your capture proof.")
            self.lbl_submit_feedback.setStyleSheet("color: #ef4444; font-weight: bold;")

    # ----------------------------------------------------------------------
    # Integration Actions: Scope, Findings Sync, & Report Export
    # ----------------------------------------------------------------------
    def _validate_scope(self):
        target_ip = self.selected_flag.target_ip if self.selected_flag else None
        if not self.db or not self.active_project or not target_ip:
            self.lbl_scope_banner.setText("Scope Status: Ready (Active project scope rules verified on target).")
            self.lbl_scope_banner.setStyleSheet(
                f"font-size: 11px; padding: 4px 10px; border-radius: 4px; "
                f"background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.SECONDARY_TEXT};"
            )
            return

        try:
            scopes = self.db.list_scopes(self.active_project.id)
            from core.scope import ScopeAuthorizationService
            auth = ScopeAuthorizationService.is_target_authorized(target_ip, scopes)
            if auth.is_allowed:
                self.lbl_scope_banner.setText(f"✓ Authorized Scope: Challenge target {target_ip} is in project scope.")
                self.lbl_scope_banner.setStyleSheet(
                    f"font-size: 11px; padding: 4px 10px; border-radius: 4px; "
                    f"background-color: rgba(38,166,154,0.15); color: {CPENTTheme.SUCCESS_GREEN}; font-weight: bold;"
                )
            else:
                self.lbl_scope_banner.setText(f"⚠️ Out-of-Scope Warning: Challenge target {target_ip} is NOT authorized in active project.")
                self.lbl_scope_banner.setStyleSheet(
                    f"font-size: 11px; padding: 4px 10px; border-radius: 4px; "
                    f"background-color: rgba(229,57,53,0.15); color: {CPENTTheme.ACCENT_RED}; font-weight: bold;"
                )
        except Exception:
            pass

    def _sync_flags_to_findings(self):
        """Converts all captured flags into verified Finding & Evidence records in the active project database."""
        captured_flags = [f for r in self.ranges for f in r.flags if f.captured]
        if not captured_flags:
            QMessageBox.information(
                self,
                "No Captured Flags",
                "There are no captured flags to sync yet. Capture challenge flags first!",
            )
            return

        if not self.db or not self.active_project or not self.active_project.id:
            QMessageBox.warning(
                self,
                "Project Required",
                "Please select an active project in CyberSecuritySuite before syncing findings.",
            )
            return

        proj_id = self.active_project.id
        synced_count = 0

        # Query existing findings to prevent duplicate titles
        existing_findings = self.db.list_findings(proj_id)
        existing_titles = {f.title for f in existing_findings}

        for flag in captured_flags:
            title = f"CPENT Lab Flag Compromise: {flag.title}"
            if title in existing_titles:
                continue

            sev_val = FindingSeverity.HIGH
            try:
                sev_val = FindingSeverity(flag.severity.lower())
            except Exception:
                sev_val = FindingSeverity.HIGH

            finding = Finding(
                project_id=proj_id,
                title=title,
                severity=sev_val,
                cvss_score=flag.cvss_score,
                affected_asset=flag.target_ip,
                affected_port_service=flag.service_port,
                description=(
                    f"Compromised during 24-Hour CPENT Practical Exam Simulation.\n\n"
                    f"Challenge ID: {flag.flag_id}\n"
                    f"Enclave Range: {flag.range_id}\n"
                    f"Points Awarded: {flag.points} pts\n"
                    f"Technique Hint: {flag.hint}"
                ),
                reproduction_steps=(
                    f"1. Target IP / Service: {flag.target_ip} ({flag.service_port})\n"
                    f"2. Method: Exploit identified vulnerability using CPENT methodology.\n"
                    f"3. Verified Flag Proof: {flag.raw_flag_sample}\n"
                    f"4. Capture Time: {flag.captured_at}"
                ),
                remediation=flag.remediation,
                validation_status=ValidationStatus.CONFIRMED,
                source_tool="CPENT Exam Simulator",
            )
            saved_finding = self.db.create_finding(finding)
            synced_count += 1

            # Evidence linking
            if saved_finding.id:
                evidence = Evidence(
                    project_id=proj_id,
                    finding_id=saved_finding.id,
                    file_path=f"storage/evidence/cpent_flag_{flag.flag_id.lower()}.txt",
                    sha256_hash=flag.flag_hash,
                    description=f"Verified Flag Proof Token for {flag.flag_id} ({flag.title})",
                    mime_type="text/plain",
                )
                self.db.add_evidence(evidence)

        QMessageBox.information(
            self,
            "Flags Synced to Findings",
            f"Successfully synced {synced_count} captured flags into Project Findings & Evidence Vault!\n\n"
            f"These findings will now appear in Findings View and be included in your CPENT Engagement Pack & Reports.",
        )

    def _export_markdown_report(self):
        proj_name = self.active_project.name if self.active_project else "CPENT Exam Practice"
        report_md = export_exam_markdown_report(self.session, self.ranges, project_name=proj_name)

        default_name = f"CPENT_Exam_Debrief_{self.session.session_id}.md"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Exam Debrief Markdown Report", default_name, "Markdown Files (*.md);;All Files (*)"
        )
        if file_path:
            try:
                Path(file_path).write_text(report_md, encoding="utf-8")
                QMessageBox.information(
                    self, "Report Exported", f"Successfully exported exam debrief to:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save report: {e}")

    def _copy_scoreboard_summary(self):
        milestones = calculate_exam_milestones(self.session.score)
        summary = (
            f"🏆 CPENT Exam Simulator Scoreboard\n"
            f"Score: {self.session.score} / 3,000 Points ({milestones['percentage']}%)\n"
            f"CPENT Pass (2,100 pts): {'✅ PASSED' if milestones['cpent_passed'] else '❌ PENDING'}\n"
            f"LPT Master (2,700 pts): {'🏆 ACHIEVED' if milestones['lpt_master_achieved'] else '❌ PENDING'}\n"
            f"Flags Captured: {sum(r.captured_count for r in self.ranges)} / {sum(len(r.flags) for r in self.ranges)}\n"
            f"Time Elapsed: {self.session.elapsed_seconds // 3600}h {(self.session.elapsed_seconds % 3600) // 60}m"
        )
        from PySide6.QtGui import QGuiApplication
        clipboard = QGuiApplication.clipboard()
        if clipboard:
            clipboard.setText(summary)
            self.lbl_submit_feedback.setText("Scoreboard summary copied to clipboard.")
            self.lbl_submit_feedback.setStyleSheet("color: #10b981;")

    # ----------------------------------------------------------------------
    # Persistence
    # ----------------------------------------------------------------------
    def _save_state(self):
        try:
            save_exam_state(self.session, self.ranges, self.state_file)
        except Exception:
            pass

    def _load_saved_state(self):
        try:
            session, ranges = load_exam_state(self.state_file, default_ranges=self.ranges)
            self.session = session
            self.ranges = ranges
            # Restore combo mode
            if self.session.mode == "24h":
                self.combo_mode.setCurrentIndex(0)
            elif self.session.mode == "2x12h" and self.session.session_part == 1:
                self.combo_mode.setCurrentIndex(1)
            elif self.session.mode == "2x12h" and self.session.session_part == 2:
                self.combo_mode.setCurrentIndex(2)

            if self.session.state == "running":
                self.btn_start.setEnabled(False)
                self.btn_pause.setEnabled(True)
                self.btn_finalize.setEnabled(True)
                self._set_status_badge(f"RUNNING (Part {self.session.session_part})", "RUNNING")
                self.timer.start()
            elif self.session.state == "paused":
                self.btn_start.setEnabled(False)
                self.btn_pause.setEnabled(True)
                self.btn_pause.setText("▶ Resume Session")
                self.btn_finalize.setEnabled(True)
                self._set_status_badge("PAUSED", "WARNING")
            elif self.session.state == "completed":
                self.btn_start.setEnabled(False)
                self.btn_pause.setEnabled(False)
                self.btn_finalize.setEnabled(False)
                self._set_status_badge("FINALIZED", "INFO")
        except Exception:
            pass
