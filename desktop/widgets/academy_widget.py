"""Python Security Academy Interactive Learning & Coding Challenge Workbench.

Provides hands-on secure coding exercises, AST validation, hint assistance,
and CPENT flag rewards directly embedded within CyberSecuritySuite.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from desktop.widgets.code_security_workbench import CodeEditorWidget
from modules.academy.academy_service import (
    AcademyLesson,
    AcademyService,
    Difficulty,
    VerificationResult,
)
from storage.db import Database


class AcademyWidget(QWidget):
    """Complete Python Security Academy hands-on laboratory workbench."""

    send_to_ai_chat = Signal(str)
    lesson_completed = Signal(str, int)  # lesson_id, points

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.service = AcademyService(db=db)
        self.active_lesson: Optional[AcademyLesson] = None
        self._init_ui()
        self._load_first_lesson()

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        # 1. Top Header Bar
        hdr = QHBoxLayout()
        title = QLabel("🎓 Python Security Academy & Interactive Lab Challenges")
        title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        title.setStyleSheet("color: #38bdf8;")
        hdr.addWidget(title)

        self.lbl_score = QLabel("🏆 Total Score: 0 pts")
        self.lbl_score.setStyleSheet(
            "background-color: #1e1b4b; color: #c084fc; border: 1px solid #7e22ce; border-radius: 12px; padding: 4px 12px; font-weight: bold; font-size: 11px;"
        )
        hdr.addWidget(self.lbl_score)
        hdr.addStretch()

        root.addLayout(hdr)

        # 2. Main Splitter: Left Curriculum Explorer vs Right Challenge Workspace
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #1e293b; }")

        # A. Left Curriculum Drawer
        drawer = QFrame()
        drawer.setStyleSheet("background-color: #0b0f19; border-right: 1px solid #1e293b; border-radius: 6px;")
        d_layout = QVBoxLayout(drawer)
        d_layout.setContentsMargins(10, 10, 10, 10)
        d_layout.setSpacing(8)

        lbl_tracks = QLabel("Curriculum Tracks")
        lbl_tracks.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl_tracks.setStyleSheet("color: #94a3b8;")
        d_layout.addWidget(lbl_tracks)

        self.list_lessons = QListWidget()
        self.list_lessons.setStyleSheet(
            "QListWidget { background-color: #0d1117; border: 1px solid #1e293b; color: #f1f5f9; border-radius: 6px; font-size: 11px; }"
            "QListWidget::item { padding: 8px 6px; border-bottom: 1px solid #1e293b; }"
            "QListWidget::item:selected { background-color: #1e293b; border-left: 3px solid #38bdf8; font-weight: bold; }"
        )
        self.list_lessons.itemClicked.connect(self._on_lesson_selected)
        d_layout.addWidget(self.list_lessons)
        splitter.addWidget(drawer)

        # B. Right Challenge Workspace
        work_panel = QFrame()
        work_panel.setStyleSheet("background-color: #0f172a; border-radius: 6px;")
        w_layout = QVBoxLayout(work_panel)
        w_layout.setContentsMargins(14, 12, 14, 12)
        w_layout.setSpacing(10)

        # Challenge Header Info
        top_info = QHBoxLayout()
        self.lbl_challenge_title = QLabel("Lesson Title")
        self.lbl_challenge_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_challenge_title.setStyleSheet("color: #ffffff;")
        top_info.addWidget(self.lbl_challenge_title)

        self.lbl_cwe_badge = QLabel("CWE-89")
        self.lbl_cwe_badge.setStyleSheet(
            "background-color: #7f1d1d; color: #fca5a5; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 9px;"
        )
        top_info.addWidget(self.lbl_cwe_badge)

        self.lbl_diff_badge = QLabel("Beginner")
        self.lbl_diff_badge.setStyleSheet(
            "background-color: #064e3b; color: #34d399; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 9px;"
        )
        top_info.addWidget(self.lbl_diff_badge)

        self.lbl_pts_badge = QLabel("50 pts")
        self.lbl_pts_badge.setStyleSheet(
            "background-color: #312e81; color: #a5b4fc; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 9px;"
        )
        top_info.addWidget(self.lbl_pts_badge)
        top_info.addStretch()

        w_layout.addLayout(top_info)

        # Tabs: Concept & Explanation vs Hints
        self.concept_tabs = QTabWidget()
        self.concept_tabs.setMaximumHeight(160)
        self.concept_tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #1e293b; background-color: #0b0f19; }"
            "QTabBar::tab { background-color: #1e293b; color: #94a3b8; padding: 4px 10px; font-size: 10px; }"
            "QTabBar::tab:selected { background-color: #0284c7; color: white; }"
        )

        self.txt_concept = QTextEdit()
        self.txt_concept.setReadOnly(True)
        self.txt_concept.setStyleSheet("background-color: #0b0f19; color: #cbd5e1; border: none; font-size: 11px;")
        self.concept_tabs.addTab(self.txt_concept, "📖 Concept & Attack Explanation")

        self.txt_hints = QTextEdit()
        self.txt_hints.setReadOnly(True)
        self.txt_hints.setStyleSheet("background-color: #0b0f19; color: #fef08a; border: none; font-size: 11px;")
        self.concept_tabs.addTab(self.txt_hints, "💡 Hints")

        w_layout.addWidget(self.concept_tabs)

        # Code Editor
        lbl_ed_hdr = QLabel("Interactive Code Remediation Sandbox:")
        lbl_ed_hdr.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_ed_hdr.setStyleSheet("color: #94a3b8;")
        w_layout.addWidget(lbl_ed_hdr)

        self.editor = CodeEditorWidget()
        w_layout.addWidget(self.editor, stretch=1)

        # Feedback & Verification Banner
        self.feedback_banner = QFrame()
        self.feedback_banner.setStyleSheet(
            "background-color: #1e293b; border-radius: 6px; padding: 6px; border: 1px solid #334155;"
        )
        fb_layout = QHBoxLayout(self.feedback_banner)
        fb_layout.setContentsMargins(10, 6, 10, 6)
        self.lbl_feedback = QLabel("Modify the vulnerable code above and click 'Run & Verify Fix'.")
        self.lbl_feedback.setStyleSheet("color: #94a3b8; font-size: 11px;")
        fb_layout.addWidget(self.lbl_feedback)
        w_layout.addWidget(self.feedback_banner)

        # Action Buttons
        btn_bar = QHBoxLayout()
        self.btn_verify = QPushButton("▶ Run & Verify Fix")
        self.btn_verify.setStyleSheet(
            "background-color: #16a34a; color: white; border-radius: 6px; padding: 8px 16px; font-weight: bold; font-size: 11px;"
        )
        self.btn_verify.clicked.connect(self._verify_solution)
        btn_bar.addWidget(self.btn_verify)

        self.btn_ask_ai = QPushButton("🤖 Request AI Hint")
        self.btn_ask_ai.setStyleSheet(
            "background-color: #7e22ce; color: white; border-radius: 6px; padding: 8px 14px; font-weight: bold; font-size: 11px;"
        )
        self.btn_ask_ai.clicked.connect(self._ask_ai_hint)
        btn_bar.addWidget(self.btn_ask_ai)

        self.btn_reset = QPushButton("🔄 Reset Code")
        self.btn_reset.setStyleSheet(
            "background-color: #334155; color: white; border-radius: 6px; padding: 8px 12px; font-size: 11px;"
        )
        self.btn_reset.clicked.connect(self._reset_code)
        btn_bar.addWidget(self.btn_reset)

        btn_bar.addStretch()
        w_layout.addLayout(btn_bar)

        splitter.addWidget(work_panel)
        splitter.setSizes([260, 680])

        root.addWidget(splitter, stretch=1)

    def _load_first_lesson(self):
        self.list_lessons.clear()
        for lid, lesson in self.service.lessons.items():
            check = "✔ " if lesson.is_completed else "○ "
            item = QListWidgetItem(f"{check}{lesson.title} ({lesson.points} pts)")
            item.setData(Qt.UserRole, lid)
            self.list_lessons.addItem(item)

        if self.service.lessons:
            self.list_lessons.setCurrentRow(0)
            first_lid = list(self.service.lessons.keys())[0]
            self._select_lesson(self.service.lessons[first_lid])

    def _on_lesson_selected(self, item: QListWidgetItem):
        lid = item.data(Qt.UserRole)
        lesson = self.service.lessons.get(lid)
        if lesson:
            self._select_lesson(lesson)

    def _select_lesson(self, lesson: AcademyLesson):
        self.active_lesson = lesson
        self.lbl_challenge_title.setText(lesson.title)
        self.lbl_cwe_badge.setText(lesson.cwe_id)
        self.lbl_diff_badge.setText(lesson.difficulty.value)
        self.lbl_pts_badge.setText(f"{lesson.points} pts")

        # HTML formatting for markdown concept
        html_concept = lesson.concept_explanation.replace("\n", "<br>").replace("### ", "<h3>").replace("```python", "<pre style='color:#38bdf8;'>").replace("```", "</pre>")
        self.txt_concept.setHtml(html_concept)

        hints_html = "<b>Helpful Hints:</b><br><ul>"
        for h in lesson.hints:
            hints_html += f"<li>{h}</li>"
        hints_html += "</ul>"
        self.txt_hints.setHtml(hints_html)

        self.editor.setPlainText(lesson.vulnerable_code)
        self.lbl_feedback.setText("Modify the vulnerable code above and click 'Run & Verify Fix'.")
        self.lbl_feedback.setStyleSheet("color: #94a3b8; font-size: 11px;")
        self.feedback_banner.setStyleSheet("background-color: #1e293b; border-radius: 6px; padding: 6px; border: 1px solid #334155;")

    def _verify_solution(self):
        if not self.active_lesson:
            return
        code = self.editor.toPlainText()
        res: VerificationResult = self.service.verify_solution(self.active_lesson.lesson_id, code)

        if res.is_passed:
            self.feedback_banner.setStyleSheet("background-color: #064e3b; border-radius: 6px; padding: 6px; border: 1px solid #10b981;")
            self.lbl_feedback.setText(f"🎉 {res.feedback_message}\nFLAG: {res.flag}")
            self.lbl_feedback.setStyleSheet("color: #34d399; font-weight: bold; font-size: 11px;")
            self.lesson_completed.emit(self.active_lesson.lesson_id, res.awarded_points)
            self._refresh_score()
            self._update_lesson_list()
        else:
            self.feedback_banner.setStyleSheet("background-color: #450a0a; border-radius: 6px; padding: 6px; border: 1px solid #ef4444;")
            self.lbl_feedback.setText(f"❌ {res.feedback_message}")
            self.lbl_feedback.setStyleSheet("color: #f87171; font-weight: bold; font-size: 11px;")

    def _refresh_score(self):
        total_pts = sum(l.points for l in self.service.lessons.values() if l.is_completed)
        self.lbl_score.setText(f"🏆 Total Score: {total_pts} pts")

    def _update_lesson_list(self):
        curr_row = self.list_lessons.currentRow()
        for i in range(self.list_lessons.count()):
            item = self.list_lessons.item(i)
            lid = item.data(Qt.UserRole)
            lesson = self.service.lessons.get(lid)
            if lesson:
                check = "✔ " if lesson.is_completed else "○ "
                item.setText(f"{check}{lesson.title} ({lesson.points} pts)")
                if lesson.is_completed:
                    item.setForeground(QColor("#34d399"))
        self.list_lessons.setCurrentRow(curr_row)

    def _ask_ai_hint(self):
        if not self.active_lesson:
            return
        prompt = (
            f"I am working on the Python Security Academy challenge '{self.active_lesson.title}' ({self.active_lesson.cwe_id}).\n\n"
            f"Here is my current code attempt:\n```python\n{self.editor.toPlainText()}\n```\n\n"
            f"Please give me a guided hint explaining why this is vulnerable and guide me toward the secure implementation without giving away the full answer directly."
        )
        self.send_to_ai_chat.emit(prompt)
        QMessageBox.information(
            self,
            "Dispatched to AI Assistant",
            "Sent your code and lesson context to the persistent AI Copilot. Open the AI Assistant panel to read the advice!",
        )

    def _reset_code(self):
        if self.active_lesson:
            self.editor.setPlainText(self.active_lesson.vulnerable_code)
            self.lbl_feedback.setText("Reset to starter code.")
            self.lbl_feedback.setStyleSheet("color: #94a3b8; font-size: 11px;")
            self.feedback_banner.setStyleSheet("background-color: #1e293b; border-radius: 6px; padding: 6px; border: 1px solid #334155;")

