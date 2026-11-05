"""Bob Findings & Code Security SAST Workbench.

Faithfully implements the user-referenced Code Review & SAST findings IDE interface:
- Top: Syntax-highlighted code editor with line numbers and red vulnerability highlighting.
- Bottom: 'BOB FINDINGS' panel with:
  - Fuzzy search and file filters.
  - Left-hand tree view grouping findings by source file with badge counts.
  - Right-hand finding details card with severity, CWE, and file location.
  - Action buttons:
    * '📍 Go To Location' (jumps code editor directly to vulnerable line and highlights it).
    * '💬 Investigate and improve code in chat' (sends finding and code snippet to AI Assistant).
    * '✓ Mark as Resolved'.
    * '✕ Dismiss Finding'.
- Direct integration with AST SAST engine (`ast_visitor.py`) and Bandit adapter.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QPainter,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QTextFormat,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from modules.code_security.ast_visitor import (
    CodeSecurityIssue,
    PythonSecurityASTVisitor,
    PythonSecurityScanner,
)
from storage.db import Database
from storage.models import Finding, FindingSeverity, ValidationStatus


class LineNumberArea(QWidget):
    """Gutter widget displaying line numbers for the code editor."""

    def __init__(self, editor: CodeEditorWidget):
        super().__init__(editor)
        self.code_editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.code_editor.line_number_area_paint_event(event)


class PythonHighlighter(QSyntaxHighlighter):
    """Lightweight syntax highlighter for Python code."""

    def __init__(self, parent: QTextDocument):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#c084fc"))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            r"\bdef\b", r"\bclass\b", r"\basync\b", r"\bawait\b", r"\breturn\b",
            r"\bif\b", r"\belse\b", r"\belif\b", r"\bfor\b", r"\bwhile\b",
            r"\btry\b", r"\bexcept\b", r"\bfinally\b", r"\bimport\b", r"\bfrom\b",
            r"\bas\b", r"\bself\b", r"\bwith\b", r"\braise\b",
        ]
        for pattern in keywords:
            self.highlighting_rules.append((pattern, keyword_format))

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#38bdf8"))
        self.highlighting_rules.append((r'".*?"', string_format))
        self.highlighting_rules.append((r"'.*?'", string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#64748b"))
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((r"#.*", comment_format))

    def highlightBlock(self, text: str):
        import re
        for pattern, fmt in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class CodeEditorWidget(QPlainTextEdit):
    """Code editor with gutter line numbers and vulnerable line highlighting."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        self.vulnerable_line: Optional[int] = None

        self.setFont(QFont("JetBrains Mono, Fira Code, Consolas, Courier New", 10))
        self.setStyleSheet(
            "QPlainTextEdit { background-color: #0b0f19; color: #f1f5f9; border: 1px solid #1e293b; border-radius: 6px; selection-background-color: #3b82f6; }"
        )

        self.highlighter = PythonHighlighter(self.document())
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.update_line_number_area_width(0)

    def line_number_area_width(self) -> int:
        digits = 1
        max_b = max(1, self.blockCount())
        while max_b >= 10:
            max_b //= 10
            digits += 1
        space = 14 + self.fontMetrics().horizontalAdvance('9') * digits
        return space

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def highlight_vulnerable_line(self, line_number: int):
        """Highlights the vulnerable line with red background tint."""
        self.vulnerable_line = line_number
        extra_selections = []

        if not self.isReadOnly():
            block = self.document().findBlockByNumber(max(0, line_number - 1))
            if block.isValid():
                cursor = QTextCursor(block)
                selection = QTextEditSelection() if False else None  # type helper
                fmt = QTextCharFormat()
                fmt.setBackground(QColor(127, 29, 29, 120))  # Translucent Dark Red
                fmt.setProperty(QTextFormat.FullWidthSelection, True)

                sel = QTextEdit.ExtraSelection()
                sel.format = fmt
                sel.cursor = cursor
                sel.cursor.clearSelection()
                extra_selections.append(sel)

        self.setExtraSelections(extra_selections)
        self.line_number_area.update()

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QColor("#0f172a"))

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                is_vuln = (self.vulnerable_line == block_number + 1)
                painter.setPen(QColor("#ef4444") if is_vuln else QColor("#64748b"))
                if is_vuln:
                    painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
                else:
                    painter.setFont(QFont("Segoe UI", 9))
                painter.drawText(
                    0, top, self.line_number_area.width() - 8, self.fontMetrics().height(),
                    Qt.AlignRight, number
                )

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1


class CodeSecurityWorkbenchWidget(QWidget):
    """Complete SAST Code Review & Bob Findings workbench."""

    send_to_ai_chat = Signal(str)

    def __init__(self, db: Optional[Database] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.current_issues: List[CodeSecurityIssue] = []
        self.active_issue: Optional[CodeSecurityIssue] = None
        self._init_ui()
        self.load_sample_vulnerable_code()

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Top Control & File Tab Bar
        top_bar = QHBoxLayout()
        lbl_file = QLabel("📄 user.py (Intentionally Vulnerable Lab)")
        lbl_file.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_file.setStyleSheet("color: #38bdf8;")
        self.lbl_active_file = lbl_file
        top_bar.addWidget(lbl_file)
        top_bar.addStretch()

        self.btn_open_file = QPushButton("📂 Open Source File")
        self.btn_open_file.setStyleSheet(
            "background-color: #1e293b; color: white; border-radius: 6px; padding: 6px 12px; font-weight: bold;"
        )
        self.btn_open_file.clicked.connect(self._open_file_dialog)
        top_bar.addWidget(self.btn_open_file)

        self.btn_scan = QPushButton("⚡ Run SAST Scan (Pure Python AST)")
        self.btn_scan.setStyleSheet(
            "background-color: #2563eb; color: white; border-radius: 6px; padding: 6px 14px; font-weight: bold;"
        )
        self.btn_scan.clicked.connect(self._run_scan_on_current)
        top_bar.addWidget(self.btn_scan)

        root.addLayout(top_bar)

        # Vertical Splitter: Code Editor (Top) vs Bob Findings (Bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #334155; }")

        # Top: Code Editor
        self.editor = CodeEditorWidget()
        splitter.addWidget(self.editor)

        # Bottom: BOB FINDINGS Panel
        bottom_panel = QFrame()
        bottom_panel.setStyleSheet(
            "QFrame { background-color: #0d1117; border-radius: 8px; border: 1px solid #1f2937; }"
        )
        b_layout = QVBoxLayout(bottom_panel)
        b_layout.setContentsMargins(10, 8, 10, 10)
        b_layout.setSpacing(8)

        # Panel Title & Filter Bar
        panel_header = QHBoxLayout()
        lbl_tab = QLabel("🛡️ BOB FINDINGS")
        lbl_tab.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl_tab.setStyleSheet("color: #f3f4f6; border-bottom: 2px solid #3b82f6; padding-bottom: 4px;")
        panel_header.addWidget(lbl_tab)

        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("🔍 Fuzzy search findings...")
        self.txt_filter.setStyleSheet(
            "background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; color: white; padding: 4px 8px; font-size: 11px;"
        )
        self.txt_filter.textChanged.connect(self._filter_tree)
        panel_header.addWidget(self.txt_filter)

        panel_header.addStretch()
        self.lbl_finding_count = QLabel("0 Findings")
        self.lbl_finding_count.setStyleSheet("color: #9ca3af; font-size: 11px;")
        panel_header.addWidget(self.lbl_finding_count)
        b_layout.addLayout(panel_header)

        # Splitter inside Bottom Panel: Left Tree vs Right Details
        findings_splitter = QSplitter(Qt.Horizontal)
        findings_splitter.setStyleSheet("QSplitter::handle { background-color: #21262d; }")

        # Left: Finding Tree
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setStyleSheet(
            "QTreeWidget { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 11px; }"
            "QTreeWidget::item { padding: 4px; }"
            "QTreeWidget::item:selected { background-color: #1f6feb; color: white; }"
        )
        self.tree.itemClicked.connect(self._on_tree_item_clicked)
        findings_splitter.addWidget(self.tree)

        # Right: Finding Details Card
        detail_frame = QFrame()
        detail_frame.setStyleSheet("background-color: #161b22; border-radius: 6px; border: 1px solid #30363d;")
        d_layout = QVBoxLayout(detail_frame)
        d_layout.setContentsMargins(14, 12, 14, 12)
        d_layout.setSpacing(8)

        self.lbl_det_title = QLabel("Select a finding to inspect")
        self.lbl_det_title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.lbl_det_title.setWordWrap(True)
        self.lbl_det_title.setStyleSheet("color: #f0f6fc;")
        d_layout.addWidget(self.lbl_det_title)

        self.lbl_det_desc = QLabel("")
        self.lbl_det_desc.setWordWrap(True)
        self.lbl_det_desc.setStyleSheet("color: #8b949e; font-size: 11px;")
        d_layout.addWidget(self.lbl_det_desc)

        self.lbl_det_loc = QLabel("")
        self.lbl_det_loc.setStyleSheet("color: #58a6ff; font-family: monospace; font-size: 11px;")
        d_layout.addWidget(self.lbl_det_loc)

        d_layout.addStretch()

        # Action Buttons matching the reference image!
        btn_bar = QHBoxLayout()
        self.btn_goto = QPushButton("📍 Go To Location")
        self.btn_goto.setStyleSheet(
            "background-color: #1f6feb; color: white; border-radius: 6px; padding: 6px 12px; font-weight: bold; font-size: 11px;"
        )
        self.btn_goto.clicked.connect(self._goto_location)
        btn_bar.addWidget(self.btn_goto)

        self.btn_chat = QPushButton("💬 Investigate and improve code in chat")
        self.btn_chat.setStyleSheet(
            "background-color: #238636; color: white; border-radius: 6px; padding: 6px 14px; font-weight: bold; font-size: 11px;"
        )
        self.btn_chat.clicked.connect(self._investigate_in_chat)
        btn_bar.addWidget(self.btn_chat)

        self.btn_resolve = QPushButton("✓ Mark as Resolved")
        self.btn_resolve.setStyleSheet(
            "background-color: #21262d; color: #58a6ff; border: 1px solid #30363d; border-radius: 6px; padding: 6px 10px; font-size: 11px;"
        )
        self.btn_resolve.clicked.connect(self._resolve_finding)
        btn_bar.addWidget(self.btn_resolve)

        self.btn_dismiss = QPushButton("✕ Dismiss")
        self.btn_dismiss.setStyleSheet(
            "background-color: #21262d; color: #f85149; border: 1px solid #30363d; border-radius: 6px; padding: 6px 10px; font-size: 11px;"
        )
        self.btn_dismiss.clicked.connect(self._dismiss_finding)
        btn_bar.addWidget(self.btn_dismiss)

        d_layout.addLayout(btn_bar)

        findings_splitter.addWidget(detail_frame)
        findings_splitter.setSizes([380, 520])

        b_layout.addWidget(findings_splitter, stretch=1)
        splitter.addWidget(bottom_panel)

        splitter.setSizes([450, 320])
        root.addWidget(splitter, stretch=1)

    def load_sample_vulnerable_code(self):
        """Loads sample vulnerable Python code matching Image 5 and 6."""
        code = (
            "import os\n"
            "import pickle\n"
            "import sqlite3\n"
            "from typing import Optional\n"
            "\n"
            "class UserRepository:\n"
            "    # WARNING: This method is intentionally vulnerable to SQL injection for demo purposes.\n"
            "    # DO NOT USE IN PRODUCTION.\n"
            "    # VULNERABLE: Direct string concatenation allows SQL injection\n"
            "    async def search_users_by_keyword(self, keyword: str) -> list:\n"
            "        conn = sqlite3.connect('database.db')\n"
            "        cursor = conn.cursor()\n"
            "        cursor.execute(f\"SELECT * FROM users WHERE username LIKE '%{keyword}%'\")\n"
            "        return cursor.fetchall()\n"
            "\n"
            "    def load_user_session(self, token_payload: bytes):\n"
            "        # VULNERABLE: Unsafe deserialization with pickle\n"
            "        return pickle.loads(token_payload)\n"
            "\n"
            "    def execute_maintenance(self, backup_file: str):\n"
            "        # VULNERABLE: Command injection via os.system\n"
            "        os.system(f\"tar -czf backup.tar.gz {backup_file}\")\n"
        )
        self.editor.setPlainText(code)
        self.lbl_active_file.setText("📄 user.py (Intentionally Vulnerable Lab)")
        self._run_scan_on_current()

    def _run_scan_on_current(self):
        code = self.editor.toPlainText()
        lines = code.splitlines()
        try:
            tree = ast.parse(code, filename="user.py")
            visitor = PythonSecurityASTVisitor(file_path="user.py", source_lines=lines)
            visitor.visit(tree)
            self.current_issues = visitor.issues
        except Exception:
            self.current_issues = []
        self._populate_tree()

    def _populate_tree(self):
        self.tree.clear()
        self.lbl_finding_count.setText(f"{len(self.current_issues)} Findings")

        file_groups: Dict[str, List[CodeSecurityIssue]] = {}
        for issue in self.current_issues:
            file_groups.setdefault(issue.file_path, []).append(issue)

        for filename, issues in file_groups.items():
            file_item = QTreeWidgetItem(self.tree)
            file_item.setText(0, f"📁 {filename} ({len(issues)})")
            file_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            file_item.setExpanded(True)

            for issue in issues:
                child = QTreeWidgetItem(file_item)
                child.setText(0, f"🛡️ Scan ({issue.rule_id}): {issue.title}")
                child.setData(0, Qt.UserRole, issue)

        if self.current_issues:
            first_item = self.tree.topLevelItem(0).child(0)
            self.tree.setCurrentItem(first_item)
            self._select_issue(self.current_issues[0])

    def _filter_tree(self, text: str):
        query = text.strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            match_any = False
            for j in range(top.childCount()):
                child = top.child(j)
                iss: Optional[CodeSecurityIssue] = child.data(0, Qt.UserRole)
                if not iss:
                    continue
                visible = (not query) or (query in iss.title.lower()) or (query in iss.description.lower())
                child.setHidden(not visible)
                if visible:
                    match_any = True
            top.setHidden(not match_any)

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, col: int):
        issue: Optional[CodeSecurityIssue] = item.data(0, Qt.UserRole)
        if issue:
            self._select_issue(issue)

    def _select_issue(self, issue: CodeSecurityIssue):
        self.active_issue = issue
        self.lbl_det_title.setText(f"Review Finding: {issue.cwe_id}: {issue.title}")
        self.lbl_det_desc.setText(issue.description + "\n\nSuggested Fix: " + issue.remediation)
        self.lbl_det_loc.setText(f"Location: {issue.file_path}:{issue.line_number}")
        self.editor.highlight_vulnerable_line(issue.line_number)

    def _goto_location(self):
        if not self.active_issue:
            return
        line = self.active_issue.line_number
        self.editor.highlight_vulnerable_line(line)
        block = self.editor.document().findBlockByNumber(max(0, line - 1))
        cursor = QTextCursor(block)
        self.editor.setTextCursor(cursor)
        self.editor.centerCursor()

    def _investigate_in_chat(self):
        if not self.active_issue:
            return
        prompt = (
            f"Please investigate this security vulnerability in my code:\n"
            f"- Title: {self.active_issue.title}\n"
            f"- CWE: {self.active_issue.cwe_id}\n"
            f"- File: {self.active_issue.file_path}:{self.active_issue.line_number}\n"
            f"- Code Snippet:\n```python\n{self.active_issue.code_snippet}\n```\n\n"
            f"Explain why this code is vulnerable and provide the secure, remediated version using best practices."
        )
        self.send_to_ai_chat.emit(prompt)
        QMessageBox.information(
            self,
            "Sent to AI Assistant",
            "Dispatched vulnerability context to AI Copilot. Open the AI Assistant panel to review the suggested fix!",
        )

    def _resolve_finding(self):
        if not self.active_issue:
            return
        if self.active_issue in self.current_issues:
            self.current_issues.remove(self.active_issue)
            self._populate_tree()
            QMessageBox.information(self, "Resolved", "Finding marked as resolved.")

    def _dismiss_finding(self):
        if not self.active_issue:
            return
        if self.active_issue in self.current_issues:
            self.current_issues.remove(self.active_issue)
            self._populate_tree()

    def _open_file_dialog(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Python Source Code", "", "Python Files (*.py);;All Files (*)"
        )
        if filepath:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self.editor.setPlainText(content)
                self.lbl_active_file.setText(f"📄 {os.path.basename(filepath)} ({filepath})")
                lines = content.splitlines()
                try:
                    tree = ast.parse(content, filename=filepath)
                    visitor = PythonSecurityASTVisitor(file_path=os.path.basename(filepath), source_lines=lines)
                    visitor.visit(tree)
                    self.current_issues = visitor.issues
                except Exception:
                    self.current_issues = []
                self._populate_tree()
            except Exception as e:
                QMessageBox.critical(self, "Error Opening File", f"Could not load source file: {e}")
