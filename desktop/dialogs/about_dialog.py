"""About Dialog for PentestX – CyberSecuritySuite."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOGO_PATH = PROJECT_ROOT / "Glossy PentestX Logo on Black.png"


class AboutDialog(QDialog):
    """Professional About dialog showcasing official PentestX branding, version, and platform specs."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("aboutDialog")
        self.setWindowTitle("About PentestX")
        self.setFixedSize(540, 480)
        self.setModal(True)

        if LOGO_PATH.exists():
            self.setWindowIcon(QIcon(str(LOGO_PATH)))

        self._init_ui()

    def _init_ui(self):
        self.setStyleSheet(
            "QDialog#aboutDialog { background-color: #111318; }"
            "QLabel { color: #F5F5F5; font-family: 'Segoe UI', 'Ubuntu', sans-serif; }"
        )

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(28, 24, 28, 20)
        main_layout.setSpacing(14)

        # Card container
        card = QFrame()
        card.setObjectName("aboutCard")
        card.setStyleSheet(
            "QFrame#aboutCard { background-color: #1C222C; border: 1px solid #303743; border-radius: 8px; padding: 18px; }"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(10)

        # 1. Official PentestX Logo (Smooth scaling, strictly preserving 3:1 aspect ratio)
        self.lbl_logo = QLabel()
        self.lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if LOGO_PATH.exists():
            pm = QPixmap(str(LOGO_PATH))
            if not pm.isNull():
                # 3:1 aspect ratio: 270 x 90
                scaled = pm.scaled(270, 90, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.lbl_logo.setPixmap(scaled)
        card_layout.addWidget(self.lbl_logo)

        # 2. Subtitle
        lbl_subtitle = QLabel("Penetration Testing & Security Assessment Platform")
        lbl_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_subtitle.setFont(QFont("Segoe UI", 10, QFont.Weight.Medium))
        lbl_subtitle.setStyleSheet("color: #AAB2BD; margin-bottom: 4px;")
        card_layout.addWidget(lbl_subtitle)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.HLine)
        sep1.setFrameShadow(QFrame.Plain)
        sep1.setStyleSheet("color: #303743; margin: 4px 0;")
        card_layout.addWidget(sep1)

        # 3. Version & Environment Meta
        meta_layout = QHBoxLayout()
        meta_layout.setSpacing(8)

        def make_pill(text: str, color: str = "#E53935") -> QLabel:
            pill = QLabel(text)
            pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pill.setStyleSheet(
                f"background-color: #171B22; color: {color}; border: 1px solid #303743; "
                "border-radius: 4px; padding: 3px 8px; font-size: 11px; font-weight: 600;"
            )
            return pill

        meta_layout.addWidget(make_pill("v5.2.0 (CPENT Edition)", "#E53935"))
        meta_layout.addWidget(make_pill("Ubuntu Linux", "#2EAD65"))
        meta_layout.addWidget(make_pill("Python 3.12 · PySide6", "#AAB2BD"))
        card_layout.addLayout(meta_layout)

        # 4. Core Features List
        features_layout = QVBoxLayout()
        features_layout.setSpacing(4)
        features = [
            ("⚡", "Unified Multi-Tool Engine (Nmap, SAST, Active Directory, OSINT, Web)"),
            ("🛡️", "Scope Authorization & Strict Target Isolation Guard"),
            ("🤖", "AI Security Copilot & Penetration Testing Methodologies"),
            ("🔒", "AES-256-GCM Secure Credential & API Key Vault"),
            ("📊", "Continuous Telemetry & Executive Attack Surface Analytics"),
        ]
        for icon, feat in features:
            row = QHBoxLayout()
            row.setSpacing(6)
            ic_lbl = QLabel(icon)
            ic_lbl.setFixedWidth(20)
            txt_lbl = QLabel(feat)
            txt_lbl.setStyleSheet("color: #AAB2BD; font-size: 11px;")
            row.addWidget(ic_lbl)
            row.addWidget(txt_lbl, stretch=1)
            features_layout.addLayout(row)
        card_layout.addLayout(features_layout)

        # Separator
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setFrameShadow(QFrame.Plain)
        sep2.setStyleSheet("color: #303743; margin: 4px 0;")
        card_layout.addWidget(sep2)

        # 5. Legal / Usage Notice
        lbl_legal = QLabel("PentestX CyberSecuritySuite is designed for authorized security assessments, penetration testing, and educational research only.")
        lbl_legal.setWordWrap(True)
        lbl_legal.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_legal.setStyleSheet("color: #848D9A; font-size: 10px; font-style: italic;")
        card_layout.addWidget(lbl_legal)

        main_layout.addWidget(card)

        # Bottom Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.btn_close = QPushButton("Close")
        self.btn_close.setObjectName("btnAboutClose")
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.setFixedSize(100, 32)
        self.btn_close.setStyleSheet(
            "QPushButton { background-color: #E53935; color: #FFFFFF; border: none; "
            "border-radius: 4px; font-weight: 600; font-size: 12px; } "
            "QPushButton:hover { background-color: #B71C1C; } "
            "QPushButton:pressed { background-color: #9A0007; }"
        )
        self.btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_close)
        btn_layout.addStretch()
        main_layout.addLayout(btn_layout)

