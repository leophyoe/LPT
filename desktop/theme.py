"""Centralized Theme System for CyberSecuritySuite.

Provides a complete application-wide Dark Mode and Light Mode theme system:
- Centralized Design Tokens (Dark and Light modes)
- Professional Security Red accent (#D32F2F / #B71C1C)
- Accessible WCAG-compliant contrast for all controls, tables, dialogs, and badges
- Dynamic runtime theme switching via ThemeManager without restarting
- Persistence of user theme preference
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QApplication, QWidget

logger = logging.getLogger(__name__)

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
CHECKMARK_ICON_PATH = (ASSETS_DIR / "checkmark.png").as_posix()
RADIO_DOT_ICON_PATH = (ASSETS_DIR / "radio_dot.png").as_posix()


class ThemeMode(str, Enum):
    """Supported application theme modes."""
    DARK = "dark"
    LIGHT = "light"


@dataclass
class ThemeTokens:
    """Color and typography design tokens for a theme mode."""
    mode: ThemeMode

    # Accent colors
    accent_red: str = "#D32F2F"
    accent_hover: str = "#B71C1C"
    accent_pressed: str = "#9A0007"
    accent_subtle: str = "rgba(211, 47, 47, 0.12)"

    # Foundation backgrounds
    app_bg: str = "#15171C"
    surface_bg: str = "#20232B"
    sidebar_bg: str = "#1A1D24"
    elevated_bg: str = "#262A34"
    card_bg: str = "#20232B"
    card_hover_bg: str = "#2B303C"
    input_bg: str = "#181A20"
    terminal_bg: str = "#0F1014"

    # Text colors
    primary_text: str = "#F3F4F6"
    secondary_text: str = "#A7ADB8"
    muted_text: str = "#8B95A3"
    inactive_text: str = "#8B95A3"

    # Borders & Dividers
    border: str = "#2B303C"
    border_subtle: str = "#1E2128"
    border_focus: str = "#D32F2F"
    border_light: str = "#3A4150"

    # Tables & Lists
    table_header_bg: str = "#1A1D24"
    table_alt_row: str = "#1C1F27"
    table_selected_bg: str = "#2D3341"

    # Scrollbars
    scrollbar_bg: str = "#15171C"
    scrollbar_handle: str = "#373E4D"
    scrollbar_handle_hover: str = "#4B5563"

    # Canvas & Network Map
    canvas_bg: str = "#15171C"
    canvas_grid_minor: str = "#1E2128"
    canvas_grid_major: str = "#2B303C"

    # Semantic Severity Colors (Distinct and meaningful)
    severity_critical: str = "#FF6B72"
    severity_high: str = "#FF9F5A"
    severity_medium: str = "#FFD166"
    severity_low: str = "#63B3ED"
    severity_informational: str = "#A7ADB8"

    # Semantic Status Colors
    status_success: str = "#4ADE80"
    status_warning: str = "#FFD166"
    status_error: str = "#FF6B72"
    status_info: str = "#63B3ED"
    status_observed: str = "#60A5FA"
    status_muted: str = "#8B95A3"

    # Professional Dark Extensions
    primary_blue: str = "#2563EB"
    cyber_cyan: str = "#06B6D4"


# Design A — Professional Dark Tokens (Enterprise Theme)
PROFESSIONAL_DARK_TOKENS = ThemeTokens(
    mode=ThemeMode.DARK,
    accent_red="#EF4444",
    accent_hover="#DC2626",
    accent_pressed="#B91C1C",
    accent_subtle="rgba(239, 68, 68, 0.16)",

    app_bg="#101827",
    surface_bg="#1E293B",
    sidebar_bg="#0F172A",
    elevated_bg="#1E293B",
    card_bg="#1E293B",
    card_hover_bg="#334155",
    input_bg="#0F172A",
    terminal_bg="#080C14",

    primary_text="#F8FAFC",
    secondary_text="#94A3B8",
    muted_text="#64748B",
    inactive_text="#64748B",

    border="#334155",
    border_subtle="#1E293B",
    border_focus="#2563EB",
    border_light="#475569",

    table_header_bg="#0F172A",
    table_alt_row="#131D2E",
    table_selected_bg="#1E3A8A",

    scrollbar_bg="#101827",
    scrollbar_handle="#334155",
    scrollbar_handle_hover="#475569",

    canvas_bg="#080C14",
    canvas_grid_minor="#111827",
    canvas_grid_major="#1E293B",

    severity_critical="#EF4444",
    severity_high="#F97316",
    severity_medium="#EAB308",
    severity_low="#22C55E",
    severity_informational="#38BDF8",

    status_success="#22C55E",
    status_warning="#EAB308",
    status_error="#EF4444",
    status_info="#38BDF8",
    status_observed="#06B6D4",
    status_muted="#64748B",

    primary_blue="#2563EB",
    cyber_cyan="#06B6D4",
)


# Default Dark Mode Design Tokens
DARK_TOKENS = ThemeTokens(
    mode=ThemeMode.DARK,
    accent_red="#D32F2F",
    accent_hover="#B71C1C",
    accent_pressed="#9A0007",
    accent_subtle="rgba(211, 47, 47, 0.16)",

    app_bg="#15171C",
    surface_bg="#20232B",
    sidebar_bg="#1A1D24",
    elevated_bg="#262A34",
    card_bg="#20232B",
    card_hover_bg="#2B303C",
    input_bg="#181A20",
    terminal_bg="#0F1014",

    primary_text="#F3F4F6",
    secondary_text="#A7ADB8",
    muted_text="#8B95A3",
    inactive_text="#8B95A3",

    border="#2B303C",
    border_subtle="#1E2128",
    border_focus="#D32F2F",
    border_light="#3A4150",

    table_header_bg="#1A1D24",
    table_alt_row="#1C1F27",
    table_selected_bg="#2D3341",

    scrollbar_bg="#15171C",
    scrollbar_handle="#373E4D",
    scrollbar_handle_hover="#4B5563",

    canvas_bg="#15171C",
    canvas_grid_minor="#1E2128",
    canvas_grid_major="#2B303C",

    severity_critical="#FF6B72",
    severity_high="#FF9F5A",
    severity_medium="#FFD166",
    severity_low="#63B3ED",
    severity_informational="#A7ADB8",

    status_success="#4ADE80",
    status_warning="#FFD166",
    status_error="#FF6B72",
    status_info="#63B3ED",
    status_observed="#60A5FA",
    status_muted="#8B95A3",
)

# Default Light Mode Design Tokens
LIGHT_TOKENS = ThemeTokens(
    mode=ThemeMode.LIGHT,
    accent_red="#B42318",
    accent_hover="#912018",
    accent_pressed="#7A271A",
    accent_subtle="rgba(180, 35, 24, 0.08)",

    app_bg="#F1F4F7",
    surface_bg="#FFFFFF",
    sidebar_bg="#E8EDF2",
    elevated_bg="#E9EEF4",
    card_bg="#FFFFFF",
    card_hover_bg="#E6ECF3",
    input_bg="#FFFFFF",
    terminal_bg="#14171E",  # Dark console contrast keeps terminal output readable in light mode

    primary_text="#182230",
    secondary_text="#455363",
    muted_text="#5F6B7A",
    inactive_text="#5F6B7A",

    border="#C7D0DA",
    border_subtle="#DCE3EA",
    border_focus="#B42318",
    border_light="#B4C0CC",

    table_header_bg="#E8EDF2",
    table_alt_row="#F5F7F9",
    table_selected_bg="#DCE6F0",

    scrollbar_bg="#F1F4F7",
    scrollbar_handle="#B4C0CC",
    scrollbar_handle_hover="#8997A7",

    canvas_bg="#F1F4F7",
    canvas_grid_minor="#DCE3EA",
    canvas_grid_major="#C7D0DA",

    severity_critical="#C5221F",
    severity_high="#B9380A",
    severity_medium="#A84408",
    severity_low="#0369A1",
    severity_informational="#475569",

    status_success="#166534",
    status_warning="#A84408",
    status_error="#C5221F",
    status_info="#0369A1",
    status_observed="#1D4ED8",
    status_muted="#526071",
)


class CPENTTheme:
    """Centralized color and styling tokens for backward compatibility and static references."""

    # Primary & Foundation Colors
    PRIMARY_BLUE = "#2680FF"
    DEEP_NAVY = "#00148F"

    # Active Design Tokens
    APP_BG = DARK_TOKENS.app_bg
    SIDEBAR_BG = DARK_TOKENS.sidebar_bg
    PANEL_BG = DARK_TOKENS.surface_bg
    ELEVATED_PANEL = DARK_TOKENS.elevated_bg
    CARD_BG = DARK_TOKENS.card_bg
    CARD_HOVER_BG = DARK_TOKENS.card_hover_bg
    INPUT_BG = DARK_TOKENS.input_bg
    TERMINAL_BG = DARK_TOKENS.terminal_bg

    PRIMARY_TEXT = DARK_TOKENS.primary_text
    SECONDARY_TEXT = DARK_TOKENS.secondary_text
    MUTED_TEXT = DARK_TOKENS.muted_text
    INACTIVE_TEXT = DARK_TOKENS.inactive_text

    BORDER = DARK_TOKENS.border
    BORDER_SUBTLE = DARK_TOKENS.border_subtle
    BORDER_FOCUS = DARK_TOKENS.border_focus
    BORDER_LIGHT = DARK_TOKENS.border_light

    RED_ACCENT = DARK_TOKENS.accent_red
    ACCENT_RED = DARK_TOKENS.accent_red
    ACCENT_HOVER = DARK_TOKENS.accent_hover
    AMBER_ACCENT = "#FFBF00"
    WARNING_AMBER = "#FFBF00"
    SUCCESS_GREEN = "#22C55E"
    ERROR_RED = "#EF4444"
    INFO_CYAN = "#38BDF8"
    MUTED_GRAY = "#4D4D4D"

    # Specific Light Tokens for Reference
    LIGHT_APP_BG = LIGHT_TOKENS.app_bg
    LIGHT_SURFACE = LIGHT_TOKENS.surface_bg
    LIGHT_PRIMARY_TEXT = LIGHT_TOKENS.primary_text
    LIGHT_SECONDARY_TEXT = LIGHT_TOKENS.secondary_text
    LIGHT_BORDER = LIGHT_TOKENS.border

    # Typography Font Stacks (High-Legibility & Burmese Inclusivity Standard)
    FONT_FAMILY_HEADING = "'Inter', 'Noto Sans', 'Noto Sans Myanmar', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    FONT_FAMILY_BODY = "'Inter', 'Noto Sans', 'Noto Sans Myanmar', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Ubuntu, sans-serif"
    FONT_FAMILY_MONO = "'JetBrains Mono', 'Fira Code', 'Noto Sans Mono', 'Ubuntu Mono', 'DejaVu Sans Mono', Consolas, monospace"


def get_ui_font(size: int = 12, bold: bool = False, heading: bool = False, mono: bool = False) -> QFont:
    """Returns a standard, high-legibility QFont with verified font fallbacks for English and Burmese."""
    font = QFont()
    if mono:
        font.setFamilies([
            "JetBrains Mono",
            "Fira Code",
            "Noto Sans Mono",
            "Ubuntu Mono",
            "DejaVu Sans Mono",
            "monospace",
        ])
    elif heading:
        font.setFamilies([
            "Inter",
            "Noto Sans",
            "Noto Sans Myanmar",
            "Ubuntu",
            "DejaVu Sans",
            "sans-serif",
        ])
        font.setWeight(QFont.Weight.DemiBold if not bold else QFont.Weight.Bold)
    else:
        font.setFamilies([
            "Inter",
            "Noto Sans",
            "Noto Sans Myanmar",
            "Ubuntu",
            "DejaVu Sans",
            "sans-serif",
        ])
        if bold:
            font.setWeight(QFont.Weight.Bold)
    font.setPointSize(size)
    return font


# QColor instances for programmatic canvas drawing
COLOR_PRIMARY_BLUE = QColor(CPENTTheme.PRIMARY_BLUE)
COLOR_DEEP_NAVY = QColor(CPENTTheme.DEEP_NAVY)
COLOR_APP_BG = QColor(CPENTTheme.APP_BG)
COLOR_PANEL_BG = QColor(CPENTTheme.PANEL_BG)
COLOR_ELEVATED_PANEL = QColor(CPENTTheme.ELEVATED_PANEL)
COLOR_PRIMARY_TEXT = QColor(CPENTTheme.PRIMARY_TEXT)
COLOR_SECONDARY_TEXT = QColor(CPENTTheme.SECONDARY_TEXT)
COLOR_BORDER = QColor(CPENTTheme.BORDER)
COLOR_BORDER_SUBTLE = QColor(CPENTTheme.BORDER_SUBTLE)
COLOR_RED_ACCENT = QColor(CPENTTheme.RED_ACCENT)
COLOR_AMBER_ACCENT = QColor(CPENTTheme.AMBER_ACCENT)
COLOR_SUCCESS_GREEN = QColor(CPENTTheme.SUCCESS_GREEN)
COLOR_ERROR_RED = QColor(CPENTTheme.ERROR_RED)
COLOR_MUTED_GRAY = QColor(CPENTTheme.MUTED_GRAY)

# Semantic Severity Color Palette
SEVERITY_COLORS_HEX: Dict[str, str] = {
    "CRITICAL": DARK_TOKENS.severity_critical,
    "HIGH": DARK_TOKENS.severity_high,
    "MEDIUM": DARK_TOKENS.severity_medium,
    "LOW": DARK_TOKENS.severity_low,
    "INFORMATIONAL": DARK_TOKENS.severity_informational,
}

SEVERITY_QCOLORS: Dict[str, QColor] = {
    "CRITICAL": QColor(DARK_TOKENS.severity_critical),
    "HIGH": QColor(DARK_TOKENS.severity_high),
    "MEDIUM": QColor(DARK_TOKENS.severity_medium),
    "LOW": QColor(DARK_TOKENS.severity_low),
    "INFORMATIONAL": QColor(DARK_TOKENS.severity_informational),
}

# Validation Status Color Palette
VALIDATION_COLORS_HEX: Dict[str, str] = {
    "CONFIRMED": DARK_TOKENS.status_success,
    "OBSERVED": DARK_TOKENS.status_observed,
    "NEEDS_VALIDATION": DARK_TOKENS.status_warning,
    "UNVERIFIED": DARK_TOKENS.secondary_text,
    "FALSE_POSITIVE": DARK_TOKENS.muted_text,
}

# Execution Status Colors
EXECUTION_COLORS_HEX: Dict[str, str] = {
    "PASSED": DARK_TOKENS.status_success,
    "FAILED": DARK_TOKENS.status_error,
    "BLOCKED": "#F87171",
    "RUNNING": DARK_TOKENS.status_observed,
    "PENDING": DARK_TOKENS.secondary_text,
    "ERROR": DARK_TOKENS.status_error,
    "CANCELLED": DARK_TOKENS.muted_text,
    "NEEDS_REVIEW": DARK_TOKENS.status_warning,
}


def get_badge_qss(status_or_severity: str, mode: Optional[Union[ThemeMode, str]] = None) -> str:
    """Returns a standardized compact pill badge stylesheet for a given status or severity code."""
    token = status_or_severity.strip().upper().replace(" ", "_").replace("-", "_")
    target_mode = ThemeMode(mode) if mode else ThemeManager.instance().current_mode
    is_dark = target_mode == ThemeMode.DARK

    if token in ("CRITICAL", "FAILED", "ERROR"):
        bg = "#3D1014" if is_dark else "#FEE2E2"
        fg = "#EF4444" if is_dark else "#B91C1C"
        border = "#D91F26" if is_dark else "#F87171"
    elif token in ("HIGH",):
        bg = "#382010" if is_dark else "#FFEDD5"
        fg = "#F97316" if is_dark else "#C2410C"
        border = "#EA580C" if is_dark else "#FB923C"
    elif token in ("MEDIUM", "NEEDS_VALIDATION", "NEEDS_REVIEW", "WARNING"):
        bg = "#383010" if is_dark else "#FEF3C7"
        fg = "#FFBF00" if is_dark else "#B45309"
        border = "#CA8A04" if is_dark else "#FBBF24"
    elif token in ("LOW", "INFO_CYAN"):
        bg = "#10243D" if is_dark else "#E0F2FE"
        fg = "#38BDF8" if is_dark else "#0369A1"
        border = "#0284C7" if is_dark else "#38BDF8"
    elif token in ("PASSED", "CONFIRMED", "VERIFIED", "SUCCESS", "READY", "ACTIVE"):
        bg = "#0E3320" if is_dark else "#DCFCE7"
        fg = "#22C55E" if is_dark else "#15803D"
        border = "#16A34A" if is_dark else "#4ADE80"
    elif token in ("OBSERVED", "RUNNING"):
        bg = "#152742" if is_dark else "#DBEAFE"
        fg = "#60A5FA" if is_dark else "#1D4ED8"
        border = "#2563EB" if is_dark else "#60A5FA"
    elif token in ("BLOCKED",):
        bg = "#2B1D20" if is_dark else "#FEE2E2"
        fg = "#F87171" if is_dark else "#B91C1C"
        border = "#991B1B" if is_dark else "#F87171"
    else:  # INFORMATIONAL, UNVERIFIED, FALSE_POSITIVE, PENDING, CANCELLED
        bg = "#151F30" if is_dark else "#F1F5F9"
        fg = "#A8B3C7" if is_dark else "#475569"
        border = "#2B394D" if is_dark else "#CBD5E1"

    return (
        f"background-color: {bg}; color: {fg}; border: 1px solid {border}; "
        f"border-radius: 4px; font-weight: bold; font-size: 11px; padding: 2px 7px;"
    )


def generate_stylesheet(tokens: ThemeTokens) -> str:
    """Generates a complete, comprehensive Qt stylesheet for the specified theme tokens."""
    is_dark = tokens.mode == ThemeMode.DARK

    # Terminal foreground contrast: dark console in both modes maintains high readability
    terminal_fg = tokens.primary_text if is_dark else "#F3F4F6"

    return f"""
/* ==========================================================================
   CyberSecuritySuite — {tokens.mode.value.upper()} THEME STYLESHEET
   ========================================================================== */

QMainWindow, QDialog {{
    background-color: {tokens.app_bg};
    color: {tokens.primary_text};
}}

QWidget {{
    font-family: {CPENTTheme.FONT_FAMILY_BODY};
    font-size: 13px;
    color: {tokens.primary_text};
}}

/* Tooltips */
QToolTip {{
    background-color: {tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 5px 8px;
    font-size: 11px;
}}

/* ==========================================================================
   Navigation Sidebar
   ========================================================================== */
#sidebar {{
    background-color: {tokens.sidebar_bg};
    border-right: 1px solid {tokens.border};
    min-width: 228px;
    max-width: 240px;
}}

#sidebar QLabel#appTitle {{
    color: {tokens.primary_text};
    font-family: {CPENTTheme.FONT_FAMILY_HEADING};
    font-size: 16px;
    font-weight: 700;
    padding: 14px 10px 2px 10px;
    letter-spacing: 0.3px;
}}

#sidebar QLabel#appSubtitle {{
    color: {tokens.secondary_text};
    font-size: 10px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 0px 14px 12px 14px;
    border-bottom: 1px solid {tokens.border_subtle};
    margin-bottom: 8px;
}}

QPushButton.nav-btn {{
    background-color: transparent;
    color: {tokens.secondary_text};
    border: 1px solid transparent;
    border-radius: 5px;
    padding: 9px 12px;
    text-align: left;
    font-weight: 500;
    font-size: 13px;
}}

QPushButton.nav-btn:hover {{
    background-color: {tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
}}

QPushButton.nav-btn:checked {{
    background-color: {tokens.elevated_bg};
    border: 1px solid {tokens.accent_red};
    border-left: 3px solid {tokens.accent_red};
    color: {tokens.primary_text};
    font-weight: 600;
}}

/* ==========================================================================
   Buttons
   ========================================================================== */
QPushButton {{
    background-color: {tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 6px 12px;
    font-weight: 500;
    font-size: 13px;
}}

QPushButton:hover {{
    background-color: {tokens.card_hover_bg};
    border-color: {tokens.border_focus};
    color: {tokens.primary_text};
}}

QPushButton:pressed {{
    background-color: {tokens.surface_bg};
}}

QPushButton:disabled {{
    background-color: {tokens.surface_bg};
    color: {tokens.inactive_text};
    border-color: {tokens.border_subtle};
}}

QPushButton.action-primary,
QPushButton[class="action-primary"] {{
    background-color: {"#2563EB" if is_dark else tokens.accent_red};
    color: #FFFFFF;
    border: 1px solid {"#3B82F6" if is_dark else tokens.accent_hover};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}}

QPushButton.action-primary:hover,
QPushButton[class="action-primary"]:hover {{
    background-color: {"#1D4ED8" if is_dark else tokens.accent_hover};
    border-color: {"#60A5FA" if is_dark else tokens.accent_pressed};
    color: #FFFFFF;
}}

QPushButton.action-secondary,
QPushButton[class="action-secondary"] {{
    background-color: {"#1E293B" if is_dark else tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {"#334155" if is_dark else tokens.border};
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 500;
}}

QPushButton.action-secondary:hover,
QPushButton[class="action-secondary"]:hover {{
    background-color: {"#334155" if is_dark else tokens.card_hover_bg};
    border-color: {"#475569" if is_dark else tokens.border_focus};
    color: #FFFFFF;
}}

QPushButton.action-destructive,
QPushButton[class="action-destructive"] {{
    background-color: #991B1B;
    color: #FFFFFF;
    border: 1px solid #7F1D1D;
    font-weight: 600;
}}

QPushButton.action-destructive:hover,
QPushButton[class="action-destructive"]:hover {{
    background-color: #B91C1C;
    border-color: #991B1B;
}}

QPushButton.action-ghost,
QPushButton[class="action-ghost"] {{
    background-color: transparent;
    color: {tokens.accent_red};
    border: 1px solid transparent;
}}

QPushButton.action-ghost:hover,
QPushButton[class="action-ghost"]:hover {{
    background-color: {tokens.elevated_bg};
    border: 1px solid {tokens.border};
}}

/* ==========================================================================
   Inputs, Text Edits, Combos
   ========================================================================== */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QSpinBox {{
    background-color: {tokens.input_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 6px 8px;
    font-size: 13px;
    selection-background-color: {tokens.accent_red};
    selection-color: #FFFFFF;
}}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus {{
    border: 1px solid {tokens.border_focus};
}}

QLineEdit::placeholder, QTextEdit::placeholder, QPlainTextEdit::placeholder {{
    color: {tokens.muted_text};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid {tokens.border_subtle};
}}

QComboBox QAbstractItemView {{
    background-color: {tokens.surface_bg};
    border: 1px solid {tokens.border};
    selection-background-color: {tokens.table_selected_bg};
    selection-color: {tokens.primary_text};
    color: {tokens.primary_text};
    padding: 4px;
}}

/* Checkboxes and Radios */
QCheckBox, QRadioButton {{
    color: {tokens.primary_text};
    spacing: 6px;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {"#334155" if is_dark else tokens.border};
    border-radius: 3px;
    background-color: {"#0F172A" if is_dark else tokens.input_bg};
}}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: {"#2563EB" if is_dark else tokens.border_focus};
}}

QCheckBox::indicator:checked {{
    background-color: {"#2563EB" if is_dark else tokens.accent_red};
    border-color: {"#3B82F6" if is_dark else tokens.accent_red};
    image: url("{CHECKMARK_ICON_PATH}");
}}

QRadioButton::indicator:checked {{
    background-color: {"#2563EB" if is_dark else tokens.accent_red};
    border-color: {"#3B82F6" if is_dark else tokens.accent_red};
    image: url("{RADIO_DOT_ICON_PATH}");
}}

/* Group Boxes */
QGroupBox {{
    border: 1px solid {tokens.border};
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 10px;
    background-color: {tokens.surface_bg};
    font-weight: 600;
    color: {tokens.primary_text};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 6px;
    color: {tokens.primary_text};
    font-weight: 700;
}}

/* ==========================================================================
   Tables & Headers (Behind24 / Modern Cyber Console High-Density Standard)
   ========================================================================== */
QTableWidget, QTableView {{
    background-color: {"#0B0F19" if is_dark else tokens.surface_bg};
    alternate-background-color: {"#111827" if is_dark else tokens.table_alt_row};
    gridline-color: {"#1E293B" if is_dark else tokens.border_subtle};
    border: 1px solid {"#1E293B" if is_dark else tokens.border};
    border-radius: 6px;
    color: {tokens.primary_text};
    selection-background-color: {"#1E3A8A" if is_dark else tokens.table_selected_bg};
    selection-color: {tokens.primary_text};
}}

QHeaderView::section {{
    background-color: {"#0F172A" if is_dark else tokens.table_header_bg};
    color: {"#94A3B8" if is_dark else tokens.secondary_text};
    border: none;
    border-bottom: 1px solid {"#1E293B" if is_dark else tokens.border};
    border-right: 1px solid {"#1E293B" if is_dark else tokens.border_subtle};
    padding: 8px 12px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QTableCornerButton::section {{
    background-color: {"#0F172A" if is_dark else tokens.table_header_bg};
    border: none;
    border-bottom: 1px solid {"#1E293B" if is_dark else tokens.border};
    border-right: 1px solid {"#1E293B" if is_dark else tokens.border};
}}

/* ==========================================================================
   Tabs
   ========================================================================== */
QTabWidget::pane {{
    border: 1px solid {tokens.border};
    background-color: {tokens.surface_bg};
    top: -1px;
    border-radius: 0 0 6px 6px;
}}

QTabBar::tab {{
    background-color: {"#111827" if is_dark else tokens.elevated_bg};
    color: {tokens.secondary_text};
    border: 1px solid {"#1E293B" if is_dark else tokens.border};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 7px 16px;
    margin-right: 3px;
    font-weight: 500;
    font-size: 12px;
}}

QTabBar::tab:hover {{
    background-color: {"#1E293B" if is_dark else tokens.card_hover_bg};
    color: {tokens.primary_text};
}}

QTabBar::tab:selected {{
    background-color: {tokens.surface_bg};
    color: {"#38BDF8" if is_dark else tokens.primary_text};
    border-bottom: 2px solid {"#2563EB" if is_dark else tokens.accent_red};
    border-top: 2px solid {"#3B82F6" if is_dark else tokens.accent_red};
    font-weight: 600;
}}

/* ==========================================================================
   Scrollbars
   ========================================================================== */
QScrollBar:vertical {{
    background: {tokens.scrollbar_bg};
    width: 12px;
    margin: 0px;
    border-radius: 6px;
    border: 1px solid {tokens.border_subtle};
}}

QScrollBar::handle:vertical {{
    background: {tokens.scrollbar_handle};
    min-height: 28px;
    border-radius: 5px;
    margin: 1px;
}}

QScrollBar::handle:vertical:hover {{
    background: {tokens.scrollbar_handle_hover};
}}

QScrollBar:horizontal {{
    background: {tokens.scrollbar_bg};
    height: 12px;
    margin: 0px;
    border-radius: 6px;
    border: 1px solid {tokens.border_subtle};
}}

QScrollBar::handle:horizontal {{
    background: {tokens.scrollbar_handle};
    min-width: 28px;
    border-radius: 5px;
    margin: 1px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {tokens.scrollbar_handle_hover};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    border: none;
    background: none;
}}

/* ==========================================================================
   Splitters
   ========================================================================== */
QSplitter#workspaceSplitter::handle:vertical,
QSplitter::handle:vertical {{
    background-color: {tokens.border};
    height: 10px;
    margin: 1px 0px;
    border-top: 1px solid {tokens.border_subtle};
    border-bottom: 1px solid {tokens.border_subtle};
    border-radius: 2px;
}}

QSplitter#workspaceSplitter::handle:vertical:hover,
QSplitter::handle:vertical:hover {{
    background-color: {tokens.accent_red};
    height: 10px;
}}

QSplitter::handle:horizontal {{
    background-color: {tokens.border_subtle};
    width: 6px;
}}

QSplitter::handle:horizontal:hover {{
    background-color: {tokens.accent_red};
}}

/* ERP Dashboard Cards */
QFrame#erpCtrlCard,
QFrame#erpMetricCard,
QFrame#erpGridCard {{
    background-color: {tokens.surface_bg};
    border: 1px solid {tokens.border};
    border-radius: 6px;
}}

#rightAIPanel {{
    background-color: {tokens.surface_bg};
    border-left: 1px solid {tokens.border};
}}

#aiChatDisplay {{
    background-color: {tokens.surface_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 6px;
    padding: 10px;
}}

#aiChatInput {{
    background-color: {tokens.input_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 6px;
    padding: 8px;
}}

#aiChatInput:focus {{
    border: 1px solid {tokens.accent_red};
}}

QPushButton.quick-chip {{
    background-color: {tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 13px;
    font-size: 11px;
    font-weight: 500;
    padding: 2px 10px;
}}

QPushButton.quick-chip:hover {{
    background-color: {tokens.accent_red};
    color: #FFFFFF;
    border-color: {tokens.accent_red};
}}

#commandsShelf {{
    background-color: {tokens.elevated_bg};
    border: 1px solid {tokens.border};
    border-radius: 6px;
    padding: 6px;
}}

QPushButton.action-chip {{
    background-color: {tokens.input_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 3px 8px;
    font-family: {CPENTTheme.FONT_FAMILY_MONO};
    font-size: 11px;
}}

QPushButton.action-chip:hover {{
    border-color: {tokens.accent_red};
    color: {tokens.accent_red};
}}

/* ==========================================================================
   Terminal View & Shell
   ========================================================================== */
#terminalView {{
    background-color: {tokens.terminal_bg};
    color: {terminal_fg};
    font-family: {CPENTTheme.FONT_FAMILY_MONO};
    font-size: 12px;
    border: 1px solid {tokens.border};
    border-radius: 4px;
}}

#terminalHeader {{
    background-color: {tokens.surface_bg};
    border-top: 1px solid {tokens.border};
    border-left: 1px solid {tokens.border};
    border-right: 1px solid {tokens.border};
    border-bottom: 1px solid {tokens.border_subtle};
}}

QPushButton#expandTerminalButton {{
    background-color: {tokens.elevated_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
}}

QPushButton#expandTerminalButton:hover {{
    background-color: {tokens.card_hover_bg};
    border-color: {tokens.border_focus};
}}

/* ==========================================================================
   Status Bar
   ========================================================================== */
QStatusBar {{
    background-color: {tokens.sidebar_bg};
    color: {tokens.secondary_text};
    border-top: 1px solid {tokens.border};
    font-size: 11px;
    padding: 3px 12px;
}}

QStatusBar QLabel {{
    color: {tokens.secondary_text};
    padding: 2px 8px;
}}

/* ==========================================================================
   Menus & Dialogs
   ========================================================================== */
QMenu {{
    background-color: {tokens.surface_bg};
    color: {tokens.primary_text};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 16px;
    border-radius: 3px;
}}

QMenu::item:selected {{
    background-color: {tokens.table_selected_bg};
    color: {tokens.primary_text};
}}

/* ==========================================================================
   Dashboard & Analytics Styling
   ========================================================================== */
#dashboardView {{
    background-color: {tokens.app_bg};
}}

QLabel#dashTitle {{
    font-family: {CPENTTheme.FONT_FAMILY_HEADING};
    font-size: 20px;
    font-weight: 700;
    color: {tokens.primary_text};
}}

QLabel#dashSubtitle {{
    color: {tokens.secondary_text};
    font-size: 12px;
}}

QLabel#projectBadge {{
    background: {tokens.elevated_bg};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    padding: 4px 10px;
    color: {tokens.accent_red};
    font-weight: 600;
    font-size: 11px;
}}

QFrame#metricCard, QFrame#dashboardPanel {{
    background: {tokens.surface_bg};
    border: 1px solid {tokens.border};
    border-radius: 6px;
}}

QFrame#metricCard:hover {{
    border: 1px solid {tokens.accent_red};
}}

QLabel#metricName {{
    color: {tokens.secondary_text};
    font-size: 11px;
    text-transform: uppercase;
}}

QLabel#metricValue {{
    color: {tokens.primary_text};
    font-size: 22px;
    font-weight: 700;
}}

QLabel#panelTitle {{
    color: {tokens.primary_text};
    font-weight: 700;
    font-size: 13px;
}}

QLabel#viewHeader, QLabel.view-header {{
    font-size: 18px;
    font-weight: 700;
    color: {tokens.primary_text};
    font-family: {CPENTTheme.FONT_FAMILY_HEADING};
}}

QLabel#viewSubtitle, QLabel.view-subtitle {{
    font-size: 12px;
    color: {tokens.secondary_text};
}}

QLabel#sectionTitle, QLabel.section-title {{
    font-size: 12px;
    font-weight: 700;
    color: {tokens.primary_text};
    font-family: {CPENTTheme.FONT_FAMILY_HEADING};
}}

QLabel#severityLabel {{
    color: {tokens.secondary_text};
    font-size: 12px;
}}

QFrame#listRow {{
    background: transparent;
    border-bottom: 1px solid {tokens.border_subtle};
}}

QFrame#listRow:hover {{
    background: {tokens.elevated_bg};
    border-radius: 4px;
}}

QLabel#rowText {{
    color: {tokens.primary_text};
}}

QLabel#emptyState {{
    color: {tokens.muted_text};
    font-style: italic;
}}

QProgressBar {{
    background-color: {tokens.elevated_bg};
    border: 1px solid {tokens.border};
    border-radius: 4px;
    text-align: center;
    color: {tokens.primary_text};
}}

QProgressBar::chunk {{
    background-color: {tokens.accent_red};
    border-radius: 3px;
}}

/* ==========================================================================
   Badges
   ========================================================================== */
QLabel.badge-critical {{
    background-color: {"#3D1014" if is_dark else "#FEE2E2"};
    color: {"#EF4444" if is_dark else "#B91C1C"};
    border: 1px solid {"#D91F26" if is_dark else "#F87171"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-high {{
    background-color: {"#382010" if is_dark else "#FFEDD5"};
    color: {"#F97316" if is_dark else "#C2410C"};
    border: 1px solid {"#EA580C" if is_dark else "#FB923C"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-medium {{
    background-color: {"#383010" if is_dark else "#FEF3C7"};
    color: {"#FFBF00" if is_dark else "#B45309"};
    border: 1px solid {"#CA8A04" if is_dark else "#FBBF24"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-low {{
    background-color: {"#10243D" if is_dark else "#E0F2FE"};
    color: {"#38BDF8" if is_dark else "#0369A1"};
    border: 1px solid {"#0284C7" if is_dark else "#38BDF8"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-info {{
    background-color: {"#151F30" if is_dark else "#F1F5F9"};
    color: {"#A8B3C7" if is_dark else "#475569"};
    border: 1px solid {"#2B394D" if is_dark else "#CBD5E1"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 600;
    font-size: 11px;
}}

QLabel.badge-verified, QLabel.badge-passed {{
    background-color: {"#0E3320" if is_dark else "#DCFCE7"};
    color: {"#22C55E" if is_dark else "#15803D"};
    border: 1px solid {"#16A34A" if is_dark else "#4ADE80"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-failed, QLabel.badge-error {{
    background-color: {"#3D1014" if is_dark else "#FEE2E2"};
    color: {"#EF4444" if is_dark else "#B91C1C"};
    border: 1px solid {"#D91F26" if is_dark else "#F87171"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-blocked {{
    background-color: {"#2B1D20" if is_dark else "#FEE2E2"};
    color: {"#F87171" if is_dark else "#B91C1C"};
    border: 1px solid {"#991B1B" if is_dark else "#F87171"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-observed {{
    background-color: {"#152742" if is_dark else "#DBEAFE"};
    color: {"#60A5FA" if is_dark else "#1D4ED8"};
    border: 1px solid {"#2563EB" if is_dark else "#60A5FA"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}

QLabel.badge-needs-validation {{
    background-color: {"#383010" if is_dark else "#FEF3C7"};
    color: {"#FFBF00" if is_dark else "#B45309"};
    border: 1px solid {"#CA8A04" if is_dark else "#FBBF24"};
    border-radius: 4px;
    padding: 2px 7px;
    font-weight: 700;
    font-size: 11px;
}}
"""


# Pre-rendered stylesheets for static and quick access
DARK_THEME_QSS = generate_stylesheet(DARK_TOKENS)
LIGHT_THEME_QSS = generate_stylesheet(LIGHT_TOKENS)


class ThemeManager(QObject):
    """Centralized Theme Management service for CyberSecuritySuite.

    Controls theme switching between Dark and Light modes, generates stylesheets,
    updates color token singletons, and persists preferences.
    """

    theme_changed = Signal(str)  # Emits "dark" or "light"

    _instance: Optional[ThemeManager] = None

    def __init__(self, config_dir: Optional[Path] = None, config_path: Optional[Path] = None):
        super().__init__()
        if config_path is not None:
            self._config_file = Path(config_path)
        else:
            base_dir = config_dir or (Path(__file__).resolve().parent.parent / "storage" / "data")
            self._config_file = base_dir / "theme_preference.json"
        self._mode: ThemeMode = ThemeMode.DARK
        self._load_preference()

    @classmethod
    def instance(cls) -> ThemeManager:
        if cls._instance is None:
            cls._instance = ThemeManager()
        return cls._instance

    @property
    def current_mode(self) -> ThemeMode:
        return self._mode

    @property
    def mode(self) -> ThemeMode:
        return self._mode

    @property
    def is_dark(self) -> bool:
        return self._mode == ThemeMode.DARK

    @property
    def is_light(self) -> bool:
        return self._mode == ThemeMode.LIGHT

    def get_tokens(self, mode: Optional[Union[ThemeMode, str]] = None) -> ThemeTokens:
        """Returns the design tokens for the specified or current theme mode."""
        if mode is None:
            target_mode = self._mode
        elif isinstance(mode, ThemeMode):
            target_mode = mode
        else:
            target_mode = ThemeMode(str(mode).strip().lower())
        return LIGHT_TOKENS if target_mode == ThemeMode.LIGHT else DARK_TOKENS

    def get_stylesheet(self, mode: Optional[Union[ThemeMode, str]] = None) -> str:
        """Returns the complete QSS stylesheet for the specified or current theme mode."""
        tokens = self.get_tokens(mode)
        return generate_stylesheet(tokens)

    def set_theme_mode(self, mode: Union[ThemeMode, str], apply_to_app: bool = True) -> ThemeMode:
        """Sets the active theme mode, synchronizes global tokens, and optionally applies styling."""
        if isinstance(mode, ThemeMode):
            new_mode = mode
        else:
            new_mode = ThemeMode(str(mode).strip().lower())

        self._mode = new_mode
        tokens = self.get_tokens(new_mode)
        self._sync_global_tokens(tokens)
        self._save_preference()

        try:
            from desktop.icons import clear_cache as clear_icon_cache
            clear_icon_cache()
        except Exception:
            pass

        if apply_to_app:
            self.apply_theme()

        self.theme_changed.emit(new_mode.value)
        return new_mode

    def toggle_theme(self, apply_to_app: bool = True) -> ThemeMode:
        """Toggles between Dark and Light mode."""
        new_mode = ThemeMode.LIGHT if self._mode == ThemeMode.DARK else ThemeMode.DARK
        return self.set_theme_mode(new_mode, apply_to_app=apply_to_app)

    def apply_theme(self, target: Optional[QWidget] = None) -> None:
        """Applies the current theme stylesheet to the given widget or entire QApplication."""
        qss = self.get_stylesheet()
        if target is not None:
            target.setStyleSheet(qss)
        else:
            app = QApplication.instance()
            if app:
                app.setStyleSheet(qss)

    def _sync_global_tokens(self, tokens: ThemeTokens) -> None:
        """Synchronizes legacy and programmatic CPENTTheme constants with active theme."""
        CPENTTheme.APP_BG = tokens.app_bg
        CPENTTheme.PANEL_BG = tokens.surface_bg
        CPENTTheme.SIDEBAR_BG = tokens.sidebar_bg
        CPENTTheme.ELEVATED_PANEL = tokens.elevated_bg
        CPENTTheme.CARD_BG = tokens.card_bg
        CPENTTheme.CARD_HOVER_BG = tokens.card_hover_bg
        CPENTTheme.INPUT_BG = tokens.input_bg
        CPENTTheme.TERMINAL_BG = tokens.terminal_bg
        CPENTTheme.PRIMARY_TEXT = tokens.primary_text
        CPENTTheme.SECONDARY_TEXT = tokens.secondary_text
        CPENTTheme.MUTED_TEXT = tokens.muted_text
        CPENTTheme.BORDER = tokens.border
        CPENTTheme.BORDER_SUBTLE = tokens.border_subtle
        CPENTTheme.BORDER_LIGHT = tokens.border_light
        CPENTTheme.BORDER_FOCUS = tokens.border_focus
        CPENTTheme.RED_ACCENT = tokens.accent_red
        CPENTTheme.SUCCESS_GREEN = tokens.status_success
        CPENTTheme.ERROR_RED = tokens.status_error
        CPENTTheme.AMBER_ACCENT = tokens.status_warning
        CPENTTheme.WARNING_AMBER = tokens.status_warning
        CPENTTheme.INFO_CYAN = tokens.status_info
        CPENTTheme.MUTED_GRAY = tokens.status_muted

        SEVERITY_COLORS_HEX.update({
            "CRITICAL": tokens.severity_critical,
            "HIGH": tokens.severity_high,
            "MEDIUM": tokens.severity_medium,
            "LOW": tokens.severity_low,
            "INFORMATIONAL": tokens.severity_informational,
        })
        SEVERITY_QCOLORS.update({
            name: QColor(color) for name, color in SEVERITY_COLORS_HEX.items()
        })
        VALIDATION_COLORS_HEX.update({
            "CONFIRMED": tokens.status_success,
            "OBSERVED": tokens.status_observed,
            "NEEDS_VALIDATION": tokens.status_warning,
            "UNVERIFIED": tokens.secondary_text,
            "FALSE_POSITIVE": tokens.status_muted,
        })
        EXECUTION_COLORS_HEX.update({
            "PASSED": tokens.status_success,
            "FAILED": tokens.status_error,
            "BLOCKED": "#F87171" if tokens.mode == ThemeMode.DARK else "#B91C1C",
            "RUNNING": tokens.status_observed,
            "PENDING": tokens.secondary_text,
            "ERROR": tokens.status_error,
            "CANCELLED": tokens.status_muted,
            "NEEDS_REVIEW": tokens.status_warning,
        })

        global COLOR_APP_BG, COLOR_PANEL_BG, COLOR_ELEVATED_PANEL
        global COLOR_PRIMARY_TEXT, COLOR_SECONDARY_TEXT, COLOR_BORDER
        global COLOR_BORDER_SUBTLE, COLOR_RED_ACCENT, COLOR_AMBER_ACCENT
        global COLOR_SUCCESS_GREEN, COLOR_ERROR_RED, COLOR_MUTED_GRAY

        COLOR_APP_BG = QColor(tokens.app_bg)
        COLOR_PANEL_BG = QColor(tokens.surface_bg)
        COLOR_ELEVATED_PANEL = QColor(tokens.elevated_bg)
        COLOR_PRIMARY_TEXT = QColor(tokens.primary_text)
        COLOR_SECONDARY_TEXT = QColor(tokens.secondary_text)
        COLOR_BORDER = QColor(tokens.border)
        COLOR_BORDER_SUBTLE = QColor(tokens.border_subtle)
        COLOR_RED_ACCENT = QColor(tokens.accent_red)
        COLOR_AMBER_ACCENT = QColor(tokens.status_warning)
        COLOR_SUCCESS_GREEN = QColor(tokens.status_success)
        COLOR_ERROR_RED = QColor(tokens.status_error)
        COLOR_MUTED_GRAY = QColor(tokens.status_muted)

    def _load_preference(self) -> None:
        """Loads saved theme preference from local JSON file."""
        try:
            if self._config_file.is_file():
                data = json.loads(self._config_file.read_text(encoding="utf-8"))
                pref = data.get("theme", "dark")
                self._mode = ThemeMode(pref)
                self._sync_global_tokens(self.get_tokens(self._mode))
        except Exception as exc:
            logger.debug("Failed to read theme preference: %s", exc)
            self._mode = ThemeMode.DARK

    def _save_preference(self) -> None:
        """Saves current theme preference to local JSON file."""
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            self._config_file.write_text(
                json.dumps({"theme": self._mode.value, "updated_at": str(os.path.getmtime(__file__))}),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("Failed to write theme preference: %s", exc)
