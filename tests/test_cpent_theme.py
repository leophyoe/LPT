"""Comprehensive tests for CyberSecuritySuite Dark & Light Mode Theme System."""

import json
import re
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication

from desktop.theme import (
    CPENTTheme,
    DARK_THEME_QSS,
    DARK_TOKENS,
    LIGHT_THEME_QSS,
    LIGHT_TOKENS,
    SEVERITY_COLORS_HEX,
    SEVERITY_QCOLORS,
    VALIDATION_COLORS_HEX,
    EXECUTION_COLORS_HEX,
    ThemeManager,
    ThemeMode,
    ThemeTokens,
    generate_stylesheet,
    get_badge_qss,
)


def test_theme_tokens_specifications():
    """Verify dark and light tokens match the requested design specifications."""
    hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")

    # Dark Tokens Verification
    assert DARK_TOKENS.mode == ThemeMode.DARK
    assert DARK_TOKENS.accent_red == "#D32F2F"
    assert DARK_TOKENS.accent_hover == "#B71C1C"
    assert DARK_TOKENS.app_bg == "#15171C"
    assert DARK_TOKENS.surface_bg == "#20232B"
    assert DARK_TOKENS.primary_text == "#F3F4F6"
    assert DARK_TOKENS.secondary_text == "#A7ADB8"

    # Light Tokens Verification
    assert LIGHT_TOKENS.mode == ThemeMode.LIGHT
    assert LIGHT_TOKENS.accent_red == "#B42318"
    assert LIGHT_TOKENS.accent_hover == "#912018"
    assert LIGHT_TOKENS.app_bg == "#F1F4F7"
    assert LIGHT_TOKENS.surface_bg == "#FFFFFF"
    assert LIGHT_TOKENS.primary_text == "#182230"
    assert LIGHT_TOKENS.secondary_text == "#455363"
    assert LIGHT_TOKENS.border == "#C7D0DA"

    for token in [
        DARK_TOKENS.app_bg, DARK_TOKENS.surface_bg, DARK_TOKENS.accent_red,
        LIGHT_TOKENS.app_bg, LIGHT_TOKENS.surface_bg, LIGHT_TOKENS.border
    ]:
        assert hex_pattern.match(token)


def _contrast_ratio(foreground: str, background: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("tokens", [DARK_TOKENS, LIGHT_TOKENS], ids=["dark", "light"])
def test_normal_text_colors_meet_wcag_aa_contrast(tokens):
    """Normal-size text colors remain readable on primary, input, and sidebar surfaces."""
    for foreground in (
        tokens.secondary_text,
        tokens.muted_text,
        tokens.inactive_text,
        tokens.severity_critical,
        tokens.severity_high,
        tokens.severity_medium,
        tokens.severity_low,
        tokens.severity_informational,
        tokens.status_success,
        tokens.status_warning,
        tokens.status_error,
        tokens.status_info,
        tokens.status_observed,
        tokens.status_muted,
    ):
        for background in (tokens.surface_bg, tokens.input_bg, tokens.sidebar_bg):
            assert _contrast_ratio(foreground, background) >= 4.5, (
                f"{foreground} on {background} is below 4.5:1 in {tokens.mode.value} mode"
            )


def test_theme_switch_updates_semantic_text_colors(tmp_path):
    manager = ThemeManager(config_path=tmp_path / "theme.json")

    manager.set_theme_mode(ThemeMode.LIGHT, apply_to_app=False)
    assert SEVERITY_COLORS_HEX["CRITICAL"] == LIGHT_TOKENS.severity_critical
    assert SEVERITY_QCOLORS["CRITICAL"].name().upper() == LIGHT_TOKENS.severity_critical
    assert VALIDATION_COLORS_HEX["FALSE_POSITIVE"] == LIGHT_TOKENS.status_muted
    assert EXECUTION_COLORS_HEX["CANCELLED"] == LIGHT_TOKENS.status_muted
    assert CPENTTheme.SUCCESS_GREEN == LIGHT_TOKENS.status_success
    assert CPENTTheme.AMBER_ACCENT == LIGHT_TOKENS.status_warning

    manager.set_theme_mode(ThemeMode.DARK, apply_to_app=False)


def test_theme_manager_singleton_and_toggle(qapp):
    """Verify ThemeManager singleton, dynamic switching, and signal emission."""
    manager = ThemeManager.instance()
    assert manager is ThemeManager.instance()

    events = []
    manager.theme_changed.connect(events.append)

    # Force to Dark Mode
    manager.set_theme_mode(ThemeMode.DARK, apply_to_app=False)
    assert manager.is_dark is True
    assert manager.is_light is False
    assert manager.current_mode == ThemeMode.DARK
    assert events[-1] == "dark"

    # Toggle to Light Mode
    toggled = manager.toggle_theme(apply_to_app=False)
    assert toggled == ThemeMode.LIGHT
    assert manager.is_dark is False
    assert manager.is_light is True
    assert events[-1] == "light"

    # Toggle back to Dark Mode
    toggled_back = manager.toggle_theme(apply_to_app=False)
    assert toggled_back == ThemeMode.DARK
    assert manager.is_dark is True
    assert events[-1] == "dark"

    manager.theme_changed.disconnect(events.append)


def test_stylesheet_generation_dark_and_light():
    """Verify stylesheet generation produces valid QSS with correct design tokens."""
    dark_qss = generate_stylesheet(DARK_TOKENS)
    assert DARK_TOKENS.app_bg in dark_qss
    assert DARK_TOKENS.surface_bg in dark_qss
    assert DARK_TOKENS.accent_red in dark_qss
    assert "QMainWindow" in dark_qss
    assert "QTabWidget" in dark_qss
    assert "QTableWidget" in dark_qss

    light_qss = generate_stylesheet(LIGHT_TOKENS)
    assert LIGHT_TOKENS.app_bg in light_qss
    assert LIGHT_TOKENS.surface_bg in light_qss
    assert LIGHT_TOKENS.border in light_qss
    assert "QMainWindow" in light_qss
    assert "QTabWidget" in light_qss
    assert "QTableWidget" in light_qss

    assert DARK_THEME_QSS == dark_qss
    assert LIGHT_THEME_QSS == light_qss


def test_semantic_severity_badge_contrast():
    """Verify distinct semantic severity badge styling for both dark and light themes."""
    # Dark Mode Badges
    dark_crit = get_badge_qss("CRITICAL", mode=ThemeMode.DARK)
    assert "#DC2626" in dark_crit or "#EF4444" in dark_crit
    assert "border-radius" in dark_crit

    dark_high = get_badge_qss("HIGH", mode=ThemeMode.DARK)
    assert "#EA580C" in dark_high or "#F97316" in dark_high

    dark_med = get_badge_qss("MEDIUM", mode=ThemeMode.DARK)
    assert "#D97706" in dark_med or "#FFBF00" in dark_med

    dark_low = get_badge_qss("LOW", mode=ThemeMode.DARK)
    assert "#0284C7" in dark_low or "#38BDF8" in dark_low

    dark_pass = get_badge_qss("PASSED", mode=ThemeMode.DARK)
    assert "#16A34A" in dark_pass or "#22C55E" in dark_pass

    # Light Mode Badges (ensure accessible light background tints and dark readable text)
    light_crit = get_badge_qss("CRITICAL", mode=ThemeMode.LIGHT)
    assert "#FEE2E2" in light_crit or "#DC2626" in light_crit

    light_high = get_badge_qss("HIGH", mode=ThemeMode.LIGHT)
    assert "#FFEDD5" in light_high or "#EA580C" in light_high

    light_med = get_badge_qss("MEDIUM", mode=ThemeMode.LIGHT)
    assert "#FEF3C7" in light_med or "#D97706" in light_med

    light_pass = get_badge_qss("PASSED", mode=ThemeMode.LIGHT)
    assert "#DCFCE7" in light_pass or "#16A34A" in light_pass


def test_theme_preference_persistence(tmp_path):
    """Verify that theme preference persists correctly to config file."""
    config_file = tmp_path / "theme_preference.json"
    manager = ThemeManager(config_path=config_file)

    assert manager.current_mode == ThemeMode.DARK

    manager.set_theme_mode(ThemeMode.LIGHT, apply_to_app=False)
    assert config_file.exists()
    data = json.loads(config_file.read_text(encoding="utf-8"))
    assert data["theme"] == "light"

    # Reload new manager from the persisted config
    new_manager = ThemeManager(config_path=config_file)
    assert new_manager.current_mode == ThemeMode.LIGHT


def test_cpent_theme_backward_compatibility():
    """Verify legacy CPENTTheme constants remain available and synchronized."""
    assert hasattr(CPENTTheme, "APP_BG")
    assert hasattr(CPENTTheme, "RED_ACCENT")
    assert hasattr(CPENTTheme, "PRIMARY_TEXT")
    assert hasattr(CPENTTheme, "FONT_FAMILY_HEADING")
    assert hasattr(CPENTTheme, "FONT_FAMILY_BODY")
    assert hasattr(CPENTTheme, "FONT_FAMILY_MONO")

    assert "CRITICAL" in SEVERITY_COLORS_HEX
    assert "HIGH" in SEVERITY_COLORS_HEX
    assert "MEDIUM" in SEVERITY_COLORS_HEX
    assert "LOW" in SEVERITY_COLORS_HEX
    assert "CONFIRMED" in VALIDATION_COLORS_HEX
    assert "PASSED" in EXECUTION_COLORS_HEX
