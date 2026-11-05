# Phase 2 UI/UX Redesign Changelog
**Project:** CyberSecuritySuite / LPT Workstation  
**Author:** Senior PySide6 UI/UX Architect & Accessibility Engineer  
**Date:** 2026-11-05  
**Version:** 2.0.0-phase2  
**Status:** ACCEPTED & VERIFIED  

---

## 1. Overview of Changes

Phase 2 overhauled the visual hierarchy, theme responsiveness, typography, and layout ergonomics across the LPT desktop application. All changes were implemented purely in the presentation layer without altering database schemas or backend contracts.

---

## 2. File-by-File Detailed Changelog

### `desktop/icons.py`
- **Added:** New unified Lucide SVG icon engine utilizing `PySide6.QtSvg.QSvgRenderer`.
- **Added:** Dynamic color tinting support via XML attribute replacement.
- **Added:** In-memory `QIcon` caching with `clear_cache()` hook triggered on theme change.

### `desktop/theme.py`
- **Updated:** Typography subsystem with `get_ui_font(size, bold, heading, mono)` providing fallback support across `Inter`, `Noto Sans`, `Noto Sans Myanmar`, `Ubuntu`, `DejaVu Sans`.
- **Added:** `@property def mode(self) -> ThemeMode:` to `ThemeManager` for convenient mode inspection.
- **Added:** Automatic icon cache invalidation on theme switch in `set_theme_mode()`.
- **Preserved:** Calibrated WCAG AA contrast tokens in `DARK_TOKENS` and `LIGHT_TOKENS` satisfying 100% of `tests/test_cpent_theme.py`.
- **Archived:** Original version to `.archive/desktop/theme.py.bak_20261105_phase2`.

### `desktop/widgets/sidebar_nav.py`
- **Updated:** `SidebarNavItem.update_display()` to dynamically read active theme tokens instead of hardcoding dark hex codes.
- **Added:** `_on_theme_changed()` handler connected to `ThemeManager.instance().theme_changed`.
- **Redesigned:** Active project and scope indicator card with distinct high-contrast styling and visual borders.
- **Archived:** Original version to `.archive/desktop/widgets/sidebar_nav.py.bak_20261105_phase2`.

### `desktop/widgets/vscode_terminal.py`
- **Updated:** Pre-initialized Chromium page background with `self.web_view.page().setBackgroundColor(QColor("#060911"))`.
- **Fixed:** Eliminated white flashing and white box artifacts during startup and window re-renders.
- **Archived:** Original version to `.archive/desktop/widgets/vscode_terminal.py.bak_20261105_phase2`.

### `desktop/views/assets_view.py`
- **Redesigned:** Header into two-row high-density layout separating search/refresh from sub-view switcher and recon actions.
- **Removed:** Prototype codename `(Behind24)` from sub-view toggle button (`🛰️ Digital Assets`).
- **Added:** 1-Click collapsible analytics drawer (`btn_toggle_analytics = QPushButton("📊  Analytics Cards")`), recovering 160px of vertical space for the main Asset Table.
- **Fixed:** Filter drawer button squishing by enforcing 28px minimum heights.
- **Expanded:** Table column sizing (`Risk Posture` 120px, `Type` 95px, `Status` 95px), eliminating `[SK POST` and `& S` clipping.
- **Added:** Full `_on_theme_changed()` handler updating all 8 KPI cards, distribution bars, donut charts, and inspector tables.
- **Archived:** Original version to `.archive/desktop/views/assets_view.py.bak_20261105_phase2`.

### `desktop/views/projects_view.py`
- **Fixed:** Qt keyboard mnemonic underscore pollution by escaping ampersands (`&&`) in tab titles (`"🎯 Scope Boundaries && Exclusions"`, `"📜 RoE && Audit Trail"`) and buttons (`"📋 Edit RoE && State"`).
- **Expanded:** `self.plans_table` column widths (Authorized Scope 160px, Timeline 120px), eliminating `'HORIZED SC` truncation.
- **Added:** Theme-adaptive styling for preflight checks and assessment criteria text editors.
- **Added:** `_on_theme_changed()` handler connected to `ThemeManager.instance().theme_changed`.
- **Archived:** Original version to `.archive/desktop/views/projects_view.py.bak_20261105_phase2`.

### `desktop/views/findings_view.py`
- **Fixed:** Header title truncation (`Security Findings & Evidence Repository`).
- **Expanded:** `self.table` column widths (`Affected Asset` 160px, `Status` 110px, `Confidence` 95px, `Assessment` 120px), eliminating `FFECTED ASSE` truncations.
- **Added:** `_on_theme_changed()` handler updating table and detail pane colors for Dark and Light modes.
- **Archived:** Original version to `.archive/desktop/views/findings_view.py.bak_20261105_phase2`.

### `desktop/views/dashboard_view.py`
- **Fixed:** Light Mode white-on-white text in `_populate_findings_table` by explicitly binding item foregrounds based on active theme mode.
- **Updated:** `RiskGauge.paintEvent` with dynamic high-contrast track arcs (`#E2E8F0` / `#1E293B`) and crisp typography (`get_ui_font()`).
- **Added:** Dynamic background styling on `self.container` resolving the hardcoded `#0B0F19` dark box in Light Mode.
- **Added:** `_on_theme_changed()` handler connected to `ThemeManager.instance().theme_changed`.
- **Archived:** Original version to `.archive/desktop/views/dashboard_view.py.bak_20261105_phase2`.

### `desktop/views/tools_view.py`
- **Expanded:** Table column sizing (`Tool Name` 160px, `Category` 110px, `Status` 90px, `CLI` 55px, `Adapter` 75px, `GUI` 55px, `Parser` 75px), eliminating name ellipses (`OWASP Amas...`) and header cuts (`D \`, `PARS`).
- **Fixed:** Keyboard mnemonic underscore in `"📥 Unavailable Tools && Guides"`.
- **Added:** `_on_theme_changed()` handler for Dark and Light mode styling of tool details drawer and diagnostic text box.
- **Archived:** Original version to `.archive/desktop/views/tools_view.py.bak_20261105_phase2`.

