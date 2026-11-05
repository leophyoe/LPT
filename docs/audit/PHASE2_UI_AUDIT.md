# Phase 2 UI/UX Comprehensive Audit & Defect Report
**Project:** CyberSecuritySuite / LPT Workstation  
**Author:** Senior PySide6 UI/UX Architect & Accessibility Engineer  
**Date:** 2026-11-05  
**Audit Target:** All Desktop GUI Views, Dialogs, Theme Tokens, and Rendering States  
**Baseline Screenshots Captured:** 19 full-resolution screenshots in `storage/audit_screenshots/baseline/`  
**Status:** AUDIT COMPLETED — DEFECTS CATALOGED & PRIORITIZED

---

## 1. Executive Summary

This comprehensive audit was conducted under **Phase 2 — Professional UI/UX Redesign & Information Hierarchy** of the LPT Master Development Roadmap. High-resolution pixel rendering and offscreen visual captures were analyzed across all core workspaces in both **Dark Mode** and **Light Mode**.

The audit confirms the user's primary observation:  
> *"design တွေ က ဖတ် လို တောင် မရဘူး ဘာ လည် လုပ် အုန်း design တွေ"*  
> (*"The designs cannot even be read! What is going on with the designs?"*)

The root causes of unreadability and visual degradation across the application are:
1. **749 scattered inline `setStyleSheet` calls** that override global theme tokens, hardcode low-contrast dark hex values, and break Light Mode completely.
2. **Missing system font fallback stacks:** The stylesheet referenced `'Open Sans'`, `'Poppins'`, and `'Segoe UI'` (absent on Linux), causing Qt to fall back to unhinted X11 fonts while omitting `Inter` and `Noto Sans Myanmar` entirely.
3. **Severe table column clipping and text truncation:** Fixed layout constraints squish table headers (`'HORIZED SC`, `FFECTED ASSE`, `& S`, `[SK POST`, `D \`, `PARS`) and truncate page headers (`Security Findings & Evidence Rep`, `Inventory, exposure and operational signr...`).
4. **Broken Light Mode:** Light mode leaves sidebars and card panels pitch black (`#0F172A`, `#1E293B`) while rendering input boxes and table cells white with white text, causing total white-on-white text erasure.
5. **Terminal white box flashing:** `QWebEngineView` lacks page-level background color pre-initialization, rendering a stark white rectangle inside the dark workstation.
6. **Clashing visual hierarchy & rainbow controls:** Action buttons display inconsistent, non-standardized colors (bright red, purple, cyan, green, yellow) with arbitrary raw underscores in labels (`Scope Boundaries_Exclusions`, `Edit RoE _State`, `RoE _Audit Trail`).

---

## 2. Global Design System & Typography Defects

| Component | Defect Description | Root Cause | Impact |
| :--- | :--- | :--- | :--- |
| **Font Family Stack** | Missing `Inter` and `Noto Sans Myanmar`. Host Linux uses DejaVu/Ubuntu fallback. | `CPENTTheme.FONT_FAMILY_BODY = "'Open Sans', 'Segoe UI', ..."` | Burmese characters fail to render or render with broken glyphs; English text lacks crisp modern metrics. |
| **Typography Scale** | Many labels, badge texts, and table cells use 9px, 10px, or 11px font sizes. | Inline font size declarations in widgets. | Eye strain, unreadable labels on standard and HiDPI displays. |
| **Dark Theme Contrast** | Muted and secondary texts use `#64748B`, `#8B95A3`, `#4D4D4D` on `#15171C` / `#1E293B` (Contrast ratio < 2.8:1). | WCAG non-compliant dark palette tokens. | Text blends into dark background; unreadable under normal ambient light. |
| **Light Theme Inversion** | 749 hardcoded `setStyleSheet` calls hardcode dark backgrounds (`#1E293B`, `#0F172A`). | Inline stylesheets bypass `ThemeManager`. | Light Mode produces inverted frankenstein layouts (black cards with white text boxes and white-on-white text). |
| **Icon Standardization** | Emojis (`📁`, `🌐`, `📜`, `🚀`) mixed with custom text glyphs (`[✓]`, `[X]`, `•`). | Lack of unified SVG icon system. | Inconsistent icon weights, misaligned vertical baselines. |

---

## 3. Page-by-Page Audit Findings

### 3.1 Main Window & Navigation Sidebar (`desktop/widgets/sidebar_nav.py`)
- **Active Project Selector:** The project indicator (`+ p1`, `Scope: Unassigned`) renders as an unstyled, low-contrast text box without visual boundaries or interactive feedback.
- **Section Headers:** Headers (`WORKSPACE`, `METHODOLOGY WORKFLOW`, `OPERATIONS & LABS`) are very dim (`#64748B`) with small font sizes.
- **Sidebar Background:** Stays dark `#0F172A` even when application is toggled to Light Mode.
- **Collapse Toggle:** Small icon with unclear click target state.

### 3.2 Engagements & Scope Workspace (`desktop/views/projects_view.py`)
- **Underscore Label Pollution:** Tabs display raw code identifiers: `Scope Boundaries_Exclusions`, `Edit RoE _State`, `RoE _Audit Trail`.
- **Table Header Truncation:** Column `'HORIZED SC` instead of `AUTHORIZED SCOPE`.
- **Notes & Preflight Box:** Hardcoded pure black `#080C14` background in both dark and light modes with low-contrast dark red text.
- **Action Buttons:** "New Engagement" is bright red in light mode and blue in dark mode with inconsistent corner radii and padding.

### 3.3 Digital Assets Workspace (`desktop/views/assets_view.py`)
- **Header Truncation:** Subtitle cuts off: `Inventory, exposure and operational signr...`.
- **Tab Header Corruption:** Tab titles truncated into gibberish: `:al Assets (Bel` and `'e Recon_Gooç`.
- **Filter Sidebar:** Left "FILTERS" panel is crushed; checkboxes and radio buttons are squished into thin horizontal blue lines.
- **Table Column Clipping:** Columns `& S` (Status) and `[SK POST` (Risk Posture) are unreadable.
- **Inspector Empty State:** Inspector text replaced by series of dots/dashes (`--- ---- ---`).
- **Button Styling:** Jarring contrast between "Detect WAF (WAFW00F)" (saturated red) and "Harvest CT Subdomains" (cyan).

### 3.4 Executive Security Analytics / Dashboard (`desktop/views/dashboard_view.py`)
- **Exposure Score Circle:** "0/100 Not assessed" has dark gray text on dark gray circle (Contrast ratio ~2.1:1).
- **Project Selector Header:** Redundant small red dot badge `p1` with no label next to project combobox.
- **White-on-White Table Text in Light Mode:** In Light Mode, table rows turn white with white text (`#F8FAFC`), completely wiping out text readability.
- **Telemetry Timeline:** Empty list panel with harsh dark borders and no user-friendly empty state message.

### 3.5 Internal Network Discovery & Scan (`desktop/views/network_scan_view.py`)
- **Garish Top Cards:** Top summary cards use heavy brown, forest green, maroon, and navy background fills that clash with the dark slate background.
- **Rainbow Action Buttons:** Scan controller features bright red ("Run Nmap Scan"), cyan ("Local Footprint"), green ("Import Nmap XML"), and purple ("CPENT 6-Step Wizard") buttons side by side.
- **Table Empty State:** Discovered assets table shows empty gray rows without an empty state illustration or "Run your first scan" prompt.

### 3.6 Security Findings & Evidence (`desktop/views/findings_view.py`)
- **Title Truncation:** Header truncated as `Security Findings & Evidence Rep`.
- **Column Header Truncation:** Column `FFECTED ASSE` instead of `AFFECTED ASSET / HOST`.
- **Button Clustering:** 7 export buttons (`Export PDF`, `HTML`, `Markdown`, `JSON`, `All Formats`, `CPENT Pack`, `Auto-update`) are crammed into the header bar without grouping or dropdown consolidation.

### 3.7 CPENT Professional Reports (`desktop/views/reports_view.py`)
- **Underscore Labels:** Tabs display `Executive Posture _Analytics`, `Findings Matrix _Evidence Vault`.
- **Inconsistent Buttons:** PDF button is solid blue, HTML button is light gray with low-contrast text, CPENT Pack is purple.

### 3.8 Tool Integration Dashboard (`desktop/views/tools_view.py`)
- **Severe Name Truncation:** Every tool name in the table has an ellipsis (`OWASP Amas...`, `Nmap Netwo...`, `TShark Packe...`).
- **Header Truncations:** Headers `D \` (Dependencies) and `PARS` (Parser) are cut off.
- **Path Text Contrast:** Tool binary path in inspector is dark red on dark background.
- **Filter Label:** `Unavailable Tools_Guides` contains an underscore.

### 3.9 Integrated Terminal Presentation (`desktop/widgets/vscode_terminal.py`)
- **White Flashing / White Box:** `QWebEngineView` default canvas background is white, displaying a large white rectangle before the terminal finishes loading.
- **Light Mode Contrast:** Terminal tabs turn white while shell content remains dark, causing border misalignment.

---

## 4. UI/UX Remediation Roadmap

To fix these defects systematically without breaking any working backend functionality, the redesign will proceed in the strict order authorized:
1. **Design System & Tokens:** Define Navy/Slate palette (`#0B1120`, `#1E293B`, `#334155`), High-Contrast Text (`#F8FAFC`, `#E2E8F0`, `#94A3B8`), Red/Blue Accents (`#EF4444`, `#3B82F6`), Inter + Noto Sans Myanmar font stacks, and clean Lucide SVG icons.
2. **Main Window & Navigation:** Clean project selector pill, professional sidebar with clear methodology sections and badge indicators, consistent header bar.
3. **Engagements & Scope:** Fix tab titles, expand table columns, high-contrast notes panel, responsive button layout.
4. **Digital Assets:** Fix tab corruption, un-squish filter sidebar, widen table columns, clear inspector state, cohesive button styling.
5. **Dashboard & Metrics:** Fix white-on-white Light Mode bugs, enhance contrast of exposure score, clean metric cards.
6. **Network Scan & Tools:** Harmonize button colors, expand table headers, remove ellipses, clear empty states.
7. **Findings & Reports:** Fix title truncations, group export actions into clean dropdowns, remove underscore label bugs.
8. **Terminal Presentation:** Pre-set `web_view.page().setBackgroundColor("#080C14")` to eliminate white flashing; harmonize tabs.
9. **Dark & Light Mode Verification:** Validate that every view renders with crisp, accessible WCAG AA contrast in both modes.

