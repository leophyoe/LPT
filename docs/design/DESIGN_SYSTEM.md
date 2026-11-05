# LPT Workstation Design System
**Version:** 2.0 (Phase 2 Master Redesign)  
**Framework:** PySide6 / Qt Widgets  
**Design Philosophy:** Cybersecurity Workstation First, Accessible, High-Contrast, Data-Dense, Responsive.

---

## 1. Design Principles

1. **Information Hierarchy First:** Primary targets, critical vulnerabilities, and active session states must be immediately distinct from ambient telemetry.
2. **Accessible Contrast (WCAG AA Compliant):** All body and data text must achieve at least 4.5:1 contrast against its background; headers and large controls must achieve at least 3.0:1.
3. **Cohesive Color Restraint:** Replace rainbow button palettes with a strict semantic palette: Navy/Slate foundation with Security Red (`#EF4444`) and Assessment Blue (`#3B82F6`) primary accents.
4. **Typography & Script Inclusivity:** Full support for English and Burmese scripts using `Inter`, `Noto Sans`, and `Noto Sans Myanmar` with proportional baseline rendering.
5. **Fail-Safe Theme Inversion:** Both Dark Mode and Light Mode must provide fully realized, high-contrast palettes without hardcoded inverted artifacts.

---

## 2. Color Palette & Design Tokens

### 2.1 Dark Mode (Primary Workstation Palette)

| Token Name | Hex Code | Purpose / Usage |
| :--- | :--- | :--- |
| `app_bg` | `#0B1120` | Root application background (Deep Midnight Navy) |
| `surface_bg` | `#1E293B` | Main workspace cards, panels, and table containers |
| `sidebar_bg` | `#0F172A` | Left navigation sidebar background |
| `elevated_bg` | `#283548` | Hover states, active dropdowns, modal card headers |
| `input_bg` | `#0D1526` | Text inputs, search bars, combobox backgrounds |
| `terminal_bg` | `#060911` | PTY / xterm.js console background |
| `border_subtle` | `#1E293B` | Subtle separators, inactive tab outlines |
| `border_default` | `#334155` | Card borders, table grid lines, input outlines |
| `border_focus` | `#3B82F6` | Focused inputs, selected items, active borders |
| `primary_text` | `#F8FAFC` | Main headings, table primary cells, active tab text |
| `secondary_text` | `#CBD5E1` | Subtitles, column headers, metadata, field labels |
| `muted_text` | `#94A3B8` | Timestamps, helper hints, empty state descriptions |

### 2.2 Light Mode (Daylight Audit Palette)

| Token Name | Hex Code | Purpose / Usage |
| :--- | :--- | :--- |
| `app_bg` | `#F8FAFC` | Root application background (Clean Slate White) |
| `surface_bg` | `#FFFFFF` | Main cards, tables, and modal backgrounds |
| `sidebar_bg` | `#F1F5F9` | Left navigation sidebar background |
| `elevated_bg` | `#E2E8F0` | Hover states, card headers |
| `input_bg` | `#FFFFFF` | Text inputs, search bars, combobox backgrounds |
| `terminal_bg` | `#0F172A` | Dark console contrast for shell readability |
| `border_subtle` | `#E2E8F0` | Subtle separators |
| `border_default` | `#CBD5E1` | Card outlines, table lines, input borders |
| `border_focus` | `#2563EB` | Active borders and focus rings |
| `primary_text` | `#0F172A` | Headings, active text, primary data |
| `secondary_text` | `#334155` | Column headers, labels, metadata |
| `muted_text` | `#64748B` | Helper hints, inactive labels |

### 2.3 Semantic Brand & Severity Accents

| Token Name | Dark Hex | Light Hex | Semantic Meaning |
| :--- | :--- | :--- | :--- |
| `accent_blue` | `#3B82F6` | `#2563EB` | Primary actions, active navigation, hyperlinks |
| `accent_red` | `#EF4444` | `#DC2626` | Critical severity, destructive actions, high-alert status |
| `severity_critical` | `#EF4444` | `#B91C1C` | CVSS 9.0–10.0 vulnerabilities, fatal errors |
| `severity_high` | `#F97316` | `#C2410C` | CVSS 7.0–8.9 vulnerabilities, urgent risks |
| `severity_medium` | `#FBBF24` | `#D97706` | CVSS 4.0–6.9 vulnerabilities, warnings |
| `severity_low` | `#38BDF8` | `#0284C7` | CVSS 0.1–3.9 vulnerabilities, low risk |
| `severity_info` | `#94A3B8` | `#475569` | Informational observations, tech fingerprinting |
| `status_success` | `#10B981` | `#059669` | Verified finding, passed check, live host |
| `status_blocked` | `#F87171` | `#DC2626` | Scope Guard blocked target, quarantined host |

---

## 3. Typography Specification

### 3.1 Font Stacks
1. **Primary Interface Font Stack (Body & UI):**
   ```css
   font-family: 'Inter', 'Noto Sans', 'Noto Sans Myanmar', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Ubuntu, sans-serif;
   ```
2. **Heading & Title Font Stack:**
   ```css
   font-family: 'Inter', 'Noto Sans', 'Noto Sans Myanmar', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
   font-weight: 600;
   ```
3. **Monospace & Code Font Stack (Terminal, Payloads, Evidence, Hashes):**
   ```css
   font-family: 'JetBrains Mono', 'Fira Code', 'Noto Sans Mono', 'Ubuntu Mono', 'DejaVu Sans Mono', Consolas, monospace;
   ```

### 3.2 Type Scale
- **Display 1 (App Title):** 16px / SemiBold (600) / Tracking +0.3px
- **H1 (Workspace Header):** 18px / SemiBold (600) / Line Height 24px
- **H2 (Card / Section Header):** 14px / SemiBold (600) / Line Height 20px
- **Body Regular (Main UI Text):** 13px / Regular (400) / Line Height 18px
- **Body Small (Table Cells, Secondary Meta):** 12px / Regular (400) / Line Height 16px
- **Caption / Badge:** 11px / Medium (500) / Letter Spacing +0.2px
- **Code / Monospace:** 12px / Regular (400) / Line Height 16px

---

## 4. Spacing & Grid System

- **Base Unit:** 4px
- **Micro Spacing:** 4px (`space-1`), 8px (`space-2`)
- **Control Spacing:** 12px (`space-3`), 16px (`space-4`)
- **Section Spacing:** 20px (`space-5`), 24px (`space-6`)
- **Card Padding:** 16px internal padding with 1px border (`border_default`) and 6px corner radius (`border-radius: 6px`).
- **Button Padding:** Vertical 7px, Horizontal 14px for standard buttons; Vertical 5px, Horizontal 10px for compact toolbar buttons.

