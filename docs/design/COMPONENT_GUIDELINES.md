# LPT Workstation Component Guidelines & Standards
**Version:** 2.0 (Phase 2 Master Redesign)  
**Target:** PySide6 / Qt Widgets Component Library  

---

## 1. Buttons & Interactive Controls

### 1.1 Button Hierarchy

| Button Variant | QSS / Visual Treatment (Dark Mode) | Usage Context |
| :--- | :--- | :--- |
| **Primary Action** (`btn-primary`) | Background: `#3B82F6`; Hover: `#2563EB`; Text: `#FFFFFF`; Radius: 5px | Main workflow step (e.g., "Run Scan", "Save Evidence", "New Assessment") |
| **Secondary Action** (`btn-secondary`) | Background: `#1E293B`; Border: 1px solid `#334155`; Hover: `#283548`; Text: `#F8FAFC` | Supporting operations (e.g., "Export CSV", "Refresh", "Edit Details") |
| **Danger / High-Alert** (`btn-danger`) | Background: `#EF4444`; Hover: `#DC2626`; Text: `#FFFFFF` | Destructive or high-risk actions (e.g., "Archive Project", "Delete Finding") |
| **Ghost / Flat** (`btn-ghost`) | Background: transparent; Hover: `#1E293B`; Text: `#CBD5E1` | Auxiliary toolbar toggles, collapse buttons, copy helpers |

### 1.2 Button Rules
1. **No Rainbow Palettes:** Do not place four buttons with four different solid background colors (red, purple, cyan, green) side by side. Use Primary Blue for the main action and Secondary Slate for supporting actions.
2. **Explicit Icon Alignment:** All button icons must precede the label with a standard 6px gap (`QSize(16, 16)` icon size).
3. **No Raw Underscores:** Button labels must never expose code identifiers (e.g., write "Edit RoE State", not "Edit RoE _State").

---

## 2. Tables & Data Grids (`QTableWidget` / `QTableView`)

### 2.1 Table Metrics & Specifications
- **Header Height:** 36px
- **Row Height:** 32px (Compact mode: 28px)
- **Header Typography:** 11px / SemiBold (600) / Text Transform: Uppercase / Letter Spacing: 0.5px
- **Header Background:** `#0F172A` (Dark) / `#F1F5F9` (Light)
- **Cell Typography:** 12px / Regular (400) / Text Color: `#F8FAFC` (Dark) / `#0F172A` (Light)
- **Alternating Row Color:** `#131D2E` (Dark) / `#F8FAFC` (Light)
- **Selected Row Color:** `#1E3A8A` with `#60A5FA` border accent

### 2.2 Text Truncation & Column Widths
1. **Never Truncate Core Identifiers:** Columns like `ID`, `SEVERITY`, `IP / HOST`, and `PORT` must have explicit minimum column widths preventing abbreviation.
2. **Interactive Tooltips on Truncation:** Any cell that abbreviates text with an ellipsis (`...`) must set a full tooltip on hover (`item.setToolTip(full_text)`).
3. **Auto-Resize with Stretch:** The primary content column (e.g., `FINDING TITLE`, `ASSET VALUE`, `TOOL NAME`) must set `QHeaderView.Stretch` to expand responsively to available window width.

---

## 3. Project Selector Pill & Scope Status Badge

### 3.1 Project Selector Pill (Top Sidebar & Header)
- **Container:** Rounded pill (`border-radius: 6px; background-color: #1E293B; border: 1px solid #334155; padding: 6px 10px;`)
- **Icon:** Lucide Folder / Briefcase (`QSize(14, 14)`)
- **Project Label:** `#F8FAFC`, 13px SemiBold
- **Interactive State:** Hover background `#283548`; clicking triggers the project selection dropdown or project dialog.

### 3.2 Scope Boundary Status Pill
- **Authorized Scope:** Green outline pill (`border: 1px solid #10B981; background: rgba(16, 185, 129, 0.12); color: #10B981;`) showing `"N Authorized Targets"`.
- **Unassigned Scope:** Amber warning pill (`border: 1px solid #FBBF24; background: rgba(251, 191, 36, 0.12); color: #FBBF24;`) showing `"Scope: Unassigned"`.

---

## 4. Status & Severity Pill Badges

All badges must use standardized `border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 600;`:

| Code | Dark Background | Dark Text | Dark Border |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | `#3D1014` | `#EF4444` | `#D91F26` |
| **HIGH** | `#382010` | `#F97316` | `#EA580C` |
| **MEDIUM** | `#383010` | `#FBBF24` | `#CA8A04` |
| **LOW** | `#10243D` | `#38BDF8` | `#0284C7` |
| **INFO** | `#151F30` | `#94A3B8` | `#334155` |
| **CONFIRMED** | `#0E3320` | `#10B981` | `#16A34A` |
| **BLOCKED** | `#2B1D20` | `#F87171` | `#991B1B` |

---

## 5. Empty States & Loading Feedback

Every data container (Assets Table, Findings Table, Discovered Hosts, Evidence Vault, Notes Inspector) must provide an explicit empty state when 0 records exist:
1. **Clean Icon:** Centered Lucide outline icon (48x48, color: `#64748B`).
2. **Clear Heading:** 14px SemiBold `#CBD5E1` (e.g., `"No Assets Ingested Yet"`).
3. **Actionable Subtitle:** 12px `#94A3B8` guiding the operator on the exact action needed (e.g., `"Execute a network discovery scan in the Terminal below or run Nmap to discover targets."`).
4. **Call-to-Action Button:** An optional secondary action button (e.g., `"+ Add Authorized Target"`).

