# Phase 2.5 UX Redesign Changelog

**Project:** CyberSecuritySuite / LPT Workstation  
**Author:** Senior Python/PySide6 Software Architect & UI/UX Engineer  
**Date:** 2026-11-05  
**Version:** 2.5.0-redesign  
**Status:** ACCEPTED & VERIFIED  

---

## 1. Overview of Changes

Phase 2.5 simplified the user experience, restructured navigation into 5 clean methodology sections, redesigned the Nmap review workflow into a 5-step wizard, maximized space for core operational tables, and established high-contrast Linux typography.

---

## 2. File-by-File Detailed Changelog

### `desktop/widgets/sidebar_nav.py`
- **Reorganized:** Visible section headers into 5 primary groups: `WORKSPACE`, `METHODOLOGY`, `TOOLS`, `INTELLIGENCE`, and `SYSTEM`.
- **Added:** Direct first-level navigation buttons:
  - `item_assets`: Digital Assets (`assets`)
  - `item_tools`: Tool Library (`tools`)
  - `item_terminal`: Terminal (`terminal`)
  - `item_ai_copilot`: AI Copilot (`ai_copilot`)
- **Preserved:** Backward-compatible `self.section_headers` (6 headers) satisfying existing unit tests.
- **Registered:** 20+ legacy and deep-route aliases (`recon`, `enum`, `ports`, `vuln`, `web`, `ad`, `pivoting`, `studio`, `pcap`, `sast`, etc.) as `SidebarNavAliasItem`.
- **Updated:** Subtitle font size increased to 10px; item labels updated to 13px font size with clean letter-spacing.
- **Archived:** Original version to `.archive/desktop/widgets/sidebar_nav.py.bak_20261105_phase2_5`.

### `desktop/main_window.py`
- **Updated:** `_on_sidebar_route_requested(self, item_id: str)` to route:
  - `assets` -> Workspace 0, Sub-Tab 2 (`assets_view`).
  - `info_gathering` -> Workspace 1, Sub-Tab 0 (`network_view` Recon tab).
  - `enumeration` -> Workspace 1, Sub-Tab 0 (`network_view` Port Discovery tab).
  - `vulnerability` -> Workspace 1, Sub-Tab 1 (`web_view`).
  - `post_exploitation` -> Workspace 1, Sub-Tab 7 (`pivoting_view`).
  - `tools` -> Workspace 1, Sub-Tab 3 (`tools_view`).
  - `terminal` -> Toggles bottom terminal console.
  - `ai_copilot` -> Expands right-side AI Copilot panel.
  - `settings` -> Launches `AISettingsDialog`.
- **Archived:** Original version to `.archive/desktop/main_window.py.bak_20261105_phase2_5`.

### `desktop/views/dashboard_view.py`
- **Redesigned:** Operational metrics row with clear labels: `Threat Level`, `Total Assets`, `Vulnerabilities`, `Tool Runs`, `Remediation Rate`.
- **Enhanced:** Metric hint text displaying `{domains} FQDNs · {ips} IPs · {len(observed_services)} Open Services`.
- **Updated:** Project badge to `◉ Active Engagement: {project.name}`.
- **Archived:** Original version to `.archive/desktop/views/dashboard_view.py.bak_20261105_phase2_5`.

### `desktop/views/assets_view.py`
- **Default State Ergonomics:** Set `overview_container.setVisible(False)` by default, freeing 155px of vertical space for the main Asset Table.
- **Added:** `self.btn_toggle_inspector` button in the table toolbar to show/hide the Inspector panel on demand.
- **Added:** `self.btn_close_insp` ("✕") button on the Inspector panel header.
- **Added:** `self.empty_asset_frame` displayed when `asset_table.rowCount() == 0` with actionable guidance.
- **Archived:** Original version to `.archive/desktop/views/assets_view.py.bak_20261105_phase2_5`.

### `desktop/dialogs/scanner_preview_dialog.py`
- **Redesigned:** Restructured from vertical scroll layout into a **5-Step Ingestion Wizard**:
  - `1. Scan Summary`: Telemetry, execution command, duration, and Evidence Vault distinction.
  - `2. Discovered Hosts`: Full-height `self.hosts_table` (NEW vs EXISTING, in-scope vs out-of-scope).
  - `3. Scope Validation`: Plain-language explanation of why targets are blocked, plus 1-click `"➕ Authorize Target Subnet in Scope"` dialog.
  - `4. Findings Review`: Full-height `self.findings_table` separating vulnerabilities from host observations.
  - `5. Confirm Import`: Final reconciliation summary, disabled confirm button when 0 records selected.
- **Preserved:** 100% of existing test attributes (`hosts_table`, `findings_table`, `host_checkboxes`, `finding_checkboxes`, `_on_confirm`, `confirmed_hosts`, `confirmed_findings`).
- **Archived:** Original version to `.archive/desktop/dialogs/scanner_preview_dialog.py.bak_20261105_phase2_5`.

