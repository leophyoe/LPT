# CyberSecuritySuite — Critical Asset Ingestion Root Cause Diagnostic Report

**Project:** CyberSecuritySuite  
**Path:** `/home/leo/Desktop/cybersecuritysuite`  
**Database SHA-256 (Before & After):** `c8d8aa9c0cb6a66682e678d2e3b5762df9086cffc43457ba489541e1ff7a7143`  
**Audit Mode:** Strict READ-ONLY Forensic Investigation  
**Date:** 2026-11-01  

---

## 1. Executive Summary

A critical user-reported defect was investigated where a ping sweep command (`nmap -sn 192.168.100.7/24`) executed inside the CyberSecuritySuite Terminal successfully printed 6 live hosts (`192.168.100.1`, `.3`, `.7`, `.10`, `.35`, `.40`), but **none of these discovered hosts appeared in the Digital Assets / Attack Surface Management table**.

Our forensic trace through the complete **Terminal → Process/PTY → Session Recorder → Scope Guard → Parser → Asset Inventory → SQLite Database → Assets GUI View** pipeline confirmed that **the underlying parser (`NmapParser.parse_text`) and asset inventory service (`AssetInventoryService.sync_scan_assets`) work correctly**, but discovered assets failed to reach the database due to three compounding architectural disconnects:

1. **`[💾 Save Evidence]` Does Not Ingest Assets:** When the user clicked `[💾 Save Evidence]` on the terminal dock, the handler (`VSCodeTerminal.save_session_evidence`) strictly writes the terminal output to raw files (`storage/evidence/session_*.raw` and `.txt`) and inserts an audit record into the `evidence` and `terminal_sessions` tables. **It never calls `TerminalIngestEngine` or `AssetInventoryService`**.
2. **Missing Engagement Scopes in Project 4 (`p1`):** The active engagement created by the user (`p1`, id: 4) had **0 authorized target scopes** in `target_scopes`. CyberSecuritySuite's fail-closed security architecture (`ScopeAuthorizationService`) strictly disallows committing out-of-scope assets to the database. Even when the `ScannerResultPreviewDialog` is triggered, every discovered host is marked `❌ OUT-OF-SCOPE` and disabled from synchronization (`cb.setChecked(False); cb.setEnabled(False)`).
3. **Passive Terminal Scanner Notification Banner:** In the interactive PTY terminal (`desktop/widgets/vscode_terminal.py`), scanner completion detection does not automatically commit to SQLite; it displays a transient notification banner (`[🔍 Review & Sync into Project]`). If the operator clicks `[💾 Save Evidence]` instead, the scan remains unparsed.
4. **Missing GUI Refresh Signal in Command Console:** In the alternate Command Console tab (`desktop/widgets/terminal_view.py`), `_save_command_result` calls `TerminalIngestEngine.ingest_command_output`, but **never emits `project_data_updated`**, so the UI views never receive notification to refresh from SQLite.

---

## 2. Forensic Database Evidence

Forensic examination of `storage/data/cybersecuritysuite.db` revealed the exact chronological sequence of events:

```text
1. 2026-11-01 16:30:46: Engagement 'p1' created (id: 4) by 'security_lead'.
2. Target Scopes for Project 4: Exactly 0 records in target_scopes table.
3. 2026-11-01 16:32:12: terminal_scope_guard blocked out-of-scope scan against '192.168.100.7'.
   Audit Log #58: "Blocked attempt to run scan against unauthorized target '192.168.100.7'. Reason: No authorized target scopes defined for this project."
4. 2026-11-01 16:33:03: Operator clicked [Save Evidence] in the terminal dock.
   ToolExecution #16: 'Terminal Session sess_fa6a25df43_1793550081' (project_id: 4)
   Evidence #24: 'storage/evidence/session_sess_fa6a25df43_1793550081.raw' (project_id: 4)
```

Inspection of `storage/evidence/session_sess_fa6a25df43_1793550081.txt` confirmed the actual terminal output:
```text
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-01 22:53 +0630
Nmap scan report for _gateway (192.168.100.1)
Host is up (0.016s latency).
Nmap scan report for 192.168.100.3
Host is up (0.15s latency).
Nmap scan report for leo (192.168.100.7)
Host is up (0.00014s latency).
Nmap scan report for 192.168.100.10
Host is up (0.053s latency).
Nmap scan report for 192.168.100.35
Host is up (0.25s latency).
Nmap scan report for 192.168.100.40
Host is up (0.044s latency).
Nmap done: 256 IP addresses (6 hosts up) scanned in 19.44 seconds
```

The output was saved into Evidence #24, but `asset_nodes` for project 4 remained empty (`0` rows).

---

## 3. Pipeline Component Diagnostic Status Matrix

| Component | File Path | Function / Method | Status | Diagnostic Finding |
| :--- | :--- | :--- | :--- | :--- |
| **Terminal PTY Output** | `desktop/widgets/vscode_terminal.py` | `_on_pty_data` | **WORKING** | Data stream correctly received from `/dev/pts/*` and buffered in `_terminal_buffer`. |
| **Scanner Completion Detection** | `desktop/widgets/vscode_terminal.py` | `_check_completed_scan_output` | **PARTIAL** | Detects `"Nmap done:"` and shows a banner, but does NOT persist data unless user clicks `[🔍 Review & Sync]`. |
| **Evidence Saver** | `desktop/widgets/vscode_terminal.py` | `save_session_evidence` | **DEFECT** | Saves evidence raw file and DB record, but **NEVER parses or ingests discovered assets**. |
| **Manual Sync Button** | `desktop/widgets/vscode_terminal.py` | `sync_terminal_output` | **WORKING** | Opens `ScannerResultPreviewDialog` when clicked, but blocked if scope is missing. |
| **Nmap Console Parser** | `modules/network/nmap_parser.py` | `parse_text` | **WORKING** | Correctly extracts all 6 hosts, status `up`, latencies, and hostnames (`_gateway`, `leo`). Zero-port ping sweep is fully supported. |
| **Scope Authorization Service** | `core/scope.py` | `is_target_authorized` | **WORKING (FAIL-CLOSED)** | Strictly blocks assets when `scopes` list is empty (`"No authorized target scopes defined for this project."`). |
| **Scanner Preview Dialog** | `desktop/dialogs/scanner_preview_dialog.py` | `_init_ui`, `_on_confirm` | **DEFECT** | When scope is missing, disables all host checkboxes with `❌ OUT-OF-SCOPE` without offering to define the subnet scope. |
| **Asset Ingestion Engine** | `terminal/ingest.py` | `ingest_command_output` | **WORKING** | Given in-scope subnet, correctly generates 8 `AssetNode` records (6 IPs, 2 Hostnames) and 6 `Finding` records. |
| **Command Console Saver** | `desktop/widgets/terminal_view.py` | `_save_command_result` | **DEFECT** | Calls `TerminalIngestEngine.ingest_command_output` but **fails to emit `project_data_updated` signal**. |
| **Assets GUI View** | `desktop/views/assets_view.py` | `refresh`, `_render_table` | **WORKING** | Queries `db.list_asset_nodes(project_id)`. Renders accurately when rows exist in `asset_nodes`. |

---

## 4. Root Causes in Detail

### Cause A: `save_session_evidence()` does not parse or sync assets
In `desktop/widgets/vscode_terminal.py`:
```python
@Slot()
def save_session_evidence(self):
    ...
    res = session.recorder.save_session_as_evidence(db=self.db, project_id=self.active_project.id)
    self.project_data_updated.emit()
    QMessageBox.information(self, "Evidence Saved", ...)
```
When an operator finishes running scans in the terminal, they naturally click `[💾 Save Evidence]`. The code vaults the session raw text, but completely omits scanning for tool outputs or syncing assets. The user believes the session has been synchronized into the project, but the asset inventory is completely untouched.

### Cause B: Missing Target Scope in Project 4 (`p1`) blocks synchronization
In `desktop/dialogs/scanner_preview_dialog.py`:
```python
scope_check = ScopeAuthorizationService.is_target_authorized(h.ip, self.scopes, project=self.project)
if scope_check.is_allowed:
    item_scope = QTableWidgetItem("✅ Authorized (In-Scope)")
else:
    item_scope = QTableWidgetItem(f"❌ OUT-OF-SCOPE ({scope_check.reason})")
    cb.setChecked(False)
    cb.setEnabled(False)  # Disallow syncing out of scope
```
Because project 4 was newly created and had no target scopes registered:
1. `ScopeAuthorizationService.is_target_authorized` returned `allowed=False, reason="No authorized target scopes defined for this project."`.
2. All 6 checkboxes were disabled and unchecked.
3. Even if the operator opened the sync dialog, clicking `Confirm & Sync` synced `0` hosts.

### Cause C: `TerminalWidget._save_command_result` drops UI refresh signal
In `desktop/widgets/terminal_view.py`:
```python
TerminalIngestEngine.ingest_command_output(...)
# Missing: self.project_data_updated.emit()
```
When commands are executed from Tab 2 ("⚡ Command Console"), `_save_command_result` successfully persists findings and assets into SQLite (if in-scope), but fails to emit `self.project_data_updated.emit()`. `MainWindow._on_terminal_project_data_updated` is never invoked, leaving `AssetsView` with stale data until manual reload.

---

## 5. Safe Minimal Remediation Plan (Awaiting Approval)

To fix this issue safely without breaking security boundaries, schema changes, or database modifications:

### Patch 1: Auto-Offer Ingestion in `save_session_evidence`
In `desktop/widgets/vscode_terminal.py` -> `save_session_evidence()`:
After saving the evidence, inspect the plain text using `NmapParser.parse_text`. If live hosts or scanner findings are detected:
- Prompt or automatically trigger `sync_terminal_output()`, so that saving evidence seamlessly gives the operator the option to commit discovered assets into the inventory.

### Patch 2: Scope Guidance in `ScannerResultPreviewDialog`
In `desktop/dialogs/scanner_preview_dialog.py`:
When `self.scopes` is empty or all discovered hosts are rejected due to missing scopes:
- Provide an inline action: `[➕ Authorize Subnet in Project Scope]`.
- Allow the operator (if authorized lead tester) to quickly authorize `192.168.100.0/24` into `target_scopes` for the active project directly from the review dialog, rather than forcing them to cancel, navigate away, and re-run the scan.

### Patch 3: Emit `project_data_updated` in `TerminalWidget._save_command_result`
In `desktop/widgets/terminal_view.py`:
Add `self.project_data_updated.emit()` after `TerminalIngestEngine.ingest_command_output(...)` so that all open views (`AssetsView`, `NetworkScanView`, `TopologyView`, `DashboardView`) immediately reload from SQLite.

### Patch 4: Retroactive Ingestion Utility
Add an `[📥 Ingest Discovered Assets]` action in the Cryptographic Evidence Vault / Terminal Session History tab:
- Allows operators to click any existing recorded session (such as Session `sess_fa6a25df43_1793550081` / Evidence #24) and immediately parse and commit its 6 live hosts into the project asset inventory once scope is defined.

---

## 6. Audit Verification & Safety Guarantee

- Database SHA-256 before audit: `c8d8aa9c0cb6a66682e678d2e3b5762df9086cffc43457ba489541e1ff7a7143`
- Database SHA-256 after audit: `c8d8aa9c0cb6a66682e678d2e3b5762df9086cffc43457ba489541e1ff7a7143`
- Source files modified: `0`
- External network requests: `0`
- Safe reproduction completed using isolated in-memory test databases.

