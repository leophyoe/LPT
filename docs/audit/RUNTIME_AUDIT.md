# LPT Workstation — Phase 0: Runtime Verification Audit
**Document ID:** `docs/audit/RUNTIME_AUDIT.md`  
**Audit Date:** 2026-11-05  
**Auditor:** Senior Software Architect & QA Lead  
**Status:** COMPLETED — END-TO-END RUNTIME VALIDATION  

---

## 1. Executive Summary

This runtime audit validates the actual runtime execution of the LPT application across GUI presentation, headless execution, CLI shell interaction, scanner execution, parser pipelines, database read/writes, report generation, and AI Copilot heuristics.

---

## 2. Application Startup & Execution Modes

The master entrypoint `main.py` supports four distinct operational execution modes:

```text
               ┌──────────────────┐
               │     main.py      │
               └────────┬─────────┘
                        │
       ┌────────────────┼────────────────┬────────────────┐
       ▼                ▼                ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Desktop GUI │ │ Headless VNC │ │ CLI Console  │ │ Tool Checker │
│ (PySide6 QSS)│ │  (Port 5900) │ │  (--cli)     │ │  (--tools)   │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

1. **Desktop GUI Mode (`python3 main.py`):** Launches PySide6 Dark Cyber Workstation with full graphical capabilities when an active display (`$DISPLAY` or `$WAYLAND_DISPLAY`) is available.
2. **Headless Offscreen Mode (`QT_QPA_PLATFORM=offscreen python3 main.py`):** Runs the full Qt event loop headlessly for automated integration tests without requiring an X11 server.
3. **Headless VNC Server Mode (`python3 main.py --vnc`):** Automatically initializes an internal VNC desktop server listening on `127.0.0.1:5900`, enabling remote graphical access.
4. **Interactive CLI Console Mode (`python3 main.py --cli`):** Standalone terminal environment for low-overhead pentesting, tool testing, and execution in server environments.
5. **Tool Diagnostics (`python3 main.py --tools`):** Scans system PATH and local fallback directories to audit all 33 integrated tools.

---

## 3. Detailed Runtime Verification Checklist

| Verification Task | Test Method | Observed Result | Status |
|---|---|---|---|
| **1. Python Environment & Imports** | `.venv/bin/python -c "import PySide6, requests, sqlite3"` | All imports load cleanly without missing C-extensions | **PASS** |
| **2. GUI Window Instantiation** | Offscreen headless instantiation of `MainWindow` with production DB | Main window creates, binds active project `p1`, and closes cleanly | **PASS** |
| **3. Navigation Signal/Slot Routing** | Automated routing between Dashboard, Projects, Scope, Recon, and Labs | Correct view stack and subtab switching verified | **PASS** |
| **4. PTY Terminal Initialization** | Execution of `VSCodeTerminal` PTY bash worker | Real pseudo-terminal spawns, streams output, and terminates cleanly | **PASS** |
| **5. Command Execution Engine** | `ProcessRunner.run(['echo', 'LPT_TEST'])` | Captures returncode 0, stdout stream, and timestamps | **PASS** |
| **6. Nmap Parser Pipeline** | Parsing synthetic Nmap host-discovery (`-sn`) and service scan output | Extracts hosts, ports, services, OS fingerprint, and banners | **PASS** |
| **7. Scanner Result Preview Dialog** | Instantiation of `ScannerResultPreviewDialog` with discovered hosts | Differentiates in-scope vs out-of-scope; enforces fail-closed boundary | **PASS** |
| **8. Database CRUD Isolation** | Synthetic project creation, scope definition, and asset persistence | Database operations succeed idempotently on temporary test databases | **PASS** |
| **9. Evidence Vaulting** | Saving raw ANSI session with cryptographic SHA-256 hash | Evidence record created, file written to disk, hash verified | **PASS** |
| **10. Retroactive Ingestion** | Ingesting discovered assets from saved terminal session | Persists `AssetNode` and `AssetEdge` without creating duplicates | **PASS** |
| **11. Scope Guard Enforcement** | Attempting scan against out-of-scope IP address | Blocked immediately with `EngagementAuditLog` record | **PASS** |
| **12. HTML Report Generation** | `ReportBuilder.generate_html(project_id)` | Generates complete self-contained HTML report with SVG topology | **PASS** |
| **13. Markdown & JSON Export** | `ReportBuilder.generate_markdown()`, `generate_json()` | Formatted Markdown and structured JSON written cleanly | **PASS** |
| **14. PDF Report Generation** | `ReportBuilder.generate_pdf(project_id)` | Generates printable PDF via PySide6 `QPdfWriter` | **PASS** |
| **15. AI Heuristic Diagnostics** | `AICopilotEngine.diagnose_output(error_str, exit_code=1)` | Returns root cause, analysis, suggested fix, and command | **PASS** |
| **16. AI Sensitive Data Redaction** | `redact_sensitive_text(raw_terminal_with_api_keys)` | Masks bearer tokens, AWS keys, and private keys | **PASS** |

---

## 4. Runtime Deficiencies & Warnings Observed

1. **Deprecated SSL Constants (60 Warnings):**
   * Deprecation warnings are emitted during TLS test execution: `ssl.TLSVersion.TLSv1 is deprecated` and `ssl.TLSVersion.TLSv1_1 is deprecated` in Python 3.12+.
   * *Resolution Plan:* Retain the legacy protocol checks for penetration testing capability while silencing standard library deprecation warnings or using version-agnostic integer guards.
2. **Missing DOCX Pipeline:**
   * `ReportBuilder` has HTML, Markdown, JSON, and PDF, but no `.docx` export method is implemented.
   * *Resolution Plan:* Implement `generate_docx()` using `python-docx`.
3. **QWebEngine Process Sandbox Warnings:**
   * When WebEngine launches in sandboxed Linux containers, standard Chromium warnings (`Failed to connect to system_bus_socket`) appear in stderr.
   * *Resolution Plan:* Set `QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu"` consistently across all WebEngine widgets.

