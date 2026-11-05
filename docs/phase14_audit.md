# Phase 14 — Operational Vulnerability Scanner & Security Tools GUI Integration Audit

**Project:** `CyberSecuritySuite`  
**Date:** 2026-10-28  
**Status:** Stage 1 Audit Complete (Ready for User Review & Stage 2 Approval)

---

## 1. Executive Summary

This audit assesses the current state of `CyberSecuritySuite` at `/home/leo/Desktop/cybersecuritysuite`, focusing on the real security tools installed, existing execution adapters, database models, scope enforcement, and UI components. 

The primary goal of Phase 14 is to transition the application from discrete tabs and learning playbooks into a unified, **GUI-driven Vulnerability Assessment Workbench** with real tool execution, comprehensive findings normalization, and a dedicated **Metasploit Exploit Validation** architecture (with safe mock fallbacks and clear installation diagnostics when `msfconsole` is not present).

---

## 2. Repository Architecture & Entrypoint Inventory

### 2.1 Application Entrypoints
- `main.py`: The master multi-mode launcher supporting:
  - **Desktop GUI** (Default): Launches PySide6 Dark Cyber Workstation.
  - **Headless VNC Mode** (`--vnc`): Spins up Xvfb/VNC server on port 5900 for remote viewing.
  - **CLI Interactive Shell** (`--cli`): Fallback terminal runner when no X11/Wayland display is detected.
  - **Automated Diagnostics** (`--tools`): Evaluates all 31 registered security tools on the host.
- Environment & PATH: `main.py` prepends both `bin/` and `.venv/bin/` to `$PATH`, ensuring local tool wrappers (`bin/sqlmap`, `bin/nikto`, `bin/wafw00f`, `bin/c0desec`, `bin/zap.sh`) and virtual environment packages take precedence over system defaults.

### 2.2 Database & Persistence Layer (`storage/db.py`)
- SQLite storage engine with WAL mode (`PRAGMA journal_mode=WAL`), foreign key enforcement, and explicit indexing.
- Core Models (`storage/models.py`):
  - `Project`: Engagement metadata, client name, status, Rules of Engagement (active recon, prohibited tests).
  - `TargetScope`: Explicit IP/CIDR/Hostname definitions with `is_authorized` and `rule_type` (`ALLOWED` vs `EXCLUDED`).
  - `AssessmentSession`: Operational time-tracking and status (`active`, `completed`, `blocked`).
  - `ToolExecution`: Audit log of exact CLI arguments, exit code, duration, start/end timestamps, stdout/stderr paths.
  - `Finding`: Normalized security vulnerability findings (`severity`, `confidence`, `affected_asset`, `affected_port_service`, `cve_id`, `cwe_id`, `cvss_score`, `remediation`, `validation_status`: `OBSERVED` vs `CONFIRMED`).
  - `Evidence`: Cryptographic provenance tracking with SHA-256 integrity hash, MIME type, and local file storage in `storage/evidence/`.
  - `AssetNode` & `AssetObservation`: Persistent network topology and asset inventory items.

### 2.3 Central Execution Engine (`core/execution_service.py` & `terminal/runner.py`)
- `ToolExecutionService`: Centralized singleton managing execution jobs with an explicit state machine:
  $$\text{QUEUED} \longrightarrow \text{VALIDATING} \longrightarrow \text{RUNNING} \longrightarrow \text{PARSING} \longrightarrow \text{COMPLETED / FAILED / CANCELLED / TIMED\_OUT / BLOCKED}$$
- `ProcessRunner`: Subprocess execution using `subprocess.Popen` with `shell=False`, argument list passing, process group isolation (`start_new_session=True`), line-buffered stdout/stderr streaming, and graceful process cancellation via `SIGTERM` followed by `SIGKILL`.
- Secret Redaction: `ToolExecutionService.redact_sensitive_args` automatically masks passwords, tokens, API keys, and hashes (`-p`, `-P`, `--pass`, `--token`) before recording to logs or UI.

### 2.4 Scope Authorization & Rules of Engagement (`core/scope.py`)
- `ScopeAuthorizationService`: Enforces fail-closed validation before any active network probe or tool execution.
- Rules:
  1. **Exclusions strictly override inclusions**: Any target matching an `EXCLUDED` scope rule is blocked unconditionally.
  2. **Active Reconnaissance Gate**: If a project's ROE disables active reconnaissance (`allow_active_recon=False`), intrusive scans (port scanning, brute forcing, web vulnerability probing) are blocked immediately.
  3. **Loopback & Local Range Handling**: `127.0.0.1` and `localhost` are validated against registered project scopes.

---

## 3. Real Security Tool Availability & Maturity Audit

An empirical audit of the host environment `/home/leo/Desktop/cybersecuritysuite` was conducted to distinguish **Installed & Verified**, **Missing Binary**, and **Report Import Only** tools:

| Tool Name | Binary Path on Host | Detected Version | Integration Type | Maturity Status |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | `/usr/bin/nmap` | `7.94SVN` | Real CLI Subprocess | **Fully Operational** (Scan profiles, `-Pn` skip ping, non-root fallback, XML parsing, asset sync) |
| **SQLMap** | `bin/sqlmap` | `1.10.10.13#dev` | Real CLI Subprocess | **Fully Operational** (`sqlmap_adapter.py`, batch mode, risk/level controls, scope guard) |
| **Gobuster** | `/usr/bin/gobuster` | `3.6` | Real CLI Subprocess | **Fully Operational** (`gobuster_adapter.py`, dir/dns/fuzz modes, wordlist validation) |
| **Nikto** | `bin/nikto` | `2.6.1 (LW 2.5)` | Real CLI Subprocess | **Fully Operational** (`nikto_adapter.py`, XML/text parser, port/tuning flags) |
| **WAFW00F** | `bin/wafw00f` | `2.2.0` | Real CLI Subprocess | **Fully Operational** (`wafw00f_adapter.py`, WAF detection, finding persistence) |
| **c0desec** | `bin/c0desec` | `1.0.0` | Real Python Engine | **Fully Operational** (`c0desec_adapter.py`, multi-tier web recon, secret detection) |
| **OWASP PTK** | `modules/web/ptk_engine.py` | `1.0.0` | Real Python Engine | **Fully Operational** (R-Builder cURL replayer, JWT Lab, SCA, Encoders) |
| **THC-Hydra** | `/usr/bin/hydra` | `9.5` | Real CLI Subprocess | **Fully Operational** (`hydra_adapter.py`, rate-limited, dry-run mode, lockout guards) |
| **Hashcat** | `/usr/bin/hashcat` | `6.2.6` | Real CLI Subprocess | **Fully Operational** (`password_cracker_adapter.py`, throttled `-w 2`, potfile parser) |
| **John the Ripper**| `bin/john` | `1.9.0-jumbo-1` | Real CLI Subprocess | **Fully Operational** (`password_cracker_adapter.py`, wordlist attack, potfile sync) |
| **Binwalk** | `/usr/bin/binwalk` | `2.3.3` | Real CLI Subprocess | **Fully Operational** (`firmware_analyzer.py`, signature analysis, entropy mapping) |
| **Volatility 3** | `source/system/volatility3/vol.py`| `2.28.3` | Real CLI Subprocess | **Fully Operational** (`volatility_adapter.py`, memory forensics, plugin execution) |
| **OWASP ZAP** | `/usr/local/bin/zap.sh` | `2.17.0` | Report Import & Daemon | **Partially Operational** (XML/JSON report import fully working; active CLI headless runner needs completion) |
| **Burp Suite** | *Not on system PATH* | *N/A* | Report Import Only | **Import Operational** (Burp XML parser working; live scanning requires external enterprise Burp) |
| **Metasploit** | *Not on system PATH* | *Missing* | Not Integrated | **Missing** (`msfconsole` not installed; requires installation diagnostics and dedicated Exploit Validation UI) |
| **Bandit** | *Not installed in .venv* | *N/A* | Adapter Ready | **Missing Package** (Built-in `ast_visitor.py` provides standalone AST-based SAST analysis without Bandit) |
| **Semgrep** | *Not installed in .venv* | *N/A* | Placeholder | **Missing Package** (Requires `pip install semgrep` or offline rules engine) |
| **TShark / Scapy**| *Not installed* | *N/A* | Pure Python Fallback | **Operational Fallback** (`pcap_analyzer.py` uses binary struct decoding for offline PCAP packet inspection) |

---

## 4. Test Suite Health & Stability Audit

- **Total Test Count:** **467 Tests** collected across 32 test files.
- **Pass Rate:** **100% (467 / 467 Passed)** under `QT_QPA_PLATFORM=offscreen`.
- **Runtime:** 38.41 seconds.
- **Root Cause Analysis of Prior Exit Codes (134 / 139):**
  - **Exit Code 139 (SIGSEGV):** In PySide6/Qt6, when widgets containing Chromium/WebEngine processes (such as the xterm.js PTY terminal) or background threads are terminated abruptly during pytest runner teardown, the underlying C++ Qt application context may attempt to destroy font caches or OpenGL contexts after Python has already freed memory.
  - **Mitigation:** In all tests, Qt widgets are isolated via `qtbot.addWidget()` and run in headless offscreen mode (`QT_QPA_PLATFORM=offscreen`). Background threads in tests are strictly joined or run as daemons before the test scope exits.

---

## 5. Feature Gap Analysis for Phase 14

### Gap 1: Unified Vulnerability Assessment Workbench
*Current State:* Assessment tools are split across `Network Discovery` (Nmap), `Web Testing` (c0desec, PTK, Nikto, SQLMap, Gobuster), `Active Directory` (Hydra, Hashcat, Weak Passwords), and `Tools` (diagnostic matrix).  
*Requirement:* A consolidated, single-pane **Vulnerability Assessment Workspace** that lets operators:
1. Select the active assessment engagement.
2. View real-time authorized targets and exclusions with an interactive scope verification badge.
3. Select an installed security tool (Nmap, SQLMap, Nikto, Gobuster, WAFW00F, ZAP, Hydra).
4. Configure validated parameters with an exact command preview.
5. Monitor live sanitized output, execution duration, and progress bar.
6. Automatically populate the unified Findings Table with severity, CVE/CWE, CVSS, and evidence links.
7. Export comprehensive PDF, HTML, Markdown, and JSON reports in one click.

### Gap 2: Metasploit Framework (`msfconsole`) Exploit Validation Architecture
*Current State:* No Metasploit adapter or GUI view exists in the project. `msfconsole` is not installed on the host machine.  
*Requirement:* 
1. Build `modules/exploit/metasploit_adapter.py`:
   - Non-intrusive version and path detection (`msfconsole --version`).
   - Actionable installation guidance when missing (`curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall`).
   - Module metadata queries (`msfconsole -q -x "info <module>; exit"`).
   - Strict target scope and Rules of Engagement verification before any module configuration.
   - Non-destructive execution preview and dry-run validation.
   - Fail-safe mock engine for testing and offline development when `msfconsole` is not installed.
2. Build `desktop/views/exploit_validation_view.py`:
   - Clearly separated from ordinary vulnerability scanning with prominent safety warnings: `⚠️ Authorized Lab & Controlled Exploit Validation Only`.
   - Explicit operator confirmation requirement before any module execution.
   - Never auto-executes exploits or AI-generated commands.

### Gap 3: OWASP ZAP Active Scanning CLI Runner
*Current State:* ZAP integration exists in `zap_adapter.py` but is restricted to importing existing ZAP reports or checking daemon health.  
*Requirement:* Add an active headless baseline execution workflow (`zap.sh -cmd -quickurl <url> ...`) leveraging the installed `/usr/local/bin/zap.sh` binary, with scope validation and output evidence capture.

---

## 6. Phased Implementation Plan for Phase 14

```
Stage 1: Repository Audit & Tool Diagnostics [COMPLETED]
   │
   ▼
Stage 2: Unified Vulnerability Scanner GUI Workbench (desktop/views/vulnerability_scanner_view.py)
   │     - Assessment selector & live scope guard display
   │     - Multi-tool controller (Nmap, SQLMap, Nikto, Gobuster, WAFW00F, ZAP)
   │     - Real-time output streaming, progress indicator, and findings grid
   │
   ▼
Stage 3: Metasploit Exploit Validation Architecture (modules/exploit/metasploit_adapter.py)
   │     - Safe version check, installation guide, module metadata parsing
   │     - Strict fail-closed scope validation and dry-run preview
   │     - High-fidelity unit test suite with mock msfconsole runner
   │
   ▼
Stage 4: Metasploit GUI Integration & Exploit Safety Controls (desktop/views/metasploit_view.py)
   │     - Dedicated "Exploit Validation" tab under Assessment workspace
   │     - Module browser, option parameter validator (RHOSTS, LPORT)
   │     - Operator confirmation dialog & non-destructive execution mode
   │
   ▼
Stage 5: Central Execution & Report Integration Verification
   │     - Associate real scan results with active assessment sessions
   │     - SHA-256 evidence integrity verification
   │     - Multi-format report export (PDF, HTML, MD, JSON)
   │
   ▼
Stage 6: Comprehensive Regression Testing & Phase 14 Validation Report
         - Unit tests for Metasploit adapter & Vulnerability Scanner
         - 100% test suite passing verification (467+ tests)
         - Production of docs/phase14_validation_report.md
```

---

## 7. Mandatory Change Controls & Safety Commitments
- **Zero Git commands:** Never invoke `git commit`, `git push`, `git rebase`, etc.
- **Non-Destructive Backups:** Timestamped backups (`.bak_20261028_phase14_*`) will be created before modifying any existing file.
- **Fail-Closed Scope Enforcement:** No active tool will ever execute against unverified or out-of-scope targets.
- **Zero Simulation Claims:** Tools that are missing (e.g. `msfconsole`, `burpsuite`) will be labeled as "Not Installed / Setup Required", never mocked as working live tools in the operational UI.

---

*Report prepared and validated for Phase 14 Stage 1.*  
*Awaiting User Approval to proceed with Stage 2.*

