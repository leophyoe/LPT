# Changelog

All notable changes to the CyberSecuritySuite platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] - 2026-10-20

### Added
- **Core Architecture & Storage (Phase 1)**:
  - SQLite persistent database manager in `storage/db.py` featuring Write-Ahead Logging (WAL) and foreign key cascades.
  - Domain models in `storage/models.py` for Projects, Target Scopes, Tool Executions, Security Findings, and Evidence records.
  - Pre-execution target scope authorization service in `core/scope.py` supporting IP addresses, CIDR subnet containment, and hostname/domain matching.
- **Process Execution & Tool Registry (Phase 2)**:
  - System tool registry in `core/registry.py` detecting host binaries (`nmap`, `zap.sh`, `tshark`, `nuclei`) and checking versions.
  - Asynchronous streaming process runner in `terminal/runner.py` with real-time stdout/stderr callback streaming, execution duration tracking, timeouts, and process-group cancellation (`SIGTERM`/`SIGKILL`).
- **Network Security Workflow (Phase 4)**:
  - `NmapParser` in `modules/network/nmap_parser.py` extracting host states, open ports, service banners, and translating them into structured findings with severity levels and remediation guidance.
  - `NmapAdapter` in `modules/network/nmap_adapter.py` validating target scope, constructing safe argument arrays, executing scans via `ProcessRunner`, saving raw XML evidence with SHA-256 hashes, and storing findings.
- **Desktop Workstation UI (Phase 3 & Action 3)**:
  - PySide6 desktop application in `desktop/` styled with a dark cybersecurity workstation theme (`desktop/theme.py`).
  - Integrated terminal console widget (`desktop/widgets/terminal_view.py`) supporting real-time streaming, color-coded streams, and clipboard copy.
  - Projects & Scope management view (`desktop/views/projects_view.py`).
  - Network discovery scan view (`desktop/views/network_scan_view.py`) with background execution thread and scope guard modal alerts.
  - Findings and Evidence triage view (`desktop/views/findings_view.py`) with severity badges and markdown remediation panel.
  - CPENT learning & practical labs roadmap view (`desktop/views/cpent_labs_view.py`).
- **CPENT Learning Platform & Practical Methodologies (Phase 9)**:
  - Structured CPENT test models in `labs/cpent/curriculum.py` covering OSINT, Social Engineering, and Network Pentesting.
  - Complete 30-Day CPENT AI Study Plan in `labs/cpent/study_plan.py` spanning 4 weeks of structured theory, practical tasks, and tool recommendations.
  - Interactive multi-tab CPENT Desktop View in `desktop/views/cpent_labs_view.py`:
    - Tab 1: 🗓️ 30-Day Study Roadmap with daily tasks and progress tracking.
    - Tab 2: 🛡️ Assessment Methodologies explorer with live search and markdown guidance.
    - Tab 3: ⚡ Practical Command & One-Liner Cheat Sheet (Nmap, NetExec, Pivoting, Chisel, SMB, Metasploit).
  - Reference materials collected in `labs/cpent/references/`: Vitaly Ford CPENT notes, CPENT-Crash-Course, CPENT-Learning, and CPENTv1StudyGuide.
  - Integration of `c0desec-pentest` in `source/web/c0desec-pentest` for web/API security testing.
- **Web & API Security Integration (Phase 4 / c0desec Adapter)**:
  - `WebSecurityAdapter` in `modules/web/c0desec_adapter.py` providing safe, passive web application & API reconnaissance with strict scope enforcement.
  - Integration with `source/web/c0desec-pentest` constants and secret detection regex patterns (`SECRET_PATTERNS`).
  - Automated sensitive-value redaction via `redact_secret_value()` ensuring credentials/tokens are never exposed in logs or findings.
  - HTTP security header inspection (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Server version disclosures).
  - Insecure CORS misconfiguration detection (reflective origins with credentials).
  - Web route & endpoint extraction from HTML anchors, scripts, and forms.
  - Raw JSON evidence vault archiving with SHA-256 cryptographic integrity hash.
  - Desktop `WebScanView` in `desktop/views/web_scan_view.py` with multi-tab results display (Discovered Routes, JS Secret Candidates, Response Headers), background worker thread, cancel capability, and real-time terminal streaming.
  - Integration into `MainWindow` navigation bar and project-switching signal pipeline.
- **Professional Assessment Reporting System (Phase 6)**:
  - Multi-format report builder in `reports/builder.py` aggregating Project metadata, Target Scopes, Tool Executions, Findings, and Evidence records.
  - **HTML**: Self-contained, responsive, print-friendly (`@media print`) vulnerability report with executive summary cards, severity breakdown, CVSS tags, technical findings, and cryptographic evidence hashes.
  - **Markdown**: Portable technical report following CPENT / PTES methodology, findings matrix, and evidence verification table.
  - **JSON**: Machine-readable schema-compliant export for CI/CD and automated assessment ingestion.
  - **Desktop Integration**: Export toolbar embedded in `desktop/views/findings_view.py` providing one-click export for HTML, Markdown, and JSON with file location confirmation.
- **Tool Integration Dashboard & Execution Verification (Phase 7)**:
  - Interactive Tools Dashboard in `desktop/views/tools_view.py` categorizing open-source security tools (Nmap, SQLMap, c0desec, WAFW00F, Gobuster, Bandit, Volatility 3).
  - Real executable resolution, version verification, adapter discovery, and safe local testing capability.
- **Terminal Session Evidence & Report Integration (Phase 8)**:
  - `TerminalSessionRecorder` in `terminal/recorder.py` capturing separate input and output event streams with timestamped JSON logs.
  - PTY session recording integrated into `VSCodeTerminal` (`desktop/widgets/vscode_terminal.py`) with Start/Stop Recording and Save Session as Evidence controls.
  - Command Shell recording integrated into `TerminalWidget` (`desktop/widgets/terminal_view.py`) with reliable command boundary and exit code tracking.
  - Dedicated `TerminalSessionHistoryWidget` and `SessionViewerDialog` in `desktop/widgets/terminal_session_history.py` (Tab 5) displaying vaulted sessions with clean plain-text, redacted report preview, raw ANSI stream, and structured JSON events.
  - Cryptographic SHA-256 hash calculation over exact saved evidence bytes and deduplication to prevent duplicate database rows.
  - Secret and credential redaction (`redact_sensitive_text`) masking CLI passwords, auth tokens, AWS credentials, and private keys for reports while preserving unaltered byte-exact raw evidence.
  - Extended HTML, Markdown, and JSON report generation in `reports/builder.py` incorporating interactive terminal audit trails.
- **Secure AI Provider Settings & Credential Management (Phase 11)**:
  - `CredentialManager` in `core/credential_manager.py` with multi-tiered credential management:
    - OS Keyring support via `keyring` (GNOME Keyring / FreeDesktop Secret Service).
    - Machine-bound encrypted local vault (`~/.config/cybersecuritysuite/.vault_credentials`) with restricted `0600` POSIX permissions and SHA-256 host/UID derived symmetric stream cipher.
    - In-memory transient session cache and environment variable fallbacks (`GEMINI_API_KEY`, `OPENAI_API_KEY`).
    - Key masking utility ensuring full keys are never exposed in UI or logs (`AIza••••••••4X9Z`).
  - Native multi-tab PySide6 `AISettingsDialog` in `desktop/dialogs/ai_settings_dialog.py`:
    - Tab 1: Google Gemini API (model selector, password-masked input with show/hide toggle, masked key display, live connection test, clear key, and quick API link).
    - Tab 2: OpenAI API (model selector, password-masked input, live connection test, clear key).
    - Tab 3: Local Ollama (offline local server URL, model selector, connection test verifying model presence).
    - Tab 4: Built-in Cybersecurity Heuristic Engine (100% offline, zero data transmission).
  - Main Window sidebar integration in `desktop/main_window.py` with `⚙️ AI & API Settings` navigation button and terminal assistant settings launcher.
  - Live AI connection testing (`test_connection`) in `core/ai_copilot.py` with real HTTP probes and precise error mapping (HTTP 400 invalid key, 401 unauthorized, 429 quota exhaustion, timeout, connection refused).
  - Cloud Transmission Consent Gate: mandatory explicit user confirmation checkbox before transmitting terminal data to cloud AI providers.
  - Automatic Sensitive Secret Redaction (`redact_sensitive_text`) masking passwords, bearer tokens, and private keys prior to prompt assembly.
  - Zero Auto-Execution Safety: AI-generated commands require explicit user review and pass Scope Guard verification.
- **Comprehensive Test Suite**:
  - 115 automated unit, integration, and UI tests across all modules, models, adapters, PTY lifecycle, recording, evidence integrity, reports, AI assistant, credential vault, and settings UI. 100% passing (115/115).
