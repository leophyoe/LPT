# Development Roadmap: CyberSecuritySuite

This roadmap breaks down the progressive evolution of the platform into measurable, verifiable phases.

---

## Phase 0: Environment & Workspace Verification (Current)
- [x] Inspect local directory, system resources, and existing tools.
- [x] Establish canonical repository structure (`core/`, `modules/`, `desktop/`, etc.).
- [x] Initialize Git repository with safe `.gitignore`.
- [x] Set up Python virtual environment (`.venv`) and dependencies (`PySide6`, `pytest`, `pytest-qt`).
- [x] Draft initial core documentation suite.

---

## Phase 1: Core Data Models & Persistent Project Storage
- [ ] Define SQLite database schema with WAL mode support:
  - Projects (`id`, `name`, `client`, `description`, `created_at`, `status`)
  - Target Scopes (`id`, `project_id`, `target`, `target_type`, `is_authorized`, `notes`)
  - Tool Executions (`id`, `project_id`, `tool_name`, `command`, `exit_code`, `started_at`, `finished_at`, `raw_output_path`)
  - Findings (`id`, `project_id`, `title`, `severity`, `cvss_score`, `affected_asset`, `description`, `remediation`, `status`)
  - Evidence (`id`, `finding_id`, `execution_id`, `file_path`, `sha256_hash`, `timestamp`)
- [ ] Implement database migration and connection management (`storage/db.py`).
- [ ] Write unit tests for storage repositories and models (`tests/test_storage.py`).

---

## Phase 2: Process Execution Engine & Integrated Terminal
- [ ] Implement `ProcessRunner` with asynchronous streaming of stdout and stderr (`terminal/runner.py`).
- [ ] Implement timeout handling, process cancellation, and exit code capture.
- [ ] Implement scope validation guard (`core/scope.py`) enforcing pre-execution checks.
- [ ] Build basic terminal display widget (`desktop/widgets/terminal_view.py`).
- [ ] Write integration tests for command execution, timeouts, and cancellation (`tests/test_runner.py`).

---

## Phase 3: Minimal Desktop GUI Shell (PySide6)
- [ ] Implement main window with responsive navigation sidebar (`desktop/main_window.py`):
  - Dashboard
  - Projects & Scope
  - Network Assessment
  - Web & API Testing
  - Integrated Terminal
  - Findings & Evidence
  - AI Assistant
  - Reports
  - CPENT Learning & Labs
  - Settings
- [ ] Add project creation and selection dialogs.
- [ ] Integrate the terminal panel at the bottom of the workspace.
- [ ] Implement clean dark theme styling.
- [ ] Write GUI tests using `pytest-qt` (`tests/test_ui.py`).

---

## Phase 4: First Security Assessment Workflow (Nmap Adapter)
- [ ] Implement `NmapAdapter` in `modules/network/nmap_adapter.py`:
  - Build safe discovery and port-scan commands (`-sV`, `-O`, `-sC`, etc.).
  - Enforce scope check on target IPs and CIDR ranges.
  - Implement XML and standard output parser (`modules/network/nmap_parser.py`).
- [ ] Convert parsed hosts, open ports, and service banners into structured findings.
- [ ] Save raw XML output into the Evidence Vault with SHA-256 hashes.
- [ ] End-to-end integration test against a local loopback/fixture target.

---

## Phase 5: AI Security Assistant Integration
- [ ] Implement provider-agnostic AI interface (`ai/engine.py`):
  - Support local providers (Ollama / llama.cpp) and remote APIs (OpenAI / Gemini / Anthropic).
- [ ] Implement sensitive data redaction engine (`ai/redactor.py`).
- [ ] Build features:
  - Terminal scan explanation.
  - False-positive detection & triage.
  - Remediation & secure coding advice.
  - Command risk review before execution.
- [ ] Add AI Assistant chat/triage panel in the desktop UI.

---

## Phase 6: Multi-Format Reporting System (Completed)
- [x] Implement report builder supporting HTML, Markdown, and JSON (`reports/builder.py`).
- [x] Create executive summary and technical deep-dive templates.
- [x] Incorporate evidence links, severity distribution charts, and methodology sections.
- [x] Automated validation of generated report outputs (`tests/test_reports.py`).

---

## Phase 7: CPENT-Oriented Learning Platform & Labs
- [ ] Design original, non-infringing curriculum modules mapping to core pentesting domains:
  - Network Penetration Testing & Lateral Movement
  - Active Directory & Kerberos Assessment Concepts
  - Web Application & API Security
  - Pivoting & Double Pivoting in Segmented Networks
  - Privilege Escalation (Linux & Windows)
- [ ] Implement local containerized lab manager using Docker/Podman (`labs/lab_manager.py`).
- [ ] Add AI Tutor mode for guided hints, conceptual explanations, and lab review.
- [ ] Track student completion, practical checklists, and lab report generation.

---

## Phase 8: Module Expansion (Web, Mobile, Code, Cloud)
- [ ] Web Security: OWASP ZAP & HTTP traffic inspection adapter (`modules/web/`).
- [ ] Mobile Security: Android APK static analysis adapter (`modules/mobile/`).
- [ ] Code Security: SAST & secret scanner adapter (`modules/code_security/`).
- [ ] Cloud Posture: Read-only cloud auditor adapter (`modules/cloud/`).
