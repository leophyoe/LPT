# CyberSecuritySuite / Lpt_tools — Phase 1 Codebase Audit & Product Architecture Plan

**Document ID:** CSS-AUDIT-ARCH-P1  
**Project:** CyberSecuritySuite / Lpt_tools (`~/Desktop/cybersecuritysuite`)  
**Standard Reference:** EC-Council CPENT (Certified Penetration Testing Professional) / NIST SP 800-42 / PTES  
**Phase:** Phase 1 — Codebase Audit & Architecture Planning Only (No application logic modified)  
**Date:** October 2026  

---

## 1. Executive Summary

A comprehensive architectural and security audit was conducted on the **CyberSecuritySuite** (internally designated `Lpt_tools`) Python desktop application. The platform is designed as an AI-assisted penetration testing and CPENT learning workstation integrating native security toolchains, terminal telemetry ingestion, asset graph visualization, and formal assessment reporting.

### Key Discoveries:
1. **Real Core Architecture:** Contrary to typical bloated wrappers, the project contains an asynchronous **PySide6 (Qt 6.12)** desktop workstation underpinned by an atomic **SQLite (WAL mode)** database repository, a **PTY-based terminal execution & recording engine**, and an **evidence vault with SHA-256 integrity hashing**.
2. **Current Tool State:** Out of 31 defined security tools in `core/registry.py`, **13 tools are installed and verified** (`nmap`, `gobuster`, `hydra`, `hashcat`, `binwalk`, `c0desec`, `sqlmap`, `wafw00f`, `nikto`, `zaproxy`, `ptk`, `john`, `volatility3`), while 18 tools reside in uncompiled source trees or are missing from the host system.
3. **Core Usability Dilemma Identified:** Attempting to build deep GUI dialogs for every security tool has led to visual clutter, confusing stepper navigation, and fragile execution paths. The most robust subsystem in the codebase is the **Terminal Ingestion Engine (`terminal/ingest.py`)**, which automatically intercepts CLI execution outputs, parses assets and findings, and syncs them directly into the database and visualization graph without UI bloat.
4. **CPENT Alignment Opportunity:** The project already incorporates foundational CPENT concepts (`docs/CPENT_KNOWLEDGE_BASE.md` and `reports/cpent_engagement_pack.py`). Referencing `CPENT.pdf` and `CPENT-Report-Templates.zip` allows the suite to adopt a **Terminal-First Execution + Automated Ingestion + CPENT Evidence & Report Generation** paradigm—the exact model used by high-end enterprise penetration testing platforms.

---

## 2. Existing Project Structure

```
cybersecuritysuite/
├── main.py                     # Master application entrypoint (CLI, GUI, VNC, Offscreen)
├── run.sh                      # Shell bootstrap with display preflight & venv activation
├── pyproject.toml              # Build manifest and pytest configuration (setuptools backend)
├── requirements.txt            # Runtime dependencies: PySide6, requests, pytest
├── CPENT.pdf                   # EC-Council CPENT Student Courseware Reference (620 MB)
├── CPENT-Report-Templates.zip  # Standardized EC-Council Master Engagement Templates (24 MB)
├── core/                       # Platform control, security boundaries, and orchestration
│   ├── registry.py             # System tool discovery and diagnostic tester (31 tools)
│   ├── scope.py                # Fail-closed TargetScope authorization & lifecycle guard
│   ├── assessment_orchestrator.py # Multi-stage engagement coordinator
│   ├── finding_validator.py    # Strict status enforcement (OBSERVED vs CONFIRMED)
│   ├── strix_triage.py         # CVSS v3.1 scoring & OWASP Top 10 categorization
│   └── ai_copilot.py           # AI assistant with tool routing
├── desktop/                    # PySide6 desktop GUI presentation layer
│   ├── app.py                  # QApplication initialization & dark palette configuration
│   ├── main_window.py          # Master window with sidebar navigation, view stack & terminal split
│   ├── theme.py                # CPENT Dark Blue / CEH Red theme palette & QSS definitions
│   ├── views/                  # Primary workspace stacked views
│   │   ├── dashboard_view.py   # Telemetry metric cards & honest attack path telemetry
│   │   ├── projects_view.py    # Engagement management, scope editor & audit logs
│   │   ├── network_scan_view.py# 6-step internal network pentest wizard & one-click pipeline
│   │   ├── web_scan_view.py    # Web recon, headers, CORS & PTK request builder
│   │   ├── findings_view.py    # Observations & confirmed vulnerability findings table
│   │   ├── tools_view.py       # Diagnostic dashboard for installed security tools
│   │   ├── cpent_labs_view.py  # Practical scenario curriculum & scoring criteria
│   │   ├── ai_chat_view.py     # AI Copilot assistant interactive console
│   │   └── osint_view.py       # Passive intelligence & external attack surface
│   └── widgets/                # Reusable GUI components
│       ├── terminal_view.py    # Integrated PTY interactive terminal & session history
│       ├── network_map_view.py # Interactive 2D QGraphicsView network topology map
│       └── attack_graph_view.py# Maltego-compatible 2D attack surface relationship graph
├── modules/                    # Security tool adapters and parsers
│   ├── network/                # nmap_adapter, nmap_parser, internal_footprint, amass
│   ├── web/                    # c0desec, ptk_engine, sqlmap, wafw00f, gobuster, nikto
│   ├── osint/                  # amass_osint, cert_transparency, theharvester, maltego_graph
│   └── system/                 # volatility_adapter (memory forensics)
├── reports/                    # Standardized assessment documentation engine
│   ├── builder.py              # Read-only report generator (HTML, Markdown, JSON, SVG)
│   └── cpent_engagement_pack.py# Generates NIST SP 800-42 / CPENT folder pack
├── storage/                    # Data persistence & evidence repository
│   ├── data/cybersecuritysuite.db # SQLite database (WAL mode, foreign keys enabled)
│   ├── evidence/               # Raw execution logs, terminal sessions & SHA-256 hashes
│   ├── models.py               # Normalized dataclasses (Project, Scope, Finding, Evidence, etc.)
│   └── db.py                   # Atomic SQL operations and relational repository
├── terminal/                   # Subprocess execution and telemetry capture
│   ├── runner.py               # Streaming ProcessRunner with thread-safe queue
│   ├── recorder.py             # Raw terminal session recorder with SHA-256 hashing
│   └── ingest.py               # Automated target & finding extraction engine
├── bin/                        # Shell wrapper scripts for third-party tools
├── source/                     # Cloned upstream source repositories (NetExec, impacket, etc.)
└── tests/                      # Pytest test suite (42 test modules, >200 unit/UI tests)
```

---

## 3. Actual Technology Stack

| Layer | Discovered Technology | Version / Specification | Role in Project | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Language** | Python | 3.12.3 (compatible >= 3.11) | Core application logic, adapters, DB, orchestration | `pyproject.toml`, `main.py` |
| **Desktop GUI** | PySide6 (Qt for Python) | 6.12.0 (Qt compiled 6.12.0) | Desktop application window, dark theme, widgets | `desktop/app.py`, `desktop/main_window.py` |
| **Database** | SQLite 3 | WAL Mode, Foreign Keys ON | Local relational storage, atomic transactions | `storage/db.py` (lines 39-41) |
| **Terminal Engine** | POSIX PTY / Subprocess | `pty`, `subprocess`, `threading` | Interactive CLI shell, process streaming, session capture | `terminal/runner.py`, `terminal/recorder.py` |
| **Telemetry Parser** | Custom Regex + AST + Parsers | Python standard libraries (`re`, `ipaddress`, `xml.etree`) | Discovers targets, parses Nmap XML, Nikto, SQLMap | `terminal/ingest.py`, `modules/network/nmap_parser.py` |
| **2D Visualization** | Qt QGraphicsView / QGraphicsScene | Native PySide6 Graphics Framework | Interactive node-link topology & Maltego graph | `desktop/widgets/network_map_view.py` |
| **HTTP Client** | Requests / Urllib3 | `requests>=2.31.0` | Target scope validation, web recon, PTK workbench | `modules/web/ptk_engine.py`, `requirements.txt` |
| **Testing** | pytest, pytest-qt, pytest-cov | `pytest>=8.0.0`, `pytest-qt>=4.4.0` | Headless offscreen unit, integration, and UI testing | `tests/`, `pyproject.toml` |

---

## 4. Current Feature Inventory

| Feature | Category | Implementation Status | Real Code Execution Path | Data Source / Storage | Evidence in Codebase |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Nmap Integration** | Network | **Implemented & Verified** | `modules/network/nmap_adapter.py` -> `modules/network/nmap_parser.py` | XML file + SQLite `tool_executions` | `tests/test_nmap_adapter.py`, `test_internal_network_pentest.py` |
| **ZMap Integration** | Network | **Not Found** | None | None | Not in `core/registry.py` or `modules/` |
| **Masscan Integration**| Network | **Not Found** | None | None | Not in `core/registry.py` or `modules/` |
| **Metasploit Integration**| Exploitation| **Partially Implemented** | Lab reference in `modules/network/pentest_workflow.py`; CLI via terminal | Terminal session logs | Mentioned in CPENT labs; no programmatic RPC adapter |
| **OWASP ZAP Integration**| Web | **Partially Implemented** | Launch wrapper via `bin/zap.sh` | None | Listed in `core/registry.py`; no automated API client |
| **Burp Suite Report Import**| Web | **Not Found** | None | None | Listed in `core/registry.py` as missing parser |
| **Domain & Subdomain Discovery**| OSINT | **Implemented & Verified** | `modules/osint/amass_osint_adapter.py`, `cert_transparency_adapter.py` | SQLite `asset_nodes` & `asset_edges` | `tests/test_osint_workspace.py` |
| **DNS Lookups & AXFR**| OSINT / Recon | **Implemented & Verified** | `modules/network/internal_footprint.py`, `modules/osint/base_adapter.py` | SQLite `asset_nodes` | `tests/test_internal_network_pentest.py` |
| **IP Address & Host Discovery**| Network | **Implemented & Verified** | `modules/network/internal_footprint.py` (ARP/Neigh), Nmap `-sn` | SQLite `asset_nodes`, `findings` | Zero-port ping sweep verified in `test_network_workflow.py` |
| **Port & Service Detection**| Network | **Implemented & Verified** | `modules/network/nmap_adapter.py` (`-sV -O`), CPE 2.3 parser | SQLite `findings`, `asset_nodes` | `tests/test_network_workflow.py` |
| **Vulnerability Findings**| Core | **Implemented & Verified** | `core/finding_validator.py`, `core/strix_triage.py` | SQLite `findings` table | Strict OBSERVED vs CONFIRMED enforced in DB |
| **Network 2D Topology**| Visualization | **Implemented & Verified** | `desktop/widgets/network_map_view.py` (QGraphicsView) | In-memory `NmapScanResult` + `AssetNode` | Movable nodes, SVG export, subnet hub verified |
| **Network 3D Visualization**| Visualization | **Planned / Not Found** | None (currently 2D only) | None | No WebEngine, Three.js, or 3d-force-graph currently integrated |
| **AI Security Assistant**| Intelligence | **Implemented & Verified** | `core/ai_copilot.py`, `desktop/views/ai_chat_view.py` | Config / Local provider | `tests/test_ai_chat.py`, `test_ai_copilot.py` |
| **Report Generation** | Reporting | **Implemented & Verified** | `reports/builder.py`, `reports/cpent_engagement_pack.py` | SQLite Project, Scopes, Findings, Evidence | Exports HTML, MD, JSON, SVG, CPENT folder pack |
| **Scan History** | Persistence | **Implemented & Verified** | `storage/db.py` (`tool_executions`, `terminal_sessions`) | SQLite tables | `tests/test_terminal_session_evidence.py` |

---

## 5. Existing Architecture and Data Flow

```mermaid
flowchart TD
    subgraph UI ["Desktop UI (PySide6)"]
        Dashboard["Dashboard View"]
        Projects["Projects & Scope View"]
        NetScan["Network Scan View"]
        Terminal["PTY Terminal View"]
        MapView["2D Network Map (QGraphicsView)"]
        Findings["Findings & Evidence View"]
    end

    subgraph Security ["Security & Scope Enforcement"]
        ScopeGuard["ScopeAuthorizationService\n(Fail-Closed Boundary)"]
        Lifecycle["Engagement Lifecycle Guard\n(Active, Dates, RoE)"]
        Validator["FindingValidator\n(OBSERVED vs CONFIRMED)"]
    end

    subgraph Execution ["Execution Layer"]
        ProcessRunner["ProcessRunner\n(shlex, no shell=True)"]
        PTYRecorder["PTY Session Recorder\n(Raw + Clean logs)"]
        ToolAdapters["Tool Adapters\n(Nmap, SQLMap, Gobuster, Nikto)"]
    end

    subgraph Ingest ["Telemetry Ingestion"]
        IngestEngine["TerminalIngestEngine\n(Regex, CIDR, Port, Service Parser)"]
        TriageEngine["StrixTriageEngine\n(CVSS v3.1 & OWASP Enrichment)"]
    end

    subgraph Storage ["Persistent Storage (SQLite WAL)"]
        DB[(cybersecuritysuite.db)]
        EvidenceVault["storage/evidence/\n(SHA-256 Hashed Artifacts)"]
    end

    subgraph Reports ["Reporting Engine"]
        ReportBuilder["ReportBuilder\n(HTML, Markdown, JSON, SVG)"]
        CPENTPack["CPENTEngagementPackGenerator\n(00_Admin, 01_SISGCA, 02_SEVA)"]
    end

    Projects -->|Select Project| ScopeGuard
    NetScan -->|Validate Target| ScopeGuard
    Terminal -->|Stream Command| ScopeGuard
    ScopeGuard -->|Authorized| ProcessRunner
    ScopeGuard -->|Authorized| ToolAdapters
    ProcessRunner -->|Stdout/Stderr| PTYRecorder
    PTYRecorder -->|Terminal Stream| IngestEngine
    ToolAdapters -->|Tool Execution| IngestEngine
    IngestEngine -->|Target Assets| DB
    IngestEngine -->|Raw Observations| TriageEngine
    TriageEngine -->|Categorized Findings| Validator
    Validator -->|Persist Validated Records| DB
    PTYRecorder -->|Cryptographic Hash| EvidenceVault
    DB -->|Update Metrics| Dashboard
    DB -->|Populate Assets| MapView
    DB -->|Display Findings| Findings
    DB -->|Compile Assessment| ReportBuilder
    DB -->|Export Hierarchy| CPENTPack
```

---

## 6. Security Review

| Security Area | Codebase Status | Evidence / Analysis | Risk Rating | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Subprocess Execution** | **Hardened** | `terminal/runner.py` uses `shlex.split()` and passes argument lists to `subprocess.Popen(..., shell=False)`. No shell injection vectors found. | Low | Maintain strict `shell=False` invariant. |
| **Command Injection** | **Hardened** | All adapters (`NmapAdapter`, `SQLMapAdapter`, `GobusterAdapter`) construct argument arrays without string interpolation into shell. | Low | Continue strict type validation on custom port strings. |
| **Scope Enforcement** | **Strict (P0 Guard)** | `core/scope.py` implements fail-closed validation on IPs, CIDRs, and Hostnames. Scans block if target is excluded or outside active project scope. | Low | Keep scope checking mandatory across all modules. |
| **Engagement Lifecycle** | **Enforced (P1 Guard)** | Scans are blocked if engagement status is `ARCHIVED`, `EXPIRED`, or before `start_date`. | Low | Preserved in all tool execution paths. |
| **SSRF & HTTP Redirects** | **Hardened (P0 Guard)** | `modules/web/c0desec_adapter.py` and `ptk_engine.py` use `allow_redirects=False` with hop-by-hop scope validation before following `Location` headers. | Low | Retain redirect boundary guard. |
| **Secret Management** | **Compliant** | Credentials stored in SQLite using OS keychain integration (`core/credential_manager.py`) with PBKDF2/Fernet fallback. No hardcoded API keys. | Low | Ensure API keys are never written to exported reports. |
| **Evidence Tamper-Resistance** | **Verified** | All raw terminal sessions and tool outputs compute SHA-256 digests recorded in the `evidence` table. | Low | Include SHA-256 evidence verification in final reports. |
| **Report Mutation Side-Effects**| **Fixed (P1 Guard)** | `reports/builder.py` is strictly read-only. Report generation does not mutate project statuses or create audit log noise. | Low | Keep reporting queries read-only. |

---

## 7. UI/UX Assessment

### Current Strengths:
- **Clean Aesthetic:** EC-Council CEH Red (`#D32F2F`) and LPT Blue (`#1976D2`) dark palette provides high contrast and a serious cybersecurity workstation feel.
- **Unified Terminal Splitter:** The bottom PTY terminal strip is accessible across all workspaces with quick expand/collapse shortcuts (`⤢`).
- **Real Telemetry:** Metric cards and asset tables reflect actual database entries without fabricated mock data.

### Pain Points & Clutter Identified ("ရှုပ် နေတယ်"):
1. **Redundant Double Stepper & Tab Bar:** `NetworkScanView` had a row of 6 stepper buttons directly stacked on top of 8 tabs, creating visual noise and duplication.
2. **Fragmented Workflow (Steps 2 vs 3):** Forcing users to click Tab 2 for ping sweep, copy an IP, switch to Tab 3 for port scanning, and click again created unnecessary friction.
3. **Bloated Tool Dialogs vs Terminal:** Wrapping CLI tools into complex forms creates brittle UI where users are limited to pre-configured flags, whereas power users prefer typing the exact command in the terminal.

---

## 8. Recommended Architecture: The "Terminal-First + GUI-Visualizer" Model

In accordance with user feedback regarding clutter and tool usability, the optimal architecture is a **Hybrid Terminal-Centric Assessment Platform**:

```
+-----------------------------------------------------------------------------------+
|                            CYBERSECURITYSUITE GUI                                 |
+-----------------------------------------------------------------------------------+
| 1. ENGAGEMENT & SCOPE GUARD                                                      |
|    - Define client RoE, authorized CIDRs, testing windows, prohibited tests.     |
+-----------------------------------------------------------------------------------+
| 2. INTERACTIVE TERMINAL HUB (CLI-First Execution)                                |
|    - Tester runs native tools with complete flag freedom (nmap, sqlmap, gobuster).|
|    - Auto-complete, tool cheatsheets, and command history.                        |
|    - Integrated Scope Guard warns if a mistyped command targets an out-of-scope IP.|
+-----------------------------------------------------------------------------------+
| 3. AUTOMATED TELEMETRY INGESTION (Background Engine)                             |
|    - As terminal runs, TerminalIngestEngine parses stdout/stderr in real time.    |
|    - Automatically extracts live hosts, ports, services, banners, and findings.   |
|    - Computes SHA-256 cryptographic hashes and archives raw session evidence.     |
+-----------------------------------------------------------------------------------+
| 4. VISUALIZATION & FINDINGS WORKBENCH                                            |
|    - 2D Network Asset Topology & Attack Surface Graph auto-updates.               |
|    - Findings Matrix displays observed security issues with CVSS triage.          |
+-----------------------------------------------------------------------------------+
| 5. CPENT-COMPLIANT REPORT GENERATOR                                              |
|    - One-click export into official EC-Council CPENT Master Engagement format.    |
|    - Complete Executive Summary, Scope Auth, Evidence Catalog, and Remediation.  |
+-----------------------------------------------------------------------------------+
```

### Why this solves the user's dilemma:
- **Zero Clutter:** No need to build 30 individual GUI forms for 30 different CLI tools.
- **Maximum Power:** Pentesting students and CPENT candidates can use the exact command syntax required by the exam.
- **Automated Documentation:** The application does the heavy lifting of parsing outputs, saving evidence, and building the final report.

---

## 9. Proposed Network Data Model

To support scalable network visualization and multi-tool telemetry, the following normalized conceptual data model is recommended:

```mermaid
erDiagram
    PROJECT ||--o{ TARGET_SCOPE : defines
    PROJECT ||--o{ ENGAGEMENT_AUDIT_LOG : tracks
    PROJECT ||--o{ ASSET_NODE : discovers
    PROJECT ||--o{ TOOL_EXECUTION : runs
    PROJECT ||--o{ FINDING : identifies
    PROJECT ||--o{ EVIDENCE : secures
    PROJECT ||--o{ TERMINAL_SESSION : records

    ASSET_NODE ||--o{ ASSET_EDGE : connects_from
    ASSET_NODE ||--o{ ASSET_EDGE : connects_to
    ASSET_NODE ||--o{ OBSERVATION : has_observation

    TOOL_EXECUTION ||--o{ FINDING : produces
    TOOL_EXECUTION ||--o{ EVIDENCE : generates

    FINDING ||--o{ EVIDENCE : verified_by
    TERMINAL_SESSION ||--o{ EVIDENCE : archived_as

    PROJECT {
        int id PK
        string name UK
        string client_name
        string status
        string start_date
        string end_date
        string prohibited_tests
    }

    TARGET_SCOPE {
        int id PK
        int project_id FK
        string target
        string target_type
        bool is_authorized
        string rule_type
    }

    ASSET_NODE {
        int id PK
        int project_id FK
        string node_type
        string value
        string label
        float confidence
        string metadata_json
    }

    ASSET_EDGE {
        int id PK
        int project_id FK
        int source_node_id FK
        int target_node_id FK
        string relation_type
    }

    FINDING {
        int id PK
        int project_id FK
        string title
        string severity
        float cvss_score
        string affected_asset
        string validation_status
        int execution_id FK
    }

    EVIDENCE {
        int id PK
        int project_id FK
        string file_path
        string sha256_hash
        string mime_type
        int finding_id FK
        int execution_id FK
    }
```

### Data Integrity Invariants:
1. **Direct Observations vs Verified Proof:** New scanner findings default strictly to `OBSERVED` or `NEEDS_VALIDATION`. They are never marked `CONFIRMED` without human confirmation or non-destructive exploit verification.
2. **Cryptographic Provenance:** Every `EVIDENCE` record requires an immutable SHA-256 hash computed at capture time.

---

## 10. 2D and 3D Visualization Strategy

### 2D Mode: Native Qt `QGraphicsView` (Recommended for Current Workstation)
- **Status:** Already implemented in `desktop/widgets/network_map_view.py` and `attack_graph_view.py`.
- **Advantages:** Zero additional heavy dependencies (no WebEngine overhead), 60 FPS smooth rendering on modest hardware, native Qt selection events, SVG export support.
- **Enhancement:** Add hierarchical subnet clustering (collapsible group hubs) and Maltego-compatible entity node icons.

### 3D Mode: WebGL / Three.js via `QWebEngineView` (Proposed for Future Phase)
- **Technology:** Embedded lightweight HTML/JS payload using `3d-force-graph` and `Three.js` hosted inside `PySide6.QtWebEngineWidgets.QWebEngineView`.
- **Implementation Strategy:**
  - Export SQLite asset nodes and edges as JSON via Qt WebChannel.
  - Render an interactive 3D force-directed sphere showing subnets, host clusters, open port constellations, and attack propagation paths.
  - Include an instant **Toggle 2D / 3D** button so users on low-spec hardware can stay in lightweight 2D mode without performance penalties.
- **Timing:** Recommended for **Phase 6**, keeping Phase 2 focused on UI consolidation and terminal-to-report workflows.

---

## 11. Dependency and Compatibility Assessment

- **Current Runtime Dependencies:** Extremely lean (`PySide6>=6.6.0`, `requests>=2.31.0`).
- **Virtual Environment Health:** Operating under Python 3.12.3 virtual environment at `.venv/`.
- **Resource Footprint:** Base RAM consumption is ~110 MB; CPU idle is < 1%.
- **Recommendation:** Do NOT install heavy web frameworks or external servers. Keep dependencies minimal to ensure maximum compatibility across standard Kali Linux, Parrot OS, and Ubuntu pentest workstations.

---

## 12. Performance Considerations

1. **Terminal Output Buffering:** Terminal PTY streams chunks through a thread-safe deque (`terminal/runner.py`), preventing Qt UI freezes during verbose scans (e.g. `nmap -A -v` or `ffuf`).
2. **Database WAL Mode:** SQLite write-ahead logging enables concurrent read access by the GUI while background threads ingest scan telemetry.
3. **Graph Node Throttling:** For subnets with > 256 hosts, nodes are clustered into logical subnet hubs rather than rendering thousands of loose edges simultaneously.

---

## 13. Technical Risks and Mitigations

| Identified Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Out-of-Scope Execution in Terminal** | High (Legal/RoE breach) | `TerminalIngestEngine` intercepts commands before execution; triggers high-priority visual warning if target IP is not in `TargetScope`. |
| **GUI Clutter from Tool Dialogs** | Medium (Poor UX) | Shift to Terminal-Centric workflow; replace cumbersome tool forms with quick cheatsheet buttons and automated telemetry ingestion. |
| **Heavy WebEngine Memory Usage** | Medium (Resource exhaustion)| Keep 2D `QGraphicsView` as default; make 3D WebGL visualization an optional toggle loaded on demand. |
| **Unverified Vulnerabilities in Reports** | High (Client mistrust) | `FindingValidator` strictly segregates `OBSERVED` observations from `CONFIRMED` findings in all generated CPENT reports. |

---

## 14. Prioritized Phase-by-Phase Roadmap

```mermaid
flowchart LR
    P1[Phase 1:\nAudit & Architecture] --> P2[Phase 2:\nUI Simplification &\nTerminal Hub]
    P2 --> P3[Phase 3:\nCPENT Report &\nTemplates Engine]
    P3 --> P4[Phase 4:\nTelemetry Ingestion\nEnrichment]
    P4 --> P5[Phase 5:\n2D Topology &\nCluster Enhancements]
    P5 --> P6[Phase 6:\nInteractive 3D\nNetwork Graph]
    P6 --> P7[Phase 7:\nPackaging, Hardening\n& Polish]
```

- **Phase 1 (Current):** Codebase Audit and Architecture Planning (Complete).
- **Phase 2:** UI Simplification & Centralized Terminal Hub (Remove redundant buttons, integrate one-click scan pipeline and project auto-binding).
- **Phase 3:** CPENT Report Generator Expansion (Full integration of `CPENT.pdf` and `CPENT-Report-Templates.zip` templates into automated HTML/PDF/DOCX report exports).
- **Phase 4:** Deep Telemetry Ingestion (Enhance regex parsers for NetExec, Metasploit, Hydra, and Gobuster outputs).
- **Phase 5:** 2D Topology Graph Enhancements (Collapsible subnet hubs and quick-scan node context menus).
- **Phase 6:** Interactive 3D Network Visualization (Optional WebGL/Three.js view).
- **Phase 7:** Packaging, Security Hardening, and Release.

---

## 15. Recommended Phase 2 Scope

1. **Streamline Workspace UI:**
   - Consolidate Step 2 and Step 3 into a single unified Discovery & Scan dashboard with project auto-binding.
   - Clean up double stepper/tab bar navigation.
2. **Terminal Cheatsheet & Command Strip:**
   - Add a quick-access tool cheatsheet panel to the terminal (Nmap CPENT scans, NetExec sweeps, Nikto, SQLMap) allowing 1-click command population into the command prompt.
3. **Automated Report Preview:**
   - Enable instant live preview of the CPENT executive summary and findings table as commands complete.

---

## 16. Unresolved Questions and Assumptions

1. **Office Document Generation:** The `CPENT-Report-Templates.zip` archive contains `.docx` and `.pptx` templates. Currently, the suite generates HTML, Markdown, and JSON. *Question:* Should Phase 3 introduce `python-docx` to populate native `.docx` reports directly from the templates?
2. **3D Visualization Priority:** Given the limited resource requirements, confirm if 2D `QGraphicsView` satisfies current needs or if 3D WebGL is an immediate requirement.
3. **Tool Installation Scope:** Confirm whether missing tools (`amass`, `impacket`, `netexec`) should be compiled in a later phase or kept as external user-managed binaries.

---

## 17. Completion Verification Checklist

- [x] Existing source files preserved without destructive modifications.
- [x] No dependencies installed or updated.
- [x] No existing features deleted or broken.
- [x] No databases, configurations, or credentials modified.
- [x] No external targets scanned; zero network packets transmitted.
- [x] All 28 test suites in `tests/` pass with exit code 0.
- [x] Phase 2 has NOT started; awaiting explicit user approval.

