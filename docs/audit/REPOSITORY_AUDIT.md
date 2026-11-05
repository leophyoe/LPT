# LPT Workstation — Phase 0: Repository Audit Report
**Document ID:** `docs/audit/REPOSITORY_AUDIT.md`  
**Audit Date:** 2026-11-05  
**Auditor:** Senior Software Architect & Lead Security Engineer  
**Status:** COMPLETED — READ-ONLY BASELINE AUDIT  

---

## 1. Executive Summary

This repository audit provides an exhaustive, read-only architectural baseline of the **LPT (CyberSecuritySuite)** penetration testing workstation. The codebase is a specialized hybrid application integrating **Professional Penetration Testing Workstation capabilities**, an **AI-Assisted Security Assessment Platform**, and a **Practical CPENT Learning and Lab Platform** implemented in **Python 3.12** and **PySide6**.

### Key Baseline Metrics
* **Total Python Source Files:** 142 modules (excluding virtual environment and external source clones).
* **Test Suite Status:** **744 passed**, 0 failed, 60 deprecation warnings (117.45s runtime).
* **Git Remote:** `https://github.com/leophyoe/LPT.git` (branch `main`).
* **Active Working Tree:** Clean (zero uncommitted changes).
* **Database State:** SQLite 3 with WAL enabled; `c8d8aa9c0cb6a66682e678d2e3b5762df9086cffc43457ba489541e1ff7a7143`. `PRAGMA integrity_check;` returned `ok`.

---

## 2. Directory Structure & Functional Layout

```text
/home/leo/Desktop/cybersecuritysuite/
├── ai/                     # Multi-provider AI abstractions and future provider modules
├── bin/                    # Local helper wrappers and binary integrations (nmap, amass, etc.)
├── core/                   # Application domain services, scope guard, registry, copilot, correlation
│   ├── analysis/           # Historical comparison and temporal analysis
│   ├── correlation/        # Cross-tool finding & asset service correlator
│   ├── enrichment/         # CVE, CVSS, and intelligence enrichment engines
│   └── parsers/            # Universal normalized models and scanner parsers
├── desktop/                # PySide6 desktop GUI implementation
│   ├── dialogs/            # Modal preview, settings, and scoping dialogs
│   ├── resources/          # WebGL 3D HTML, static assets, and QSS style sheets
│   ├── views/              # Primary workspace views (Assets, Scans, Reports, Projects, OSINT)
│   └── widgets/            # Reusable UI widgets (2D Map, 3D WebGL Map, Terminals, Inspectors)
├── docs/                   # Architectural blueprints, methodology guides, and audit logs
│   └── audit/              # Phase 0 formal audit deliverables
├── labs/                   # CPENT hands-on curriculum, challenge modules, and exam simulation
├── modules/                # Specialized domain execution modules & tool adapters
│   ├── academy/            # CPENT Academy progress tracking
│   ├── code_security/      # Static code analysis (Bandit, AST visitor)
│   ├── crypto/             # TLS/SSL cipher, protocol & certificate security analyzer
│   ├── identity/           # Active Directory LDAP / Kerberos live enumerator
│   ├── iot/                # Embedded firmware and hardware security analyzer
│   ├── network/            # Nmap, Amass, Nuclei adapters, socket scanner, PCAP analyzer
│   ├── orchestration/      # Sn1per multi-tool automated chain orchestrator
│   ├── osint/              # DNS resolver, RDAP client, CT harvester, Maltego graph
│   ├── system/             # Hydra, John, Hashcat, Volatility 3 memory forensics
│   ├── tools/              # Offline hash identification and rainbow table lookup
│   ├── vuln/               # Active vulnerability verifier and scanner
│   ├── web/                # Burp, OWASP ZAP, SQLMap, Nikto, Gobuster, ffuf, WAFW00F, PTK
│   └── wireless/           # 802.11 Wi-Fi PCAP analyzer and security auditor
├── reports/                # Report generation engines (HTML, Markdown, JSON, PDF via Qt PDF)
├── source/                 # Local source clones for offline tool building and reference
├── storage/                # SQLite persistent storage, migrations, and raw evidence vault
│   ├── data/               # Production database (`cybersecuritysuite.db`)
│   └── evidence/           # Vaulted raw ANSI terminal sessions, logs, and screenshots
├── terminal/               # PTY interactive execution, command streaming, and session recording
└── tests/                  # Pytest automated verification suite (744 unit, integration, and GUI tests)
```

---

## 3. Architecture Component Breakdown

### 3.1 GUI & Presentation Layer (`desktop/`)
* **Framework:** PySide6 6.12.0 (Qt 6.12.0) with Qt Widgets, Qt Graphics View, and Qt WebEngine.
* **Navigation Architecture:** Two-tiered navigation:
  1. Top-level methodology selector (`MainWindow` view stack): Scope & Projects, Security Workspace (Network, Web, OSINT, AD, Wireless, Code), Findings & Reporting, and CPENT Labs.
  2. Context-sensitive sidebar (`SidebarNav`): Collapsible project-first workflow navigation.
* **Terminal Integration:** Embedded bottom dock widget (`TerminalWidget`) combining:
  * Tab 1: Real interactive Linux pseudo-terminal via PTY + xterm.js (`VSCodeTerminal`).
  * Tab 2: Managed command console with execution history and streaming output.
  * Tab 3: Structured application and tool execution logs.
  * Tab 4: AI Copilot analysis assistant.
  * Tab 5: Cryptographic Evidence Vault with integrity checking and session ingestion.

### 3.2 Core Domain & Business Logic (`core/`)
* **Scope Guard (`core/scope.py`):** Strictly enforces fail-closed authorization. Evaluates target IP addresses, CIDR ranges, domain wildcards, and explicit exclusion rules. Discovered targets outside authorized scope cannot be scanned or auto-imported.
* **Tool Registry (`core/registry.py`):** Maintains metadata for 33 assessment tools, discovering binaries across system PATH and local fallback directories (`bin/`).
* **Execution Service (`core/execution_service.py`):** Structured subprocess execution manager capturing return codes, stdout, and stderr with timeouts and execution tracking.
* **Asset Inventory Service (`core/asset_inventory.py`):** Normalizes scanner results into relational `AssetNode` and `AssetEdge` graphs.

### 3.3 Storage Layer (`storage/`)
* **Database Engine:** SQLite 3 in Write-Ahead Logging (WAL) mode (`cybersecuritysuite.db`).
* **Entity Models (`storage/models.py`):** `Project`, `TargetScope`, `AssetNode`, `AssetEdge`, `Finding`, `Evidence`, `ToolExecution`, `TerminalSessionRecord`, `EngagementAuditLog`, `AssessmentPlan`, and `Observation`.
* **Integrity Features:** Cryptographic SHA-256 evidence hashing, automated audit logging, idempotent upserts via `ON CONFLICT` constraints, and strictly isolated project partitioning.

### 3.4 AI Copilot Layer (`core/ai_copilot.py`)
* **Architecture:** 2,152 lines of multi-provider integration supporting Built-in Offline Heuristics, Local Ollama (`llama3`, `deepseek-r1`), Google Gemini API, OpenAI API, DeepSeek API, and Anthropic API.
* **Security Guardrails:** Automated credential management via `core/credential_manager.py`, pre-flight scope validation, and mandatory outbound secret redaction (`terminal/recorder.py::redact_sensitive_text`).

### 3.5 Visualization Layer (`desktop/widgets/` & `desktop/resources/`)
* **2D Network Topology:** Native Qt `QGraphicsView` (`desktop/widgets/network_map_view.py`) featuring subnet radial positioning, bezier connection curves, gateway clustering, and interactive host inspection.
* **3D Network Mesh:** Embedded WebGL / Three.js view (`desktop/widgets/webgl_3d_network_view.py` & `desktop/resources/visualization/3d_map.html`) utilizing Qt WebEngine with bi-directional `QWebChannel` synchronization.

---

## 4. Code Quality & Test Suite Assessment

* **Test Execution Summary:** All **744 tests** pass cleanly with 0 failures.
* **Warnings Identified:** 60 warnings, primarily related to deprecated `ssl.TLSVersion.TLSv1` / `TLSv1_1` compatibility constants in `tests/test_tls_security_analyzer.py` and `modules/vuln/verifier.py`.
* **Code Smells & Debt:**
  1. Monolithic files in need of modular decomposition (`core/ai_copilot.py` at 2,152 lines; `reports/builder.py` at 2,932 lines; `desktop/widgets/topology_designer.py` at 2,820 lines).
  2. Backup files (`*.bak_*`) scattered across source directories from prior repair phases; should be archived into `.archive/`.
  3. Hardcoded CLI wrappers in `bin/` rather than dynamic tool environment resolution.

---

## 5. Architectural Findings & Verdict

The repository possesses a mature, high-functioning core architecture. The foundational modules for CLI-to-GUI pipelining, scope enforcement, terminal session recording, SQLite persistence, and 2D/3D visualization are completely functional and verified by 744 passing tests.

