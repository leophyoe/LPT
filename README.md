# CyberSecuritySuite (Working Codename)

> **AI-Assisted Modular Desktop Penetration Testing & CPENT Learning Platform**

---

## 1. Project Overview

**CyberSecuritySuite** is an extensible, modular cybersecurity desktop platform built on Ubuntu/Linux using **Python** and **PySide6**. It is designed to combine professional penetration testing capabilities, an integrated terminal, AI-assisted security analysis, evidence and findings management, professional multi-format reporting, and a dedicated, original learning platform for the **EC-Council Certified Penetration Testing Professional (CPENT)** certification.

This project is built from the source-code level up—not as a simple dashboard wrapping random CLI tools, but as a cohesive architecture with structured schemas, verified execution controls, and reproducible data workflows.

---

## 2. Key Capabilities

- **Modular Security Adapters**: Structured integrations for network discovery, web application security, API testing, mobile (Android/iOS) analysis, system auditing, cloud posture, and reverse engineering.
- **Controlled Process Execution Engine**: Streaming stdout/stderr into an integrated terminal, capturing exit codes, timestamps, and versions with cancellation and strict timeout enforcement.
- **Target Scope & Authorization Enforcement**: Strict pre-execution scope validation ensuring only authorized targets and networks can be scanned or tested.
- **AI Security Assistant**: Contextual interpretation of scan outputs, false-positive triage, correlation of findings, and remediation suggestions without sending unredacted credentials or executing unauthorized actions.
- **Structured Findings & Evidence Management**: Standardized findings schema (CVSS-compatible) paired with cryptographic evidence hashing, reproduction steps, and audit logs.
- **Multi-Format Professional Reporting**: Executive and Technical assessment reports in HTML, PDF, Markdown, JSON, and CSV, plus an original CPENT methodology-and-evidence report generated from persisted assessment records.
- **Original CPENT Learning Platform**: Original, authorized curriculum modules, intentional local lab environments (Docker/Podman), progress tracking, and AI tutoring for CPENT exam preparation.

---

## 3. Architecture Overview

```text
User / Student
      │
      ▼
┌────────────────────────────────────────────────────────┐
│             Desktop UI Layer (PySide6)                 │
│  - Project Workspace     - Integrated Terminal         │
│  - Findings & Evidence   - CPENT Learning & Labs       │
│  - AI Security Assistant - Settings & Scope            │
└─────────────────────────┬──────────────────────────────┘
                          │
      ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Core Services│   │Execution Eng.│   │  AI Service  │
│ - Projects   │   │ - Tool Reg.  │   │ - Redaction  │
│ - Scope Auth │   │ - Terminal   │   │ - Triage/Exp.│
│ - Findings   │   │ - Timeouts   │   │ - Providers  │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│Storage Engine│   │Output Parsers│   │Reports & Labs│
│ - SQLite     │   │ - JSON/XML   │   │ - HTML/MD/JSON│
│ - Evidence   │   │ - SARIF/Raw  │   │ - Lab Manager│
└──────────────┘   └──────────────┘   └──────────────┘
```

---

## 4. Repository Layout

```text
CyberSecuritySuite/
├── core/             # Application services, orchestration & scope authorization
├── modules/          # Tool adapters (Nmap, ZAP, etc.) & output parsers
├── desktop/          # PySide6 user interface, widgets, and themes
├── terminal/         # Integrated terminal runner, process streamer & PTY
├── ai/               # AI providers, prompt templates & data redaction
├── storage/          # SQLite database models, migrations & evidence store
├── reports/          # Report generators (HTML, Markdown, JSON) & templates
├── labs/             # Original CPENT learning modules & lab configurations
├── source/           # Upstream third-party source repos (isolated & ignored)
│   ├── network/
│   ├── web/
│   ├── mobile/
│   ├── system/
│   ├── wireless/
│   ├── cloud/
│   ├── code_security/
│   ├── reverse_engineering/
│   └── vulnerability/
├── docs/             # Architecture, security model, and roadmap documentation
├── licenses/         # License inventory and component notices
├── third_party/      # Approved external dependencies and reference files
├── tests/            # Automated unit, integration, parser, and UI tests
├── scripts/          # Developer tooling and automation scripts
├── pyproject.toml    # Python project configuration and dependencies
└── requirements.txt  # Core runtime and test requirements
```

---

## 5. Getting Started (Ubuntu Linux)

### Prerequisites
- Ubuntu 22.04 LTS or 24.04 LTS (x86_64)
- Python 3.11+ (`python3-venv`, `python3-pip`)
- Git

### Installation
```bash
# Clone or navigate to the repository
cd ~/Desktop/cybersecuritysuite

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Running Tests
```bash
source .venv/bin/activate
pytest
```

---

## 6. Security, Ethics, and Authorization Disclaimer

This software is strictly intended for **authorized penetration testing, defensive security assessments, research, and educational purposes**. 

- Never perform security assessments against any system, network, or domain without explicit, written authorization from the system owner.
- The platform enforces an explicit target scope check before any active tool execution.
- Educational lab modules utilize isolated, deliberately vulnerable local containers/environments and do not connect to external third-party targets.
- This project is an independent educational effort and is **not officially affiliated with, endorsed by, or sponsored by EC-Council**.

---

## 7. License

To be established. All upstream open-source code reused in `source/` retains its original copyright and license terms. See `docs/SOURCE_INVENTORY.md` and the `licenses/` directory for full attribution details.
