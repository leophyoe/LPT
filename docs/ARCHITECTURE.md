# System Architecture: CyberSecuritySuite

## 1. High-Level Architecture

The platform follows a layered, modular architecture with clear service boundaries to ensure testability, safety, and source-level extensibility.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DESKTOP UI LAYER (PySide6)                      │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Workspaces: Dashboard | Projects | Network | Web | System | Cloud │ │
│ │             Code Security | Reverse Eng | Terminal | CPENT Labs    │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────┐ ┌───────────────────────────────┐ │
│ │ Integrated Terminal & Streamer   │ │ AI Security Assistant Panel   │ │
│ └──────────────────────────────────┘ └───────────────────────────────┘ │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Events / Signals / Service Calls)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          CORE SERVICES LAYER                           │
│ ┌───────────────────────────┐ ┌──────────────────────────────────────┐ │
│ │ ProjectService            │ │ ScopeAuthorizationService            │ │
│ │ - Session lifecycle       │ │ - CIDR / IP / Domain validator       │ │
│ │ - Active project context  │ │ - Active vs Passive operation guard  │ │
│ └───────────────────────────┘ └──────────────────────────────────────┘ │
│ ┌───────────────────────────┐ ┌──────────────────────────────────────┐ │
│ │ ToolExecutionService      │ │ Finding & EvidenceService            │ │
│ │ - Command generation      │ │ - CVSS scoring & validation status   │ │
│ │ - Subprocess PTY / stream │ │ - Evidence hashing & provenance      │ │
│ │ - Timeouts & cancellation │ │ - Reproduction steps & remediation   │ │
│ └───────────────────────────┘ └──────────────────────────────────────┘ │
│ ┌───────────────────────────┐ ┌──────────────────────────────────────┐ │
│ │ AIService                 │ │ ReportService & LabService           │ │
│ │ - Pluggable providers     │ │ - HTML / Markdown / JSON exporters │ │
│ │ - Secret Redaction engine │ │ - Docker/Podman lab runner           │ │
│ └───────────────────────────┘ └──────────────────────────────────────┘ │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       MODULES & ADAPTERS LAYER                         │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ BaseToolAdapter: validate_scope(), build_command(), parse_output()  │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│   ▲                       ▲                      ▲                     │
│   │                       │                      │                     │
│ ┌─┴─────────────┐   ┌─────┴──────────┐   ┌───────┴───────────────┐     │
│ │ NmapAdapter   │   │ ZAPAdapter     │   │ CodeSecurityAdapter   │ ... │
│ └───────────────┘   └────────────────┘   └───────────────────────┘     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       STORAGE & PERSISTENCE LAYER                      │
│ ┌─────────────────────────────────┐ ┌────────────────────────────────┐ │
│ │ SQLite Database (WAL Mode)      │ │ Evidence Vault (Local Storage) │ │
│ │ - projects, scopes, executions  │ │ - Raw tool outputs (XML, JSON) │ │
│ │ - findings, evidence_records    │ │ - PCAP files, logs, artifacts  │ │
│ │ - lab_progress, audit_history   │ │ - SHA-256 integrity checks    │ │
│ └─────────────────────────────────┘ └────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Scope & Authorization Guard (`core/scope.py`)
No command or tool execution can be started without validation against the project's target scope.
- **Scope Definitions**: Allowed IPv4/IPv6 addresses, CIDR blocks, hostnames, and explicit excluded targets.
- **Mode Classification**:
  - `PASSIVE`: Information gathering without direct probe traffic (e.g. DNS lookups, search engine recon).
  - `ACTIVE`: Port scanning, service enumeration, crawler traffic. Requires user scope confirmation.
  - `INTRUSIVE`: Vulnerability validation, exploits, brute-forcing. Requires double confirmation and lab authorization.

### 2.2 Execution Engine & Terminal (`terminal/runner.py`)
- Employs non-blocking process execution via `QProcess` or `asyncio.subprocess` with pseudo-terminal (PTY) emulation.
- Streams standard output and standard error in real time into the desktop terminal widget.
- Collects raw execution logs with timestamps, tool versions, exit codes, and execution durations.
- Automatically routes raw output to the corresponding adapter's parser.

### 2.3 Modules & Adapters (`modules/`)
Each tool adapter implements a defined contract:
```python
class BaseToolAdapter(ABC):
    name: str
    version: str
    category: str

    @abstractmethod
    def validate_target(self, target: str, scope: TargetScope) -> bool: ...

    @abstractmethod
    def build_command(self, options: ToolOptions) -> list[str]: ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> ParsedToolResult: ...
```
This isolates tool-specific logic from the UI and core database.

### 2.4 Findings & Evidence System (`storage/models.py`)
- **Finding Record**: Title, description, severity (Informational, Low, Medium, High, Critical), CVSS 3.1 vector, affected asset, affected port/endpoint, validation status (Unverified, Validated, False Positive), remediation, references.
- **Evidence Record**: File path, file hash (SHA-256), discovery timestamp, associated tool execution ID, raw output snapshot.

### 2.5 AI Security Assistant (`ai/`)
- **Provider Agnostic**: Interfaces with local models (e.g., Ollama/llama.cpp) or remote cloud APIs (e.g., Gemini, OpenAI, Claude) via unified provider interfaces.
- **Redaction Pipeline**: Runs regular expressions and entropy detectors to redact IP addresses (optional), API keys, passwords, and private tokens before sending prompts to remote models.
- **Triage & Guidance**: Assesses parsed findings, explains technical risks, proposes remediation steps, and assists learners with CPENT exercise concepts.

### 2.6 CPENT Learning & Labs (`labs/`)
- Encapsulates modular curriculum tracks (Network Penetration Testing, Active Directory, Web/API Attacks, Pivoting, Exploit Analysis).
- Orchestrates Docker/Podman container stacks for local, isolated, hands-on lab targets.
- Tracks student progress, flags, knowledge checks, and generated lab completion reports.
