# Security, Privacy & Safety Model

## 1. Scope & Authorization Architecture

The platform enforces a strict pre-execution authorization check for any security operation.

```text
User Request / Scan Trigger
          │
          ▼
┌───────────────────────────────────────────────┐
│           Scope Authorization Guard           │
│  - Is target IP / Host in authorized scope?   │
│  - Is target explicitly excluded?             │
│  - Does the project have signed authorization?│
└───────────────────────┬───────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          │ Passes                    │ Fails
          ▼                           ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│ Operation Classification │   │ Execution Blocked        │
│ - PASSIVE (Auto-allowed) │   │ (Logged in Audit Log)    │
│ - ACTIVE (Prompt user)   │   └──────────────────────────┘
│ - INTRUSIVE (Explicit OK)│
└──────────────────────────┘
```

### Authorization Levels
1. **Passive**: Information retrieval that sends no probe packets directly to the target (DNS queries, WHOIS, local source code analysis).
2. **Active**: Probes, port scans, HTTP directory fuzzing. Requires the target to match the authorized project scope and requires user confirmation.
3. **Intrusive**: Vulnerability verification, exploit modules, high-frequency brute forcing. Requires explicit confirmation and confirmation that the target is a controlled lab or authorized system.

---

## 2. Process Execution Safety

1. **No `shell=True` Execution**: Commands are never executed as arbitrary concatenated shell strings. All executions pass structured argument arrays (`list[str]`) directly to `subprocess.Popen` / `QProcess`.
2. **Timeout & Resource Limits**: Every process execution is assigned a strict timeout (configurable, default 15 minutes). Hanging processes are terminated cleanly via SIGTERM, followed by SIGKILL if unresponsive.
3. **Cancellation Mechanism**: Users can abort running tasks at any time from the UI with immediate process group termination.
4. **Privilege Demarcation**: The application does not run as `root`. Tools requiring raw socket privileges (such as SYN scans in Nmap) utilize standard Linux capabilities (`setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip`) or prompt via `pkexec` with full command transparency.

---

## 3. Data Privacy & AI Redaction

1. **Local-First Processing**: All scanning results, outputs, database records, and evidence files reside strictly on the local machine.
2. **Pre-AI Redaction**: Before sending any context (terminal output, scan results, or code snippets) to external AI models:
   - Target credentials, passwords, tokens, API keys, and hashes are automatically replaced with `[REDACTED_SECRET]`.
   - Internal IP ranges and customer names can be anonymized based on user privacy settings.
3. **Transparent Provider Selection**: Users are clearly notified whether an AI query is processed locally (e.g. Ollama) or transmitted to an external API (e.g. Gemini, OpenAI).

---

## 4. Evidence Integrity

- Every raw output, PCAP file, or artifact captured by an execution adapter is immediately hashed using **SHA-256**.
- The hash is stored in the database alongside the timestamp and execution metadata to support later integrity checks and evidence provenance in audit reports.
- During report generation, each evidence file is re-hashed and labeled `verified`, `mismatch`, `missing`, `unverified`, or `error`. A stored digest alone is not represented as proof that the current on-disk file is intact.
- Terminal-session evidence points to the exact raw capture bytes covered by its SHA-256 digest; the separate plain-text transcript is a convenience view, not the hashed artifact.

---

## 5. Terminal Console vs. Automated Assessment Adapters

1. **Interactive Terminal Console**:
   - The interactive terminal (`TerminalWidget` / `VSCodeTerminal`) functions strictly as an **Unrestricted Operator Console**. It allows human operators to run standard Ubuntu commands (e.g. `ls`, `cd`, `grep`, custom helper scripts, package installation, or debugging).
   - **Explicit Security Boundary**: The interactive terminal shell is **NOT scope-enforced**. It does NOT attempt to parse or block arbitrary bash commands, pipes, redirects, or custom binaries. Operators retain full operational authority and responsibility for manual shell actions.
   - When an active project is selected, terminal executions and session metadata are audited in `engagement_audit_logs` under `actor="operator_console"`, scrubbed of credentials, vaulted with SHA-256 cryptographic hashes in `evidence`, and linked to the active project for chain of custody.
   - Under automated testing or headless environments, the terminal console defaults to in-memory SQLite isolation, preventing silent writes to production databases.

2. **Automated Assessment Adapters**:
   - All automated security assessment adapters (`NmapAdapter`, `NiktoAdapter`, `SQLMapAdapter`, `HydraAdapter`, `WAFW00FAdapter`, `GobusterAdapter`, `AmassAdapter`) are strictly **Scope-Enforced** through `ScopeAuthorizationService` and `ToolExecutionService`.
   - Automated adapters fail closed before any subprocess creation if the target is outside the authorized project scope, if the engagement is archived/suspended, or if authorization dates have expired.
   - High-Risk Intrusive Operations (e.g. SQLMap injection testing with `risk > 1` / `level > 1` / crawling, or Hydra online brute-forcing with `tasks > 4` or dual dictionaries) require explicit operator confirmation (`confirmed_high_risk=True`).
   - Automated tools use tokenized argument arrays (`shell=False`), maximum execution limits, real-time output callbacks, and non-blocking background execution.

---

## 6. Multi-Project and Database Isolation

1. **Multi-Project Isolation**:
   - The platform strictly partitions all operational data by `project_id`.
   - Target scopes, asset graph topology (nodes and edges), security findings, evidence files, tool execution records, and engagement audit logs cannot be accessed, listed, or mutated across project boundaries.
   - Cross-project ID queries return `None` or empty sets.

2. **Database Test Isolation**:
   - Automated tests run against ephemeral in-memory SQLite databases (`:memory:`) or dedicated temporary test databases.
   - A global test harness (`tests/conftest.py`) actively intercepts database connection attempts: any test attempting to open or mutate the production database (`storage/data/cybersecuritysuite.db`) raises a `RuntimeError` immediately.
   - Pre- and post-test integrity verification ensures zero bytes or records are modified in production datasets during test suites.
