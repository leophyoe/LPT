# Architecture Decision Records (ADR)

## ADR 001: Temporary Project Working Name
- **Date:** 2026-10-20
- **Status:** Accepted
- **Context:** Candidate names such as *FortiForge*, *SecForge AI*, *VulnForge*, and *RedCore Security* have potential brand conflicts or pending trademark reviews.
- **Decision:** Use `CyberSecuritySuite` as the temporary working codename and directory identifier until formal domain and trademark clearing is completed.
- **Consequences:** Codebase namespacing will use `cybersecuritysuite`. Rebranding will be handled via configuration constants.

---

## ADR 002: GUI Framework Choice (PySide6 / Qt 6)
- **Date:** 2026-10-20
- **Status:** Accepted
- **Context:** The application requires a performant, native desktop UI on Ubuntu Linux featuring an integrated terminal, docked sidebars, real-time output streaming, and complex tables.
- **Decision:** Select **PySide6** (official Qt for Python).
- **Consequences:** Provides native Linux rendering, rock-solid event loop (`QEventLoop`), rich widgets (`QSplitter`, `QPlainTextEdit`), and strong support for multi-threading (`QThread`, `QProcess`).

---

## ADR 003: Single-User Persistence via SQLite (WAL Mode)
- **Date:** 2026-10-20
- **Status:** Accepted
- **Context:** An initial prototype requires zero external server setup, local-first privacy, and reliable atomic transactions for projects, findings, and logs.
- **Decision:** Use **SQLite 3** with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) enabled.
- **Consequences:** Zero infrastructure cost, self-contained single-file portability, high concurrency for background execution threads. A PostgreSQL migration path will be preserved for future multi-user versions.

---

## ADR 004: Execution Engine Strategy (Subprocess PTY vs In-Memory Embedding)
- **Date:** 2026-10-20
- **Status:** Accepted
- **Context:** Security tools (Nmap, ZAP, Nuclei, Tshark) are written in different languages (C/C++, Java, Go) with varied dependencies and copyleft licenses.
- **Decision:** Isolate all third-party tool execution using standard subprocesses with PTY emulation, streaming stdout/stderr, enforcing strict argument lists and timeouts.
- **Consequences:** Prevents license contamination, isolates crashes, allows version tracking, and avoids fragile source-code merging of third-party C/Java codebases into Python.

---

## ADR 005: Original CPENT Curriculum & Lab Strategy
- **Date:** 2026-10-20
- **Status:** Accepted
- **Context:** The platform aims to prepare learners for EC-Council CPENT practical skills without infringing upon EC-Council copyright or proprietary courseware.
- **Decision:** Develop 100% original, self-authored learning modules, practice checklists, and local Docker/Podman labs aligned with publicly available pentesting methodologies.
- **Consequences:** Ensures legal and ethical compliance, independent educational value, and safe local experimentation.
