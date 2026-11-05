# LPT Workstation — Phase 0: Database Safety & Structure Audit
**Document ID:** `docs/audit/DATABASE_AUDIT.md`  
**Audit Date:** 2026-11-05  
**Auditor:** Senior Software Architect & Database Engineer  
**Status:** COMPLETED — READ-ONLY DATABASE ASSESSMENT  

---

## 1. Executive Summary & Cryptographic Baseline

The database storage layer utilizes an embedded SQLite 3 database operating in **Write-Ahead Logging (WAL)** mode. The audit was conducted in strictly **read-only mode** (`?mode=ro`) to prevent any mutation of production assessment records.

### Production Database Integrity Baseline
* **File Location:** `/home/leo/Desktop/cybersecuritysuite/storage/data/cybersecuritysuite.db`
* **File Size:** 233,472 bytes (57 pages @ 4096 bytes/page)
* **SHA-256 Checksum:** `c8d8aa9c0cb6a66682e678d2e3b5762df9086cffc43457ba489541e1ff7a7143`
* **Integrity Status:** `PRAGMA integrity_check;` returned **`ok`**
* **Journal Mode:** `wal`
* **Synchronous Setting:** `2` (`FULL`)

---

## 2. Table Census & Record Distribution

| Table Name | Record Count | Primary Key | Foreign Key Cascade Behavior | Purpose |
|---|---|---|---|---|
| `projects` | 4 | `id` (AUTOINCREMENT) | Root entity | Engagement & Project assessment metadata |
| `target_scopes` | 19 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Fail-closed scope boundary rules |
| `asset_nodes` | 18 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Discovered network assets, IPs, hostnames |
| `asset_edges` | 4 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Topology relationships & port bindings |
| `findings` | 30 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Confirmed and unverified vulnerabilities |
| `evidence` | 24 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Cryptographic artifacts & session logs |
| `observations` | 96 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Raw security observations & banners |
| `tool_executions` | 16 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Process execution history & exit codes |
| `engagement_audit_logs` | 58 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Immutable operator actions audit trail |
| `terminal_sessions` | 6 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Vaulted interactive PTY terminal sessions |
| `assessments` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Sub-assessment instances |
| `assessment_plans` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Preflight assessment plans |
| `assessment_sessions` | 5 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Security testing workflow runs |
| `osint_cases` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | OSINT investigation cases |
| `osint_assets` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | OSINT entities & indicators |
| `osint_relationships` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | OSINT graph edges |
| `osint_observations` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | OSINT raw evidence observations |
| `osint_scope_decisions`| 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | OSINT quarantine determinations |
| `collection_runs` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Automated OSINT execution runs |
| `scope_decisions` | 0 | `id` (AUTOINCREMENT) | `ON DELETE CASCADE` (`projects.id`) | Scope change approvals |

---

## 3. Schema Structure & Evolution

### 3.1 Migration Architecture
Schema evolution is handled programmatically in `storage/db.py::_migrate_columns`. When connecting to an existing SQLite file:
1. Base tables are defined via `CREATE TABLE IF NOT EXISTS`.
2. Existing column names are inspected using `PRAGMA table_info(<table>)`.
3. New columns (e.g. `engagement_id`, `sow_reference`, `rule_type`, `ports_allowed`) are appended non-destructively using `ALTER TABLE <table> ADD COLUMN ...`.
4. Existing user records, foreign keys, and indexes are never dropped.

### 3.2 Uniqueness Constraints & Duplicate Prevention
To guarantee idempotency during repeated scans:
* `asset_nodes`: `UNIQUE(project_id, node_type, value)`
* `asset_edges`: `UNIQUE(project_id, source_node_id, target_node_id, relation_type)`
* `terminal_sessions`: `UNIQUE(session_id)`
* `projects`: `UNIQUE(name)`

Database write queries use `INSERT OR IGNORE` or SQLite `ON CONFLICT DO UPDATE` clauses to update metadata without creating duplicate entities or orphan records.

---

## 4. Performance & Indexing Analysis

### Current Index State
Currently, only implicit primary key and unique constraint auto-indexes exist:
* `sqlite_autoindex_projects_1`
* `sqlite_autoindex_terminal_sessions_1`
* `sqlite_autoindex_asset_nodes_1`
* `sqlite_autoindex_asset_edges_1`
* `sqlite_autoindex_assessment_sessions_1`

### Optimization Recommendations (Phase 1)
Foreign keys (`project_id`) across high-volume tables (`target_scopes`, `findings`, `evidence`, `observations`, `asset_nodes`, `asset_edges`) currently perform table scans when filtering by project. Adding the following covering indexes will significantly improve GUI load times:
1. `CREATE INDEX IF NOT EXISTS idx_asset_nodes_project ON asset_nodes(project_id, node_type);`
2. `CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, severity);`
3. `CREATE INDEX IF NOT EXISTS idx_target_scopes_project ON target_scopes(project_id, is_authorized);`
4. `CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id);`
5. `CREATE INDEX IF NOT EXISTS idx_audit_project ON engagement_audit_logs(project_id, timestamp);`

