"""Database management and SQLite repository for CyberSecuritySuite.

Enforces SQLite WAL mode, foreign key integrity, and provides atomic
operations for Projects, Scopes, Executions, Findings, and Evidence.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional, Tuple, Union

from storage.models import (
    _utc_now_iso,
    AssetEdge,
    AssetNode,
    Assessment,
    AssessmentPlan,
    AssessmentSession,
    AssessmentStatus,
    EngagementAuditLog,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Observation,
    OSINTCase,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    TerminalSessionRecord,
    TestCategory,
    ToolExecution,
    ValidationStatus,
)

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    client_name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    engagement_id TEXT DEFAULT '',
    lead_tester TEXT DEFAULT '',
    authorized_contact TEXT DEFAULT '',
    emergency_contact TEXT DEFAULT '',
    sow_reference TEXT DEFAULT '',
    authorization_doc TEXT DEFAULT '',
    start_date TEXT DEFAULT '',
    end_date TEXT DEFAULT '',
    timezone TEXT DEFAULT 'UTC',
    allowed_hours TEXT DEFAULT '',
    max_rate_limit INTEGER DEFAULT 100,
    allow_active_recon INTEGER DEFAULT 0,
    prohibited_tests TEXT DEFAULT 'DoS/DDoS, Social Engineering, Physical Intrusion, Account Lockout Brute Force'
);

CREATE TABLE IF NOT EXISTS target_scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT DEFAULT 'ip_address',
    is_authorized INTEGER DEFAULT 1,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    rule_type TEXT DEFAULT 'allowed',
    environment TEXT DEFAULT 'production',
    ports_allowed TEXT DEFAULT '',
    expires_at TEXT,
    effective_from TEXT DEFAULT '',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS engagement_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT DEFAULT '',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    node_type TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT DEFAULT '',
    source_tool TEXT DEFAULT '',
    confidence REAL DEFAULT 1.0,
    metadata_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, node_type, value),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asset_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    source_node_id INTEGER NOT NULL,
    target_node_id INTEGER NOT NULL,
    relation_type TEXT NOT NULL,
    source_tool TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    verification_state TEXT DEFAULT 'observed',
    confidence REAL DEFAULT 1.0,
    evidence_id INTEGER,
    last_seen TEXT DEFAULT '',
    metadata_json TEXT DEFAULT '{}',
    UNIQUE(project_id, source_node_id, target_node_id, relation_type),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (source_node_id) REFERENCES asset_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (target_node_id) REFERENCES asset_nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    exit_code INTEGER,
    started_at TEXT,
    finished_at TEXT,
    duration_seconds REAL,
    raw_output_path TEXT,
    created_at TEXT NOT NULL,
    assessment_id INTEGER,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'informational',
    cvss_score REAL,
    cvss_vector TEXT,
    affected_asset TEXT DEFAULT '',
    affected_port_service TEXT DEFAULT '',
    description TEXT DEFAULT '',
    reproduction_steps TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    validation_status TEXT DEFAULT 'unverified',
    source_tool TEXT DEFAULT '',
    execution_id INTEGER,
    created_at TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    assessment_id INTEGER,
    updated_at TEXT DEFAULT '',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    finding_id INTEGER,
    execution_id INTEGER,
    description TEXT DEFAULT '',
    mime_type TEXT DEFAULT 'text/plain',
    created_at TEXT NOT NULL,
    assessment_id INTEGER,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS terminal_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    working_directory TEXT DEFAULT '',
    exit_status INTEGER,
    raw_output_path TEXT,
    plain_text_path TEXT,
    sha256_hash TEXT DEFAULT '',
    evidence_id INTEGER,
    execution_id INTEGER,
    command_count INTEGER DEFAULT 0,
    commands_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS osint_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    objective TEXT DEFAULT 'External Attack Surface & Passive Intelligence',
    authorization_reference TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    analyst_notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    case_id INTEGER,
    asset_id INTEGER,
    source_tool TEXT DEFAULT '',
    method TEXT DEFAULT 'passive',
    raw_data TEXT DEFAULT '',
    confidence REAL DEFAULT 1.0,
    verification_status TEXT DEFAULT 'unverified',
    evidence_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id) REFERENCES osint_cases(id) ON DELETE SET NULL,
    FOREIGN KEY (asset_id) REFERENCES asset_nodes(id) ON DELETE SET NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS assessment_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    test_category TEXT DEFAULT 'network_discovery',
    target TEXT NOT NULL,
    acceptance_criteria TEXT DEFAULT '',
    status TEXT DEFAULT 'draft',
    preflight_blockers TEXT DEFAULT '',
    execution_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS assessment_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    authorized_scope TEXT DEFAULT '',
    selected_tools TEXT DEFAULT '[]',
    status TEXT DEFAULT 'pending',
    started_at TEXT NOT NULL,
    ended_at TEXT,
    created_at TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    authorized_scope TEXT DEFAULT '',
    start_date TEXT DEFAULT '',
    end_date TEXT DEFAULT '',
    status TEXT DEFAULT 'planned',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
"""


class Database:
    """Manages SQLite connections, migrations, and repository operations."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def close(self) -> None:
        if self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None

    @contextmanager
    def session(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides an atomic transactional connection context."""
        conn = self.get_connection()
        try:
            with conn:
                yield conn
        finally:
            if self._mem_conn is None:
                conn.close()

    def _init_db(self) -> None:
        with self.session() as conn:
            conn.executescript(SCHEMA_SQL)
            self._migrate_columns(conn)

    def _migrate_columns(self, conn: sqlite3.Connection) -> None:
        """Dynamically add missing columns to existing SQLite tables for schema evolution."""
        try:
            p_cols = {col["name"] for col in conn.execute("PRAGMA table_info(projects)").fetchall()}
            new_project_cols = [
                ("engagement_id", "TEXT DEFAULT ''"),
                ("lead_tester", "TEXT DEFAULT ''"),
                ("authorized_contact", "TEXT DEFAULT ''"),
                ("emergency_contact", "TEXT DEFAULT ''"),
                ("sow_reference", "TEXT DEFAULT ''"),
                ("authorization_doc", "TEXT DEFAULT ''"),
                ("start_date", "TEXT DEFAULT ''"),
                ("end_date", "TEXT DEFAULT ''"),
                ("timezone", "TEXT DEFAULT 'UTC'"),
                ("allowed_hours", "TEXT DEFAULT ''"),
                ("max_rate_limit", "INTEGER DEFAULT 100"),
                ("allow_active_recon", "INTEGER DEFAULT 0"),
                ("prohibited_tests", "TEXT DEFAULT 'DoS/DDoS, Social Engineering, Physical Intrusion, Account Lockout Brute Force'"),
            ]
            for col_name, col_def in new_project_cols:
                if col_name not in p_cols:
                    conn.execute(f"ALTER TABLE projects ADD COLUMN {col_name} {col_def};")

            s_cols = {col["name"] for col in conn.execute("PRAGMA table_info(target_scopes)").fetchall()}
            new_scope_cols = [
                ("rule_type", "TEXT DEFAULT 'allowed'"),
                ("environment", "TEXT DEFAULT 'production'"),
                ("ports_allowed", "TEXT DEFAULT ''"),
                ("expires_at", "TEXT"),
                ("effective_from", "TEXT DEFAULT ''"),
            ]
            for col_name, col_def in new_scope_cols:
                if col_name not in s_cols:
                    conn.execute(f"ALTER TABLE target_scopes ADD COLUMN {col_name} {col_def};")

            f_cols = {col["name"] for col in conn.execute("PRAGMA table_info(findings)").fetchall()}
            new_finding_cols = [
                ("validation_method", "TEXT DEFAULT ''"),
                ("severity_rationale", "TEXT DEFAULT ''"),
                ("confidence", "REAL DEFAULT 1.0"),
                ("assessment_id", "INTEGER"),
                ("updated_at", "TEXT DEFAULT ''"),
            ]
            for col_name, col_def in new_finding_cols:
                if col_name not in f_cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def};")

            # Ensure tool_executions has assessment_id
            te_cols = {col["name"] for col in conn.execute("PRAGMA table_info(tool_executions)").fetchall()}
            if "assessment_id" not in te_cols:
                conn.execute("ALTER TABLE tool_executions ADD COLUMN assessment_id INTEGER;")

            # Ensure evidence has assessment_id
            ev_cols = {col["name"] for col in conn.execute("PRAGMA table_info(evidence)").fetchall()}
            if "assessment_id" not in ev_cols:
                conn.execute("ALTER TABLE evidence ADD COLUMN assessment_id INTEGER;")

            # Ensure observations table has source_tool and raw_data columns
            obs_cols = {col["name"] for col in conn.execute("PRAGMA table_info(observations)").fetchall()}
            new_obs_cols = [
                ("source_tool", "TEXT DEFAULT ''"),
                ("raw_data", "TEXT DEFAULT ''"),
            ]
            for col_name, col_def in new_obs_cols:
                if col_name not in obs_cols:
                    conn.execute(f"ALTER TABLE observations ADD COLUMN {col_name} {col_def};")

            # Ensure asset_edges has phase 2 intelligence columns
            ae_cols = {col["name"] for col in conn.execute("PRAGMA table_info(asset_edges)").fetchall()}
            new_edge_cols = [
                ("verification_state", "TEXT DEFAULT 'observed'"),
                ("confidence", "REAL DEFAULT 1.0"),
                ("evidence_id", "INTEGER"),
                ("last_seen", "TEXT DEFAULT ''"),
                ("metadata_json", "TEXT DEFAULT '{}'"),
            ]
            for col_name, col_def in new_edge_cols:
                if col_name not in ae_cols:
                    conn.execute(f"ALTER TABLE asset_edges ADD COLUMN {col_name} {col_def};")

            # Ensure assessments table exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    authorized_scope TEXT DEFAULT '',
                    start_date TEXT DEFAULT '',
                    end_date TEXT DEFAULT '',
                    status TEXT DEFAULT 'planned',
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
                );
            """)
        except Exception:
            pass

    # ---------------------------------------------------------
    # Project Operations
    # ---------------------------------------------------------
    @staticmethod
    def _row_to_project(row: sqlite3.Row) -> Project:
        d = dict(row)
        return Project(
            id=d.get("id"),
            name=d.get("name", ""),
            client_name=d.get("client_name", ""),
            description=d.get("description", ""),
            status=ProjectStatus(d.get("status", "active")),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
            engagement_id=d.get("engagement_id", ""),
            lead_tester=d.get("lead_tester", ""),
            authorized_contact=d.get("authorized_contact", ""),
            emergency_contact=d.get("emergency_contact", ""),
            sow_reference=d.get("sow_reference", ""),
            authorization_doc=d.get("authorization_doc", ""),
            start_date=d.get("start_date", ""),
            end_date=d.get("end_date", ""),
            timezone=d.get("timezone", "UTC"),
            allowed_hours=d.get("allowed_hours", ""),
            max_rate_limit=d.get("max_rate_limit", 100),
            allow_active_recon=bool(d.get("allow_active_recon", 0)),
            prohibited_tests=d.get("prohibited_tests", "DoS/DDoS, Social Engineering, Physical Intrusion, Account Lockout Brute Force"),
        )

    def create_project(self, project: Project) -> Project:
        query = """
            INSERT INTO projects (
                name, client_name, description, status, created_at, updated_at,
                engagement_id, lead_tester, authorized_contact, emergency_contact,
                sow_reference, authorization_doc, start_date, end_date, timezone,
                allowed_hours, max_rate_limit, allow_active_recon, prohibited_tests
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    project.name,
                    project.client_name,
                    project.description,
                    project.status.value,
                    project.created_at,
                    project.updated_at,
                    project.engagement_id,
                    project.lead_tester,
                    project.authorized_contact,
                    project.emergency_contact,
                    project.sow_reference,
                    project.authorization_doc,
                    project.start_date,
                    project.end_date,
                    project.timezone,
                    project.allowed_hours,
                    project.max_rate_limit,
                    1 if project.allow_active_recon else 0,
                    project.prohibited_tests,
                ),
            )
            project.id = cursor.lastrowid
            return project

    def update_project(self, project: Project) -> bool:
        query = """
            UPDATE projects SET
                name = ?, client_name = ?, description = ?, status = ?, updated_at = ?,
                engagement_id = ?, lead_tester = ?, authorized_contact = ?, emergency_contact = ?,
                sow_reference = ?, authorization_doc = ?, start_date = ?, end_date = ?,
                timezone = ?, allowed_hours = ?, max_rate_limit = ?, allow_active_recon = ?,
                prohibited_tests = ?
            WHERE id = ?
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    project.name,
                    project.client_name,
                    project.description,
                    project.status.value,
                    project.updated_at,
                    project.engagement_id,
                    project.lead_tester,
                    project.authorized_contact,
                    project.emergency_contact,
                    project.sow_reference,
                    project.authorization_doc,
                    project.start_date,
                    project.end_date,
                    project.timezone,
                    project.allowed_hours,
                    project.max_rate_limit,
                    1 if project.allow_active_recon else 0,
                    project.prohibited_tests,
                    project.id,
                ),
            )
            return cursor.rowcount > 0

    def get_project(self, project_id: int) -> Optional[Project]:
        query = "SELECT * FROM projects WHERE id = ?"
        with self.session() as conn:
            row = conn.execute(query, (project_id,)).fetchone()
            if not row:
                return None
            return self._row_to_project(row)

    def list_projects(self) -> List[Project]:
        query = "SELECT * FROM projects ORDER BY created_at DESC"
        with self.session() as conn:
            rows = conn.execute(query).fetchall()
            return [self._row_to_project(row) for row in rows]

    def delete_project(self, project_id: int) -> bool:
        query = "DELETE FROM projects WHERE id = ?"
        with self.session() as conn:
            cursor = conn.execute(query, (project_id,))
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Target Scope Operations
    # ---------------------------------------------------------
    @staticmethod
    def _row_to_scope(row: sqlite3.Row) -> TargetScope:
        d = dict(row)
        raw_tt = d.get("target_type", "ip_address")
        try:
            target_type = TargetType(raw_tt)
        except ValueError:
            target_type = TargetType.HOSTNAME

        raw_rt = d.get("rule_type", "allowed")
        try:
            rule_type = ScopeRuleType(raw_rt)
        except ValueError:
            rule_type = ScopeRuleType.ALLOWED

        return TargetScope(
            id=d.get("id"),
            project_id=d.get("project_id"),
            target=d.get("target", ""),
            target_type=target_type,
            is_authorized=bool(d.get("is_authorized", 1)),
            notes=d.get("notes", ""),
            created_at=d.get("created_at", ""),
            rule_type=rule_type,
            environment=d.get("environment", "production"),
            ports_allowed=d.get("ports_allowed", ""),
            expires_at=d.get("expires_at"),
            effective_from=d.get("effective_from"),
        )

    def add_scope(self, scope: TargetScope) -> TargetScope:
        query = """
            INSERT INTO target_scopes (
                project_id, target, target_type, is_authorized, notes, created_at,
                rule_type, environment, ports_allowed, expires_at, effective_from
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    scope.project_id,
                    scope.target,
                    scope.target_type.value,
                    1 if scope.is_authorized else 0,
                    scope.notes,
                    scope.created_at,
                    scope.rule_type.value,
                    scope.environment,
                    scope.ports_allowed,
                    scope.expires_at,
                    scope.effective_from or "",
                ),
            )
            scope.id = cursor.lastrowid
            return scope

    def get_scope(self, scope_id: int, project_id: Optional[int] = None) -> Optional[TargetScope]:
        if project_id is not None:
            query = "SELECT * FROM target_scopes WHERE id = ? AND project_id = ?"
            params = (scope_id, project_id)
        else:
            query = "SELECT * FROM target_scopes WHERE id = ?"
            params = (scope_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return self._row_to_scope(row)

    def list_scopes(self, project_id: int) -> List[TargetScope]:
        query = "SELECT * FROM target_scopes WHERE project_id = ? ORDER BY id ASC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [self._row_to_scope(row) for row in rows]

    def update_scope(self, scope: TargetScope) -> bool:
        query = """
            UPDATE target_scopes SET
                target = ?, target_type = ?, is_authorized = ?, notes = ?,
                rule_type = ?, environment = ?, ports_allowed = ?, expires_at = ?, effective_from = ?
            WHERE id = ?
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    scope.target,
                    scope.target_type.value,
                    1 if scope.is_authorized else 0,
                    scope.notes,
                    scope.rule_type.value,
                    scope.environment,
                    scope.ports_allowed,
                    scope.expires_at,
                    scope.effective_from or "",
                    scope.id,
                ),
            )
            return cursor.rowcount > 0

    def delete_scope(self, scope_id: int) -> bool:
        query = "DELETE FROM target_scopes WHERE id = ?"
        with self.session() as conn:
            cursor = conn.execute(query, (scope_id,))
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Engagement Audit Log Operations
    # ---------------------------------------------------------
    def add_audit_log(self, entry: EngagementAuditLog) -> EngagementAuditLog:
        query = """
            INSERT INTO engagement_audit_logs (project_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    entry.project_id,
                    entry.actor,
                    entry.action,
                    entry.details,
                    entry.timestamp,
                ),
            )
            entry.id = cursor.lastrowid
            return entry

    def list_audit_logs(self, project_id: int) -> List[EngagementAuditLog]:
        query = "SELECT * FROM engagement_audit_logs WHERE project_id = ? ORDER BY timestamp DESC, id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                EngagementAuditLog(
                    id=row["id"],
                    project_id=row["project_id"],
                    actor=row["actor"],
                    action=row["action"],
                    details=row["details"],
                    timestamp=row["timestamp"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Attack Surface Asset Graph Operations (Maltego Interop)
    # ---------------------------------------------------------
    def upsert_asset_node(self, node: AssetNode) -> AssetNode:
        meta_json = json.dumps(node.metadata_json) if isinstance(node.metadata_json, (dict, list)) else (node.metadata_json or "{}")
        query = """
            INSERT INTO asset_nodes (project_id, node_type, value, label, source_tool, confidence, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, node_type, value) DO UPDATE SET
                label = excluded.label,
                source_tool = excluded.source_tool,
                confidence = excluded.confidence,
                metadata_json = excluded.metadata_json
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    node.project_id,
                    node.node_type,
                    node.value,
                    node.label or node.value,
                    node.source_tool,
                    node.confidence,
                    meta_json,
                    node.created_at,
                ),
            )
            if cursor.lastrowid:
                node.id = cursor.lastrowid
            else:
                existing = conn.execute(
                    "SELECT id FROM asset_nodes WHERE project_id = ? AND node_type = ? AND value = ?",
                    (node.project_id, node.node_type, node.value),
                ).fetchone()
                if existing:
                    node.id = existing["id"]
            return node

    add_asset_node = upsert_asset_node

    def get_asset_node(self, node_id: int, project_id: Optional[int] = None) -> Optional[AssetNode]:
        if project_id is not None:
            query = "SELECT * FROM asset_nodes WHERE id = ? AND project_id = ?"
            params = (node_id, project_id)
        else:
            query = "SELECT * FROM asset_nodes WHERE id = ?"
            params = (node_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return AssetNode(
                id=row["id"],
                project_id=row["project_id"],
                node_type=row["node_type"],
                value=row["value"],
                label=row["label"],
                source_tool=row["source_tool"],
                confidence=row["confidence"],
                metadata_json=row["metadata_json"],
                created_at=row["created_at"],
            )

    def list_asset_nodes(self, project_id: int) -> List[AssetNode]:
        query = "SELECT * FROM asset_nodes WHERE project_id = ? ORDER BY id ASC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                AssetNode(
                    id=row["id"],
                    project_id=row["project_id"],
                    node_type=row["node_type"],
                    value=row["value"],
                    label=row["label"],
                    source_tool=row["source_tool"],
                    confidence=row["confidence"],
                    metadata_json=row["metadata_json"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def add_asset_edge(self, edge: AssetEdge) -> AssetEdge:
        query = """
            INSERT INTO asset_edges (
                project_id, source_node_id, target_node_id, relation_type, source_tool, created_at,
                verification_state, confidence, evidence_id, last_seen, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, source_node_id, target_node_id, relation_type) DO NOTHING
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    edge.project_id,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.relation_type,
                    edge.source_tool,
                    edge.created_at,
                    getattr(edge, "verification_state", "observed"),
                    float(getattr(edge, "confidence", 1.0)),
                    getattr(edge, "evidence_id", None),
                    getattr(edge, "last_seen", ""),
                    getattr(edge, "metadata_json", "{}"),
                ),
            )
            if cursor.lastrowid:
                edge.id = cursor.lastrowid
            return edge

    def upsert_asset_edge(self, edge: AssetEdge) -> AssetEdge:
        """Adds or updates an asset edge non-destructively.

        Preserves original `created_at`, updates `last_seen`, elevates or preserves
        verification_state, updates confidence, merges metadata, and aggregates
        evidence identifiers without overwriting historical references.
        """
        now = _utc_now_iso()
        verification_state = getattr(edge, "verification_state", "observed") or "observed"
        confidence = float(getattr(edge, "confidence", 1.0))
        evidence_id = getattr(edge, "evidence_id", None)
        last_seen = getattr(edge, "last_seen", "") or now
        source_tool = edge.source_tool or ""

        try:
            new_meta = json.loads(getattr(edge, "metadata_json", "{}") or "{}")
        except Exception:
            new_meta = {}

        select_query = """
            SELECT * FROM asset_edges
            WHERE project_id = ? AND source_node_id = ? AND target_node_id = ? AND relation_type = ?
        """
        with self.session() as conn:
            existing = conn.execute(
                select_query,
                (edge.project_id, edge.source_node_id, edge.target_node_id, edge.relation_type),
            ).fetchone()

            if not existing:
                if evidence_id is not None and "evidence_ids" not in new_meta:
                    new_meta["evidence_ids"] = [evidence_id]
                meta_json = json.dumps(new_meta)

                insert_query = """
                    INSERT INTO asset_edges (
                        project_id, source_node_id, target_node_id, relation_type, source_tool, created_at,
                        verification_state, confidence, evidence_id, last_seen, metadata_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cursor = conn.execute(
                    insert_query,
                    (
                        edge.project_id,
                        edge.source_node_id,
                        edge.target_node_id,
                        edge.relation_type,
                        source_tool,
                        edge.created_at or now,
                        verification_state,
                        confidence,
                        evidence_id,
                        last_seen,
                        meta_json,
                    ),
                )
                edge.id = cursor.lastrowid
                edge.metadata_json = meta_json
                edge.last_seen = last_seen
                return edge
            else:
                edge.id = existing["id"]
                original_created_at = existing["created_at"]
                edge.created_at = original_created_at

                existing_state = existing["verification_state"] if "verification_state" in existing.keys() else "observed"
                if existing_state == "manual":
                    final_state = "manual"
                elif verification_state == "observed" or existing_state == "observed":
                    final_state = "observed"
                else:
                    final_state = verification_state or existing_state

                final_conf = max(float(existing["confidence"] or 0.0), confidence) if "confidence" in existing.keys() else confidence

                merged_meta = {}
                if "metadata_json" in existing.keys() and existing["metadata_json"]:
                    try:
                        merged_meta = json.loads(existing["metadata_json"])
                    except Exception:
                        merged_meta = {}
                merged_meta.update(new_meta)

                ev_list = merged_meta.get("evidence_ids", [])
                if not isinstance(ev_list, list):
                    ev_list = [ev_list] if ev_list else []
                old_ev_id = existing["evidence_id"] if "evidence_id" in existing.keys() else None
                if old_ev_id and old_ev_id not in ev_list:
                    ev_list.append(old_ev_id)
                if evidence_id and evidence_id not in ev_list:
                    ev_list.append(evidence_id)
                if ev_list:
                    merged_meta["evidence_ids"] = ev_list

                meta_json = json.dumps(merged_meta)
                final_evidence_id = evidence_id if evidence_id is not None else old_ev_id

                update_query = """
                    UPDATE asset_edges
                    SET verification_state = ?, confidence = ?, evidence_id = ?, last_seen = ?, metadata_json = ?
                    WHERE id = ?
                """
                conn.execute(
                    update_query,
                    (final_state, final_conf, final_evidence_id, last_seen, meta_json, edge.id),
                )
                edge.verification_state = final_state
                edge.confidence = final_conf
                edge.evidence_id = final_evidence_id
                edge.last_seen = last_seen
                edge.metadata_json = meta_json
                return edge

    def get_asset_edge_by_nodes(
        self, project_id: int, source_node_id: int, target_node_id: int, relation_type: str
    ) -> Optional[AssetEdge]:
        query = """
            SELECT * FROM asset_edges
            WHERE project_id = ? AND source_node_id = ? AND target_node_id = ? AND relation_type = ?
        """
        with self.session() as conn:
            row = conn.execute(
                query, (project_id, source_node_id, target_node_id, relation_type)
            ).fetchone()
            if not row:
                return None
            return AssetEdge(
                id=row["id"],
                project_id=row["project_id"],
                source_node_id=row["source_node_id"],
                target_node_id=row["target_node_id"],
                relation_type=row["relation_type"],
                source_tool=row["source_tool"] if "source_tool" in row.keys() else "",
                created_at=row["created_at"],
                verification_state=row["verification_state"] if "verification_state" in row.keys() else "observed",
                confidence=float(row["confidence"]) if "confidence" in row.keys() and row["confidence"] is not None else 1.0,
                evidence_id=row["evidence_id"] if "evidence_id" in row.keys() else None,
                last_seen=row["last_seen"] if "last_seen" in row.keys() and row["last_seen"] is not None else "",
                metadata_json=row["metadata_json"] if "metadata_json" in row.keys() and row["metadata_json"] is not None else "{}",
            )

    def get_asset_edge(self, edge_id: int, project_id: Optional[int] = None) -> Optional[AssetEdge]:
        if project_id is not None:
            query = "SELECT * FROM asset_edges WHERE id = ? AND project_id = ?"
            params = (edge_id, project_id)
        else:
            query = "SELECT * FROM asset_edges WHERE id = ?"
            params = (edge_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return AssetEdge(
                id=row["id"],
                project_id=row["project_id"],
                source_node_id=row["source_node_id"],
                target_node_id=row["target_node_id"],
                relation_type=row["relation_type"],
                source_tool=row["source_tool"] if "source_tool" in row.keys() else "",
                created_at=row["created_at"],
                verification_state=row["verification_state"] if "verification_state" in row.keys() else "observed",
                confidence=float(row["confidence"]) if "confidence" in row.keys() and row["confidence"] is not None else 1.0,
                evidence_id=row["evidence_id"] if "evidence_id" in row.keys() else None,
                last_seen=row["last_seen"] if "last_seen" in row.keys() and row["last_seen"] is not None else "",
                metadata_json=row["metadata_json"] if "metadata_json" in row.keys() and row["metadata_json"] is not None else "{}",
            )

    def list_asset_edges(self, project_id: int) -> List[AssetEdge]:
        query = "SELECT * FROM asset_edges WHERE project_id = ? ORDER BY id ASC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                AssetEdge(
                    id=row["id"],
                    project_id=row["project_id"],
                    source_node_id=row["source_node_id"],
                    target_node_id=row["target_node_id"],
                    relation_type=row["relation_type"],
                    source_tool=row["source_tool"] if "source_tool" in row.keys() else "",
                    created_at=row["created_at"],
                    verification_state=row["verification_state"] if "verification_state" in row.keys() else "observed",
                    confidence=float(row["confidence"]) if "confidence" in row.keys() and row["confidence"] is not None else 1.0,
                    evidence_id=row["evidence_id"] if "evidence_id" in row.keys() else None,
                    last_seen=row["last_seen"] if "last_seen" in row.keys() and row["last_seen"] is not None else "",
                    metadata_json=row["metadata_json"] if "metadata_json" in row.keys() and row["metadata_json"] is not None else "{}",
                )
                for row in rows
            ]

    def delete_asset_graph(self, project_id: int) -> None:
        with self.session() as conn:
            conn.execute("DELETE FROM asset_edges WHERE project_id = ?", (project_id,))
            conn.execute("DELETE FROM asset_nodes WHERE project_id = ?", (project_id,))

    # ---------------------------------------------------------
    # Tool Execution Operations
    # ---------------------------------------------------------
    def create_execution(self, execution: ToolExecution) -> ToolExecution:
        query = """
            INSERT INTO tool_executions (project_id, tool_name, command, status, exit_code, started_at, finished_at, duration_seconds, raw_output_path, created_at, assessment_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    execution.project_id,
                    execution.tool_name,
                    execution.command,
                    execution.status.value,
                    execution.exit_code,
                    execution.started_at,
                    execution.finished_at,
                    execution.duration_seconds,
                    execution.raw_output_path,
                    execution.created_at,
                    getattr(execution, "assessment_id", None),
                ),
            )
            execution.id = cursor.lastrowid
            return execution

    def update_execution(self, execution: ToolExecution) -> None:
        query = """
            UPDATE tool_executions
            SET status = ?, exit_code = ?, started_at = ?, finished_at = ?, duration_seconds = ?, raw_output_path = ?, assessment_id = ?
            WHERE id = ?
        """
        with self.session() as conn:
            conn.execute(
                query,
                (
                    execution.status.value,
                    execution.exit_code,
                    execution.started_at,
                    execution.finished_at,
                    execution.duration_seconds,
                    execution.raw_output_path,
                    getattr(execution, "assessment_id", None),
                    execution.id,
                ),
            )

    def get_execution(self, execution_id: int, project_id: Optional[int] = None) -> Optional[ToolExecution]:
        if project_id is not None:
            query = "SELECT * FROM tool_executions WHERE id = ? AND project_id = ?"
            params = (execution_id, project_id)
        else:
            query = "SELECT * FROM tool_executions WHERE id = ?"
            params = (execution_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return ToolExecution(
                id=row["id"],
                project_id=row["project_id"],
                tool_name=row["tool_name"],
                command=row["command"],
                status=ExecutionStatus(row["status"]),
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                exit_code=row["exit_code"],
                duration_seconds=row["duration_seconds"],
                raw_output_path=row["raw_output_path"] if "raw_output_path" in row.keys() else None,
                assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
            )

    def list_executions(self, project_id: int, assessment_id: Optional[int] = None) -> List[ToolExecution]:
        if assessment_id is not None:
            query = "SELECT * FROM tool_executions WHERE project_id = ? AND assessment_id = ? ORDER BY id DESC"
            params = (project_id, assessment_id)
        else:
            query = "SELECT * FROM tool_executions WHERE project_id = ? ORDER BY id DESC"
            params = (project_id,)
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                ToolExecution(
                    id=row["id"],
                    project_id=row["project_id"],
                    tool_name=row["tool_name"],
                    command=row["command"],
                    status=ExecutionStatus(row["status"]),
                    exit_code=row["exit_code"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    duration_seconds=row["duration_seconds"],
                    raw_output_path=row["raw_output_path"],
                    created_at=row["created_at"],
                    assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Finding Operations
    # ---------------------------------------------------------
    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        d = dict(row)
        raw_sev = d.get("severity", "informational")
        try:
            sev = FindingSeverity(raw_sev)
        except ValueError:
            sev = FindingSeverity.INFORMATIONAL

        raw_val = d.get("validation_status", "unverified")
        try:
            val_stat = ValidationStatus(raw_val)
        except ValueError:
            val_stat = ValidationStatus.UNVERIFIED

        return Finding(
            id=d.get("id"),
            project_id=d.get("project_id"),
            title=d.get("title", ""),
            severity=sev,
            cvss_score=d.get("cvss_score"),
            cvss_vector=d.get("cvss_vector"),
            affected_asset=d.get("affected_asset", ""),
            affected_port_service=d.get("affected_port_service", ""),
            description=d.get("description", ""),
            reproduction_steps=d.get("reproduction_steps", ""),
            remediation=d.get("remediation", ""),
            validation_status=val_stat,
            source_tool=d.get("source_tool", ""),
            execution_id=d.get("execution_id"),
            validation_method=d.get("validation_method", "") or "",
            severity_rationale=d.get("severity_rationale", "") or "",
            confidence=float(d.get("confidence", 1.0) or 1.0),
            assessment_id=d.get("assessment_id"),
            updated_at=d.get("updated_at") or d.get("created_at", ""),
            created_at=d.get("created_at", ""),
        )

    def create_finding(self, finding: Finding) -> Finding:
        val_method = getattr(finding, "validation_method", "") or ""
        sev_rationale = getattr(finding, "severity_rationale", "") or ""
        confidence = getattr(finding, "confidence", 1.0) or 1.0
        assessment_id = getattr(finding, "assessment_id", None)
        updated_at = getattr(finding, "updated_at", "") or finding.created_at or _utc_now_iso()
        query = """
            INSERT INTO findings (project_id, title, severity, cvss_score, cvss_vector, affected_asset,
                                 affected_port_service, description, reproduction_steps, remediation,
                                 validation_status, source_tool, execution_id, validation_method,
                                 severity_rationale, confidence, assessment_id, updated_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    finding.project_id,
                    finding.title,
                    finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    finding.cvss_score,
                    finding.cvss_vector,
                    finding.affected_asset,
                    finding.affected_port_service,
                    finding.description,
                    finding.reproduction_steps,
                    finding.remediation,
                    finding.validation_status.value if hasattr(finding.validation_status, "value") else str(finding.validation_status),
                    finding.source_tool,
                    finding.execution_id,
                    val_method,
                    sev_rationale,
                    confidence,
                    assessment_id,
                    updated_at,
                    finding.created_at,
                ),
            )
            finding.id = cursor.lastrowid
            return finding

    add_finding = create_finding

    def update_finding(self, finding: Finding, project_id: Optional[int] = None) -> bool:
        pid = project_id if project_id is not None else getattr(finding, "project_id", None)
        if pid is not None:
            query = """
                UPDATE findings
                SET title = ?, severity = ?, cvss_score = ?, cvss_vector = ?,
                    affected_asset = ?, affected_port_service = ?, description = ?,
                    reproduction_steps = ?, remediation = ?, validation_status = ?,
                    source_tool = ?, execution_id = ?, validation_method = ?,
                    severity_rationale = ?, confidence = ?, assessment_id = ?, updated_at = ?
                WHERE id = ? AND project_id = ?
            """
            params = (
                finding.title,
                finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                finding.cvss_score,
                finding.cvss_vector,
                finding.affected_asset,
                finding.affected_port_service,
                finding.description,
                finding.reproduction_steps,
                finding.remediation,
                finding.validation_status.value if hasattr(finding.validation_status, "value") else str(finding.validation_status),
                finding.source_tool,
                finding.execution_id,
                getattr(finding, "validation_method", "") or "",
                getattr(finding, "severity_rationale", "") or "",
                getattr(finding, "confidence", 1.0) or 1.0,
                getattr(finding, "assessment_id", None),
                _utc_now_iso(),
                finding.id,
                pid,
            )
        else:
            query = """
                UPDATE findings
                SET title = ?, severity = ?, cvss_score = ?, cvss_vector = ?,
                    affected_asset = ?, affected_port_service = ?, description = ?,
                    reproduction_steps = ?, remediation = ?, validation_status = ?,
                    source_tool = ?, execution_id = ?, validation_method = ?,
                    severity_rationale = ?, confidence = ?, assessment_id = ?, updated_at = ?
                WHERE id = ?
            """
            params = (
                finding.title,
                finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                finding.cvss_score,
                finding.cvss_vector,
                finding.affected_asset,
                finding.affected_port_service,
                finding.description,
                finding.reproduction_steps,
                finding.remediation,
                finding.validation_status.value if hasattr(finding.validation_status, "value") else str(finding.validation_status),
                finding.source_tool,
                finding.execution_id,
                getattr(finding, "validation_method", "") or "",
                getattr(finding, "severity_rationale", "") or "",
                getattr(finding, "confidence", 1.0) or 1.0,
                getattr(finding, "assessment_id", None),
                _utc_now_iso(),
                finding.id,
            )
        with self.session() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    def delete_finding(self, finding_id: int, project_id: Optional[int] = None) -> bool:
        if project_id is not None:
            query = "DELETE FROM findings WHERE id = ? AND project_id = ?"
            params = (finding_id, project_id)
        else:
            query = "DELETE FROM findings WHERE id = ?"
            params = (finding_id,)
        with self.session() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    def list_findings(self, project_id: int, assessment_id: Optional[int] = None) -> List[Finding]:
        if assessment_id is not None:
            query = "SELECT * FROM findings WHERE project_id = ? AND assessment_id = ? ORDER BY id DESC"
            params = (project_id, assessment_id)
        else:
            query = "SELECT * FROM findings WHERE project_id = ? ORDER BY id DESC"
            params = (project_id,)
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_finding(row) for row in rows]

    def get_finding(self, finding_id: int, project_id: Optional[int] = None) -> Optional[Finding]:
        if project_id is not None:
            query = "SELECT * FROM findings WHERE id = ? AND project_id = ?"
            params = (finding_id, project_id)
        else:
            query = "SELECT * FROM findings WHERE id = ?"
            params = (finding_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def update_finding_status(self, finding_id: int, status: ValidationStatus, project_id: Optional[int] = None) -> bool:
        if project_id is not None:
            query = "UPDATE findings SET validation_status = ?, updated_at = ? WHERE id = ? AND project_id = ?"
            params = (status.value if hasattr(status, "value") else str(status), _utc_now_iso(), finding_id, project_id)
        else:
            query = "UPDATE findings SET validation_status = ?, updated_at = ? WHERE id = ?"
            params = (status.value if hasattr(status, "value") else str(status), _utc_now_iso(), finding_id)
        with self.session() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Evidence Operations
    # ---------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> Evidence:
        query = """
            INSERT INTO evidence (project_id, file_path, sha256_hash, finding_id, execution_id, description, mime_type, created_at, assessment_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    evidence.project_id,
                    evidence.file_path,
                    evidence.sha256_hash,
                    evidence.finding_id,
                    evidence.execution_id,
                    evidence.description,
                    evidence.mime_type,
                    evidence.created_at,
                    getattr(evidence, "assessment_id", None),
                ),
            )
            evidence.id = cursor.lastrowid
            return evidence

    def list_evidence(self, project_id: int, assessment_id: Optional[int] = None) -> List[Evidence]:
        if assessment_id is not None:
            query = "SELECT * FROM evidence WHERE project_id = ? AND assessment_id = ? ORDER BY id DESC"
            params = (project_id, assessment_id)
        else:
            query = "SELECT * FROM evidence WHERE project_id = ? ORDER BY id DESC"
            params = (project_id,)
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                Evidence(
                    id=row["id"],
                    project_id=row["project_id"],
                    file_path=row["file_path"],
                    sha256_hash=row["sha256_hash"],
                    finding_id=row["finding_id"],
                    execution_id=row["execution_id"],
                    description=row["description"],
                    mime_type=row["mime_type"],
                    created_at=row["created_at"],
                    assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
                )
                for row in rows
            ]

    def get_evidence_by_hash(self, project_id: int, sha256_hash: str) -> Optional[Evidence]:
        """Finds an evidence record by SHA-256 hash to prevent duplicate entries."""
        query = "SELECT * FROM evidence WHERE project_id = ? AND sha256_hash = ? LIMIT 1"
        with self.session() as conn:
            row = conn.execute(query, (project_id, sha256_hash)).fetchone()
            if not row:
                return None
            return Evidence(
                id=row["id"],
                project_id=row["project_id"],
                file_path=row["file_path"],
                sha256_hash=row["sha256_hash"],
                finding_id=row["finding_id"],
                execution_id=row["execution_id"],
                description=row["description"],
                mime_type=row["mime_type"],
                created_at=row["created_at"],
                assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
            )

    def get_evidence(self, evidence_id: int, project_id: Optional[int] = None) -> Optional[Evidence]:
        """Retrieves an evidence record by primary key ID, optionally isolating by project_id."""
        if project_id is not None:
            query = "SELECT * FROM evidence WHERE id = ? AND project_id = ? LIMIT 1"
            params = (evidence_id, project_id)
        else:
            query = "SELECT * FROM evidence WHERE id = ? LIMIT 1"
            params = (evidence_id,)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return Evidence(
                id=row["id"],
                project_id=row["project_id"],
                file_path=row["file_path"],
                sha256_hash=row["sha256_hash"],
                finding_id=row["finding_id"],
                execution_id=row["execution_id"],
                description=row["description"],
                mime_type=row["mime_type"],
                created_at=row["created_at"],
                assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
            )

    def get_evidence_for_finding(self, finding_id: int, project_id: Optional[int] = None) -> Optional[Evidence]:
        """Finds evidence linked to a finding either directly by finding_id or via execution_id."""
        if project_id is not None:
            query = """
                SELECT e.* FROM evidence e
                WHERE e.project_id = ? AND (
                    e.finding_id = ? OR
                    (e.execution_id IS NOT NULL AND e.execution_id = (SELECT f.execution_id FROM findings f WHERE f.id = ? AND f.project_id = ?))
                )
                ORDER BY (e.finding_id = ?) DESC, e.id DESC
                LIMIT 1
            """
            params = (project_id, finding_id, finding_id, project_id, finding_id)
        else:
            query = """
                SELECT e.* FROM evidence e
                WHERE e.finding_id = ? OR
                      (e.execution_id IS NOT NULL AND e.execution_id = (SELECT f.execution_id FROM findings f WHERE f.id = ?))
                ORDER BY (e.finding_id = ?) DESC, e.id DESC
                LIMIT 1
            """
            params = (finding_id, finding_id, finding_id)
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            return Evidence(
                id=row["id"],
                project_id=row["project_id"],
                file_path=row["file_path"],
                sha256_hash=row["sha256_hash"],
                finding_id=row["finding_id"],
                execution_id=row["execution_id"],
                description=row["description"],
                mime_type=row["mime_type"],
                created_at=row["created_at"],
                assessment_id=row["assessment_id"] if "assessment_id" in row.keys() else None,
            )

    def verify_evidence_integrity(self, evidence: Union[Evidence, int], project_id: Optional[int] = None) -> Tuple[bool, str]:
        """Verifies the SHA-256 cryptographic hash of evidence against the on-disk file.

        Returns:
            Tuple[bool, str]: (is_valid, status_message)
        """
        record = evidence if isinstance(evidence, Evidence) else self.get_evidence(evidence, project_id=project_id)
        if not record:
            return False, "Evidence record not found in database."
        if not record.file_path:
            return False, "Evidence record has no associated file path."

        file_path = Path(record.file_path)
        if not file_path.is_absolute():
            repo_root = Path(__file__).resolve().parent.parent
            candidate = repo_root / file_path
            if candidate.exists():
                file_path = candidate

        if not file_path.exists():
            return False, f"Evidence file does not exist on disk: {record.file_path}"

        expected_hash = (record.sha256_hash or record.file_hash or "").strip().lower()
        if not expected_hash:
            return False, "No expected SHA-256 hash stored in evidence record."

        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            computed_hash = hasher.hexdigest().lower()

            if computed_hash == expected_hash:
                return True, f"Integrity verified (SHA-256: {computed_hash})"
            else:
                return False, f"Integrity mismatch! Stored {expected_hash} != Computed {computed_hash}"
        except Exception as exc:
            return False, f"Error computing file hash: {exc}"

    # ---------------------------------------------------------
    # Assessment Plan Operations
    # ---------------------------------------------------------
    def create_assessment_plan(self, plan: AssessmentPlan) -> AssessmentPlan:
        """Stores a new assessment/test plan in SQLite."""
        query = """
            INSERT INTO assessment_plans (
                project_id, title, description, test_category, target,
                acceptance_criteria, status, preflight_blockers, execution_id,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    plan.project_id,
                    plan.title,
                    plan.description,
                    plan.test_category.value if hasattr(plan.test_category, "value") else str(plan.test_category),
                    plan.target,
                    plan.acceptance_criteria,
                    plan.status.value if hasattr(plan.status, "value") else str(plan.status),
                    plan.preflight_blockers,
                    plan.execution_id,
                    plan.created_at,
                    plan.updated_at,
                ),
            )
            plan.id = cursor.lastrowid
            return plan

    def update_assessment_plan(self, plan: AssessmentPlan) -> bool:
        """Updates an assessment plan's acceptance criteria, status, blockers, or execution."""
        query = """
            UPDATE assessment_plans
            SET title = ?, description = ?, test_category = ?, target = ?,
                acceptance_criteria = ?, status = ?, preflight_blockers = ?,
                execution_id = ?, updated_at = ?
            WHERE id = ?
        """
        now = _utc_now_iso()
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    plan.title,
                    plan.description,
                    plan.test_category.value if hasattr(plan.test_category, "value") else str(plan.test_category),
                    plan.target,
                    plan.acceptance_criteria,
                    plan.status.value if hasattr(plan.status, "value") else str(plan.status),
                    plan.preflight_blockers,
                    plan.execution_id,
                    now,
                    plan.id,
                ),
            )
            plan.updated_at = now
            return cursor.rowcount > 0

    def get_assessment_plan(self, plan_id: int) -> Optional[AssessmentPlan]:
        """Fetches an assessment plan by primary ID."""
        query = "SELECT * FROM assessment_plans WHERE id = ?"
        with self.session() as conn:
            row = conn.execute(query, (plan_id,)).fetchone()
            if not row:
                return None
            return self._row_to_assessment_plan(row)

    def list_assessment_plans(self, project_id: int) -> List[AssessmentPlan]:
        """Lists all assessment plans for an engagement ordered by ID descending."""
        query = "SELECT * FROM assessment_plans WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [self._row_to_assessment_plan(r) for r in rows]

    def delete_assessment_plan(self, plan_id: int) -> bool:
        """Deletes an assessment plan by ID."""
        query = "DELETE FROM assessment_plans WHERE id = ?"
        with self.session() as conn:
            cursor = conn.execute(query, (plan_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_assessment_plan(row: sqlite3.Row) -> AssessmentPlan:
        d = dict(row)
        cat_raw = d.get("test_category", "network_discovery")
        status_raw = d.get("status", "draft")
        try:
            category = TestCategory(cat_raw)
        except ValueError:
            category = TestCategory.NETWORK_DISCOVERY
        try:
            status = AssessmentStatus(status_raw)
        except ValueError:
            status = AssessmentStatus.DRAFT

        return AssessmentPlan(
            id=d.get("id"),
            project_id=d.get("project_id"),
            title=d.get("title", ""),
            description=d.get("description", ""),
            test_category=category,
            target=d.get("target", ""),
            acceptance_criteria=d.get("acceptance_criteria", ""),
            status=status,
            preflight_blockers=d.get("preflight_blockers", ""),
            execution_id=d.get("execution_id"),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )

    # ---------------------------------------------------------
    # Assessment Operations (Phase 7)
    # ---------------------------------------------------------
    @staticmethod
    def _row_to_assessment(row: sqlite3.Row) -> Assessment:
        d = dict(row)
        raw_status = d.get("status", "planned")
        try:
            status = AssessmentStatus(raw_status)
        except ValueError:
            status = AssessmentStatus.PLANNED
        return Assessment(
            id=d.get("id"),
            project_id=d.get("project_id"),
            name=d.get("name", ""),
            description=d.get("description", ""),
            authorized_scope=d.get("authorized_scope", ""),
            start_date=d.get("start_date", ""),
            end_date=d.get("end_date", ""),
            status=status,
            notes=d.get("notes", ""),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )

    def create_assessment(self, assessment: Assessment) -> Assessment:
        query = """
            INSERT INTO assessments (project_id, name, description, authorized_scope, start_date, end_date, status, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    assessment.project_id,
                    assessment.name,
                    assessment.description,
                    assessment.authorized_scope,
                    assessment.start_date,
                    assessment.end_date,
                    assessment.status.value if hasattr(assessment.status, "value") else str(assessment.status),
                    assessment.notes,
                    assessment.created_at or _utc_now_iso(),
                    assessment.updated_at or _utc_now_iso(),
                ),
            )
            assessment.id = cursor.lastrowid
            return assessment

    def update_assessment(self, assessment: Assessment) -> bool:
        query = """
            UPDATE assessments
            SET name = ?, description = ?, authorized_scope = ?, start_date = ?, end_date = ?, status = ?, notes = ?, updated_at = ?
            WHERE id = ?
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    assessment.name,
                    assessment.description,
                    assessment.authorized_scope,
                    assessment.start_date,
                    assessment.end_date,
                    assessment.status.value if hasattr(assessment.status, "value") else str(assessment.status),
                    assessment.notes,
                    _utc_now_iso(),
                    assessment.id,
                ),
            )
            return cursor.rowcount > 0

    def get_assessment(self, assessment_id: int) -> Optional[Assessment]:
        query = "SELECT * FROM assessments WHERE id = ?"
        with self.session() as conn:
            row = conn.execute(query, (assessment_id,)).fetchone()
            if not row:
                return None
            return self._row_to_assessment(row)

    def list_assessments(self, project_id: int, status: Optional[str] = None) -> List[Assessment]:
        if status:
            query = "SELECT * FROM assessments WHERE project_id = ? AND status = ? ORDER BY id DESC"
            params = (project_id, status)
        else:
            query = "SELECT * FROM assessments WHERE project_id = ? ORDER BY id DESC"
            params = (project_id,)
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_assessment(row) for row in rows]

    def delete_assessment(self, assessment_id: int) -> bool:
        with self.session() as conn:
            cursor = conn.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Terminal Session Operations
    # ---------------------------------------------------------
    def create_terminal_session(self, session: TerminalSessionRecord) -> TerminalSessionRecord:
        """Records an interactive terminal session in SQLite."""
        query = """
            INSERT INTO terminal_sessions (
                session_id, project_id, started_at, ended_at, working_directory,
                exit_status, raw_output_path, plain_text_path, sha256_hash,
                evidence_id, execution_id, command_count, commands_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    session.session_id,
                    session.project_id,
                    session.started_at,
                    session.ended_at,
                    session.working_directory,
                    session.exit_status,
                    session.raw_output_path,
                    session.plain_text_path,
                    session.sha256_hash,
                    session.evidence_id,
                    session.execution_id,
                    session.command_count,
                    session.commands_json,
                    session.created_at,
                ),
            )
            session.id = cursor.lastrowid
            return session

    def update_terminal_session(self, session: TerminalSessionRecord) -> None:
        """Updates timestamps, paths, hashes, and exit status for a terminal session."""
        query = """
            UPDATE terminal_sessions
            SET ended_at = ?, working_directory = ?, exit_status = ?,
                raw_output_path = ?, plain_text_path = ?, sha256_hash = ?,
                evidence_id = ?, execution_id = ?, command_count = ?, commands_json = ?
            WHERE session_id = ?
        """
        with self.session() as conn:
            conn.execute(
                query,
                (
                    session.ended_at,
                    session.working_directory,
                    session.exit_status,
                    session.raw_output_path,
                    session.plain_text_path,
                    session.sha256_hash,
                    session.evidence_id,
                    session.execution_id,
                    session.command_count,
                    session.commands_json,
                    session.session_id,
                ),
            )

    def get_terminal_session(self, session_id: str) -> Optional[TerminalSessionRecord]:
        """Retrieves a terminal session by its unique session_id."""
        query = "SELECT * FROM terminal_sessions WHERE session_id = ? LIMIT 1"
        with self.session() as conn:
            row = conn.execute(query, (session_id,)).fetchone()
            if not row:
                return None
            return TerminalSessionRecord(
                id=row["id"],
                session_id=row["session_id"],
                project_id=row["project_id"],
                started_at=row["started_at"],
                ended_at=row["ended_at"],
                working_directory=row["working_directory"],
                exit_status=row["exit_status"],
                raw_output_path=row["raw_output_path"],
                plain_text_path=row["plain_text_path"],
                sha256_hash=row["sha256_hash"],
                evidence_id=row["evidence_id"],
                execution_id=row["execution_id"],
                command_count=row["command_count"],
                commands_json=row["commands_json"],
                created_at=row["created_at"],
            )

    def list_terminal_sessions(self, project_id: int) -> List[TerminalSessionRecord]:
        """Lists all recorded terminal sessions for a project."""
        query = "SELECT * FROM terminal_sessions WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                TerminalSessionRecord(
                    id=row["id"],
                    session_id=row["session_id"],
                    project_id=row["project_id"],
                    started_at=row["started_at"],
                    ended_at=row["ended_at"],
                    working_directory=row["working_directory"],
                    exit_status=row["exit_status"],
                    raw_output_path=row["raw_output_path"],
                    plain_text_path=row["plain_text_path"],
                    sha256_hash=row["sha256_hash"],
                    evidence_id=row["evidence_id"],
                    execution_id=row["execution_id"],
                    command_count=row["command_count"],
                    commands_json=row["commands_json"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # -------------------------------------------------------------
    # OSINT Case Management & Observations Repository
    # -------------------------------------------------------------
    def create_osint_case(self, case: OSINTCase) -> OSINTCase:
        """Persists a new OSINT Case linked to an engagement project."""
        query = """
            INSERT INTO osint_cases (
                project_id, title, target_domain, objective,
                authorization_reference, status, analyst_notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cur = conn.execute(
                query,
                (
                    case.project_id,
                    case.title,
                    case.target_domain,
                    case.objective,
                    case.authorization_reference,
                    case.status,
                    case.analyst_notes,
                    case.created_at,
                ),
            )
            case.id = cur.lastrowid
            return case

    def list_osint_cases(self, project_id: int) -> List[OSINTCase]:
        """Lists all OSINT Cases under a specific project."""
        query = "SELECT * FROM osint_cases WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                OSINTCase(
                    id=row["id"],
                    project_id=row["project_id"],
                    title=row["title"],
                    target_domain=row["target_domain"],
                    objective=row["objective"],
                    authorization_reference=row["authorization_reference"],
                    status=row["status"],
                    analyst_notes=row["analyst_notes"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def get_osint_case(self, case_id: int) -> Optional[OSINTCase]:
        """Retrieves a single OSINT case by ID."""
        query = "SELECT * FROM osint_cases WHERE id = ?"
        with self.session() as conn:
            row = conn.execute(query, (case_id,)).fetchone()
            if not row:
                return None
            return OSINTCase(
                id=row["id"],
                project_id=row["project_id"],
                title=row["title"],
                target_domain=row["target_domain"],
                objective=row["objective"],
                authorization_reference=row["authorization_reference"],
                status=row["status"],
                analyst_notes=row["analyst_notes"],
                created_at=row["created_at"],
            )

    def create_observation(self, obs: Observation) -> Observation:
        """Persists an intelligence observation distinctly from confirmed vulnerabilities."""
        query = """
            INSERT INTO observations (
                project_id, title, case_id, asset_id, source_tool,
                method, raw_data, confidence, verification_status,
                evidence_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cur = conn.execute(
                query,
                (
                    obs.project_id,
                    obs.title,
                    obs.case_id,
                    obs.asset_id,
                    obs.source_tool,
                    obs.method,
                    obs.raw_data,
                    obs.confidence,
                    obs.verification_status,
                    obs.evidence_id,
                    obs.created_at,
                ),
            )
            obs.id = cur.lastrowid
            return obs

    def list_observations(self, project_id: int, case_id: Optional[int] = None) -> List[Observation]:
        """Lists observations for a project, optionally filtered by case."""
        if case_id is not None:
            query = "SELECT * FROM observations WHERE project_id = ? AND case_id = ? ORDER BY id DESC"
            params = (project_id, case_id)
        else:
            query = "SELECT * FROM observations WHERE project_id = ? ORDER BY id DESC"
            params = (project_id,)

        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                Observation(
                    id=row["id"],
                    project_id=row["project_id"],
                    title=row["title"],
                    case_id=row["case_id"],
                    asset_id=row["asset_id"],
                    source_tool=row["source_tool"],
                    method=row["method"],
                    raw_data=row["raw_data"],
                    confidence=row["confidence"],
                    verification_status=row["verification_status"],
                    evidence_id=row["evidence_id"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    def list_observations_for_asset(self, project_id: int, asset_id: int) -> List[Observation]:
        """Lists all historical observations recorded for a specific asset node."""
        query = "SELECT * FROM observations WHERE project_id = ? AND asset_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id, asset_id)).fetchall()
            return [
                Observation(
                    id=row["id"],
                    project_id=row["project_id"],
                    title=row["title"],
                    case_id=row["case_id"],
                    asset_id=row["asset_id"],
                    source_tool=row["source_tool"],
                    method=row["method"],
                    raw_data=row["raw_data"],
                    confidence=row["confidence"],
                    verification_status=row["verification_status"],
                    evidence_id=row["evidence_id"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Assessment Session Operations
    # ---------------------------------------------------------
    @staticmethod
    def _parse_selected_tools(val: Any) -> List[str]:
        if isinstance(val, list):
            return val
        if isinstance(val, str) and val.strip().startswith("["):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
        if isinstance(val, str) and val.strip():
            return [val.strip()]
        return []

    def create_assessment_session(self, session: AssessmentSession) -> AssessmentSession:
        """Persists a new assessment session."""
        tools_str = json.dumps(session.selected_tools) if isinstance(session.selected_tools, list) else (session.selected_tools or "[]")
        query = """
            INSERT INTO assessment_sessions (
                session_id, project_id, authorized_scope, selected_tools,
                status, started_at, ended_at, created_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    session.session_id,
                    session.project_id,
                    session.authorized_scope,
                    tools_str,
                    session.status,
                    session.started_at,
                    session.ended_at,
                    session.created_at,
                    session.metadata_json,
                ),
            )
            session.id = cursor.lastrowid
            return session

    def update_assessment_session(self, session: AssessmentSession) -> bool:
        """Updates assessment session status, end time, and metadata."""
        tools_str = json.dumps(session.selected_tools) if isinstance(session.selected_tools, list) else (session.selected_tools or "[]")
        query = """
            UPDATE assessment_sessions
            SET status = ?, ended_at = ?, metadata_json = ?, selected_tools = ?, authorized_scope = ?
            WHERE session_id = ?
        """
        with self.session() as conn:
            cursor = conn.execute(
                query,
                (
                    session.status,
                    session.ended_at,
                    session.metadata_json,
                    tools_str,
                    session.authorized_scope,
                    session.session_id,
                ),
            )
            return cursor.rowcount > 0

    def get_assessment_session(self, session_id: str) -> Optional[AssessmentSession]:
        """Retrieves an assessment session by its session_id string."""
        query = "SELECT * FROM assessment_sessions WHERE session_id = ? LIMIT 1"
        with self.session() as conn:
            row = conn.execute(query, (session_id,)).fetchone()
            if not row:
                return None
            return AssessmentSession(
                id=row["id"],
                session_id=row["session_id"],
                project_id=row["project_id"],
                authorized_scope=row["authorized_scope"],
                selected_tools=self._parse_selected_tools(row["selected_tools"]),
                status=row["status"],
                started_at=row["started_at"],
                ended_at=row["ended_at"],
                created_at=row["created_at"],
                metadata_json=row["metadata_json"],
            )

    def list_assessment_sessions(self, project_id: int) -> List[AssessmentSession]:
        """Lists all assessment sessions for a given project."""
        query = "SELECT * FROM assessment_sessions WHERE project_id = ? ORDER BY id DESC"
        with self.session() as conn:
            rows = conn.execute(query, (project_id,)).fetchall()
            return [
                AssessmentSession(
                    id=row["id"],
                    session_id=row["session_id"],
                    project_id=row["project_id"],
                    authorized_scope=row["authorized_scope"],
                    selected_tools=self._parse_selected_tools(row["selected_tools"]),
                    status=row["status"],
                    started_at=row["started_at"],
                    ended_at=row["ended_at"],
                    created_at=row["created_at"],
                    metadata_json=row["metadata_json"],
                )
                for row in rows
            ]

    # ---------------------------------------------------------
    # Finding Deduplication
    # ---------------------------------------------------------
    def find_duplicate_finding(
        self,
        project_id: int,
        title: str,
        affected_asset: str,
        affected_port_service: str = "",
    ) -> Optional[Finding]:
        """Checks if a matching finding already exists for the asset and service."""
        query = """
            SELECT * FROM findings
            WHERE project_id = ? AND title = ? AND affected_asset = ? AND affected_port_service = ?
            LIMIT 1
        """
        with self.session() as conn:
            row = conn.execute(
                query,
                (project_id, title, affected_asset, affected_port_service),
            ).fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def upsert_finding_deduplicated(self, finding: Finding) -> Finding:
        """Inserts finding only if not already recorded for the same asset/service."""
        existing = self.find_duplicate_finding(
            finding.project_id,
            finding.title,
            finding.affected_asset,
            finding.affected_port_service,
        )
        if existing:
            return existing
        return self.create_finding(finding)

    # Backward compatibility aliases
    create_evidence = add_evidence
    create_target_scope = add_scope
    list_target_scopes = list_scopes
    create_tool_execution = create_execution
    get_audit_logs = list_audit_logs
