-- Migration 001: Phase 1 High-Impact Performance Indexes
-- Pre-conditions: Ensure database backup is taken before execution.

BEGIN TRANSACTION;

-- 1. Index findings for rapid severity filtering per project
CREATE INDEX IF NOT EXISTS idx_findings_project_severity 
ON findings(project_id, severity);

-- 2. Index target scopes for rapid Scope Guard authorization lookups
CREATE INDEX IF NOT EXISTS idx_target_scopes_project_auth 
ON target_scopes(project_id, is_authorized);

-- 3. Index evidence records for rapid project evidence vault rendering
CREATE INDEX IF NOT EXISTS idx_evidence_project 
ON evidence(project_id);

COMMIT;

-- Update query planner statistics
PRAGMA optimize;

