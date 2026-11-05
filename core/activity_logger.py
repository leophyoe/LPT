"""Activity logging service with automatic secret scrubbing.

Records user-approved scan operations, scan starts, completions, imports,
exports, errors, and report generation events without leaking credentials,
API keys, or sensitive material.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from storage.db import Database
from storage.models import EngagementAuditLog, _utc_now_iso

# Regex patterns matching known secret shapes
SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"(?i)(api[_-]?key[\s:=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
    re.compile(r"(?i)(password[\s:=]+)[^\s,;]+", re.IGNORECASE),
    re.compile(r"(?i)(token[\s:=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
]

SENSITIVE_KEY_NAMES = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth", "authorization", "bearer", "credential", "credentials",
    "private_key", "deepseek_api_key", "openai_api_key", "anthropic_api_key",
}


def sanitize_text(text: str) -> str:
    """Scrub sensitive patterns such as tokens, bearer auth, and passwords from string."""
    if not text or not isinstance(text, str):
        return str(text or "")
    sanitized = text
    for pat in SECRET_PATTERNS:
        sanitized = pat.sub(r"\1[REDACTED]" if pat.groups else "[REDACTED]", sanitized)
    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively scrub sensitive keys and secret values from collections."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEY_NAMES or any(s in str(k).lower() for s in ("password", "secret", "apikey", "api_key", "token")):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_data(v)
        return cleaned
    elif isinstance(data, (list, tuple)):
        return [sanitize_data(x) for x in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    return data


class ActivityLogger:
    """Integrates audit logging into assessment workflows with strict secret sanitization."""

    def __init__(self, db: Database):
        self.db = db

    def log(
        self,
        project_id: int,
        action: str,
        outcome: str = "success",
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "operator",
    ) -> EngagementAuditLog:
        """Sanitizes details and persists an activity log entry."""
        payload: Dict[str, Any] = {
            "action_type": action,
            "outcome": outcome,
        }
        if session_id:
            payload["session_id"] = session_id

        if details:
            payload.update(sanitize_data(details))

        details_json = json.dumps(payload, default=str)

        entry = EngagementAuditLog(
            project_id=project_id,
            action=action,
            actor=actor,
            details=details_json,
            timestamp=_utc_now_iso(),
        )
        return self.db.add_audit_log(entry)

    def list_logs(self, project_id: int) -> List[EngagementAuditLog]:
        """Lists historical audit entries for project."""
        return self.db.list_audit_logs(project_id)

