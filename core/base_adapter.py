"""Base security adapter interface and standardized result contract for CyberSecuritySuite.

Defines the consistent execution lifecycle, scope enforcement, evidence hashing,
normalized findings, and assessment linkage for all integrated security tools.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    Project,
    TargetScope,
    ToolExecution,
    _utc_now_iso,
)


@dataclass
class SecurityToolResult:
    """Standardized result returned across all security tool adapters."""
    tool_name: str
    target: str
    is_authorized: bool
    scope_reason: str
    execution_status: ExecutionStatus
    execution_id: Optional[int] = None
    evidence_id: Optional[int] = None
    evidence_hash: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
    duration_seconds: float = 0.0
    assessment_id: Optional[int] = None


class BaseSecurityAdapter(abc.ABC):
    """Abstract base class establishing a consistent integration contract for security tools."""

    def __init__(self, db: Database):
        self.db = db

    @property
    @abc.abstractmethod
    def tool_name(self) -> str:
        """Canonical tool identifier matching ToolRegistry (e.g. 'nmap', 'c0desec', 'zaproxy', 'burpsuite')."""
        pass

    @property
    @abc.abstractmethod
    def display_name(self) -> str:
        """Human-readable display name."""
        pass

    def check_availability(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Verifies if the underlying tool binary or engine is available on the host system.
        
        Returns:
            Tuple[is_installed, version_str, binary_path]
        """
        registry = ToolRegistry()
        tool = registry.get_tool(self.tool_name)
        if tool and tool.is_installed:
            return True, tool.version, tool.binary_path
        return False, None, None

    def validate_target_scope(
        self,
        target: str,
        project_id: int,
        project: Optional[Project] = None,
    ) -> ScopeCheckResult:
        """Enforces strict scope authorization and engagement lifecycle checks."""
        scopes = self.db.list_scopes(project_id) if self.db else []
        if project is None and self.db:
            project = self.db.get_project(project_id)
        return ScopeAuthorizationService.is_target_authorized(target, scopes, project=project)

    def persist_finding_deduplicated(self, finding: Finding) -> Finding:
        """Saves a normalized finding using deduplication to prevent duplicate records on repeated imports."""
        if not self.db:
            return finding
        return self.db.upsert_finding_deduplicated(finding)

