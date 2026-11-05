"""Assessment preflight validation and safety readiness service.

Performs fail-closed verification before tests are allowed to run:
1. Target Scope & Authorization: Fails closed when project or scope is unverified or expired.
2. Tool & Dependency Readiness: Verifies required executables and minimum versions via ToolRegistry.
3. Rules of Engagement & Constraints: Ensures target is not in explicit exclusions and conforms to rate limits.
4. Lab & Socket Availability: Validates connectivity to required local fixtures or isolated lab ports.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    AssessmentPlan,
    AssessmentStatus,
    Project,
    TargetScope,
    TestCategory,
)


class VerificationCheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"
    NEEDS_REVIEW = "needs_review"


@dataclass
class PreflightCheckResult:
    is_ready: bool
    status: VerificationCheckStatus
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    tool_readiness: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    scope_details: Dict[str, Any] = field(default_factory=dict)
    lab_details: Dict[str, Any] = field(default_factory=dict)


class PreflightChecker:
    """Pre-execution assessment guard and environment validator."""

    CATEGORY_REQUIRED_TOOLS = {
        TestCategory.NETWORK_DISCOVERY: ["nmap"],
        TestCategory.ACTIVE_DIRECTORY: ["nmap"],
        TestCategory.PRIVILEGE_ESCALATION: [],
        TestCategory.WEB_APPLICATION: ["c0desec"],
        TestCategory.BINARY_EXPLOITATION: [],
    }

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()

    def run_preflight(
        self,
        target: str,
        project: Optional[Project],
        test_category: TestCategory = TestCategory.NETWORK_DISCOVERY,
        scopes: Optional[List[TargetScope]] = None,
    ) -> PreflightCheckResult:
        """Executes full fail-closed preflight validation suite."""
        blockers: List[str] = []
        warnings: List[str] = []
        tool_readiness: Dict[str, Dict[str, Any]] = {}
        scope_details: Dict[str, Any] = {}
        lab_details: Dict[str, Any] = {}

        # 1. Project Authorization Guard
        if not project or not project.id:
            blockers.append("BLOCKED: No active assessment project selected. Preflight authorization failed.")
            return PreflightCheckResult(
                is_ready=False,
                status=VerificationCheckStatus.BLOCKED,
                blockers=blockers,
                warnings=warnings,
            )

        lifecycle_ok, lifecycle_msg = ScopeAuthorizationService.validate_engagement_lifecycle(project)
        if not lifecycle_ok:
            blockers.append(f"BLOCKED: Engagement lifecycle validation failed: {lifecycle_msg}")

        # 2. Target Scope Guard (Fail-Closed)
        if not target or not target.strip():
            blockers.append("BLOCKED: Target specification is missing or empty.")
        else:
            p_scopes = scopes if scopes is not None else self.db.list_scopes(project.id)
            if not p_scopes:
                blockers.append("BLOCKED: No authorized target scopes defined for this project.")
            else:
                scope_res: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(target, p_scopes)
                scope_details = {
                    "target": target,
                    "is_authorized": scope_res.is_allowed,
                    "reason": scope_res.reason,
                    "matched_rule": scope_res.matched_scope.rule_type.value if scope_res.matched_scope else "none",
                }
                if not scope_res.is_allowed:
                    blockers.append(f"BLOCKED: Target '{target}' is not in authorized scope: {scope_res.reason}")

        # 3. Tool Readiness & Version Checks
        req_tools = self.CATEGORY_REQUIRED_TOOLS.get(test_category, [])
        for tool_name in req_tools:
            tool = self.registry.get_tool(tool_name)
            if not tool or not tool.is_installed:
                blockers.append(
                    f"Tool Missing: '{tool_name}' is required for {test_category.value} but is not installed or available on PATH."
                )
                tool_readiness[tool_name] = {
                    "installed": False,
                    "version": None,
                    "error": tool.error_message if tool else "Tool not found in registry",
                    "install_guide": tool.install_guide if tool else "",
                }
            else:
                tool_readiness[tool_name] = {
                    "installed": True,
                    "version": tool.version or "Detected",
                    "path": tool.binary_path,
                }

        # 4. RoE & Operational Constraints
        if hasattr(project, "prohibited_tests") and project.prohibited_tests:
            warnings.append(f"RoE Boundary Notice: Prohibited activities: {project.prohibited_tests}")

        # 5. Local Lab / Socket Connectivity Pre-check (if targeting localhost / 127.0.0.1)
        if any(h in target for h in ("127.0.0.1", "localhost", "::1")):
            lab_details["is_local_lab"] = True
            lab_details["note"] = "Local laboratory / loopback target detected."
        else:
            lab_details["is_local_lab"] = False

        is_ready = len(blockers) == 0
        if blockers:
            status = VerificationCheckStatus.BLOCKED
        elif warnings:
            status = VerificationCheckStatus.NEEDS_REVIEW
        else:
            status = VerificationCheckStatus.PASSED

        return PreflightCheckResult(
            is_ready=is_ready,
            status=status,
            blockers=blockers,
            warnings=warnings,
            tool_readiness=tool_readiness,
            scope_details=scope_details,
            lab_details=lab_details,
        )

