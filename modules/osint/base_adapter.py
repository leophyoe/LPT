"""Base interface and normalized data structures for OSINT intelligence source adapters.

Enforces scope verification, capability detection, passive vs active distinction,
timeout handling, credential safety, and structured intelligence results.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    TargetScope,
)


@dataclass
class OSINTDiscoveryResult:
    """Normalized output contract returned by all OSINT source adapters."""
    source_tool: str
    target: str
    discovered_assets: List[AssetNode] = field(default_factory=list)
    relationships: List[AssetEdge] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    quarantined_assets: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    status: str = "completed"  # completed, failed, cancelled, unavailable, scope_rejected
    error_message: str = ""
    duration_seconds: float = 0.0
    evidence_id: Optional[int] = None


class BaseOSINTAdapter(abc.ABC):
    """Abstract contract for modular OSINT reconnaissance adapters."""

    def __init__(self, db: Database):
        self.db = db

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Internal canonical identifier (e.g. 'amass', 'cert_transparency', 'theharvester')."""
        pass

    @property
    @abc.abstractmethod
    def display_name(self) -> str:
        """User-facing display name."""
        pass

    @property
    @abc.abstractmethod
    def is_passive_capable(self) -> bool:
        """Indicates if this tool can run purely passive non-intrusive OSINT."""
        pass

    @property
    @abc.abstractmethod
    def requires_api_key(self) -> bool:
        """Indicates whether this tool requires paid or external API credentials."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Detects whether binary or required library is executable on this system."""
        pass

    @abc.abstractmethod
    def run_discovery(
        self,
        target_domain: str,
        project: Project,
        scopes: List[TargetScope],
        passive_only: bool = True,
        case_id: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        timeout: float = 120.0,
    ) -> OSINTDiscoveryResult:
        """Executes discovery, validates scope at boundary, and records assets & observations."""
        pass

