"""OWASP Amass OSINT Source Adapter.

Integrates OWASP Amass into the unified OSINT Workspace architecture, enforcing
passive reconnaissance by default, scope validation, and observation tracking.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, List, Optional

from modules.network.amass_adapter import AmassAdapter, AmassOptions
from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    TargetScope,
)


class AmassOSINTAdapter(BaseOSINTAdapter):
    """Unified OSINT adapter for OWASP Amass."""

    def __init__(self, db: Database):
        super().__init__(db)
        self.adapter = AmassAdapter(db=self.db)

    @property
    def name(self) -> str:
        return "amass"

    @property
    def display_name(self) -> str:
        return "OWASP Amass (Domain & Subdomain Enumeration)"

    @property
    def is_passive_capable(self) -> bool:
        return True

    @property
    def requires_api_key(self) -> bool:
        return False  # Free/local by default; API keys are purely optional

    def is_available(self) -> bool:
        """Verifies if a genuine, functional Amass binary is installed (not a broken wrapper)."""
        from core.registry import ToolRegistry
        tool = ToolRegistry().get_tool("amass")
        if tool and tool.is_installed:
            return True
        host_bin = shutil.which("amass")
        if host_bin and Path(host_bin).resolve() != Path("bin/amass").resolve():
            return True
        return False

    def cancel(self) -> bool:
        return self.adapter.cancel()

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
        options = AmassOptions(
            target_domain=target_domain,
            passive_only=passive_only,
            active_recon=not passive_only,
            timeout=timeout,
        )

        evidence_dir = Path("storage/evidence") / f"project_{project.id}"
        success, msg, findings, tool_exec, amass_res = self.adapter.execute_scan(
            project=project,
            options=options,
            scopes=scopes,
            on_output=on_output,
            evidence_dir=evidence_dir,
        )

        result = OSINTDiscoveryResult(
            source_tool=self.name,
            target=target_domain,
            status="completed" if success else ("scope_rejected" if "out of scope" in msg.lower() else "failed"),
            error_message="" if success else msg,
        )

        if amass_res:
            result.quarantined_assets = amass_res.quarantined
            # Load stored asset nodes & edges from DB for this project
            nodes = self.db.list_asset_nodes(project.id)
            edges = self.db.list_asset_edges(project.id)
            result.discovered_assets = nodes
            result.relationships = edges

            # Record OSINT Observations (distinct from vulnerability findings)
            for rec in amass_res.records:
                obs = Observation(
                    project_id=project.id,
                    case_id=case_id,
                    source_tool="amass",
                    method="amass_passive" if passive_only else "amass_active",
                    title=f"Discovered {rec.name} ({rec.tag})",
                    raw_data=f"Domain: {rec.domain}, IPs: {', '.join(a.ip for a in rec.addresses if a.ip)}, Sources: {', '.join(rec.sources)}",
                    confidence=1.0,
                    verification_status="verified",
                    evidence_id=tool_exec.id if tool_exec else None,
                )
                saved_obs = self.db.create_observation(obs)
                result.observations.append(saved_obs)

        return result

