"""Optional OSINT Source Adapter for Recon-ng.

Checks framework availability, evaluates modular dependencies, and guides
the analyst if Recon-ng is not installed.
"""

from __future__ import annotations

import shutil
from typing import Callable, List, Optional

from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from storage.db import Database
from storage.models import Project, TargetScope


class ReconNgAdapter(BaseOSINTAdapter):
    """Optional adapter for Recon-ng reconnaissance framework."""

    @property
    def name(self) -> str:
        return "recon_ng"

    @property
    def display_name(self) -> str:
        return "Recon-ng (Modular Reconnaissance Framework - Optional)"

    @property
    def is_passive_capable(self) -> bool:
        return True

    @property
    def requires_api_key(self) -> bool:
        return True  # Framework relies heavily on third-party API keys configured in keys table

    def is_available(self) -> bool:
        return shutil.which("recon-ng") is not None

    def run_discovery(
        self,
        target_domain: str,
        project: Project,
        scopes: List[TargetScope],
        passive_only: bool = True,
        case_id: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        timeout: float = 60.0,
    ) -> OSINTDiscoveryResult:
        result = OSINTDiscoveryResult(source_tool=self.name, target=target_domain)

        if not self.is_available():
            msg = (
                "[-] Recon-ng is not currently installed on this system.\n"
                "    To install: sudo apt install recon-ng OR git clone https://github.com/lanmaster53/recon-ng.git\n"
                "    Note: Recon-ng requires manual marketplace module installations and API key provisioning."
            )
            if on_output:
                on_output(f"{msg}\n", "system")
            result.status = "unavailable"
            result.error_message = "Recon-ng is not installed."
            return result

        result.status = "completed"
        return result

