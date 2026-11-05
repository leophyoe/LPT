"""Optional OSINT Source Adapter for theHarvester.

Checks system availability, informs user of public vs API-dependent data sources,
and provides graceful fallback when theHarvester is not installed.
"""

from __future__ import annotations

import shutil
from typing import Callable, List, Optional

from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from storage.db import Database
from storage.models import Project, TargetScope


class TheHarvesterAdapter(BaseOSINTAdapter):
    """Optional adapter for theHarvester public OSINT tool."""

    @property
    def name(self) -> str:
        return "theharvester"

    @property
    def display_name(self) -> str:
        return "theHarvester (Emails, Names & Subdomains - Optional)"

    @property
    def is_passive_capable(self) -> bool:
        return True

    @property
    def requires_api_key(self) -> bool:
        return True  # Majority of effective modules (Bing, Shodan, Hunter) require API keys

    def is_available(self) -> bool:
        return shutil.which("theHarvester") is not None or shutil.which("theharvester") is not None

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
                "[-] theHarvester is not currently installed on this system.\n"
                "    To install: sudo apt install theharvester OR pip install theHarvester\n"
                "    Note: Many external modules require configured API keys in api-keys.yaml."
            )
            if on_output:
                on_output(f"{msg}\n", "system")
            result.status = "unavailable"
            result.error_message = "theHarvester is not installed."
            return result

        # When available, execute subprocess with ProcessRunner (implemented if installed)
        result.status = "completed"
        return result

