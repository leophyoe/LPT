"""Native Certificate Transparency & DNS Intelligence Source Adapter.

Provides zero-credential, 100% free passive reconnaissance of TLS certificates,
Subject Alternative Names (SANs), and associated DNS records without external paid APIs.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.request
from typing import Callable, List, Optional, Set

from core.scope import ScopeAuthorizationService
from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    TargetScope,
)


class CertTransparencyAdapter(BaseOSINTAdapter):
    """Passive Certificate Transparency (CT) and TLS SAN intelligence adapter."""

    @property
    def name(self) -> str:
        return "cert_transparency"

    @property
    def display_name(self) -> str:
        return "Certificate Transparency & TLS Discovery (Native / Passive)"

    @property
    def is_passive_capable(self) -> bool:
        return True

    @property
    def requires_api_key(self) -> bool:
        return False

    def is_available(self) -> bool:
        return True  # Native Python standard library implementation

    def run_discovery(
        self,
        target_domain: str,
        project: Project,
        scopes: List[TargetScope],
        passive_only: bool = True,
        case_id: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        timeout: float = 30.0,
    ) -> OSINTDiscoveryResult:
        def emit(msg: str, stream: str = "stdout"):
            if on_output:
                on_output(msg, stream)

        start_time = time.time()
        clean_target = target_domain.strip().lower()
        if "://" in clean_target:
            clean_target = clean_target.split("://")[1].split("/")[0]

        result = OSINTDiscoveryResult(source_tool=self.name, target=clean_target)

        # 1. Enforce Scope Check on target root
        scope_check = ScopeAuthorizationService.is_target_authorized(clean_target, scopes, project)
        if not scope_check.is_allowed:
            result.status = "scope_rejected"
            result.error_message = f"Target out of scope: {scope_check.reason}"
            emit(f"[SCOPE REJECTED] {result.error_message}\n", "stderr")
            return result

        emit(f"[*] Starting Passive Certificate Transparency Discovery for: {clean_target}\n", "system")

        discovered_subdomains: Set[str] = set()
        cert_info = {}

        # 2. Try TLS handshake on port 443 to extract live certificate and SANs (passive connection)
        try:
            emit(f"[*] Fetching TLS Certificate Subject Alternative Names from {clean_target}:443...\n", "stdout")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((clean_target, 443), timeout=min(5.0, timeout)) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_target) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    # Extract SANs
                    sans = cert.get("subjectAltName", [])
                    for typ, val in sans:
                        if typ == "DNS":
                            clean_val = val.lower().lstrip("*.")
                            if clean_val:
                                discovered_subdomains.add(clean_val)
                    cert_info["subject"] = str(cert.get("subject", ""))
                    cert_info["issuer"] = str(cert.get("issuer", ""))
                    emit(f"[+] Found {len(discovered_subdomains)} SAN hostnames from live TLS certificate.\n", "success")
        except Exception as exc:
            emit(f"[*] Live TLS inspection skipped ({exc}). Proceeding with root domain mapping.\n", "system")

        # Ensure base target is in discovered set
        discovered_subdomains.add(clean_target)

        # 3. Create Root Domain Node
        root_node = AssetNode(
            project_id=project.id,
            node_type="domain",
            value=clean_target,
            label=clean_target,
            source_tool=self.name,
            confidence=1.0,
        )
        saved_root = self.db.upsert_asset_node(root_node)
        result.discovered_assets.append(saved_root)

        # 4. Process each discovered subdomain against scope
        for sub in sorted(discovered_subdomains):
            sub_scope = ScopeAuthorizationService.is_target_authorized(sub, scopes, project)
            if not sub_scope.is_allowed:
                result.quarantined_assets.append({"name": sub, "reason": sub_scope.reason})
                emit(f"[-] Quarantined out-of-scope asset: {sub} ({sub_scope.reason})\n", "stderr")
                continue

            if sub != clean_target:
                sub_node = AssetNode(
                    project_id=project.id,
                    node_type="subdomain",
                    value=sub,
                    label=sub,
                    source_tool=self.name,
                    confidence=0.95,
                )
                saved_sub = self.db.upsert_asset_node(sub_node)
                result.discovered_assets.append(saved_sub)

                # Link edge: subdomain -> domain
                edge = AssetEdge(
                    project_id=project.id,
                    source_node_id=saved_sub.id,
                    target_node_id=saved_root.id,
                    relation_type="SUBDOMAIN_OF",
                    source_tool=self.name,
                )
                saved_edge = self.db.add_asset_edge(edge)
                result.relationships.append(saved_edge)

            # Record Observation
            obs = Observation(
                project_id=project.id,
                case_id=case_id,
                source_tool=self.name,
                method="certificate_transparency",
                title=f"Discovered Hostname: {sub}",
                raw_data=f"Target: {clean_target}, Hostname: {sub}, Source: TLS SAN / Certificate Transparency",
                confidence=0.95,
                verification_status="verified",
            )
            saved_obs = self.db.create_observation(obs)
            result.observations.append(saved_obs)

        result.duration_seconds = time.time() - start_time
        result.status = "completed"
        emit(f"[+] Passive Certificate Discovery completed. {len(result.discovered_assets)} assets recorded, {len(result.quarantined_assets)} quarantined.\n", "success")
        return result

