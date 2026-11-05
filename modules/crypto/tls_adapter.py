"""TLS / SSL Security Assessment Adapter.

Integrates the TLS/SSL Certificate & Cipher Suite Analyzer into CyberSecuritySuite:
- Strict ScopeAuthorizationService validation prior to connection.
- ToolExecution recording with lifecycle states (QUEUED, RUNNING, COMPLETED, FAILED, BLOCKED).
- Automatic SHA-256 evidence vaulting.
- Normalized finding persistence with deduplication.
- AssetNode inventory synchronization (X.509 certificates and secure service ports).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from core.base_adapter import BaseSecurityAdapter, SecurityToolResult
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from modules.crypto.tls_analyzer import TLSAssessmentEngine, TLSAssessmentReport
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ToolExecution,
    _utc_now_iso,
)

logger = logging.getLogger(__name__)


class TLSAssessmentAdapter(BaseSecurityAdapter):
    """Orchestrates professional TLS/SSL and cryptographic cipher evaluations."""

    def __init__(self, db: Database, evidence_dir: Optional[Union[Path, str]] = None):
        super().__init__(db)
        if evidence_dir is None:
            self.evidence_dir = Path("storage/evidence")
        elif isinstance(evidence_dir, str):
            self.evidence_dir = Path(evidence_dir)
        else:
            self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @property
    def tool_name(self) -> str:
        return "tls_analyzer"

    @property
    def display_name(self) -> str:
        return "TLS / SSL Certificate & Cipher Suite Analyzer"

    def check_availability(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Pure Python engine is always available on the host environment."""
        import ssl
        return True, f"Python ssl (OpenSSL {ssl.OPENSSL_VERSION})", "internal:modules.crypto.tls_analyzer"

    def assess_target(
        self,
        project_id: int,
        target_host: str,
        port: int = 443,
        timeout: float = 3.0,
        output_callback: Optional[Callable[[str, str], None]] = None,
    ) -> SecurityToolResult:
        """Executes a full, scope-validated TLS assessment against target_host:port."""
        t_start = datetime.now(timezone.utc)
        target_str = f"{target_host}:{port}"

        def emit(msg: str, stream: str = "stdout"):
            if output_callback:
                output_callback(msg, stream)

        emit(f"[*] Pre-flight: Validating scope authorization for target '{target_str}'...\n", "system")

        # 1. Scope Enforcement (Fail-Closed)
        project = self.db.get_project(project_id) if self.db else None
        scope_res = self.validate_target_scope(target_host, project_id, project=project)

        if not scope_res.is_allowed:
            emit(f"[-] Access Denied: Target '{target_str}' outside authorized scope: {scope_res.reason}\n", "stderr")
            return SecurityToolResult(
                tool_name=self.tool_name,
                target=target_str,
                is_authorized=False,
                scope_reason=scope_res.reason,
                execution_status=ExecutionStatus.FAILED,
                error_message=f"Scope authorization rejected: {scope_res.reason}",
            )

        emit(f"[+] Scope authorized: {scope_res.reason}\n", "success")

        # DNS Resolution, IPv4/IPv6 Validation & DNS Rebinding Guard
        connect_ip: Optional[str] = None
        if self._is_ip(target_host):
            connect_ip = target_host
        else:
            try:
                emit(f"[*] Resolving DNS for target hostname '{target_host}'...\n", "system")
                addr_infos = socket.getaddrinfo(target_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips: List[str] = []
                for addr in addr_infos:
                    ip_str = addr[4][0]
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)

                if not resolved_ips:
                    err_msg = f"DNS resolution returned no IP addresses for '{target_host}'; authorization rejected."
                    emit(f"[-] Access Denied: {err_msg}\n", "stderr")
                    return SecurityToolResult(
                        tool_name=self.tool_name,
                        target=target_str,
                        is_authorized=False,
                        scope_reason=err_msg,
                        execution_status=ExecutionStatus.FAILED,
                        error_message=err_msg,
                    )

                # Validate every resolved IP address against engagement scope
                for r_ip in resolved_ips:
                    ip_scope_res = self.validate_target_scope(r_ip, project_id, project=project)
                    if not ip_scope_res.is_allowed:
                        err_msg = (
                            f"Target hostname '{target_host}' resolves to IP '{r_ip}', "
                            f"which is outside authorized scope: {ip_scope_res.reason}"
                        )
                        emit(f"[-] Access Denied: {err_msg}\n", "stderr")
                        return SecurityToolResult(
                            tool_name=self.tool_name,
                            target=target_str,
                            is_authorized=False,
                            scope_reason=err_msg,
                            execution_status=ExecutionStatus.FAILED,
                            error_message=err_msg,
                        )

                # Pin connection to the first verified authorized IP to prevent DNS rebinding
                connect_ip = resolved_ips[0]
                emit(f"[+] DNS verified: {target_host} -> {resolved_ips} (Pinned: {connect_ip})\n", "success")

            except (socket.gaierror, OSError) as dns_err:
                err_msg = f"DNS resolution failed for '{target_host}': {dns_err}; failed closed."
                emit(f"[-] Access Denied: {err_msg}\n", "stderr")
                return SecurityToolResult(
                    tool_name=self.tool_name,
                    target=target_str,
                    is_authorized=False,
                    scope_reason=err_msg,
                    execution_status=ExecutionStatus.FAILED,
                    error_message=err_msg,
                )

        # 2. Record ToolExecution
        exec_record: Optional[ToolExecution] = None
        if self.db:
            exec_record = self.db.create_tool_execution(
                ToolExecution(
                    project_id=project_id,
                    tool_name=self.tool_name,
                    command=f"tls_analyzer --target {target_host} --port {port}",
                    status=ExecutionStatus.RUNNING,
                    started_at=_utc_now_iso(),
                )
            )

        execution_id = exec_record.id if exec_record else None

        # 3. Execute Assessment Probes
        try:
            emit(f"[*] Initiating TLS Handshake & Certificate Deep-Inspection on {target_host}:{port}...\n", "stdout")
            report: TLSAssessmentReport = TLSAssessmentEngine.assess_target(
                project_id=project_id,
                target_host=target_host,
                port=port,
                timeout=timeout,
                connect_ip=connect_ip,
            )

            emit(f"[+] Certificate analysis completed. Hostname match: {report.certificate.hostname_matches if report.certificate else 'N/A'}\n", "success")
            emit(f"[*] Audited {len(report.protocols)} protocol versions and {len(report.cipher_groups)} cipher categories.\n", "stdout")
            emit(f"[+] Security findings identified: {len(report.findings)} issues.\n", "system")

        except Exception as exc:
            err_msg = f"TLS Assessment execution error on {target_host}:{port}: {exc}"
            logger.exception(err_msg)
            emit(f"[-] Error: {err_msg}\n", "stderr")

            if exec_record and self.db:
                exec_record.status = ExecutionStatus.FAILED
                exec_record.finished_at = _utc_now_iso()
                self.db.update_execution(exec_record)

            return SecurityToolResult(
                tool_name=self.tool_name,
                target=target_str,
                is_authorized=True,
                scope_reason=scope_res.reason,
                execution_status=ExecutionStatus.FAILED,
                execution_id=execution_id,
                error_message=err_msg,
            )

        # 4. Cryptographic Evidence Vaulting
        evidence_id: Optional[int] = None
        evidence_hash: Optional[str] = None
        try:
            # Build clean serializable payload
            evidence_data = {
                "assessment_target": target_str,
                "timestamp": report.timestamp,
                "overall_posture": report.overall_posture,
                "certificate": asdict(report.certificate) if report.certificate else None,
                "protocols": [asdict(p) for p in report.protocols],
                "cipher_groups": [asdict(c) for c in report.cipher_groups],
                "findings": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "cvss_score": f.cvss_score,
                        "affected_asset": f.affected_asset,
                        "remediation": f.remediation,
                    }
                    for f in report.findings
                ],
            }
            json_payload = json.dumps(evidence_data, indent=2)
            report.evidence_payload = json_payload

            evidence_hash = hashlib.sha256(json_payload.encode("utf-8")).hexdigest()
            filename = f"tls_evidence_{target_host}_{port}_{int(t_start.timestamp())}.json"
            ev_file_path = self.evidence_dir / filename
            with open(ev_file_path, "w", encoding="utf-8") as f:
                f.write(json_payload)

            if self.db:
                ev_obj = self.db.add_evidence(
                    Evidence(
                        project_id=project_id,
                        file_path=str(ev_file_path),
                        sha256_hash=evidence_hash,
                        execution_id=execution_id,
                        description=f"Raw cryptographic evidence for TLS assessment on {target_str}",
                        mime_type="application/json",
                    )
                )
                evidence_id = ev_obj.id

            emit(f"[+] Cryptographic evidence vaulted: SHA256={evidence_hash[:16]}... ({filename})\n", "success")

        except Exception as ev_err:
            logger.warning(f"Failed to vault evidence file: {ev_err}")

        # 5. Persist Deduplicated Findings linked to Execution and Evidence
        persisted_findings: List[Finding] = []
        for finding in report.findings:
            finding.execution_id = execution_id
            if self.db:
                saved = self.persist_finding_deduplicated(finding)
                persisted_findings.append(saved)
            else:
                persisted_findings.append(finding)

        # 6. Inventory Enrichment & AssetNode Updates
        if self.db and report.certificate:
            try:
                cert = report.certificate
                # Upsert Certificate AssetNode
                cert_node = self.db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type="cert",
                        value=cert.sha256_fingerprint or f"cert:{target_str}",
                        label=f"Cert: {cert.subject.get('commonName', target_host)}",
                        source_tool=self.tool_name,
                        confidence=1.0,
                        metadata_json=json.dumps({
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "sans": cert.subject_alt_names,
                            "not_after": cert.not_after,
                            "key_size": cert.public_key_bits,
                            "sig_alg": cert.signature_algorithm,
                            "validation_status": cert.validation_status,
                            "sha256": cert.sha256_fingerprint,
                        }),
                    )
                )

                # Link Host to Certificate:
                # Query existing nodes for project to find host_node without calling nonexistent methods
                existing_nodes = self.db.list_asset_nodes(project_id)
                host_node = next((n for n in existing_nodes if n.value == target_host), None)
                if not host_node:
                    host_node = self.db.upsert_asset_node(
                        AssetNode(
                            project_id=project_id,
                            node_type="ip" if self._is_ip(target_host) else "domain",
                            value=target_host,
                            label=target_host,
                            source_tool=self.tool_name,
                        )
                    )

                if host_node and cert_node and host_node.id and cert_node.id:
                    self.db.upsert_asset_edge(
                        AssetEdge(
                            project_id=project_id,
                            source_node_id=host_node.id,
                            target_node_id=cert_node.id,
                            relation_type="HAS_CERTIFICATE",
                            source_tool=self.tool_name,
                            evidence_id=evidence_id,
                        )
                    )
                    emit(f"[+] Asset inventory updated: Linked {target_host} -> {cert_node.label} (HAS_CERTIFICATE)\n", "success")
                else:
                    err_msg = (
                        f"Failed to link host to certificate: "
                        f"host_node_id={getattr(host_node, 'id', None)}, "
                        f"cert_node_id={getattr(cert_node, 'id', None)}"
                    )
                    logger.error(err_msg)
                    emit(f"[-] {err_msg}\n", "stderr")
            except Exception as inv_err:
                logger.error(f"Failed to persist TLS inventory / relationships: {inv_err}", exc_info=True)
                emit(f"[-] Error updating asset inventory: {inv_err}\n", "stderr")

        # 7. Finalize ToolExecution
        duration = (datetime.now(timezone.utc) - t_start).total_seconds()
        if exec_record and self.db:
            exec_record.status = ExecutionStatus.COMPLETED
            exec_record.exit_code = 0
            exec_record.finished_at = _utc_now_iso()
            exec_record.duration_seconds = duration
            if evidence_hash:
                exec_record.raw_output_path = str(self.evidence_dir / f"tls_evidence_{target_host}_{port}_{int(t_start.timestamp())}.json")
            self.db.update_execution(exec_record)

        emit(f"[+] TLS Security Assessment concluded successfully in {duration:.2f}s.\n", "success")

        return SecurityToolResult(
            tool_name=self.tool_name,
            target=target_str,
            is_authorized=True,
            scope_reason=scope_res.reason,
            execution_status=ExecutionStatus.COMPLETED,
            execution_id=execution_id,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            findings=persisted_findings,
            raw_output=report.evidence_payload,
            duration_seconds=duration,
        )

    @staticmethod
    def _is_ip(val: str) -> bool:
        try:
            import ipaddress
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False
