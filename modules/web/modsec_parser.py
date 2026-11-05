"""ModSecurity Web Application Firewall (WAF) Audit Log Parser for CyberSecuritySuite.

Parses ModSecurity audit log transactions (Sections A through Z), extracting
HTTP request metadata, matched OWASP Core Rule Set (CRS) IDs, attack categories
(SQLi, XSS, RCE, Path Traversal), and correlates events into normalized findings
and cryptographic evidence records.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    ValidationStatus,
    _utc_now_iso,
)


@dataclass
class ModSecRuleMatch:
    """Represents a specific WAF rule trigger inside a transaction trailer."""
    rule_id: str
    message: str
    severity: str
    tags: List[str] = field(default_factory=list)
    data: str = ""
    file_origin: str = ""
    line_number: str = ""


@dataclass
class ModSecTransaction:
    """Represents an entire ModSecurity audit log transaction."""
    transaction_id: str
    timestamp: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    method: str = "GET"
    uri: str = "/"
    protocol: str = "HTTP/1.1"
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    rule_matches: List[ModSecRuleMatch] = field(default_factory=list)
    raw_section_a: str = ""
    raw_section_b: str = ""
    raw_section_c: str = ""
    raw_section_h: str = ""


class ModSecurityParser:
    """Parser and correlation engine for ModSecurity WAF audit logs."""

    # Map ModSecurity severities (0-EMERGENCY to 7-DEBUG) to FindingSeverity
    SEVERITY_MAP = {
        "0": FindingSeverity.CRITICAL,  # EMERGENCY
        "1": FindingSeverity.CRITICAL,  # ALERT
        "2": FindingSeverity.CRITICAL,  # CRITICAL
        "3": FindingSeverity.HIGH,      # ERROR
        "4": FindingSeverity.MEDIUM,    # WARNING
        "5": FindingSeverity.LOW,       # NOTICE
        "6": FindingSeverity.INFORMATIONAL,  # INFO
        "7": FindingSeverity.INFORMATIONAL,  # DEBUG
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "warning": FindingSeverity.MEDIUM,
        "notice": FindingSeverity.LOW,
        "error": FindingSeverity.HIGH,
    }

    @classmethod
    def parse_log_content(cls, log_text: str) -> List[ModSecTransaction]:
        """Parses multi-section ModSecurity audit log format."""
        transactions: List[ModSecTransaction] = []
        if not log_text or not log_text.strip():
            return transactions

        # Split into transactions by Section A boundary: --[hex]-[A]--
        # Header regex: --([a-f0-9]+)-A--
        boundary_pattern = re.compile(r"^--([a-fA-F0-9]+)-([A-Z])--", re.MULTILINE)
        matches = list(boundary_pattern.finditer(log_text))
        if not matches:
            return transactions

        # Group sections by transaction ID
        raw_tx_sections: Dict[str, Dict[str, str]] = {}
        for i, match in enumerate(matches):
            tx_id = match.group(1)
            section_code = match.group(2)
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(log_text)
            section_content = log_text[start_pos:end_pos].strip()

            if tx_id not in raw_tx_sections:
                raw_tx_sections[tx_id] = {}
            raw_tx_sections[tx_id][section_code] = section_content

        for tx_id, sections in raw_tx_sections.items():
            tx = cls._build_transaction(tx_id, sections)
            if tx:
                transactions.append(tx)

        return transactions

    @classmethod
    def _build_transaction(cls, tx_id: str, sections: Dict[str, str]) -> Optional[ModSecTransaction]:
        sec_a = sections.get("A", "")
        # Format of A: [15/May/2026:14:22:10 +0200] 192.168.1.100 54321 192.168.1.50 80
        # or ISO date
        client_ip = "127.0.0.1"
        client_port = 0
        server_ip = "127.0.0.1"
        server_port = 80
        timestamp = _utc_now_iso()

        if sec_a:
            parts = sec_a.split()
            if len(parts) >= 5:
                timestamp = parts[0].strip("[]")
                client_ip = parts[1]
                try:
                    client_port = int(parts[2])
                except ValueError:
                    client_port = 0
                server_ip = parts[3]
                try:
                    server_port = int(parts[4])
                except ValueError:
                    server_port = 80

        tx = ModSecTransaction(
            transaction_id=tx_id,
            timestamp=timestamp,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            raw_section_a=sec_a,
            raw_section_b=sections.get("B", ""),
            raw_section_c=sections.get("C", ""),
            raw_section_h=sections.get("H", ""),
        )

        # Parse Section B: Request line + Headers
        sec_b = sections.get("B", "")
        if sec_b:
            lines = sec_b.splitlines()
            if lines:
                req_line = lines[0].split()
                if len(req_line) >= 2:
                    tx.method = req_line[0]
                    tx.uri = req_line[1]
                    if len(req_line) >= 3:
                        tx.protocol = req_line[2]

                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        tx.request_headers[k.strip().lower()] = v.strip()

        # Parse Section F: Response Headers
        sec_f = sections.get("F", "")
        if sec_f:
            first_line = sec_f.splitlines()[0] if sec_f.splitlines() else ""
            status_match = re.search(r"HTTP/\d\.\d\s+(\d{3})", first_line)
            if status_match:
                tx.response_status = int(status_match.group(1))

        # Parse Section H: Audit Log Trailer & Rule Matches
        sec_h = sections.get("H", "")
        if sec_h:
            tx.rule_matches = cls._parse_section_h(sec_h)

        return tx

    @classmethod
    def _parse_section_h(cls, sec_h: str) -> List[ModSecRuleMatch]:
        matches: List[ModSecRuleMatch] = []
        # Pattern: Message: Access denied with code 403 (phase 2). Pattern match ... [file "..."] [line "..."] [id "942100"] [msg "SQL Injection Attack"] [severity "CRITICAL"] [tag "..."]
        for line in sec_h.splitlines():
            if not line.startswith("Message:"):
                continue

            id_m = re.search(r'\[id\s+"?(\d+)"?\]', line)
            msg_m = re.search(r'\[msg\s+"([^"]+)"\]', line)
            sev_m = re.search(r'\[severity\s+"?([A-Za-z0-9]+)"?\]', line)
            tags = re.findall(r'\[tag\s+"([^"]+)"\]', line)
            data_m = re.search(r'\[data\s+"([^"]+)"\]', line)

            rule_id = id_m.group(1) if id_m else "WAF-RULE"
            msg = msg_m.group(1) if msg_m else line[8:].strip()
            sev = sev_m.group(1) if sev_m else "HIGH"
            data = data_m.group(1) if data_m else ""

            matches.append(
                ModSecRuleMatch(
                    rule_id=rule_id,
                    message=msg,
                    severity=sev,
                    tags=tags,
                    data=data,
                )
            )
        return matches

    @classmethod
    def import_modsec_log(
        cls,
        db: Database,
        project_id: int,
        log_content: str,
        scopes: List[TargetScope],
        source_filename: str = "modsec_audit.log",
        evidence_dir: Optional[Path] = None,
        assessment_id: Optional[int] = None,
    ) -> Tuple[List[Finding], List[Evidence], ScopeCheckResult]:
        """Correlates WAF log events with scope and saves findings and evidence."""
        transactions = cls.parse_log_content(log_content)
        if not transactions:
            return [], [], ScopeCheckResult(is_allowed=False, reason="No valid ModSecurity transactions detected in log.")

        # Identify unique target hosts/IPs
        target_hosts = set()
        for tx in transactions:
            host_header = tx.request_headers.get("host", "").split(":")[0]
            if host_header:
                target_hosts.add(host_header)
            target_hosts.add(tx.server_ip)

        # Check scope authorization against all target servers
        authorized_targets = set()
        for th in target_hosts:
            chk = ScopeAuthorizationService.is_target_authorized(th, scopes)
            if chk.is_allowed:
                authorized_targets.add(th)

        if not authorized_targets:
            return [], [], ScopeCheckResult(
                is_allowed=False,
                reason=f"All ModSecurity target servers ({', '.join(target_hosts)}) are outside authorized project scope.",
            )

        # Save cryptographic evidence of raw log
        sha256 = hashlib.sha256(log_content.encode("utf-8")).hexdigest()
        ev_record: Optional[Evidence] = None
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            ev_file = evidence_dir / f"modsec_{project_id}_{Path(source_filename).name}"
            ev_file.write_text(log_content, encoding="utf-8")
            ev_record = db.add_evidence(
                Evidence(
                    project_id=project_id,
                    file_path=str(ev_file),
                    sha256_hash=sha256,
                    description=f"ModSecurity WAF Audit Log: {source_filename}",
                    mime_type="text/plain",
                    assessment_id=assessment_id,
                )
            )

        findings: List[Finding] = []
        ev_list: List[Evidence] = [ev_record] if ev_record else []

        for tx in transactions:
            host = tx.request_headers.get("host", tx.server_ip)
            target_name = host.split(":")[0]
            if target_name not in authorized_targets and tx.server_ip not in authorized_targets:
                continue

            for match in tx.rule_matches:
                sev = cls.SEVERITY_MAP.get(str(match.severity).lower(), FindingSeverity.MEDIUM)
                title = f"WAF Block Triggered: [{match.rule_id}] {match.message} on {tx.method} {tx.uri}"

                desc = (
                    f"ModSecurity Web Application Firewall triggered rule **{match.rule_id}** "
                    f"during an incoming HTTP request.\n\n"
                    f"- **Client IP:** `{tx.client_ip}:{tx.client_port}`\n"
                    f"- **Server IP:** `{tx.server_ip}:{tx.server_port}`\n"
                    f"- **Request Line:** `{tx.method} {tx.uri} {tx.protocol}`\n"
                    f"- **WAF Alert Message:** {match.message}\n"
                    f"- **Matched Payload Data:** `{match.data or 'N/A'}`\n"
                    f"- **Tags:** {', '.join(match.tags) if match.tags else 'None'}\n"
                    f"- **Transaction ID:** `{tx.transaction_id}`\n"
                )
                remediation = (
                    "Investigate source IP and payload for exploit activity. If this alert represents legitimate traffic, "
                    f"review WAF Rule ID {match.rule_id} and tune CRS exclusions accordingly."
                )

                finding = Finding(
                    project_id=project_id,
                    title=title,
                    severity=sev,
                    affected_asset=f"{target_name}:{tx.server_port}",
                    affected_port_service=f"{tx.server_port}/tcp (http)",
                    description=desc,
                    reproduction_steps=f"Replay request from client {tx.client_ip}: {tx.method} {tx.uri}\nHeaders:\n" + "\n".join([f"{k}: {v}" for k, v in tx.request_headers.items()]),
                    remediation=remediation,
                    validation_status=ValidationStatus.OBSERVED,
                    source_tool="modsecurity",
                    assessment_id=assessment_id,
                )
                created_f = db.create_finding(finding)
                findings.append(created_f)

        return findings, ev_list, ScopeCheckResult(
            is_allowed=True,
            reason=f"Successfully imported {len(findings)} WAF findings for in-scope targets.",
        )

