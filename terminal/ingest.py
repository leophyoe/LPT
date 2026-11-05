"""Terminal command output ingestion, target discovery, and finding extraction engine.

When supported security tools are executed in the integrated command shell, this engine:
1. Checks parsed findings against existing authorized project scopes; it never grants scope.
2. Ingests supported tool output (Nmap, Nikto, SQLMap, WAFW00F, Gobuster/FFUF)
   into structured findings.
3. Imports valid Nmap XML into the scoped asset inventory, linked to its evidence.
4. Enriches and persists in-scope findings into SQLite.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

from core.asset_inventory import AssetInventoryService
from core.scope import ScopeAuthorizationService
from core.strix_triage import StrixTriageEngine
from modules.network.nmap_parser import NmapParser
from modules.web.c0desec_adapter import SECRET_PATTERNS, redact_secret_value
from modules.web.gobuster_adapter import GobusterAdapter
from modules.web.nikto_parser import NiktoParser
from modules.web.sqlmap_adapter import SQLMapAdapter
from modules.web.wafw00f_adapter import WAFW00FAdapter
from storage.db import Database
from storage.models import (
    AssetNode,
    Finding,
    FindingSeverity,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@dataclass
class TerminalIngestResult:
    """Summary of terminal or scanner ingestion operation."""
    findings: List[Finding] = field(default_factory=list)
    hosts_synced: int = 0
    ports_synced: int = 0
    tools_detected: List[str] = field(default_factory=list)
    is_unparsed_evidence: bool = False
    status_message: str = ""


class TerminalIngestEngine:
    """Extracts assets, scans results, and security findings from interactive terminal executions."""

    last_result: Optional[TerminalIngestResult] = None

    @staticmethod
    def extract_targets(command: str, output: str) -> List[Tuple[str, TargetType]]:
        """Extracts candidate target assets (URLs, IPs, CIDRs, Hostnames) from CLI command and output."""
        targets: List[Tuple[str, TargetType]] = []
        seen: Set[str] = set()

        def _add(t: str, tt: TargetType):
            cleaned = t.strip().rstrip("/").lower()
            if not cleaned or cleaned in seen:
                return
            # Ignore standard command binaries, flags, and common shell keywords
            if cleaned.startswith("-") or cleaned in {
                "python", "python3", "bash", "sh", "sudo", "grep", "cat", "echo",
                "curl", "wget", "nmap", "nikto", "sqlmap", "wafw00f", "gobuster", "ffuf",
                "dir", "true", "false", "head", "tail", "output", "stdout", "stderr",
            }:
                return
            seen.add(cleaned)
            targets.append((t.strip().rstrip("/"), tt))

        full_text = f"{command}\n{output}"

        # 1. URLs
        vendor_domains = {
            "nmap.org", "cirt.net", "sqlmap.org", "github.com", "gitlab.com",
            "owasp.org", "w3.org", "iana.org", "python.org", "pypi.org",
            "gnu.org", "kali.org", "ubuntu.com", "debian.org",
        }
        url_matches = re.findall(r"https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]+", full_text)
        for u in url_matches:
            parsed = urlparse(u)
            host = (parsed.hostname or "").lower()
            if any(host == vd or host.endswith(f".{vd}") for vd in vendor_domains):
                continue
            _add(u, TargetType.URL)

        # 2. IP Addresses & CIDR Ranges
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", full_text)
        for ip_cand in ip_matches:
            try:
                if "/" in ip_cand:
                    net = ipaddress.ip_network(ip_cand, strict=False)
                    _add(str(net), TargetType.CIDR_RANGE)
                else:
                    addr = ipaddress.ip_address(ip_cand)
                    # Ignore loopback 0.0.0.0 and broadcast 255.255.255.255
                    if str(addr) not in ("0.0.0.0", "255.255.255.255"):
                        _add(str(addr), TargetType.IP_ADDRESS)
            except ValueError:
                pass

        # 3. Hostnames / Domains
        # From Nmap report lines: 'Nmap scan report for target.com (1.2.3.4)'
        nmap_hosts = re.findall(r"Nmap scan report for\s+([a-zA-Z0-9.\-_]+)", output, re.IGNORECASE)
        for h in nmap_hosts:
            if not any(c.isdigit() for c in h.split(".")) or "." in h:
                _add(h, TargetType.HOSTNAME)

        # From Nikto output
        nikto_host = re.search(r"Target Hostname:\s*([a-zA-Z0-9.\-_]+)", output, re.IGNORECASE)
        if nikto_host:
            _add(nikto_host.group(1), TargetType.HOSTNAME)

        # From Command Arguments (e.g., nmap scanme.nmap.org, ping google.com)
        words = command.split()
        for idx, word in enumerate(words):
            if word in ("-u", "--url", "-h", "--host", "-target", "--target") and idx + 1 < len(words):
                cand = words[idx + 1].strip("'\"")
                if "://" in cand:
                    _add(cand, TargetType.URL)
                elif re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$", cand):
                    _add(cand, TargetType.HOSTNAME)
            elif "." in word and not word.startswith("-") and not word.startswith("/"):
                clean_word = word.strip("'\",;()")
                if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$", clean_word):
                    _add(clean_word, TargetType.HOSTNAME)

        return targets

    @staticmethod
    def register_targets(
        db: Database,
        project_id: int,
        targets: List[Tuple[str, TargetType]],
        tool_name: str = "terminal",
    ) -> List[TargetScope]:
        """Return existing scope matches without creating authorization records."""
        scopes = db.list_scopes(project_id)
        matches: List[TargetScope] = []
        seen_ids: Set[int] = set()
        project = db.get_project(project_id)
        for target_str, _target_type in targets:
            check = ScopeAuthorizationService.is_target_authorized(
                target_str, scopes, project=project
            )
            matched = check.matched_scope
            if check.is_allowed and matched and matched.id not in seen_ids:
                matches.append(matched)
                seen_ids.add(matched.id)
        return matches

    @classmethod
    def ingest_command_output(
        cls,
        db: Database,
        project_id: int,
        execution_id: Optional[int],
        tool_name: str,
        command: str,
        output: str,
        evidence_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Parse trusted scanner output and persist only scope-authorized records."""
        if not output.strip():
            return []

        # Validate that execution_id actually exists in database; if not, fallback to None to satisfy FK
        valid_execution_id = execution_id
        if execution_id is not None:
            with db.session() as conn:
                row = conn.execute("SELECT id FROM tool_executions WHERE id = ?", (execution_id,)).fetchone()
                if not row:
                    valid_execution_id = None

        # Candidate targets are not authorization. Only existing project scopes
        # may be used to admit findings or assets into the project data model.
        scopes = db.list_scopes(project_id)
        project = db.get_project(project_id)

        parsed_findings: List[Finding] = []
        command_lower = command.lower()
        tool_lower = tool_name.lower()
        nmap_result = None

        detected_tools: List[str] = []
        synced_hosts_count = 0
        synced_ports_count = 0
        is_unparsed_evidence = False

        # Determine if this execution is a general terminal/PTY session that may contain
        # embedded or scrolled scanner outputs
        is_terminal_session = (
            tool_lower in ("pty_terminal", "terminal", "session", "terminal_session")
            or tool_lower.startswith("vault_")
            or command_lower in ("pty_session", "terminal_session")
        )

        stripped_output = output.strip()

        # 2. Route to specialized parsers
        if is_terminal_session:
            # Check for identifiable scanner blocks inside the terminal text
            has_nmap_xml = bool(re.search(r"(<\?xml[\s\S]*?</nmaprun>|<nmaprun[\s\S]*?</nmaprun>)", stripped_output))
            has_nmap_text = bool(
                "nmap" in command_lower
                or re.search(r"Starting Nmap|Nmap scan report for|Nmap done:|nmap:\s*unrecognized", stripped_output, re.IGNORECASE)
                or (
                    re.search(r"\bnmap\b", stripped_output, re.IGNORECASE)
                    and re.search(r"\d+/(?:tcp|udp)\s+(?:open|closed|filtered)", stripped_output)
                )
                or (
                    re.search(r"\bPORT\s+STATE\s+SERVICE\b", stripped_output)
                    and re.search(r"\d+/(?:tcp|udp)\s+(?:open|closed|filtered)", stripped_output)
                )
            )

            if has_nmap_xml:
                detected_tools.append("nmap")
                xml_match = re.search(r"(<\?xml[\s\S]*?</nmaprun>|<nmaprun[\s\S]*?</nmaprun>)", stripped_output)
                xml_text = xml_match.group(1) if xml_match else stripped_output
                nmap_result = NmapParser.parse_xml(xml_text)
                if nmap_result and nmap_result.hosts:
                    try:
                        synced_nodes, _ = AssetInventoryService(db).sync_scan_assets(
                            project_id=project_id,
                            scan_result=nmap_result,
                            scopes=scopes,
                            source_tool="nmap",
                            evidence_id=evidence_id,
                        )
                        synced_hosts_count += len(synced_nodes)
                        for h in nmap_result.hosts:
                            synced_ports_count += sum(1 for p in h.ports if p.state == "open")
                    except Exception as exc:
                        logger.warning("Failed to sync XML scan assets: %s", exc)
                parsed_findings.extend(
                    cls._parse_nmap(xml_text, project_id, valid_execution_id, command="nmap")
                )
            elif has_nmap_text:
                detected_tools.append("nmap")
                # Extract command line from prompt if available
                cmd_match = re.search(r"(?:^|[\$#>])\s*(nmap\s+[^\r\n]+)", stripped_output)
                extracted_cmd = cmd_match.group(1).strip() if cmd_match else "nmap"

                nmap_result = NmapParser.parse_text(stripped_output, command=extracted_cmd)
                if nmap_result and nmap_result.hosts and any(h.status == "up" for h in nmap_result.hosts):
                    try:
                        synced_nodes, _ = AssetInventoryService(db).sync_scan_assets(
                            project_id=project_id,
                            scan_result=nmap_result,
                            scopes=scopes,
                            source_tool="nmap",
                            evidence_id=evidence_id,
                        )
                        synced_hosts_count += len(synced_nodes)
                        for h in nmap_result.hosts:
                            synced_ports_count += sum(1 for p in h.ports if p.state == "open")
                    except Exception as exc:
                        logger.warning("Failed to sync terminal scan assets: %s", exc)
                parsed_findings.extend(
                    cls._parse_nmap(stripped_output, project_id, valid_execution_id, command=extracted_cmd)
                )

            # Check for Nikto
            if re.search(r"- Nikto v|\+ Target IP:|\+ Target Hostname:", stripped_output, re.IGNORECASE):
                detected_tools.append("nikto")
                nikto_f = cls._parse_nikto(stripped_output, project_id, valid_execution_id)
                parsed_findings.extend(nikto_f)
                cls._sync_web_tool_assets(db, project_id, "nikto", "nikto", nikto_f, scopes, evidence_id)

            # Check for SQLMap
            if re.search(r"sqlmap identified the following injection points|---[\s\S]*?Parameter:", stripped_output):
                detected_tools.append("sqlmap")
                sqlmap_f = cls._parse_sqlmap("sqlmap", stripped_output, project_id, valid_execution_id)
                parsed_findings.extend(sqlmap_f)
                cls._sync_web_tool_assets(db, project_id, "sqlmap", "sqlmap", sqlmap_f, scopes, evidence_id)

            # Check for WAFW00F
            if re.search(r"The site [^\r\n]+ is behind|No WAF detected|Checking https?://", stripped_output, re.IGNORECASE):
                detected_tools.append("wafw00f")
                waf_f = cls._parse_wafw00f("wafw00f", stripped_output, project_id, valid_execution_id)
                parsed_findings.extend(waf_f)
                cls._sync_web_tool_assets(db, project_id, "wafw00f", "wafw00f", waf_f, scopes, evidence_id)

            # Check for Gobuster / FFUF
            if re.search(r"Starting gobuster|Found:\s*https?://", stripped_output, re.IGNORECASE):
                detected_tools.append("gobuster")
                gob_f = cls._parse_gobuster("gobuster", stripped_output, project_id, valid_execution_id)
                parsed_findings.extend(gob_f)
                cls._sync_web_tool_assets(db, project_id, "gobuster", "gobuster", gob_f, scopes, evidence_id)

            if not detected_tools:
                is_unparsed_evidence = True

        elif tool_lower == "nmap" or "nmap" in command_lower:
            detected_tools.append("nmap")
            if stripped_output.startswith(("<?xml", "<nmaprun")):
                nmap_result = NmapParser.parse_xml(stripped_output)
                if nmap_result and nmap_result.hosts:
                    try:
                        synced_nodes, _ = AssetInventoryService(db).sync_scan_assets(
                            project_id=project_id,
                            scan_result=nmap_result,
                            scopes=scopes,
                            source_tool="nmap",
                            evidence_id=evidence_id,
                        )
                        synced_hosts_count += len(synced_nodes)
                        for h in nmap_result.hosts:
                            synced_ports_count += sum(1 for p in h.ports if p.state == "open")
                    except Exception as exc:
                        logger.warning("Failed to sync XML scan assets: %s", exc)
            else:
                nmap_result = NmapParser.parse_text(stripped_output, command=command)
                # For console text scans, sync discovered live hosts / services to asset inventory
                if nmap_result and nmap_result.hosts and any(h.status == "up" for h in nmap_result.hosts):
                    try:
                        synced_nodes, _ = AssetInventoryService(db).sync_scan_assets(
                            project_id=project_id,
                            scan_result=nmap_result,
                            scopes=scopes,
                            source_tool="nmap",
                            evidence_id=evidence_id,
                        )
                        synced_hosts_count += len(synced_nodes)
                        for h in nmap_result.hosts:
                            synced_ports_count += sum(1 for p in h.ports if p.state == "open")
                    except Exception as exc:
                        logger.warning("Failed to sync terminal scan assets: %s", exc)

            parsed_findings.extend(
                cls._parse_nmap(output, project_id, valid_execution_id, command=command)
            )
        elif tool_lower == "nikto" or "nikto" in command_lower:
            detected_tools.append("nikto")
            parsed_findings.extend(cls._parse_nikto(output, project_id, valid_execution_id))
        elif tool_lower == "sqlmap" or "sqlmap" in command_lower:
            detected_tools.append("sqlmap")
            parsed_findings.extend(cls._parse_sqlmap(command, output, project_id, valid_execution_id))
        elif tool_lower == "wafw00f" or "wafw00f" in command_lower:
            detected_tools.append("wafw00f")
            parsed_findings.extend(cls._parse_wafw00f(command, output, project_id, valid_execution_id))
        elif tool_lower in ("gobuster", "ffuf") or any(t in command_lower for t in ("gobuster", "ffuf")):
            detected_tools.append("gobuster")
            parsed_findings.extend(cls._parse_gobuster(command, output, project_id, valid_execution_id))

        # 3. For web / target tools, sync any tested in-scope assets into inventory
        if not is_terminal_session and any(w in tool_lower or w in command_lower for w in ("nikto", "sqlmap", "wafw00f", "gobuster", "ffuf")):
            cls._sync_web_tool_assets(db, project_id, tool_name, command, parsed_findings, scopes, evidence_id)

        # Generic terminal text is not trusted scanner evidence. Keep the
        # dedicated helper available, but only route named scanner output here.
        if tool_lower in {"gitleaks", "trivy", "nuclei"}:
            parsed_findings.extend(
                cls._parse_generic_patterns(command, output, project_id, valid_execution_id)
            )

        # 4. Enrich findings with Strix AI triage, CVSS approximation, and persist in SQLite
        persisted_findings: List[Finding] = []
        for f in parsed_findings:
            scope_check = ScopeAuthorizationService.is_target_authorized(
                f.affected_asset, scopes, project=project
            )
            if not scope_check.is_allowed:
                continue
            f.project_id = project_id
            f.execution_id = valid_execution_id
            if assessment_id is not None:
                f.assessment_id = assessment_id
            if not f.source_tool:
                f.source_tool = tool_name

            # Enrich using Strix Triage Engine
            triaged = StrixTriageEngine.triage_finding(f)
            if not f.cvss_score:
                f.cvss_score = triaged.cvss_score
            if not f.cvss_vector:
                f.cvss_vector = triaged.cvss_vector
            if not f.remediation and triaged.remediation_summary:
                f.remediation = triaged.remediation_summary

            saved = db.upsert_finding_deduplicated(f)
            persisted_findings.append(saved)

        # Record structured summary of this ingestion operation
        status_msg = ""
        if detected_tools:
            status_msg = (
                f"Ingested output from {', '.join(detected_tools).upper()}: "
                f"{synced_hosts_count} host(s), {synced_ports_count} port(s) synced; "
                f"{len(persisted_findings)} finding(s) persisted."
            )
        elif is_unparsed_evidence:
            status_msg = "Unparsed terminal session evidence; no recognized scanner output blocks detected."
        else:
            status_msg = f"{len(persisted_findings)} finding(s) persisted."

        cls.last_result = TerminalIngestResult(
            findings=persisted_findings,
            hosts_synced=synced_hosts_count,
            ports_synced=synced_ports_count,
            tools_detected=detected_tools,
            is_unparsed_evidence=is_unparsed_evidence,
            status_message=status_msg,
        )

        return persisted_findings

    @classmethod
    def ingest_session(
        cls,
        db: Database,
        project_id: int,
        execution_id: Optional[int],
        output: str,
        evidence_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
        tool_name: str = "pty_terminal",
        command: str = "pty_session",
    ) -> TerminalIngestResult:
        """Parse terminal session text and return rich TerminalIngestResult."""
        cls.ingest_command_output(
            db=db,
            project_id=project_id,
            execution_id=execution_id,
            tool_name=tool_name,
            command=command,
            output=output,
            evidence_id=evidence_id,
            assessment_id=assessment_id,
        )
        return cls.last_result or TerminalIngestResult()

    @classmethod
    def _sync_web_tool_assets(
        cls,
        db: Database,
        project_id: int,
        tool_name: str,
        command: str,
        findings: List[Finding],
        scopes: List[Any],
        evidence_id: Optional[int] = None,
    ):
        """Register tested web targets into active asset inventory if authorized."""
        targets_to_check: Set[str] = set()
        for f in findings:
            if f.affected_asset:
                targets_to_check.add(f.affected_asset)

        # Also extract candidate URLs/targets from command
        url_match = re.search(r"https?://[^\s\"']+", command)
        if url_match:
            targets_to_check.add(url_match.group(0))

        for target in targets_to_check:
            host_val = target
            if "://" in target:
                parsed = urlparse(target)
                host_val = parsed.hostname or target
            elif "/" in target and not target.endswith("/"):
                host_val = target.split("/")[0]

            host_val = host_val.strip("[]")
            if not host_val:
                continue

            scope_check = ScopeAuthorizationService.is_target_authorized(host_val, scopes)
            if not scope_check.is_allowed:
                continue

            is_ip = False
            try:
                ipaddress.ip_address(host_val)
                is_ip = True
            except ValueError:
                is_ip = False

            node_type = "ip" if is_ip else "hostname"
            port_num = 443 if "https" in target else 80
            meta = {
                "discovery_source": tool_name,
                "tested_url": target if "://" in target else "",
                "open_ports": [port_num],
                "services": [{"port": port_num, "service": "https" if port_num == 443 else "http", "proto": "tcp"}],
            }
            try:
                db.upsert_asset_node(
                    AssetNode(
                        project_id=project_id,
                        node_type=node_type,
                        value=host_val,
                        label=host_val,
                        source_tool=tool_name,
                        confidence=1.0,
                        metadata_json=json.dumps(meta),
                    )
                )
            except Exception as exc:
                logger.debug("Failed to upsert web asset node: %s", exc)

    @staticmethod
    def _parse_nmap(
        output: str,
        project_id: int,
        execution_id: Optional[int],
        command: str = "",
    ) -> List[Finding]:
        """Parses Nmap XML or standard console output into findings."""
        findings: List[Finding] = []
        stripped = output.strip()

        # Try XML first
        if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
            try:
                scan_result = NmapParser.parse_xml(stripped)
                if scan_result:
                    findings.extend(NmapParser.to_findings(scan_result, project_id, execution_id))
                    for host in scan_result.hosts:
                        if host.status == "up" and not any(p.state == "open" for p in host.ports):
                            findings.append(
                                Finding(
                                    project_id=project_id,
                                    title=f"Host Discovered (No Open Ports): {host.hostname or host.ip}",
                                    severity=FindingSeverity.INFORMATIONAL,
                                    affected_asset=host.hostname or host.ip,
                                    description="Nmap reported host state is up. No open listening ports were detected.",
                                    source_tool="nmap",
                                    execution_id=execution_id,
                                )
                            )
                    return findings
            except Exception:
                pass

        # Text stream parsing
        host = ""
        hostname = ""
        host_latency = ""
        current_host_has_ports = False
        live_hosts_without_ports: List[Tuple[str, str, str]] = []

        def _flush_host_if_zero_ports():
            nonlocal host, hostname, host_latency, current_host_has_ports
            if host and not current_host_has_ports:
                live_hosts_without_ports.append((host, hostname, host_latency))

        for line in output.splitlines():
            line_str = line.strip()
            report_match = re.search(r"Nmap scan report for (?:([^\s(]+)\s+\()?([0-9a-fA-F:.]+)\)?\s*$", line_str)
            if report_match:
                _flush_host_if_zero_ports()
                name_part, ip_part = report_match.groups()
                hostname = name_part if (name_part and ip_part) else ""
                host = ip_part or name_part or ""
                host_latency = ""
                current_host_has_ports = False
                continue

            up_match = re.search(r"Host is up\s*(?:\(([^)]+)\))?", line_str, re.IGNORECASE)
            if up_match:
                host_latency = up_match.group(1) or ""
                continue

            port_match = re.match(r"\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line_str, re.IGNORECASE)
            if port_match and host:
                current_host_has_ports = True
                port, protocol, service, detail = port_match.groups()
                sev = FindingSeverity.INFORMATIONAL
                remediation = "Verify that this network service is intentionally exposed and patch to current version."
                s_lower = service.lower()
                if s_lower in ("telnet", "rlogin", "rsh"):
                    sev = FindingSeverity.HIGH
                    remediation = "Replace unencrypted Telnet/rsh with SSH and restrict access via firewall."
                elif s_lower in ("smb", "microsoft-ds", "netbios-ssn"):
                    sev = FindingSeverity.MEDIUM
                    remediation = "Restrict SMB traffic to internal management networks and disable SMBv1."
                elif s_lower in ("redis", "mongodb", "elasticsearch") and "unauth" in (detail or "").lower():
                    sev = FindingSeverity.CRITICAL
                    remediation = "Enforce strong authentication and bind database service to localhost/internal interface."

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"Discovered Open Service: {service} on {host}:{port}/{protocol}",
                        severity=sev,
                        affected_asset=host,
                        affected_port_service=f"{port}/{protocol} {service} {detail or ''}".strip(),
                        description=f"Nmap discovered open {service} listening on {host}:{port}/{protocol}. Detail: {detail or 'N/A'}",
                        remediation=remediation,
                        validation_status=ValidationStatus.UNVERIFIED,
                        source_tool="nmap",
                        execution_id=execution_id,
                    )
                )

        _flush_host_if_zero_ports()

        # Create findings for live hosts with zero open ports (e.g. nmap -sn ping sweep)
        for h_ip, h_name, h_lat in live_hosts_without_ports:
            display_title = f"{h_name} ({h_ip})" if h_name else h_ip
            lat_desc = f" (Latency: {h_lat})" if h_lat else ""
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Live Host Discovered: {display_title}",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=h_ip,
                    affected_port_service="icmp/echo-discovery",
                    description=f"Host responded to reachability probe{lat_desc}. Zero open ports detected or ping sweep (-sn) executed.",
                    remediation="Verify asset inventory authorization and perform authorized port scan if services are required.",
                    validation_status=ValidationStatus.OBSERVED,
                    source_tool="nmap",
                    execution_id=execution_id,
                )
            )

        # Check for Nmap execution errors, mistyped flags, or target resolution failures
        error_match = re.search(
            r"(?:unrecognized option|Failed to resolve|Invalid target|No targets were specified|QUITTING!|WARNING: No targets)",
            output,
            re.IGNORECASE,
        )
        if error_match and not findings:
            err_line = ""
            for line in output.splitlines():
                if error_match.group(0).lower() in line.lower():
                    err_line = line.strip()
                    break
            command_targets = TerminalIngestEngine.extract_targets(command, "")
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Nmap CLI Execution Warning: {error_match.group(0)}",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=command_targets[0][0] if command_targets else "localhost",
                    affected_port_service="cli/error",
                    description=f"Nmap reported a syntax error or execution notice:\n{err_line or output[:250]}",
                    remediation="Verify Nmap option syntax and target format (e.g. nmap -sV <target>).",
                    validation_status=ValidationStatus.OBSERVED,
                    source_tool="nmap",
                    execution_id=execution_id,
                )
            )

        return findings

    @staticmethod
    def _parse_nikto(output: str, project_id: int, execution_id: int) -> List[Finding]:
        """Parses Nikto console output using NiktoParser."""
        try:
            res = NiktoParser.parse_text(output)
            return NiktoParser.to_findings(res, project_id, execution_id)
        except Exception:
            return []

    @staticmethod
    def _parse_sqlmap(command: str, output: str, project_id: int, execution_id: int) -> List[Finding]:
        """Parses SQLMap injection points and DBMS fingerprinting."""
        # Extract target URL
        target_url = ""
        u_match = re.search(r"(?:-u|--url)[=\s]+['\"]?([^'\"\s]+)['\"]?", command)
        if u_match:
            target_url = u_match.group(1)
        else:
            cand_url = re.search(r"https?://[^\s]+", output)
            if cand_url:
                target_url = cand_url.group(0)

        target_url = target_url or "Target Web Service"
        return SQLMapAdapter.parse_sqlmap_output(output, target_url, project_id, execution_id)

    @staticmethod
    def _parse_wafw00f(command: str, output: str, project_id: int, execution_id: int) -> List[Finding]:
        """Parses WAFW00F firewall detection output."""
        target_url = ""
        cand_url = re.search(r"https?://[^\s]+", f"{command} {output}")
        if cand_url:
            target_url = cand_url.group(0)
        target_url = target_url or "Target Host"

        parsed = WAFW00FAdapter(Database(":memory:")).parse_output(output, target_url)
        findings: List[Finding] = []

        if parsed.waf_detected and parsed.waf_name:
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"Web Application Firewall (WAF) Detected: {parsed.waf_name}",
                    description=(
                        f"Target '{target_url}' is protected by Web Application Firewall: '{parsed.waf_name}'. "
                        f"Fingerprint confirmed via {parsed.num_requests} probes."
                    ),
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target_url,
                    remediation="Note active WAF presence during testing as payload filtering or rate limiting may occur.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="wafw00f",
                )
            )
        elif "no waf" in output.lower() or "none" in output.lower():
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title="No Web Application Firewall (WAF) Detected",
                    description=f"No active WAF was identified protecting target '{target_url}'.",
                    severity=FindingSeverity.LOW,
                    affected_asset=target_url,
                    remediation="Consider deploying a WAF or reverse proxy to protect against automated web exploit attempts.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="wafw00f",
                )
            )

        return findings

    @staticmethod
    def _parse_gobuster(command: str, output: str, project_id: int, execution_id: int) -> List[Finding]:
        """Parses Gobuster / FFUF endpoint enumeration output."""
        endpoints = GobusterAdapter(Database(":memory:")).parse_output(output)
        if not endpoints:
            return []

        target_url = ""
        u_match = re.search(r"(?:-u|--url)[=\s]+['\"]?([^'\"\s]+)['\"]?", command)
        if u_match:
            target_url = u_match.group(1).rstrip("/")
        else:
            url_line = re.search(r"\[\+\] Url:\s*(https?://[^\s]+)", output)
            if url_line:
                target_url = url_line.group(1).rstrip("/")
        target_url = target_url or "Web Application"

        findings: List[Finding] = []
        sensitive_keywords = {"admin", "login", "config", ".git", ".env", "backup", "db", "api", "secret"}
        sensitive_endpoints = [ep for ep in endpoints if any(k in ep.path.lower() for k in sensitive_keywords)]
        general_endpoints = [ep for ep in endpoints if ep not in sensitive_endpoints]

        # Sensitive paths get individual medium/high severity findings
        for ep in sensitive_endpoints:
            sev = FindingSeverity.HIGH if any(k in ep.path.lower() for k in (".env", ".git", "backup", "config")) else FindingSeverity.MEDIUM
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"Sensitive Path Discovered: {ep.path} (HTTP {ep.status_code})",
                    description=f"Directory brute-forcing identified sensitive endpoint '{ep.path}' responding with HTTP status {ep.status_code}.",
                    severity=sev,
                    affected_asset=f"{target_url}{ep.path}",
                    affected_port_service="Web Service (HTTP)",
                    remediation="Restrict access to sensitive admin, backup, or environment files via web server authorization controls.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="gobuster",
                )
            )

        # General paths grouped into informational finding
        if general_endpoints:
            path_sample = "\n".join(f"- {e.path} (HTTP {e.status_code})" for e in general_endpoints[:20])
            if len(general_endpoints) > 20:
                path_sample += f"\n... and {len(general_endpoints) - 20} additional endpoints."
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"Discovered {len(general_endpoints)} Web Application Endpoints",
                    description=f"Directory discovery identified {len(general_endpoints)} reachable web application endpoints:\n{path_sample}",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target_url,
                    affected_port_service="Web Service (HTTP)",
                    remediation="Review reachable endpoints to ensure unintended or obsolete routes are not publicly accessible.",
                    validation_status=ValidationStatus.CONFIRMED,
                    source_tool="gobuster",
                )
            )

        return findings

    @staticmethod
    def _parse_generic_patterns(command: str, output: str, project_id: int, execution_id: int) -> List[Finding]:
        """Detects exposed secrets, API keys, or explicit CVE references in terminal output."""
        findings: List[Finding] = []

        # 1. Secret Scanning (AWS keys, Google API keys, JWT tokens, Private keys)
        secret_keys_to_scan = {
            "google_api_key", "aws_access_key", "aws_secret_key",
            "jwt", "github_token", "stripe_live_key", "private_key_header"
        }
        for secret_type, pattern in SECRET_PATTERNS.items():
            if secret_type not in secret_keys_to_scan:
                continue
            matches = pattern.findall(output)
            if matches:
                sample = str(matches[0])
                redacted = redact_secret_value(sample)
                findings.append(
                    Finding(
                        project_id=project_id,
                        execution_id=execution_id,
                        title=f"Exposed Secret Detected in Output: {secret_type.replace('_', ' ').title()}",
                        description=(
                            f"Execution output contains an exposed credential matching signature '{secret_type}'.\n"
                            f"Redacted Preview: {redacted}"
                        ),
                        severity=FindingSeverity.CRITICAL if "key" in secret_type or "secret" in secret_type else FindingSeverity.HIGH,
                        affected_asset="Command Output / CLI Session",
                        remediation="Immediately revoke the exposed secret, audit access logs, and store credentials securely in environment variables.",
                        validation_status=ValidationStatus.UNVERIFIED,
                        source_tool="secret_scanner",
                    )
                )

        # 2. CVE Pattern matching
        cve_matches = list(set(re.findall(r"\b(CVE-20\d{2}-\d{4,6})\b", output, re.IGNORECASE)))
        for cve_id in cve_matches[:5]:  # limit to top 5 distinct CVEs per run to avoid spam
            findings.append(
                Finding(
                    project_id=project_id,
                    execution_id=execution_id,
                    title=f"Vulnerability Identifier Mentioned: {cve_id.upper()}",
                    description=f"Terminal execution output references vulnerability identifier {cve_id.upper()}.",
                    severity=FindingSeverity.HIGH,
                    affected_asset="Assessment Target",
                    remediation=f"Review security advisory for {cve_id.upper()} and apply vendor patch or mitigation.",
                    validation_status=ValidationStatus.UNVERIFIED,
                    source_tool="cve_detector",
                )
            )

        return findings
