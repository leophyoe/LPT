"""Universal Parser Architecture for CyberSecuritySuite.

Provides a unified parsing and normalization interface across all primary security tools:
- Nmap (XML and plaintext)
- Nikto (JSON and text)
- SQLMap (stdout, payloads, and JSON logs)
- WAFW00F (stdout and JSON)
- Gobuster (directory and DNS fuzzing stdout)
- FFUF (JSON and stdout)

Preserves raw evidence digests, normalizes findings and service exposures,
and prevents hallucinated or unbacked claims.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.parsers.normalized_models import (
    NormalizedFinding,
    NormalizedParserResult,
    NormalizedService,
)
from storage.models import FindingSeverity, ValidationStatus

logger = logging.getLogger(__name__)


class UniversalParser:
    """Dispatches to tool-specific parsers and normalizes findings and services."""

    SUPPORTED_TOOLS = {"nmap", "nikto", "sqlmap", "wafw00f", "gobuster", "ffuf"}

    @classmethod
    def calculate_sha256(cls, content: str) -> str:
        """Computes SHA-256 hex digest of raw content."""
        if not content:
            return hashlib.sha256(b"").hexdigest()
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def detect_tool(cls, raw_content: str, filename_hint: str = "") -> str:
        """Heuristically infers the source security tool from output signatures."""
        content_lower = raw_content[:4096].lower()
        hint_lower = filename_hint.lower()

        if "nmap" in hint_lower or "<nmaprun" in content_lower or "starting nmap" in content_lower:
            return "nmap"
        if "nikto" in hint_lower or "- nikto v" in content_lower or '"banner":' in content_lower:
            return "nikto"
        if "sqlmap" in hint_lower or "sqlmap/" in content_lower or "heuristic (basic) test" in content_lower:
            return "sqlmap"
        if "wafw00f" in hint_lower or "the site" in content_lower and "is behind" in content_lower or "no waf detected" in content_lower:
            return "wafw00f"
        if "gobuster" in hint_lower or "gobuster" in content_lower or "(status:" in content_lower and "[size:" in content_lower:
            return "gobuster"
        if "ffuf" in hint_lower or '"results":' in content_lower and '"fuzz":' in content_lower or ":: method" in content_lower:
            return "ffuf"

        return "unknown"

    @classmethod
    def parse(
        cls,
        raw_output: str,
        tool_name: Optional[str] = None,
        target: str = "",
        evidence_id: Optional[int] = None,
        execution_id: Optional[int] = None,
        tool_hint: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> NormalizedParserResult:
        """Universal parser entrypoint. Dispatches to the appropriate tool parser."""
        effective_tool = tool_name or tool_hint
        effective_target = target or target_url or ""
        raw = raw_output or ""
        sha256 = cls.calculate_sha256(raw)
        tool = (effective_tool or "").lower().strip()
        if not tool or tool == "auto":
            tool = cls.detect_tool(raw)

        result = NormalizedParserResult(
            tool_name=tool,
            target=effective_target,
            raw_evidence_hash=sha256,
            raw_output=raw,
            parser_warnings=[],
            success=True,
        )

        if not raw.strip():
            result.parser_warnings.append("Empty raw output provided to parser.")
            return result

        try:
            if tool == "nmap":
                cls._parse_nmap(raw, target, result, evidence_id, execution_id)
            elif tool == "nikto":
                cls._parse_nikto(raw, target, result, evidence_id, execution_id)
            elif tool == "sqlmap":
                cls._parse_sqlmap(raw, target, result, evidence_id, execution_id)
            elif tool == "wafw00f":
                cls._parse_wafw00f(raw, target, result, evidence_id, execution_id)
            elif tool == "gobuster":
                cls._parse_gobuster(raw, target, result, evidence_id, execution_id)
            elif tool == "ffuf":
                cls._parse_ffuf(raw, target, result, evidence_id, execution_id)
            else:
                result.parser_warnings.append(f"Unrecognized or unsupported tool '{tool}'. Performing generic plaintext extraction.")
                cls._parse_generic(raw, target, result, evidence_id, execution_id)
        except Exception as exc:
            logger.exception("Error during universal parsing for tool %s: %s", tool, exc)
            result.parser_warnings.append(f"Parser exception encountered: {exc}")
            result.success = len(result.findings) > 0 or len(result.services) > 0

        # Ensure all findings carry provenance metadata
        for f in result.findings:
            if not f.raw_evidence_hash:
                f.raw_evidence_hash = sha256
            if evidence_id and not f.evidence_id:
                f.evidence_id = evidence_id
            if execution_id and not f.execution_id:
                f.execution_id = execution_id
            if not f.source_tool:
                f.source_tool = tool

        return result

    # -------------------------------------------------------------------------
    # NMAP PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_nmap(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", raw).strip()
        is_xml = "<nmaprun" in clean_text or "<?xml" in clean_text

        if is_xml:
            cls._parse_nmap_xml(clean_text, target, result, evidence_id, execution_id)
        else:
            cls._parse_nmap_text(clean_text, target, result, evidence_id, execution_id)

    @classmethod
    def _parse_nmap_xml(
        cls,
        xml_text: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        try:
            # Handle possible truncated XML gracefully
            if "</nmaprun>" not in xml_text:
                xml_text += "\n</nmaprun>"
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            result.parser_warnings.append(f"Nmap XML parse error: {e}. Falling back to regex extraction.")
            port_matches = re.finditer(r'<port\s+[^>]*portid="(\d+)"[^>]*protocol="(\w+)"[^>]*>.*?<state\s+[^>]*state="open"', xml_text, re.DOTALL | re.IGNORECASE)
            for pm in port_matches:
                pid = int(pm.group(1))
                proto = pm.group(2).lower()
                result.services.append(
                    NormalizedService(
                        host=target or "unknown-host",
                        port=pid,
                        protocol=proto,
                        source_tool="nmap",
                        confidence=0.85,
                        state="open",
                    )
                )
            if not result.services:
                port_matches2 = re.finditer(r'<port\s+[^>]*protocol="(\w+)"[^>]*portid="(\d+)"[^>]*>.*?<state\s+[^>]*state="open"', xml_text, re.DOTALL | re.IGNORECASE)
                for pm2 in port_matches2:
                    proto = pm2.group(1).lower()
                    pid = int(pm2.group(2))
                    result.services.append(
                        NormalizedService(
                            host=target or "unknown-host",
                            port=pid,
                            protocol=proto,
                            source_tool="nmap",
                            confidence=0.85,
                            state="open",
                        )
                    )
            cls._parse_nmap_text(xml_text, target, result, evidence_id, execution_id)
            return

        result.command_args = root.attrib.get("args", "")

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.attrib.get("state") != "up":
                continue

            host_ip = ""
            for addr in host_elem.findall("address"):
                if addr.attrib.get("addrtype") in ("ipv4", "ipv6"):
                    host_ip = addr.attrib.get("addr", "")
                    break

            host_name = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    host_name = hn.attrib.get("name", "")

            effective_host = host_ip or host_name or target or "unknown-host"

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                state = state_elem.attrib.get("state", "closed") if state_elem is not None else "closed"
                if state != "open":
                    continue

                port_id = int(port_elem.attrib.get("portid", 0))
                protocol = port_elem.attrib.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = service_elem.attrib.get("name", "") if service_elem is not None else ""
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""
                extra = service_elem.attrib.get("extrainfo", "") if service_elem is not None else ""

                cpes = [cpe.text for cpe in (service_elem.findall("cpe") if service_elem is not None else []) if cpe.text]

                scripts: Dict[str, str] = {}
                for script_elem in port_elem.findall("script"):
                    sid = script_elem.attrib.get("id", "")
                    sout = script_elem.attrib.get("output", "")
                    if sid and sout:
                        scripts[sid] = sout.strip()

                        # Convert vuln/exploit scripts into findings
                        is_vuln_script = any(k in sid for k in ("vuln", "cve", "exploit", "anonymous", "weak", "ssl-enum-ciphers"))
                        if is_vuln_script:
                            sev = FindingSeverity.MEDIUM
                            if any(crit in sid or crit in sout.lower() for crit in ("rce", "cve-202", "backdoor", "ms17-010")):
                                sev = FindingSeverity.CRITICAL
                            elif any(high in sid or high in sout.lower() for high in ("vulnerable", "cve-", "unauthorized")):
                                sev = FindingSeverity.HIGH

                            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", sout, re.IGNORECASE)

                            result.findings.append(
                                NormalizedFinding(
                                    title=f"Nmap Script Finding: {sid} on {effective_host}:{port_id}/{protocol}",
                                    severity=sev,
                                    affected_asset=effective_host,
                                    affected_service=f"{port_id}/{protocol}",
                                    port=port_id,
                                    protocol=protocol,
                                    cve_ids=list(dict.fromkeys(cve_matches)),
                                    description=f"Nmap script '{sid}' returned security finding:\n\n{sout.strip()}",
                                    remediation=f"Review configuration for service '{service_name}' on port {port_id}. Restrict exposure and patch vulnerabilities.",
                                    evidence_id=evidence_id,
                                    execution_id=execution_id,
                                    raw_evidence_hash=result.raw_evidence_hash,
                                    source_tool="nmap",
                                    confidence=0.95,
                                    validation_status=ValidationStatus.OBSERVED,
                                    validation_method="Nmap NSE Script Execution",
                                )
                            )

                norm_service = NormalizedService(
                    host=effective_host,
                    port=port_id,
                    protocol=protocol,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra,
                    cpe_list=cpes,
                    scripts=scripts,
                    source_tool="nmap",
                    confidence=1.0,
                    state="open",
                )
                result.services.append(norm_service)

    @classmethod
    def _parse_nmap_text(
        cls,
        text: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        """Parses standard human-readable Nmap terminal output."""
        current_ip = target
        ip_match = re.search(r"Nmap scan report for (?:([^\s\(\)]+)\s+)?\(?([0-9a-fA-F\.\:]+)\)?", text)
        if ip_match:
            current_ip = ip_match.group(2) or ip_match.group(1) or target

        # Match lines like: 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
        port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$", re.MULTILINE)
        for match in port_pattern.finditer(text):
            port_id = int(match.group(1))
            proto = match.group(2).lower()
            state = match.group(3).lower()
            svc = match.group(4)
            extra = (match.group(5) or "").strip()

            if state == "open":
                result.services.append(
                    NormalizedService(
                        host=current_ip or "unknown-host",
                        port=port_id,
                        protocol=proto,
                        service_name=svc,
                        extra_info=extra,
                        source_tool="nmap",
                        confidence=0.9,
                        state="open",
                    )
                )
                result.findings.append(
                    NormalizedFinding(
                        title=f"Open Port: {port_id}/{proto} ({svc})",
                        severity=FindingSeverity.INFORMATIONAL,
                        affected_asset=current_ip or "unknown-host",
                        affected_service=f"{port_id}/{proto}",
                        port=port_id,
                        protocol=proto,
                        description=f"Discovered open port {port_id}/{proto} running service '{svc}'. Extra: {extra or 'N/A'}",
                        remediation=f"Review whether service '{svc}' on port {port_id} should be exposed.",
                        evidence_id=evidence_id,
                        execution_id=execution_id,
                        raw_evidence_hash=result.raw_evidence_hash,
                        source_tool="nmap",
                        confidence=0.9,
                        validation_status=ValidationStatus.OBSERVED,
                        validation_method="Nmap Port Scan",
                    )
                )

    # -------------------------------------------------------------------------
    # NIKTO PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_nikto(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean = raw.strip()
        # 1. Try JSON parsing
        if clean.startswith("{") or clean.startswith("["):
            try:
                data = json.loads(clean)
                cls._parse_nikto_json(data, target, result, evidence_id, execution_id)
                return
            except json.JSONDecodeError:
                result.parser_warnings.append("Nikto output resembled JSON but failed parsing. Trying plaintext extraction.")

        # 2. Text parsing
        cls._parse_nikto_text(clean, target, result, evidence_id, execution_id)

    @classmethod
    def _parse_nikto_json(
        cls,
        data: Any,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        host = data.get("host", target) or target
        port_str = str(data.get("port", "80"))
        port = int(port_str) if port_str.isdigit() else 80

        banner = data.get("banner", "")
        if banner:
            result.services.append(
                NormalizedService(
                    host=host,
                    port=port,
                    protocol="tcp",
                    service_name="http",
                    banner=banner,
                    source_tool="nikto",
                    confidence=0.9,
                )
            )

        items = data.get("items", []) or data.get("vulnerabilities", [])
        for item in items:
            msg = item.get("msg", "") or item.get("description", "")
            if not msg:
                continue
            uri = item.get("uri", "/")
            method = item.get("method", "GET")
            osvdb = str(item.get("osvdb", "") or item.get("osvdb_id", ""))
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", msg, re.IGNORECASE)

            sev = cls._classify_nikto_severity(msg)
            title = cls._clean_nikto_title(msg, uri)

            result.findings.append(
                NormalizedFinding(
                    title=f"Nikto: {title}",
                    severity=sev,
                    affected_asset=f"{host}:{port}{uri}",
                    affected_service=f"{port}/tcp",
                    port=port,
                    protocol="tcp",
                    cve_ids=list(dict.fromkeys(cve_matches)),
                    cwe_id="CWE-200" if sev == FindingSeverity.INFORMATIONAL else ("CWE-16" if sev == FindingSeverity.LOW else "CWE-693"),
                    description=f"{msg}\nMethod: {method}\nPath: {uri}" + (f"\nOSVDB: {osvdb}" if osvdb else ""),
                    remediation="Apply vendor security patches, configure HTTP security headers, and restrict sensitive web files.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="nikto",
                    confidence=0.85,
                    validation_status=ValidationStatus.OBSERVED,
                    validation_method="Nikto Web Assessment Probe",
                )
            )

    @classmethod
    def _parse_nikto_text(
        cls,
        text: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        host = target
        port = 80

        target_match = re.search(r"Target IP:\s*([^\s]+)", text)
        if target_match:
            host = target_match.group(1)

        port_match = re.search(r"Target Port:\s*(\d+)", text)
        if port_match:
            port = int(port_match.group(1))

        server_match = re.search(r"Server:\s*(.+)", text)
        if server_match:
            banner = server_match.group(1).strip()
            result.services.append(
                NormalizedService(
                    host=host,
                    port=port,
                    protocol="tcp",
                    service_name="http",
                    banner=banner,
                    source_tool="nikto",
                    confidence=0.85,
                )
            )

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue

            msg = line[2:].strip()
            if any(skip in msg for skip in ("Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:")):
                continue

            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", msg, re.IGNORECASE)
            sev = cls._classify_nikto_severity(msg)
            title = cls._clean_nikto_title(msg)

            result.findings.append(
                NormalizedFinding(
                    title=f"Nikto: {title}",
                    severity=sev,
                    affected_asset=f"{host}:{port}",
                    affected_service=f"{port}/tcp",
                    port=port,
                    protocol="tcp",
                    cve_ids=list(dict.fromkeys(cve_matches)),
                    description=msg,
                    remediation="Harden web server configuration, restrict administrative endpoints, and deploy missing security headers.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="nikto",
                    confidence=0.8,
                    validation_status=ValidationStatus.OBSERVED,
                    validation_method="Nikto Web Assessment Probe",
                )
            )

    @classmethod
    def _classify_nikto_severity(cls, msg: str) -> FindingSeverity:
        m = msg.lower()
        if any(w in m for w in ("remote code execution", "rce", "command execution", "web shell", "sql injection")):
            return FindingSeverity.CRITICAL
        if any(w in m for w in ("directory traversal", "unauthenticated", "without authentication", "password file", "admin console", "admin portal", "admin login", "admin interface", "vulnerable to")):
            return FindingSeverity.HIGH
        if any(w in m for w in ("xss", "cross site scripting", "information disclosure", "interesting file", "backup file")):
            return FindingSeverity.MEDIUM
        if any(w in m for w in ("header", "cookie", "options", "trace method")):
            return FindingSeverity.LOW
        return FindingSeverity.INFORMATIONAL

    @classmethod
    def _clean_nikto_title(cls, msg: str, uri: str = "") -> str:
        # Strip OSVDB markers
        cleaned = re.sub(r"OSVDB-\d+:\s*", "", msg).strip()
        first_sentence = cleaned.split(".")[0].strip()
        if len(first_sentence) > 80:
            first_sentence = first_sentence[:77] + "..."
        if uri and uri != "/" and uri not in first_sentence:
            first_sentence += f" ({uri})"
        return first_sentence or "Web Exposure"

    # -------------------------------------------------------------------------
    # SQLMAP PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_sqlmap(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean = re.sub(r"\x1b\[[0-9;]*m", "", raw)

        # Detect injected parameters and techniques
        # Example pattern:
        # Parameter: id (GET)
        #     Type: boolean-based blind
        #     Title: AND boolean-based blind - WHERE or HAVING clause
        #     Payload: id=1 AND 1234=1234
        param_blocks = re.findall(
            r"Parameter:\s*([^\s\(\)]+)\s*\(([^)]+)\)\s*(.*?)(?=(?:Parameter:|\Z))",
            clean,
            re.DOTALL,
        )

        dbms_match = re.search(r"back-end DBMS:\s*([^\n\r]+)", clean, re.IGNORECASE)
        dbms_info = dbms_match.group(1).strip() if dbms_match else ""

        is_injectable = bool(param_blocks) or "is vulnerable" in clean.lower() or "sqlmap identified the following injection points" in clean.lower()

        if is_injectable and param_blocks:
            for param_name, http_method, block in param_blocks:
                techniques = re.findall(r"Type:\s*([^\n\r]+)", block)
                payload_matches = re.findall(r"Payload:\s*([^\n\r]+)", block)

                tech_summary = ", ".join(t.strip() for t in techniques) or "Injection Point Identified"
                payload_sample = payload_matches[0].strip() if payload_matches else "N/A"

                title = f"SQL Injection on Parameter '{param_name}' ({http_method})"
                desc = (
                    f"SQLMap confirmed database injection vulnerability on parameter '{param_name}' via {http_method}.\n"
                    f"Techniques: {tech_summary}\n"
                    f"Sample Payload: {payload_sample}\n"
                )
                if dbms_info:
                    desc += f"Back-end DBMS: {dbms_info}\n"

                result.findings.append(
                    NormalizedFinding(
                        title=title,
                        severity=FindingSeverity.CRITICAL,
                        affected_asset=target,
                        affected_service="http",
                        cve_ids=[],
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-89",
                        description=desc.strip(),
                        reproduction_steps=f"Reproduce with SQLMap payload:\n{payload_sample}",
                        remediation=(
                            "Use parameterized queries (prepared statements) or an ORM for all database operations. "
                            "Never concatenate untrusted user input directly into SQL statements."
                        ),
                        evidence_id=evidence_id,
                        execution_id=execution_id,
                        raw_evidence_hash=result.raw_evidence_hash,
                        source_tool="sqlmap",
                        confidence=1.0,
                        validation_status=ValidationStatus.CONFIRMED,
                        validation_method="SQLMap Active Payload Injection",
                        severity_rationale="Unsanitized parameter permits direct unauthorized database query execution.",
                    )
                )
        elif "all tested parameters do not appear to be injectable" in clean.lower():
            result.findings.append(
                NormalizedFinding(
                    title="No SQL Injection Detected",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target,
                    affected_service="http",
                    description=f"SQLMap tested candidate parameters on '{target}' and found no injectable vectors.",
                    remediation="Maintain secure coding practices and defensive parameterized queries.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="sqlmap",
                    confidence=0.9,
                    validation_status=ValidationStatus.OBSERVED,
                    validation_method="SQLMap Fuzzing Assessment",
                )
            )

    # -------------------------------------------------------------------------
    # WAFW00F PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_wafw00f(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        waf_match = re.search(r"The site\s+(?:[^\s]+)\s+is behind\s+([^\n\r\(\)]+)(?:\s*\(([^)]+)\))?", clean, re.IGNORECASE)

        if waf_match:
            waf_name = waf_match.group(1).strip()
            vendor = waf_match.group(2).strip() if waf_match.group(2) else ""
            label = f"{waf_name} ({vendor})" if vendor else waf_name

            result.findings.append(
                NormalizedFinding(
                    title=f"Web Application Firewall (WAF) Detected: {waf_name}",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target,
                    affected_service="http",
                    cwe_id="CWE-693",
                    description=f"WAFW00F fingerprinting identified active Web Application Firewall: '{label}'.",
                    remediation="Acknowledge WAF controls when scoping test engagements. Validate bypass rules if authorized.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="wafw00f",
                    confidence=0.95,
                    validation_status=ValidationStatus.CONFIRMED,
                    validation_method="WAFW00F Active Fingerprint",
                )
            )
        elif "no waf detected" in clean.lower():
            result.findings.append(
                NormalizedFinding(
                    title="No Web Application Firewall (WAF) Detected",
                    severity=FindingSeverity.LOW,
                    affected_asset=target,
                    affected_service="http",
                    cwe_id="CWE-693",
                    description=f"WAFW00F probe did not identify an active Web Application Firewall protecting '{target}'.",
                    remediation="Deploy a cloud proxy or WAF solution (e.g. ModSecurity, AWS WAF, Cloudflare) to mitigate automated exploit sweeps.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="wafw00f",
                    confidence=0.9,
                    validation_status=ValidationStatus.OBSERVED,
                    validation_method="WAFW00F Active Fingerprint",
                )
            )

    # -------------------------------------------------------------------------
    # GOBUSTER PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_gobuster(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        sensitive_patterns = [r"\.git", r"\.env", r"backup", r"config", r"swagger", r"admin", r"server-status", r"phpmyadmin"]

        for line in clean.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("[+]"):
                continue

            # Format: /path (Status: 200) [Size: 1234] [--> http://redirect]
            match = re.search(
                r"^([^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*([^\s\]]+)\])?",
                line,
            )
            if not match:
                continue

            path = match.group(1).strip()
            status_code = int(match.group(2))
            size = int(match.group(3)) if match.group(3) else None
            redirect_url = match.group(4).strip() if match.group(4) else None

            is_sensitive = any(re.search(pat, path, re.IGNORECASE) for pat in sensitive_patterns)
            sev = FindingSeverity.MEDIUM if (is_sensitive and status_code == 200) else (
                FindingSeverity.LOW if is_sensitive else FindingSeverity.INFORMATIONAL
            )

            # Finding validator rule: HTTP status code is an observation, not confirmed exploit
            val_status = ValidationStatus.NEEDS_VALIDATION if (is_sensitive and status_code == 200) else ValidationStatus.OBSERVED

            full_asset = f"{target.rstrip('/')}{path}"
            desc = (
                f"Web content brute-forcing identified path '{path}' with HTTP status {status_code} "
                f"(Response Size: {size or 'N/A'} bytes)."
            )
            if redirect_url:
                desc += f" Redirect target: {redirect_url}"

            result.findings.append(
                NormalizedFinding(
                    title=f"Discovered Web Path: {path} (HTTP {status_code})",
                    severity=sev,
                    affected_asset=full_asset,
                    affected_service="http",
                    cwe_id="CWE-538" if is_sensitive else "CWE-200",
                    description=desc,
                    remediation="Restrict unauthorized access to administrative or sensitive assets. Verify access control lists.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool="gobuster",
                    confidence=0.85,
                    validation_status=val_status,
                    validation_method="Gobuster Directory Enumeration",
                )
            )

    # -------------------------------------------------------------------------
    # FFUF PARSER
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_ffuf(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        clean = raw.strip()
        sensitive_patterns = [r"\.git", r"\.env", r"backup", r"config", r"swagger", r"admin", r"dashboard", r"portal"]

        # 1. Try JSON parsing
        if clean.startswith("{") or clean.startswith("["):
            try:
                data = json.loads(clean)
                entries = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                for item in entries:
                    url = item.get("url", "")
                    status = item.get("status", 200)
                    length = item.get("length", 0)
                    words = item.get("words", 0)
                    redirect = item.get("redirectlocation", "")

                    parsed_url = urlparse(url)
                    path = parsed_url.path or url
                    is_sensitive = any(re.search(p, path, re.IGNORECASE) for p in sensitive_patterns)
                    sev = FindingSeverity.MEDIUM if (is_sensitive and status == 200) else FindingSeverity.INFORMATIONAL

                    result.findings.append(
                        NormalizedFinding(
                            title=f"FFUF Endpoint: {path} (HTTP {status})",
                            severity=sev,
                            affected_asset=url or target,
                            affected_service="http",
                            cwe_id="CWE-538" if is_sensitive else "CWE-200",
                            description=f"FFUF fuzzer identified '{url}' (Status {status}, Length {length}, Words {words})." + (f" Redirect: {redirect}" if redirect else ""),
                            remediation="Review access controls on exposed endpoints.",
                            evidence_id=evidence_id,
                            execution_id=execution_id,
                            raw_evidence_hash=result.raw_evidence_hash,
                            source_tool="ffuf",
                            confidence=0.85,
                            validation_status=ValidationStatus.NEEDS_VALIDATION if (is_sensitive and status == 200) else ValidationStatus.OBSERVED,
                            validation_method="FFUF Web Fuzzer",
                        )
                    )
                return
            except json.JSONDecodeError:
                result.parser_warnings.append("FFUF output appeared to be JSON but failed parsing. Trying plaintext fallback.")

        # 2. Text fallback
        for line in clean.splitlines():
            line = line.strip()
            if not line or line.startswith("::") or line.startswith("["):
                continue
            # Match standard ffuf text line: e.g. "admin                   [Status: 200, Size: 1234, Words: 45, Lines: 12]"
            match = re.search(r"^([^\s]+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                is_sensitive = any(re.search(p, path, re.IGNORECASE) for p in sensitive_patterns)
                sev = FindingSeverity.MEDIUM if (is_sensitive and status == 200) else FindingSeverity.INFORMATIONAL
                result.findings.append(
                    NormalizedFinding(
                        title=f"FFUF Endpoint: /{path.lstrip('/')} (HTTP {status})",
                        severity=sev,
                        affected_asset=f"{target.rstrip('/')}/{path.lstrip('/')}",
                        affected_service="http",
                        description=f"FFUF discovered endpoint '{path}' with HTTP status {status}.",
                        remediation="Ensure proper authorization controls are active.",
                        evidence_id=evidence_id,
                        execution_id=execution_id,
                        raw_evidence_hash=result.raw_evidence_hash,
                        source_tool="ffuf",
                        confidence=0.8,
                        validation_status=ValidationStatus.OBSERVED,
                        validation_method="FFUF Web Fuzzer",
                    )
                )

    # -------------------------------------------------------------------------
    # GENERIC FALLBACK
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_generic(
        cls,
        raw: str,
        target: str,
        result: NormalizedParserResult,
        evidence_id: Optional[int],
        execution_id: Optional[int],
    ):
        """Extracts candidate IP, ports, and CVE numbers from arbitrary security tool output."""
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", raw, re.IGNORECASE)
        unique_cves = list(dict.fromkeys(cves))
        if unique_cves:
            result.findings.append(
                NormalizedFinding(
                    title=f"Security Tool Observation for {target}",
                    severity=FindingSeverity.MEDIUM,
                    affected_asset=target,
                    cve_ids=unique_cves,
                    description=f"Automated tool output identified CVE references:\n{', '.join(unique_cves)}",
                    remediation="Review referenced CVE advisories and verify vulnerable software version.",
                    evidence_id=evidence_id,
                    execution_id=execution_id,
                    raw_evidence_hash=result.raw_evidence_hash,
                    source_tool=result.tool_name or "generic",
                    confidence=0.7,
                    validation_status=ValidationStatus.NEEDS_VALIDATION,
                    validation_method="Generic Regex CVE Triage",
                )
            )
