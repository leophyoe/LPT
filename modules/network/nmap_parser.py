"""Nmap XML and raw output parser.

Converts Nmap XML scan outputs into structured Python models
and security findings with complete fingerprinting, scripts,
CPE identifiers, and evidence preservation.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from storage.models import Finding, FindingSeverity, ValidationStatus


@dataclass
class PortResult:
    port_id: int
    protocol: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe_list: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    confidence: Optional[int] = None
    method: str = ""
    state_reason: str = ""

    @property
    def service_summary(self) -> str:
        parts = [self.service_name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(filter(None, parts))


@dataclass
class HostResult:
    ip: str
    status: str
    hostname: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    address_type: str = "ipv4"
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_match: Optional[str] = None
    os_accuracy: Optional[int] = None
    device_type: Optional[str] = None
    host_scripts: Dict[str, str] = field(default_factory=dict)
    latency_ms: Optional[float] = None
    status_reason: str = ""
    uptime_seconds: Optional[int] = None

    @property
    def os_summary(self) -> str:
        if not self.os_match:
            return "Unknown OS"
        if self.os_accuracy is not None:
            return f"{self.os_match} ({self.os_accuracy}%)"
        return self.os_match


@dataclass
class NmapScanResult:
    command_args: str
    hosts: List[HostResult] = field(default_factory=list)
    raw_xml: str = ""
    scanner: str = "nmap"
    version: str = ""
    start_time: str = ""
    finish_time: str = ""
    summary: str = ""


class NmapParser:
    """Parses standard Nmap XML (-oX) into structured data."""

    @classmethod
    def parse_xml(cls, xml_content: str) -> NmapScanResult:
        """Parse Nmap XML string into NmapScanResult safely without dropping fields."""
        if not xml_content or not xml_content.strip():
            return NmapScanResult(command_args="", raw_xml="")

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as e:
            raise ValueError(f"Invalid Nmap XML output: {e}") from e

        command_args = root.attrib.get("args", "")
        scanner = root.attrib.get("scanner", "nmap")
        version = root.attrib.get("version", "")
        start_time = root.attrib.get("startstr", "")

        finish_time = ""
        summary = ""
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                finish_time = finished.attrib.get("timestr", "")
                summary = finished.attrib.get("summary", "")

        hosts: List[HostResult] = []

        for host_elem in root.findall("host"):
            # 1. Host status & reason
            status_elem = host_elem.find("status")
            status = "unknown"
            status_reason = ""
            if status_elem is not None:
                status = status_elem.attrib.get("state", "unknown")
                status_reason = status_elem.attrib.get("reason", "")

            # 2. IP and MAC addresses
            ip = ""
            address_type = "ipv4"
            mac_address = None
            vendor = None

            for addr in host_elem.findall("address"):
                atype = addr.attrib.get("addrtype", "")
                if atype in ("ipv4", "ipv6") and not ip:
                    ip = addr.attrib.get("addr", "")
                    address_type = atype
                elif atype == "mac":
                    mac_address = addr.attrib.get("addr", None)
                    vendor = addr.attrib.get("vendor", None)

            if not ip:
                continue

            # 3. Hostnames
            hostname = None
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                first_hn = hostnames_elem.find("hostname")
                if first_hn is not None:
                    hostname = first_hn.attrib.get("name")

            # 4. Latency / Round trip times
            latency_ms = None
            times_elem = host_elem.find("times")
            if times_elem is not None:
                srtt_str = times_elem.attrib.get("srtt", "")
                if srtt_str and srtt_str.isdigit():
                    try:
                        latency_ms = round(float(srtt_str) / 1000.0, 2)
                    except (ValueError, ZeroDivisionError):
                        pass

            # 5. Uptime
            uptime_seconds = None
            uptime_elem = host_elem.find("uptime")
            if uptime_elem is not None:
                sec_str = uptime_elem.attrib.get("seconds", "")
                if sec_str and sec_str.isdigit():
                    uptime_seconds = int(sec_str)

            # 6. OS Detection & Fingerprint
            os_match = None
            os_accuracy = None
            device_type = None

            os_elem = host_elem.find("os")
            if os_elem is not None:
                best_match = os_elem.find("osmatch")
                if best_match is not None:
                    os_match = best_match.attrib.get("name")
                    acc_str = best_match.attrib.get("accuracy")
                    if acc_str and acc_str.isdigit():
                        os_accuracy = int(acc_str)

                    # Device type from osclass
                    osclass = best_match.find("osclass")
                    if osclass is not None:
                        device_type = osclass.attrib.get("type")

            # 7. Host-level Scripts
            host_scripts: Dict[str, str] = {}
            hostscript_elem = host_elem.find("hostscript")
            if hostscript_elem is not None:
                for sc in hostscript_elem.findall("script"):
                    s_id = sc.attrib.get("id", "")
                    s_out = sc.attrib.get("output", "")
                    if s_id:
                        host_scripts[s_id] = s_out

            # 8. Ports & Discovered Services
            ports: List[PortResult] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    try:
                        port_id = int(port_elem.attrib.get("portid", 0))
                    except ValueError:
                        continue
                    protocol = port_elem.attrib.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"
                    state_reason = state_elem.attrib.get("reason", "") if state_elem is not None else ""

                    service_name = ""
                    product = ""
                    version = ""
                    extra_info = ""
                    method = ""
                    confidence = None
                    cpe_list: List[str] = []

                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service_name = service_elem.attrib.get("name", "")
                        product = service_elem.attrib.get("product", "")
                        version = service_elem.attrib.get("version", "")
                        extra_info = service_elem.attrib.get("extrainfo", "")
                        method = service_elem.attrib.get("method", "")
                        conf_str = service_elem.attrib.get("conf", "")
                        if conf_str and conf_str.isdigit():
                            confidence = int(conf_str)

                        for cpe_elem in service_elem.findall("cpe"):
                            if cpe_elem.text and cpe_elem.text.strip():
                                cpe_list.append(cpe_elem.text.strip())

                    # Port-level scripts
                    scripts: Dict[str, str] = {}
                    for sc in port_elem.findall("script"):
                        s_id = sc.attrib.get("id", "")
                        s_out = sc.attrib.get("output", "")
                        if s_id:
                            scripts[s_id] = s_out

                    ports.append(
                        PortResult(
                            port_id=port_id,
                            protocol=protocol,
                            state=state,
                            service_name=service_name,
                            product=product,
                            version=version,
                            extra_info=extra_info,
                            cpe_list=cpe_list,
                            scripts=scripts,
                            confidence=confidence,
                            method=method,
                            state_reason=state_reason,
                        )
                    )

            hosts.append(
                HostResult(
                    ip=ip,
                    status=status,
                    hostname=hostname,
                    ports=ports,
                    address_type=address_type,
                    mac_address=mac_address,
                    vendor=vendor,
                    os_match=os_match,
                    os_accuracy=os_accuracy,
                    device_type=device_type,
                    host_scripts=host_scripts,
                    latency_ms=latency_ms,
                    status_reason=status_reason,
                    uptime_seconds=uptime_seconds,
                )
            )

        return NmapScanResult(
            command_args=command_args,
            hosts=hosts,
            raw_xml=xml_content,
            scanner=scanner,
            version=version,
            start_time=start_time,
            finish_time=finish_time,
            summary=summary,
        )

    @classmethod
    def parse_text(cls, text: str, command: str = "") -> NmapScanResult:
        """Parse standard Nmap console text output into structured NmapScanResult."""
        if not text or not text.strip():
            return NmapScanResult(command_args=command, raw_xml="")

        scanner = "nmap"
        version = ""
        summary = ""
        hosts: List[HostResult] = []
        current_host: Optional[HostResult] = None

        def _flush_host():
            nonlocal current_host
            if current_host:
                hosts.append(current_host)
                current_host = None

        lines = text.splitlines()
        has_report_lines = bool(re.search(r"Nmap scan report for", text, re.IGNORECASE))
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Check header
            v_match = re.search(r"Starting Nmap\s+([0-9.]+)", line, re.IGNORECASE)
            if v_match:
                version = v_match.group(1)
                continue

            # Check summary line
            if line.startswith("Nmap done:"):
                summary = line
                continue

            # Host scan report
            # Examples:
            # "Nmap scan report for leo (127.0.0.1)"
            # "Nmap scan report for 192.168.100.7"
            report_match = re.search(
                r"^Nmap scan report for (?:([^\s(]+)\s+\()?([0-9a-fA-F:.]+)\)?\s*$",
                line,
                re.IGNORECASE,
            )
            if report_match:
                _flush_host()
                name_part, ip_part = report_match.groups()
                hostname = name_part if (name_part and ip_part) else None
                ip_addr = ip_part or name_part or ""
                current_host = HostResult(
                    ip=ip_addr,
                    status="up",
                    hostname=hostname,
                )
                continue

            report_match_named = re.search(r"^Nmap scan report for (\S+)$", line, re.IGNORECASE)
            if report_match_named:
                _flush_host()
                target_name = report_match_named.group(1)
                current_host = HostResult(
                    ip=target_name,
                    status="up",
                    hostname=target_name,
                )
                continue

            if not current_host:
                if has_report_lines:
                    continue
                # If command specified a target and output has no report line (e.g. partial output)
                target_ip = ""
                if command:
                    cmd_parts = command.split()
                    for p in reversed(cmd_parts):
                        clean_p = p.strip("'\",;()")
                        if not clean_p.startswith("-") and ("." in clean_p or ":" in clean_p) and "/" not in clean_p:
                            target_ip = clean_p
                            break
                if not target_ip:
                    # Look for IP in text (e.g. from prompt, ping, or status lines)
                    ip_cands = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
                    for cand in ip_cands:
                        if cand not in ("0.0.0.0", "255.255.255.255"):
                            target_ip = cand
                            break
                if not target_ip:
                    # Look for hostname in Service Info: Host: <host>
                    host_info_match = re.search(r"Service Info:\s*Host:\s*([a-zA-Z0-9.\-_]+)", text, re.IGNORECASE)
                    if host_info_match:
                        target_ip = host_info_match.group(1).strip()

                if target_ip and "/" not in target_ip:
                    current_host = HostResult(ip=target_ip, status="up")

            if not current_host:
                continue

            # Host is up (0.000040s latency).
            up_match = re.search(r"^Host is up(?:\s*\(([\d.]+)(m?s)\s+latency\))?", line, re.IGNORECASE)
            if up_match:
                current_host.status = "up"
                lat_val = up_match.group(1)
                lat_unit = up_match.group(2)
                if lat_val:
                    try:
                        ms = float(lat_val)
                        if lat_unit == "s":
                            ms *= 1000.0
                        current_host.latency_ms = round(ms, 2)
                    except ValueError:
                        pass
                continue

            if line.startswith("Host is down"):
                current_host.status = "down"
                continue

            # MAC Address: 00:11:22:33:44:55 (Vendor Name)
            mac_match = re.search(r"^MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?", line, re.IGNORECASE)
            if mac_match:
                current_host.mac_address = mac_match.group(1)
                current_host.vendor = mac_match.group(2) or None
                continue

            # Device type: general purpose
            dt_match = re.search(r"^Device type:\s*(.+)$", line, re.IGNORECASE)
            if dt_match:
                current_host.device_type = dt_match.group(1).strip()
                continue

            # OS details / Running:
            os_match = re.search(r"^(?:OS details|Running):\s*(.+)$", line, re.IGNORECASE)
            if os_match:
                current_host.os_match = os_match.group(1).strip()
                continue

            # Service Info: Host: leo; OS: Unix; CPE: cpe:/o:linux:linux_kernel
            svc_info_match = re.search(r"^Service Info:\s*(.+)$", line, re.IGNORECASE)
            if svc_info_match:
                info_parts = [p.strip() for p in svc_info_match.group(1).split(";")]
                for part in info_parts:
                    if part.lower().startswith("host:"):
                        h_val = part.split(":", 1)[1].strip()
                        if not current_host.hostname or current_host.hostname == current_host.ip:
                            current_host.hostname = h_val
                    elif part.lower().startswith("os:"):
                        os_val = part.split(":", 1)[1].strip()
                        if not current_host.os_match:
                            current_host.os_match = os_val
                continue

            # Port matching:
            # 21/tcp open ftp vsftpd 3.0.5
            # 80/tcp open http Apache httpd 2.4.58 ((Ubuntu))
            port_match = re.match(
                r"^(\d{1,5})/(tcp|udp|sctp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\s+(.*))?$",
                line,
                re.IGNORECASE,
            )
            if port_match:
                p_id = int(port_match.group(1))
                proto = port_match.group(2).lower()
                state = port_match.group(3).lower()
                svc_name = port_match.group(4)
                extra = (port_match.group(5) or "").strip()

                product = ""
                version = ""
                if extra:
                    parts = extra.split(None, 1)
                    product = parts[0]
                    if len(parts) > 1:
                        version = parts[1]

                current_host.ports.append(
                    PortResult(
                        port_id=p_id,
                        protocol=proto,
                        state=state,
                        service_name=svc_name,
                        product=product,
                        version=version,
                        extra_info=extra,
                    )
                )

        _flush_host()

        return NmapScanResult(
            command_args=command,
            hosts=hosts,
            raw_xml="",
            scanner=scanner,
            version=version,
            summary=summary,
        )

    @classmethod
    def parse(cls, content: str, command: str = "") -> NmapScanResult:
        """Dispatches to XML or text parser based on content structure."""
        stripped = (content or "").strip()
        if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
            try:
                return cls.parse_xml(stripped)
            except Exception:
                return cls.parse_text(stripped, command=command)
        return cls.parse_text(stripped, command=command)

    @classmethod
    def to_findings(
        cls,
        scan_result: NmapScanResult,
        project_id: int,
        execution_id: Optional[int] = None,
    ) -> List[Finding]:
        """Convert discovered open ports, services, and script alerts into structured findings.

        CRITICAL VALIDATION RULE:
        Open ports and running services are security observations (ValidationStatus.OBSERVED),
        NOT confirmed exploitable vulnerabilities.
        """
        findings: List[Finding] = []

        for host in scan_result.hosts:
            if host.status != "up":
                continue

            for port in host.ports:
                if port.state != "open":
                    continue

                service_desc = port.service_summary or "Unknown service"
                title = f"Discovered Service: {service_desc} on {host.ip}:{port.port_id}/{port.protocol}"

                # Severity rationale and initial classification
                severity = FindingSeverity.INFORMATIONAL
                remediation = "Verify whether this port/service is required for business purposes; restrict access via firewall if unnecessary."
                val_status = ValidationStatus.OBSERVED

                insecure_services = {
                    "telnet": (FindingSeverity.HIGH, "Replace Telnet with encrypted SSH."),
                    "ftp": (FindingSeverity.LOW, "Ensure FTP requires encryption (FTPS/SFTP) and disallows anonymous login."),
                    "http": (FindingSeverity.INFORMATIONAL, "Ensure HTTP traffic redirects to secure HTTPS."),
                    "smb": (FindingSeverity.MEDIUM, "Ensure SMB signing is required and SMBv1 is disabled."),
                    "ms-wbt-server": (FindingSeverity.MEDIUM, "Restrict RDP access with NLA and MFA."),
                    "vnc": (FindingSeverity.MEDIUM, "Require strong authentication and tunnel VNC through SSH/VPN."),
                    "rsh": (FindingSeverity.HIGH, "Disable legacy RSH and replace with SSH."),
                    "rlogin": (FindingSeverity.HIGH, "Disable legacy Rlogin and replace with SSH."),
                }

                svc_lower = port.service_name.lower()
                for key, (sev, rem) in insecure_services.items():
                    if key in svc_lower:
                        severity = sev
                        remediation = rem
                        break

                cpe_info = f" CPE: {', '.join(port.cpe_list)}." if port.cpe_list else ""
                description = (
                    f"Port {port.port_id}/{port.protocol} was identified as open on host {host.ip} "
                    f"({host.hostname or 'no reverse DNS'}). Service identified: {service_desc}.{cpe_info}"
                )

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        severity=severity,
                        affected_asset=host.ip,
                        affected_port_service=f"{port.port_id}/{port.protocol}",
                        description=description,
                        remediation=remediation,
                        validation_status=val_status,
                        source_tool="nmap",
                        execution_id=execution_id,
                    )
                )

                # Script findings (e.g. anonymous FTP login, SSL issues, SMB vulnerability scripts)
                for script_id, script_output in port.scripts.items():
                    out_lower = script_output.lower()
                    if any(indicator in out_lower for indicator in ("vulnerable", "allowed", "insecure", "warning", "anonymous")):
                        script_sev = FindingSeverity.LOW
                        if "vulnerable" in out_lower:
                            script_sev = FindingSeverity.HIGH
                        elif "anonymous" in out_lower and "allowed" in out_lower:
                            script_sev = FindingSeverity.MEDIUM

                        findings.append(
                            Finding(
                                project_id=project_id,
                                title=f"NSE Script Detection: {script_id} on {host.ip}:{port.port_id}/{port.protocol}",
                                severity=script_sev,
                                affected_asset=host.ip,
                                affected_port_service=f"{port.port_id}/{port.protocol}",
                                description=f"NSE script '{script_id}' reported potential issue:\n\n{script_output.strip()}",
                                remediation="Review the script output, verify service configuration, and apply vendor security patches.",
                                validation_status=ValidationStatus.NEEDS_VALIDATION,
                                source_tool=f"nmap-nse:{script_id}",
                                execution_id=execution_id,
                            )
                        )

        return findings
