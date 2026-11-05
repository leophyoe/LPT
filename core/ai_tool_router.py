"""AI-driven security tool router and execution planner.

Inspired by 0x4m4/hexstrike-ai and AIPentest/CyberStrikeAI.
Translates natural language security testing intentions into scope-authorized,
methodologically sound tool execution plans across registered assessment tools.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService
from storage.db import Database
from storage.models import Project


class ToolSafetyLevel(str, Enum):
    PASSIVE = "passive"          # Non-intrusive, headers, local file, offline analysis
    ACTIVE_SAFE = "active_safe"  # Standard port scanning, version detection
    INTRUSIVE = "intrusive"      # Directory fuzzing, SQL injection, brute forcing


@dataclass
class ToolExecutionPlan:
    tool_name: str
    display_name: str
    command: List[str]
    command_str: str
    target: str
    safety_level: ToolSafetyLevel
    reasoning: str
    is_authorized: bool
    scope_reason: str
    suggested_ui_view: Optional[str] = None  # e.g. "network", "web", "findings", "shell"


class AIToolRouter:
    """Intelligently routes natural language security objectives to concrete tool workflows."""

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def route_intent(
        self,
        prompt: str,
        project: Optional[Project] = None,
        db: Optional[Database] = None,
    ) -> ToolExecutionPlan:
        """Analyzes pentest objective and constructs an authorized tool execution plan."""
        text = prompt.strip()
        lowered = text.lower()

        # 1. Extract Target (URL, IP, or File)
        target = self._extract_target(text)

        # 2. Scope Guard Check
        is_authorized = False
        scope_reason = "Choose a project with an authorized target scope before planning network activity."
        if target and project and db:
            scopes = db.list_scopes(project.id)
            check = ScopeAuthorizationService.is_target_authorized(
                target, scopes, project=project, resolve_dns=True
            )
            is_authorized = check.is_allowed
            scope_reason = check.reason

        # 3. Tool Selection Heuristics
        # Case A: SQL Injection
        if any(k in lowered for k in ["sqlmap", "sql injection", "sqli", "inject database"]):
            tgt = target or "http://127.0.0.1:8080/item?id=1"
            cmd = ["sqlmap", "-u", tgt, "--batch", "--banner"]
            return ToolExecutionPlan(
                tool_name="sqlmap",
                display_name="SQLMap Injection Engine",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.INTRUSIVE,
                reasoning="Selected SQLMap to detect database backends and test parameter injection flaws.",
                is_authorized=is_authorized,
                scope_reason=scope_reason,
                suggested_ui_view="web",
            )

        # Case B: Web Fuzzing / Directories
        if any(k in lowered for k in ["gobuster", "fuzz", "directory", "dirsearch", "hidden paths", "routes"]):
            tgt = target or "http://127.0.0.1:8080/"
            cmd = ["gobuster", "dir", "-u", tgt, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]
            return ToolExecutionPlan(
                tool_name="gobuster",
                display_name="Gobuster Directory Fuzzer",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.INTRUSIVE,
                reasoning="Selected Gobuster for rapid brute-forcing of web endpoints, secret routes, and administrative pages.",
                is_authorized=is_authorized,
                scope_reason=scope_reason,
                suggested_ui_view="web",
            )

        # Case C: WAF / Firewall Detection
        if any(k in lowered for k in ["waf", "firewall", "wafw00f", "cloudflare", "imperva"]):
            tgt = target or "http://127.0.0.1:8080/"
            cmd = ["wafw00f", tgt]
            return ToolExecutionPlan(
                tool_name="wafw00f",
                display_name="WAFW00F Firewall Fingerprinter",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.PASSIVE,
                reasoning="Selected WAFW00F to detect active Web Application Firewalls before initiating active scans.",
                is_authorized=is_authorized,
                scope_reason=scope_reason,
                suggested_ui_view="web",
            )

        # Case D: JWT Token Analysis
        if any(k in lowered for k in ["jwt", "token", "r-builder", "curl import", "alg none", "ptk"]):
            tgt = target or "JWT Token String"
            cmd = ["ptk", "jwt", "analyze"]
            return ToolExecutionPlan(
                tool_name="ptk",
                display_name="OWASP PTK (Penetration Testing Kit)",
                command=cmd,
                command_str="ptk jwt --audit",
                target=tgt,
                safety_level=ToolSafetyLevel.PASSIVE,
                reasoning="Selected OWASP PTK Workbench to audit token signatures, expiration claims, and test 'none' algorithm bypass.",
                is_authorized=not target or is_authorized,
                scope_reason="Client-side cryptographic assessment" if not target else scope_reason,
                suggested_ui_view="web",
            )

        # Case E: Memory Forensics / Dump
        if any(k in lowered for k in ["volatility", "memory", "ram", "dump", "process list", "pslist"]):
            tgt = target or "memory.raw"
            cmd = ["vol.py", "-f", tgt, "windows.pslist"]
            return ToolExecutionPlan(
                tool_name="volatility3",
                display_name="Volatility 3 Memory Forensics",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.PASSIVE,
                reasoning="Selected Volatility 3 to analyze raw memory dumps for rootkits, rogue processes, and injected DLLs.",
                is_authorized=True,
                scope_reason="Offline forensic artifact inspection",
                suggested_ui_view="findings",
            )

        # Case F: Code Security / SAST
        if any(k in lowered for k in ["bandit", "sast", "code security", "source code", "linter"]):
            tgt = target or "."
            cmd = ["bandit", "-r", tgt, "-f", "json"]
            return ToolExecutionPlan(
                tool_name="bandit",
                display_name="Bandit Python AST Analyzer",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.PASSIVE,
                reasoning="Selected Bandit to scan Python source trees for hardcoded passwords, unsafe deserialization, and SQL formatting.",
                is_authorized=True,
                scope_reason="Local source code repository analysis",
                suggested_ui_view="findings",
            )

        # Case G: Password Cracking
        if any(k in lowered for k in ["hashcat", "hash", "crack", "john", "wordlist", "md5"]):
            tgt = target or "hash.txt"
            cmd = ["hashcat", "-m", "0", "-a", "0", tgt, "/usr/share/wordlists/rockyou.txt"]
            return ToolExecutionPlan(
                tool_name="hashcat",
                display_name="Hashcat Password Recovery",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.PASSIVE,
                reasoning="Selected Hashcat for high-performance offline dictionary cracking of captured credentials.",
                is_authorized=True,
                scope_reason="Offline hash recovery",
                suggested_ui_view="shell",
            )

        # Case H: Nikto Web Server Vulnerability Scanning
        if any(k in lowered for k in ["nikto", "web server vuln", "server vulnerability", "cgi scan", "web misconfiguration"]):
            tgt = target or "http://127.0.0.1:8080/"
            cmd = ["nikto", "-host", tgt, "-nointeractive"]
            return ToolExecutionPlan(
                tool_name="nikto",
                display_name="Nikto Web Vulnerability Scanner",
                command=cmd,
                command_str=shlex.join(cmd),
                target=tgt,
                safety_level=ToolSafetyLevel.ACTIVE_SAFE,
                reasoning="Selected Nikto to detect web server misconfigurations, dangerous CGIs, outdated software banners, and insecure HTTP response headers.",
                is_authorized=is_authorized,
                scope_reason=scope_reason,
                suggested_ui_view="web",
            )

        # Case I: Network & Port Scanning (Default Nmap)
        tgt = target or "127.0.0.1"
        is_syn = "syn" in lowered or "stealth" in lowered
        flag = "-sS" if is_syn else "-sV -sC"
        cmd = ["nmap", flag, "-Pn", "-T4", tgt]
        return ToolExecutionPlan(
            tool_name="nmap",
            display_name="Nmap Network Scanner",
            command=cmd,
            command_str=shlex.join(cmd),
            target=tgt,
            safety_level=ToolSafetyLevel.ACTIVE_SAFE,
            reasoning="Selected Nmap as primary network discovery tool to identify online hosts, open TCP/UDP ports, and service banners.",
            is_authorized=is_authorized,
            scope_reason=scope_reason,
            suggested_ui_view="network",
        )

    @staticmethod
    def _extract_target(text: str) -> str:
        """Extracts potential IP address, hostname, or URL from text."""
        # Preserve whitespace in explicitly quoted URLs, then remove only the
        # surrounding quote characters.
        quoted_url = re.search(r"[\"'](https?://[^\"']+)[\"']", text)
        if quoted_url:
            return quoted_url.group(1).rstrip(".,;)")

        # Check URLs
        url_match = re.search(r"https?://[^\s]+", text)
        if url_match:
            return url_match.group(0).rstrip(".,;')\"")

        # Check IPs
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text)
        if ip_match:
            return ip_match.group(0)

        # Check domains
        domain_match = re.search(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b", text)
        if domain_match:
            return domain_match.group(0)

        return ""
