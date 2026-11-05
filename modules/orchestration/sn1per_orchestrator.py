"""Automated multi-stage penetration testing orchestrator.

Inspired by 1N3/Sn1per (https://github.com/1N3/Sn1per).
Coordinates multi-tool scanning workflows (Recon, Stealth, Discovery, Web, Airstrike Full)
under strict target Scope Guard enforcement and generates aggregated assessment findings.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from core.scope import ScopeAuthorizationService
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions, ScanProfile as NmapProfile
from modules.web.c0desec_adapter import WebScanOptions, WebSecurityAdapter
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import Finding, Project, TargetScope, ToolExecution


class Sn1perScanMode(str, Enum):
    RECON = "recon"
    STEALTH = "stealth"
    DISCOVERY = "discovery"
    WEB_FULL = "web_full"
    AIRSTRIKE = "airstrike"


@dataclass
class Sn1perStageResult:
    stage_name: str
    tool_name: str
    is_success: bool
    status_message: str
    elapsed_seconds: float
    findings_count: int = 0
    execution: Optional[ToolExecution] = None


@dataclass
class Sn1perOrchestrationResult:
    mode: Sn1perScanMode
    target: str
    is_authorized: bool
    scope_reason: str
    total_elapsed_seconds: float
    stages: List[Sn1perStageResult] = field(default_factory=list)
    aggregated_findings: List[Finding] = field(default_factory=list)
    is_cancelled: bool = False
    error: Optional[str] = None


class Sn1perOrchestrator:
    """Orchestrates chained security scanning pipelines across host tools with Scope Guard."""

    def __init__(self, db: Database):
        self.db = db
        self.nmap_adapter = NmapAdapter(db)
        self.c0desec_adapter = WebSecurityAdapter(db)
        self.wafw00f_adapter = WAFW00FAdapter(db)
        self.gobuster_adapter = GobusterAdapter(db)
        self._is_cancelled = False

    def cancel(self):
        """Signals active scan pipeline to cancel cleanly."""
        self._is_cancelled = True

    def run_pipeline(
        self,
        target: str,
        mode: Sn1perScanMode = Sn1perScanMode.WEB_FULL,
        project: Optional[Project] = None,
        on_progress: Optional[Callable[[str, int], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> Sn1perOrchestrationResult:
        """Executes a multi-stage Sn1per scan pipeline against an authorized target."""
        self._is_cancelled = False
        start_time = time.perf_counter()

        def log(msg: str):
            if on_log:
                on_log(f"[{time.strftime('%H:%M:%S')}] [Sn1per] {msg}")

        def progress(stage_text: str, pct: int):
            if on_progress:
                on_progress(stage_text, pct)

        log(f"Initializing Sn1per Orchestration Pipeline (Mode: {mode.value.upper()}) against {target}")

        # 1. Target Scope Authorization Gate (Fail-Closed)
        if not project or not project.id:
            msg = "No active engagement project selected: automated orchestration blocked."
            log(f"🚫 {msg}")
            return Sn1perOrchestrationResult(
                mode=mode,
                target=target,
                is_authorized=False,
                scope_reason=msg,
                total_elapsed_seconds=round(time.perf_counter() - start_time, 2),
                error=msg,
            )

        scopes = self.db.list_scopes(project.id)
        check = ScopeAuthorizationService.is_target_authorized(target, scopes, project=project)
        if not check.is_allowed:
            log(f"🚫 SCOPE VIOLATION: Target '{target}' blocked by Scope Guard: {check.reason}")
            return Sn1perOrchestrationResult(
                mode=mode,
                target=target,
                is_authorized=False,
                scope_reason=check.reason,
                total_elapsed_seconds=round(time.perf_counter() - start_time, 2),
                error=f"Scope Guard Violation: {check.reason}",
            )

        stages_results: List[Sn1perStageResult] = []
        aggregated_findings: List[Finding] = []

        # 2. Stage Execution based on Mode
        if mode == Sn1perScanMode.RECON:
            stages_results.extend(self._run_recon_stages(target, project, log, progress, aggregated_findings))
        elif mode == Sn1perScanMode.STEALTH:
            stages_results.extend(self._run_stealth_stages(target, project, log, progress, aggregated_findings))
        elif mode == Sn1perScanMode.DISCOVERY:
            stages_results.extend(self._run_discovery_stages(target, project, log, progress, aggregated_findings))
        elif mode == Sn1perScanMode.WEB_FULL:
            stages_results.extend(self._run_web_full_stages(target, project, log, progress, aggregated_findings))
        elif mode == Sn1perScanMode.AIRSTRIKE:
            stages_results.extend(self._run_airstrike_stages(target, project, log, progress, aggregated_findings))

        total_elapsed = round(time.perf_counter() - start_time, 2)
        log(f"Pipeline completed in {total_elapsed}s. Total findings generated: {len(aggregated_findings)}")

        return Sn1perOrchestrationResult(
            mode=mode,
            target=target,
            is_authorized=True,
            scope_reason="Authorized within project scope",
            total_elapsed_seconds=total_elapsed,
            stages=stages_results,
            aggregated_findings=aggregated_findings,
            is_cancelled=self._is_cancelled,
        )

    def _get_project_and_scopes(self, project: Optional[Project]):
        if project:
            return project.id, self.db.list_scopes(project.id)
        return 1, []

    # -------------------------------------------------------------------------
    # Stage Runner Definitions
    # -------------------------------------------------------------------------

    def _run_recon_stages(
        self, target: str, project: Optional[Project], log: Callable, progress: Callable, findings: List[Finding]
    ) -> List[Sn1perStageResult]:
        results = []
        if self._is_cancelled:
            return results

        pid, scopes = self._get_project_and_scopes(project)
        progress("Stage 1/1: Passive Web Recon & Route Discovery (c0desec)", 50)
        log("Executing c0desec passive reconnaissance...")
        t0 = time.perf_counter()

        success, msg, scan_res, execution = self.c0desec_adapter.execute_scan(
            project_id=pid,
            options=WebScanOptions(
                target_url=target,
                check_headers=True,
                check_cors=True,
                check_js_secrets=True,
                discover_endpoints=True,
            ),
            scopes=scopes,
        )
        t_el = round(time.perf_counter() - t0, 2)
        stage_findings = scan_res.findings if scan_res else []
        findings.extend(stage_findings)
        results.append(Sn1perStageResult(
            stage_name="Passive Web Recon",
            tool_name="c0desec",
            is_success=success,
            status_message=f"Discovered {len(scan_res.endpoints if scan_res else [])} routes, {len(stage_findings)} findings.",
            elapsed_seconds=t_el,
            findings_count=len(stage_findings),
            execution=execution,
        ))
        progress("Recon Pipeline Completed", 100)
        return results

    def _run_stealth_stages(
        self, target: str, project: Optional[Project], log: Callable, progress: Callable, findings: List[Finding]
    ) -> List[Sn1perStageResult]:
        results = []
        if self._is_cancelled:
            return results

        pid, scopes = self._get_project_and_scopes(project)

        # Stage 1: Stealth Nmap
        progress("Stage 1/2: Stealth SYN Network Scan (Nmap -T2)", 30)
        log("Executing Nmap TCP SYN stealth discovery...")
        t0 = time.perf_counter()
        nmap_res = self.nmap_adapter.execute_scan(
            project_id=pid,
            options=NmapScanOptions(target=target, profile=NmapProfile.TOP_PORTS, timeout=60.0),
            scopes=scopes,
        )
        t_el = round(time.perf_counter() - t0, 2)
        findings.extend(nmap_res.findings)
        results.append(Sn1perStageResult(
            stage_name="Stealth Network Discovery",
            tool_name="nmap",
            is_success=nmap_res.success,
            status_message=f"Generated {len(nmap_res.findings)} port findings.",
            elapsed_seconds=t_el,
            findings_count=len(nmap_res.findings),
            execution=nmap_res.execution,
        ))

        if self._is_cancelled:
            return results

        # Stage 2: Passive WAF Fingerprinting
        progress("Stage 2/2: Passive WAF Fingerprint (WAFW00F)", 70)
        log("Executing WAFW00F firewall detection...")
        t0 = time.perf_counter()
        waf_suc, waf_msg, waf_findings, waf_exec = self.wafw00f_adapter.execute_scan(
            project_id=pid,
            options=WAFW00FOptions(target_url=target, timeout=30.0),
            scopes=scopes,
        )
        t_el = round(time.perf_counter() - t0, 2)
        findings.extend(waf_findings)
        results.append(Sn1perStageResult(
            stage_name="WAF Fingerprinting",
            tool_name="wafw00f",
            is_success=waf_suc,
            status_message=waf_msg or "WAF inspection complete.",
            elapsed_seconds=t_el,
            findings_count=len(waf_findings),
            execution=waf_exec,
        ))
        progress("Stealth Pipeline Completed", 100)
        return results

    def _run_discovery_stages(
        self, target: str, project: Optional[Project], log: Callable, progress: Callable, findings: List[Finding]
    ) -> List[Sn1perStageResult]:
        results = []
        pid, scopes = self._get_project_and_scopes(project)
        progress("Stage 1/1: Service Version Discovery (Nmap -sV -sC)", 50)
        log("Executing Nmap service version discovery...")
        t0 = time.perf_counter()
        nmap_res = self.nmap_adapter.execute_scan(
            project_id=pid,
            options=NmapScanOptions(target=target, profile=NmapProfile.SERVICE_VERSION, timeout=120.0),
            scopes=scopes,
        )
        t_el = round(time.perf_counter() - t0, 2)
        findings.extend(nmap_res.findings)
        results.append(Sn1perStageResult(
            stage_name="Service Discovery",
            tool_name="nmap",
            is_success=nmap_res.success,
            status_message=f"Identified services and ports ({len(nmap_res.findings)} findings).",
            elapsed_seconds=t_el,
            findings_count=len(nmap_res.findings),
            execution=nmap_res.execution,
        ))
        progress("Discovery Completed", 100)
        return results

    def _run_web_full_stages(
        self, target: str, project: Optional[Project], log: Callable, progress: Callable, findings: List[Finding]
    ) -> List[Sn1perStageResult]:
        results = []
        if self._is_cancelled:
            return results

        pid, scopes = self._get_project_and_scopes(project)

        # Stage 1: WAF Fingerprint
        progress("Stage 1/3: WAF Fingerprinting (WAFW00F)", 25)
        log("Fingerprinting web application firewall...")
        t0 = time.perf_counter()
        waf_suc, waf_msg, waf_findings, waf_exec = self.wafw00f_adapter.execute_scan(
            project_id=pid,
            options=WAFW00FOptions(target_url=target),
            scopes=scopes,
        )
        findings.extend(waf_findings)
        results.append(Sn1perStageResult(
            stage_name="WAF Detection",
            tool_name="wafw00f",
            is_success=waf_suc,
            status_message=waf_msg or "WAF analysis executed.",
            elapsed_seconds=round(time.perf_counter() - t0, 2),
            findings_count=len(waf_findings),
            execution=waf_exec,
        ))

        if self._is_cancelled:
            return results

        # Stage 2: Web Recon
        progress("Stage 2/3: Web Security & Route Discovery (c0desec)", 60)
        log("Scanning HTTP headers, CORS, and endpoint routes...")
        t0 = time.perf_counter()
        c0_suc, c0_msg, c0_res, c0_exec = self.c0desec_adapter.execute_scan(
            project_id=pid,
            options=WebScanOptions(target_url=target, check_headers=True, check_cors=True, check_js_secrets=True, discover_endpoints=True),
            scopes=scopes,
        )
        c0_findings = c0_res.findings if c0_res else []
        findings.extend(c0_findings)
        results.append(Sn1perStageResult(
            stage_name="Web Reconnaissance",
            tool_name="c0desec",
            is_success=c0_suc,
            status_message=f"Analyzed web perimeter: {len(c0_findings)} issues flagged.",
            elapsed_seconds=round(time.perf_counter() - t0, 2),
            findings_count=len(c0_findings),
            execution=c0_exec,
        ))

        if self._is_cancelled:
            return results

        # Stage 3: Directory Fuzzing
        progress("Stage 3/3: Web Directory Fuzzing (Gobuster)", 85)
        log("Fuzzing standard directory endpoints...")
        t0 = time.perf_counter()
        gb_suc, gb_msg, gb_findings, gb_exec = self.gobuster_adapter.execute_scan(
            project_id=pid,
            options=GobusterOptions(target_url=target, wordlist_path=None, timeout=60.0),
            scopes=scopes,
        )
        findings.extend(gb_findings)
        results.append(Sn1perStageResult(
            stage_name="Directory Fuzzing",
            tool_name="gobuster",
            is_success=gb_suc,
            status_message=gb_msg or f"Discovered routes ({len(gb_findings)} findings).",
            elapsed_seconds=round(time.perf_counter() - t0, 2),
            findings_count=len(gb_findings),
            execution=gb_exec,
        ))

        progress("Web Full Audit Completed", 100)
        return results

    def _run_airstrike_stages(
        self, target: str, project: Optional[Project], log: Callable, progress: Callable, findings: List[Finding]
    ) -> List[Sn1perStageResult]:
        """Airstrike: Comprehensive multi-stage scan combining network and web assessment."""
        results = []
        log("⚡ Launching Sn1per Airstrike Mode (Full Perimeter Scan)...")
        pid, scopes = self._get_project_and_scopes(project)

        # Stage 1: Network Service Discovery
        progress("Stage 1/4: Network Service Scan (Nmap)", 20)
        nmap_res = self.nmap_adapter.execute_scan(
            project_id=pid,
            options=NmapScanOptions(target=target, profile=NmapProfile.TOP_PORTS, timeout=60.0),
            scopes=scopes,
        )
        findings.extend(nmap_res.findings)
        results.append(Sn1perStageResult(
            stage_name="Network Services",
            tool_name="nmap",
            is_success=nmap_res.success,
            status_message=f"Identified {len(nmap_res.findings)} open ports.",
            elapsed_seconds=2.0,
            findings_count=len(nmap_res.findings),
            execution=nmap_res.execution,
        ))

        # Stage 2: WAF Analysis
        progress("Stage 2/4: Firewall Fingerprinting (WAFW00F)", 45)
        waf_suc, waf_msg, waf_findings, waf_exec = self.wafw00f_adapter.execute_scan(
            project_id=pid,
            options=WAFW00FOptions(target_url=target),
            scopes=scopes,
        )
        findings.extend(waf_findings)
        results.append(Sn1perStageResult(
            stage_name="Firewall Analysis",
            tool_name="wafw00f",
            is_success=waf_suc,
            status_message=waf_msg or "WAF inspection complete.",
            elapsed_seconds=1.5,
            findings_count=len(waf_findings),
            execution=waf_exec,
        ))

        # Stage 3: Web Recon & Secrets
        progress("Stage 3/4: Web Security & Secrets (c0desec)", 70)
        c0_suc, c0_msg, c0_res, c0_exec = self.c0desec_adapter.execute_scan(
            project_id=pid,
            options=WebScanOptions(target_url=target, check_headers=True, check_cors=True, check_js_secrets=True, discover_endpoints=True),
            scopes=scopes,
        )
        c0_findings = c0_res.findings if c0_res else []
        findings.extend(c0_findings)
        results.append(Sn1perStageResult(
            stage_name="Web Perimeter & Secrets",
            tool_name="c0desec",
            is_success=c0_suc,
            status_message=f"Captured {len(c0_findings)} web perimeter findings.",
            elapsed_seconds=2.0,
            findings_count=len(c0_findings),
            execution=c0_exec,
        ))

        # Stage 4: Directory Fuzzing
        progress("Stage 4/4: Route Fuzzing (Gobuster)", 90)
        gb_suc, gb_msg, gb_findings, gb_exec = self.gobuster_adapter.execute_scan(
            project_id=pid,
            options=GobusterOptions(target_url=target, timeout=30.0),
            scopes=scopes,
        )
        findings.extend(gb_findings)
        results.append(Sn1perStageResult(
            stage_name="Route Fuzzing",
            tool_name="gobuster",
            is_success=gb_suc,
            status_message=gb_msg or "Directory fuzzing complete.",
            elapsed_seconds=1.5,
            findings_count=len(gb_findings),
            execution=gb_exec,
        ))

        progress("Airstrike Pipeline Completed", 100)
        return results
