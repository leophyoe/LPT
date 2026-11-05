"""Assessment and test plan execution orchestrator for CyberSecuritySuite.

Manages end-to-end execution of structured security assessment plans:
1. Generates unique execution IDs and assessment run identifiers.
2. Orders tests by prerequisite dependencies.
3. Enforces fail-closed preflight and scope validation at the execution boundary.
4. Executes tests with bounded timeouts and escalatory process cancellation.
5. Prevents duplicate concurrent executions of the same plan or assessment run.
6. Maps test outcomes strictly into defined states:
   PASSED, FAILED, BLOCKED, ERROR, CANCELLED, NEEDS_REVIEW.
   (Note: FAILED signifies test failure or failed acceptance criteria,
    NEVER proof of a vulnerability).
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from core.preflight import PreflightChecker, VerificationCheckStatus
from core.registry import ToolRegistry
from core.scope import ScopeAuthorizationService
from core.verification_engine import (
    ActiveDirectoryVerificationService,
    NetworkVerificationService,
    PrivilegeEscalationVerificationService,
    WebBinaryVerificationService,
)
from modules.network.nmap_adapter import NmapAdapter, NmapScanOptions, ScanProfile
from modules.web.c0desec_adapter import WebScanOptions, WebSecurityAdapter
from modules.web.gobuster_adapter import GobusterAdapter, GobusterOptions
from modules.web.nikto_adapter import NiktoAdapter, NiktoScanOptions
from modules.web.wafw00f_adapter import WAFW00FAdapter, WAFW00FOptions
from storage.db import Database
from storage.models import (
    AssessmentPlan,
    AssessmentStatus,
    ExecutionStatus,
    Finding,
    Project,
    TargetScope,
    TestCategory,
    ToolExecution,
    ValidationStatus,
)
from terminal.runner import ProcessRunner


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TestExecutionState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"
    CANCELLED = "cancelled"
    NEEDS_REVIEW = "needs_review"


TestExecutionState.__test__ = False


@dataclass
class AssessmentTestItem:
    """Represents an atomic test unit within an assessment plan."""
    test_id: str
    name: str
    category: TestCategory
    target: str
    adapter_name: str  # nmap, c0desec, nikto, gobuster, wafw00f, verification_engine
    options: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)
    timeout_seconds: float = 120.0
    expected_result: str = ""
    validation_policy: str = ""


@dataclass
class TestStepResult:
    """Execution telemetry and outcome for a single test step."""
    test_id: str
    name: str
    category: TestCategory
    target: str
    state: TestExecutionState
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error_message: str = ""
    blocker_reason: str = ""
    execution_id: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)


@dataclass
class AssessmentRunResult:
    """Aggregated assessment execution report."""
    assessment_id: str
    execution_uuid: str
    project_id: int
    plan_id: Optional[int]
    status: TestExecutionState
    started_at: str
    finished_at: str = ""
    duration_seconds: float = 0.0
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    blocked_tests: int = 0
    error_tests: int = 0
    cancelled_tests: int = 0
    steps: List[TestStepResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


ProgressCallback = Callable[[str, int, str], None]  # (test_id, percent, message)
LogCallback = Callable[[str], None]


class AssessmentOrchestrator:
    """Coordinates, isolates, and records automated security assessment plans."""

    _active_runs: Dict[str, AssessmentRunResult] = {}
    _run_lock = threading.Lock()

    def __init__(self, db: Database, registry: Optional[ToolRegistry] = None):
        self.db = db
        self.registry = registry or ToolRegistry()
        self.preflight = PreflightChecker(db, self.registry)
        self._active_runners: Dict[str, ProcessRunner] = {}
        self._cancel_requested: Dict[str, bool] = {}

    @classmethod
    def is_run_active(cls, assessment_id: str) -> bool:
        with cls._run_lock:
            return assessment_id in cls._active_runs

    def cancel_run(self, assessment_id: str) -> bool:
        """Cancels an active assessment and terminates any running subprocesses."""
        with self._run_lock:
            self._cancel_requested[assessment_id] = True
            runner = self._active_runners.get(assessment_id)
            if runner and runner.is_running:
                return runner.cancel()
        return True

    def build_test_plan_items(self, plan: AssessmentPlan) -> List[AssessmentTestItem]:
        """Maps an AssessmentPlan into structured AssessmentTestItems."""
        items: List[AssessmentTestItem] = []
        target = plan.target
        cat = plan.test_category

        if cat == TestCategory.NETWORK_DISCOVERY:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-NET-DISC-{plan.id or 1}",
                    name="Network Host & Service Fingerprinting",
                    category=cat,
                    target=target,
                    adapter_name="nmap",
                    options={"profile": ScanProfile.TOP_PORTS.value},
                    timeout_seconds=180.0,
                    expected_result="Host reachability verified and port banners indexed.",
                    validation_policy="Require verified service banner before flagging exposures.",
                )
            )
        elif cat == TestCategory.ACTIVE_DIRECTORY:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-AD-CONN-{plan.id or 1}",
                    name="Domain Service Port Reachability",
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    options={"action": "audit_domain_connectivity"},
                    timeout_seconds=30.0,
                    expected_result="Domain Controller core ports probed.",
                )
            )
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-AD-SMB-{plan.id or 1}",
                    name="SMB Signing & Kerberos Policy Audit",
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    options={"action": "evaluate_smb_and_kerberos_hardening"},
                    prerequisites=[f"TEST-AD-CONN-{plan.id or 1}"],
                    timeout_seconds=30.0,
                    expected_result="SMB signing enforcement verified.",
                )
            )
        elif cat == TestCategory.PRIVILEGE_ESCALATION:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-PRIV-PERMS-{plan.id or 1}",
                    name="Local System File Permission Audit",
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    options={"action": "audit_local_file_permissions"},
                    timeout_seconds=20.0,
                    expected_result="No world-writable root configuration files.",
                )
            )
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-PRIV-SUID-{plan.id or 1}",
                    name="SUID/SGID Binary Inventory",
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    options={"action": "inspect_suid_binaries"},
                    timeout_seconds=30.0,
                    expected_result="Known standard SUID set verified.",
                )
            )
        elif cat == TestCategory.WEB_APPLICATION:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-WEB-HDR-{plan.id or 1}",
                    name="HTTP Security Header & Baseline Audit",
                    category=cat,
                    target=target,
                    adapter_name="c0desec",
                    options={"check_headers": True, "check_cors": True, "check_js_secrets": True},
                    timeout_seconds=60.0,
                    expected_result="CSP, HSTS, and frame protections evaluated.",
                )
            )
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-WEB-WAF-{plan.id or 1}",
                    name="Web Application Firewall Detection",
                    category=cat,
                    target=target,
                    adapter_name="wafw00f",
                    prerequisites=[f"TEST-WEB-HDR-{plan.id or 1}"],
                    timeout_seconds=60.0,
                    expected_result="WAF presence identified without disruptive payloads.",
                )
            )
        elif cat == TestCategory.BINARY_EXPLOITATION:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-BIN-SEC-{plan.id or 1}",
                    name="Binary Mitigation & ELF Header Inspection",
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    options={"action": "inspect_binary_protections"},
                    timeout_seconds=20.0,
                    expected_result="PIE and architecture protections indexed.",
                )
            )
        else:
            items.append(
                AssessmentTestItem(
                    test_id=f"TEST-GEN-{plan.id or 1}",
                    name=plan.title,
                    category=cat,
                    target=target,
                    adapter_name="verification_engine",
                    timeout_seconds=30.0,
                )
            )

        return items

    def execute_assessment(
        self,
        plan: AssessmentPlan,
        project: Project,
        custom_tests: Optional[List[AssessmentTestItem]] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_log: Optional[LogCallback] = None,
    ) -> AssessmentRunResult:
        """Executes an assessment plan under strict concurrency and preflight controls."""
        assessment_id = f"ASM-{plan.id or 0}-{int(time.time())}"
        exec_uuid = f"EXEC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # 1. Prevent Duplicate Concurrent Executions
        with self._run_lock:
            if plan.id and any(r.plan_id == plan.id for r in self._active_runs.values()):
                raise RuntimeError(
                    f"Assessment plan #{plan.id} ('{plan.title}') is already actively running. Duplicate run rejected."
                )

        def log(msg: str):
            if on_log:
                on_log(f"[{datetime.now().strftime('%H:%M:%S')}] [{exec_uuid}] {msg}")

        start_iso = _utc_now_iso()
        run_record = AssessmentRunResult(
            assessment_id=assessment_id,
            execution_uuid=exec_uuid,
            project_id=project.id,
            plan_id=plan.id,
            status=TestExecutionState.RUNNING,
            started_at=start_iso,
        )

        with self._run_lock:
            self._active_runs[assessment_id] = run_record
            self._cancel_requested[assessment_id] = False

        log(f"Initializing assessment run '{plan.title}' on target '{plan.target}'")

        try:
            # 2. Preflight Safety Validation (Fail-Closed)
            preflight_res = self.preflight.run_preflight(
                target=plan.target,
                project=project,
                test_category=plan.test_category,
            )
            if not preflight_res.is_ready or preflight_res.blockers:
                block_msg = "\n".join(preflight_res.blockers)
                log(f"⛔ PREFLIGHT BLOCKED: {block_msg}")
                run_record.status = TestExecutionState.BLOCKED
                run_record.error = block_msg
                run_record.finished_at = _utc_now_iso()
                if plan.id:
                    plan.status = AssessmentStatus.BLOCKED
                    plan.preflight_blockers = block_msg
                    self.db.update_assessment_plan(plan)
                return run_record

            # Update Plan Status to In-Progress
            if plan.id:
                plan.status = AssessmentStatus.IN_PROGRESS
                plan.preflight_blockers = ""
                self.db.update_assessment_plan(plan)

            tests_to_run = custom_tests or self.build_test_plan_items(plan)
            run_record.total_tests = len(tests_to_run)

            # 3. Order and Execute Tests
            completed_test_ids: Dict[str, TestExecutionState] = {}

            for idx, test_item in enumerate(tests_to_run):
                if self._cancel_requested.get(assessment_id, False):
                    log(f"⏹️ Assessment cancellation requested. Terminating sequence.")
                    step = TestStepResult(
                        test_id=test_item.test_id,
                        name=test_item.name,
                        category=test_item.category,
                        target=test_item.target,
                        state=TestExecutionState.CANCELLED,
                        blocker_reason="Assessment cancelled by operator",
                    )
                    run_record.steps.append(step)
                    run_record.cancelled_tests += 1
                    continue

                # Check Prerequisites
                unmet_prereqs = [
                    p for p in test_item.prerequisites
                    if completed_test_ids.get(p) not in (TestExecutionState.PASSED, TestExecutionState.NEEDS_REVIEW)
                ]
                if unmet_prereqs:
                    log(f"⚠️ Test '{test_item.name}' BLOCKED: Unmet prerequisites: {unmet_prereqs}")
                    step = TestStepResult(
                        test_id=test_item.test_id,
                        name=test_item.name,
                        category=test_item.category,
                        target=test_item.target,
                        state=TestExecutionState.BLOCKED,
                        blocker_reason=f"Prerequisite tests not passed: {', '.join(unmet_prereqs)}",
                    )
                    run_record.steps.append(step)
                    run_record.blocked_tests += 1
                    completed_test_ids[test_item.test_id] = TestExecutionState.BLOCKED
                    continue

                pct = int(((idx) / len(tests_to_run)) * 100)
                if on_progress:
                    on_progress(test_item.test_id, pct, f"Running: {test_item.name}")

                log(f"▶️ Executing [{idx+1}/{len(tests_to_run)}]: {test_item.name} ({test_item.adapter_name})")
                step_res = self._execute_test_step(
                    assessment_id=assessment_id,
                    project=project,
                    plan=plan,
                    test_item=test_item,
                    log=log,
                )
                run_record.steps.append(step_res)
                completed_test_ids[test_item.test_id] = step_res.state

                if step_res.state == TestExecutionState.PASSED:
                    run_record.passed_tests += 1
                elif step_res.state == TestExecutionState.FAILED:
                    run_record.failed_tests += 1
                elif step_res.state == TestExecutionState.BLOCKED:
                    run_record.blocked_tests += 1
                elif step_res.state == TestExecutionState.ERROR:
                    run_record.error_tests += 1
                elif step_res.state == TestExecutionState.CANCELLED:
                    run_record.cancelled_tests += 1

                run_record.findings.extend(step_res.findings)

            # Determine Aggregate Run Outcome
            run_record.finished_at = _utc_now_iso()
            t_start = datetime.fromisoformat(run_record.started_at).timestamp()
            t_end = datetime.fromisoformat(run_record.finished_at).timestamp()
            run_record.duration_seconds = round(t_end - t_start, 2)

            if run_record.cancelled_tests > 0:
                run_record.status = TestExecutionState.CANCELLED
            elif run_record.error_tests > 0:
                run_record.status = TestExecutionState.ERROR
            elif run_record.failed_tests > 0:
                run_record.status = TestExecutionState.FAILED
            elif run_record.blocked_tests > 0:
                run_record.status = TestExecutionState.BLOCKED
            else:
                run_record.status = TestExecutionState.PASSED

            if plan.id:
                if run_record.status == TestExecutionState.PASSED:
                    plan.status = AssessmentStatus.COMPLETED
                elif run_record.status == TestExecutionState.CANCELLED:
                    plan.status = AssessmentStatus.CANCELLED
                elif run_record.status == TestExecutionState.BLOCKED:
                    plan.status = AssessmentStatus.BLOCKED
                else:
                    plan.status = AssessmentStatus.FAILED
                self.db.update_assessment_plan(plan)

            if on_progress:
                on_progress("ALL", 100, f"Assessment completed: {run_record.status.value.upper()}")

            log(f"Assessment complete. Status: {run_record.status.value.upper()}. Findings: {len(run_record.findings)}")
            return run_record

        finally:
            with self._run_lock:
                self._active_runs.pop(assessment_id, None)
                self._active_runners.pop(assessment_id, None)
                self._cancel_requested.pop(assessment_id, None)

    def _execute_test_step(
        self,
        assessment_id: str,
        project: Project,
        plan: AssessmentPlan,
        test_item: AssessmentTestItem,
        log: LogCallback,
    ) -> TestStepResult:
        """Executes a single test item using the designated adapter."""
        t0 = time.perf_counter()
        started_iso = _utc_now_iso()

        # Fail-closed scope re-check immediately before execution
        scopes = self.db.list_scopes(project.id)
        scope_res = ScopeAuthorizationService.is_target_authorized(
            test_item.target, scopes, project=project
        )
        if not scope_res.is_allowed:
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=test_item.target,
                state=TestExecutionState.BLOCKED,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                blocker_reason=f"Scope violation: {scope_res.reason}",
            )

        adapter_name = test_item.adapter_name.lower().strip()

        try:
            # 1. Deterministic Verification Engine Adapters
            if adapter_name == "verification_engine":
                return self._run_verification_engine_step(
                    test_item=test_item,
                    started_iso=started_iso,
                    t0=t0,
                )

            # 2. Nmap Adapter
            elif adapter_name == "nmap":
                nmap = NmapAdapter(self.db, self.registry)
                profile = ScanProfile(test_item.options.get("profile", ScanProfile.TOP_PORTS.value))
                ports = test_item.options.get("ports")
                opts = NmapScanOptions(
                    target=test_item.target,
                    profile=profile,
                    ports=ports,
                    timeout=test_item.timeout_seconds,
                )
                res = nmap.execute_scan(project=project, options=opts, scopes=scopes)
                duration = round(time.perf_counter() - t0, 2)
                state = TestExecutionState.PASSED if res.is_authorized and res.execution and res.execution.exit_code == 0 else TestExecutionState.FAILED
                return TestStepResult(
                    test_id=test_item.test_id,
                    name=test_item.name,
                    category=test_item.category,
                    target=test_item.target,
                    state=state,
                    started_at=started_iso,
                    finished_at=_utc_now_iso(),
                    duration_seconds=duration,
                    exit_code=res.execution.exit_code if res.execution else -1,
                    execution_id=res.execution.id if res.execution else None,
                    findings=res.findings,
                )

            # 3. c0desec Web Adapter
            elif adapter_name == "c0desec":
                c0desec = WebSecurityAdapter(self.db)
                wopts = WebScanOptions(
                    target_url=test_item.target,
                    check_headers=test_item.options.get("check_headers", True),
                    check_cors=test_item.options.get("check_cors", True),
                    check_js_secrets=test_item.options.get("check_js_secrets", True),
                    timeout=test_item.timeout_seconds,
                )
                success, msg, scan_res, execution = c0desec.execute_scan(
                    project_id=project.id,
                    options=wopts,
                    scopes=scopes,
                )
                duration = round(time.perf_counter() - t0, 2)
                findings = scan_res.findings if scan_res else []
                state = TestExecutionState.PASSED if success else TestExecutionState.FAILED
                return TestStepResult(
                    test_id=test_item.test_id,
                    name=test_item.name,
                    category=test_item.category,
                    target=test_item.target,
                    state=state,
                    started_at=started_iso,
                    finished_at=_utc_now_iso(),
                    duration_seconds=duration,
                    exit_code=execution.exit_code if execution else 0,
                    execution_id=execution.id if execution else None,
                    findings=findings,
                )

            # 4. WAFW00F Adapter
            elif adapter_name == "wafw00f":
                waf = WAFW00FAdapter(self.db)
                w_opts = WAFW00FOptions(target_url=test_item.target, timeout=test_item.timeout_seconds)
                success, msg, findings, exec_rec, w_res = waf.execute_scan(
                    project=project, options=w_opts, scopes=scopes
                )
                duration = round(time.perf_counter() - t0, 2)
                state = TestExecutionState.PASSED if success else TestExecutionState.FAILED
                return TestStepResult(
                    test_id=test_item.test_id,
                    name=test_item.name,
                    category=test_item.category,
                    target=test_item.target,
                    state=state,
                    started_at=started_iso,
                    finished_at=_utc_now_iso(),
                    duration_seconds=duration,
                    exit_code=exec_rec.exit_code if exec_rec else 0,
                    execution_id=exec_rec.id if exec_rec else None,
                    findings=findings,
                )

            # Fallback for Unknown Adapter
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=test_item.target,
                state=TestExecutionState.ERROR,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                error_message=f"Unsupported execution adapter: '{test_item.adapter_name}'",
            )

        except Exception as e:
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=test_item.target,
                state=TestExecutionState.ERROR,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                error_message=str(e),
            )

    def _run_verification_engine_step(
        self,
        test_item: AssessmentTestItem,
        started_iso: str,
        t0: float,
    ) -> TestStepResult:
        """Executes pure Python deterministic verification actions."""
        action = test_item.options.get("action", "")
        target = test_item.target

        if action == "audit_domain_connectivity":
            res = ActiveDirectoryVerificationService.audit_domain_connectivity(target)
            is_dc = res.get("is_active_directory_reachable", False)
            state = TestExecutionState.PASSED if is_dc else TestExecutionState.NEEDS_REVIEW
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=target,
                state=state,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                stdout=f"AD Reachable Services: {res.get('reachable_services')}/{res.get('total_checked')}",
            )

        elif action == "evaluate_smb_and_kerberos_hardening":
            # Deterministic check
            res = ActiveDirectoryVerificationService.evaluate_smb_and_kerberos_hardening(
                smb_signing_required=test_item.options.get("smb_signing_required", False),
                smb_signing_enabled=test_item.options.get("smb_signing_enabled", True),
                kerberos_preauth_disabled_accounts=test_item.options.get("roastable_users", []),
            )
            findings_data = res.get("security_findings", [])
            state = TestExecutionState.PASSED if res.get("is_smb_relay_safe") else TestExecutionState.FAILED
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=target,
                state=state,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                stdout=f"SMB Relay Safe: {res.get('is_smb_relay_safe')}. Findings: {len(findings_data)}",
            )

        elif action == "audit_local_file_permissions":
            custom_files = test_item.options.get("target_files")
            results = PrivilegeEscalationVerificationService.audit_local_file_permissions(custom_files)
            misconfigured = any(r.get("is_misconfigured") for r in results)
            state = TestExecutionState.FAILED if misconfigured else TestExecutionState.PASSED
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=target,
                state=state,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                stdout=f"Audited {len(results)} system files. Misconfigurations: {misconfigured}",
            )

        elif action == "inspect_suid_binaries":
            binaries = PrivilegeEscalationVerificationService.inspect_suid_binaries()
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=target,
                state=TestExecutionState.PASSED,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                stdout=f"Indexed {len(binaries)} local SUID binaries.",
            )

        elif action == "inspect_binary_protections":
            prot = WebBinaryVerificationService.inspect_binary_protections(target)
            state = TestExecutionState.PASSED if prot.get("is_elf") else TestExecutionState.FAILED
            return TestStepResult(
                test_id=test_item.test_id,
                name=test_item.name,
                category=test_item.category,
                target=target,
                state=state,
                started_at=started_iso,
                finished_at=_utc_now_iso(),
                duration_seconds=round(time.perf_counter() - t0, 2),
                stdout=f"ELF: {prot.get('is_elf')}, PIE: {prot.get('is_pie')}, Arch: {prot.get('bit_depth')}-bit",
            )

        return TestStepResult(
            test_id=test_item.test_id,
            name=test_item.name,
            category=test_item.category,
            target=target,
            state=TestExecutionState.ERROR,
            started_at=started_iso,
            finished_at=_utc_now_iso(),
            duration_seconds=round(time.perf_counter() - t0, 2),
            error_message=f"Unknown verification action '{action}'",
        )

