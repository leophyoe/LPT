"""Attack Path Analysis Dialog for PentestX / CyberSecuritySuite.

Connects the 2D network topology and asset inventory with the evidence-grounded
AIDataAnalystEngine to display multi-stage attack chains, prerequisites,
hypothesis steps, validation actions, and supporting citations without simulation or hallucination.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import QDeadlineTimer, QObject, QThread, Qt, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.ai_data_analyst import (
    AIDataAnalystEngine,
    AttackPathChain,
    DataAnalystReport,
    EvidenceCitation,
)
from core.parsers.normalized_models import NormalizedFinding
from core.scope import ScopeAuthorizationService
from desktop.theme import CPENTTheme, get_badge_qss
from storage.db import Database
from storage.models import AssetEdge, AssetNode, Evidence, Finding, Project, TargetScope

logger = logging.getLogger(__name__)


def extract_clean_host(raw: str) -> str:
    """Extracts canonical host or IP address from URLs, host:port, or network strings."""
    if not raw or not isinstance(raw, str):
        return ""
    cleaned = ScopeAuthorizationService._extract_host_or_ip(raw.strip())
    if cleaned:
        return cleaned
    target = raw.strip()
    if "://" in target or target.startswith("//"):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    if ":" in target and not target.endswith("]"):
        parts = target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0]
    return target.strip()


def parse_target_identity(clean_host: str) -> Tuple[bool, Optional[Any], Optional[str]]:
    """Determines whether a cleaned host string is an IP address or a hostname.

    Returns:
        (is_ip, ip_address_obj, hostname_str_lowercase)
    """
    if not clean_host:
        return False, None, None
    try:
        ip = ipaddress.ip_address(clean_host)
        return True, ip, None
    except ValueError:
        return False, None, clean_host.lower().rstrip(".")


def check_target_scope(
    target: str,
    scopes: List[TargetScope],
    project: Optional[Project] = None,
) -> Tuple[str, str]:
    """Evaluates target against project authorization scope boundaries using canonical ScopeAuthorizationService.

    Returns:
        (status_text, badge_token)
    """
    if not scopes:
        return "Scope Unassigned", "WARNING"

    result = ScopeAuthorizationService.is_target_authorized(target, scopes, project=project)
    if result.is_allowed:
        return "Authorized In-Scope Target", "CONFIRMED"

    if "No authorized target scopes defined" in result.reason:
        return "Scope Unassigned", "WARNING"

    return "Out-of-Scope / Quarantine Target", "CRITICAL"


@dataclass
class AttackPathAnalysisResult:
    """Consolidated outcome of background attack path analysis."""

    target_report: DataAnalystReport
    project_report: DataAnalystReport
    verified_direct_chains: List[AttackPathChain]
    verified_pivot_chains: List[Tuple[AttackPathChain, str, str]]
    unverified_pivot_chains: List[Tuple[AttackPathChain, str, str]]
    all_citations: List[EvidenceCitation]
    remediations: List[str]
    inferences: List[str]
    summary_text: str
    posture_text: str
    posture_token: str
    target_findings: List[Finding]
    scope_text: str
    scope_token: str
    evidence_map: Dict[int, Evidence]
    blocked_reason: str = ""
    worker_thread_id: int = 0


@dataclass
class AttackPathAnalysisSnapshot:
    """Immutable database inputs passed from the UI thread to the analysis worker."""

    all_findings: List[Finding]
    target_findings: List[Finding]
    evidence_map: Dict[int, Evidence]
    nodes_by_id: Dict[int, AssetNode]
    target_node_ids: set
    target_ip_obj: Optional[Any]
    target_hostname: Optional[str]
    edges: List[AssetEdge]
    stored_subnets: list
    scopes: List[TargetScope]
    scope_allowed: bool
    scope_reason: str
    scope_text: str
    scope_token: str


class AttackPathAnalysisWorker(QThread):
    """Loads project data and performs attack path analysis off the Qt main thread."""

    analysis_completed = Signal(object, int)  # result: AttackPathAnalysisResult, generation_id: int
    analysis_failed = Signal(str, int)       # error_message: str, generation_id: int

    def __init__(
        self,
        target_ip: str,
        project: Project,
        db: Database,
        generation_id: int = 0,
        snapshot: Optional[AttackPathAnalysisSnapshot] = None,
    ):
        super().__init__()
        self.target_ip = target_ip
        self.project = project
        self.db = db
        self.generation_id = generation_id
        self.snapshot = snapshot
        self._cancel_event = threading.Event()
        self.worker_thread_id = 0

    def cancel(self):
        """Sets cooperative cancellation flag."""
        self._cancel_event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def run(self):
        """Loads database inputs and executes analysis without touching Qt widgets."""
        self.worker_thread_id = threading.get_ident()
        if self.is_cancelled:
            return

        try:
            snapshot = self.snapshot or AttackPathAnalysisDialog._collect_analysis_snapshot(
                self.db, self.project, self.target_ip
            )
            if self.is_cancelled:
                return

            if not snapshot.scope_allowed:
                report = DataAnalystReport(
                    project_id=self.project.id,
                    executive_summary=snapshot.scope_reason,
                    overall_posture="QUARANTINE / BLOCKED",
                    finding_counts={},
                    attack_paths=[],
                    prioritized_remediations=[],
                    citations=[],
                    unvalidated_inferences=[],
                )
                result = AttackPathAnalysisResult(
                    target_report=report,
                    project_report=report,
                    verified_direct_chains=[],
                    verified_pivot_chains=[],
                    unverified_pivot_chains=[],
                    all_citations=[],
                    remediations=[],
                    inferences=[],
                    summary_text=(
                        "<b>Scope Authorization Blocked:</b> "
                        f"{html_escape(snapshot.scope_reason)}"
                    ),
                    posture_text="Posture: Blocked (Scope Violation)",
                    posture_token="CRITICAL",
                    target_findings=[],
                    scope_text=snapshot.scope_text,
                    scope_token=snapshot.scope_token,
                    evidence_map={},
                    blocked_reason=snapshot.scope_reason,
                    worker_thread_id=self.worker_thread_id,
                )
                self.analysis_completed.emit(result, self.generation_id)
                return

            # Normalize only with project- and finding-linked evidence records.
            target_norm = [
                NormalizedFinding.from_finding(f, evidence=snapshot.evidence_map.get(f.id))
                for f in snapshot.target_findings
            ]
            all_norm = [
                NormalizedFinding.from_finding(f, evidence=snapshot.evidence_map.get(f.id))
                for f in snapshot.all_findings
            ]

            if self.is_cancelled:
                return

            # The analyst receives an in-memory list and has no database connection.
            analyst = AIDataAnalystEngine()
            target_report = analyst.analyze_project(project_id=self.project.id, findings=target_norm)
            project_report = analyst.analyze_project(project_id=self.project.id, findings=all_norm)

            if self.is_cancelled:
                return

            # Preserve the existing direct-target and verified-relationship rules.
            verified_direct_chains = target_report.attack_paths
            verified_pivot_chains = []
            unverified_pivot_chains = []

            for chain in project_report.attack_paths:
                # Skip if chain is already represented in direct target findings
                if any(c.chain_name == chain.chain_name for c in verified_direct_chains):
                    continue

                rel_state, rel_detail = AttackPathAnalysisDialog._verify_path_relationship_static(
                    chain=chain,
                    target_node_ids=snapshot.target_node_ids,
                    target_ip_obj=snapshot.target_ip_obj,
                    target_hostname=snapshot.target_hostname,
                    nodes_by_id=snapshot.nodes_by_id,
                    edges=snapshot.edges,
                    stored_subnets=snapshot.stored_subnets,
                    project_id=self.project.id,
                )

                if rel_state == "Verified Relationship":
                    verified_pivot_chains.append((chain, rel_state, rel_detail))
                elif rel_state == "Unverified Relationship":
                    unverified_pivot_chains.append((chain, rel_state, rel_detail))
                else:
                    # "No Relationship Evidence": strictly rejected
                    pass

            if self.is_cancelled:
                return

            # 4. Formulate Summary and Posture
            if verified_direct_chains or verified_pivot_chains or unverified_pivot_chains:
                summary_parts = []
                if verified_direct_chains:
                    summary_parts.append(
                        f"<b>{len(verified_direct_chains)} direct attack path(s)</b> directly affecting target <b>{self.target_ip}</b>"
                    )
                if verified_pivot_chains:
                    summary_parts.append(
                        f"<b>{len(verified_pivot_chains)} verified lateral movement path(s)</b> supported by verified topology relationships"
                    )
                if unverified_pivot_chains:
                    summary_parts.append(
                        f"<b>{len(unverified_pivot_chains)} unverified pivot hypothesis(es)</b>"
                    )

                summary_text = (
                    "Identified " + " and ".join(summary_parts) + ". "
                    "Review the hypothesis chains, validation actions, and supporting evidence citations below."
                )
            else:
                summary_text = (
                    f"Security analysis completed for target <b>{self.target_ip}</b>. "
                    "No multi-stage attack chains identified on this asset, and no verified topology relationships "
                    "(AssetEdge or recorded shared subnet) connect other project attack vectors to this target."
                )

            posture_text = f"Posture: {target_report.overall_posture}"
            posture_token = target_report.overall_posture.split()[0] if target_report.overall_posture else "LOW"

            all_citations = target_report.citations + project_report.citations
            remediations = target_report.prioritized_remediations or project_report.prioritized_remediations
            inferences = target_report.unvalidated_inferences or project_report.unvalidated_inferences

            res = AttackPathAnalysisResult(
                target_report=target_report,
                project_report=project_report,
                verified_direct_chains=verified_direct_chains,
                verified_pivot_chains=verified_pivot_chains,
                unverified_pivot_chains=unverified_pivot_chains,
                all_citations=all_citations,
                remediations=remediations,
                inferences=inferences,
                summary_text=summary_text,
                posture_text=posture_text,
                posture_token=posture_token,
                target_findings=snapshot.target_findings,
                scope_text=snapshot.scope_text,
                scope_token=snapshot.scope_token,
                evidence_map=snapshot.evidence_map,
                worker_thread_id=self.worker_thread_id,
            )

            if not self.is_cancelled:
                self.analysis_completed.emit(res, self.generation_id)

        except Exception as exc:
            logger.exception("AttackPathAnalysisWorker execution failed: %s", exc)
            if not self.is_cancelled:
                self.analysis_failed.emit(
                    "Analysis could not be completed. Check the application log for details.",
                    self.generation_id,
                )


class AttackPathAnalysisDialog(QDialog):
    """Deep-dive multi-stage attack path analysis dialog."""

    def __init__(
        self,
        target_ip: str,
        project: Optional[Project] = None,
        db: Optional[Database] = None,
        parent: Optional[QWidget] = None,
        sync: Optional[bool] = None,
    ):
        super().__init__(parent)
        self.target_ip = target_ip.strip()
        self.project = project
        self.db = db
        # Automatically default to sync=True when running inside pytest test runners
        self.sync = bool(os.environ.get("PYTEST_CURRENT_TEST")) if sync is None else sync

        self.report: Optional[DataAnalystReport] = None
        self.target_findings: List[Finding] = []
        self.finding_evidence: Dict[int, Optional[Evidence]] = {}
        self.evidence_records: List[Evidence] = []

        self._is_analyzing: bool = False
        self._current_generation_id: int = 0
        self._is_closed: bool = False
        self._is_destroyed: bool = False
        self._worker: Optional[AttackPathAnalysisWorker] = None

        self.setWindowTitle(f"Attack Path Analysis — {self.target_ip}")
        self.setObjectName("attackPathAnalysisDialog")
        self.resize(860, 720)
        self._build_ui()
        self.run_analysis(sync=self.sync)

    @property
    def is_analyzing(self) -> bool:
        """Returns True if a background worker analysis is currently executing."""
        return self._is_analyzing

    def wait_for_completion(self, timeout_ms: int = 5000) -> bool:
        """Waits for active background worker to finish processing, pumping Qt events."""
        if not self._worker or not self._worker.isRunning():
            return True
        deadline = QDeadlineTimer(timeout_ms)
        while self._worker.isRunning() and not deadline.hasExpired():
            QApplication.processEvents()
            QThread.msleep(5)
        QApplication.processEvents()
        return not self._worker.isRunning() and not self._is_analyzing

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        # 1. Header Card (PentestX Brand + Scope & Posture Badges)
        self.header_card = QFrame()
        self.header_card.setObjectName("dashboardPanel")
        self.header_card.setStyleSheet(
            f"QFrame#dashboardPanel {{ background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 8px; padding: 12px 16px; }"
        )
        hdr_layout = QVBoxLayout(self.header_card)
        hdr_layout.setContentsMargins(0, 0, 0, 0)
        hdr_layout.setSpacing(8)

        top_row = QHBoxLayout()
        lbl_brand = QLabel("🛡️ PENTESTX | Multi-Stage Attack Path Intelligence")
        lbl_brand.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_brand.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE};")
        top_row.addWidget(lbl_brand)
        top_row.addStretch()

        self.lbl_scope_badge = QLabel("Scope: Checking...")
        self.lbl_scope_badge.setStyleSheet(get_badge_qss("INFO_CYAN"))
        top_row.addWidget(self.lbl_scope_badge)

        self.lbl_posture_badge = QLabel("Posture: Evaluating...")
        self.lbl_posture_badge.setStyleSheet(get_badge_qss("LOW"))
        top_row.addWidget(self.lbl_posture_badge)
        hdr_layout.addLayout(top_row)

        # Meta Context Line
        self.lbl_meta = QLabel(
            f"Target Asset: <b>{self.target_ip}</b> | "
            f"Project: <b>{getattr(self.project, 'name', 'None')} (#{getattr(self.project, 'id', 'N/A')})</b> | "
            "Engine: <b>AIDataAnalystEngine (Empirical Correlation)</b>"
        )
        self.lbl_meta.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        hdr_layout.addWidget(self.lbl_meta)

        self.lbl_findings_tally = QLabel("Findings on Target: Querying database...")
        self.lbl_findings_tally.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-size: 11px; font-weight: bold;")
        hdr_layout.addWidget(self.lbl_findings_tally)

        root.addWidget(self.header_card)

        # 2. Executive Summary Callout
        self.summary_box = QFrame()
        self.summary_box.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 6px; padding: 10px 14px;"
        )
        sb_layout = QVBoxLayout(self.summary_box)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(4)

        lbl_sum_hdr = QLabel("ANALYST POSTURE ASSESSMENT")
        lbl_sum_hdr.setFont(QFont("Segoe UI", 8, QFont.Bold))
        lbl_sum_hdr.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; letter-spacing: 1px;")
        sb_layout.addWidget(lbl_sum_hdr)

        self.lbl_summary = QLabel("Initializing attack path analysis...")
        self.lbl_summary.setWordWrap(True)
        self.lbl_summary.setStyleSheet(f"color: {CPENTTheme.PRIMARY_TEXT}; font-size: 12px; line-height: 1.4;")
        sb_layout.addWidget(self.lbl_summary)
        root.addWidget(self.summary_box)

        # 3. Scrollable Attack Path Chains Container
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: transparent;")
        self.chains_layout = QVBoxLayout(self.scroll_content)
        self.chains_layout.setContentsMargins(0, 0, 0, 0)
        self.chains_layout.setSpacing(12)

        scroll.setWidget(self.scroll_content)
        root.addWidget(scroll, stretch=1)

        # 4. Bottom Button Bar
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(10)

        self.btn_refresh = QPushButton("↻ Re-Analyze")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        self.btn_refresh.setStyleSheet(
            f"QPushButton {{ background-color: {CPENTTheme.ELEVATED_PANEL}; color: {CPENTTheme.PRIMARY_BLUE}; "
            f"border: 1px solid {CPENTTheme.BORDER}; border-radius: 4px; padding: 6px 14px; font-weight: bold; font-size: 11px; }}"
            f"QPushButton:hover {{ background-color: {CPENTTheme.BORDER}; color: #ffffff; }}"
        )
        self.btn_refresh.clicked.connect(self.run_analysis)
        btn_bar.addWidget(self.btn_refresh)

        btn_bar.addStretch()

        self.btn_close = QPushButton("Close")
        self.btn_close.setCursor(Qt.PointingHandCursor)
        self.btn_close.setStyleSheet(
            "QPushButton { background-color: #2563eb; color: #ffffff; border: none; "
            "border-radius: 4px; padding: 6px 18px; font-weight: bold; font-size: 11px; }"
            "QPushButton:hover { background-color: #1d4ed8; }"
        )
        self.btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(self.btn_close)
        root.addLayout(btn_bar)

    @classmethod
    def _resolve_evidence_for_finding(
        cls,
        finding: Finding,
        db: Any,
        project_id: int,
    ) -> Optional[Evidence]:
        """Retrieves evidence linked to this finding and rejects cross-project records."""
        if (
            not db
            or not finding
            or getattr(finding, "project_id", None) != project_id
        ):
            return None

        evidence: Optional[Evidence] = None
        requested_ev_id = getattr(finding, "evidence_id", None)
        if requested_ev_id and hasattr(db, "get_evidence"):
            evidence = db.get_evidence(requested_ev_id, project_id=project_id)
        if not evidence and getattr(finding, "id", None) and hasattr(db, "get_evidence_for_finding"):
            evidence = db.get_evidence_for_finding(finding.id, project_id=project_id)

        if not evidence or getattr(evidence, "project_id", None) != project_id:
            return None

        finding_id = getattr(finding, "id", None)
        evidence_finding_id = getattr(evidence, "finding_id", None)
        evidence_execution_id = getattr(evidence, "execution_id", None)
        finding_execution_id = getattr(finding, "execution_id", None)
        direct_link = (
            (
                finding_id is not None
                and evidence_finding_id == finding_id
            )
            or requested_ev_id == getattr(evidence, "id", None)
        )
        execution_link = (
            finding_execution_id is not None
            and evidence_execution_id == finding_execution_id
        )
        if (
            not isinstance(getattr(evidence, "id", None), int)
            or evidence.id <= 0
            or (evidence_finding_id is not None and evidence_finding_id != finding_id)
            or (
                evidence_execution_id is not None
                and finding_execution_id is not None
                and evidence_execution_id != finding_execution_id
            )
            or not (direct_link or execution_link)
        ):
            return None

        return evidence

    @classmethod
    def _collect_analysis_snapshot(
        cls,
        db: Any,
        project: Project,
        target_ip: str,
    ) -> AttackPathAnalysisSnapshot:
        """Reads project data and returns a detached snapshot for the analysis worker."""
        project_id = project.id
        scopes = db.list_scopes(project_id) if hasattr(db, "list_scopes") else []
        scopes = [s for s in scopes if getattr(s, "project_id", None) == project_id]
        scope_res = ScopeAuthorizationService.is_target_authorized(
            target_ip, scopes, project=project
        )
        if scope_res.is_allowed:
            scope_text, scope_token = "Authorized In-Scope Target", "CONFIRMED"
        elif not scopes or "No authorized target scopes defined" in scope_res.reason:
            scope_text, scope_token = "Scope Unassigned", "WARNING"
        else:
            scope_text, scope_token = "Out-of-Scope / Quarantine Target", "CRITICAL"

        t_clean = extract_clean_host(target_ip)
        _, target_ip_obj, target_hostname = parse_target_identity(t_clean)

        if not scope_res.is_allowed:
            return AttackPathAnalysisSnapshot(
                all_findings=[],
                target_findings=[],
                evidence_map={},
                nodes_by_id={},
                target_node_ids=set(),
                target_ip_obj=target_ip_obj,
                target_hostname=target_hostname,
                edges=[],
                stored_subnets=[],
                scopes=scopes,
                scope_allowed=False,
                scope_reason=scope_res.reason,
                scope_text=scope_text,
                scope_token=scope_token,
            )

        all_findings = (
            db.list_findings(project_id) if hasattr(db, "list_findings") else []
        )
        all_findings = [
            f for f in all_findings
            if getattr(f, "project_id", None) == project_id
        ]
        nodes = db.list_asset_nodes(project_id) if hasattr(db, "list_asset_nodes") else []
        nodes = [n for n in nodes if getattr(n, "project_id", None) == project_id]

        known_ips = {target_ip_obj} if target_ip_obj else set()
        known_hostnames = {target_hostname} if target_hostname else set()
        for node in nodes:
            node_ips = set()
            node_hostnames = set()
            for raw_identity in (getattr(node, "value", ""), getattr(node, "label", "")):
                _, node_ip, node_host = parse_target_identity(
                    extract_clean_host(raw_identity)
                )
                if node_ip:
                    node_ips.add(node_ip)
                if node_host:
                    node_hostnames.add(node_host)
            if (
                (target_ip_obj is not None and target_ip_obj in node_ips)
                or (target_hostname is not None and target_hostname in node_hostnames)
            ):
                known_ips.update(node_ips)
                known_hostnames.update(node_hostnames)

        target_findings = []
        for finding in all_findings:
            raw_asset = (
                getattr(finding, "affected_asset", None)
                or getattr(finding, "affected_target", None)
                or ""
            ).strip()
            if not raw_asset:
                continue
            _, finding_ip, finding_host = parse_target_identity(
                extract_clean_host(raw_asset)
            )
            if (finding_ip and finding_ip in known_ips) or (
                finding_host and finding_host in known_hostnames
            ):
                target_findings.append(finding)

        evidence_map: Dict[int, Evidence] = {}
        for finding in all_findings:
            finding_id = getattr(finding, "id", None)
            if finding_id is None:
                continue
            evidence = cls._resolve_evidence_for_finding(finding, db, project_id)
            if evidence is not None:
                evidence_map[finding_id] = evidence

        nodes_by_id = {n.id: n for n in nodes if getattr(n, "id", None) is not None}
        target_node_ids = set()
        for node_id, node in nodes_by_id.items():
            identities = [
                parse_target_identity(extract_clean_host(getattr(node, attr, "")))
                for attr in ("value", "label")
            ]
            if any(
                (target_ip_obj is not None and node_ip == target_ip_obj)
                or (target_hostname is not None and node_host == target_hostname)
                for _, node_ip, node_host in identities
            ):
                target_node_ids.add(node_id)

        edges = db.list_asset_edges(project_id) if hasattr(db, "list_asset_edges") else []
        edges = [e for e in edges if getattr(e, "project_id", None) == project_id]
        stored_subnets = []
        for node in nodes:
            if getattr(node, "node_type", "").lower() == "netblock":
                value = getattr(node, "value", "").strip()
                try:
                    stored_subnets.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass
        for scope in scopes:
            value = getattr(scope, "target", "").strip()
            if "/" in value:
                try:
                    stored_subnets.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass

        return AttackPathAnalysisSnapshot(
            all_findings=all_findings,
            target_findings=target_findings,
            evidence_map=evidence_map,
            nodes_by_id=nodes_by_id,
            target_node_ids=target_node_ids,
            target_ip_obj=target_ip_obj,
            target_hostname=target_hostname,
            edges=edges,
            stored_subnets=stored_subnets,
            scopes=scopes,
            scope_allowed=True,
            scope_reason="",
            scope_text=scope_text,
            scope_token=scope_token,
        )

    def run_analysis(self, sync: Optional[bool] = None):
        """Starts scope validation, data retrieval, and analysis in a worker thread."""
        should_sync = self.sync if sync is None else sync

        # Duplicate Request Guard: Ignore if analysis is currently active
        if self._is_analyzing:
            logger.debug("Attack path analysis already in progress; duplicate request ignored.")
            return

        self._is_analyzing = True
        self.btn_refresh.setEnabled(False)
        self._current_generation_id += 1
        current_gen = self._current_generation_id

        self._clear_layout(self.chains_layout)

        if not self.db or not self.project or not getattr(self.project, "id", None):
            self.lbl_summary.setText(
                "No active engagement project selected. Select or create an assessment project in Scope & Projects "
                "to execute attack path correlation."
            )
            self.lbl_scope_badge.setText("Scope: N/A")
            self.lbl_scope_badge.setStyleSheet(get_badge_qss("WARNING"))
            self.lbl_posture_badge.setText("Posture: N/A")
            self.lbl_posture_badge.setStyleSheet(get_badge_qss("LOW"))
            self._render_empty_state("No Active Project Context")
            self._is_analyzing = False
            self.btn_refresh.setEnabled(True)
            return

        try:
            snapshot = None
            if getattr(self.db, "db_path", None) == ":memory:":
                # SQLite in-memory connections are thread-affine; detach their rows
                # on the owning thread before handing the snapshot to the worker.
                snapshot = self._collect_analysis_snapshot(
                    self.db, self.project, self.target_ip
                )
            self.lbl_summary.setText("Loading project evidence and analyzing attack paths in background...")

            self._worker = AttackPathAnalysisWorker(
                target_ip=self.target_ip,
                project=self.project,
                db=self.db,
                generation_id=current_gen,
                snapshot=snapshot,
            )
            self._worker.analysis_completed.connect(self._on_analysis_completed)
            self._worker.analysis_failed.connect(self._on_analysis_failed)
            self._worker.start()

            if should_sync:
                self.wait_for_completion()

        except Exception as exc:
            logger.exception(
                "Attack path analysis initialization failed for target %s: %s",
                self.target_ip,
                exc,
            )
            self._is_analyzing = False
            self.btn_refresh.setEnabled(True)
            self.lbl_summary.setText(
                "<font color='#ef4444'>Analysis Error: "
                "Analysis could not be completed. Check the application log for details.</font>"
            )
            self._render_error_card(
                "Analysis could not be completed. Check the application log for details."
            )

    @Slot(object, int)
    def _on_analysis_completed(self, result: AttackPathAnalysisResult, generation_id: int):
        """Main-thread slot receiving background analysis results."""
        if self._is_closed or self._is_destroyed:
            return

        if generation_id != self._current_generation_id:
            logger.debug(
                "Discarding stale analysis result from generation #%d (current: #%d)",
                generation_id,
                self._current_generation_id,
            )
            return

        if self._worker and self._worker.isRunning():
            self._worker.wait()
        self._is_analyzing = False
        self.btn_refresh.setEnabled(True)
        self.report = result.target_report
        self.target_findings = result.target_findings
        self.finding_evidence = result.evidence_map
        self.evidence_records = list(result.evidence_map.values())
        self.lbl_scope_badge.setText(f"Scope: {result.scope_text}")
        self.lbl_scope_badge.setStyleSheet(get_badge_qss(result.scope_token))
        if result.blocked_reason:
            self.lbl_posture_badge.setText(result.posture_text)
            self.lbl_posture_badge.setStyleSheet(get_badge_qss(result.posture_token))
            self.lbl_findings_tally.setText("Findings on Target: 0 (Blocked)")
            self.lbl_summary.setText(result.summary_text)
            self._clear_layout(self.chains_layout)
            self._render_quarantine_card(result.blocked_reason, result.scope_text)
            return

        crit_count = sum(
            1 for f in result.target_findings
            if getattr(f.severity, "value", str(f.severity)).lower() == "critical"
        )
        high_count = sum(
            1 for f in result.target_findings
            if getattr(f.severity, "value", str(f.severity)).lower() == "high"
        )
        med_count = sum(
            1 for f in result.target_findings
            if getattr(f.severity, "value", str(f.severity)).lower() == "medium"
        )
        low_count = sum(
            1 for f in result.target_findings
            if getattr(f.severity, "value", str(f.severity)).lower() == "low"
        )
        self.lbl_findings_tally.setText(
            f"Findings on Target: {len(result.target_findings)} "
            f"({crit_count} Critical · {high_count} High · {med_count} Medium · {low_count} Low)"
        )
        self.lbl_posture_badge.setText(result.posture_text)
        self.lbl_posture_badge.setStyleSheet(get_badge_qss(result.posture_token))
        self.lbl_summary.setText(result.summary_text)
        self._clear_layout(self.chains_layout)

        if result.verified_direct_chains or result.verified_pivot_chains or result.unverified_pivot_chains:
            for chain in result.verified_direct_chains:
                self._render_attack_chain_card(
                    chain,
                    is_direct=True,
                    relationship_state="Verified Relationship",
                    relationship_detail="Direct Target Vulnerability",
                )
            for chain, rel_state, rel_detail in result.verified_pivot_chains:
                self._render_attack_chain_card(
                    chain,
                    is_direct=False,
                    relationship_state=rel_state,
                    relationship_detail=rel_detail,
                )
            for chain, rel_state, rel_detail in result.unverified_pivot_chains:
                self._render_attack_chain_card(
                    chain,
                    is_direct=False,
                    relationship_state=rel_state,
                    relationship_detail=rel_detail,
                )
        else:
            self._render_empty_state("No Verified Attack Paths or Lateral Relationships")

        if result.inferences:
            self._render_inferences_box(result.inferences)
        if result.remediations:
            self._render_remediation_card(result.remediations)

    @Slot(str, int)
    def _on_analysis_failed(self, error_msg: str, generation_id: int):
        """Main-thread slot receiving worker errors."""
        if self._is_closed or self._is_destroyed:
            return

        if generation_id != self._current_generation_id:
            return

        if self._worker and self._worker.isRunning():
            self._worker.wait()
        self._is_analyzing = False
        self.btn_refresh.setEnabled(True)
        self.lbl_summary.setText(f"<font color='#ef4444'>Analysis Error: {html_escape(error_msg)}</font>")
        self._clear_layout(self.chains_layout)
        self._render_error_card(error_msg)

    def closeEvent(self, event):
        """Safely stops background worker upon dialog closure to prevent late UI updates."""
        self._is_closed = True
        self._stop_worker()
        super().closeEvent(event)

    def reject(self):
        """Safely stops background worker on dialog cancellation/rejection."""
        self._is_closed = True
        self._stop_worker()
        super().reject()

    def accept(self):
        """Safely stops background worker on dialog acceptance."""
        self._is_closed = True
        self._stop_worker()
        super().accept()

    def _stop_worker(self):
        """Terminates active worker and disconnects signals safely."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            try:
                self._worker.analysis_completed.disconnect(self._on_analysis_completed)
                self._worker.analysis_failed.disconnect(self._on_analysis_failed)
            except RuntimeError:
                pass
            # Do not destroy a running QThread; its work is pure local analysis and
            # checks cancellation before publishing any result.
            self._worker.wait()

    @staticmethod
    def _verify_path_relationship_static(
        chain: AttackPathChain,
        target_node_ids: set,
        target_ip_obj: Optional[Any],
        target_hostname: Optional[str],
        nodes_by_id: dict,
        edges: list,
        stored_subnets: list,
        project_id: int,
    ) -> Tuple[str, str]:
        """Validates whether a project-wide attack chain has an evidence-backed topology link to the target.

        Returns:
            (relationship_state, detail) where relationship_state is one of:
            - "Verified Relationship"
            - "Unverified Relationship"
            - "No Relationship Evidence"
        """
        # 1. Collect origin asset identifiers from chain citations
        origin_hosts = set()
        for c in chain.supporting_citations:
            aff = (c.affected_asset or "").strip()
            if aff:
                cleaned = extract_clean_host(aff)
                if cleaned:
                    origin_hosts.add(cleaned)

        if not origin_hosts:
            return "No Relationship Evidence", "No affected asset identifiers found in chain evidence citations."

        origin_node_ids = set()
        origin_ip_objs = set()
        origin_hostnames = set()

        for oh in origin_hosts:
            is_ip, ip_o, h_o = parse_target_identity(oh)
            if is_ip and ip_o:
                origin_ip_objs.add(ip_o)
            elif h_o:
                origin_hostnames.add(h_o)

        # Map to nodes_by_id strictly for the active project
        for nid, n in nodes_by_id.items():
            if getattr(n, "project_id", None) != project_id:
                continue
            v_clean = extract_clean_host(getattr(n, "value", ""))
            l_clean = extract_clean_host(getattr(n, "label", ""))
            is_v_ip, v_ip, v_h = parse_target_identity(v_clean)
            is_l_ip, l_ip, l_h = parse_target_identity(l_clean)

            matches_orig = False
            if origin_ip_objs and ((is_v_ip and v_ip in origin_ip_objs) or (is_l_ip and l_ip in origin_ip_objs)):
                matches_orig = True
            if origin_hostnames and ((not is_v_ip and v_h in origin_hostnames) or (not is_l_ip and l_h in origin_hostnames)):
                matches_orig = True

            if matches_orig:
                origin_node_ids.add(nid)
                if is_v_ip and v_ip:
                    origin_ip_objs.add(v_ip)
                elif v_h:
                    origin_hostnames.add(v_h)
                if is_l_ip and l_ip:
                    origin_ip_objs.add(l_ip)
                elif l_h:
                    origin_hostnames.add(l_h)

        # 2. Criterion A: Valid AssetEdge connecting origin and target in active project
        for edge in edges:
            if getattr(edge, "project_id", None) != project_id:
                continue
            s_id = getattr(edge, "source_node_id", None)
            t_id = getattr(edge, "target_node_id", None)
            if s_id not in nodes_by_id or t_id not in nodes_by_id:
                continue

            # Check if this edge directly links any origin node with any target node
            is_connected = (
                (s_id in origin_node_ids and t_id in target_node_ids) or
                (s_id in target_node_ids and t_id in origin_node_ids)
            )
            if is_connected:
                rel_type = getattr(edge, "relation_type", "CONNECTED_TO")
                ver_state = getattr(edge, "verification_state", "observed").lower()
                conf = getattr(edge, "confidence", 1.0)
                if ver_state in ("observed", "manual") and conf >= 0.7:
                    return (
                        "Verified Relationship",
                        f"AssetEdge #{edge.id} ({rel_type}, confidence {conf:.2f}, state={ver_state})",
                    )
                else:
                    return (
                        "Unverified Relationship",
                        f"Inferred AssetEdge #{edge.id} ({rel_type}, confidence {conf:.2f}, state={ver_state})",
                    )

        # 3. Criterion B: Explicitly recorded shared subnet in active project
        if target_ip_obj and origin_ip_objs and stored_subnets:
            for subnet in stored_subnets:
                try:
                    if target_ip_obj in subnet:
                        for o_ip in origin_ip_objs:
                            if o_ip in subnet and o_ip != target_ip_obj:
                                return (
                                    "Verified Relationship",
                                    f"Recorded Shared Subnet {subnet} in Project #{project_id}",
                                )
                except (TypeError, ValueError):
                    pass

        return (
            "No Relationship Evidence",
            "No recorded AssetEdge or shared subnet connects this asset to the origin vulnerability.",
        )

    def _verify_path_relationship(
        self,
        chain: AttackPathChain,
        target_node_ids: set,
        target_ip_obj: Optional[Any],
        target_hostname: Optional[str],
        nodes_by_id: dict,
        edges: list,
        stored_subnets: list,
    ) -> Tuple[str, str]:
        """Instance wrapper for _verify_path_relationship_static."""
        project_id = self.project.id if self.project else 0
        return self._verify_path_relationship_static(
            chain=chain,
            target_node_ids=target_node_ids,
            target_ip_obj=target_ip_obj,
            target_hostname=target_hostname,
            nodes_by_id=nodes_by_id,
            edges=edges,
            stored_subnets=stored_subnets,
            project_id=project_id,
        )

    def _render_attack_chain_card(
        self,
        chain: AttackPathChain,
        is_direct: bool = True,
        relationship_state: str = "Verified Relationship",
        relationship_detail: str = "",
    ):
        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 6px; padding: 12px; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        # Header: Name + Badges
        hdr = QHBoxLayout()
        if is_direct:
            name_pfx = "🎯 Direct Attack Chain"
        elif relationship_state == "Verified Relationship":
            name_pfx = "🔀 Verified Pivot Path"
        else:
            name_pfx = "⚠ Unverified Pivot Hypothesis"

        lbl_name = QLabel(f"{name_pfx}: {chain.chain_name}")
        lbl_name.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_name.setStyleSheet("color: #f8fafc;")
        lbl_name.setWordWrap(True)
        hdr.addWidget(lbl_name)
        hdr.addStretch()

        # Relationship State Badge
        if is_direct:
            lbl_rel = QLabel(" Direct Asset ")
            lbl_rel.setStyleSheet(get_badge_qss("CONFIRMED"))
        elif relationship_state == "Verified Relationship":
            lbl_rel = QLabel(" Verified Relationship ")
            lbl_rel.setStyleSheet(get_badge_qss("CONFIRMED"))
        else:
            lbl_rel = QLabel(" Unverified Relationship ")
            lbl_rel.setStyleSheet(get_badge_qss("WARNING"))
        hdr.addWidget(lbl_rel)

        lbl_like = QLabel(f" Likelihood: {chain.likelihood} ")
        lbl_like.setStyleSheet(get_badge_qss(chain.likelihood))
        hdr.addWidget(lbl_like)

        lbl_imp = QLabel(f" Impact: {chain.impact} ")
        lbl_imp.setStyleSheet(get_badge_qss(chain.impact))
        hdr.addWidget(lbl_imp)
        layout.addLayout(hdr)

        # Relationship Evidence Detail Row
        if relationship_detail:
            lbl_rel_detail = QLabel(f"<b>Relationship Evidence:</b> <code>{html_escape(relationship_detail)}</code>")
            lbl_rel_detail.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
            layout.addWidget(lbl_rel_detail)

        # Prerequisites
        if chain.prerequisites:
            lbl_pre_hdr = QLabel("<b>Prerequisites:</b>")
            lbl_pre_hdr.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-size: 11px;")
            layout.addWidget(lbl_pre_hdr)
            for p in chain.prerequisites:
                lbl_p = QLabel(f"  • {p}")
                lbl_p.setWordWrap(True)
                lbl_p.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
                layout.addWidget(lbl_p)

        # Attack Steps Sequence
        if chain.attack_steps:
            lbl_steps_hdr = QLabel("<b>Hypothesis Attack Sequence:</b>")
            lbl_steps_hdr.setStyleSheet("color: #f59e0b; font-size: 11px;")
            layout.addWidget(lbl_steps_hdr)
            for s in chain.attack_steps:
                lbl_s = QLabel(f"  {s}")
                lbl_s.setWordWrap(True)
                lbl_s.setStyleSheet("color: #e2e8f0; font-size: 11px; padding: 2px 0;")
                layout.addWidget(lbl_s)

        # Validation Required (Anti-Hallucination Guardrail)
        if chain.validation_required:
            val_box = QFrame()
            val_box.setStyleSheet(
                "background-color: rgba(245, 158, 11, 0.08); border: 1px dashed #f59e0b; "
                "border-radius: 4px; padding: 6px 10px;"
            )
            val_l = QVBoxLayout(val_box)
            val_l.setContentsMargins(2, 2, 2, 2)
            val_l.setSpacing(4)
            val_title = QLabel("<b>Controlled Verification Actions (Do Not Exploit Production):</b>")
            val_title.setStyleSheet("color: #f59e0b; font-size: 11px;")
            val_l.addWidget(val_title)
            for v in chain.validation_required:
                lbl_v = QLabel(f"  ✔ {v}")
                lbl_v.setWordWrap(True)
                lbl_v.setStyleSheet("color: #fef08a; font-size: 11px;")
                val_l.addWidget(lbl_v)
            layout.addWidget(val_box)

        # Supporting Evidence Citations
        if chain.supporting_citations:
            lbl_cit_hdr = QLabel("<b>Grounded Evidence Citations:</b>")
            lbl_cit_hdr.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px;")
            layout.addWidget(lbl_cit_hdr)
            for c in chain.supporting_citations:
                has_valid_ev = isinstance(c.evidence_id, int) and c.evidence_id > 0
                has_valid_hash = (
                    isinstance(c.evidence_hash, str)
                    and re.fullmatch(r"[0-9a-fA-F]{64}", c.evidence_hash) is not None
                )

                if has_valid_ev and has_valid_hash:
                    ev_str = f"Evidence ID: <code>#{c.evidence_id}</code> · Hash: <code>{c.evidence_hash}</code>"
                elif has_valid_ev:
                    ev_str = f"Evidence ID: <code>#{c.evidence_id}</code> · Hash: <code>No verified hash</code>"
                else:
                    ev_str = "Evidence: <code>No linked evidence</code>"

                cit_text = (
                    f"  📎 <b>{html_escape(c.finding_title)}</b> (Asset: {html_escape(c.affected_asset)}) · "
                    f"Tool: <code>{html_escape(c.source_tool)}</code> · {ev_str} · "
                    f"Status: <b>{html_escape(c.validation_status)}</b>"
                )
                lbl_c = QLabel(cit_text)
                lbl_c.setWordWrap(True)
                lbl_c.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
                layout.addWidget(lbl_c)
        else:
            lbl_no_cit = QLabel("<b>Grounded Evidence Citations:</b> <code>No linked evidence</code>")
            lbl_no_cit.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
            layout.addWidget(lbl_no_cit)

        self.chains_layout.addWidget(card)

    def _render_inferences_box(self, inferences: List[str]):
        box = QFrame()
        box.setStyleSheet(
            "background-color: rgba(239, 68, 68, 0.08); border: 1px solid #dc2626; border-radius: 6px; padding: 10px;"
        )
        l = QVBoxLayout(box)
        l.setContentsMargins(4, 4, 4, 4)
        l.setSpacing(4)

        hdr = QLabel("<b>⚠ Unvalidated Inferences Requiring Verification:</b>")
        hdr.setStyleSheet("color: #ef4444; font-size: 11px;")
        l.addWidget(hdr)

        for inf in inferences[:5]:
            lbl = QLabel(f"  • {inf}")
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color: #fca5a5; font-size: 11px;")
            l.addWidget(lbl)
        self.chains_layout.addWidget(box)

    def _render_remediation_card(self, remediations: List[str]):
        card = QFrame()
        card.setStyleSheet(
            f"background-color: {CPENTTheme.PANEL_BG}; border: 1px solid {CPENTTheme.BORDER}; "
            "border-radius: 6px; padding: 10px;"
        )
        l = QVBoxLayout(card)
        l.setContentsMargins(4, 4, 4, 4)
        l.setSpacing(4)

        hdr = QLabel("<b>Prioritized Mitigation Roadmap:</b>")
        hdr.setStyleSheet(f"color: {CPENTTheme.SUCCESS_GREEN}; font-size: 11px;")
        l.addWidget(hdr)

        for i, rem in enumerate(remediations[:4], 1):
            lbl = QLabel(f"  {i}. {rem}")
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color: {CPENTTheme.PRIMARY_TEXT}; font-size: 11px; padding: 2px 0;")
            l.addWidget(lbl)
        self.chains_layout.addWidget(card)

    def _render_quarantine_card(self, reason: str, scope_text: str):
        box = QFrame()
        box.setObjectName("quarantineCard")
        box.setStyleSheet(
            "QFrame#quarantineCard { background-color: #2a1215; border: 2px solid #ef4444; "
            "border-radius: 8px; padding: 20px; }"
        )
        l = QVBoxLayout(box)
        l.setContentsMargins(12, 12, 12, 12)
        l.setSpacing(10)

        hdr = QLabel(f"🛡️ PentestX Scope Quarantine Guard — {html_escape(scope_text)}")
        hdr.setFont(QFont("Segoe UI", 12, QFont.Bold))
        hdr.setStyleSheet("color: #ef4444;")
        l.addWidget(hdr)

        body = QLabel(
            f"Attack path analysis and vulnerability correlation for target <b>{html_escape(self.target_ip)}</b> "
            f"have been <b>strictly blocked (fail-closed)</b> because the target violates engagement authorization rules:<br><br>"
            f"<code>{html_escape(reason)}</code><br><br>"
            "<b>Security Policy:</b> PentestX strictly prohibits analyzing or correlating attack vectors against targets "
            "outside authorized Rules of Engagement (RoE). Zero target findings, attack paths, or pivot hypotheses "
            "are exposed for unauthorized assets.<br><br>"
            "<b>To Resolve:</b> Navigate to <b>Scope & Projects</b> in the main navigation sidebar to authorize this target, "
            "CIDR subnet, or hostname before conducting attack path analysis."
        )
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {CPENTTheme.PRIMARY_TEXT}; font-size: 11px; line-height: 1.5;")
        l.addWidget(body)

        self.chains_layout.addWidget(box)

    def _render_empty_state(self, title: str):
        box = QFrame()
        box.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; border: 1px dashed {CPENTTheme.BORDER}; "
            "border-radius: 6px; padding: 24px;"
        )
        l = QVBoxLayout(box)
        l.setAlignment(Qt.AlignCenter)
        l.setSpacing(8)

        lbl_t = QLabel(f"🔍 {title}")
        lbl_t.setFont(QFont("Segoe UI", 12, QFont.Bold))
        lbl_t.setStyleSheet(f"color: {CPENTTheme.PRIMARY_TEXT};")
        lbl_t.setAlignment(Qt.AlignCenter)
        l.addWidget(lbl_t)

        msg = (
            f"Target <b>{self.target_ip}</b> currently has no correlated multi-stage vulnerability chains.<br><br>"
            "To discover actionable attack paths:<br>"
            "1. Execute an active service probe (e.g. Nmap version detection <code>-sV</code>)<br>"
            "2. Run application assessments (e.g. Nikto, SQLMap, or Nuclei templates)<br>"
            "3. Import external assessment findings via the Findings repository."
        )
        lbl_m = QLabel(msg)
        lbl_m.setWordWrap(True)
        lbl_m.setAlignment(Qt.AlignCenter)
        lbl_m.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px; line-height: 1.5;")
        l.addWidget(lbl_m)
        self.chains_layout.addWidget(box)

    def _render_error_card(self, error_msg: str):
        box = QFrame()
        box.setStyleSheet("background-color: #3d1014; border: 1px solid #ef4444; border-radius: 6px; padding: 16px;")
        l = QVBoxLayout(box)
        l.setSpacing(6)

        hdr = QLabel("<b>Attack Path Analysis Failed</b>")
        hdr.setStyleSheet("color: #ef4444; font-size: 12px;")
        l.addWidget(hdr)

        body = QLabel(f"An unexpected error occurred during correlation: {error_msg}")
        body.setWordWrap(True)
        body.setStyleSheet("color: #fca5a5; font-size: 11px;")
        l.addWidget(body)
        self.chains_layout.addWidget(box)

    @staticmethod
    def _clear_layout(layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()


def html_escape(text: str) -> str:
    """Escapes HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
