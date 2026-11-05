"""Attack Path Analysis Dialog for PentestX / CyberSecuritySuite.

Connects the 2D network topology and asset inventory with the evidence-grounded
AIDataAnalystEngine to display multi-stage attack chains, prerequisites,
hypothesis steps, validation actions, and supporting citations without simulation or hallucination.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
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
from desktop.theme import CPENTTheme, get_badge_qss
from storage.db import Database
from storage.models import Finding, Project, TargetScope

logger = logging.getLogger(__name__)


def check_target_scope(target: str, scopes: List[TargetScope]) -> Tuple[str, str]:
    """Evaluates target against project authorization scope boundaries.

    Returns:
        (status_text, badge_token)
    """
    if not scopes:
        return "Scope Unassigned", "WARNING"

    clean_target = target.strip()
    try:
        t_ip = ipaddress.ip_address(clean_target)
        for s in scopes:
            if not getattr(s, "is_authorized", True):
                continue
            s_target = s.target.strip()
            try:
                if "/" in s_target:
                    net = ipaddress.ip_network(s_target, strict=False)
                    if t_ip in net:
                        return "Authorized In-Scope Target", "CONFIRMED"
                else:
                    if t_ip == ipaddress.ip_address(s_target):
                        return "Authorized In-Scope Target", "CONFIRMED"
            except Exception:
                if s_target.lower() == clean_target.lower():
                    return "Authorized In-Scope Target", "CONFIRMED"
    except Exception:
        for s in scopes:
            if getattr(s, "is_authorized", True) and s.target.strip().lower() in clean_target.lower():
                return "Authorized In-Scope Target", "CONFIRMED"

    return "Out-of-Scope / Quarantine Target", "CRITICAL"


class AttackPathAnalysisDialog(QDialog):
    """Deep-dive multi-stage attack path analysis dialog."""

    def __init__(
        self,
        target_ip: str,
        project: Optional[Project] = None,
        db: Optional[Database] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.target_ip = target_ip.strip()
        self.project = project
        self.db = db
        self.report: Optional[DataAnalystReport] = None
        self.target_findings: List[Finding] = []

        self.setWindowTitle(f"Attack Path Analysis — {self.target_ip}")
        self.setObjectName("attackPathAnalysisDialog")
        self.resize(860, 720)
        self._build_ui()
        self.run_analysis()

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
            f"Target: <b>{self.target_ip}</b> · Project: <b>{self.project.name if self.project else 'Unassigned'}</b>"
        )
        self.lbl_meta.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 12px;")
        hdr_layout.addWidget(self.lbl_meta)
        root.addWidget(self.header_card)

        # 2. Executive Summary & Findings Tally Card
        self.summary_card = QFrame()
        self.summary_card.setStyleSheet(
            f"background-color: {CPENTTheme.ELEVATED_PANEL}; border: 1px solid {CPENTTheme.BORDER}; border-radius: 6px; padding: 10px;"
        )
        sum_layout = QVBoxLayout(self.summary_card)
        sum_layout.setContentsMargins(8, 8, 8, 8)
        sum_layout.setSpacing(6)

        self.lbl_summary = QLabel("Initializing evidence correlation...")
        self.lbl_summary.setWordWrap(True)
        self.lbl_summary.setStyleSheet(f"color: {CPENTTheme.PRIMARY_TEXT}; font-size: 12px; line-height: 1.4;")
        sum_layout.addWidget(self.lbl_summary)

        self.lbl_findings_tally = QLabel("Findings on Target: 0 (0 Critical · 0 High · 0 Med)")
        self.lbl_findings_tally.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
        sum_layout.addWidget(self.lbl_findings_tally)
        root.addWidget(self.summary_card)

        # 3. Scroll Area for Attack Chains & Details
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        self.chains_container = QWidget()
        self.chains_container.setStyleSheet("background: transparent;")
        self.chains_layout = QVBoxLayout(self.chains_container)
        self.chains_layout.setContentsMargins(0, 0, 0, 0)
        self.chains_layout.setSpacing(10)
        self.scroll_area.setWidget(self.chains_container)
        root.addWidget(self.scroll_area, 1)

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

    def run_analysis(self):
        """Executes real evidence-grounded attack path analysis using AIDataAnalystEngine."""
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
            return

        project_id = self.project.id

        try:
            # 1. Scope boundary verification
            scopes = self.db.list_scopes(project_id) if hasattr(self.db, "list_scopes") else []
            scope_text, scope_token = check_target_scope(self.target_ip, scopes)
            self.lbl_scope_badge.setText(f"Scope: {scope_text}")
            self.lbl_scope_badge.setStyleSheet(get_badge_qss(scope_token))

            # 2. Query real findings and correlate by target IP / Hostname
            all_findings: List[Finding] = (
                self.db.list_findings(project_id) if hasattr(self.db, "list_findings") else []
            )

            # Resolve associated asset names from asset_nodes
            nodes = self.db.list_asset_nodes(project_id) if hasattr(self.db, "list_asset_nodes") else []
            associated_identifiers = {self.target_ip}
            for n in nodes:
                val = getattr(n, "value", "").strip()
                lbl = getattr(n, "label", "").strip()
                if val == self.target_ip or self.target_ip in val:
                    if lbl:
                        associated_identifiers.add(lbl)
                elif lbl == self.target_ip:
                    if val:
                        associated_identifiers.add(val)

            # Filter findings related to target
            self.target_findings = [
                f for f in all_findings
                if any(ident in (f.affected_asset or "") for ident in associated_identifiers)
            ]

            crit_count = sum(1 for f in self.target_findings if getattr(f.severity, "value", str(f.severity)).lower() == "critical")
            high_count = sum(1 for f in self.target_findings if getattr(f.severity, "value", str(f.severity)).lower() == "high")
            med_count = sum(1 for f in self.target_findings if getattr(f.severity, "value", str(f.severity)).lower() == "medium")
            low_count = sum(1 for f in self.target_findings if getattr(f.severity, "value", str(f.severity)).lower() == "low")

            self.lbl_findings_tally.setText(
                f"Findings on Target: {len(self.target_findings)} "
                f"({crit_count} Critical · {high_count} High · {med_count} Medium · {low_count} Low)"
            )

            # 3. Execute AIDataAnalystEngine
            analyst = AIDataAnalystEngine(db=self.db)

            # Analyze target-specific normalized findings
            target_norm = [NormalizedFinding.from_finding(f) for f in self.target_findings]
            target_report = analyst.analyze_project(project_id=project_id, findings=target_norm)

            # Also analyze project-wide findings to detect incoming pivot chains
            project_report = analyst.analyze_project(project_id=project_id)

            self.report = target_report
            self.lbl_posture_badge.setText(f"Posture: {target_report.overall_posture}")
            self.lbl_posture_badge.setStyleSheet(get_badge_qss(target_report.overall_posture.split()[0]))

            # Update executive summary
            if target_report.attack_paths:
                self.lbl_summary.setText(
                    f"Identified {len(target_report.attack_paths)} multi-stage attack path(s) directly affecting "
                    f"target <b>{self.target_ip}</b> based on {len(self.target_findings)} verified finding(s). "
                    "Review the hypothesis chains, validation actions, and supporting evidence citations below."
                )
                for chain in target_report.attack_paths:
                    self._render_attack_chain_card(chain, is_direct=True)
            elif project_report.attack_paths:
                self.lbl_summary.setText(
                    f"No direct attack chains formed exclusively on {self.target_ip}. However, "
                    f"<b>{len(project_report.attack_paths)} environment-wide attack chain(s)</b> were identified in "
                    f"Project #{project_id} that could facilitate lateral movement into this asset's network segment."
                )
                for chain in project_report.attack_paths:
                    self._render_attack_chain_card(chain, is_direct=False)
            else:
                self.lbl_summary.setText(
                    f"Security analysis completed for target <b>{self.target_ip}</b>. "
                    "No multi-stage attack chains identified. Current port observations and findings do not satisfy "
                    "known multi-hop compromise prerequisites."
                )
                self._render_empty_state("No Exploitable Attack Chains Identified")

            # 4. Render Unvalidated Inferences Guardrail Box
            inferences = target_report.unvalidated_inferences or project_report.unvalidated_inferences
            if inferences:
                self._render_inferences_box(inferences)

            # 5. Render Prioritized Remediation Roadmap
            remediations = target_report.prioritized_remediations or project_report.prioritized_remediations
            if remediations:
                self._render_remediation_card(remediations)

        except Exception as exc:
            logger.error("Attack path analysis execution failed for target %s: %s", self.target_ip, exc, exc_info=True)
            self.lbl_summary.setText(f"<font color='#ef4444'>Analysis Error: {html_escape(str(exc))}</font>")
            self._render_error_card(str(exc))

    def _render_attack_chain_card(self, chain: AttackPathChain, is_direct: bool = True):
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
        name_pfx = "🎯 Direct Attack Chain" if is_direct else "🔀 Pivot / Segment Path"
        lbl_name = QLabel(f"{name_pfx}: {chain.chain_name}")
        lbl_name.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lbl_name.setStyleSheet("color: #f8fafc;")
        lbl_name.setWordWrap(True)
        hdr.addWidget(lbl_name)
        hdr.addStretch()

        lbl_like = QLabel(f" Likelihood: {chain.likelihood} ")
        lbl_like.setStyleSheet(get_badge_qss(chain.likelihood))
        hdr.addWidget(lbl_like)

        lbl_imp = QLabel(f" Impact: {chain.impact} ")
        lbl_imp.setStyleSheet(get_badge_qss(chain.impact))
        hdr.addWidget(lbl_imp)
        layout.addLayout(hdr)

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
                c_hash = c.evidence_hash[:16] + "..." if c.evidence_hash else "UNHASHED"
                cit_text = (
                    f"  📎 <b>{c.finding_title}</b> (Asset: {c.affected_asset}) · "
                    f"Tool: <code>{c.source_tool}</code> · Evidence ID: <code>{c.evidence_id or 'None'}</code> · "
                    f"Hash: <code>{c_hash}</code> · Status: <b>{c.validation_status}</b>"
                )
                lbl_c = QLabel(cit_text)
                lbl_c.setWordWrap(True)
                lbl_c.setStyleSheet(f"color: {CPENTTheme.SECONDARY_TEXT}; font-size: 11px;")
                layout.addWidget(lbl_c)

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
        l.setSpacing(6)

        hdr = QLabel("<b>🛡️ Prioritized Defensive Remediation Roadmap:</b>")
        hdr.setStyleSheet(f"color: {CPENTTheme.PRIMARY_BLUE}; font-size: 11px;")
        l.addWidget(hdr)

        for r in remediations:
            lbl = QLabel(f"  {r}")
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color: #e2e8f0; font-size: 11px;")
            l.addWidget(lbl)
        self.chains_layout.addWidget(card)

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
