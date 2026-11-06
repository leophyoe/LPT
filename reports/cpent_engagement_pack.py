"""CPENT-Informed Engagement Workspace Generator.

Generates original engagement documents and evidence indexes using common
assessment documentation practices and CPENT methodology concepts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from storage.db import Database
from storage.models import Project, TargetScope
from terminal.recorder import redact_sensitive_text


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class CPENTEngagementPackGenerator:
    """Exports an original CPENT-informed assessment workspace."""

    def __init__(self, db: Database):
        self.db = db

    def generate_pack(self, project_id: int, base_dir: Path) -> Dict[str, Path]:
        """Creates the full CPENT engagement folder structure for a given project."""
        project = self.db.get_project(project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} does not exist.")

        scopes = self.db.list_scopes(project_id)
        findings = self.db.list_findings(project_id)
        evidence = self.db.list_evidence(project_id)
        executions = self.db.list_executions(project_id)

        # Engagement folder root
        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name)
        root = base_dir / f"CPENT_ENGAGEMENT_{project.engagement_id or clean_name}"
        root.mkdir(parents=True, exist_ok=True)

        created_files: Dict[str, Path] = {}

        # -------------------------------------------------------------
        # 1. Directory Structure Setup
        # -------------------------------------------------------------
        admin_dir = root / "00_Administration"
        evidence_dir = root / "01_SISGCA"
        tools_dir = root / "02_SEVA_Tools"

        subdirs = [
            admin_dir / "00A_EL",
            admin_dir / "00B_ProjPlan",
            admin_dir / "00C_Client_Info",
            admin_dir / "00D_NDA",
            admin_dir / "00E_DUA",
            admin_dir / "00F__ROE",
            admin_dir / "00G_TP",
            admin_dir / "00H_LTA",
            admin_dir / "00J_PBC",
            admin_dir / "00L_ECL",
            admin_dir / "00M_EC",
            admin_dir / "00N_MB",
            evidence_dir / "01A_OSIA",
            evidence_dir / "01B_RSEVA",
            evidence_dir / "01C_EVD&A",
            evidence_dir / "01J_Draft_Rpt",
            tools_dir,
        ]
        for d in subdirs:
            d.mkdir(parents=True, exist_ok=True)

        # -------------------------------------------------------------
        # 2. Template Generation
        # -------------------------------------------------------------
        # A. Engagement Letter
        el_file = admin_dir / "00A_EL" / "Engagement_Letter.md"
        el_content = self._render_engagement_letter(project)
        el_file.write_text(redact_sensitive_text(el_content), encoding="utf-8")
        created_files["engagement_letter"] = el_file

        # B. Initial Client Worksheet (ICW)
        icw_file = admin_dir / "00C_Client_Info" / "Initial_Client_Worksheet.md"
        icw_content = self._render_client_worksheet(project)
        icw_file.write_text(redact_sensitive_text(icw_content), encoding="utf-8")
        created_files["client_worksheet"] = icw_file

        # C. Non-Disclosure Agreement (NDA)
        nda_file = admin_dir / "00D_NDA" / "Non_Disclosure_Agreement.md"
        nda_content = self._render_nda(project)
        nda_file.write_text(redact_sensitive_text(nda_content), encoding="utf-8")
        created_files["nda"] = nda_file

        # D. Rules of Engagement (RoE)
        roe_file = admin_dir / "00F__ROE" / "Rules_of_Engagement.md"
        roe_content = self._render_roe(project)
        roe_file.write_text(redact_sensitive_text(roe_content), encoding="utf-8")
        created_files["roe"] = roe_file

        # E. Test Plan & Scope (TP)
        tp_file = admin_dir / "00G_TP" / "Test_Plan_and_Scope.md"
        tp_content = self._render_test_plan(project, scopes)
        tp_file.write_text(redact_sensitive_text(tp_content), encoding="utf-8")
        created_files["test_plan"] = tp_file

        # F. Letter of Technical Authorization (LTA - IAUTH & XAUTH)
        lta_file = admin_dir / "00H_LTA" / "Letter_of_Technical_Authorization.md"
        lta_content = self._render_lta(project, scopes)
        lta_file.write_text(redact_sensitive_text(lta_content), encoding="utf-8")
        created_files["lta"] = lta_file

        # G. Master Engagement Control List (ECL)
        ecl_file = admin_dir / "00L_ECL" / "Master_Engagement_Control_List.md"
        ecl_content = self._render_ecl(project, scopes, findings, executions)
        ecl_file.write_text(redact_sensitive_text(ecl_content), encoding="utf-8")
        created_files["ecl"] = ecl_file

        # H. OSINT & Reconnaissance Activity Log
        osint_log = evidence_dir / "01A_OSIA" / "OSINT_Activity_Log.md"
        osint_log.write_text(
            redact_sensitive_text(
                f"# OSINT & Attack Surface Activity Log\n\n"
                f"**Project:** {project.name}\n"
                f"**Generated:** {_utc_now_str()}\n\n"
                f"| Timestamp | Tool | Target Domain / Asset | Action Description | Finding ID |\n"
                f"| :--- | :--- | :--- | :--- | :---: |\n"
                f"| {project.created_at[:19]} | Initialization | N/A | Engagement Created in CyberSecuritySuite | - |\n"
            ),
            encoding="utf-8",
        )
        created_files["osint_log"] = osint_log

        # I. Cryptographic Evidence Manifest
        ev_manifest = evidence_dir / "01C_EVD&A" / "Evidence_Manifest.json"
        manifest_data = {
            "engagement_id": project.engagement_id or f"PRJ-{project.id}",
            "project_name": project.name,
            "exported_at": _utc_now_str(),
            "total_evidence_files": len(evidence),
            "evidence_records": [
                {
                    "id": ev.id,
                    "file_path": ev.file_path,
                    "sha256_hash": ev.sha256_hash,
                    "mime_type": ev.mime_type,
                    "description": ev.description,
                    "finding_id": ev.finding_id,
                }
                for ev in evidence
            ],
        }
        ev_manifest.write_text(redact_sensitive_text(json.dumps(manifest_data, indent=2)), encoding="utf-8")
        created_files["evidence_manifest"] = ev_manifest

        # J. Tool Inventory
        tools_inventory = tools_dir / "Tool_Inventory.md"
        tools_inventory.write_text(
            redact_sensitive_text(
                f"# Penetration Testing Tool Inventory & Execution History\n\n"
                f"**Project:** {project.name}\n"
                f"**Lead Tester:** {getattr(project, 'lead_tester', '') or 'N/A'}\n\n"
                f"### Executed Tools\n"
                + (
                    "\n".join(
                        f"- **{execution.tool_name}**: `{execution.command}` "
                        f"(Exit Code: {execution.exit_code})"
                        for execution in executions
                    )
                    if executions
                    else "*No automated tool executions registered yet.*"
                )
                + "\n"
            ),
            encoding="utf-8",
        )
        created_files["tool_inventory"] = tools_inventory

        # Root README
        readme_file = root / "README.md"
        readme_file.write_text(
            redact_sensitive_text(
                f"# CPENT-Informed Engagement Workspace\n\n"
                f"**Client Organization:** {project.client_name or 'N/A'}  \n"
                f"**Engagement ID:** {project.engagement_id or 'N/A'}  \n"
                f"**Lead Tester:** {getattr(project, 'lead_tester', '') or 'N/A'}  \n"
                f"**Operational Window:** {getattr(project, 'start_date', '') or 'N/A'} to {getattr(project, 'end_date', '') or 'N/A'}  \n"
                f"**Generated:** {_utc_now_str()}  \n\n"
                f"### Workspace Organization (Original structure informed by common assessment practices)\n"
                f"- **`00_Administration/`**: Legal authorization, RoE, NDAs, test plans, and client worksheets.\n"
                f"- **`01_SISGCA/`**: Security information, scans, OSINT logs, and cryptographic evidence vaults.\n"
                f"- **`02_SEVA_Tools/`**: Tool configurations, scripts, and execution records.\n"
                f"- **`03_Final_Reports/`**: Multi-format executive, technical, and original methodology reports (PDF, HTML, MD, JSON, CSV).\n"
            ),
            encoding="utf-8",
        )
        created_files["root_readme"] = readme_file

        # K. Generate Multi-Format Final Reports in 03_Final_Reports
        from reports.builder import ReportBuilder
        reports_dir = root / "03_Final_Reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_builder = ReportBuilder(self.db)
        report_paths = report_builder.generate_all(project_id, reports_dir, stable_names=True)
        for key, path in report_paths.items():
            created_files[f"report_{key}"] = path
        methodology_markdown = reports_dir / "cpent_methodology_report.md"
        report_builder.generate_cpent_methodology_markdown(project_id, output_path=methodology_markdown)
        created_files["report_cpent_methodology_markdown"] = methodology_markdown
        methodology_json = reports_dir / "cpent_methodology_report.json"
        report_builder.generate_cpent_methodology_json(project_id, output_path=methodology_json)
        created_files["report_cpent_methodology_json"] = methodology_json

        return created_files

    def generate_pack_zip(self, project_id: int, zip_path: Path) -> Path:
        """Generates the CPENT-informed workspace and archives it into a zip file."""
        import tempfile
        import zipfile

        project = self.db.get_project(project_id)
        if not project:
            raise ValueError(f"Project with ID {project_id} does not exist.")

        clean_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in project.name)
        root_folder_name = f"CPENT_ENGAGEMENT_{project.engagement_id or clean_name}"

        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_base = Path(tmp_dir)
            self.generate_pack(project_id, temp_base)
            root_dir = temp_base / root_folder_name

            zip_path = Path(zip_path)
            zip_path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in sorted(root_dir.rglob("*")):
                    if file_path.is_file():
                        arcname = file_path.relative_to(root_dir)
                        zf.write(file_path, str(arcname))

        return zip_path

    # -------------------------------------------------------------
    # Document Renderers
    # -------------------------------------------------------------
    def _render_engagement_letter(self, p: Project) -> str:
        return f"""# Penetration Testing Engagement Letter

**Date:** {_utc_now_str()[:10]}  
**Client Organization:** {p.client_name or 'Authorized Client'}  
**Engagement ID:** {p.engagement_id or f'ENG-{p.id}'}  
**Lead Penetration Tester:** {getattr(p, 'lead_tester', '') or 'Designated Lead'}  
**SoW Reference:** {getattr(p, 'sow_reference', '') or 'N/A'}  

---

### 1. Scope of Engagement
This Engagement Letter confirms that {getattr(p, 'lead_tester', '') or 'CyberSecuritySuite Assessment Team'} has been retained by **{p.client_name or 'Client Organization'}** to conduct an authorized security assessment and penetration test.

### 2. Period of Performance
Testing will commence on **{getattr(p, 'start_date', '') or 'TBD'}** and conclude on **{getattr(p, 'end_date', '') or 'TBD'}** ({getattr(p, 'timezone', 'UTC')}).
Permitted testing hours: `{getattr(p, 'allowed_hours', '') or '09:00-18:00 Local Business Hours'}`.

### 3. Deliverables
At the conclusion of the assessment, the team will deliver:
1. Executive Summary and Strategic Recommendations (Personnel, Policies, Critical Flaws, Authentication, IDS).
2. Comprehensive Technical Findings with CVSS v3.1 base scoring.
3. Cryptographically hashed Evidence Vault verifying all proof-of-concept tests.

---
*Signed on behalf of {p.client_name or 'Client'}:* ___________________________  
*Signed on behalf of Assessment Team:* ___________________________  
"""

    def _render_client_worksheet(self, p: Project) -> str:
        return f"""# Initial Client Worksheet (ICW)

**Client Name:** {p.client_name or 'N/A'}  
**Primary Authorized Contact:** {getattr(p, 'authorized_contact', '') or 'N/A'}  
**Emergency Contact (24/7):** {getattr(p, 'emergency_contact', '') or 'N/A'}  
**Engagement ID:** {p.engagement_id or 'N/A'}  
**Project Description:** {p.description or 'Security assessment'}  

### Organizational Constraints & Critical Assets
- **Critical Infrastructure Exclusions:** Critical banking, medical, or live SCADA endpoints must be isolated unless explicitly cleared.
- **Notification Protocol:** Immediate voice contact if critical compromise or unrecoverable system crash occurs.
- **Third-Party Providers:** Any cloud hosting (AWS, Azure, GCP) or SaaS providers must be verified for compliance with provider penetration testing policies.
"""

    def _render_nda(self, p: Project) -> str:
        return f"""# Mutual Non-Disclosure Agreement (NDA)

**Client:** {p.client_name or 'Client Organization'}  
**Engagement:** {p.name} ({p.engagement_id or 'N/A'})  
**Effective Date:** {_utc_now_str()[:10]}  

### Confidential Information
All vulnerability findings, source code, network architectures, employee credentials, and evidence collected during this assessment constitute **Strictly Confidential Information**.

### Protective Obligations
The assessment team agrees:
1. Not to disclose or distribute any findings or client data to unauthorized third parties.
2. To store evidence using cryptographic hashing and access control.
3. To securely shred and scrub all client data upon completion of post-testing retention periods.
"""

    def _render_roe(self, p: Project) -> str:
        return f"""# Rules of Engagement (RoE)

**Project:** {p.name}  
**Engagement ID:** {p.engagement_id or 'N/A'}  
**Lifecycle Status:** {p.status.value.upper()}  

---

### 1. Operational Constraints
- **Maximum Request Rate:** `{getattr(p, 'max_rate_limit', 100)}` requests/sec.
- **Active OSINT Permitted:** `{'YES' if getattr(p, 'allow_active_recon', False) else 'NO (Passive Discovery Only)'}`.
- **Testing Time Window:** `{getattr(p, 'start_date', '') or 'N/A'}` to `{getattr(p, 'end_date', '') or 'N/A'}` ({getattr(p, 'timezone', 'UTC')}).
- **Operational Testing Hours:** `{getattr(p, 'allowed_hours', '') or 'Anytime with monitoring'}`.

### 2. Prohibited Techniques & Tests
`{getattr(p, 'prohibited_tests', '') or 'Denial of Service (DoS/DDoS), physical facility intrusion, unapproved social engineering, and destructive database operations.'}`

### 3. Emergency Stop & Incident Response
If an operational interruption or unintentional downtime occurs:
1. Immediately execute emergency stop: terminate active scanners and background processes.
2. Notify Client Emergency Contact: **{getattr(p, 'emergency_contact', '') or 'Designated SecOps'}**.
3. Record exact timestamp, source IP, and command string in the engagement log.
"""

    def _render_test_plan(self, p: Project, scopes: List[TargetScope]) -> str:
        lines = [
            f"# Penetration Testing Test Plan & Scope Definition",
            f"",
            f"**Project:** {p.name}  ",
            f"**Engagement ID:** {p.engagement_id or 'N/A'}  ",
            f"**Testing Methodology:** EC-Council CPENT & PTES Standards  ",
            f"",
            f"### In-Scope Targets & Boundaries",
            f"",
            f"| Target Asset | Target Type | Rule | Authorized | Allowed Environment | Allowed Ports |",
            f"| :--- | :--- | :---: | :---: | :--- | :--- |",
        ]
        if scopes:
            for s in scopes:
                auth = "YES ✓" if s.is_authorized else "NO ✗"
                rule = getattr(s, "rule_type", "ALLOWED")
                rule_name = rule.value if hasattr(rule, "value") else str(rule)
                lines.append(
                    f"| `{s.target}` | {s.target_type.value} | `{rule_name}` | {auth} | {s.environment or 'All'} | {s.ports_allowed or 'All'} |"
                )
        else:
            lines.append("| *No explicit targets registered* | - | - | - | - | - |")

        lines.extend([
            f"",
            f"### Testing Phases",
            f"1. **Phase 1: OSINT & Attack Surface Enumeration** (Passive DNS, Subdomains, Amass, Cert Logs)",
            f"2. **Phase 2: External Perimeter Assessment** (Firewall ACL probe, port scanning, service versioning)",
            f"3. **Phase 3: Web & API Security Inspection** (OWASP Top 10, SQLi, XSS, CSRF, JWT, SSRF)",
            f"4. **Phase 4: Vulnerability Verification & Evidence Capture** (Proof-of-concept capture, SHA-256 hash generation)",
            f"5. **Phase 5: Reporting & Post-Assessment Briefing** (CPENT executive recommendations, risk assessment matrix)",
        ])
        return "\n".join(lines)

    def _render_lta(self, p: Project, scopes: List[TargetScope]) -> str:
        target_list = ", ".join([f"`{s.target}`" for s in scopes if s.is_authorized]) or "All authorized client systems"
        return f"""# Letter of Technical Authorization (LTA)
## Incorporating Internal Authorization (IAUTH) & External Authorization (XAUTH)

**To Whom It May Concern / Network Administrators / Cloud Hosting Providers:**

This document serves as formal written authorization under computer crime statutes (including CFAA and equivalent regional legislation) authorizing **{getattr(p, 'lead_tester', '') or 'CyberSecuritySuite Assessment Team'}** to perform security penetration testing on the following client assets:

**Authorized In-Scope Assets:**  
{target_list}

**Authorized Testing Period:**  
{getattr(p, 'start_date', '') or 'Start'} through {getattr(p, 'end_date', '') or 'End'} ({getattr(p, 'timezone', 'UTC')})

**Authorized By Client Representative:**  
Name: {getattr(p, 'authorized_contact', '') or 'Authorized Officer'}  
Organization: {p.client_name or 'Client Organization'}  
Signature: ____________________________________  
Date: {_utc_now_str()[:10]}  
"""

    def _render_ecl(self, p: Project, scopes: List[TargetScope], findings: List[Any], executions: List[Any]) -> str:
        return f"""# Master Engagement Control List (ECL)

**Engagement ID:** {p.engagement_id or 'N/A'}  
**Project:** {p.name}  
**Lifecycle Status:** {p.status.value.upper()}  
**Lead Tester:** {getattr(p, 'lead_tester', '') or 'N/A'}  
**Total Scopes Configured:** {len(scopes)}  
**Total Tool Executions:** {len(executions)}  
**Total Security Findings:** {len(findings)}  

### Engagement Checklist
- [x] Initial Client Worksheet (ICW) Completed
- [x] Non-Disclosure Agreement (NDA) Executed
- [x] Engagement Letter (EL) Countersigned
- [x] Rules of Engagement (RoE) Established & Rate Limits Defined
- [x] Scope Guard Rules Configured in CyberSecuritySuite
- [x] Letter of Technical Authorization (IAUTH / XAUTH) Signed
- [{'x' if executions else ' '}] Tool Executions & Scans Logged
- [{'x' if findings else ' '}] Vulnerability Findings Verified with Proof of Concept
- [{'x' if findings else ' '}] Cryptographic Evidence Hashes Recorded in Vault
- [ ] Post-Testing Cleanup Verified
- [ ] Final CPENT Report Delivered
"""
