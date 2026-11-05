# LPT Workstation — Phase 0: Prioritized Repair & Implementation Plan
**Document ID:** `docs/audit/RECOMMENDED_REPAIR_PLAN.md`  
**Audit Date:** 2026-11-05  
**Auditor:** Senior Software Architect & Technical Project Manager  
**Status:** COMPLETED — ROADMAP EXECUTION BLUEPRINT  

---

## 1. Executive Summary

Based on the exhaustive findings from the Phase 0 audits (`REPOSITORY_AUDIT.md`, `FEATURE_AUDIT.md`, `DATABASE_AUDIT.md`, `RUNTIME_AUDIT.md`, and `DEPENDENCY_AUDIT.md`), the LPT Workstation has an exceptionally solid, verified foundation with **744 passing tests** and a verified production database. 

This document defines the **Prioritized Repair & Implementation Plan** covering Phase 1 through Phase 15, adhering strictly to the incremental, non-destructive safety rules established in the Master Development Prompt.

---

## 2. Phase-by-Phase Prioritized Implementation Roadmap

```text
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 0: Complete Read-Only Audits & Baselines [COMPLETED]            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Wait for Approval)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Core Application Stability & Performance Indexing             │
│ - Add covering indexes to SQLite database (project_id lookups)        │
│ - Modernize SSL constants to eliminate 60 deprecation warnings         │
│ - Clean up historical backup files into .archive/                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Professional UI/UX Redesign & Accessibility                   │
│ - Upgrade font hierarchy: body 13-14px, headers 15-17px, titles 24px   │
│ - Red-accented dark & light theme WCAG contrast compliance             │
│ - Assets view empty-state action cards & high-contrast master grid     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Project-First Scoping & Multi-Assessment Container            │
│ - Unified project hierarchy supporting multiple sub-assessment tabs    │
│ - Enhanced client information & Rules of Engagement metadata           │
│ - Fail-closed scope boundary wizard with exclusion visualizer          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: Terminal Execution Engine & Ingestion Hardening               │
│ - Terminal scrollback buffer memory cap                                │
│ - Dual-track execution: unrestricted shell vs scope-enforced runner    │
│ - Expanded Nikto/Gobuster session log parsers                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: Tool Catalog & Workflow Integration                           │
│ - Dynamic tool status inspection in Tool Catalog GUI                   │
│ - Amass Go binary and Nuclei automated installer guidance              │
│ - Context-aware tool launching from project workflows                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 6: Guided & Manual Penetration Testing Workflows                 │
│ - 9-stage guided pentest wizard with task checklists                   │
│ - Real-time progress tracker and evidence binding                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 7: AI Copilot Multi-Provider Architecture & Pentester Approval  │
│ - Modularize core/ai_copilot.py into ai/providers/ (OpenAI, Local)     │
│ - Mandatory 2-step Pentester Command Approval modal with audit trail   │
│ - Automated credential storage & pre-flight secret redaction           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 8: Vulnerability & Evidence Management System                    │
│ - One-click status transitions (Verify, Remediate, False Positive)     │
│ - Screenshot viewer with embedded zoom in Evidence Vault               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 9: 2D & 3D Network Visualization Hardening                       │
│ - Level-of-Detail (LOD) optimization for large subnets (>500 hosts)    │
│ - WebGL capability detection & automatic software fallback             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 10: Security Analytics & Dashboard Widgets                       │
│ - Apache ECharts / PyQtGraph real-time performance monitors            │
│ - Project vulnerability timeline & posture metrics                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASE 11: Professional Client Deliverables & Multi-Format Reporting   │
│ - Implement python-docx for native editable DOCX export                │
│ - Implement ReportLab for high-fidelity PDF layout                     │
│ - Jinja2-based customizable template architecture                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PHASES 12–15: CPENT Labs, Hardening, Full QA & Release Documentation   │
│ - CPENT practical lab isolation from client engagements                │
│ - Full regression test suite passing 100%                              │
│ - Comprehensive documentation (User Guide, Security Model, Changelog)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Immediate Next Step: Phase 1 Action Plan

Upon receiving user approval, Phase 1 execution will perform targeted, non-breaking stability enhancements:
1. **Database Covering Indexes:** Add non-destructive indexes (`CREATE INDEX IF NOT EXISTS`) on `asset_nodes(project_id)`, `findings(project_id)`, and `target_scopes(project_id)` to speed up GUI rendering under large datasets.
2. **Eliminate 60 Deprecation Warnings:** Modernize SSL protocol check tests in `tests/test_tls_security_analyzer.py` and `modules/vuln/verifier.py` to keep test logs completely clean.
3. **Repository Workspace Hygiene:** Move legacy `*.bak_*` files into `.archive/` to restore clean directory tree readability while preserving rollback safety.
4. **Verification Gate:** Re-run the full 744-test suite to verify 0 failures and 0 warnings.

