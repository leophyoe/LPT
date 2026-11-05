# Phase 2.5 UX Redesign Specification & Architecture Report

**Project:** CyberSecuritySuite / LPT Workstation  
**Author:** Senior Python/PySide6 Software Architect & UI/UX Engineer  
**Date:** 2026-11-05  
**Scope:** Design System, Navigation Architecture, Workspace Visual Layouts & 5-Step Nmap Ingestion Wizard  
**Status:** DESIGN SPECIFICATION APPROVED FOR IMPLEMENTATION  

---

## 1. Design System & Visual Hierarchy

### 1.1 Color Palette: Professional Navy / Slate
The visual design transitions to an enterprise-grade cybersecurity workstation aesthetic based on calibrated Navy and Slate tokens, completely eliminating neon accents and harsh saturated borders.

| Token | Dark Mode Value | Light Mode Value | Semantic Role |
| :--- | :--- | :--- | :--- |
| `BG_BASE` | `#090D16` (Deep Navy) | `#F8FAFC` (Pure Daylight Slate) | Root window & workspace canvas |
| `BG_SURFACE` | `#0F172A` (Slate 900) | `#FFFFFF` (Pure White) | Cards, modals, containers, tables |
| `BG_ELEVATED` | `#1E293B` (Slate 800) | `#F1F5F9` (Slate 100) | Headers, toolbars, sub-nav bars |
| `BORDER_DEFAULT` | `#334155` (Slate 700) | `#CBD5E1` (Slate 300) | Standard component outlines |
| `BORDER_FOCUSED` | `#38BDF8` (Sky Blue) | `#2563EB` (Royal Blue) | Active items, focused inputs |
| `TEXT_PRIMARY` | `#F8FAFC` (Slate 50) | `#0F172A` (Slate 900) | Headings, table cells, primary labels |
| `TEXT_MUTED` | `#94A3B8` (Slate 400) | `#64748B` (Slate 500) | Subtitles, metadata, timestamps |
| `STATUS_SUCCESS` | `#10B981` (Emerald) | `#059669` (Dark Emerald) | Authorized scope, live hosts, passed |
| `STATUS_WARNING` | `#F59E0B` (Amber) | `#D97706` (Dark Amber) | Scope warnings, suspected issues |
| `STATUS_DANGER` | `#EF4444` (Rose Red) | `#DC2626` (Dark Red) | Blocked scope, critical/high findings |

### 1.2 Typography & Font Stack
Standardizes font rendering across Linux desktop environments:
- **Font Stack Fallback:** `Inter`, `Noto Sans`, `Noto Sans Myanmar`, `Ubuntu`, `DejaVu Sans`, `sans-serif`.
- **Monospace Stack:** `JetBrains Mono`, `Fira Code`, `DejaVu Sans Mono`, `Ubuntu Mono`, `monospace`.
- **Minimum Body Size:** Standardized to **13px / 14px** across all views and dialogs. Subtitles and auxiliary badges are constrained to minimum **10px / 11px**, eliminating microscopic 8px labels.
- **Line Heights & Spacing:** Generous line spacing (1.4–1.5x) to maintain effortless scanning during long penetration testing engagements.

---

## 2. Streamlined Navigation Architecture

The sidebar navigation is simplified from 6 complex headers down into **5 clear functional sections**, preserving 100% of underlying routes, deep-links, and test contracts:

```
┌───────────────────────────────────────────────────┐
│ CyberSecuritySuite                                │
│ Professional Pentest Workstation                  │
├───────────────────────────────────────────────────┤
│ ◈ Project: Alpha Engagement (Scope: 3 CIDRs)      │
├───────────────────────────────────────────────────┤
│ WORKSPACE                                         │
│   ⌂  Dashboard                                    │
│   ◈  Engagements                                  │
│   🛰️ Digital Assets                              │
│                                                   │
│ METHODOLOGY                                       │
│   1. Information Gathering                        │
│   2. Enumeration & Mapping                        │
│   3. Vulnerability Assessment                     │
│   4. Exploitation                                 │
│   5. Reporting & Evidence                         │
│                                                   │
│ TOOLS                                             │
│   ⚙️ Tool Library                                 │
│   💻 Terminal Console                             │
│                                                   │
│ INTELLIGENCE                                      │
│   🤖 AI Security Copilot                          │
│   🎓 CPENT Academy & Labs                         │
│                                                   │
│ SYSTEM                                            │
│   ⚙️ Settings                                     │
├───────────────────────────────────────────────────┤
│ ☀ Light Mode / 🌙 Dark Mode                       │
└───────────────────────────────────────────────────┘
```

### Route & Backward Compatibility Mapping
| Sidebar Item | Identifier | Target Workspace / Sub-Tab | Backward Compatible Aliases |
| :--- | :--- | :--- | :--- |
| **Dashboard** | `dashboard` | Workspace 0, Sub-Tab 1 | `btn_dashboard` |
| **Engagements** | `projects` | Workspace 0, Sub-Tab 0 | `btn_projects`, `scope`, `audit` |
| **Digital Assets** | `assets` | Workspace 0, Sub-Tab 2 | `info_gathering`, `asset_discovery` |
| **Information Gathering** | `info_gathering` | Workspace 1, Sub-Tab 2 (OSINT & Recon) | `recon`, `footprint`, `osint` |
| **Enumeration & Mapping** | `enumeration` | Workspace 1, Sub-Tab 0 (Network Discovery) | `enum`, `ports`, `discovery`, `studio`, `topology` |
| **Vulnerability Assessment**| `vulnerability` | Workspace 1, Sub-Tab 1 (Web & Vuln) | `vuln`, `web`, `assessment` |
| **Exploitation** | `post_exploitation` | Workspace 1, Sub-Tab 7 (Pivoting & AD) | `pivoting`, `ad`, `exploit` |
| **Reporting & Evidence** | `reporting` | Workspace 2, Sub-Tab 0 / 1 (Reports & Findings) | `reports`, `findings` |
| **Tool Library** | `tools` | Workspace 1, Sub-Tab 3 (Tools Dashboard) | `terminal_tools` |
| **Terminal Console** | `terminal` | Toggle bottom persistent terminal panel | `terminal_widget` |
| **AI Security Copilot** | `ai_copilot` | Toggle right AI Copilot assistant panel | `btn_toggle_ai_panel` |
| **CPENT Academy & Labs** | `cpent_labs` | Workspace 3 (CPENT Labs View) | `exploit_lab`, `cpent` |
| **Settings** | `settings` | System Settings & AI Model Router Dialog | `btn_ai_settings` |

---

## 3. Workspace Layout & Ergonomics

### 3.1 Executive Dashboard (`dashboard_view.py`)
- **Primary Operational Metric Strip:** Clean top banner displaying:
  - **Total Assets** (with active count)
  - **Live Hosts** (hosts responding to ICMP / TCP SYN)
  - **Open Ports** (total discovered services)
  - **Vulnerabilities** (total identified security findings)
  - **Critical Findings** (high-visibility red badge)
  - **Active Engagement** (project name, client name, authorized scope summary)
- **Zero-State Call to Action:** When no hosts or scans exist, clear onboarding cards guide the operator to (1) "Define Authorized Target Scope" or (2) "Launch Nmap Discovery Scan".
- **Elimination of Mock Numbers:** All metrics strictly compute against the active SQLite project records.

### 3.2 Digital Assets Workspace (`assets_view.py`)
- **Table Space Maximization:** Remove bulky multi-card headers by default; allocate 80%+ vertical window height to the Asset Grid.
- **Collapsible Inspector:** Asset details inspector can be smoothly toggled or collapsed with a single click, allowing the Asset Table to expand across the full window width.
- **Readable Table Columns:** Set explicit column budgets (IP/Host: 160px, Type: 100px, Open Ports: 200px, Risk Posture: 120px, Last Seen: 140px).

---

## 4. Five-Step Nmap Review & Synchronization Wizard

The `ScannerResultPreviewDialog` is completely restructured from a cramped vertical scroll layout into an intuitive **Five-Step Modal Wizard**:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Review & Confirm Scan Ingestion — NMAP                                 │
├────────────────────────────────────────────────────────────────────────┤
│ [1. Scan Summary]  [2. Discovered Hosts]  [3. Scope Validation]        │
│ [4. Findings Review]  [5. Confirm Import]                              │
├────────────────────────────────────────────────────────────────────────┤
│ STEP 1: SCAN SUMMARY                                                   │
│   • Target Engagement: Alpha Corporate Audit                           │
│   • Command: nmap -sV -sC -T4 10.10.10.0/24                            │
│   • Discovered Hosts: 3 hosts up (2 In-Scope, 1 Out-of-Scope)          │
│   • Scan Duration: 14.2s                                               │
│   • Raw Output Status: Safely saved to Evidence Vault                  │
├────────────────────────────────────────────────────────────────────────┤
│ STEP 2: DISCOVERED HOSTS & SERVICES                                    │
│   • Clean, full-height table of discovered IPs, hostnames & open ports │
│   • Differentiates ✨ NEW ASSET vs 🔄 EXISTING / UPDATE                │
├────────────────────────────────────────────────────────────────────────┤
│ STEP 3: SCOPE VALIDATION & AUTHORIZATION GATE                          │
│   • Visual list of in-scope vs blocked targets                         │
│   • Explains in plain language WHY each target is blocked              │
│   • 1-Click "Authorize Target Subnet in Scope" button with RoE prompt  │
├────────────────────────────────────────────────────────────────────────┤
│ STEP 4: FINDINGS & VULNERABILITY TRIAGE                                │
│   • Lists detected security findings separated from host observations  │
│   • Checkboxes to include/exclude specific findings                    │
├────────────────────────────────────────────────────────────────────────┤
│ STEP 5: CONFIRM & SYNCHRONIZE                                          │
│   • Final reconciliation summary: X hosts to add, Y findings to log    │
│   • Clear distinction: Evidence is ALREADY preserved; this step ONLY   │
│     persists structured AssetNode and Finding records                  │
│   • [Cancel (Keep Raw Evidence Only)]    [Confirm & Sync to Project]   │
└────────────────────────────────────────────────────────────────────────┘
```

### Security & Invariant Guarantees:
1. **Never Automatically Authorize:** Discovered targets outside authorized scope remain strictly blocked unless the operator explicitly reviews and confirms scope expansion.
2. **Fail-Closed Import Button:** The "Confirm & Sync" button is disabled if zero authorized records are selected.
3. **Evidence Decoupling:** Raw command output is preserved as Evidence regardless of whether structured import succeeds or is cancelled.
4. **No Auto-Promotion to Confirmed:** Host discovery records remain classified as `OBSERVED`, never automatically elevated to `CONFIRMED` vulnerabilities.

---

## 5. Terminal Console Presentation

- **Readability:** Monospace font size set to 13px (`JetBrains Mono`, `Fira Code`, `DejaVu Sans Mono`).
- **ANSI Output Rendering:** High-contrast color palette for standard ANSI color codes (30–37, 90–97).
- **Execution Bar:** High-density, unclipped top control bar with clear buttons:
  - `📋 Copy Buffer`
  - `💾 Save Evidence`
  - `📥 Review & Ingest`
  - `🤖 Ask Copilot`
  - `⤢ Maximize / Restore`
  - `✕ Hide`

