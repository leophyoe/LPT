# LPT Workstation — Phase 0: Dependency & Tool Ecosystem Audit
**Document ID:** `docs/audit/DEPENDENCY_AUDIT.md`  
**Audit Date:** 2026-11-05  
**Auditor:** Senior Software Architect & Systems Engineer  
**Status:** COMPLETED — ENVIRONMENT & DEPENDENCY ASSESSMENT  

---

## 1. Executive Summary

This dependency audit evaluates the Python runtime environment, virtual environment package installation status, discrepancy between configuration manifests, external binary tools installed on the host operating system, and missing libraries required for future phases (such as ReportLab and python-docx).

---

## 2. Python Runtime Environment

* **Python Version:** `Python 3.12.3` (64-bit Linux ELF)
* **Virtual Environment Path:** `/home/leo/Desktop/cybersecuritysuite/.venv`
* **Virtual Environment Python:** `/home/leo/Desktop/cybersecuritysuite/.venv/bin/python3`
* **Pip Version:** `pip 24.0`
* **System Hardware:** AMD Ryzen 5 5600U (6 cores / 12 threads), 14 GiB RAM (~10 GiB free/cache available). Fits well within the 8 GiB RAM target baseline.

---

## 3. Python Package Audit (Installed vs Declared)

| Package Name | Installed Version | Declared in `requirements.txt` | Declared in `pyproject.toml` | Status / Purpose |
|---|---|---|---|---|
| **PySide6** | 6.12.0 | `PySide6>=6.6.0` | `PySide6>=6.6.0` | **INSTALLED & VERIFIED** (Main GUI framework) |
| **PySide6_Essentials** | 6.12.0 | Implicit | Implicit | **INSTALLED & VERIFIED** (QtCore, QtGui, QtWidgets) |
| **PySide6_Addons** | 6.12.0 | Implicit | Implicit | **INSTALLED & VERIFIED** (QtWebChannel, QtSvg) |
| **PySide6_WebEngine** | 6.12.0.140 | Implicit | Implicit | **INSTALLED & VERIFIED** (3D WebGL / xterm.js view) |
| **PySide6_Pdf** | 6.12.0.140 | Implicit | Implicit | **INSTALLED & VERIFIED** (QPdfWriter report generation) |
| **shiboken6** | 6.12.0 | Implicit | Implicit | **INSTALLED & VERIFIED** (C++/Python bindings) |
| **requests** | 2.34.2 | `requests>=2.31.0` | Missing | **INSTALLED & VERIFIED** (HTTP API requests) |
| **pytest** | 9.1.1 | `pytest>=8.0.0` | `pytest>=8.0.0` (dev) | **INSTALLED & VERIFIED** (Test runner) |
| **pytest-qt** | 4.5.0 | `pytest-qt>=4.4.0` | `pytest-qt>=4.4.0` (dev) | **INSTALLED & VERIFIED** (Qt GUI test automation) |
| **pytest-cov** | 7.1.0 | `pytest-cov>=4.1.0` | `pytest-cov>=4.1.0` (dev) | **INSTALLED & VERIFIED** (Code coverage tracking) |
| **Pygments** | 2.21.0 | Unlisted | Unlisted | **INSTALLED & VERIFIED** (Code syntax highlighting) |
| **ReportLab** | None | Unlisted | Unlisted | **MISSING** (Required for Phase 11 PDF engine) |
| **python-docx** | None | Unlisted | Unlisted | **MISSING** (Required for Phase 11 DOCX export) |
| **pyqtgraph** | None | Unlisted | Unlisted | **MISSING** (Target architecture for live charts) |
| **Pydantic** | None | Unlisted | Unlisted | **OPTIONAL** (Target architecture for data validation) |

---

## 4. Host System Security Tool Binary Audit

Audited via `core/registry.py::ToolRegistry` and system path inspection:

### 4.1 Native System Binaries Installed on Host PATH
* **Nmap (`/usr/bin/nmap`):** Version 7.94SVN detected. Full TCP/UDP scanning, OS detection, service versioning.
* **Masscan (`/usr/bin/masscan`):** Fast asynchronous SYN packet scanner installed.
* **Nikto (`/usr/bin/nikto`):** Web server vulnerability auditing scanner installed.
* **SQLMap (`/usr/bin/sqlmap`):** Automatic SQL injection and database takeover engine installed.
* **THC-Hydra (`/usr/bin/hydra`):** Network login brute-force cracker installed.
* **John the Ripper (`/usr/sbin/john`):** Multi-algorithm password hash cracker installed.
* **Hashcat (`/usr/bin/hashcat`):** High-performance rule-based password recovery engine installed.
* **Binwalk (`/usr/bin/binwalk`):** Firmware reverse engineering and extraction tool installed.
* **Wireshark (`/usr/bin/wireshark`):** Network packet analysis suite installed.
* **Gobuster (`/usr/bin/gobuster`):** Fast directory and DNS busting engine installed.
* **ffuf (`/usr/bin/ffuf`):** High-speed HTTP web fuzzer installed.

### 4.2 Local Python & Script Engines (100% Operational)
* **Active Directory / LDAP Enumerator (`modules/identity/ldap_adapter.py`):** Pure-Python LDAP/LDAPS client; requires zero external system packages.
* **TLS / SSL Security Analyzer (`modules/crypto/tls_adapter.py`):** Pure-Python TLS cipher, cert, and protocol analyzer.
* **c0desec Web Recon (`bin/c0desec`):** Python-based automated information gathering script.
* **OWASP PTK Engine (`modules/web/ptk_engine.py`):** Pure-Python web request security tester.
* **WAFW00F (`bin/wafw00f`):** Python firewall detector wrapper.
* **Volatility 3 (`source/system/volatility3/vol.py`):** Python 3 memory forensics framework.
* **OWASP ZAP (`bin/zap.sh`):** Local shell script wrapper for Zed Attack Proxy.

### 4.3 Missing or Unbuilt Binaries (Gracefully Handled / Future Phases)
* **OWASP Amass:** Wrapper in `bin/amass` exists, but underlying Go binary not installed.
* **Nuclei:** Not installed in `/usr/bin/nuclei`; template-based vuln engine planned for Phase 5.
* **Burp Suite:** Not in system PATH (expected in standard desktop environments).
* **Impacket & NetExec:** Source clones present in `source/network/`; Python libraries not compiled into `.venv`.
* **Radare2, Bandit, Semgrep, Gitleaks, Trivy, Prowler, ScoutSuite, JADX, MobSF:** Source repositories cloned in `source/`, available for optional local compilation in later phases.

---

## 5. Dependency Recommendations & Action Plan

1. **Phase 0 Safety:** No new package installations required for Phase 0.
2. **Phase 11 (Reporting):** Add `reportlab>=4.0.0` and `python-docx>=1.1.0` to `requirements.txt` and `pyproject.toml` when reaching the Client Reporting phase.
3. **Phase 10 (Charts):** Add `pyqtgraph>=0.13.0` for real-time live performance monitors.
4. **Environment Isolation:** Keep `pyproject.toml` synchronized with `requirements.txt`.

