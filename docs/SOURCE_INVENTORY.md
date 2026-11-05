# Source & Third-Party Component Inventory

This document tracks all external open-source repositories, components, licenses, integration strategies, and architectural decisions.

---

## 1. Component Tracking Matrix

| Component | Official Repository | License | Integration Strategy | Host Status | Decision / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Nmap** | [nmap/nmap](https://github.com/nmap/nmap) | Nmap Public Source License (NPSL) v0.92 | Subprocess adapter + XML output parser | Installed (`v7.94SVN`) | **Approved**: Selected for initial Network Discovery workflow. Uses host executable with strict argument controls. |
| **OWASP ZAP** | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Apache 2.0 | Daemon service + REST API client | Installed (`zap.sh` in `/usr/local/bin`) | **Approved**: Primary engine for web application spidering and active scanning. |
| **Nuclei** | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Subprocess adapter + JSON output parser | Not installed | **Candidate**: Fast, template-based vulnerability scanner. High candidate for Phase 8. |
| **Wireshark / Tshark** | [wireshark/wireshark](https://github.com/wireshark/wireshark) | GPL v2.0 | Tshark CLI adapter + PCAP parser | Not installed | **Candidate**: Useful for packet capture analysis and passive traffic inspection. |
| **MobSF** | [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | GPL v3.0 | Isolated container / REST API | Not installed | **Candidate**: Mobile static/dynamic analysis. Best run via dedicated container due to heavy dependencies. |
| **SQLMap** | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) | GPL v2.0 | Subprocess adapter / Python module | Not installed | **Investigate**: Powerful SQL injection engine. Requires strict lab confirmation and authorization guards. |
| **Semgrep** | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL 2.1 / Proprietary components | Subprocess adapter (OSS CLI) | Not installed | **Candidate**: Static application security testing (SAST) for source-code security. |
| **Bandit** | [PyCQA/bandit](https://github.com/PyCQA/bandit) | Apache 2.0 | Python library / CLI adapter | Not installed | **Approved**: Lightweight Python code security analysis. |
| **Trivy** | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache 2.0 | Subprocess adapter + JSON parser | Not installed | **Approved**: Container image and dependency vulnerability scanner. |
| **Volatility 3** | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) | VSL v1.0 | Python library / isolated service | Not installed | **Candidate**: Memory forensics analysis for system investigations. |

---

## 2. Integration Guidelines

1. **No Blind Code Merges**: Large C/C++/Java codebases (such as Nmap, Wireshark, ZAP, Ghidra) are executed as isolated services or subprocesses via dedicated adapter classes, rather than embedding foreign source trees directly into Python.
2. **License Compliance**: Copyleft-licensed tools (GPL/LGPL) must maintain boundary separation through subprocess/API execution to prevent license contamination of the core platform.
3. **Reproducible Tool Versions**: The execution engine records the exact runtime version of any tool executed (`--version`) and embeds it into project execution logs and evidence records.
