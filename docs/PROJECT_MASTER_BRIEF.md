# Project Master Brief: CyberSecuritySuite

**Document Version:** 1.0.0  
**Status:** Foundation & Architecture Stage  
**Primary Environment:** Ubuntu Linux (x86_64)  
**Proposed Application Type:** Native Desktop Application (Python + PySide6)  
**Temporary Working Name:** `CyberSecuritySuite` (Candidate names: FortiForge, SecForge AI, VulnForge, RedCore Security pending trademark/domain review)  
**Primary Learning Objective:** EC-Council CPENT Preparation via original labs and study workflows  

---

## 1. Executive Summary & Philosophy

CyberSecuritySuite is an AI-assisted, modular desktop cybersecurity and penetration testing platform. Rather than serving as an external wrapper or launcher for command-line tools, the system is designed from the source-code level up to provide:
1. **Source-level understanding & reuse**: Integrate, study, and customize open-source security tools into cohesive workflows.
2. **Integrated Terminal & Execution Engine**: PTY streaming, timeout controls, argument sanitization, exit code capture, and structured parsing into actionable models.
3. **AI Security Assistant**: Transparent, privacy-conscious triage of findings, scan explanation, command risk review, and false-positive filtering.
4. **Findings & Evidence Management**: Standardized findings with CVSS scoring, reproduction steps, cryptographic evidence hashing, and audit trails.
5. **Multi-Format Reporting**: Professional HTML (with print-to-PDF stylesheet support), Markdown, and JSON reports with executive summaries and technical deep-dives.
6. **CPENT-Oriented Learning Platform**: Original, isolated, and intentionally vulnerable practical labs, study modules, and AI tutoring for penetration testing mastery without infringing on proprietary EC-Council materials.

---

## 2. Target Assessment Domains

1. **Network Security**: Host discovery, port/service scanning, version identification, traffic inspection (e.g. Nmap, Wireshark/Tshark).
2. **Web Application & API Security**: HTTP/S inspection, proxying, spidering, injection detection, API endpoint testing, header analysis.
3. **Android & Mobile Security**: Static APK analysis, manifest/permission inspection, secrets scanning, certificate validation.
4. **System Security & Enterprise**: Linux/Windows auditing, permission checking, Active Directory assessment concepts, process inspection.
5. **Wireless Security**: Wi-Fi inventory, configuration audit, capture analysis.
6. **Cloud Security**: Read-only posture assessment (AWS, GCP, Azure), IAM and storage exposure checks.
7. **Source-Code Security**: SAST, dependency auditing, secret detection (Semgrep, Bandit, Gitleaks, Trivy).
8. **Reverse Engineering & Forensics**: Binary metadata inspection, strings, symbol analysis, memory forensics workflows in isolated environments.

---

## 3. Strict Operating & Ethical Principles

- **Authorization First**: No active testing without explicit, recorded project scope and written authorization.
- **Safety & Isolation**: Dangerous operations (exploits, brute-forcing, active testing) require explicit user confirmation.
- **Privacy & Redaction**: Credentials, tokens, private keys, and sensitive data are redacted prior to AI prompts or external processing.
- **No Hallucinations / Fabrication**: Findings must be grounded in verified tool outputs and evidence artifacts.
- **Educational Integrity**: CPENT materials are 100% original, respecting EC-Council trademarks and copyrights.
