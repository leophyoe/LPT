"""Scanners-Box open-source security tools catalog.

Inspired by We5ter/Scanners-Box (https://github.com/We5ter/Scanners-Box).
A curated knowledge base and categorization matrix of open-source penetration testing
and security auditing scanners across 12 primary domains.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ScannersBoxItem:
    name: str
    display_name: str
    category: str
    description: str
    github_url: str
    install_command: str
    language: str
    tags: List[str]
    binary_name: Optional[str] = None

    @property
    def is_installed_on_host(self) -> bool:
        if self.binary_name:
            return shutil.which(self.binary_name) is not None
        return False


class ScannersBoxCatalog:
    """Arsenal directory of curated open-source security scanners and tools."""

    CATEGORIES = [
        "Subdomain & OSINT",
        "Port & Network Scanners",
        "Web Application Scanners",
        "Directory & Route Fuzzers",
        "Database & SQL Injection",
        "WAF & Firewall Fingerprinting",
        "Password & Credential Auditing",
        "Cloud Security & Posture",
        "Source Code Security (SAST/SCA)",
        "Mobile Security (Android/iOS)",
        "Memory Forensics & Reverse Eng",
        "Active Directory & Network Protocols",
    ]

    ITEMS: List[ScannersBoxItem] = [
        # 1. Subdomain & OSINT
        ScannersBoxItem(
            name="amass",
            display_name="OWASP Amass",
            category="Subdomain & OSINT",
            description="In-depth attack surface mapping and external asset discovery using open source information gathering and active recon techniques.",
            github_url="https://github.com/owasp-amass/amass",
            install_command="sudo apt install amass or go install -v github.com/owasp-amass/amass/v4/...@master",
            language="Go",
            tags=["subdomain", "dns", "osint", "mapping"],
            binary_name="amass",
        ),
        ScannersBoxItem(
            name="sublist3r",
            display_name="Sublist3r",
            category="Subdomain & OSINT",
            description="Fast subdomains enumeration tool designed to enumerate subdomains of websites using OSINT.",
            github_url="https://github.com/aboul3la/Sublist3r",
            install_command="pip install sublist3r or git clone https://github.com/aboul3la/Sublist3r.git",
            language="Python",
            tags=["subdomain", "osint", "search-engine"],
            binary_name="sublist3r",
        ),
        ScannersBoxItem(
            name="theharvester",
            display_name="theHarvester",
            category="Subdomain & OSINT",
            description="E-mails, subdomains, and names harvester using search engines, PGP key servers, and SHODAN database.",
            github_url="https://github.com/laramies/theHarvester",
            install_command="pip install theHarvester or sudo apt install theharvester",
            language="Python",
            tags=["osint", "emails", "subdomain"],
            binary_name="theHarvester",
        ),

        # 2. Port & Network Scanners
        ScannersBoxItem(
            name="nmap",
            display_name="Nmap Network Scanner",
            category="Port & Network Scanners",
            description="Network exploration and security auditing tool. Supports TCP/UDP scanning, OS detection, service versioning, and NSE scripts.",
            github_url="https://github.com/nmap/nmap",
            install_command="sudo apt install nmap",
            language="C/C++",
            tags=["port-scanner", "network", "nse", "discovery"],
            binary_name="nmap",
        ),
        ScannersBoxItem(
            name="masscan",
            display_name="Masscan",
            category="Port & Network Scanners",
            description="Ultra-fast Internet port scanner capable of scanning the entire Internet in under 6 minutes using asynchronous packet transmission.",
            github_url="https://github.com/robertdavidgraham/masscan",
            install_command="sudo apt install masscan",
            language="C",
            tags=["port-scanner", "asynchronous", "high-speed"],
            binary_name="masscan",
        ),
        ScannersBoxItem(
            name="rustscan",
            display_name="RustScan",
            category="Port & Network Scanners",
            description="Fast port scanner built in Rust that automatically pipes discovered open ports directly into Nmap.",
            github_url="https://github.com/RustScan/RustScan",
            install_command="cargo install rustscan or download Debian .deb release",
            language="Rust",
            tags=["rust", "fast", "nmap-pipe"],
            binary_name="rustscan",
        ),

        # 3. Web Application Scanners
        ScannersBoxItem(
            name="zaproxy",
            display_name="OWASP ZAP",
            category="Web Application Scanners",
            description="Leading open-source web application security scanner, dynamic testing tool (DAST), and interception proxy.",
            github_url="https://github.com/zaproxy/zaproxy",
            install_command="sudo apt install zaproxy or launch /usr/local/bin/zap.sh",
            language="Java",
            tags=["proxy", "dast", "spider", "fuzzer"],
            binary_name="zap.sh",
        ),
        ScannersBoxItem(
            name="nuclei",
            display_name="Nuclei Vulnerability Scanner",
            category="Web Application Scanners",
            description="Fast and customizable vulnerability scanner based on simple YAML-based DSL templates.",
            github_url="https://github.com/projectdiscovery/nuclei",
            install_command="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            language="Go",
            tags=["templates", "cve", "dast", "yaml"],
            binary_name="nuclei",
        ),
        ScannersBoxItem(
            name="nikto",
            display_name="Nikto Web Server Scanner",
            category="Web Application Scanners",
            description="Web server scanner which performs comprehensive tests against web servers for multiple items including dangerous files and outdated versions.",
            github_url="https://github.com/sullo/nikto",
            install_command="sudo apt install nikto libxml-writer-perl",
            language="Perl",
            tags=["web", "server-audit", "cgi"],
            binary_name="nikto",
        ),
        ScannersBoxItem(
            name="ptk",
            display_name="OWASP PTK (Penetration Testing Kit)",
            category="Web Application Scanners",
            description="Browser-inspired web penetration testing workbench providing R-Builder request tampering, JWT lab, encoders, and SCA analysis.",
            github_url="https://github.com/DenisPodgurskii/pentestkit",
            install_command="Built-in native engine: modules/web/ptk_engine.py",
            language="Python",
            tags=["r-builder", "jwt", "encoder", "sca"],
            binary_name="ptk",
        ),

        # 4. Directory & Route Fuzzers
        ScannersBoxItem(
            name="gobuster",
            display_name="Gobuster Directory Fuzzer",
            category="Directory & Route Fuzzers",
            description="Tool used to brute-force URIs (directories and files), DNS subdomains, and virtual host names.",
            github_url="https://github.com/OJ/gobuster",
            install_command="sudo apt install gobuster or go install github.com/OJ/gobuster/v3@latest",
            language="Go",
            tags=["fuzzing", "directory", "vhost", "dns"],
            binary_name="gobuster",
        ),
        ScannersBoxItem(
            name="ffuf",
            display_name="ffuf (Fast Web Fuzzer)",
            category="Directory & Route Fuzzers",
            description="Fast web fuzzer written in Go designed to discover hidden resources and parameters.",
            github_url="https://github.com/ffuf/ffuf",
            install_command="go install github.com/ffuf/ffuf/v2@latest",
            language="Go",
            tags=["fuzzer", "fast", "parameters"],
            binary_name="ffuf",
        ),
        ScannersBoxItem(
            name="dirsearch",
            display_name="dirsearch",
            category="Directory & Route Fuzzers",
            description="Advanced command-line tool designed to brute force directories and files in webservers.",
            github_url="https://github.com/maurosoria/dirsearch",
            install_command="pip install dirsearch",
            language="Python",
            tags=["directory", "wordlist", "bruteforce"],
            binary_name="dirsearch",
        ),

        # 5. Database & SQL Injection
        ScannersBoxItem(
            name="sqlmap",
            display_name="SQLMap Injection Engine",
            category="Database & SQL Injection",
            description="Automatic SQL injection and database takeover tool supporting error-based, boolean-blind, time-blind, and UNION query techniques.",
            github_url="https://github.com/sqlmapproject/sqlmap",
            install_command="sudo apt install sqlmap or source/web/sqlmap",
            language="Python",
            tags=["sqli", "database", "takeover", "tamper"],
            binary_name="sqlmap",
        ),
        ScannersBoxItem(
            name="ghauri",
            display_name="Ghauri",
            category="Database & SQL Injection",
            description="Advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws.",
            github_url="https://github.com/r0oth3x49/ghauri",
            install_command="pip install ghauri",
            language="Python",
            tags=["sqli", "bypass", "waf-evasion"],
            binary_name="ghauri",
        ),

        # 6. WAF & Firewall Fingerprinting
        ScannersBoxItem(
            name="wafw00f",
            display_name="WAFW00F Firewall Fingerprinter",
            category="WAF & Firewall Fingerprinting",
            description="Identifies and fingerprints Web Application Firewalls (WAFs) protecting a website by sending normal and malicious HTTP requests.",
            github_url="https://github.com/EnableSecurity/wafw00f",
            install_command="pip install wafw00f or source/web/wafw00f",
            language="Python",
            tags=["waf", "firewall", "fingerprint"],
            binary_name="wafw00f",
        ),

        # 7. Password & Credential Auditing
        ScannersBoxItem(
            name="hydra",
            display_name="THC-Hydra Network Logon Cracker",
            category="Password & Credential Auditing",
            description="Very fast network logon cracker supporting numerous protocols (SSH, FTP, HTTP-POST, RDP, SMB, MySQL, etc.).",
            github_url="https://github.com/vanhauser-thc/thc-hydra",
            install_command="sudo apt install hydra",
            language="C",
            tags=["password", "bruteforce", "network-auth"],
            binary_name="hydra",
        ),
        ScannersBoxItem(
            name="hashcat",
            display_name="Hashcat Password Recovery",
            category="Password & Credential Auditing",
            description="World's fastest and most advanced password recovery utility supporting rule-based attacks, combinator, and mask attacks.",
            github_url="https://github.com/hashcat/hashcat",
            install_command="sudo apt install hashcat",
            language="C",
            tags=["password-cracking", "gpu", "hashes"],
            binary_name="hashcat",
        ),
        ScannersBoxItem(
            name="john",
            display_name="John the Ripper",
            category="Password & Credential Auditing",
            description="Rapid password cracking tool primarily designed for Unix password hashes, zip, and office documents.",
            github_url="https://github.com/openwall/john",
            install_command="sudo apt install john",
            language="C",
            tags=["password", "unix-hash", "wordlist"],
            binary_name="john",
        ),

        # 8. Cloud Security & Posture
        ScannersBoxItem(
            name="prowler",
            display_name="Prowler Cloud Security Tool",
            category="Cloud Security & Posture",
            description="Open Source security tool to perform AWS, GCP, and Azure security best practices assessments and compliance audits.",
            github_url="https://github.com/prowler-cloud/prowler",
            install_command="pip install prowler",
            language="Python",
            tags=["cloud", "aws", "gcp", "azure", "compliance"],
            binary_name="prowler",
        ),
        ScannersBoxItem(
            name="scoutsuite",
            display_name="ScoutSuite Multi-Cloud Auditor",
            category="Cloud Security & Posture",
            description="Open source multi-cloud security-auditing tool providing clear HTML risk dashboards.",
            github_url="https://github.com/nccgroup/ScoutSuite",
            install_command="pip install scoutsuite",
            language="Python",
            tags=["cloud", "audit", "multi-cloud"],
            binary_name="scout",
        ),

        # 9. Source Code Security (SAST/SCA)
        ScannersBoxItem(
            name="bandit",
            display_name="Bandit Python AST Analyzer",
            category="Source Code Security (SAST/SCA)",
            description="Security linter designed to find common security issues in Python code using Abstract Syntax Trees.",
            github_url="https://github.com/PyCQA/bandit",
            install_command="pip install bandit pyyaml stevedore",
            language="Python",
            tags=["sast", "python", "ast"],
            binary_name="bandit",
        ),
        ScannersBoxItem(
            name="semgrep",
            display_name="Semgrep Static Analysis",
            category="Source Code Security (SAST/SCA)",
            description="Fast, open-source static analysis engine for finding bugs and enforcing code standards with pattern matching.",
            github_url="https://github.com/semgrep/semgrep",
            install_command="pip install semgrep",
            language="OCaml/Python",
            tags=["sast", "rules", "multi-language"],
            binary_name="semgrep",
        ),
        ScannersBoxItem(
            name="gitleaks",
            display_name="Gitleaks Secret Scanner",
            category="Source Code Security (SAST/SCA)",
            description="SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos.",
            github_url="https://github.com/gitleaks/gitleaks",
            install_command="sudo apt install golang-go && go install github.com/zricethezav/gitleaks/v8@latest",
            language="Go",
            tags=["secrets", "git", "tokens"],
            binary_name="gitleaks",
        ),
        ScannersBoxItem(
            name="trivy",
            display_name="Trivy Vulnerability Scanner",
            category="Source Code Security (SAST/SCA)",
            description="Comprehensive security scanner for container images, file systems, Git repositories, and Kubernetes.",
            github_url="https://github.com/aquasecurity/trivy",
            install_command="sudo apt install trivy or curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
            language="Go",
            tags=["sca", "container", "cve", "supply-chain"],
            binary_name="trivy",
        ),

        # 10. Mobile Security (Android/iOS)
        ScannersBoxItem(
            name="mobsf",
            display_name="MobSF (Mobile Security Framework)",
            category="Mobile Security (Android/iOS)",
            description="Automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework.",
            github_url="https://github.com/MobSF/Mobile-Security-Framework-MobSF",
            install_command="docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest",
            language="Python",
            tags=["mobile", "android", "ios", "apk"],
            binary_name="mobsf",
        ),
        ScannersBoxItem(
            name="jadx",
            display_name="JADX Dex to Java Decompiler",
            category="Mobile Security (Android/iOS)",
            description="Command line and GUI tools for producing Java source code from Android Dex and APK files.",
            github_url="https://github.com/skylot/jadx",
            install_command="sudo apt install jadx or download release binary from GitHub",
            language="Java",
            tags=["decompiler", "android", "apk", "reverse"],
            binary_name="jadx",
        ),
        ScannersBoxItem(
            name="apktool",
            display_name="Apktool Reverse Engineering",
            category="Mobile Security (Android/iOS)",
            description="Tool for reverse engineering 3rd party, closed, binary Android apps. Decodes resources and disassembles Smali.",
            github_url="https://github.com/iBotPeaches/Apktool",
            install_command="sudo apt install apktool",
            language="Java",
            tags=["android", "smali", "apk-decode"],
            binary_name="apktool",
        ),

        # 11. Memory Forensics & Reverse Eng
        ScannersBoxItem(
            name="volatility3",
            display_name="Volatility 3 Memory Forensics",
            category="Memory Forensics & Reverse Eng",
            description="Advanced memory forensics analysis framework for incident responders, malware analysts, and penetration testers.",
            github_url="https://github.com/volatilityfoundation/volatility3",
            install_command="pip install volatility3 or source/system/volatility3",
            language="Python",
            tags=["forensics", "ram", "memory-dump", "incident-response"],
            binary_name="vol.py",
        ),
        ScannersBoxItem(
            name="binwalk",
            display_name="Binwalk Firmware Analyzer",
            category="Memory Forensics & Reverse Eng",
            description="Fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.",
            github_url="https://github.com/ReFirmLabs/binwalk",
            install_command="sudo apt install binwalk",
            language="Python",
            tags=["firmware", "iot", "extraction"],
            binary_name="binwalk",
        ),
        ScannersBoxItem(
            name="radare2",
            display_name="Radare2 Reverse Engineering",
            category="Memory Forensics & Reverse Eng",
            description="Unix-like reverse engineering framework and commandline toolset with disassembler and debugger.",
            github_url="https://github.com/radareorg/radare2",
            install_command="sudo apt install radare2 or cd source/reverse_engineering/radare2 && sys/install.sh",
            language="C",
            tags=["reversing", "disassembler", "debugging"],
            binary_name="r2",
        ),

        # 12. Active Directory & Network Protocols
        ScannersBoxItem(
            name="impacket",
            display_name="Impacket Protocol Toolkit",
            category="Active Directory & Network Protocols",
            description="Collection of Python classes for working with network protocols (SMB, MSRPC, Kerberos, LDAP) and credential dumping.",
            github_url="https://github.com/fortra/impacket",
            install_command="pip install impacket",
            language="Python",
            tags=["active-directory", "smb", "kerberos", "ldap"],
            binary_name="impacket",
        ),
        ScannersBoxItem(
            name="netexec",
            display_name="NetExec (CrackMapExec)",
            category="Active Directory & Network Protocols",
            description="Network service exploitation tool that helps automate assessing the security of large Active Directory networks.",
            github_url="https://github.com/Pennyw0rth/NetExec",
            install_command="pip install netexec",
            language="Python",
            tags=["active-directory", "network-auth", "post-exploitation"],
            binary_name="netexec",
        ),
    ]

    @classmethod
    def get_all_items(cls) -> List[ScannersBoxItem]:
        return list(cls.ITEMS)

    @classmethod
    def get_by_category(cls, category: str) -> List[ScannersBoxItem]:
        return [i for i in cls.ITEMS if i.category == category]

    @classmethod
    def search(cls, query: str, category: Optional[str] = None) -> List[ScannersBoxItem]:
        q = query.lower().strip()
        results = cls.ITEMS
        if category and category != "All Categories":
            results = [i for i in results if i.category == category]
        if not q:
            return results
        return [
            i for i in results
            if q in i.name.lower()
            or q in i.display_name.lower()
            or q in i.description.lower()
            or any(q in t.lower() for t in i.tags)
        ]

