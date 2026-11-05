"""30-Day CPENT Study Plan and practical preparation schedule.

Based on authorized public curriculum blueprints and community best practices.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class StudyDay:
    day: int
    week: int
    title: str
    focus_area: str
    topics: List[str]
    hands_on_tasks: List[str]
    recommended_tools: List[str] = field(default_factory=list)


CPENT_30_DAY_PLAN: List[StudyDay] = [
    # Week 1: Foundation, Reconnaissance & Web/API
    StudyDay(
        day=1,
        week=1,
        title="Pentesting Fundamentals & Lab Setup",
        focus_area="Methodology",
        topics=["Black/Grey/White box testing", "PTES and OWASP testing frameworks", "MITRE ATT&CK mapping", "Lab architecture"],
        hands_on_tasks=["Verify local assessment environment", "Verify Nmap, ZAP, and Python environments", "Setup isolated lab networks"],
        recommended_tools=["nmap", "wireshark", "python3"],
    ),
    StudyDay(
        day=2,
        week=1,
        title="Scoping, Legal Authorization & RoE",
        focus_area="Pre-Engagement",
        topics=["Rules of Engagement (RoE)", "Scope boundaries & exclusions", "Target Authorization verification", "Non-Disclosure Agreements"],
        hands_on_tasks=["Configure authorized target scopes in CyberSecuritySuite", "Test scope guard restrictions"],
        recommended_tools=["CyberSecuritySuite Scope Guard"],
    ),
    StudyDay(
        day=3,
        week=1,
        title="OSINT & Attack Surface Mapping",
        focus_area="Reconnaissance",
        topics=["Passive DNS enumeration", "Certificate transparency logs", "Google Hacking Database (GHDB)", "Shodan device fingerprinting"],
        hands_on_tasks=["Perform passive subdomain enumeration", "Craft targeted Google dorks", "Query Shodan for edge exposed assets"],
        recommended_tools=["subfinder", "whois", "dig", "shodan"],
    ),
    StudyDay(
        day=4,
        week=1,
        title="Social Engineering Vectors & Awareness Auditing",
        focus_area="Human Vectors",
        topics=["Phishing, Spear Phishing & Whaling", "Vishing scenarios", "Physical security & tailgating", "Removable media baiting"],
        hands_on_tasks=["Audit email domain spoofability (SPF/DKIM/DMARC)", "Draft authorized phishing pretexting template"],
        recommended_tools=["gophish", "setoolkit"],
    ),
    StudyDay(
        day=5,
        week=1,
        title="Web & API Assessment: Discovery & Mapping",
        focus_area="Web Security",
        topics=["HTTP/S request-response inspection", "Hidden endpoint discovery", "API parameter fuzzing", "JavaScript secret extraction"],
        hands_on_tasks=["Run directory and route fuzzing", "Analyze client-side JS bundles for embedded API keys and tokens"],
        recommended_tools=["ffuf", "zaproxy", "c0desec"],
    ),
    StudyDay(
        day=6,
        week=1,
        title="Web & API Assessment: Vulnerability Verification",
        focus_area="Web Security",
        topics=["SQL injection (error-based, blind, time-based)", "Cross-Site Scripting (XSS)", "SSRF & IDOR flaws", "JWT token tampering"],
        hands_on_tasks=["Automate SQL injection detection in testbed", "Test parameter tampering in authenticated endpoints"],
        recommended_tools=["sqlmap", "zaproxy", "nuclei"],
    ),
    StudyDay(
        day=7,
        week=1,
        title="Weekly Review & Assessment Report Generation",
        focus_area="Review & Reporting",
        topics=["Evidence verification & SHA-256 hashing", "CVSS 3.1 scoring calculation", "Executive summary vs technical report"],
        hands_on_tasks=["Compile Week 1 findings into assessment report", "Review test logs and terminal history"],
        recommended_tools=["CyberSecuritySuite Reporting Engine"],
    ),

    # Week 2: Enterprise Network & System Penetration Testing
    StudyDay(
        day=8,
        week=2,
        title="Host Discovery & Stealth Port Scanning",
        focus_area="Network Pentest",
        topics=["ICMP sweeps & TCP ping variants", "SYN half-open vs Full Connect", "Evasion scans (NULL, FIN, XMAS, ACK)", "MTU fragmentation"],
        hands_on_tasks=["Execute multi-profile Nmap scans against lab target", "Inspect packet headers in Wireshark"],
        recommended_tools=["nmap", "tshark", "hping3"],
    ),
    StudyDay(
        day=9,
        week=2,
        title="Service Enumeration: SMB, RPC & NFS",
        focus_area="Network Pentest",
        topics=["SMB share permissions & null sessions", "RPC endpoints & portmapper", "NFS exported filesystems (`showmount`)", "Anonymous access risks"],
        hands_on_tasks=["Enumerate SMB shares and sessions with NetExec", "Mount remote NFS export without lock (`nolock`)"],
        recommended_tools=["netexec", "smbclient", "rpcinfo"],
    ),
    StudyDay(
        day=10,
        week=2,
        title="Service Enumeration: SNMP, LDAP, SMTP & NTP",
        focus_area="Network Pentest",
        topics=["SNMP MIB walking with community strings", "LDAP user and domain queries", "SMTP user verification (`VRFY`/`EXPN`)", "NTP monlist reflection"],
        hands_on_tasks=["Enumerate SNMP tree for network routes and running processes", "Verify mail server user accounts"],
        recommended_tools=["snmpwalk", "onesixtyone", "ldapsearch"],
    ),
    StudyDay(
        day=11,
        week=2,
        title="Active Directory Assessment: Recon & Kerberos",
        focus_area="Active Directory",
        topics=["Kerberoasting concepts", "AS-REP Roasting", "LLMNR / NBT-NS poisoning", "BloodHound graph analysis"],
        hands_on_tasks=["Simulate LLMNR poisoning in lab", "Request TGS tickets for SPNs and inspect hash format"],
        recommended_tools=["impacket", "responder", "netexec"],
    ),
    StudyDay(
        day=12,
        week=2,
        title="Active Directory: Lateral Movement & Domain Privilege",
        focus_area="Active Directory",
        topics=["Pass-the-Hash (PtH) and Pass-the-Ticket (PtT)", "DCSync attack mechanics", "Domain controller replication permissions", "GPO abuse"],
        hands_on_tasks=["Extract NT hashes from lab DC using secretsdump", "Perform PtH authentication with NetExec"],
        recommended_tools=["impacket", "netexec"],
    ),
    StudyDay(
        day=13,
        week=2,
        title="Linux Security & Privilege Escalation",
        focus_area="System Security",
        topics=["SUID/SGID binary abuse", "Sudo privileges & wildcard misconfigurations", "Kernel exploit verification", "Cron job & service hijacking"],
        hands_on_tasks=["Audit Linux system configurations for PrivEsc vectors", "Crack unshadowed password hashes with John/Hashcat"],
        recommended_tools=["linpeas", "john", "hashcat"],
    ),
    StudyDay(
        day=14,
        week=2,
        title="Windows Security & Local Privilege Escalation",
        focus_area="System Security",
        topics=["Unquoted service paths", "AlwaysInstallElevated registry keys", "Token impersonation (SeImpersonatePrivilege)", "SAM database dumping"],
        hands_on_tasks=["Inspect service permissions and binaries", "Dump local SAM hashes and test extraction"],
        recommended_tools=["winpeas", "mimikatz", "netexec"],
    ),

    # Week 3: Advanced Offensive Security & Pivoting
    StudyDay(
        day=15,
        week=3,
        title="Binary Analysis & Reverse Engineering Basics",
        focus_area="Reverse Engineering",
        topics=["ELF and PE header structure", "Strings, symbols and imports extraction", "Disassembly with radare2/Ghidra", "Format string vulnerability basics"],
        hands_on_tasks=["Inspect binary metadata and identify compiler protections", "Disassemble test binary in radare2"],
        recommended_tools=["radare2", "ghidra", "rabin2"],
    ),
    StudyDay(
        day=16,
        week=3,
        title="Buffer Overflow Exploitation Concepts",
        focus_area="Exploit Development",
        topics=["32-bit stack architecture (ESP, EBP, EIP)", "Controlling EIP with cyclical patterns", "Bad character elimination", "JMP ESP trampolines"],
        hands_on_tasks=["Identify crash offset using pattern create/offset", "Construct working local exploit POC against vulnerable lab service"],
        recommended_tools=["radare2", "metasploit", "gdb"],
    ),
    StudyDay(
        day=17,
        week=3,
        title="Pivoting & Multi-Hop Network Routing",
        focus_area="Advanced Network",
        topics=["SSH dynamic & local port forwarding", "Proxychains and SOCKS proxies", "Chisel HTTP tunneling", "Double pivoting across dual-homed hosts"],
        hands_on_tasks=["Route Nmap scans through SOCKS proxy into isolated subnet", "Establish reverse port forwarding tunnel"],
        recommended_tools=["chisel", "ssh", "proxychains"],
    ),
    StudyDay(
        day=18,
        week=3,
        title="Wireless Security Assessment",
        focus_area="Wireless",
        topics=["802.11 frames & monitoring modes", "WPA2 4-way handshake capture", "WPA3 Transition mode considerations", "Rogue AP identification"],
        hands_on_tasks=["Inspect captured EAPOL 4-way handshake in Wireshark", "Audit pre-shared key complexity"],
        recommended_tools=["aircrack-ng", "wireshark"],
    ),
    StudyDay(
        day=19,
        week=3,
        title="IoT & Firmware Security Basics",
        focus_area="IoT & Embedded",
        topics=["Firmware extraction with binwalk", "Embedded squashfs filesystem analysis", "Hardcoded credentials in firmware configs", "UART/JTAG interface awareness"],
        hands_on_tasks=["Unpack firmware image and audit shadow/config files"],
        recommended_tools=["binwalk", "strings"],
    ),
    StudyDay(
        day=20,
        week=3,
        title="Post-Exploitation & State Restoration",
        focus_area="Methodology",
        topics=["Artifact tracking & log review", "Backdoor removal", "Temporary credential cleanup", "Defensive remediation recommendations"],
        hands_on_tasks=["Execute complete lab cleanup checklist", "Verify target state restoration"],
        recommended_tools=["CyberSecuritySuite Audit Engine"],
    ),
    StudyDay(
        day=21,
        week=3,
        title="Pivoting & Exploitation Practical Exercise",
        focus_area="Practical Lab",
        topics=["Multi-stage engagement synthesis", "Edge compromise -> Tunnel -> Internal Host -> Privilege Escalation"],
        hands_on_tasks=["Complete end-to-end multi-subnet penetration test challenge"],
        recommended_tools=["All platform tools"],
    ),

    # Week 4: Practical Mock Exam & Final Preparation
    StudyDay(
        day=22,
        week=4,
        title="Mock Practical: External Perimeter & OSINT",
        focus_area="Exam Simulation",
        topics=["Speed and accuracy in reconnaissance", "Flag and proof file capture with SHA-256", "Timing constraints"],
        hands_on_tasks=["Complete timed OSINT & perimeter host discovery lab challenge"],
        recommended_tools=["CyberSecuritySuite"],
    ),
    StudyDay(
        day=23,
        week=4,
        title="Mock Practical: Internal Network & Pivot",
        focus_area="Exam Simulation",
        topics=["Segmented network navigation", "Service version identification", "Pivoting persistence"],
        hands_on_tasks=["Compromise dual-homed pivot and route scan into subnet 2"],
        recommended_tools=["CyberSecuritySuite", "chisel"],
    ),
    StudyDay(
        day=24,
        week=4,
        title="Mock Practical: Active Directory Attack Path",
        focus_area="Exam Simulation",
        topics=["Service ticket roasting", "Privilege escalation to Domain Admin", "Extracting domain proof flags"],
        hands_on_tasks=["Complete Active Directory attack chain in lab"],
        recommended_tools=["impacket", "netexec"],
    ),
    StudyDay(
        day=25,
        week=4,
        title="Mock Practical: Web Application Flaws",
        focus_area="Exam Simulation",
        topics=["Database extraction via SQLi", "File upload and remote code execution", "Privilege escalation from web user"],
        hands_on_tasks=["Exploit vulnerable web target to gain interactive shell"],
        recommended_tools=["sqlmap", "c0desec"],
    ),
    StudyDay(
        day=26,
        week=4,
        title="Mock Practical: Binary Exploit Challenge",
        focus_area="Exam Simulation",
        topics=["Identify vulnerable service binary", "Analyze buffer space and bad characters", "Execute shellcode payload"],
        hands_on_tasks=["Exploit standalone buffer overflow service in isolated container"],
        recommended_tools=["radare2", "python3"],
    ),
    StudyDay(
        day=27,
        week=4,
        title="24-Hour Timed Full Practical Simulation",
        focus_area="Exam Simulation",
        topics=["Stamina, documentation discipline, methodology execution, evidence integrity"],
        hands_on_tasks=["Simulate 12-hour or 24-hour practical exam scope across all target subnets"],
        recommended_tools=["CyberSecuritySuite"],
    ),
    StudyDay(
        day=28,
        week=4,
        title="Report Drafting & Audit Review",
        focus_area="Reporting",
        topics=["Executive summary", "Vulnerability assessment matrix", "Step-by-step reproduction walkthrough", "Remediation priority"],
        hands_on_tasks=["Generate full professional assessment report using platform template"],
        recommended_tools=["CyberSecuritySuite Reporting Engine"],
    ),
    StudyDay(
        day=29,
        week=4,
        title="Weak Area Refinement & Knowledge Checks",
        focus_area="Revision",
        topics=["Review incorrect answers & missed flags", "Tool syntax memorization", "Alternative pivoting strategies"],
        hands_on_tasks=["Re-attempt failed lab objectives", "Solidify one-liner syntax for key utilities"],
        recommended_tools=["CyberSecuritySuite Terminal"],
    ),
    StudyDay(
        day=30,
        week=4,
        title="Final Exam Readiness & Strategy Alignment",
        focus_area="Exam Readiness",
        topics=["Exam day strategy", "Time management (breaks, sleep)", "Evidence folder organization", "Confidence check"],
        hands_on_tasks=["Verify personal attack workstation readiness and all tool binaries"],
        recommended_tools=["All platform tools"],
    ),
]

