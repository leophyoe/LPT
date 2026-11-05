# CPENT Knowledge Base & Penetration Testing Methodology

This document captures the structured assessment methodologies, testing checklists, data schemas, and reporting criteria for the **EC-Council Certified Penetration Testing Professional (CPENT)** certification, as integrated into **CyberSecuritySuite**.

---

## 1. Structure of the CPENT Assessment Methodologies

The practical certification track is organized into three major operational methodologies:
1. **Open-Source Intelligence (OSINT) Methodology** (44 Steps)
2. **Social Engineering Penetration Testing Methodology** (32 Steps)
3. **Network Penetration Testing (External & Internal) Methodology** (126 Steps)

---

## 2. Methodology Breakdown & Automation Mapping

### Module 1: Open-Source Intelligence (OSINT)
Used during the pre-engagement reconnaissance phase to map target attack surfaces without sending intrusive packets directly to defensive firewalls.

| Test ID | Test Category & Objective | Key Tools / Services | Automation / Adapter in Platform |
| :--- | :--- | :--- | :--- |
| **Test 1.1** | Find Domain and Sub-domains | `subfinder`, `amass`, `findomain` | `modules/osint/subdomains.py` (Passive DNS, CT logs) |
| **Test 1.2** | Find Similar or Parallel Domain Names | `dnstwist`, `urlcrazy` | Domain typo-squatting detection |
| **Test 1.3** | Advanced Search Operators & GHDB | Google Dorks, Exploit-DB GHDB | Search syntax generator for exposed configs/PDFs |
| **Test 1.4** | Footprint Target via Shodan | `shodan` API, `censys` | Queries exposed edge devices, banners, and IoT |
| **Test 1.6 - 1.7** | Employee & Email Harvesting | `theHarvester`, Hunter.io | Email format identifier (`first.last@domain.com`) |
| **Test 1.8** | Breach Credential Enumeration | HaveIBeenPwned API, DeHashed | Leaked credential risk analysis |
| **Test 2.1 - 2.5** | Website Analysis & HTML Inspection | Web crawlers, `curl` | Header inspection, comment/secret scanning |
| **Test 3.1 - 3.2** | Whois & IP Range Allocation | `whois`, RIR databases | Autonomous System (ASN) and CIDR mapping |
| **Test 3.3** | DNS Record Enumeration | `dig`, `dnsrecon` | Queries A, AAAA, MX, NS, CNAME, SOA, TXT records |
| **Test 3.5** | DNS Zone Transfer (AXFR) | `dig axfr` | Automatic detection of misconfigured nameservers |
| **Test 3.6 - 3.7** | Network Topology & Traceroute | `traceroute`, `tcptraceroute` | Hop-by-hop latency and visual route mapping |

---

### Module 2: Social Engineering Penetration Testing
Assesses the human factor and physical perimeter resilience in strictly authorized engagements.

| Test ID | Attack Vector | Objective | Platform Implementation |
| :--- | :--- | :--- | :--- |
| **Test 1.1 - 1.6** | **Email Vector** | Phishing, Spear Phishing, Whaling, Pharming | Pre-assessment checklist, email header spoofability checks (SPF, DKIM, DMARC validator) |
| **Test 2.1 - 2.2** | **Telephone Vector** | Voice Phishing (Vishing), SMiShing | Scenario generator, pretexting templates, employee response logging table |
| **Test 3.1 - 3.13** | **Physical Vector** | Tailgating, Badge Clones, USB Drops, Dumpster Diving, Elicitation | Physical audit checklist, evidence photography tracking, findings recording |

---

### Module 3: Network Penetration Testing (External & Internal)
The core technical assessment phase spanning reconnaissance, scanning, enumeration, vulnerability verification, exploitation, pivoting, and post-exploitation.

#### Phase A: Port Scanning & Host Discovery
- **Test 1.1 - 1.2**: ICMP & ARP Host Discovery (`nmap -sn`)
- **Test 1.3 - 1.5**: Full Connect (`-sT`) and SYN Half-Open (`-sS`) Port Scanning
- **Test 1.6 - 1.8**: Evasion Scans (NULL `-sN`, FIN `-sF`, XMAS `-sX`, ACK `-sA`, UDP `-sU`)
- **Test 1.9**: Fragmentation Scanning (`-f`, `--mtu`) to inspect firewall reassembly behavior

#### Phase B: OS & Service Fingerprinting
- **Test 3.1 - 3.2**: TCP/IP OS Fingerprinting (`nmap -O`) and SMB dialect identification
- **Test 3.3 - 3.7**: Banner Grabbing via raw sockets (Python, Netcat, Telnet, Metasploit)
- **Test 3.9**: Internal Network Mapping & gateway discovery

#### Phase C: Deep Service Enumeration
- **Test 4.1 - 4.3**: NetBIOS (`nbtscan`) and SNMP Community Strings (`snmpwalk -v2c -c public`)
- **Test 4.4 - 4.5**: LDAP user/group queries and NTP monlist time-server queries
- **Test 4.6 - 4.7**: SMTP user verification (`VRFY`/`EXPN`) and IPSec VPN Gateway probing (`ike-scan`)
- **Test 4.9 - 4.11**: SMB Shares (`netexec smb --shares`, `smbclient -L`) and Null Sessions
- **Test 4.17 - 4.18**: Promiscuous Traffic Sniffing & PCAP inspection (`tshark`, `tcpdump`)

#### Phase D: Vulnerability Assessment & Analysis
- **Test 5.1 - 5.3**: Automated vulnerability scanning with Nmap NSE (`--script vuln`)
- **Test 5.4 - 5.8**: Service version mapping to CVEs, CVSS ratings, and exploit references
- **Test 5.9**: Risk Assessment Process (Weakness, Impact, Exploitable Mechanism, Remediation)

#### Phase E: Exploitation & Post-Exploitation
- **Test 6.1 - 6.7**: Windows Exploitation (Remote password auditing, Meterpreter, Buffer Overflows)
- **Test 7.1 - 7.3**: Linux Exploitation (SUID binaries, sudo misconfigurations, remote shells)
- **Test 8.1 - 8.5**: Layer 2 Attacks (ARP Poisoning, MITM, DNS Cache Poisoning)
- **Test 8.9**: Privilege Escalation (PrivEsc) workflows
- **Test 10.1 - 10.5**: Defensive evasion and backdoor persistence analysis in controlled labs
- **Test 10.7**: **Cleanup & Prevision State Restoration**: Mandatory removal of artifacts, temporary users, and exploit binaries

---

## 3. Reporting Schema Standards

Every test in the CPENT methodology mandates strict documentation:
1. **Target Organization & URL/Scope**
2. **Commands & Scripts Used** (with full arguments)
3. **Execution Success Confirmation** (`Yes` / `No`)
4. **Gathered Artifacts / Output Data Table**
5. **Tools & Services Utilized**
6. **Results Analysis & Risk Evaluation**
7. **Actionable Remediation Guidance**

This structure is directly baked into our `storage/models.py` and `reports/` engine.
