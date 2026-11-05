"""24-Hour CPENT Exam Range Simulator & Flag Scoreboard Engine.

Models the official EC-Council CPENT (Certified Penetration Testing Professional)
and LPT (Master) practical exam specifications:
- 3,000 Total Available Points across 6 specialized Challenge Enclaves.
- 24-Hour Continuous Marathon or 2 x 12-Hour Split Sessions.
- 2,100 Points (70%) CPENT Certification Passing Threshold.
- 2,700 Points (90%) LPT (Master) Elite Honor Threshold.
- Cryptographic Flag Verification, State Persistence, and Gap Analysis.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_flag(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


@dataclass
class ExamFlag:
    """Individual challenge flag within an exam range."""
    flag_id: str
    range_id: str
    title: str
    points: int = 100
    target_ip: str = "10.10.1.50"
    service_port: str = "80/TCP"
    hint: str = ""
    methodology_category: str = "web_application"
    flag_hash: str = ""
    raw_flag_sample: str = ""
    captured: bool = False
    captured_at: Optional[str] = None
    evidence_text: str = ""
    cvss_score: float = 7.5
    severity: str = "high"
    remediation: str = ""

    def __post_init__(self):
        if self.raw_flag_sample and not self.flag_hash:
            self.flag_hash = _hash_flag(self.raw_flag_sample)


@dataclass
class ExamRange:
    """Challenge enclave / zone within the CPENT exam."""
    range_id: str
    name: str
    icon: str
    target_subnet: str
    description: str
    total_points: int
    flags: List[ExamFlag] = field(default_factory=list)

    @property
    def captured_points(self) -> int:
        return sum(f.points for f in self.flags if f.captured)

    @property
    def captured_count(self) -> int:
        return sum(1 for f in self.flags if f.captured)

    @property
    def total_count(self) -> int:
        return len(self.flags)


@dataclass
class ExamSession:
    """Tracks active or paused exam session state, elapsed time, and milestones."""
    session_id: str = "CPENT-SIM-01"
    mode: str = "24h"  # '24h' or '2x12h'
    session_part: int = 1  # 1 or 2
    state: str = "not_started"  # 'not_started', 'running', 'paused', 'completed'
    start_time: Optional[str] = None
    elapsed_seconds: int = 0
    total_allowed_seconds: int = 86400  # 24 * 3600
    score: int = 0
    captured_flag_ids: List[str] = field(default_factory=list)
    project_id: Optional[int] = None
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    @property
    def remaining_seconds(self) -> int:
        rem = self.total_allowed_seconds - self.elapsed_seconds
        return max(0, rem)

    @property
    def cpent_passed(self) -> bool:
        return self.score >= 2100

    @property
    def lpt_master_achieved(self) -> bool:
        return self.score >= 2700


def get_default_exam_ranges() -> List[ExamRange]:
    """Generates the official 6 CPENT Challenge Enclaves totaling 3,000 points (30 flags)."""
    ranges: List[ExamRange] = []

    # ------------------------------------------------------------------
    # Range 1: CTF & Web Application Exploitation (500 pts - 5 flags)
    # ------------------------------------------------------------------
    r1_flags = [
        ExamFlag(
            flag_id="R1-FLAG-01",
            range_id="range_1",
            title="Blind SQL Injection with WAF Bypass",
            points=100,
            target_ip="10.10.1.50",
            service_port="80/TCP (HTTP)",
            hint="Inspect SQL injection filter bypass with HTTP parameter pollution and inline comments.",
            methodology_category="web_application",
            raw_flag_sample="CPENT{b11nd_sq1_waf_bypa55}",
            cvss_score=8.6,
            severity="high",
            remediation="Use parameterized queries and sanitize user input with strict type whitelisting.",
        ),
        ExamFlag(
            flag_id="R1-FLAG-02",
            range_id="range_1",
            title="Server-Side Request Forgery (SSRF) Cloud Metadata Leak",
            points=100,
            target_ip="10.10.1.51",
            service_port="8080/TCP (HTTP)",
            hint="Exploit PDF export generator URL parameter to query internal metadata endpoint 169.254.169.254.",
            methodology_category="web_application",
            raw_flag_sample="CPENT{ssrf_cloud_m3tadata_leak}",
            cvss_score=8.2,
            severity="high",
            remediation="Restrict outbound HTTP requests from web workers using network egress filtering.",
        ),
        ExamFlag(
            flag_id="R1-FLAG-03",
            range_id="range_1",
            title="Insecure Object Deserialization & RCE",
            points=100,
            target_ip="10.10.1.52",
            service_port="8443/TCP (HTTPS)",
            hint="Analyze base64 Java serialized session token using ysoserial CommonsCollections payload.",
            methodology_category="web_application",
            raw_flag_sample="CPENT{jav4_ys0s3r1al_rce_pwn}",
            cvss_score=9.8,
            severity="critical",
            remediation="Do not deserialize untrusted data streams; migrate to cryptographically signed JSON Web Tokens.",
        ),
        ExamFlag(
            flag_id="R1-FLAG-04",
            range_id="range_1",
            title="Command Injection Space/Character Filter Evasion",
            points=100,
            target_ip="10.10.1.53",
            service_port="80/TCP (HTTP)",
            hint="Bypass space filter using ${IFS} or bash brace expansion {cat,/etc/passwd}.",
            methodology_category="web_application",
            raw_flag_sample="CPENT{cmd_1nj_1fs_bypa55_root}",
            cvss_score=9.0,
            severity="critical",
            remediation="Avoid shell invocation functions (system, exec, popen); pass argument arrays directly.",
        ),
        ExamFlag(
            flag_id="R1-FLAG-05",
            range_id="range_1",
            title="PHP Type Juggling & Authentication Bypass",
            points=100,
            target_ip="10.10.1.54",
            service_port="443/TCP (HTTPS)",
            hint="Exploit loose comparison (==) against magic hash strings starting with 0e.",
            methodology_category="web_application",
            raw_flag_sample="CPENT{php_m4g1c_hash_auth_bypass}",
            cvss_score=7.8,
            severity="high",
            remediation="Enforce strict comparison (===) and use password_verify() with bcrypt or Argon2.",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_1",
            name="CTF & Web Applications",
            icon="🌐",
            target_subnet="10.10.1.0/24",
            description="Perimeter web applications featuring custom WAF filters, deserialization, and cloud SSRF.",
            total_points=500,
            flags=r1_flags,
        )
    )

    # ------------------------------------------------------------------
    # Range 2: Multi-Hop Pivoting & Tunneling (500 pts - 5 flags)
    # ------------------------------------------------------------------
    r2_flags = [
        ExamFlag(
            flag_id="R2-FLAG-01",
            range_id="range_2",
            title="DMZ Linux Bastion Host Compromise",
            points=100,
            target_ip="10.10.2.10",
            service_port="22/TCP (SSH)",
            hint="Obtain leaked private key from web backup directory and connect to pivot router.",
            methodology_category="network_pivoting",
            raw_flag_sample="CPENT{dmz_bast1on_ssh_k3y_root}",
            cvss_score=8.5,
            severity="high",
            remediation="Enforce passphrase-protected SSH keys and disable root login via SSH.",
        ),
        ExamFlag(
            flag_id="R2-FLAG-02",
            range_id="range_2",
            title="Chisel Reverse SOCKS5 Tunneling Setup",
            points=100,
            target_ip="10.10.2.10",
            service_port="8000/TCP (HTTP)",
            hint="Deploy chisel client reverse tunnel connecting back to listener port 8000.",
            methodology_category="network_pivoting",
            raw_flag_sample="CPENT{ch1sel_r3v_s0cks5_tunneled}",
            cvss_score=7.0,
            severity="high",
            remediation="Deploy host-based intrusion prevention to detect unauthorized reverse tunneling binaries.",
        ),
        ExamFlag(
            flag_id="R2-FLAG-03",
            range_id="range_2",
            title="Second-Hop Dual-Homed Windows Pivot",
            points=100,
            target_ip="172.16.20.15",
            service_port="3389/TCP (RDP)",
            hint="Tunnel through DMZ host into 172.16.20.0/24 subnet to reach the jump box.",
            methodology_category="network_pivoting",
            raw_flag_sample="CPENT{w1n_dual_h0m3_p1v0t_pwn}",
            cvss_score=8.0,
            severity="high",
            remediation="Isolate internal subnets with stateful firewalls preventing transverse routing.",
        ),
        ExamFlag(
            flag_id="R2-FLAG-04",
            range_id="range_2",
            title="Triple Pivot to Deep Isolated Core Network",
            points=100,
            target_ip="192.168.100.5",
            service_port="8080/TCP (HTTP)",
            hint="Route ProxyChains through both Chisel SOCKS proxies into isolated 192.168.100.0/24 enclave.",
            methodology_category="network_pivoting",
            raw_flag_sample="CPENT{tr1pl3_h0p_proxycha1ns_mast3r}",
            cvss_score=8.8,
            severity="high",
            remediation="Enforce microsegmentation and terminate all unauthorized inter-VLAN forwarding.",
        ),
        ExamFlag(
            flag_id="R2-FLAG-05",
            range_id="range_2",
            title="Internal Core File Server NTLM Hash Capture",
            points=100,
            target_ip="192.168.100.20",
            service_port="445/TCP (SMB)",
            hint="Trigger SMB authentication request from backend core server to capture NetNTLMv2 hash.",
            methodology_category="network_pivoting",
            raw_flag_sample="CPENT{int3rnal_c0re_smb_ntlm_h4sh}",
            cvss_score=8.2,
            severity="high",
            remediation="Disable NTLMv1/v2 across all internal file servers; mandate Kerberos with SMB Signing.",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_2",
            name="Multi-Hop Pivoting & Tunneling",
            icon="🔀",
            target_subnet="10.10.2.0/24 -> 172.16.20.0/24 -> 192.168.100.0/24",
            description="Deep multi-tier network topology requiring Chisel, SSH tunnels, and ProxyChains routing.",
            total_points=500,
            flags=r2_flags,
        )
    )

    # ------------------------------------------------------------------
    # Range 3: Active Directory Forest Dominance (600 pts - 6 flags)
    # ------------------------------------------------------------------
    r3_flags = [
        ExamFlag(
            flag_id="R3-FLAG-01",
            range_id="range_3",
            title="BloodHound Domain Recon & Shortest Attack Path",
            points=100,
            target_ip="10.10.3.10",
            service_port="389/TCP (LDAP)",
            hint="Collect domain graph with bloodhound-python and query shortest path to Domain Admins.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{bl00dhound_ad_r3con_path}",
            cvss_score=6.5,
            severity="medium",
            remediation="Audit Active Directory Access Control Lists (ACLs) to eliminate shadow administrator paths.",
        ),
        ExamFlag(
            flag_id="R3-FLAG-02",
            range_id="range_3",
            title="AS-REP Roasting No Pre-Authentication Account",
            points=100,
            target_ip="10.10.3.10",
            service_port="88/TCP (Kerberos)",
            hint="Execute GetNPUsers.py to request TGT for users with DONT_REQ_PREAUTH set.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{asrep_r0ast_hashcat_cr4ck}",
            cvss_score=7.8,
            severity="high",
            remediation="Enforce Kerberos pre-authentication (UF_DONT_REQUIRE_PREAUTH = False) on all accounts.",
        ),
        ExamFlag(
            flag_id="R3-FLAG-03",
            range_id="range_3",
            title="Kerberoasting MSSQL Service Account TGS",
            points=100,
            target_ip="10.10.3.15",
            service_port="1433/TCP (MSSQL)",
            hint="Request Service Ticket for MSSQL SPN with GetUserSPNs.py and crack with Hashcat -m 13100.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{krb5tgs_spn_mssql_cr4ck3d}",
            cvss_score=8.0,
            severity="high",
            remediation="Use Group Managed Service Accounts (gMSA) with 120-character auto-rotated passwords.",
        ),
        ExamFlag(
            flag_id="R3-FLAG-04",
            range_id="range_3",
            title="Unconstrained Delegation Ticket Injection",
            points=100,
            target_ip="10.10.3.20",
            service_port="80/TCP (IIS)",
            hint="Extract cached Domain Admin TGT from memory of server with unconstrained delegation enabled.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{uncon5tra1ned_d3legation_pwn}",
            cvss_score=8.5,
            severity="high",
            remediation="Disable unconstrained delegation; configure Resource-Based Constrained Delegation (RBCD).",
        ),
        ExamFlag(
            flag_id="R3-FLAG-05",
            range_id="range_3",
            title="NTDS.dit DCSync Replication Dump",
            points=100,
            target_ip="10.10.3.10",
            service_port="445/TCP (SMB)",
            hint="Run secretsdump.py with Replicating Directory Changes permissions to extract krbtgt NTLM hash.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{dcsync_krbtgt_ntds_d0m1nance}",
            cvss_score=9.5,
            severity="critical",
            remediation="Restrict DS-Replication-Get-Changes-All permissions strictly to Domain Controllers.",
        ),
        ExamFlag(
            flag_id="R3-FLAG-06",
            range_id="range_3",
            title="Forged Kerberos Golden Ticket Full Forest Admin",
            points=100,
            target_ip="10.10.3.10",
            service_port="88/TCP (Kerberos)",
            hint="Forge TGT ticket using ticketer.py with krbtgt hash and domain SID.",
            methodology_category="active_directory",
            raw_flag_sample="CPENT{g0ld3n_t1cket_f0rest_adm1n}",
            cvss_score=9.9,
            severity="critical",
            remediation="Rotate krbtgt account password twice with a 24-hour interval and monitor Event ID 4768.",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_3",
            name="Active Directory Forest",
            icon="🌲",
            target_subnet="10.10.3.0/24 (CPENT.LOCAL)",
            description="Enterprise Windows Domain with Kerberos delegation vulnerabilities, DCSync, and Golden Tickets.",
            total_points=600,
            flags=r3_flags,
        )
    )

    # ------------------------------------------------------------------
    # Range 4: Binary Analysis & Stack Buffer Overflow (500 pts - 5 flags)
    # ------------------------------------------------------------------
    r4_flags = [
        ExamFlag(
            flag_id="R4-FLAG-01",
            range_id="range_4",
            title="Custom Daemon Crash Fuzzing & Length Discovery",
            points=100,
            target_ip="10.10.4.50",
            service_port="9999/TCP (Custom)",
            hint="Send incremental cyclic buffer payloads to locate the exact crash threshold.",
            methodology_category="binary_exploitation",
            raw_flag_sample="CPENT{fuzz1ng_un1qu3_cr4sh_d3t3ct}",
            cvss_score=7.5,
            severity="high",
            remediation="Implement bounded string copy functions (strncpy, snprintf) and enable stack canaries.",
        ),
        ExamFlag(
            flag_id="R4-FLAG-02",
            range_id="range_4",
            title="Exact EIP Cyclic Pattern Offset Identified",
            points=100,
            target_ip="10.10.4.50",
            service_port="9999/TCP (Custom)",
            hint="Query crash address with msf-pattern_offset to pinpoint exact 4-byte EIP overwrite position.",
            methodology_category="binary_exploitation",
            raw_flag_sample="CPENT{cjc1ic_patt3rn_0ffset_f0und}",
            cvss_score=7.8,
            severity="high",
            remediation="Compile binaries with Address Space Layout Randomization (ASLR) and stack protector flags.",
        ),
        ExamFlag(
            flag_id="R4-FLAG-03",
            range_id="range_4",
            title="Bad Characters Memory Elimination Matrix",
            points=100,
            target_ip="10.10.4.50",
            service_port="9999/TCP (Custom)",
            hint="Compare memory bytearray using mona.py to eliminate corrupted null bytes and delimiters.",
            methodology_category="binary_exploitation",
            raw_flag_sample="CPENT{b4dch4rs_cl3an_byt34rray}",
            cvss_score=7.5,
            severity="high",
            remediation="Sanitize all input byte streams before parsing inside unmanaged memory buffers.",
        ),
        ExamFlag(
            flag_id="R4-FLAG-04",
            range_id="range_4",
            title="JMP ESP Gadget Return Pointer Overwrite",
            points=100,
            target_ip="10.10.4.50",
            service_port="9999/TCP (Custom)",
            hint="Locate non-ASLR module containing opcode \\xff\\xe4 (JMP ESP) to divert execution.",
            methodology_category="binary_exploitation",
            raw_flag_sample="CPENT{jmp_3sp_m0na_gadg3t_h1jack}",
            cvss_score=8.5,
            severity="high",
            remediation="Ensure Data Execution Prevention (DEP / NX) is strictly enforced on all loaded DLLs.",
        ),
        ExamFlag(
            flag_id="R4-FLAG-05",
            range_id="range_4",
            title="Shellcode Execution & Root Privilege Shell",
            points=100,
            target_ip="10.10.4.50",
            service_port="4444/TCP (Reverse Shell)",
            hint="Deliver msfvenom staged reverse TCP shellcode preceded by 16-byte NOP sled.",
            methodology_category="binary_exploitation",
            raw_flag_sample="CPENT{st4ck_0v3rfl0w_r00t_sh3ll}",
            cvss_score=9.8,
            severity="critical",
            remediation="Never execute service daemons with elevated SYSTEM or root privileges; isolate in sandboxes.",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_4",
            name="Binary Analysis & 32-bit Exploitation",
            icon="⚙️",
            target_subnet="10.10.4.0/24",
            description="32-bit x86 proprietary network daemon requiring memory fuzzing, EIP offset, and shellcode execution.",
            total_points=500,
            flags=r4_flags,
        )
    )

    # ------------------------------------------------------------------
    # Range 5: IoT & Firmware Reverse Engineering (400 pts - 4 flags)
    # ------------------------------------------------------------------
    r5_flags = [
        ExamFlag(
            flag_id="R5-FLAG-01",
            range_id="range_5",
            title="Binwalk Firmware Unpacking & Squashfs Extraction",
            points=100,
            target_ip="10.10.5.10",
            service_port="80/TCP (HTTP)",
            hint="Extract compressed file systems from router .bin firmware with binwalk -Me.",
            methodology_category="iot_firmware",
            raw_flag_sample="CPENT{b1nwalk_f1rmware_squ4shfs_xtr}",
            cvss_score=6.8,
            severity="medium",
            remediation="Encrypt firmware binaries using hardware-backed cryptographic keys (Secure Boot).",
        ),
        ExamFlag(
            flag_id="R5-FLAG-02",
            range_id="range_5",
            title="Hardcoded SSL Private Key & Root Credential Extraction",
            points=100,
            target_ip="10.10.5.10",
            service_port="22/TCP (SSH)",
            hint="Search extracted root filesystem /etc/shadow and /etc/ssl/certs for hardcoded secrets.",
            methodology_category="iot_firmware",
            raw_flag_sample="CPENT{h4rdcoded_pr1vkey_cr3ds_l3ak}",
            cvss_score=8.4,
            severity="high",
            remediation="Do not bake static private keys or credentials into distributed firmware images.",
        ),
        ExamFlag(
            flag_id="R5-FLAG-03",
            range_id="range_5",
            title="Emulated MIPS/ARM Architecture Backdoor Exploit",
            points=100,
            target_ip="10.10.5.10",
            service_port="5555/TCP (Backdoor)",
            hint="Emulate MIPS binary with QEMU and send secret magic handshake to unlock debug shell.",
            methodology_category="iot_firmware",
            raw_flag_sample="CPENT{m1ps_q3mu_b4ckd00r_pwn3d}",
            cvss_score=9.1,
            severity="critical",
            remediation="Strip manufacturing debug backdoors and unused listener daemons before commercial release.",
        ),
        ExamFlag(
            flag_id="R5-FLAG-04",
            range_id="range_5",
            title="Firmware Cryptographic Signature Check Bypass",
            points=100,
            target_ip="10.10.5.10",
            service_port="8080/TCP (Web Admin)",
            hint="Bypass web upgrade signature check by modifying CRC32 checksum in firmware header.",
            methodology_category="iot_firmware",
            raw_flag_sample="CPENT{f1rmware_s1gnature_ch3ck_bypa55}",
            cvss_score=8.7,
            severity="high",
            remediation="Validate firmware authenticity with asymmetric digital signatures (RSA-4096 / Ed25519).",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_5",
            name="IoT & Firmware Analysis",
            icon="📡",
            target_subnet="10.10.5.0/24",
            description="Embedded router devices and MIPS/ARM binaries requiring firmware dissection and backdoor exploitation.",
            total_points=400,
            flags=r5_flags,
        )
    )

    # ------------------------------------------------------------------
    # Range 6: OT / SCADA & Industrial Control Systems (500 pts - 5 flags)
    # ------------------------------------------------------------------
    r6_flags = [
        ExamFlag(
            flag_id="R6-FLAG-01",
            range_id="range_6",
            title="Modbus TCP (Port 502) Function Code 01 Coil Read",
            points=100,
            target_ip="10.10.6.100",
            service_port="502/TCP (Modbus)",
            hint="Query discrete input coils on PLC unit ID 1 using modbus-cli or pymodbus script.",
            methodology_category="ot_scada",
            raw_flag_sample="CPENT{m0dbus_c01l_r3ad_funct10n_01}",
            cvss_score=7.0,
            severity="high",
            remediation="Isolate industrial OT networks behind strict unidirectional security gateways.",
        ),
        ExamFlag(
            flag_id="R6-FLAG-02",
            range_id="range_6",
            title="PLC Holding Register Extraction (FC 03)",
            points=100,
            target_ip="10.10.6.100",
            service_port="502/TCP (Modbus)",
            hint="Dump holding registers 40001 through 40050 to extract operational sensor telemetry.",
            methodology_category="ot_scada",
            raw_flag_sample="CPENT{plc_h0ld1ng_r3g1ster_fc03_d4ta}",
            cvss_score=7.5,
            severity="high",
            remediation="Enforce encrypted industrial communication protocols (Modbus Security / TLS encapsulation).",
        ),
        ExamFlag(
            flag_id="R6-FLAG-03",
            range_id="range_6",
            title="Holding Register Modification & Valve Actuation",
            points=100,
            target_ip="10.10.6.100",
            service_port="502/TCP (Modbus)",
            hint="Send Function Code 06 (Write Single Register) to overwrite safety valve cutoff threshold.",
            methodology_category="ot_scada",
            raw_flag_sample="CPENT{m0dbus_wr1te_v4lve_ov3rr1de}",
            cvss_score=8.9,
            severity="high",
            remediation="Deploy hardware write-protection switches on critical PLC safety controller registers.",
        ),
        ExamFlag(
            flag_id="R6-FLAG-04",
            range_id="range_6",
            title="Siemens S7comm Protocol Diagnostic Read",
            points=100,
            target_ip="10.10.6.105",
            service_port="102/TCP (ISO-TSAP)",
            hint="Use s7scan to probe PLC CPU rack/slot and extract firmware revision details.",
            methodology_category="ot_scada",
            raw_flag_sample="CPENT{s7c0mm_pr0t0c0l_d1agn0st1cs}",
            cvss_score=6.9,
            severity="medium",
            remediation="Disable legacy S7comm protocol and enable S7comm-Plus with integrity protection.",
        ),
        ExamFlag(
            flag_id="R6-FLAG-05",
            range_id="range_6",
            title="Industrial Emergency Safety System Bypass",
            points=100,
            target_ip="10.10.6.110",
            service_port="502/TCP (Modbus)",
            hint="Send malformed emergency broadcast command to force safety shutoff interlock disable.",
            methodology_category="ot_scada",
            raw_flag_sample="CPENT{sc4da_3m3rg3ncy_saf3ty_bypa55}",
            cvss_score=9.6,
            severity="critical",
            remediation="Isolate Safety Instrumented Systems (SIS) from basic process control networks (BPCS).",
        ),
    ]
    ranges.append(
        ExamRange(
            range_id="range_6",
            name="OT / SCADA & Industrial Systems",
            icon="🏭",
            target_subnet="10.10.6.0/24",
            description="Industrial control infrastructure with Modbus TCP PLCs, RTUs, and Siemens S7 controllers.",
            total_points=500,
            flags=r6_flags,
        )
    )

    return ranges


def verify_flag_submission(candidate: str, flag: ExamFlag) -> bool:
    """Verifies user-submitted flag string against candidate hash or plaintext sample."""
    if not candidate or not candidate.strip():
        return False
    cleaned = candidate.strip()
    # Check plaintext direct match (case-sensitive as standard CTF)
    if flag.raw_flag_sample and cleaned == flag.raw_flag_sample:
        return True
    # Check SHA-256 match
    candidate_hash = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    if flag.flag_hash and candidate_hash.lower() == flag.flag_hash.lower():
        return True
    return False


def calculate_exam_milestones(score: int) -> Dict[str, Any]:
    """Computes exam scoring thresholds, pass status, and missing points."""
    return {
        "score": score,
        "max_score": 3000,
        "percentage": round((score / 3000.0) * 100.0, 1),
        "cpent_passed": score >= 2100,
        "cpent_needed": max(0, 2100 - score),
        "lpt_master_achieved": score >= 2700,
        "lpt_master_needed": max(0, 2700 - score),
    }


def generate_gap_analysis(ranges: List[ExamRange], score: int) -> Dict[str, Any]:
    """Provides actionable tactical advice for optimal flag capture paths to reach 2,100 / 2,700 pts."""
    uncaptured_by_range: Dict[str, int] = {}
    range_names: Dict[str, str] = {}
    total_uncaptured_points = 0

    for r in ranges:
        un_pts = sum(f.points for f in r.flags if not f.captured)
        uncaptured_by_range[r.range_id] = un_pts
        range_names[r.range_id] = f"{r.icon} {r.name}"
        total_uncaptured_points += un_pts

    # Sort ranges by remaining available points descending
    sorted_targets = sorted(uncaptured_by_range.items(), key=lambda kv: kv[1], reverse=True)
    best_ranges = [(range_names[rid], pts) for rid, pts in sorted_targets if pts > 0]

    milestones = calculate_exam_milestones(score)
    advice = []

    if milestones["lpt_master_achieved"]:
        advice.append("🏆 Outstanding achievement! You have surpassed 2,700 points and qualified for LPT (Master)!")
        advice.append("Ensure all proof-of-concept evidence is attached before generating your 24-hour exam report.")
    elif milestones["cpent_passed"]:
        rem = milestones["lpt_master_needed"]
        advice.append(f"🎯 CPENT Certification Passed ({score}/3000 pts)! You need {rem} more points for LPT (Master).")
        if best_ranges:
            top_name, top_pts = best_ranges[0]
            advice.append(f"💡 Recommended Focus: Target {top_name} to unlock up to {top_pts} additional points.")
    else:
        needed = milestones["cpent_needed"]
        advice.append(f"⏱️ You currently need {needed} points to reach the 2,100 pt CPENT Passing mark.")
        if best_ranges:
            top_name, top_pts = best_ranges[0]
            flags_needed = (needed + 99) // 100
            advice.append(f"💡 Priority Enclave: {top_name} holds {top_pts} points. Capturing {flags_needed} flags will secure your certification.")

    return {
        "milestones": milestones,
        "best_enclaves": best_ranges,
        "advice_lines": advice,
        "total_uncaptured_points": total_uncaptured_points,
    }


def save_exam_state(session: ExamSession, ranges: List[ExamRange], file_path: Path | str) -> None:
    """Serializes exam state, timer progress, and captured flags to JSON file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "session": asdict(session),
        "captured_flags": [
            {
                "flag_id": f.flag_id,
                "range_id": f.range_id,
                "captured_at": f.captured_at,
                "evidence_text": f.evidence_text,
            }
            for r in ranges
            for f in r.flags
            if f.captured
        ],
    }

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_exam_state(
    file_path: Path | str, default_ranges: Optional[List[ExamRange]] = None
) -> tuple[ExamSession, List[ExamRange]]:
    """Restores exam session and applies captured flags onto ranges."""
    ranges = default_ranges if default_ranges is not None else get_default_exam_ranges()
    path = Path(file_path)

    if not path.exists():
        return ExamSession(), ranges

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_sess = data.get("session", {})
        session = ExamSession(
            session_id=raw_sess.get("session_id", "CPENT-SIM-01"),
            mode=raw_sess.get("mode", "24h"),
            session_part=raw_sess.get("session_part", 1),
            state=raw_sess.get("state", "not_started"),
            start_time=raw_sess.get("start_time"),
            elapsed_seconds=raw_sess.get("elapsed_seconds", 0),
            total_allowed_seconds=raw_sess.get("total_allowed_seconds", 86400),
            score=raw_sess.get("score", 0),
            captured_flag_ids=raw_sess.get("captured_flag_ids", []),
            project_id=raw_sess.get("project_id"),
        )

        captured_map = {item["flag_id"]: item for item in data.get("captured_flags", [])}
        computed_score = 0
        for r in ranges:
            for f in r.flags:
                if f.flag_id in captured_map:
                    f.captured = True
                    f.captured_at = captured_map[f.flag_id].get("captured_at")
                    f.evidence_text = captured_map[f.flag_id].get("evidence_text", "")
                    computed_score += f.points

        session.score = computed_score
        return session, ranges
    except Exception:
        return ExamSession(), ranges


def export_exam_markdown_report(
    session: ExamSession, ranges: List[ExamRange], project_name: str = "CPENT Exam Practice"
) -> str:
    """Generates an executive exam transcript and flag verification debrief in Markdown."""
    milestones = calculate_exam_milestones(session.score)
    hours = session.elapsed_seconds // 3600
    minutes = (session.elapsed_seconds % 3600) // 60
    seconds = session.elapsed_seconds % 60

    result_badge = "🏆 LPT (MASTER) QUALIFIED" if milestones["lpt_master_achieved"] else (
        "🎯 CPENT CERTIFIED PASS" if milestones["cpent_passed"] else "❌ INCOMPLETE / NOT PASSED"
    )

    lines = [
        f"# EC-Council CPENT / LPT Master Exam Simulator Debrief",
        f"**Project / Engagement:** {project_name}",
        f"**Session ID:** `{session.session_id}` | **Exam Mode:** `{session.mode.upper()}`",
        f"**Date Generated:** `{_utc_now_iso()}`",
        "",
        "---",
        "",
        "## 1. Executive Performance Summary",
        f"- **Final Score:** `{session.score} / 3000 Points` ({milestones['percentage']}%)",
        f"- **Result:** **{result_badge}**",
        f"- **Time Elapsed:** `{hours:02d}h {minutes:02d}m {seconds:02d}s`",
        f"- **CPENT Passing Threshold (70% / 2,100 pts):** {'✅ PASSED' if milestones['cpent_passed'] else '❌ NOT MET'}",
        f"- **LPT Master Honor Threshold (90% / 2,700 pts):** {'🏆 ACHIEVED' if milestones['lpt_master_achieved'] else '❌ NOT MET'}",
        "",
        "| Challenge Enclave | Target Subnet | Score Achieved | Max Points | Captured |",
        "| :--- | :--- | :---: | :---: | :---: |",
    ]

    for r in ranges:
        lines.append(
            f"| {r.icon} {r.name} | `{r.target_subnet}` | **{r.captured_points}** | {r.total_points} | {r.captured_count}/{r.total_count} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 2. Captured Flag Verification & Evidence Log",
    ])

    captured_flags = [f for r in ranges for f in r.flags if f.captured]
    if not captured_flags:
        lines.append("*No flags captured yet in this simulation session.*")
    else:
        lines.append("| Flag ID | Enclave | Challenge Title | Target IP | Points | Captured At |")
        lines.append("| :--- | :--- | :--- | :--- | :---: | :--- |")
        for f in captured_flags:
            lines.append(
                f"| `{f.flag_id}` | `{f.range_id}` | {f.title} | `{f.target_ip}:{f.service_port}` | **+{f.points}** | `{f.captured_at or 'N/A'}` |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Tactical Gap Analysis & Recommendations",
    ])
    gap = generate_gap_analysis(ranges, session.score)
    for adv in gap["advice_lines"]:
        lines.append(f"- {adv}")

    return "\n".join(lines)

