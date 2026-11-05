"""Unit and integration test suite for Python Security Learning Features.

Covers:
1. Pure Python AST Security Scanner (Feature A):
   - Command injection (os.system, subprocess shell=True, eval/exec).
   - Insecure deserialization (pickle, PyYAML without SafeLoader).
   - Insecure TLS bypass (verify=False, unverified SSL context).
   - Hardcoded secrets and credentials in variables.
   - Weak hashing (MD5).
   - SQL injection string formatting.
2. Offline PCAP Protocol Analyzer (Feature B):
   - DNS tunneling & high entropy detection.
   - HTTP web attack payload extraction.
   - ARP poisoning / duplicate MAC detection.
   - Evidence Vault integrity and scope gating.
"""

from __future__ import annotations

from pathlib import Path
import struct
import pytest

from modules.code_security.ast_visitor import PythonSecurityScanner
from modules.network.pcap_analyzer import OfflinePCAPAnalyzer
from storage.db import Database
from storage.models import (
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def sample_project(db: Database) -> Project:
    p = db.create_project(
        Project(
            name="Python Security Learning Lab",
            client_name="Internal Defense Academy",
            description="Testing AST SAST and PCAP protocol analysis.",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p.id, target="192.168.1.100", target_type=TargetType.IP_ADDRESS
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p.id, target="vulnerable_app.py", target_type=TargetType.HOSTNAME
        )
    )
    return p


SAMPLE_VULNERABLE_PYTHON_CODE = """
import os
import subprocess
import pickle
import yaml
import hashlib
import requests
import sqlite3

def run_service(user_input):
    # 1. Command Injection
    os.system("ping -c 1 " + user_input)
    subprocess.Popen(f"echo {user_input}", shell=True)

    # 2. Arbitrary Code Execution
    eval(user_input)

    # 3. Unsafe Deserialization
    data = pickle.loads(user_input.encode())
    cfg = yaml.load(user_input)

    # 4. Insecure TLS Bypass
    requests.get("https://internal.corp", verify=False)

    # 5. Weak Hashing
    h = hashlib.md5(user_input.encode()).hexdigest()

    # 6. Hardcoded Secret
    jwt_secret = "SuperSecretKey987654321"

    # 7. SQL Injection
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM accounts WHERE id = '{user_input}'")
"""


def test_python_ast_scanner_detects_all_vulnerability_categories(
    db: Database, sample_project: Project, tmp_path: Path
):
    """Verifies AST scanner detects command injection, pickle, eval, secrets, and sqli."""
    py_file = tmp_path / "vulnerable_app.py"
    py_file.write_text(SAMPLE_VULNERABLE_PYTHON_CODE, encoding="utf-8")

    scanner = PythonSecurityScanner(db=db)
    res = scanner.scan_path(py_file, project_id=sample_project.id)

    assert res.scanned_files_count == 1
    assert len(res.issues) >= 8

    rule_ids = {issue.rule_id for issue in res.issues}
    # Command Injection
    assert "PY-SEC-001" in rule_ids  # eval/exec
    assert "PY-SEC-002" in rule_ids  # os.system
    assert "PY-SEC-003" in rule_ids  # subprocess shell=True
    # Deserialization
    assert "PY-SEC-004" in rule_ids  # pickle.loads
    assert "PY-SEC-005" in rule_ids  # yaml.load
    # Insecure TLS
    assert "PY-SEC-006" in rule_ids  # verify=False
    # Weak Crypto
    assert "PY-SEC-008" in rule_ids  # hashlib.md5
    # SQLi
    assert "PY-SEC-009" in rule_ids  # SQL Injection
    # Hardcoded Secrets
    assert "PY-SEC-010" in rule_ids  # jwt_secret

    # Check normalized findings
    assert len(res.findings) == len(res.issues)
    assert res.evidence_id is not None
    assert res.evidence_hash != ""


def test_pcap_analyzer_detects_dns_tunneling_and_http_attacks(
    db: Database, sample_project: Project, tmp_path: Path
):
    """Verifies PCAP analyzer dissects DNS tunneling, HTTP web attacks, and ARP anomalies."""
    pcap_file = tmp_path / "traffic_sample.pcap"

    # Global PCAP header (DLT_EN10MB = 1)
    pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packets = []

    # 1. DNS Packet with Tunneling Query (High entropy long subdomain)
    eth_dns = b"\x00\x0c\x29\x11\x22\x33\x00\x0c\x29\xaa\xbb\xcc\x08\x00"
    ip_dns = (
        b"\x45\x00\x00\x5c\x12\x34\x00\x00\x40\x11\x00\x00"
        + bytes([192, 168, 1, 100])  # src_ip
        + bytes([8, 8, 8, 8])  # dst_ip
    )
    udp_dns = struct.pack("!HHHH", 54321, 53, 72, 0)
    # Long high-entropy DNS query
    dns_sub = b"a98f7e6d5c4b3a210fedcba9876543210fedcba"
    dns_domain = struct.pack("B", len(dns_sub)) + dns_sub + b"\x04corp\x03com\x00"
    dns_payload = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + dns_domain
        + struct.pack("!HH", 16, 1)  # TXT record query
    )
    packets.append(eth_dns + ip_dns + udp_dns + dns_payload)

    # 2. HTTP Packet with SQL Injection Payload
    eth_http = b"\x00\x0c\x29\x11\x22\x33\x00\x0c\x29\xaa\xbb\xcc\x08\x00"
    ip_http = (
        b"\x45\x00\x00\x80\x56\x78\x00\x00\x40\x06\x00\x00"
        + bytes([10, 0, 0, 5])
        + bytes([192, 168, 1, 100])
    )
    tcp_http = struct.pack("!HHIIBBHHH", 49152, 80, 1000, 0, 0x50, 0x18, 8192, 0, 0)
    http_data = b"GET /products?category=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1\r\nHost: 192.168.1.100\r\nUser-Agent: sqlmap/1.7\r\n\r\n"
    packets.append(eth_http + ip_http + tcp_http + http_data)

    # 3. Two conflicting ARP replies for 192.168.1.100 (ARP Poisoning anomaly)
    # ARP 1: MAC aa:aa:aa:aa:aa:aa claims 192.168.1.100
    arp_pkt1 = (
        b"\xff\xff\xff\xff\xff\xff\xaa\xaa\xaa\xaa\xaa\xaa\x08\x06"
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + b"\xaa\xaa\xaa\xaa\xaa\xaa"
        + bytes([192, 168, 1, 100])
        + b"\x00\x00\x00\x00\x00\x00"
        + bytes([192, 168, 1, 1])
    )
    packets.append(arp_pkt1)

    # ARP 2: MAC bb:bb:bb:bb:bb:bb claims 192.168.1.100
    arp_pkt2 = (
        b"\xff\xff\xff\xff\xff\xff\xbb\xbb\xbb\xbb\xbb\xbb\x08\x06"
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + b"\xbb\xbb\xbb\xbb\xbb\xbb"
        + bytes([192, 168, 1, 100])
        + b"\x00\x00\x00\x00\x00\x00"
        + bytes([192, 168, 1, 1])
    )
    packets.append(arp_pkt2)

    with open(pcap_file, "wb") as f:
        f.write(pcap_hdr)
        for p in packets:
            pkt_hdr = struct.pack("<IIII", 1700000000, 500000, len(p), len(p))
            f.write(pkt_hdr)
            f.write(p)

    analyzer = OfflinePCAPAnalyzer(db=db)
    res = analyzer.analyze_pcap(
        pcap_file, project_id=sample_project.id, evidence_dir=tmp_path
    )

    assert res.total_packets == 4
    assert len(res.dns_queries) == 1
    assert res.dns_queries[0].is_suspicious_tunnel is True

    assert len(res.http_transactions) == 1
    assert "SQL Injection (CWE-89)" in res.http_transactions[0].attack_tags

    assert len(res.arp_anomalies) >= 1
    assert "192.168.1.100" in res.arp_anomalies[0]

    # Verify findings created and in scope
    assert len(res.findings) >= 2
    assert res.is_authorized is True

