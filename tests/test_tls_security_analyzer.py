"""Comprehensive Automated Test Suite for TLS/SSL Security & Cipher Suite Analyzer.

Verifies:
1. Valid trusted certificate
2. Expired certificate detection
3. Self-signed certificate detection
4. Hostname mismatch detection (RFC 6125)
5. Incomplete certificate chain / untrusted issuer handling
6. TLS 1.2 safe handshake
7. TLS 1.3 safe handshake
8. Weak cipher suite detection (NULL, EXPORT, Anonymous, 3DES, RC4)
9. Unsupported protocol handling
10. Strict scope authorization rejection (Fail-closed)
11. Evidence cryptographic SHA-256 integrity
12. Finding-to-evidence & execution linkage
13. Duplicate finding prevention
14. Report builder integration (HTML & Markdown)
15. GUI widget empty state and result rendering
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Generator, Tuple

import pytest
from PySide6.QtWidgets import QApplication

from core.scope import ScopeAuthorizationService
from desktop.widgets.tls_analyzer_widget import TLSAnalyzerWidget
from modules.crypto.tls_adapter import TLSAssessmentAdapter
from modules.crypto.tls_analyzer import (
    TLSAssessmentEngine,
    TLSAssessmentReport,
    TLSCertificateAnalyzer,
    TLSCipherAnalyzer,
    TLSProtocolAnalyzer,
)
from reports.builder import ReportBuilder, ReportFormat
from storage.db import Database
from storage.models import (
    Finding,
    FindingSeverity,
    Project,
    ScopeRuleType,
    TargetScope,
    TargetType,
    ValidationStatus,
)


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def generate_synthetic_cert(
    output_dir: Path,
    common_name: str = "localhost",
    sans: Optional[list[str]] = None,
    days: int = 30,
    key_type: str = "rsa:2048",
    sig_hash: str = "sha256",
) -> Tuple[Path, Path]:
    """Generates synthetic certificate and private key using openssl CLI."""
    key_file = output_dir / f"{common_name}_key.pem"
    cert_file = output_dir / f"{common_name}_cert.pem"

    cmd = [
        "openssl", "req", "-x509", "-newkey", key_type,
        "-keyout", str(key_file), "-out", str(cert_file),
        "-days", str(days), "-nodes",
        f"-{sig_hash}",
        "-subj", f"/CN={common_name}/O=CyberSecuritySuite/C=US",
    ]
    if sans:
        san_str = ",".join(sans)
        cmd.extend(["-addext", f"subjectAltName={san_str}"])

    subprocess.run(cmd, check=True, capture_output=True)
    return cert_file, key_file


class MockServerContext:
    """Manages an ephemeral background mock TLS server on localhost."""

    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        min_ver: Optional[ssl.TLSVersion] = None,
        max_ver: Optional[ssl.TLSVersion] = None,
        ciphers: Optional[str] = None,
    ):
        self.cert_path = cert_path
        self.key_path = key_path
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind(("127.0.0.1", 0))
        self.server_sock.listen(5)
        self.port = self.server_sock.getsockname()[1]
        self.running = True

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if min_ver:
            self.ctx.minimum_version = min_ver
        if max_ver:
            self.ctx.maximum_version = max_ver
        if ciphers:
            try:
                self.ctx.set_ciphers(ciphers)
            except ssl.SSLError:
                pass
        self.ctx.load_cert_chain(str(cert_path), str(key_path))

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
                with self.ctx.wrap_socket(conn, server_side=True) as ssock:
                    _ = ssock.recv(1024)
                    ssock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except Exception:
                pass

    def stop(self):
        self.running = False
        try:
            self.server_sock.close()
        except Exception:
            pass


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "test_tls.db")


@pytest.fixture
def temp_project(temp_db: Database) -> Project:
    p = temp_db.create_project(Project(name="TLS Assessment Test Project", client_name="Acme Corp"))
    # Authorize 127.0.0.1 / localhost
    temp_db.add_scope(TargetScope(
        project_id=p.id,
        target="127.0.0.1",
        target_type=TargetType.IP_ADDRESS,
        rule_type=ScopeRuleType.ALLOWED,
    ))
    temp_db.add_scope(TargetScope(
        project_id=p.id,
        target="localhost",
        target_type=TargetType.HOSTNAME,
        rule_type=ScopeRuleType.ALLOWED,
    ))
    return p


# =====================================================================
# 1. Valid Trusted Certificate
# =====================================================================
def test_valid_trusted_certificate(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "localhost", ["DNS:localhost", "IP:127.0.0.1"], days=365)
    with open(cert, "r") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())

    info = TLSCertificateAnalyzer.parse_der_certificate(der, "localhost")
    assert info.subject.get("commonName") == "localhost"
    assert info.hostname_matches is True
    assert info.is_expired is False
    assert info.is_not_yet_valid is False
    assert info.days_until_expiration >= 360
    assert info.public_key_bits == 2048
    assert "RSA" in info.public_key_algorithm
    assert "SHA-256" in info.signature_algorithm or "sha256" in info.signature_algorithm.lower()


# =====================================================================
# 2. Expired Certificate
# =====================================================================
def test_expired_certificate(tmp_path: Path):
    # Generate cert and modify validity in DER bytes to past year
    cert, key = generate_synthetic_cert(tmp_path, "expired.local", ["DNS:expired.local"], days=1)
    with open(cert, "r") as f:
        der = bytearray(ssl.PEM_cert_to_DER_cert(f.read()))

    # Find second UTCTime (notAfter) and set year to 20 (2020)
    idx1 = der.find(b"\x17\x0d")
    idx2 = der.find(b"\x17\x0d", idx1 + 15)
    der[idx2 + 2 : idx2 + 4] = b"20"

    info = TLSCertificateAnalyzer.parse_der_certificate(bytes(der), "expired.local")
    assert info.is_expired is True
    assert info.days_until_expiration < 0

    val_status, val_msg = TLSCertificateAnalyzer.evaluate_trust_chain("expired.local", 443, info)
    assert val_status == "expired"
    assert "expired" in val_msg.lower()


# =====================================================================
# 3. Self-Signed Certificate
# =====================================================================
def test_self_signed_certificate(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "selfsigned.local", ["DNS:selfsigned.local"], days=90)
    with open(cert, "r") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())

    info = TLSCertificateAnalyzer.parse_der_certificate(der, "selfsigned.local")
    assert info.is_self_signed is True
    assert info.subject == info.issuer

    # Evaluating against public CA bundle should report self-signed
    val_status, val_msg = TLSCertificateAnalyzer.evaluate_trust_chain("selfsigned.local", 443, info)
    assert val_status in ("self_signed", "untrusted_issuer")


# =====================================================================
# 4. Hostname Mismatch (RFC 6125)
# =====================================================================
def test_hostname_mismatch(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "internal-portal.corp", ["DNS:internal-portal.corp"], days=90)
    with open(cert, "r") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())

    # Assess connecting to target 'api.corp'
    info = TLSCertificateAnalyzer.parse_der_certificate(der, "api.corp")
    assert info.hostname_matches is False

    val_status, val_msg = TLSCertificateAnalyzer.evaluate_trust_chain("api.corp", 443, info)
    assert val_status == "hostname_mismatch"
    assert "mismatch" in val_msg.lower()


# =====================================================================
# 5. Incomplete Certificate Chain / Untrusted Issuer
# =====================================================================
def test_incomplete_certificate_chain(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "leaf.local", ["DNS:leaf.local"], days=60)
    with open(cert, "r") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())

    info = TLSCertificateAnalyzer.parse_der_certificate(der, "leaf.local")
    # Untrusted custom entity
    val_status, _ = TLSCertificateAnalyzer.evaluate_trust_chain("leaf.local", 443, info)
    assert val_status in ("self_signed", "untrusted_issuer", "incomplete_chain")


# =====================================================================
# 6. TLS 1.2 Handshake
# =====================================================================
def test_tls12_handshake_success(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "localhost", ["DNS:localhost", "IP:127.0.0.1"])
    server = MockServerContext(cert, key, min_ver=ssl.TLSVersion.TLSv1_2, max_ver=ssl.TLSVersion.TLSv1_2)
    try:
        protocols = TLSProtocolAnalyzer.audit_protocols("127.0.0.1", server.port)
        tls12 = next((p for p in protocols if p.protocol_version == "TLSv1.2"), None)
        assert tls12 is not None
        assert tls12.status == "supported"
        assert tls12.negotiated_cipher is not None
    finally:
        server.stop()


# =====================================================================
# 7. TLS 1.3 Handshake
# =====================================================================
def test_tls13_handshake_success(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "localhost", ["DNS:localhost", "IP:127.0.0.1"])
    server = MockServerContext(cert, key, min_ver=ssl.TLSVersion.TLSv1_3, max_ver=ssl.TLSVersion.TLSv1_3)
    try:
        protocols = TLSProtocolAnalyzer.audit_protocols("127.0.0.1", server.port)
        tls13 = next((p for p in protocols if p.protocol_version == "TLSv1.3"), None)
        assert tls13 is not None
        assert tls13.status == "supported"
    finally:
        server.stop()


# =====================================================================
# 8. Weak Cipher Suite Detection
# =====================================================================
def test_weak_cipher_detection(tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "localhost", ["DNS:localhost", "IP:127.0.0.1"])
    server = MockServerContext(cert, key)
    try:
        cipher_results = TLSCipherAnalyzer.audit_ciphers("127.0.0.1", server.port)
        assert len(cipher_results) > 0
        cat_ids = {c.category for c in cipher_results}
        assert "null" in cat_ids
        assert "export" in cat_ids
        assert "forward_secrecy" in cat_ids
    finally:
        server.stop()


# =====================================================================
# 9. Unsupported Protocol Handling
# =====================================================================
def test_unsupported_protocol_handling():
    res_ssl2 = TLSProtocolAnalyzer._probe_ssl_legacy("SSLv2", False)
    assert res_ssl2.status == "unavailable"
    assert "disabled" in res_ssl2.notes or "removed" in res_ssl2.notes


# =====================================================================
# 10. Scope Rejection (Fail-Closed)
# =====================================================================
def test_scope_rejection(temp_db: Database, temp_project: Project, tmp_path: Path):
    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")

    # Assess unauthorized IP (not 127.0.0.1)
    res = adapter.assess_target(temp_project.id, "192.168.100.99", port=443)
    assert res.is_authorized is False
    assert "authorized scope" in res.scope_reason.lower()


# =====================================================================
# 11. Evidence SHA-256 Integrity
# =====================================================================
def test_evidence_sha256_integrity(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"])
    server = MockServerContext(cert, key)
    ev_dir = tmp_path / "evidence"
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=ev_dir)
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"
        assert res.evidence_hash is not None
        assert res.evidence_id is not None

        # Verify evidence in DB
        ev_record = temp_db.get_evidence(res.evidence_id)
        assert ev_record is not None
        assert ev_record.sha256_hash == res.evidence_hash

        # Verify file content hash matches
        with open(ev_record.file_path, "rb") as f:
            calculated = hashlib.sha256(f.read()).hexdigest()
        assert calculated == res.evidence_hash
    finally:
        server.stop()


# =====================================================================
# 12. Finding-to-Evidence Linkage
# =====================================================================
def test_finding_to_evidence_linkage(temp_db: Database, temp_project: Project, tmp_path: Path):
    # Self-signed synthetic cert generates finding
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert len(res.findings) >= 1
        for f in res.findings:
            assert f.execution_id == res.execution_id
            assert f.source_tool == "tls_analyzer"
    finally:
        server.stop()


# =====================================================================
# 13. Duplicate Finding Prevention
# =====================================================================
def test_duplicate_finding_prevention(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")

        # Run 1
        res1 = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        initial_findings = temp_db.list_findings(temp_project.id)
        count1 = len(initial_findings)

        # Run 2 against exact same target
        res2 = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        updated_findings = temp_db.list_findings(temp_project.id)
        count2 = len(updated_findings)

        # Count should remain identical (deduplicated)
        assert count1 == count2
    finally:
        server.stop()


# =====================================================================
# 14. Report Generation Integration
# =====================================================================
def test_report_generation_with_tls(temp_db: Database, temp_project: Project, tmp_path: Path):
    # Create finding and evidence
    f = temp_db.create_finding(Finding(
        project_id=temp_project.id,
        title="Expired TLS / SSL Certificate",
        severity=FindingSeverity.HIGH,
        affected_asset="127.0.0.1:443",
        source_tool="tls_analyzer",
        remediation="Renew TLS certificate from public CA.",
        validation_status=ValidationStatus.CONFIRMED,
    ))

    builder = ReportBuilder(db=temp_db)

    # 1. Markdown Report
    md_content = builder.generate_markdown(temp_project.id)
    assert "## TLS / SSL Certificate & Cryptographic Assessment" in md_content
    assert "Expired TLS / SSL Certificate" in md_content
    assert "127.0.0.1:443" in md_content

    # 2. HTML Report
    html_content = builder.generate_html(temp_project.id)
    assert "TLS / SSL Certificate & Cryptographic Assessment" in html_content
    assert "Expired TLS / SSL Certificate" in html_content


# =====================================================================
# 15. GUI Empty State and Result Rendering
# =====================================================================
def test_gui_empty_state_and_rendering(qapp, temp_db: Database, temp_project: Project, tmp_path: Path):
    widget = TLSAnalyzerWidget(db=temp_db)
    widget.set_active_project(temp_project)

    # Empty / initial state
    assert widget.tabs.count() == 6
    assert "UNASSESSED" in widget.lbl_posture.text()
    assert widget.table_protocols.rowCount() == 0
    assert widget.table_findings.rowCount() == 0

    # Simulate completed report rendering
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"])
    server = MockServerContext(cert, key)
    try:
        report = TLSAssessmentEngine.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        widget._render_report(report)

        assert widget.table_protocols.rowCount() > 0
        assert widget.table_ciphers.rowCount() > 0
        assert widget.lbl_cn.text() == "127.0.0.1"
    finally:
        server.stop()


# =====================================================================
# 16. Certificate AssetNode Creation
# =====================================================================
def test_certificate_asset_node_creation(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"

        nodes = temp_db.list_asset_nodes(temp_project.id)
        cert_nodes = [n for n in nodes if n.node_type == "cert"]
        assert len(cert_nodes) == 1
        c_node = cert_nodes[0]
        assert c_node.id is not None
        assert c_node.source_tool == "tls_analyzer"
        assert "127.0.0.1" in c_node.label
        meta = json.loads(c_node.metadata_json)
        assert "sha256" in meta
        assert "not_after" in meta
        assert "subject" in meta
    finally:
        server.stop()


# =====================================================================
# 17. Host-to-Certificate HAS_CERTIFICATE Edge Creation
# =====================================================================
def test_host_to_certificate_edge_creation(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"

        edges = temp_db.list_asset_edges(temp_project.id)
        cert_edges = [e for e in edges if e.relation_type == "HAS_CERTIFICATE"]
        assert len(cert_edges) == 1
        edge = cert_edges[0]
        assert edge.source_node_id > 0
        assert edge.target_node_id > 0
        assert edge.source_tool == "tls_analyzer"
        assert edge.evidence_id == res.evidence_id

        nodes = {n.id: n for n in temp_db.list_asset_nodes(temp_project.id)}
        assert edge.source_node_id in nodes
        assert nodes[edge.source_node_id].value == "127.0.0.1"
        assert edge.target_node_id in nodes
        assert nodes[edge.target_node_id].node_type == "cert"
    finally:
        server.stop()


# =====================================================================
# 18. Duplicate Edge Prevention
# =====================================================================
def test_duplicate_edge_prevention(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")

        # Run 1
        res1 = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res1.execution_status.value == "completed"
        edges1 = [e for e in temp_db.list_asset_edges(temp_project.id) if e.relation_type == "HAS_CERTIFICATE"]
        assert len(edges1) == 1
        edge_id = edges1[0].id

        # Run 2 against exact same target
        res2 = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res2.execution_status.value == "completed"
        edges2 = [e for e in temp_db.list_asset_edges(temp_project.id) if e.relation_type == "HAS_CERTIFICATE"]

        # Number of edges must remain exactly 1 (not duplicated)
        assert len(edges2) == 1
        assert edges2[0].id == edge_id
    finally:
        server.stop()


# =====================================================================
# 19. Evidence Directory Passed as String
# =====================================================================
def test_evidence_dir_passed_as_string(temp_db: Database, temp_project: Project, tmp_path: Path):
    str_dir = str(tmp_path / "custom_str_evidence")
    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=str_dir)
    assert isinstance(adapter.evidence_dir, Path)
    assert adapter.evidence_dir.exists()

    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"])
    server = MockServerContext(cert, key)
    try:
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"
        files = list(adapter.evidence_dir.glob("*.json"))
        assert len(files) == 1
    finally:
        server.stop()


# =====================================================================
# 20. Evidence Directory Passed as Path
# =====================================================================
def test_evidence_dir_passed_as_path(temp_db: Database, temp_project: Project, tmp_path: Path):
    path_dir = tmp_path / "custom_path_evidence"
    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=path_dir)
    assert isinstance(adapter.evidence_dir, Path)
    assert adapter.evidence_dir.exists()

    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"])
    server = MockServerContext(cert, key)
    try:
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"
        files = list(adapter.evidence_dir.glob("*.json"))
        assert len(files) == 1
    finally:
        server.stop()


# =====================================================================
# 21. Ed25519 OID Recognition
# =====================================================================
def test_ed25519_oid_recognition():
    from modules.crypto.tls_analyzer import PUBLIC_KEY_OIDS, SIGNATURE_ALG_OIDS, OID_MAP, TLSCertificateAnalyzer, TLSCertificateInfo

    # 1. Dictionary mappings
    assert "1.3.101.112" in PUBLIC_KEY_OIDS
    assert PUBLIC_KEY_OIDS["1.3.101.112"][0] == "Ed25519"
    assert "1.3.101.112" in SIGNATURE_ALG_OIDS
    assert SIGNATURE_ALG_OIDS["1.3.101.112"][0] == "Ed25519"
    assert "1.3.101.112" in OID_MAP
    assert OID_MAP["1.3.101.112"][0] == "Ed25519"

    # 2. Synthetic ASN.1 DER parser test with Ed25519 OID in outer signature algorithm
    # Construct minimal ASN.1 sequence: SEQUENCE { TBSCert SEQUENCE {}, SigAlg SEQUENCE { OBJECT IDENTIFIER 1.3.101.112 } }
    ed25519_oid_bytes = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])  # 1.3.101.112
    sig_alg_seq = bytes([0x30, len(ed25519_oid_bytes)]) + ed25519_oid_bytes
    tbs_cert_seq = bytes([0x30, 0x00])  # Empty TBS
    cert_val = tbs_cert_seq + sig_alg_seq
    der_bytes = bytes([0x30, len(cert_val)]) + cert_val

    info = TLSCertificateInfo(subject={}, issuer={})
    TLSCertificateAnalyzer._parse_asn1_parameters(der_bytes, info)
    assert info.signature_algorithm == "Ed25519"


# =====================================================================
# 22. Out-of-Scope Hostname Rejection
# =====================================================================
def test_out_of_scope_hostname_rejection(temp_db: Database, temp_project: Project, tmp_path: Path):
    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
    # Hostname not in authorized scopes
    res = adapter.assess_target(temp_project.id, "unauthorized.evilcorp.com", port=443)
    assert res.is_authorized is False
    assert res.execution_status.value == "failed"
    assert "scope" in res.error_message.lower() or "scope" in res.scope_reason.lower()


# =====================================================================
# 23. DNS Resolution Changes & Rebinding Prevention
# =====================================================================
def test_dns_resolution_rebinding_prevention(temp_db: Database, temp_project: Project, tmp_path: Path, monkeypatch):
    # Add in-scope domain
    temp_db.add_scope(TargetScope(
        project_id=temp_project.id,
        target="corp.internal",
        target_type=TargetType.HOSTNAME,
        rule_type=ScopeRuleType.ALLOWED,
    ))

    # Mock DNS resolution to return an out-of-scope IP (e.g. 10.254.254.254)
    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host == "corp.internal":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.254.254.254", port))
            ]
        return socket.getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
    res = adapter.assess_target(temp_project.id, "corp.internal", port=443)

    # Must reject because resolved IP 10.254.254.254 is outside authorized scope
    assert res.is_authorized is False
    assert "outside authorized scope" in res.error_message
    assert "10.254.254.254" in res.error_message


# =====================================================================
# 24. IPv4 and IPv6 Scope Validation
# =====================================================================
def test_ipv4_and_ipv6_scope_validation(temp_db: Database, temp_project: Project, tmp_path: Path):
    # Add IPv6 scope to project
    temp_db.add_scope(TargetScope(
        project_id=temp_project.id,
        target="::1",
        target_type=TargetType.IP_ADDRESS,
        rule_type=ScopeRuleType.ALLOWED,
    ))
    # Add IPv6 excluded scope
    temp_db.add_scope(TargetScope(
        project_id=temp_project.id,
        target="2001:db8::/32",
        target_type=TargetType.CIDR_RANGE,
        rule_type=ScopeRuleType.EXCLUDED,
    ))

    adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")

    # 1. Allowed IPv4
    res_v4 = adapter.validate_target_scope("127.0.0.1", temp_project.id)
    assert res_v4.is_allowed is True

    # 2. Allowed IPv6
    res_v6 = adapter.validate_target_scope("::1", temp_project.id)
    assert res_v6.is_allowed is True

    # 3. Excluded IPv6
    res_v6_ex = adapter.validate_target_scope("2001:db8::1", temp_project.id)
    assert res_v6_ex.is_allowed is False

    # 4. Out-of-scope IPv6
    res_v6_out = adapter.validate_target_scope("2607:f8b0:4005:805::200e", temp_project.id)
    assert res_v6_out.is_allowed is False


# =====================================================================
# 25. Complete Evidence and Finding Linkage
# =====================================================================
def test_evidence_and_finding_linkage_complete(temp_db: Database, temp_project: Project, tmp_path: Path):
    cert, key = generate_synthetic_cert(tmp_path, "127.0.0.1", ["IP:127.0.0.1"], days=30)
    server = MockServerContext(cert, key)
    try:
        adapter = TLSAssessmentAdapter(db=temp_db, evidence_dir=tmp_path / "evidence")
        res = adapter.assess_target(temp_project.id, "127.0.0.1", port=server.port)
        assert res.execution_status.value == "completed"
        assert res.execution_id is not None
        assert res.evidence_id is not None

        # Verify findings in DB are linked to execution_id
        findings = temp_db.list_findings(temp_project.id)
        assert len(findings) > 0
        for f in findings:
            assert f.execution_id == res.execution_id

        # Verify evidence in DB is linked to execution_id
        ev = temp_db.get_evidence(res.evidence_id)
        assert ev is not None
        assert ev.execution_id == res.execution_id

        # Verify AssetEdge has evidence_id linked
        edges = [e for e in temp_db.list_asset_edges(temp_project.id) if e.relation_type == "HAS_CERTIFICATE"]
        assert len(edges) == 1
        assert edges[0].evidence_id == res.evidence_id
    finally:
        server.stop()

