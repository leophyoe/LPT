"""Tests for Phase 6A: Active Directory / LDAP Live Enumeration.

Covers:
- RootDSE and Naming Context parsing
- Domain Controller, Users, Groups, Computers, OUs enumeration
- UAC bitmask flag analysis (AS-REP roasting, password never expires, password not required)
- Domain Password Policy parsing & weakness detection
- Scope Authorization and Fail-Closed rejection
- Sensitive attribute redaction and SHA-256 evidence generation
- Duplicate asset handling during database synchronization
- UI widget integration
"""

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
from typing import Dict, List
from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

from core.scope import ScopeAuthorizationService
from reports.builder import ReportBuilder
from modules.identity.ldap_adapter import (
    DomainPasswordPolicy,
    LDAPEnumerationResult,
    LDAPLiveEnumerationAdapter,
    UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH,
    UAC_NORMAL_ACCOUNT,
    UAC_PASSWD_NOTREQD,
    UAC_SERVER_TRUST_ACCOUNT,
)
from modules.identity.ldap_client import (
    LDAPEntry,
    ReadOnlyLDAPClient,
    SCOPE_BASE,
    SCOPE_SUBTREE,
    TAG_BIND_RESPONSE,
    TAG_SEARCH_RES_DONE,
    TAG_SEARCH_RES_ENTRY,
    MAX_MESSAGE_SIZE,
    RESULT_SIZE_LIMIT_EXCEEDED,
    SENSITIVE_ATTRIBUTES,
    decode_integer,
    decode_length,
    encode_enumerated,
    encode_integer,
    encode_octet_string,
    encode_sequence,
    encode_tlv,
    escape_filter_value,
    format_guid,
    format_sid,
    parse_sequence_elements,
)
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    FindingSeverity,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


# Helper to build mock search response messages
def build_search_entry_msg(msg_id: int, dn: str, attributes: Dict[str, List[str]]) -> bytes:
    attr_seqs = []
    for k, vals in attributes.items():
        v_seq = encode_tlv(0x31, b"".join(encode_octet_string(v) for v in vals))
        attr_seqs.append(encode_tlv(0x30, encode_octet_string(k) + v_seq))
    attrs_tlv = encode_tlv(0x30, b"".join(attr_seqs))
    entry_op = encode_tlv(TAG_SEARCH_RES_ENTRY, encode_octet_string(dn) + attrs_tlv)
    return encode_sequence([encode_integer(msg_id), entry_op])


def build_search_done_msg(msg_id: int, code: int = 0) -> bytes:
    done_op = encode_tlv(TAG_SEARCH_RES_DONE, encode_enumerated(code) + encode_octet_string("") + encode_octet_string(""))
    return encode_sequence([encode_integer(msg_id), done_op])


def build_bind_response_msg(msg_id: int, code: int = 0) -> bytes:
    bind_op = encode_tlv(TAG_BIND_RESPONSE, encode_enumerated(code) + encode_octet_string("") + encode_octet_string(""))
    return encode_sequence([encode_integer(msg_id), bind_op])


class MockActiveDirectoryServer:
    """Mock LDAP server providing standard Active Directory directory responses."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((host, port))
        self.host, self.port = self.server_sock.getsockname()
        self.server_sock.listen(5)
        self.is_running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.server_sock.settimeout(0.5)
        while self.is_running:
            try:
                conn, _ = self.server_sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _recv_exact(self, conn: socket.socket, length: int) -> bytes:
        buf = bytearray()
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _handle_client(self, conn: socket.socket):
        conn.settimeout(2.0)
        try:
            while self.is_running:
                # Read 1 byte tag
                tag = conn.recv(1)
                if not tag:
                    break
                # Read length
                len_b = conn.recv(1)
                if not len_b:
                    break
                length = len_b[0]
                if length >= 128:
                    num_bytes = length & 0x7F
                    length_bytes = self._recv_exact(conn, num_bytes)
                    length = int.from_bytes(length_bytes, "big")
                payload = self._recv_exact(conn, length)
                if len(payload) < length:
                    break

                # Extract request message id to correlate responses
                elements = parse_sequence_elements(payload)
                req_msg_id = decode_integer(elements[0][1]) if elements else 1

                # Protocol op tag is at offset after message id
                # Simple dispatch based on bytes:
                if b"\x60" in payload:  # BindRequest
                    conn.sendall(build_bind_response_msg(req_msg_id, 0))
                elif b"\x63" in payload:  # SearchRequest
                    # Check what is requested
                    if b"8192" in payload:
                        # Domain Controllers
                        entry = build_search_entry_msg(req_msg_id, "CN=DC01,OU=Domain Controllers,DC=corp,DC=local", {
                            "sAMAccountName": ["DC01$"],
                            "dNSHostName": ["dc01.corp.local"],
                            "operatingSystem": ["Windows Server 2022 Datacenter"],
                            "operatingSystemVersion": ["10.0 (20348)"],
                        })
                        conn.sendall(entry + build_search_done_msg(req_msg_id, 0))
                    elif b"person" in payload:
                        # Users: 1 AS-REP roastable, 1 never expire, 1 normal
                        u1 = build_search_entry_msg(req_msg_id, "CN=sql_svc,OU=Service Accounts,DC=corp,DC=local", {
                            "sAMAccountName": ["sql_svc"],
                            "userPrincipalName": ["sql_svc@corp.local"],
                            "displayName": ["SQL Service Account"],
                            "userAccountControl": [str(UAC_NORMAL_ACCOUNT | UAC_DONT_REQ_PREAUTH)],
                        })
                        u2 = build_search_entry_msg(req_msg_id, "CN=legacy_user,OU=Users,DC=corp,DC=local", {
                            "sAMAccountName": ["legacy_user"],
                            "displayName": ["Legacy User"],
                            "userAccountControl": [str(UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD)],
                        })
                        u3 = build_search_entry_msg(req_msg_id, "CN=insecure_user,OU=Users,DC=corp,DC=local", {
                            "sAMAccountName": ["insecure_user"],
                            "displayName": ["Insecure User"],
                            "userAccountControl": [str(UAC_NORMAL_ACCOUNT | UAC_PASSWD_NOTREQD)],
                        })
                        conn.sendall(u1 + u2 + u3 + build_search_done_msg(req_msg_id, 0))
                    elif b"group" in payload:
                        # Groups
                        g1 = build_search_entry_msg(req_msg_id, "CN=Domain Admins,CN=Users,DC=corp,DC=local", {
                            "sAMAccountName": ["Domain Admins"],
                            "adminCount": ["1"],
                            "member": ["CN=Administrator,CN=Users,DC=corp,DC=local"],
                            "description": ["Designated administrators of the domain"],
                        })
                        conn.sendall(g1 + build_search_done_msg(req_msg_id, 0))
                    elif b"computer" in payload:
                        # Computers
                        c1 = build_search_entry_msg(req_msg_id, "CN=WS-FIN-01,OU=Workstations,DC=corp,DC=local", {
                            "sAMAccountName": ["WS-FIN-01$"],
                            "dNSHostName": ["ws-fin-01.corp.local"],
                            "operatingSystem": ["Windows 11 Enterprise"],
                            "operatingSystemVersion": ["10.0 (22621)"],
                            "whenCreated": ["20260101120000.0Z"],
                        })
                        conn.sendall(c1 + build_search_done_msg(req_msg_id, 0))
                    elif b"organizationalUnit" in payload:
                        # OUs
                        ou1 = build_search_entry_msg(req_msg_id, "OU=Domain Controllers,DC=corp,DC=local", {
                            "ou": ["Domain Controllers"],
                            "description": ["Default container for domain controllers"],
                        })
                        conn.sendall(ou1 + build_search_done_msg(req_msg_id, 0))
                    elif b"minPwdLength" in payload or b"lockoutThreshold" in payload:
                        # Password Policy: Weak policy (length 7, lockout 0)
                        pol = build_search_entry_msg(req_msg_id, "DC=corp,DC=local", {
                            "minPwdLength": ["7"],
                            "pwdProperties": ["0"],
                            "lockoutThreshold": ["0"],
                            "lockoutDuration": ["-18000000000"],
                            "pwdHistoryLength": ["2"],
                        })
                        conn.sendall(pol + build_search_done_msg(req_msg_id, 0))
                    elif b"defaultNamingContext" in payload or b"dnsHostName" in payload:
                        # RootDSE response
                        entry = build_search_entry_msg(req_msg_id, "", {
                            "defaultNamingContext": ["DC=corp,DC=local"],
                            "rootDomainNamingContext": ["DC=corp,DC=local"],
                            "dnsHostName": ["dc01.corp.local"],
                            "domainFunctionality": ["7"],
                            "supportedLDAPVersion": ["3", "2"],
                            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO"],
                        })
                        conn.sendall(entry + build_search_done_msg(req_msg_id, 0))
                    else:
                        conn.sendall(build_search_done_msg(req_msg_id, 0))
                elif b"\x42" in payload:  # UnbindRequest
                    break
        except Exception:
            pass
        finally:
            conn.close()

    def close(self):
        self.is_running = False
        try:
            self.server_sock.close()
        except Exception:
            pass


@pytest.fixture
def mock_ad_server():
    server = MockActiveDirectoryServer()
    yield server
    server.close()


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db = Database(f.name)
        yield db
        db.close()


def test_ldap_client_bind_and_root_dse(mock_ad_server):
    """Verifies that ReadOnlyLDAPClient can bind and retrieve RootDSE attributes."""
    client = ReadOnlyLDAPClient(mock_ad_server.host, port=mock_ad_server.port, timeout=2.0)
    ok, msg = client.bind()
    assert ok is True
    assert "successful" in msg.lower()

    entries = client.search(base_dn="", scope=SCOPE_BASE, attributes=["defaultNamingContext", "dnsHostName"])
    client.unbind()

    assert len(entries) == 1
    root = entries[0]
    assert root.get_first("defaultNamingContext") == "DC=corp,DC=local"
    assert root.get_first("dnsHostName") == "dc01.corp.local"


def test_ldap_adapter_full_enumeration_and_findings(mock_ad_server, test_db):
    """Verifies complete Active Directory enumeration, finding generation, and asset synthesis."""
    # Setup authorized project
    proj = test_db.create_project(Project(name="AD Security Audit", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    with tempfile.TemporaryDirectory() as ev_dir:
        result = adapter.execute_enumeration(
            project_id=proj.id,
            target_host=mock_ad_server.host,
            port=mock_ad_server.port,
            use_ssl=False,
            scopes=[scope],
            project=proj,
            evidence_dir=Path(ev_dir),
        )

        assert result.is_authorized is True
        assert result.default_naming_context == "DC=corp,DC=local"
        assert len(result.domain_controllers) >= 1
        assert result.domain_controllers[0]["dns_hostname"] == "dc01.corp.local"

        # Verify Users & UAC analysis
        assert len(result.users) == 3
        asrep_users = [u for u in result.users if u["dont_req_preauth"]]
        assert len(asrep_users) == 1
        assert asrep_users[0]["sam_name"] == "sql_svc"

        # Verify Password Policy
        assert result.password_policy is not None
        assert result.password_policy.min_pwd_length == 7
        assert result.password_policy.lockout_threshold == 0
        assert result.password_policy.complexity_enabled is False

        # Verify Findings Generation
        finding_titles = [f.title for f in result.findings]
        # 1. Anonymous bind finding
        assert any("Anonymous LDAP Bind Permitted" in t for t in finding_titles)
        # 2. Cleartext LDAP finding
        assert any("Cleartext" in t for t in finding_titles)
        # 3. AS-REP Roastable finding
        assert any("AS-REP Roasting" in t for t in finding_titles)
        # 4. Passwords never expire finding
        assert any("Never Expire" in t for t in finding_titles)
        # 5. Passwords not required finding
        assert any("Without Password Requirement" in t for t in finding_titles)
        # 6. Weak password policy finding
        assert any("Weak Active Directory Domain Password Policy" in t for t in finding_titles)

        # Verify Assets synthesized
        node_types = [n.node_type for n in result.discovered_nodes]
        assert "domain_controller" in node_types
        assert "domain" in node_types
        assert "computer" in node_types

        # Verify Evidence SHA-256
        assert result.evidence_id is not None
        ev = test_db.get_evidence(result.evidence_id)
        assert ev is not None
        assert len(ev.sha256_hash) == 64


def test_ldap_adapter_out_of_scope_rejection(test_db):
    """Verifies fail-closed blocking of out-of-scope targets and audit logging."""
    proj = test_db.create_project(Project(name="Restricted Scope", status=ProjectStatus.ACTIVE))
    # Authorized only for 10.0.0.0/8
    test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target="10.0.0.0/8",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    result = adapter.execute_enumeration(
        project_id=proj.id,
        target_host="192.168.99.50",  # Out of scope!
        port=389,
        project=proj,
    )

    assert result.is_authorized is False
    assert "out-of-scope" in result.error_message.lower()

    # Verify audit log record
    logs = test_db.list_audit_logs(proj.id)
    assert len(logs) >= 1
    assert logs[0].action == "out_of_scope_scan_blocked"
    assert "192.168.99.50" in logs[0].details


def test_ldap_synchronize_to_database_avoids_duplicates(mock_ad_server, test_db):
    """Verifies that synchronizing results avoids duplicate assets and correctly updates records."""
    proj = test_db.create_project(Project(name="Sync Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    result = adapter.execute_enumeration(
        project_id=proj.id,
        target_host=mock_ad_server.host,
        port=mock_ad_server.port,
        scopes=[scope],
        project=proj,
    )

    # First Sync
    synced_assets_1, synced_findings_1 = adapter.synchronize_to_database(proj.id, result)
    initial_assets = test_db.list_asset_nodes(proj.id)
    assert len(initial_assets) == len(result.discovered_nodes)

    # Second Sync (re-synchronizing should not create duplicate assets)
    synced_assets_2, _ = adapter.synchronize_to_database(proj.id, result)
    assert synced_assets_2 == 0  # 0 new assets created
    second_assets = test_db.list_asset_nodes(proj.id)
    assert len(second_assets) == len(initial_assets)


def test_ldap_gui_widget_instantiation(test_db):
    """Verifies that ADLDAPLiveEnumeratorWidget instantiates and integrates with dark theme."""
    _ = QApplication.instance() or QApplication([])

    from desktop.widgets.ad_ldap_enumerator_widget import ADLDAPLiveEnumeratorWidget
    widget = ADLDAPLiveEnumeratorWidget(db=test_db)

    proj = test_db.create_project(Project(name="GUI Test", status=ProjectStatus.ACTIVE))
    widget.set_active_project(proj)

    assert widget.active_project.id == proj.id
    assert "GUI Test" in widget.lbl_project_status.text()
    assert widget.btn_start.isEnabled() is True
    assert widget.btn_sync.isEnabled() is False

    widget.close()


# ==============================================================================
# Phase 6A.1 Hardening & Security Test Suite
# ==============================================================================

def test_ber_malformed_input():
    """Verifies that malformed, oversized, or indefinite BER lengths are rejected safely."""
    # 1. Indefinite length encoding (0x80) is prohibited in LDAP per RFC 4511 §5.1
    with pytest.raises(ValueError, match="[Ii]ndefinite"):
        decode_length(b"\x80\x00\x00", 0)

    # 2. Length byte length > 4 is rejected
    with pytest.raises(ValueError, match="exceeds"):
        decode_length(b"\x85\x01\x00\x00\x00\x00", 0)

    # 3. Message size exceeding MAX_MESSAGE_SIZE (16MB) is rejected
    oversized_len_bytes = (17 * 1024 * 1024).to_bytes(4, "big")
    with pytest.raises(ValueError, match="exceeds"):
        decode_length(b"\x84" + oversized_len_bytes, 0)

    # 4. Truncated sequence parsing returns safely without unhandled exceptions
    truncated_res = parse_sequence_elements(b"\x30\x05\x01")
    assert isinstance(truncated_res, list)


def test_partial_socket_reads():
    """Verifies that ReadOnlyLDAPClient._recv_exact reconstructs fragmented TCP chunks."""
    class FragmentedSocket:
        def __init__(self, data: bytes):
            self.data = bytearray(data)

        def recv(self, bufsize: int) -> bytes:
            if not self.data:
                return b""
            # Deliver only 1 byte at a time to test multi-chunk assembly
            b = bytes([self.data.pop(0)])
            return b

    test_payload = b"CYBERSECURITYSUITE_LDAP_PARTIAL_READ_TEST"
    client = ReadOnlyLDAPClient("127.0.0.1")
    client._sock = FragmentedSocket(test_payload)
    assembled = client._recv_exact(len(test_payload))
    assert assembled == test_payload


def test_tls_certificate_rejection():
    """Verifies that strict certificate verification rejects untrusted/self-signed certs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = os.path.join(tmpdir, "cert.pem")
        key_file = os.path.join(tmpdir, "key.pem")
        # Generate temporary self-signed cert
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_file,
                "-out", cert_file, "-days", "1", "-nodes", "-subj", "/CN=localhost"
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

        def serve():
            try:
                conn, _ = server_sock.accept()
                ssl_conn = ctx.wrap_socket(conn, server_side=True)
                ssl_conn.close()
            except Exception:
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()

        # Strict cert validation (verify_cert=True) MUST reject self-signed cert
        client_strict = ReadOnlyLDAPClient("127.0.0.1", port=port, use_ssl=True, verify_cert=True, timeout=2.0)
        ok_strict, msg_strict = client_strict.connect()
        assert ok_strict is False
        assert "certificate" in msg_strict.lower() or "failed" in msg_strict.lower()

        server_sock.close()


def test_ldap_filter_injection():
    """Verifies that escape_filter_value properly sanitizes RFC 4515 special characters."""
    raw_input = r"admin*)(uid=*))(|(uid=*\x00"
    escaped = escape_filter_value(raw_input)
    # RFC 4515: \ -> \5c, * -> \2a, ( -> \28, ) -> \29, NUL -> \00
    assert r"\2a" in escaped
    assert r"\28" in escaped
    assert r"\29" in escaped
    assert r"\5c" in escaped
    assert r"*" not in escaped
    assert r"(" not in escaped
    assert r")" not in escaped


def test_sensitive_credential_redaction():
    """Verifies that sensitive credentials and password hashes are automatically redacted."""
    stream = bytearray()
    # Create entry with sensitive attributes
    stream.extend(build_search_entry_msg(1, "CN=AdminUser,DC=corp,DC=local", {
        "sAMAccountName": ["admin"],
        "userPassword": ["SuperSecretCleartext123"],
        "unicodePwd": ["RawNTHashSecretBytes"],
        "ntPwdHash": ["aad3b435b51404eeaad3b435b51404ee"],
        "supplementalCredentials": ["KerberosKeyBlob"],
    }))
    stream.extend(build_search_done_msg(1, 0))

    class MockStreamSocket:
        def __init__(self, data: bytes):
            self.data = bytearray(data)

        def sendall(self, d: bytes):
            pass

        def recv(self, n: int) -> bytes:
            chunk = self.data[:n]
            del self.data[:n]
            return bytes(chunk)

    client = ReadOnlyLDAPClient("127.0.0.1")
    client._sock = MockStreamSocket(stream)
    client._is_bound = True
    entries = client.search(base_dn="DC=corp,DC=local")

    assert len(entries) == 1
    admin_entry = entries[0]
    assert admin_entry.get_first("sAMAccountName") == "admin"
    assert admin_entry.get_first("userPassword") == "[REDACTED_SENSITIVE_ATTRIBUTE]"
    assert admin_entry.get_first("unicodePwd") == "[REDACTED_SENSITIVE_ATTRIBUTE]"
    assert admin_entry.get_first("ntPwdHash") == "[REDACTED_SENSITIVE_ATTRIBUTE]"
    assert admin_entry.get_first("supplementalCredentials") == "[REDACTED_SENSITIVE_ATTRIBUTE]"


def test_binary_attribute_formatting():
    """Verifies that binary objectGUID and objectSid attributes are formatted correctly."""
    # Test GUID: 16 bytes converted to UUID
    raw_guid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    guid_str = format_guid(raw_guid)
    assert len(guid_str) == 36
    assert guid_str.count("-") == 4
    assert guid_str == "04030201-0605-0807-090a-0b0c0d0e0f10"

    # Test SID: S-1-5-21-12345-67890-11111-500
    raw_sid = bytes([1, 5, 0, 0, 0, 0, 0, 5])
    for sub_auth in [21, 12345, 67890, 11111, 500]:
        raw_sid += sub_auth.to_bytes(4, "little")
    sid_str = format_sid(raw_sid)
    assert sid_str == "S-1-5-21-12345-67890-11111-500"


def test_paging_and_size_limits():
    """Verifies proper handling of directory size limits and oversized message guards."""
    # 1. Server returns RESULT_SIZE_LIMIT_EXCEEDED (code 4)
    stream = bytearray()
    stream.extend(build_search_entry_msg(1, "CN=User1,DC=corp,DC=local", {"sAMAccountName": ["user1"]}))
    stream.extend(build_search_done_msg(1, RESULT_SIZE_LIMIT_EXCEEDED))

    class MockStreamSocket:
        def __init__(self, data: bytes):
            self.data = bytearray(data)

        def sendall(self, d: bytes):
            pass

        def recv(self, n: int) -> bytes:
            chunk = self.data[:n]
            del self.data[:n]
            return bytes(chunk)

    client = ReadOnlyLDAPClient("127.0.0.1")
    client._sock = MockStreamSocket(stream)
    client._is_bound = True
    entries = client.search(base_dn="DC=corp,DC=local")
    assert len(entries) == 1
    assert client.last_result_code == RESULT_SIZE_LIMIT_EXCEEDED

    # 2. Oversized message guard
    oversized_header = bytes([0x30, 0x84]) + (MAX_MESSAGE_SIZE + 100).to_bytes(4, "big")
    client._sock = MockStreamSocket(oversized_header)
    with pytest.raises(ValueError, match="exceeds maximum allowable limit"):
        client._read_one_message()


def test_out_of_scope_ip_resolution(test_db):
    """Verifies fail-closed blocking when target hostname resolves to an unauthorized IP."""
    proj = test_db.create_project(Project(name="DNS Scope Guard Test", status=ProjectStatus.ACTIVE))
    test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target="10.10.10.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    # Hostname resolves to 198.51.100.50 (outside 10.10.10.0/24)
    with patch("socket.gethostbyname", return_value="198.51.100.50"):
        res = adapter.execute_enumeration(
            project_id=proj.id,
            target_host="ad-dc.corp.local",
            port=389,
            project=proj,
        )

    assert res.is_authorized is False
    assert "out-of-scope" in res.error_message.lower()

    # Verify audit log is recorded
    audit_logs = test_db.list_audit_logs(proj.id)
    assert len(audit_logs) >= 1
    assert audit_logs[0].action == "out_of_scope_scan_blocked"


def test_timeout_handling():
    """Verifies that ReadOnlyLDAPClient handles unresponsive endpoints without indefinite hanging."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def hang():
        try:
            conn, _ = srv.accept()
            time.sleep(2.0)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=hang, daemon=True)
    t.start()

    client = ReadOnlyLDAPClient("127.0.0.1", port=port, timeout=0.1)
    ok, msg = client.bind()
    assert ok is False
    assert any(term in msg.lower() for term in ("timed out", "timeout", "connection reset"))

    client.close()
    srv.close()


def test_multiple_ldap_response_entries():
    """Verifies streaming multiple SearchResultEntry messages followed by SearchResultDone."""
    stream = bytearray()
    for i in range(5):
        stream.extend(build_search_entry_msg(1, f"CN=User{i},DC=corp,DC=local", {
            "sAMAccountName": [f"user{i}"],
            "mail": [f"user{i}@corp.local"],
        }))
    stream.extend(build_search_done_msg(1, 0))

    class MockStreamSocket:
        def __init__(self, data: bytes):
            self.data = bytearray(data)

        def sendall(self, d: bytes):
            pass

        def recv(self, n: int) -> bytes:
            chunk = self.data[:n]
            del self.data[:n]
            return bytes(chunk)

    client = ReadOnlyLDAPClient("127.0.0.1")
    client._sock = MockStreamSocket(stream)
    client._is_bound = True
    entries = client.search(base_dn="DC=corp,DC=local")

    assert len(entries) == 5
    for i, e in enumerate(entries):
        assert e.get_first("sAMAccountName") == f"user{i}"
        assert e.get_first("mail") == f"user{i}@corp.local"


def test_ldap_end_to_end_integration_flow(mock_ad_server, test_db):
    """Phase 6A.2 End-to-End Integration Verification:

    Verifies the complete pipeline:
    Target Scope -> Live LDAP Enumeration -> Normalized Results -> Asset Preview ->
    User Confirmation -> DB Persistence & Deduplication -> Evidence & SHA-256 ->
    ReportBuilder Markdown & HTML Generation.
    """
    proj = test_db.create_project(Project(name="E2E AD Integration", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    with tempfile.TemporaryDirectory() as ev_dir:
        adapter = LDAPLiveEnumerationAdapter(db=test_db)
        res = adapter.execute_enumeration(
            project_id=proj.id,
            target_host=mock_ad_server.host,
            port=mock_ad_server.port,
            scopes=[scope],
            project=proj,
            evidence_dir=Path(ev_dir),
        )

        # 1. Verify Scope Authorization & Live Results
        assert res.is_authorized is True
        assert res.default_naming_context == "DC=corp,DC=local"
        assert len(res.domain_controllers) >= 1
        assert len(res.users) == 3
        assert len(res.groups) == 1
        assert len(res.computers) == 1
        assert res.password_policy is not None

        # 2. Verify Findings Classification
        titles = [f.title for f in res.findings]
        assert any("AS-REP Roasting" in t for t in titles)
        assert any("Never Expire" in t for t in titles)
        assert any("Without Password Requirement" in t for t in titles)
        assert any("Weak Active Directory Domain Password Policy" in t for t in titles)

        # 3. Simulate User Confirmation & Database Synchronization
        synced_assets_1, synced_findings_1 = adapter.synchronize_to_database(proj.id, res)
        assert synced_assets_1 == len(res.discovered_nodes)
        assert synced_findings_1 == len(res.findings)

        # 4. Verify Duplicate Asset Re-synchronization Prevention
        synced_assets_2, _ = adapter.synchronize_to_database(proj.id, res)
        assert synced_assets_2 == 0

        # 5. Verify ReportBuilder Markdown & HTML Synthesis
        rb = ReportBuilder(db=test_db)
        md_report = rb.generate_markdown(proj.id)
        html_report = rb.generate_html(proj.id)

        assert "Active Directory Weak Password & Credential Audit" in md_report
        assert "Active Directory Weak Password & Credential Audit" in html_report
        for f in res.findings:
            assert f.title in md_report

        # 6. Verify Evidence Immutability & SHA-256
        ev = test_db.get_evidence(res.evidence_id)
        assert ev is not None
        file_bytes = Path(ev.file_path).read_bytes()
        assert hashlib.sha256(file_bytes).hexdigest() == ev.sha256_hash
        # Ensure sensitive secrets are not stored in evidence file
        assert "SuperSecretCleartext" not in file_bytes.decode("utf-8")


# ==============================================================================
# Phase 6A.3 Remediation Test Suite (10 Dedicated Tests)
# ==============================================================================

def test_remediation_asset_edge_creation(mock_ad_server, test_db):
    """Gap 1: Verifies Domain -> DC and Domain -> Member Computer edges are created in SQLite."""
    proj = test_db.create_project(Project(name="Edge Creation Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    with tempfile.TemporaryDirectory() as ev_dir:
        adapter = LDAPLiveEnumerationAdapter(db=test_db)
        res = adapter.execute_enumeration(
            project_id=proj.id,
            target_host=mock_ad_server.host,
            port=mock_ad_server.port,
            scopes=[scope],
            project=proj,
            evidence_dir=Path(ev_dir),
        )

        assert res.is_authorized is True
        assert len(res.discovered_edges) >= 2

        # Synchronize to database
        adapter.synchronize_to_database(proj.id, res)

        edges = test_db.list_asset_edges(proj.id)
        assert len(edges) >= 2

        relation_types = [e.relation_type for e in edges]
        assert "HAS_DOMAIN_CONTROLLER" in relation_types
        assert "HAS_MEMBER_COMPUTER" in relation_types

        # Verify edge endpoints exist in SQLite asset_nodes
        for edge in edges:
            src_node = test_db.get_asset_node(edge.source_node_id)
            tgt_node = test_db.get_asset_node(edge.target_node_id)
            assert src_node is not None
            assert tgt_node is not None
            assert src_node.node_type == "domain"
            assert tgt_node.node_type in ("domain_controller", "computer")


def test_remediation_duplicate_edge_prevention(mock_ad_server, test_db):
    """Gap 1: Verifies re-synchronizing does not create duplicate asset edges."""
    proj = test_db.create_project(Project(name="Edge Idempotency Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    res = adapter.execute_enumeration(
        project_id=proj.id,
        target_host=mock_ad_server.host,
        port=mock_ad_server.port,
        scopes=[scope],
        project=proj,
    )

    # First sync
    adapter.synchronize_to_database(proj.id, res)
    initial_edges = test_db.list_asset_edges(proj.id)
    assert len(initial_edges) >= 2

    # Second sync (re-synchronization)
    adapter.synchronize_to_database(proj.id, res)
    second_edges = test_db.list_asset_edges(proj.id)
    assert len(second_edges) == len(initial_edges)


def test_remediation_existing_asset_preservation(mock_ad_server, test_db):
    """Gap 1: Verifies pre-existing asset records are updated non-destructively without data loss."""
    proj = test_db.create_project(Project(name="Asset Preservation Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    # Pre-populate asset representing the domain controller
    pre_node = test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            value=mock_ad_server.host,
            node_type="domain_controller",
            label="DC01-PreExisting",
            metadata_json=json.dumps({"nmap_fingerprint": "preserved_scan_data", "custom_tag": "pre_scanned"}),
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    res = adapter.execute_enumeration(
        project_id=proj.id,
        target_host=mock_ad_server.host,
        port=mock_ad_server.port,
        scopes=[scope],
        project=proj,
    )

    adapter.synchronize_to_database(proj.id, res)

    # Verify original asset was preserved and enriched
    post_node = test_db.get_asset_node(pre_node.id)
    assert post_node is not None
    assert post_node.id == pre_node.id
    meta = json.loads(post_node.metadata_json)
    assert meta.get("custom_tag") == "pre_scanned"
    assert meta.get("nmap_fingerprint") == "preserved_scan_data"


def test_remediation_2d_ad_asset_rendering(test_db):
    """Gap 2: Verifies 2D NetworkMapView properly loads and applies distinct styles to AD assets."""
    _ = QApplication.instance() or QApplication([])
    from desktop.widgets.network_map_view import NetworkMapView, NetworkHostNodeItem

    proj = test_db.create_project(Project(name="2D Map Test", status=ProjectStatus.ACTIVE))
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            value="corp.local",
            node_type="domain",
            label="corp.local",
        )
    )
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            value="192.168.10.5",
            node_type="domain_controller",
            label="DC01",
            metadata_json=json.dumps({"dns_hostname": "dc01.corp.local"}),
        )
    )
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            value="192.168.10.55",
            node_type="computer",
            label="WS-FIN-01",
            metadata_json=json.dumps({"os": "Windows 11 Pro"}),
        )
    )

    view = NetworkMapView()
    view.load_discovered_assets(test_db, proj.id)

    # Verify that host items for domain, domain_controller, and computer were instantiated
    host_items = [it for it in view.scene.items() if isinstance(it, NetworkHostNodeItem)]
    device_types = [getattr(it.host, "device_type", "") for it in host_items]

    assert "Domain" in device_types
    assert "Domain Controller" in device_types
    assert "Computer" in device_types

    view.close()


def test_remediation_3d_ip_subnet_resolution(test_db):
    """Gap 3: Verifies 3D WebGL topology extracts valid IPv4/IPv6 and groups non-IPs into AD fallback."""
    _ = QApplication.instance() or QApplication([])
    from desktop.widgets.webgl_3d_network_view import WebGL3DNetworkView

    proj = test_db.create_project(Project(name="3D Topo Test", status=ProjectStatus.ACTIVE))
    test_db.upsert_asset_node(
        AssetNode(project_id=proj.id, value="10.50.2.14", node_type="ip", label="10.50.2.14")
    )
    test_db.upsert_asset_node(
        AssetNode(project_id=proj.id, value="2001:db8:85a3::8a2e:370:7334", node_type="ip", label="ipv6-node")
    )
    test_db.upsert_asset_node(
        AssetNode(project_id=proj.id, value="corp.local", node_type="domain", label="corp.local")
    )
    test_db.upsert_asset_node(
        AssetNode(
            project_id=proj.id,
            value="fileserver.corp.local",
            node_type="hostname",
            label="fileserver",
            metadata_json=json.dumps({"ip": "10.50.2.20"}),
        )
    )

    view = WebGL3DNetworkView()
    view.load_discovered_assets(test_db, proj.id)

    assert hasattr(view, "_pending_payload") and view._pending_payload is not None
    graph_data = json.loads(view._pending_payload)
    nodes = graph_data["nodes"]
    subnet_labels = [n["label"] for n in nodes if n.get("type") == "Subnet Domain"]

    # Verify IPv4 /24 subnet hub exists
    assert any("10.50.2.0/24" in lbl for lbl in subnet_labels)
    # Verify IPv6 /64 subnet hub exists
    assert any("2001:" in lbl and "/64" in lbl for lbl in subnet_labels)
    # Verify Active Directory fallback grouping hub exists
    assert any("Active Directory & Enterprise Directory" in lbl for lbl in subnet_labels)

    view.close()


def test_remediation_finding_to_evidence_association(mock_ad_server, test_db):
    """Gap 4: Verifies created evidence_id is associated with all relevant Finding instances."""
    proj = test_db.create_project(Project(name="Evidence Assoc Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    with tempfile.TemporaryDirectory() as ev_dir:
        adapter = LDAPLiveEnumerationAdapter(db=test_db)
        res = adapter.execute_enumeration(
            project_id=proj.id,
            target_host=mock_ad_server.host,
            port=mock_ad_server.port,
            scopes=[scope],
            project=proj,
            evidence_dir=Path(ev_dir),
        )

        assert res.evidence_id is not None
        assert len(res.findings) > 0
        for f in res.findings:
            assert f.evidence_id == res.evidence_id

        # Verify findings persisted in DB are correlated to evidence
        adapter.synchronize_to_database(proj.id, res)
        db_findings = test_db.list_findings(proj.id)
        assert len(db_findings) == len(res.findings)
        for f in db_findings:
            ev_for_f = test_db.get_evidence_for_finding(f.id)
            assert ev_for_f is not None
            assert ev_for_f.id == res.evidence_id


def test_remediation_evidence_creation_failure_handling(mock_ad_server, test_db):
    """Gap 4: Verifies fail-safe handling when evidence creation or disk write fails."""
    proj = test_db.create_project(Project(name="Evidence Failure Test", status=ProjectStatus.ACTIVE))
    scope = test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target=mock_ad_server.host,
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)
    with patch.object(test_db, "create_evidence", side_effect=OSError("Disk full")):
        with tempfile.TemporaryDirectory() as ev_dir:
            res = adapter.execute_enumeration(
                project_id=proj.id,
                target_host=mock_ad_server.host,
                port=mock_ad_server.port,
                scopes=[scope],
                project=proj,
                evidence_dir=Path(ev_dir),
            )

        # Flow succeeds without crashing
        assert res.is_authorized is True
        assert res.evidence_id is None
        assert len(res.findings) > 0
        for f in res.findings:
            assert f.evidence_id is None


def test_remediation_ldaps_verification_default():
    """Security Requirement: Verifies LDAPS verification is enabled by default in client & widget."""
    client = ReadOnlyLDAPClient("127.0.0.1")
    assert client.verify_cert is True

    _ = QApplication.instance() or QApplication([])
    from desktop.widgets.ad_ldap_enumerator_widget import ADLDAPLiveEnumeratorWidget
    widget = ADLDAPLiveEnumeratorWidget()
    assert widget.chk_verify_cert.isChecked() is True
    assert widget.chk_ssl.isChecked() is False
    assert widget.chk_verify_cert.isEnabled() is False  # Disabled until SSL is checked

    widget.close()


def test_remediation_insecure_lab_mode_warning():
    """Security Requirement: Verifies prominent warning dialog when disabling TLS verification."""
    _ = QApplication.instance() or QApplication([])
    from desktop.widgets.ad_ldap_enumerator_widget import ADLDAPLiveEnumeratorWidget
    widget = ADLDAPLiveEnumeratorWidget()

    widget.chk_ssl.setChecked(True)
    assert widget.chk_verify_cert.isEnabled() is True
    assert widget.chk_verify_cert.isChecked() is True

    with patch("PySide6.QtWidgets.QMessageBox.warning") as mock_warn:
        widget.chk_verify_cert.setChecked(False)
        assert mock_warn.called is True
        title, message = mock_warn.call_args[0][1], mock_warn.call_args[0][2]
        assert "Warning" in title or "Insecure" in title
        assert "interception" in message.lower() or "mitm" in message.lower() or "lab" in message.lower()

        # Re-enabling strict verification does not trigger warning
        mock_warn.reset_mock()
        widget.chk_verify_cert.setChecked(True)
        assert mock_warn.called is False

    widget.close()


def test_remediation_dns_multi_ip_scope_enforcement(test_db):
    """Security Requirement: Verifies multi-IP DNS resolution fails closed if ANY IP is out of scope."""
    proj = test_db.create_project(Project(name="Multi-IP Scope Guard", status=ProjectStatus.ACTIVE))
    test_db.create_target_scope(
        TargetScope(
            project_id=proj.id,
            target="10.20.30.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
        )
    )

    adapter = LDAPLiveEnumerationAdapter(db=test_db)

    # Scenario A: Target hostname resolves to 2 IPs: one in-scope (10.20.30.5), one out-of-scope (192.168.1.1)
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.5", 389)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 389)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        res = adapter.execute_enumeration(
            project_id=proj.id,
            target_host="dualhomed-dc.corp.local",
            port=389,
            project=proj,
        )

        assert res.is_authorized is False
        assert "out-of-scope" in res.error_message.lower()
        assert "192.168.1.1" in res.scope_reason

    # Scenario B: Target hostname resolves to 2 IPs, BOTH in-scope -> passes scope check
    mock_addrinfo_in_scope = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.5", 389)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.6", 389)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo_in_scope):
        with patch.object(ReadOnlyLDAPClient, "connect", return_value=(False, "Connection refused in mock test")):
            res2 = adapter.execute_enumeration(
                project_id=proj.id,
                target_host="dualhomed-dc.corp.local",
                port=389,
                project=proj,
            )
            # Authorization should be granted even if downstream connect returns test refused
            assert res2.is_authorized is True

