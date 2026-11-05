"""Comprehensive Unit and Integration Tests for Pure-Python DNS and RDAP Engines (Phase 7A).

Tests:
1. DNS wire packet query construction (RFC 1035 / RFC 3596).
2. DNS wire packet response parsing (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV).
3. Pointer compression decompression (0xC0 prefix) and cyclic pointer safety.
4. Fallback mechanism to socket.getaddrinfo when UDP 53 is unavailable.
5. RDAP client domain lookup, jCard parsing, and event timestamp parsing.
6. RDAP client IP lookup and CIDR/organization parsing.
7. RDAP client ASN lookup and attribution.
8. RDAP network timeout, 404 handling, and offline resilience.
9. PassiveReconAdapter integration with DNS + RDAP in temporary isolated database.
10. Strict scope enforcement on discovered DNS/RDAP assets and topology edges.
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.scope import ScopeAuthorizationService
from modules.osint.dns_resolver import (
    DNSRecord,
    DNSSummary,
    PurePythonDNSResolver,
    TYPE_A,
    TYPE_AAAA,
    TYPE_ANY,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_PTR,
    TYPE_SOA,
    TYPE_SRV,
    TYPE_TXT,
    build_dns_query_packet,
    parse_dns_response_packet,
)
from modules.osint.passive_recon import PassiveReconAdapter
from modules.osint.rdap_client import (
    PurePythonRDAPClient,
    RDAPASNResult,
    RDAPDomainResult,
    RDAPIPResult,
    _extract_vcard_fn_and_email,
    _parse_rdap_events,
)
from storage.db import Database
from storage.models import (
    AssetEdge,
    AssetNode,
    Observation,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
)


@pytest.fixture
def test_db(tmp_path: Path):
    """Provides an isolated temporary database for test execution."""
    return Database(str(tmp_path / "phase7a_test.db"))


@pytest.fixture
def sample_project(test_db: Database):
    """Creates a sample authorized project with scoped domain and IP rules."""
    proj = test_db.create_project(
        Project(
            name="Phase 7A OSINT Verification Project",
            client_name="Test Enterprise Corp",
            status=ProjectStatus.ACTIVE,
            allow_active_recon=False,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="targetcorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="*.targetcorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    test_db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="out-of-scope.targetcorp.com",
            target_type=TargetType.HOSTNAME,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )
    return proj


# =====================================================================
# Unit Tests: DNS Wire Protocol Client
# =====================================================================

def test_dns_query_packet_construction():
    """Verifies that RFC 1035 DNS query packets are correctly constructed."""
    query = build_dns_query_packet("example.com", "A", tx_id=0x1234)
    assert len(query) >= 12
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", query[:12])
    assert tx_id == 0x1234
    assert flags == 0x0100  # Standard query with RD (Recursion Desired) bit set
    assert qdcount == 1
    assert ancount == 0

    # QNAME: \x07example\x03com\x00
    qname_part = query[12:-4]
    assert qname_part == b"\x07example\x03com\x00"

    # QTYPE=1 (A), QCLASS=1 (IN)
    qtype, qclass = struct.unpack("!HH", query[-4:])
    assert qtype == TYPE_A
    assert qclass == 1


def test_dns_response_packet_parsing_a_record():
    """Verifies parsing of standard DNS A record response."""
    # Build synthetic packet
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", TYPE_A, 1)
    # Answer: pointer to name at offset 12 (0xC00C), type A, class IN (1), ttl 300, rdlength 4, IP 93.184.216.34
    ip_bytes = socket.inet_aton("93.184.216.34")
    ans_name = struct.pack("!H", 0xC00C)
    ans_meta = struct.pack("!HHIH", TYPE_A, 1, 300, len(ip_bytes))
    answer = ans_name + ans_meta + ip_bytes
    packet = header + question + answer

    rcode, records = parse_dns_response_packet(packet)
    assert rcode == 0
    assert len(records) == 1
    rec = records[0]
    assert rec.name == "example.com"
    assert rec.record_type == "A"
    assert rec.ttl == 300
    assert rec.data == "93.184.216.34"


def test_dns_response_packet_parsing_cname_and_mx():
    """Verifies parsing of CNAME and MX records with wire compression pointers."""
    header = struct.pack("!HHHHHH", 0x2222, 0x8180, 1, 2, 0, 0)
    question = b"\x04mail\x07example\x03com\x00" + struct.pack("!HH", TYPE_ANY, 1)

    # Answer 1: CNAME -> mx.example.com
    # Wire name: \x02mx\xc0\x11 (mx. + pointer to offset 17: example.com)
    cname_target = b"\x02mx\xc0\x11"
    ans1 = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", TYPE_CNAME, 1, 600, len(cname_target)) + cname_target

    # Answer 2: MX -> preference 10, exchange maxserver.example.com
    # 'maxserver' has 9 letters -> length \x09
    mx_data = struct.pack("!H", 10) + b"\x09maxserver\xc0\x11"
    ans2 = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", TYPE_MX, 1, 600, len(mx_data)) + mx_data

    packet = header + question + ans1 + ans2
    rcode, records = parse_dns_response_packet(packet)
    assert rcode == 0
    assert len(records) == 2

    cname_rec = next(r for r in records if r.record_type == "CNAME")
    assert cname_rec.data == "mx.example.com"

    mx_rec = next(r for r in records if r.record_type == "MX")
    assert isinstance(mx_rec.data, dict)
    assert mx_rec.data["preference"] == 10
    assert mx_rec.data["exchange"] == "maxserver.example.com"


def test_dns_response_packet_parsing_txt_and_ns():
    """Verifies parsing of TXT (SPF/verification) and NS records."""
    header = struct.pack("!HHHHHH", 0x3333, 0x8180, 1, 2, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", TYPE_TXT, 1)

    # TXT: length byte + text string
    txt_content = b"v=spf1 include:_spf.example.com ~all"
    rdata_txt = bytes([len(txt_content)]) + txt_content
    ans_txt = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", TYPE_TXT, 1, 300, len(rdata_txt)) + rdata_txt

    # NS: ns1.example.com
    ns_wire = b"\x03ns1\xc0\x0c"
    ans_ns = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", TYPE_NS, 1, 86400, len(ns_wire)) + ns_wire

    packet = header + question + ans_txt + ans_ns
    rcode, records = parse_dns_response_packet(packet)
    assert rcode == 0
    assert len(records) == 2

    txt_rec = next(r for r in records if r.record_type == "TXT")
    assert txt_rec.data == "v=spf1 include:_spf.example.com ~all"

    ns_rec = next(r for r in records if r.record_type == "NS")
    assert ns_rec.data == "ns1.example.com"


def test_dns_cyclic_pointer_safety():
    """Verifies that infinite pointer loops do not cause infinite recursion or freeze."""
    header = struct.pack("!HHHHHH", 0x4444, 0x8180, 0, 1, 0, 0)
    # Loop pointer: points to offset 12, which points to offset 12...
    ans_loop = struct.pack("!HHIHH", 0xC00C, TYPE_A, 1, 300, 4) + socket.inet_aton("1.2.3.4")
    packet = header + ans_loop

    # Must complete safely without RecursionError or hang
    rcode, records = parse_dns_response_packet(packet)
    assert isinstance(records, list)


def test_dns_resolver_fallback():
    """Verifies that PurePythonDNSResolver falls back to getaddrinfo when UDP query fails."""
    resolver = PurePythonDNSResolver(nameservers=["192.0.2.1"])  # RFC 5737 TEST-NET-1 (unreachable)

    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]
        summary = resolver.resolve_all_records("example.com", timeout=0.2)
        assert "93.184.216.34" in summary.a
        assert "2606:2800:220:1:248:1893:25c8:1946" in summary.aaaa


# =====================================================================
# Unit Tests: RDAP Client
# =====================================================================

def test_rdap_domain_parsing():
    """Verifies parsing of standard RFC 7483 domain RDAP response."""
    raw_rdap = {
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "TARGETCORP.COM",
        "status": ["client transfer prohibited", "active"],
        "nameservers": [{"ldhName": "NS1.TARGETCORP.COM"}, {"ldhName": "NS2.TARGETCORP.COM"}],
        "events": [
            {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-08-01T12:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "MarkMonitor Inc."],
                    ],
                ],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
            }
        ],
    }

    client = PurePythonRDAPClient()
    with patch.object(client, "_fetch_json", return_value=(raw_rdap, None)):
        res = client.lookup_domain("targetcorp.com")
        assert res.is_successful is True
        assert res.domain == "targetcorp.com"
        assert res.registrar == "MarkMonitor Inc."
        assert res.iana_id == "292"
        assert "ns1.targetcorp.com" in res.nameservers
        assert res.created_date == "1997-09-15T04:00:00Z"
        assert res.expiration_date == "2028-09-14T04:00:00Z"


def test_rdap_ip_network_parsing():
    """Verifies parsing of IP address network allocations in RDAP."""
    raw_ip_rdap = {
        "handle": "NET-192-168-1-0-1",
        "startAddress": "192.168.1.0",
        "endAddress": "192.168.1.255",
        "ipVersion": "v4",
        "name": "TEST-NET-BLOCK",
        "country": "US",
        "status": ["active"],
        "cidr0_cidrs": [{"v4prefix": "192.168.1.0", "length": 24}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Target Security Org"],
                    ],
                ],
            }
        ],
    }

    client = PurePythonRDAPClient()
    with patch.object(client, "_fetch_json", return_value=(raw_ip_rdap, None)):
        res = client.lookup_ip("192.168.1.50")
        assert res.is_successful is True
        assert res.cidr == "192.168.1.0/24"
        assert res.country == "US"
        assert res.organization == "Target Security Org"


def test_rdap_asn_attribution():
    """Verifies parsing of Autonomous System Number (ASN) in RDAP."""
    raw_asn_rdap = {
        "handle": "AS15169",
        "startAutnum": 15169,
        "endAutnum": 15169,
        "name": "GOOGLE",
        "country": "US",
        "events": [{"eventAction": "allocation", "eventDate": "2000-03-30T00:00:00Z"}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Google LLC"],
                    ],
                ],
            }
        ],
    }

    client = PurePythonRDAPClient()
    with patch.object(client, "_fetch_json", return_value=(raw_asn_rdap, None)):
        res = client.lookup_asn("15169")
        assert res.is_successful is True
        assert res.asn == "AS15169"
        assert res.name == "GOOGLE"
        assert res.organization == "Google LLC"


def test_rdap_error_and_timeout_resilience():
    """Verifies graceful degradation when RDAP registry is offline or returns HTTP 404."""
    client = PurePythonRDAPClient()
    with patch.object(client, "_fetch_json", return_value=(None, "HTTP 404: Not Found")):
        res = client.lookup_domain("nonexistent-domain-test-404.xyz")
        assert res.is_successful is False
        assert "404" in (res.error_message or "")


# =====================================================================
# Integration Tests: PassiveReconAdapter
# =====================================================================

def test_passive_recon_full_discovery_pipeline(test_db: Database, sample_project: Project):
    """Verifies end-to-end integration of DNS and RDAP engines into PassiveReconAdapter and Asset Graph."""
    adapter = PassiveReconAdapter(test_db)
    scopes = test_db.list_scopes(sample_project.id)

    # Mock DNS summary
    mock_dns = DNSSummary(
        target="targetcorp.com",
        a=["192.168.1.10", "192.168.1.20"],
        cname=["app.targetcorp.com"],
        mx=[{"preference": 10, "exchange": "mail.targetcorp.com"}],
        ns=["ns1.targetcorp.com", "ns2.targetcorp.com"],
        txt=["v=spf1 include:_spf.targetcorp.com ~all"],
        soa={"mname": "ns1.targetcorp.com", "rname": "admin.targetcorp.com"},
    )

    # Mock RDAP domain result
    mock_rdap_dom = RDAPDomainResult(
        domain="targetcorp.com",
        registrar="Enterprise Registrar Services",
        created_date="2005-05-15T00:00:00Z",
        expiration_date="2027-05-15T00:00:00Z",
        nameservers=["ns1.targetcorp.com", "ns2.targetcorp.com"],
        status=["clientTransferProhibited"],
        is_successful=True,
    )

    # Mock RDAP IP result
    mock_rdap_ip = RDAPIPResult(
        ip="192.168.1.10",
        cidr="192.168.1.0/24",
        country="US",
        organization="Target Corp Infrastructure",
        asn="AS65001",
        is_successful=True,
    )

    output_messages = []

    def on_out(msg, stream):
        output_messages.append((msg, stream))

    with patch.object(adapter.dns_resolver, "resolve_all_records", return_value=mock_dns), \
         patch.object(adapter.rdap_client, "lookup_domain", return_value=mock_rdap_dom), \
         patch.object(adapter.rdap_client, "lookup_ip", return_value=mock_rdap_ip), \
         patch("urllib.request.urlopen") as mock_url:

        # Mock crt.sh JSON response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps([
            {"name_value": "vpn.targetcorp.com"},
            {"name_value": "out-of-scope.targetcorp.com"},
        ]).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        mock_url.return_value = mock_resp

        result = adapter.run_discovery(
            target_domain="targetcorp.com",
            project=sample_project,
            scopes=scopes,
            timeout=5.0,
            on_output=on_out,
        )

    assert result.status == "completed"
    assert len(result.discovered_assets) > 0

    # Verify Asset Nodes in database
    nodes = test_db.list_asset_nodes(sample_project.id)
    node_values = {n.value: n for n in nodes}

    assert "targetcorp.com" in node_values
    assert node_values["targetcorp.com"].node_type == "domain"

    assert "app.targetcorp.com" in node_values
    assert node_values["app.targetcorp.com"].node_type == "subdomain"

    assert "vpn.targetcorp.com" in node_values
    assert node_values["vpn.targetcorp.com"].node_type == "subdomain"

    assert "ns1.targetcorp.com" in node_values
    assert node_values["ns1.targetcorp.com"].node_type == "nameserver"

    assert "mail.targetcorp.com" in node_values
    assert node_values["mail.targetcorp.com"].node_type == "mail_exchange"

    assert "192.168.1.10" in node_values
    assert node_values["192.168.1.10"].node_type == "ip"

    assert "AS65001" in node_values
    assert node_values["AS65001"].node_type == "asn"

    # Verify Asset Edges in database
    edges = test_db.list_asset_edges(sample_project.id)
    relations = {(e.source_node_id, e.target_node_id, e.relation_type) for e in edges}

    # Root -> IP: RESOLVES_TO
    root_id = node_values["targetcorp.com"].id
    ip_id = node_values["192.168.1.10"].id
    asn_id = node_values["AS65001"].id
    ns_id = node_values["ns1.targetcorp.com"].id
    mx_id = node_values["mail.targetcorp.com"].id
    sub_id = node_values["vpn.targetcorp.com"].id

    assert (root_id, ip_id, "RESOLVES_TO") in relations
    assert (ip_id, asn_id, "ANNOUNCED_BY_ASN") in relations
    assert (ns_id, root_id, "NS_FOR") in relations
    assert (mx_id, root_id, "MX_RECORD_FOR") in relations
    assert (sub_id, root_id, "SUBDOMAIN_OF") in relations

    # Verify Scope Quarantine
    quarantine_targets = [q["target"] for q in result.quarantined_assets]
    assert "out-of-scope.targetcorp.com" in quarantine_targets
    assert "out-of-scope.targetcorp.com" not in node_values

    # Verify Observation Record
    observations = test_db.list_observations(sample_project.id)
    assert len(observations) == 1
    obs = observations[0]
    assert "Passive Recon & Tech Profile" in obs.title
    obs_data = json.loads(obs.raw_data)
    assert obs_data["target"] == "targetcorp.com"
    assert "192.168.1.10" in obs_data["resolved_ips"]
    assert "ns1.targetcorp.com" in obs_data["nameservers"]
