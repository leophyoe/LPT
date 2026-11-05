"""Unit tests for NmapParser."""

import pytest
from modules.network.nmap_parser import NmapParser
from storage.models import FindingSeverity

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -F -oX - 192.168.1.100" version="7.94">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.100" addrtype="ipv4"/>
<hostnames>
<hostname name="printer.internal.lab" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" product="vsftpd" version="3.0.3" method="probed" conf="10"/></port>
<port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet" product="Linux telnetd" version="" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="smb" product="Samba smbd" version="4.9.5" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>
"""


def test_nmap_parser_extracts_hosts_and_ports():
    result = NmapParser.parse_xml(SAMPLE_NMAP_XML)
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "192.168.1.100"
    assert host.hostname == "printer.internal.lab"
    assert host.status == "up"

    # Verify extracted ports
    assert len(host.ports) == 5
    open_ports = [p for p in host.ports if p.state == "open"]
    assert len(open_ports) == 4

    p21 = next(p for p in host.ports if p.port_id == 21)
    assert p21.service_name == "ftp"
    assert p21.product == "vsftpd"
    assert p21.version == "3.0.3"
    assert p21.service_summary == "ftp vsftpd 3.0.3"


def test_nmap_parser_to_findings():
    result = NmapParser.parse_xml(SAMPLE_NMAP_XML)
    findings = NmapParser.to_findings(result, project_id=1, execution_id=42)

    # Only open ports produce findings (port 8080 was closed)
    assert len(findings) == 4

    # Verify severity classification
    telnet_finding = next(f for f in findings if "23/tcp" in f.affected_port_service)
    assert telnet_finding.severity == FindingSeverity.HIGH
    assert "Replace Telnet" in telnet_finding.remediation

    smb_finding = next(f for f in findings if "445/tcp" in f.affected_port_service)
    assert smb_finding.severity == FindingSeverity.MEDIUM

    http_finding = next(f for f in findings if "80/tcp" in f.affected_port_service)
    assert http_finding.severity == FindingSeverity.INFORMATIONAL
    assert http_finding.execution_id == 42


def test_nmap_parser_handles_empty_or_malformed_xml():
    empty_result = NmapParser.parse_xml("")
    assert len(empty_result.hosts) == 0

    with pytest.raises(ValueError):
        NmapParser.parse_xml("<not-valid-xml")
