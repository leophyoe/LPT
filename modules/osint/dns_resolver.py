"""Pure-Python DNS Wire Protocol Client & Multi-Record Resolver (RFC 1035 / RFC 3596).

Provides zero-dependency DNS resolution for:
- A (IPv4) & AAAA (IPv6)
- CNAME (Canonical Name Aliases)
- MX (Mail Exchange & Priorities)
- TXT (SPF, DKIM, DMARC, Verification Records)
- NS (Authoritative Name Servers)
- SOA (Start of Authority)
- PTR (Reverse DNS In-Addr/IP6 Lookups)
- SRV (Service Location Records)

Includes robust socket.getaddrinfo fallback for environments where outbound UDP 53
is firewalled, throttled, or offline.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# RFC 1035 / RFC 3596 Record Types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255

TYPE_MAP: Dict[str, int] = {
    "A": TYPE_A,
    "NS": TYPE_NS,
    "CNAME": TYPE_CNAME,
    "SOA": TYPE_SOA,
    "PTR": TYPE_PTR,
    "MX": TYPE_MX,
    "TXT": TYPE_TXT,
    "AAAA": TYPE_AAAA,
    "SRV": TYPE_SRV,
    "ANY": TYPE_ANY,
}

REV_TYPE_MAP: Dict[int, str] = {v: k for k, v in TYPE_MAP.items()}

# Default Public DNS Resolvers (Google, Cloudflare, Quad9)
DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


@dataclass
class DNSRecord:
    """Represents a single parsed DNS Resource Record."""
    name: str
    record_type: str
    ttl: int
    data: Any
    raw_type: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "ttl": self.ttl,
            "data": self.data,
        }


@dataclass
class DNSSummary:
    """Consolidated multi-record DNS reconnaissance profile for a target domain."""
    target: str
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    mx: List[Dict[str, Any]] = field(default_factory=list)  # {"preference": int, "exchange": str}
    txt: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    soa: Optional[Dict[str, Any]] = None
    srv: List[Dict[str, Any]] = field(default_factory=list)
    ptr: List[str] = field(default_factory=list)
    all_records: List[DNSRecord] = field(default_factory=list)
    nameserver_used: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "a": self.a,
            "aaaa": self.aaaa,
            "cname": self.cname,
            "mx": self.mx,
            "txt": self.txt,
            "ns": self.ns,
            "soa": self.soa,
            "srv": self.srv,
            "ptr": self.ptr,
            "total_records": len(self.all_records),
            "nameserver_used": self.nameserver_used,
            "error_message": self.error_message,
        }


def _encode_domain_name(domain: str) -> bytes:
    """Encodes a domain name string into RFC 1035 length-prefixed wire format."""
    parts = domain.strip(".").split(".")
    encoded = bytearray()
    for part in parts:
        part_bytes = part.encode("idna")
        if len(part_bytes) > 63:
            raise ValueError(f"DNS label too long: {part}")
        encoded.append(len(part_bytes))
        encoded.extend(part_bytes)
    encoded.append(0)
    return bytes(encoded)


def _decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decodes a domain name from DNS wire bytes, handling RFC 1035 compression pointers."""
    labels: List[str] = []
    jumped = False
    original_offset = offset
    max_hops = 60  # Guard against cyclical compression loops

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        # Compression Pointer (0xC0 | offset)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            max_hops -= 1
            if max_hops <= 0:
                break
            continue

        offset += 1
        if length == 0:
            break

        if offset + length > len(data):
            break

        try:
            label = data[offset : offset + length].decode("idna")
        except Exception:
            label = data[offset : offset + length].decode("latin-1", errors="replace")
        labels.append(label)
        offset += length

    domain_str = ".".join(labels)
    final_offset = original_offset if jumped else offset
    return domain_str, final_offset


def build_dns_query_packet(
    domain: str,
    qtype: Union[int, str] = TYPE_A,
    query_id: Optional[int] = None,
    tx_id: Optional[int] = None,
) -> bytes:
    """Constructs a standard 12-byte RFC 1035 DNS Question packet."""
    resolved_id = tx_id if tx_id is not None else query_id
    qid = resolved_id if resolved_id is not None else random.randint(1, 65535)
    flags = 0x0100  # Standard query, Recursion Desired (RD)
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", qid, flags, qdcount, ancount, nscount, arcount)
    qname_bytes = _encode_domain_name(domain)

    if isinstance(qtype, str):
        qtype_num = TYPE_MAP.get(qtype.upper(), TYPE_A)
    else:
        qtype_num = qtype

    question = struct.pack("!HH", qtype_num, 1)  # QTYPE, QCLASS=IN (1)
    return header + qname_bytes + question


def parse_dns_response_packet(data: bytes) -> Tuple[int, List[DNSRecord]]:
    """Parses a raw DNS response packet into an integer RCODE and list of DNSRecord objects."""
    if len(data) < 12:
        return 1, []

    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F

    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = _decode_domain_name(data, offset)
        offset += 4  # Skip QTYPE (2) + QCLASS (2)

    records: List[DNSRecord] = []

    # Parse answer, authority, and additional sections
    total_answers = ancount + nscount + arcount
    for _ in range(total_answers):
        if offset >= len(data):
            break

        name, offset = _decode_domain_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata_bytes = data[offset : offset + rdlength]
        rec_data: Any = None
        type_name = REV_TYPE_MAP.get(rtype, f"TYPE{rtype}")

        try:
            if rtype == TYPE_A and rdlength == 4:
                rec_data = socket.inet_ntoa(rdata_bytes)
            elif rtype == TYPE_AAAA and rdlength == 16:
                rec_data = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            elif rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
                rec_data, _ = _decode_domain_name(data, offset)
            elif rtype == TYPE_MX:
                if rdlength >= 3:
                    pref = struct.unpack("!H", rdata_bytes[:2])[0]
                    mx_host, _ = _decode_domain_name(data, offset + 2)
                    rec_data = {"preference": pref, "exchange": mx_host}
            elif rtype == TYPE_TXT:
                # Concatenate one or more character-strings (length byte followed by string)
                txt_parts = []
                t_off = 0
                while t_off < len(rdata_bytes):
                    t_len = rdata_bytes[t_off]
                    t_off += 1
                    txt_parts.append(rdata_bytes[t_off : t_off + t_len].decode("utf-8", errors="replace"))
                    t_off += t_len
                rec_data = "".join(txt_parts)
            elif rtype == TYPE_SRV:
                if rdlength >= 7:
                    priority, weight, port = struct.unpack("!HHH", rdata_bytes[:6])
                    srv_target, _ = _decode_domain_name(data, offset + 6)
                    rec_data = {"priority": priority, "weight": weight, "port": port, "target": srv_target}
            elif rtype == TYPE_SOA:
                mname, next_off = _decode_domain_name(data, offset)
                rname, next_off = _decode_domain_name(data, next_off)
                if next_off + 20 <= offset + rdlength:
                    serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[next_off : next_off + 20])
                    rec_data = {
                        "primary_ns": mname,
                        "responsible_email": rname.replace(".", "@", 1),
                        "serial": serial,
                        "refresh": refresh,
                        "retry": retry,
                        "expire": expire,
                        "minimum_ttl": minimum,
                    }
            else:
                rec_data = rdata_bytes.hex()
        except Exception as parse_err:
            logger.debug(f"Error parsing record payload for {type_name}: {parse_err}")
            rec_data = rdata_bytes.hex()

        offset += rdlength
        if rec_data is not None:
            records.append(DNSRecord(name=name, record_type=type_name, ttl=ttl, data=rec_data, raw_type=rtype))

    return rcode, records


class PurePythonDNSResolver:
    """RFC 1035 compliant pure-Python DNS resolver with zero third-party dependencies."""

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 3.0):
        self.nameservers = nameservers or self._get_system_or_default_nameservers()
        self.timeout = timeout

    @staticmethod
    def _get_system_or_default_nameservers() -> List[str]:
        """Discovers active system nameservers from /etc/resolv.conf, falling back to public roots."""
        ns_list = []
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver") and len(line.split()) >= 2:
                        ip = line.split()[1]
                        if ip and ip not in ns_list:
                            ns_list.append(ip)
        except Exception:
            pass
        return ns_list if ns_list else DEFAULT_NAMESERVERS

    def query(
        self,
        domain: str,
        qtype: Union[str, int] = "A",
        nameserver: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> List[DNSRecord]:
        """Sends a direct RFC 1035 UDP query to the selected nameserver and returns parsed records."""
        ns = nameserver or (self.nameservers[0] if self.nameservers else "8.8.8.8")
        tout = timeout or self.timeout
        qtype_str = qtype if isinstance(qtype, str) else REV_TYPE_MAP.get(qtype, "A")

        clean_domain = domain.strip().rstrip(".")
        packet = build_dns_query_packet(clean_domain, qtype)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(tout)
                sock.sendto(packet, (ns, 53))
                resp_data, _ = sock.recvfrom(4096)
                rcode, records = parse_dns_response_packet(resp_data)
                # Filter records matching requested qtype (unless ANY was queried)
                if qtype_str.upper() != "ANY":
                    return [r for r in records if r.record_type.upper() == qtype_str.upper()]
                return records
        except Exception as exc:
            logger.debug(f"Direct UDP DNS query failed for {clean_domain} ({qtype_str}) via {ns}: {exc}")
            return []

    def resolve_all_records(
        self,
        domain_or_ip: str,
        timeout: Optional[float] = None,
    ) -> DNSSummary:
        """Executes a full multi-record DNS reconnaissance audit (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR)."""
        clean_target = domain_or_ip.strip().rstrip(".")
        summary = DNSSummary(target=clean_target)
        tout = timeout or self.timeout

        is_ip = False
        try:
            ipaddress.ip_address(clean_target)
            is_ip = True
        except ValueError:
            pass

        # 1. Reverse DNS Lookups (PTR) if target is an IP
        if is_ip:
            try:
                ip_obj = ipaddress.ip_address(clean_target)
                rev_name = ip_obj.reverse_pointer
                ptr_records = self.query(rev_name, "PTR", timeout=tout)
                for rec in ptr_records:
                    if isinstance(rec.data, str):
                        summary.ptr.append(rec.data)
                        summary.all_records.append(rec)
            except Exception as ptr_err:
                logger.debug(f"PTR lookup error: {ptr_err}")

            # Fallback to socket.gethostbyaddr
            if not summary.ptr:
                try:
                    host_name, _, _ = socket.gethostbyaddr(clean_target)
                    summary.ptr.append(host_name)
                except Exception:
                    pass
            return summary

        # 2. Forward Domain DNS Reconnaissance
        active_ns = self.nameservers[0] if self.nameservers else "8.8.8.8"
        summary.nameserver_used = active_ns

        # Audit standard record types
        target_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        for q_type in target_types:
            records = self.query(clean_target, q_type, nameserver=active_ns, timeout=tout)
            for r in records:
                summary.all_records.append(r)
                if r.record_type == "A" and isinstance(r.data, str):
                    if r.data not in summary.a:
                        summary.a.append(r.data)
                elif r.record_type == "AAAA" and isinstance(r.data, str):
                    if r.data not in summary.aaaa:
                        summary.aaaa.append(r.data)
                elif r.record_type == "CNAME" and isinstance(r.data, str):
                    if r.data not in summary.cname:
                        summary.cname.append(r.data)
                elif r.record_type == "MX" and isinstance(r.data, dict):
                    if r.data not in summary.mx:
                        summary.mx.append(r.data)
                elif r.record_type == "TXT" and isinstance(r.data, str):
                    if r.data not in summary.txt:
                        summary.txt.append(r.data)
                elif r.record_type == "NS" and isinstance(r.data, str):
                    if r.data not in summary.ns:
                        summary.ns.append(r.data)
                elif r.record_type == "SOA" and isinstance(r.data, dict):
                    summary.soa = r.data

        # 3. Robust socket.getaddrinfo fallback for A and AAAA
        if not summary.a or not summary.aaaa:
            try:
                addr_info = socket.getaddrinfo(clean_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for family, _, _, _, sockaddr in addr_info:
                    ip_str = sockaddr[0]
                    if family == socket.AF_INET and ip_str not in summary.a:
                        summary.a.append(ip_str)
                        summary.all_records.append(DNSRecord(name=clean_target, record_type="A", ttl=300, data=ip_str, raw_type=TYPE_A))
                    elif family == socket.AF_INET6 and ip_str not in summary.aaaa:
                        summary.aaaa.append(ip_str)
                        summary.all_records.append(DNSRecord(name=clean_target, record_type="AAAA", ttl=300, data=ip_str, raw_type=TYPE_AAAA))
            except Exception:
                pass

        return summary
