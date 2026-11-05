"""Pure-Python Read-Only LDAP & Active Directory Client.

Implements lightweight, robust RFC 4511 Basic Encoding Rules (BER) encoding
and decoding for LDAP over TCP (port 389) and LDAPS / TLS (port 636).
Zero external C dependencies or package requirements.

SAFETY & HARDENING CONTROLS:
- Strictly read-only operations (Search, Bind, Unbind).
- Never modifies Active Directory objects, attributes, or passwords.
- Strict RFC 4515 filter escaping (escape_filter_value).
- Redaction of sensitive credentials, hashes, and secrets (SENSITIVE_ATTRIBUTES).
- Binary attribute decoders for objectGUID (UUID) and objectSid (S-1-5-21-...).
- Maximum message size guard (MAX_MESSAGE_SIZE = 16MB) to prevent memory DoS.
- Prohibition of indefinite length BER encoding (RFC 4511 §5.1).
- Loop-based chunk assembly in _recv_exact for partial TCP socket reads.
- Message ID verification and correlation across response streams.
- Strict TLS certificate verification support with hostname checks and no silent fallback.
- Read-only referral skipping to avoid unexpected out-of-scope pivots.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Maximum allowable incoming message size (16 MB) to prevent memory exhaustion
MAX_MESSAGE_SIZE = 16 * 1024 * 1024

# Blacklist of sensitive attributes that must never be stored in cleartext
SENSITIVE_ATTRIBUTES = {
    "unicodepwd",
    "ntpwdhash",
    "lmpwdhash",
    "userpassword",
    "supplementalcredentials",
    "dbcspwd",
    "currentvalue",
    "priorvalue",
}

# LDAP Scope Constants (RFC 4511)
SCOPE_BASE = 0        # baseObject
SCOPE_ONELEVEL = 1    # singleLevel
SCOPE_SUBTREE = 2     # wholeSubtree

# LDAP Protocol Operation Tags (RFC 4511)
TAG_BIND_REQUEST = 0x60         # [APPLICATION 0]
TAG_BIND_RESPONSE = 0x61        # [APPLICATION 1]
TAG_UNBIND_REQUEST = 0x42       # [APPLICATION 2]
TAG_SEARCH_REQUEST = 0x63       # [APPLICATION 3]
TAG_SEARCH_RES_ENTRY = 0x64     # [APPLICATION 4]
TAG_SEARCH_RES_DONE = 0x65      # [APPLICATION 5]
TAG_SEARCH_RES_REF = 0x73       # [APPLICATION 19]

# LDAP Result Codes
RESULT_SUCCESS = 0
RESULT_OPERATIONS_ERROR = 1
RESULT_PROTOCOL_ERROR = 2
RESULT_TIME_LIMIT_EXCEEDED = 3
RESULT_SIZE_LIMIT_EXCEEDED = 4
RESULT_COMPARE_FALSE = 5
RESULT_COMPARE_TRUE = 6
RESULT_AUTH_METHOD_NOT_SUPPORTED = 7
RESULT_STRONGER_AUTH_REQUIRED = 8
RESULT_REFERRAL = 10
RESULT_ADMIN_LIMIT_EXCEEDED = 11
RESULT_UNAVAILABLE_CRITICAL_EXTENSION = 12
RESULT_CONFIDENTIALITY_REQUIRED = 13
RESULT_SASL_BIND_IN_PROGRESS = 14
RESULT_NO_SUCH_ATTRIBUTE = 16
RESULT_UNDEFINED_ATTRIBUTE_TYPE = 17
RESULT_INAPPROPRIATE_MATCHING = 18
RESULT_CONSTRAINT_VIOLATION = 19
RESULT_ATTRIBUTE_OR_VALUE_EXISTS = 20
RESULT_INVALID_ATTRIBUTE_SYNTAX = 21
RESULT_NO_SUCH_OBJECT = 32
RESULT_ALIAS_PROBLEM = 33
RESULT_INVALID_DN_SYNTAX = 34
RESULT_INAPPROPRIATE_AUTHENTICATION = 48
RESULT_INVALID_CREDENTIALS = 49
RESULT_INSUFFICIENT_ACCESS_RIGHTS = 50
RESULT_BUSY = 51
RESULT_UNAVAILABLE = 52
RESULT_UNWILLING_TO_PERFORM = 53


@dataclass
class LDAPEntry:
    """Represents an Active Directory / LDAP object entry."""
    dn: str
    attributes: Dict[str, List[str]] = field(default_factory=dict)

    def get_first(self, attr_name: str, default: str = "") -> str:
        """Returns the first value of an attribute (case-insensitive lookup)."""
        target = attr_name.lower()
        for k, vals in self.attributes.items():
            if k.lower() == target and vals:
                return vals[0]
        return default

    def get_list(self, attr_name: str) -> List[str]:
        """Returns all values of an attribute (case-insensitive lookup)."""
        target = attr_name.lower()
        for k, vals in self.attributes.items():
            if k.lower() == target:
                return list(vals)
        return []


# ==============================================================================
# Binary Attribute Formatters (GUID & SID)
# ==============================================================================

def format_guid(raw_bytes: bytes) -> str:
    """Formats 16-byte raw Microsoft GUID into standard UUID string format."""
    if len(raw_bytes) == 16:
        # Microsoft GUID binary format has mixed-endian fields:
        # Data1 (uint32 LE), Data2 (uint16 LE), Data3 (uint16 LE), Data4 (8 bytes BE)
        d1, d2, d3 = struct.unpack("<IHH", raw_bytes[:8])
        d4 = raw_bytes[8:].hex()
        return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:4]}-{d4[4:]}"
    return raw_bytes.hex()


def format_sid(raw_bytes: bytes) -> str:
    """Formats binary Active Directory objectSid into standard string (e.g. S-1-5-21-...)."""
    if len(raw_bytes) < 8:
        return raw_bytes.hex()
    revision = raw_bytes[0]
    sub_auth_count = raw_bytes[1]
    authority = int.from_bytes(raw_bytes[2:8], "big")
    sub_authorities = []
    offset = 8
    for _ in range(sub_auth_count):
        if offset + 4 <= len(raw_bytes):
            sub_auth = struct.unpack("<I", raw_bytes[offset:offset + 4])[0]
            sub_authorities.append(sub_auth)
            offset += 4
    sub_str = "-".join(str(s) for s in sub_authorities)
    return f"S-{revision}-{authority}-{sub_str}" if sub_authorities else f"S-{revision}-{authority}"


def escape_filter_value(val: str) -> str:
    """Escapes user input for safe embedding in LDAP filter expressions (RFC 4515)."""
    # Backslash must be escaped first
    val = val.replace("\\", "\\5c")
    val = val.replace("*", "\\2a")
    val = val.replace("(", "\\28")
    val = val.replace(")", "\\29")
    val = val.replace("\0", "\\00")
    return val


# ==============================================================================
# ASN.1 Basic Encoding Rules (BER) Primitives
# ==============================================================================

def encode_length(length: int) -> bytes:
    """Encodes a length according to ASN.1 BER rules."""
    if length < 0:
        raise ValueError(f"Negative BER length not allowed: {length}")
    if length < 128:
        return bytes([length])
    len_bytes = []
    temp = length
    while temp > 0:
        len_bytes.insert(0, temp & 0xFF)
        temp >>= 8
    return bytes([0x80 | len(len_bytes)]) + bytes(len_bytes)


def decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes an ASN.1 BER length. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("Unexpected end of data while reading length byte")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset

    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length encoding (0x80) is prohibited in LDAP (RFC 4511 §5.1)")
    if num_bytes > 4:
        raise ValueError(f"Oversized BER length encoding: {num_bytes} bytes exceeds safe limit")
    if offset + num_bytes > len(data):
        raise ValueError("Length bytes exceed data boundary")

    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    offset += num_bytes
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"BER length {length} exceeds maximum safety limit ({MAX_MESSAGE_SIZE} bytes)")
    return length, offset


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encodes a Tag-Length-Value (TLV) element."""
    return bytes([tag]) + encode_length(len(value)) + value


def decode_tlv(data: bytes, offset: int = 0) -> Tuple[Optional[Tuple[int, bytes]], int]:
    """Decodes a single TLV element. Returns ((tag, value_bytes), new_offset)."""
    if offset >= len(data):
        return None, offset
    tag = data[offset]
    offset += 1
    length, offset = decode_length(data, offset)
    if offset + length > len(data):
        raise ValueError(f"Value length {length} exceeds available data ({len(data) - offset} bytes)")
    val = data[offset:offset + length]
    return (tag, val), offset + length


def encode_integer(val: int) -> bytes:
    """Encodes an integer to ASN.1 BER."""
    if val == 0:
        return encode_tlv(0x02, b"\x00")
    b = []
    temp = val
    if temp < 0:
        # 2's complement
        temp = (1 << (temp.bit_length() + 8)) + temp
    while temp > 0:
        b.insert(0, temp & 0xFF)
        temp >>= 8
    if val > 0 and (b[0] & 0x80):
        b.insert(0, 0)
    return encode_tlv(0x02, bytes(b))


def decode_integer(data: bytes) -> int:
    """Decodes ASN.1 BER bytes to integer."""
    if not data:
        return 0
    return int.from_bytes(data, "big", signed=True)


def encode_octet_string(val: str | bytes) -> bytes:
    """Encodes an Octet String (Tag 0x04)."""
    raw = val.encode("utf-8") if isinstance(val, str) else val
    return encode_tlv(0x04, raw)


def decode_octet_string(data: bytes) -> str:
    """Decodes an Octet String to string with UTF-8 decoding and fallback."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def encode_enumerated(val: int) -> bytes:
    """Encodes an Enumerated value (Tag 0x0A)."""
    raw_int = encode_integer(val)
    return bytes([0x0A]) + raw_int[1:]


def encode_boolean(val: bool) -> bytes:
    """Encodes a Boolean value (Tag 0x01)."""
    return encode_tlv(0x01, b"\xFF" if val else b"\x00")


def encode_sequence(elements: List[bytes], tag: int = 0x30) -> bytes:
    """Encodes a sequence of child byte elements."""
    return encode_tlv(tag, b"".join(elements))


def parse_sequence_elements(data: bytes) -> List[Tuple[int, bytes]]:
    """Extracts all top-level TLV elements from a sequence payload."""
    elements = []
    offset = 0
    while offset < len(data):
        try:
            item, offset = decode_tlv(data, offset)
        except ValueError:
            break
        if item is None:
            break
        elements.append(item)
    return elements


# ==============================================================================
# LDAP Filter Compilation (RFC 4511 §4.5.1)
# ==============================================================================

def compile_ldap_filter(filter_str: str) -> bytes:
    """Compiles a standard LDAP filter string into RFC 4511 BER filter bytes."""
    clean = filter_str.strip()
    if not clean:
        clean = "(objectClass=*)"

    if clean.startswith("(") and clean.endswith(")"):
        clean = clean[1:-1].strip()

    # Present filter: e.g. "objectClass=*"
    if clean.endswith("=*"):
        attr_name = clean[:-2].strip()
        return encode_tlv(0x87, attr_name.encode("utf-8"))

    # Equality filter: e.g. "sAMAccountName=admin"
    if "=" in clean and not (clean.startswith("&") or clean.startswith("|") or clean.startswith("!")):
        parts = clean.split("=", 1)
        attr = parts[0].strip()
        val = parts[1].strip()
        return encode_tlv(0xA3, encode_octet_string(attr) + encode_octet_string(val))

    # AND filter: e.g. "&(objectCategory=person)(objectClass=user)"
    if clean.startswith("&"):
        inner = clean[1:].strip()
        sub_filters = _split_composite_filter(inner)
        return encode_tlv(0xA0, b"".join(compile_ldap_filter(sf) for sf in sub_filters))

    # OR filter: e.g. "|(objectClass=user)(objectClass=group)"
    if clean.startswith("|"):
        inner = clean[1:].strip()
        sub_filters = _split_composite_filter(inner)
        return encode_tlv(0xA1, b"".join(compile_ldap_filter(sf) for sf in sub_filters))

    # NOT filter: e.g. "!(userAccountControl:1.2.840.113556.1.4.803:=2)"
    if clean.startswith("!"):
        inner = clean[1:].strip()
        return encode_tlv(0xA2, compile_ldap_filter(inner))

    # Fallback to present filter
    return encode_tlv(0x87, clean.encode("utf-8"))


def _split_composite_filter(text: str) -> List[str]:
    """Splits compound sub-filters honoring parenthesis balancing."""
    filters = []
    depth = 0
    start = -1
    for idx, ch in enumerate(text):
        if ch == "(":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start != -1:
                filters.append(text[start:idx + 1])
                start = -1
    return filters if filters else [text]


# ==============================================================================
# Read-Only LDAP Client
# ==============================================================================

class ReadOnlyLDAPClient:
    """Professional, pure-Python read-only Active Directory & LDAP client."""

    def __init__(
        self,
        host: str,
        port: int = 389,
        use_ssl: bool = False,
        timeout: float = 10.0,
        verify_cert: bool = True,
        server_hostname: Optional[str] = None,
    ):
        self.host = host.strip()
        self.port = int(port)
        self.use_ssl = bool(use_ssl)
        self.timeout = max(1.0, float(timeout))
        self.verify_cert = bool(verify_cert)
        self.server_hostname = (server_hostname or self.host).strip()
        self._sock: Optional[socket.socket] = None
        self._msg_counter = 1
        self._is_bound = False
        self._bound_user = ""
        self.last_result_code: int = 0
        self.last_diagnostic_message: str = ""
        self.last_matched_dn: str = ""

    def connect(self) -> Tuple[bool, str]:
        """Establishes a network socket connection to the LDAP/LDAPS service."""
        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_cert:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self._sock = ctx.wrap_socket(
                    raw_sock,
                    server_hostname=self.server_hostname if self.verify_cert else None,
                )
            else:
                self._sock = raw_sock

            self._sock.settimeout(self.timeout)
            return True, f"Connected to {self.host}:{self.port} (SSL={self.use_ssl})"
        except ssl.SSLCertVerificationError as cert_err:
            logger.warning(f"LDAPS Certificate Verification Failed for {self.host}: {cert_err}")
            return False, f"TLS Certificate Error: {cert_err}"
        except Exception as exc:
            logger.warning(f"Failed to connect to LDAP {self.host}:{self.port}: {exc}")
            return False, f"Connection error to {self.host}:{self.port}: {exc}"

    def bind(self, bind_dn: str = "", password: str = "") -> Tuple[bool, str]:
        """Performs a Read-Only Simple Bind or Anonymous Bind.

        Passwords are never logged or stored in instance state.
        """
        if not self._sock:
            ok, msg = self.connect()
            if not ok:
                return False, msg

        msg_id = self._next_msg_id()
        ver = encode_integer(3)
        name = encode_octet_string(bind_dn)
        auth = encode_tlv(0x80, password.encode("utf-8")) if password else encode_tlv(0x80, b"")
        protocol_op = encode_tlv(TAG_BIND_REQUEST, ver + name + auth)
        ldap_msg = encode_sequence([encode_integer(msg_id), protocol_op])

        try:
            self._sock.sendall(ldap_msg)
            resp = self._read_one_message()
            if not resp:
                return False, "Empty or disconnected response during bind"

            res_msg_id, op_tag, op_data = resp
            if op_tag != TAG_BIND_RESPONSE:
                return False, f"Unexpected bind response op_tag: 0x{op_tag:02x}"

            res_code, matched_dn, diag_msg = self._parse_ldap_result(op_data)
            self.last_result_code = res_code
            self.last_diagnostic_message = diag_msg
            self.last_matched_dn = matched_dn

            if res_code == RESULT_SUCCESS:
                self._is_bound = True
                self._bound_user = bind_dn if bind_dn else "anonymous"
                return True, "Bind successful"
            elif res_code == RESULT_INVALID_CREDENTIALS:
                return False, "Authentication failed: Invalid credentials (49)"
            elif res_code == RESULT_INAPPROPRIATE_AUTHENTICATION:
                return False, "Authentication failed: Anonymous bind disabled or rejected (48)"
            else:
                return False, f"Bind failed with LDAP result code {res_code}: {diag_msg or matched_dn}"
        except Exception as exc:
            return False, f"Socket error during bind: {exc}"

    def search(
        self,
        base_dn: str = "",
        scope: int = SCOPE_SUBTREE,
        filter_str: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        size_limit: int = 500,
        time_limit: int = 15,
    ) -> List[LDAPEntry]:
        """Executes a Read-Only LDAP search query, returning a list of LDAPEntry objects."""
        if not self._sock or not self._is_bound:
            # Attempt automatic anonymous bind if not already bound
            ok, msg = self.bind()
            if not ok:
                logger.warning(f"Auto-bind failed: {msg}")
                return []

        msg_id = self._next_msg_id()
        base = encode_octet_string(base_dn)
        sc = encode_enumerated(scope)
        deref = encode_enumerated(0)
        sz = encode_integer(max(1, min(size_limit, 2000)))
        tm = encode_integer(max(1, min(time_limit, 60)))
        types_only = encode_boolean(False)
        filter_bytes = compile_ldap_filter(filter_str)

        attrs_to_query = attributes or ["*"]
        attrs_seq = encode_sequence([encode_octet_string(a) for a in attrs_to_query])

        search_op = encode_tlv(
            TAG_SEARCH_REQUEST,
            base + sc + deref + sz + tm + types_only + filter_bytes + attrs_seq,
        )
        ldap_msg = encode_sequence([encode_integer(msg_id), search_op])

        entries: List[LDAPEntry] = []
        try:
            self._sock.sendall(ldap_msg)

            while True:
                resp = self._read_one_message()
                if not resp:
                    break

                res_msg_id, op_tag, op_data = resp
                # Check message ID correlation (allow res_msg_id 0 for unsolicited server notices)
                if res_msg_id != msg_id and res_msg_id != 0:
                    logger.debug(f"Ignoring mismatched message ID: {res_msg_id} != {msg_id}")
                    continue

                if op_tag == TAG_SEARCH_RES_ENTRY:
                    entry = self._parse_search_entry(op_data)
                    if entry:
                        entries.append(entry)
                elif op_tag == TAG_SEARCH_RES_DONE:
                    res_code, matched_dn, diag = self._parse_ldap_result(op_data)
                    self.last_result_code = res_code
                    self.last_diagnostic_message = diag
                    self.last_matched_dn = matched_dn
                    if res_code != RESULT_SUCCESS and res_code != RESULT_SIZE_LIMIT_EXCEEDED:
                        logger.info(f"LDAP search completed with code {res_code}: {diag}")
                    break
                elif op_tag == TAG_SEARCH_RES_REF:
                    # Referral entry, safely skip to prevent out-of-scope pivots
                    continue
                else:
                    logger.debug(f"Unhandled search response tag: 0x{op_tag:02x}")

            return entries
        except Exception as exc:
            logger.warning(f"Exception during LDAP search: {exc}")
            return entries

    def unbind(self):
        """Sends an unbind request and gracefully terminates session."""
        if self._sock and self._is_bound:
            try:
                msg_id = self._next_msg_id()
                op = bytes([TAG_UNBIND_REQUEST, 0x00])
                msg = encode_sequence([encode_integer(msg_id), op])
                self._sock.sendall(msg)
            except Exception:
                pass
        self.close()

    def close(self):
        """Closes the network socket."""
        self._is_bound = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _next_msg_id(self) -> int:
        cur = self._msg_counter
        self._msg_counter += 1
        return cur

    def _read_one_message(self) -> Optional[Tuple[int, int, bytes]]:
        """Reads exactly one complete ASN.1 BER LDAPMessage from the socket."""
        if not self._sock:
            return None

        # Read Tag (1 byte)
        tag_byte = self._sock.recv(1)
        if not tag_byte:
            return None
        tag = tag_byte[0]
        if tag != 0x30:
            logger.warning(f"Invalid message start tag: 0x{tag:02x}")
            return None

        # Read Length
        len_first_byte = self._sock.recv(1)
        if not len_first_byte:
            return None
        first = len_first_byte[0]

        if first < 128:
            length = first
        else:
            num_bytes = first & 0x7F
            if num_bytes == 0:
                raise ValueError("Indefinite length encoding (0x80) is prohibited in LDAP (RFC 4511 §5.1)")
            if num_bytes > 4:
                raise ValueError(f"Oversized BER length encoding: {num_bytes} bytes exceeds safe limit")
            len_rem = self._recv_exact(num_bytes)
            length = int.from_bytes(len_rem, "big")

        if length > MAX_MESSAGE_SIZE:
            raise ValueError(f"LDAP message size {length} exceeds maximum allowable limit ({MAX_MESSAGE_SIZE} bytes)")

        payload = self._recv_exact(length)

        # Parse message elements
        elements = parse_sequence_elements(payload)
        if len(elements) < 2:
            return None

        msg_id = decode_integer(elements[0][1])
        protocol_op_tag = elements[1][0]
        protocol_op_data = elements[1][1]
        return msg_id, protocol_op_tag, protocol_op_data

    def _recv_exact(self, count: int) -> bytes:
        """Helper to read an exact byte count from stream socket handling partial chunks."""
        buf = bytearray()
        while len(buf) < count:
            chunk = self._sock.recv(min(count - len(buf), 8192))
            if not chunk:
                raise ConnectionResetError("Remote server closed connection prematurely")
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _parse_search_entry(data: bytes) -> Optional[LDAPEntry]:
        """Parses a SearchResultEntry payload with binary formatting and sensitive redaction."""
        items = parse_sequence_elements(data)
        if len(items) < 2:
            return None

        dn = decode_octet_string(items[0][1])
        attrs_payload = items[1][1]

        attributes: Dict[str, List[str]] = {}
        for attr_seq in parse_sequence_elements(attrs_payload):
            parts = parse_sequence_elements(attr_seq[1])
            if len(parts) >= 2:
                attr_name = decode_octet_string(parts[0][1])
                val_set = parts[1][1]
                vals = []
                attr_lower = attr_name.lower()

                for val_item in parse_sequence_elements(val_set):
                    raw_val = val_item[1]
                    if attr_lower in SENSITIVE_ATTRIBUTES:
                        vals.append("[REDACTED_SENSITIVE_ATTRIBUTE]")
                    elif attr_lower in ("objectsid", "sid"):
                        vals.append(format_sid(raw_val))
                    elif attr_lower in ("objectguid", "guid"):
                        vals.append(format_guid(raw_val))
                    else:
                        vals.append(decode_octet_string(raw_val))

                attributes[attr_name] = vals

        return LDAPEntry(dn=dn, attributes=attributes)

    @staticmethod
    def _parse_ldap_result(data: bytes) -> Tuple[int, str, str]:
        """Parses standard LDAPResult: resultCode, matchedDN, diagnosticMessage."""
        items = parse_sequence_elements(data)
        res_code = decode_integer(items[0][1]) if len(items) > 0 else 0
        matched_dn = decode_octet_string(items[1][1]) if len(items) > 1 else ""
        diag_msg = decode_octet_string(items[2][1]) if len(items) > 2 else ""
        return res_code, matched_dn, diag_msg
