"""Pure-Python Registration Data Access Protocol (RDAP) Client (RFC 7480-7484).

Provides native zero-dependency querying of international Internet registries (RIRs & ICANN):
- Domain Registration & Expiry Lookups
- IP Address & Subnet Netblock Attribution (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- Autonomous System Number (ASN) Ownership & Organization Profiling
- Entity & vCard parsing (Registrar, Registrant, Administrative & Abuse Contacts)
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# RFC 7484 RDAP Bootstrap Root Providers
BOOTSTRAP_DOMAIN_URL = "https://rdap.org/domain/{target}"
BOOTSTRAP_IP_URL = "https://rdap.org/ip/{target}"
BOOTSTRAP_AUTNUM_URL = "https://rdap.org/autnum/{target}"


@dataclass
class RDAPDomainResult:
    """Structured RDAP domain registration metadata."""
    domain: str
    handle: str = ""
    status: List[str] = field(default_factory=list)
    registrar: str = ""
    iana_id: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    created_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    entities: Dict[str, Any] = field(default_factory=dict)
    raw_json: Dict[str, Any] = field(default_factory=dict)
    is_successful: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "handle": self.handle,
            "status": self.status,
            "registrar": self.registrar,
            "iana_id": self.iana_id,
            "nameservers": self.nameservers,
            "created_date": self.created_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "entities": self.entities,
            "is_successful": self.is_successful,
            "error_message": self.error_message,
        }


@dataclass
class RDAPIPResult:
    """Structured RDAP IP address network allocation metadata."""
    ip: str
    handle: str = ""
    name: str = ""
    cidr: str = ""
    country: str = ""
    organization: str = ""
    asn: Optional[str] = None
    status: List[str] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    raw_json: Dict[str, Any] = field(default_factory=dict)
    is_successful: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "handle": self.handle,
            "name": self.name,
            "cidr": self.cidr,
            "country": self.country,
            "organization": self.organization,
            "asn": self.asn,
            "status": self.status,
            "entities": self.entities,
            "is_successful": self.is_successful,
            "error_message": self.error_message,
        }


@dataclass
class RDAPASNResult:
    """Structured RDAP BGP Autonomous System Number (ASN) metadata."""
    asn: str
    handle: str = ""
    name: str = ""
    country: str = ""
    organization: str = ""
    allocated_date: Optional[str] = None
    raw_json: Dict[str, Any] = field(default_factory=dict)
    is_successful: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asn": self.asn,
            "handle": self.handle,
            "name": self.name,
            "country": self.country,
            "organization": self.organization,
            "allocated_date": self.allocated_date,
            "is_successful": self.is_successful,
            "error_message": self.error_message,
        }


def _extract_vcard_fn_and_email(entity: Dict[str, Any]) -> Dict[str, str]:
    """Parses RFC 7095 jCard / vCard data structures from RDAP entity entries."""
    parsed: Dict[str, str] = {}
    vcard = entity.get("vcardArray", [])
    if len(vcard) >= 2 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4:
                prop_name = prop[0]
                prop_val = prop[3]
                if prop_name == "fn" and isinstance(prop_val, str):
                    parsed["name"] = prop_val
                elif prop_name == "email" and isinstance(prop_val, str):
                    parsed["email"] = prop_val
                elif prop_name == "tel" and isinstance(prop_val, str):
                    parsed["phone"] = prop_val
                elif prop_name == "adr" and isinstance(prop_val, list):
                    addr_parts = [str(x) for x in prop_val if x]
                    if addr_parts:
                        parsed["address"] = ", ".join(addr_parts)
    return parsed


def _parse_rdap_events(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """Parses RDAP event array for registration, expiration, and last changed dates."""
    dates: Dict[str, str] = {}
    for ev in events:
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action and date:
            if action in ("registration", "allocated"):
                dates["created"] = date
            elif action in ("expiration", "expire"):
                dates["expires"] = date
            elif action in ("last changed", "last updated"):
                dates["updated"] = date
    return dates


class PurePythonRDAPClient:
    """RFC 7480-7484 HTTPS REST client for universal Internet registry lookups."""

    def __init__(self, user_agent: Optional[str] = None, timeout: float = 6.0):
        self.user_agent = user_agent or "CyberSecuritySuite-OSINT/1.0 (+https://cybersecuritysuite.local)"
        self.timeout = timeout

    def _fetch_json(self, url: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Safely fetches and parses an RDAP JSON payload over HTTPS."""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/rdap+json, application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    raw_data = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw_data), None
                return None, f"HTTP Error {resp.status}"
        except urllib.error.HTTPError as h_err:
            if h_err.code == 404:
                return None, "RDAP record not found (404 Not Found)."
            return None, f"RDAP HTTP Error: {h_err.code} {h_err.reason}"
        except Exception as exc:
            return None, f"RDAP connection error: {exc}"

    def lookup_domain(self, domain: str) -> RDAPDomainResult:
        """Performs universal RDAP registration lookup for an Internet domain name."""
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = clean_domain.split("://")[1].split("/")[0]

        result = RDAPDomainResult(domain=clean_domain)
        url = BOOTSTRAP_DOMAIN_URL.format(target=urllib.parse.quote(clean_domain))

        data, err = self._fetch_json(url)
        if err or not data:
            result.error_message = err or "Empty RDAP payload"
            return result

        result.raw_json = data
        result.is_successful = True
        result.handle = data.get("handle", "")
        result.status = data.get("status", [])

        # Parse Dates
        dates = _parse_rdap_events(data.get("events", []))
        result.created_date = dates.get("created")
        result.expiration_date = dates.get("expires")
        result.updated_date = dates.get("updated")

        # Parse Nameservers
        ns_list = []
        for ns_obj in data.get("nameservers", []):
            ns_name = ns_obj.get("ldhName") or ns_obj.get("handle", "")
            if ns_name:
                ns_list.append(ns_name.lower())
        result.nameservers = ns_list

        # Parse Entities (Registrar, Registrant, Abuse)
        entities_map: Dict[str, Any] = {}
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard_data = _extract_vcard_fn_and_email(ent)
            ent_handle = ent.get("handle", "")
            name = vcard_data.get("name") or ent_handle

            if "registrar" in roles:
                result.registrar = name
                public_ids = ent.get("publicIds", [])
                for pid in public_ids:
                    if pid.get("type") == "IANA Registrar ID":
                        result.iana_id = pid.get("identifier")

            for r in roles:
                if r not in entities_map:
                    entities_map[r] = {
                        "name": name,
                        "handle": ent_handle,
                        **vcard_data,
                    }

        result.entities = entities_map
        return result

    def lookup_ip(self, ip_str: str) -> RDAPIPResult:
        """Performs RDAP allocation and network block lookup for an IPv4 or IPv6 address."""
        clean_ip = ip_str.strip()
        result = RDAPIPResult(ip=clean_ip)
        url = BOOTSTRAP_IP_URL.format(target=urllib.parse.quote(clean_ip))

        data, err = self._fetch_json(url)
        if err or not data:
            result.error_message = err or "Empty RDAP payload"
            return result

        result.raw_json = data
        result.is_successful = True
        result.handle = data.get("handle", "")
        result.name = data.get("name", "")
        result.country = data.get("country", "")
        result.status = data.get("status", [])

        # Parse CIDR
        cidrs = []
        for c in data.get("cidr0_cidrs", []):
            p = c.get("v4prefix") or c.get("v6prefix") or c.get("prefix")
            l = c.get("length")
            if p is not None and l is not None:
                cidrs.append(f"{p}/{l}")
        if not cidrs:
            start_ip = data.get("startAddress")
            end_ip = data.get("endAddress")
            if start_ip and end_ip:
                cidrs.append(f"{start_ip} - {end_ip}")
        result.cidr = ", ".join(cidrs)

        # Parse Entities
        entities_map: Dict[str, Any] = {}
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard_data = _extract_vcard_fn_and_email(ent)
            name = vcard_data.get("name") or ent.get("handle", "")
            if "registrant" in roles or "administrative" in roles:
                if not result.organization:
                    result.organization = name
            for r in roles:
                if r not in entities_map:
                    entities_map[r] = {"name": name, **vcard_data}

        result.entities = entities_map
        return result

    def lookup_asn(self, asn_val: Union[int, str]) -> RDAPASNResult:
        """Performs RDAP query for an Autonomous System Number (ASN)."""
        clean_asn = str(asn_val).strip().upper()
        if clean_asn.startswith("AS"):
            clean_asn = clean_asn[2:]

        result = RDAPASNResult(asn=f"AS{clean_asn}")
        url = BOOTSTRAP_AUTNUM_URL.format(target=urllib.parse.quote(clean_asn))

        data, err = self._fetch_json(url)
        if err or not data:
            result.error_message = err or "Empty RDAP payload"
            return result

        result.raw_json = data
        result.is_successful = True
        result.handle = data.get("handle", "")
        result.name = data.get("name", "")
        result.country = data.get("country", "")

        dates = _parse_rdap_events(data.get("events", []))
        result.allocated_date = dates.get("created")

        # Parse Organization
        for ent in data.get("entities", []):
            vcard_data = _extract_vcard_fn_and_email(ent)
            name = vcard_data.get("name") or ent.get("handle", "")
            if name:
                result.organization = name
                break

        return result
