# CyberSecuritySuite — Phase 7A
## Pure-Python DNS & RDAP Reconnaissance Engine: Read-Only Architecture Audit & Gap Analysis

**Project:** CyberSecuritySuite  
**Inspection Type:** Pre-Implementation Architectural Audit (READ-ONLY)  
**Date:** November 1, 2026  
**Status:** Audit Complete — Standing by for Implementation Approval  
**Production Database SHA-256:** `6c7387a760b82c1358d84750992bc6706d513636b9038aa0fd79ed0fda1c38e6` (`PRAGMA integrity_check: ok`)

---

## 1. Executive Summary

A comprehensive read-only audit of the CyberSecuritySuite Information Gathering and OSINT subsystems was performed to establish baseline capabilities, identify architecture gaps in DNS and RDAP handling, and define an implementation roadmap for Phase 7A.

The audit confirms that while the application features a robust GUI workflow (`OSINTView`), strict scope authorization gating (`ScopeAuthorizationService`), and asset graph relationship tracking (`AssetNode`, `AssetEdge`, `AttackGraphView`), the underlying baseline passive discovery engine was relying on primitive OS resolver calls (`socket.gethostbyname_ex`), lacked standard multi-record DNS resolution (missing AAAA, MX, TXT, NS, SOA, PTR, SRV), had no native RDAP client, and used brittle external shell executions (`host`) for ASN lookups.

Phase 7A will eliminate external binary dependencies and provide a native, pure-Python RFC 1035 / RFC 3596 wire protocol DNS resolver and an RFC 7480–7484 HTTPS RDAP client seamlessly integrated into the existing `PassiveReconAdapter` and `OSINTView` UI without modifying the database schema.

---

## 2. Feature Gap Matrix (Existing vs. Missing)

| Capability / Feature | Baseline Status | Existing Implementation | Confirmed Gap / Defect | Target Phase 7A Implementation |
| :--- | :---: | :--- | :--- | :--- |
| **DNS A (IPv4)** | **Partial** | `socket.gethostbyname_ex()` | Only returns IPv4 addresses; cannot query custom nameservers or control timeout. | Pure-Python wire query with fallback to `socket.getaddrinfo`. |
| **DNS AAAA (IPv6)** | **Missing** | None | IPv6 resolution completely missing from baseline OSINT adapter. | Wire query for `TYPE_AAAA=28` + IPv6 fallback in `socket.getaddrinfo`. |
| **DNS CNAME (Aliases)** | **Partial** | Extracted from `gethostbyname_ex` aliases | Only exposes canonical alias if OS resolver returns it; misses chain traversal. | RFC 1035 CNAME parsing with wire label decompression. |
| **DNS MX (Mail)** | **Missing** | None | No mail server enumeration or prioritization. | Wire query for `TYPE_MX=15`; unpacks uint16 preference and exchange domain. |
| **DNS TXT (SPF/DKIM)** | **Missing** | None | Cannot evaluate SPF, DMARC, or verification records. | Wire query for `TYPE_TXT=16`; extracts length-prefixed strings. |
| **DNS NS (Nameservers)** | **Missing** | None | Authoritative zone delegation servers not discovered. | Wire query for `TYPE_NS=2`; maps authoritative nameservers. |
| **DNS SOA (Authority)** | **Missing** | None | Zone serial, primary master, admin mailbox missing. | Wire query for `TYPE_SOA=6`; parses mname, rname, serial, timers. |
| **DNS PTR (Reverse)** | **Missing** | None | Reverse in-addr.arpa lookup missing from passive adapter. | Wire query for `TYPE_PTR=12` + fallback to `socket.gethostbyaddr`. |
| **DNS SRV (Services)** | **Missing** | None | Service records (e.g. `_ldap._tcp`, `_kerberos._tcp`) not queried. | Wire query for `TYPE_SRV=33`; parses priority, weight, port, target. |
| **Wire Protocol Parser** | **Missing** | None (`dnspython` is not installed) | System relied on OS C-library resolver wrapper. | Zero-dependency pure-Python RFC 1035 packet builder and response parser. |
| **Compression Pointers** | **Missing** | None | N/A | RFC 1035 0xC0 pointer resolution with 60-hop cyclic safety limit. |
| **RDAP Domain Lookups** | **Missing** | Claimed in docstring; 0 lines of code in baseline | No domain expiration, creation, or registrar lookups. | Pure-Python RFC 7480-7484 client against `rdap.org/domain/{target}`. |
| **RDAP Entity / vCard** | **Missing** | None | No contact, registrar, or administrative entity extraction. | RFC 7095 jCard array parser (`_extract_vcard_fn_and_email`). |
| **RDAP IP / Netblock** | **Missing** | None | Subnet allocations and CIDR ranges not extracted via RDAP. | Query against `rdap.org/ip/{ip}`; extracts `cidr0_cidrs`, country, org. |
| **ASN BGP Attribution** | **Broken** | `subprocess.run(["host", ...])` | Depends on host `host` CLI binary; fails on minimal environments; brittle parsing. | Native RDAP query (`rdap.org/autnum/{asn}`) with fallback to Cymru DNS. |
| **Scope Boundary Guard** | **Implemented** | `ScopeAuthorizationService` | Functional for domain and IP targets. | Enforce fail-closed check on all discovered MX, NS, and IPs. |
| **AssetNode Persistence** | **Implemented** | `self.db.upsert_asset_node()` | Supported for `domain` and `ip`. | Extend ingestion to `nameserver`, `mail_exchange`, and `asn` nodes. |
| **AssetEdge Persistence** | **Implemented** | `self.db.upsert_asset_edge()` | Supported for `SUBDOMAIN_OF` and `RESOLVES_TO`. | Add `NS_FOR`, `MX_RECORD_FOR`, and `ANNOUNCED_BY_ASN` edges. |
| **Evidence & Observations** | **Implemented** | `Observation` and `Evidence` tables | Functional. | Persist comprehensive multi-record DNS and RDAP payload in Observation. |
| **Information Gathering UI** | **Implemented** | `desktop/views/osint_view.py` | 6-tab workspace with streaming telemetry log. | Wire live output streaming into existing `OSINTView` telemetry box. |

---

## 3. Existing Architecture Audit Details

### A. Existing DNS Resolver Capabilities
- **Current State:** The baseline `PassiveReconAdapter` relied on `socket.gethostbyname_ex()`. It could only obtain IPv4 addresses and hostname aliases reported by local OS name resolution.
- **Deficiencies:**
  1. No ability to query specific record types (`AAAA`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `SRV`).
  2. Inability to target explicit nameservers (e.g. `8.8.8.8`, `1.1.1.1`) to bypass poisoned or intercepted local resolvers.
  3. No support for IPv6 AAAA records.
  4. Third-party dependency `dnspython` is not installed in `.venv`.
- **Solution:** A standard library RFC 1035 wire protocol client implemented purely in `socket` and `struct`.

### B. Existing WHOIS / RDAP Capabilities
- **Current State:** The baseline adapter had no operational WHOIS or RDAP code. Registration dates and registrar identities were completely omitted from discovery results.
- **Deficiencies:** Analysts had no visibility into domain age, impending expiration, nameservers delegated at the registrar level, or registrant organizations without running external command-line tools.
- **Solution:** An asynchronous-compatible HTTPS client querying standard ICANN / RIR bootstrap endpoints (`rdap.org`), parsing JSON responses and RFC 7095 jCard contact arrays.

### C. Existing ASN and CIDR Lookup
- **Current State:** Function `resolve_ip_asn()` invoked `subprocess.run(["host", "-t", "txt", f"{rev_ip}.origin.asn.cymru.com"])`.
- **Deficiencies:**
  1. Spawns an OS subprocess requiring `/usr/bin/host`.
  2. Silently fails if `bind9-host` is uninstalled.
  3. Only extracts ASN and BGP prefix; does not provide allocation range, network handle, country, or organization.
- **Solution:** Native RDAP IP lookup (`rdap.org/ip/{target}`) yielding structured CIDR, country, organization, and ASN, with DNS TXT resolution as a secondary zero-subprocess fallback.

### D. Existing CT and Amass Integrations
- `cert_transparency_adapter.py`: Operates natively via `crt.sh` JSON queries and regex filtering. Fully operational and verified.
- `amass_osint_adapter.py`: Operates as a wrapper around the local Amass binary. Checks availability and fails gracefully if Amass is not installed.
- **Conclusion:** These modules are working as intended and will remain unchanged.

### E. Existing Engagement Scope Enforcement
- `ScopeAuthorizationService.is_target_authorized()` provides centralized validation against `TargetScope` entries (allowed vs. excluded, hostname, IP, CIDR, wildcard).
- **Audit Finding:** The baseline adapter checked scope for subdomains and IPs, but lacked explicit validation for mail exchangers and nameservers.
- **Phase 7A Enhancement:** Guarantee that every discovered domain, subdomain, mail exchange, nameserver, and IP address passes through `is_target_authorized()` before an `AssetNode` or `AssetEdge` is generated. Out-of-scope discoveries are recorded in `quarantined_assets`.

### F. Existing Asset Graph Persistence
- Database models `AssetNode` and `AssetEdge` support arbitrary node types and relation types:
  - Supported node types: `domain`, `subdomain`, `ip`, `host`, `cert`, `nameserver`, `mail_exchange`, `asn`.
  - Supported edge types: `SUBDOMAIN_OF`, `RESOLVES_TO`, `NS_FOR`, `MX_RECORD_FOR`, `ANNOUNCED_BY_ASN`.
- Uniqueness constraints on `AssetEdge` prevent duplicate relationships during repeated scans.
- **Audit Finding:** The baseline adapter only created `SUBDOMAIN_OF` and `RESOLVES_TO`. In Phase 7A, we will also create `NS_FOR`, `MX_RECORD_FOR`, and `ANNOUNCED_BY_ASN`.

### G. Existing Evidence and Findings Integration
- Security testing principles prohibit misrepresenting normal passive recon findings (such as missing DNSSEC or standard MX records) as critical vulnerabilities.
- Correlated recon data must be stored in the `Observation` table and linked to the root `AssetNode` and `Project`, preserving evidence integrity without triggering false-positive alerts.

### H. Existing GUI Workflow
- `OSINTView` in `desktop/views/osint_view.py` provides an intuitive user experience:
  - Case management tab linking investigations to authorized engagements.
  - Discovery tab with live streaming telemetry output.
  - Maltego-compatible interactive relationship graph (`AttackGraphView`).
  - Asset inventory tab with "Authorize Selected in Project Scope" action.
  - Correlated observations viewer.

---

## 4. Proposed Module Architecture

```
modules/osint/
├── __init__.py
├── base_adapter.py              (Unchanged abstract interface: BaseOSINTAdapter)
├── cert_transparency_adapter.py (Unchanged CT log scraper)
├── amass_osint_adapter.py       (Unchanged Amass wrapper)
├── theharvester_adapter.py      (Unchanged optional wrapper)
├── recon_ng_adapter.py          (Unchanged optional wrapper)
├── maltego_graph.py             (Unchanged graph export engine)
├── dns_resolver.py              <-- Phase 7A Pure-Python DNS Wire Protocol Client
├── rdap_client.py               <-- Phase 7A Pure-Python RDAP REST Client
└── passive_recon.py             <-- Phase 7A Integrated Passive Adapter (Orchestrator)
```

### Module Responsibilities:
1. **`dns_resolver.py` (`PurePythonDNSResolver`):**
   - Pure-Python binary packet constructor (`build_dns_query_packet`) and response parser (`parse_dns_response_packet`).
   - Supports: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV.
   - Decompresses RFC 1035 labels with recursion protection.
   - Fallback to `socket.getaddrinfo` when UDP 53 is unreachable.
2. **`rdap_client.py` (`PurePythonRDAPClient`):**
   - Connects to universal bootstrap HTTPS endpoints (`rdap.org`).
   - Parses domain, IP, and ASN records.
   - Decodes jCard contact lists and registration timestamps.
3. **`passive_recon.py` (`PassiveReconAdapter`):**
   - Orchestrates DNS, RDAP, CT logs, and HTTP tech fingerprinting.
   - Enforces scope gating on all assets.
   - Ingests nodes and relational edges into the database.
   - Saves observation records.

---

## 5. GUI Integration Plan

The existing `OSINTView` (`desktop/views/osint_view.py`) already instantiates:
```python
self.adapters["passive_recon"] = PassiveReconAdapter(self.db)
```
No major redesign of `OSINTView` is required. The integration points are:
1. **Streaming Telemetry Output:** `PassiveReconAdapter` invokes `on_output(msg, stream)` for every resolved DNS record (A, AAAA, MX, NS, TXT, SOA), RDAP registrar, creation date, and ASN routing info. These stream live into `self.discovery_log`.
2. **Asset Inventory Table:** As `AssetNode` records are upserted for nameservers, mail servers, IPs, and ASNs, they appear immediately in the "Asset Inventory & Scope Review" tab upon completion.
3. **Attack Graph Canvas:** The `AttackGraphView` automatically renders nodes and edges (`RESOLVES_TO`, `MX_RECORD_FOR`, `NS_FOR`, `ANNOUNCED_BY_ASN`) using the existing graph layout engine.

---

## 6. Test Plan

A dedicated test suite `tests/test_dns_rdap_engine.py` covering:
1. **Wire Packet Serialization:** Header, QNAME length prefixing, QTYPE, and QCLASS validation.
2. **Wire Packet Deserialization:** Parsing A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV records.
3. **Pointer Decompression:** RFC 1035 `0xC0` pointer offsets and cyclic pointer loop safety.
4. **Offline / Firewall Fallback:** `socket.getaddrinfo` fallback validation.
5. **RDAP Domain Lookups:** JSON parsing, jCard entity decoding, event date parsing.
6. **RDAP IP & Netblock:** CIDR extraction, country, and organization parsing.
7. **RDAP ASN Attribution:** Autonomous system name and handle parsing.
8. **Error Resilience:** HTTP 404, timeouts, and malformed payload handling.
9. **End-to-End Adapter Integration:** Complete discovery run in temporary database.
10. **Scope Quarantine:** Out-of-scope targets quarantined without DB insertion.
11. **Full Repository Regression Suite:** Zero regression across the entire test suite.

---

## 7. Risk Assessment & Safety Controls

| Identified Risk | Severity | Mitigation Strategy |
| :--- | :---: | :--- |
| **Out-of-Scope Network Probing** | High | Scope check enforced on every discovered asset before persistence or secondary lookups. |
| **DNS Packet Cyclic Loop DoS** | High | Maximum hop limit (60) in wire label decompressor prevents infinite loops on cyclic packets. |
| **Outbound UDP 53 Blocking** | Medium | Graceful fallback to `socket.getaddrinfo` ensures standard domain resolution continues even when raw UDP 53 is blocked. |
| **External RDAP Rate Limiting** | Low | Configurable short timeouts (5-6s), single-request bootstrapping via `rdap.org`, and graceful error handling on HTTP 429/503. |
| **Production Database Corruption** | Critical | Use isolated temporary databases for all tests; verify SHA-256 before and after work; no schema migrations. |
| **False-Positive Findings** | Medium | Missing DNS records or normal recon data are recorded as `Observation` items, not vulnerability findings. |

---

## 8. Staged Implementation Plan

- **Stage 1 (Pure-Python Wire DNS Resolver):** Verify `modules/osint/dns_resolver.py` query packaging, parsing, and label decompression.
- **Stage 2 (Pure-Python RDAP Client):** Verify `modules/osint/rdap_client.py` HTTPS REST client, jCard parsing, and CIDR/ASN lookups.
- **Stage 3 (Adapter Wiring & Graph Ingestion):** Wire both engines into `modules/osint/passive_recon.py`, enforcing scope validation and persisting `AssetNode` / `AssetEdge` topology.
- **Stage 4 (Automated Testing & Regressions):** Execute `tests/test_dns_rdap_engine.py` and full repository regression suite.
- **Stage 5 (Verification & Delivery):** Confirm production database immutability and deliver final technical report.

---

> **Status:** Read-only architecture audit complete. No source code modifications or database operations have been executed during this audit. Standing by for your explicit approval before proceeding to implementation.

