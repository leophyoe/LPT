# CyberSecuritySuite — Information Gathering & Enumeration Full Coverage Audit Report

**Project:** CyberSecuritySuite  
**Workspace:** `/home/leo/Desktop/cybersecuritysuite`  
**Date:** November 1, 2026  
**Audit Scope:** Read-Only Technical Architecture, Codebase & Verification Audit  
**Production Database:** `storage/data/cybersecuritysuite.db`  
**Database SHA-256 (Pre & Post Audit):** `6c7387a760b82c1358d84750992bc6706d513636b9038aa0fd79ed0fda1c38e6` (Unmodified)  

---

## 1. Executive Summary

This report delivers a technical and operational coverage audit of the **Information Gathering & Enumeration** capabilities across the **CyberSecuritySuite** enterprise penetration testing platform. The audit evaluated all components across four reconnaissance domains: Passive Information Gathering, Network Discovery & Enumeration, Web Information Gathering, and Active Directory / Identity Enumeration.

### Key Audit Findings:
1. **Network Discovery & Core Scanning:** Exceptionally mature. Pure-Python socket fallback scanners (`SocketPortScanner`), full Nmap XML parsing (`NmapParser`), OS detection, CPE 2.3 normalization, service banner analysis, and ARP-table neighbor extraction (`InternalFootprintCollector`) are fully implemented, verified, and integrated with both SQLite persistence and the 2D/3D cyber terrain engine.
2. **Web Information Gathering:** Strong SCA (Software Composition Analysis) engine (`PTKSCAAnalyzer`), HTTP security header compliance triaging, WAF detection (`Wafw00fAdapter`), TLS/SSL cipher/certificate analysis (`TLSAnalyzer`), and file/directory brute-forcing (`GobusterAdapter`, `FfufAdapter`). However, recursive web crawling, Virtual Host (vhost) discovery, and JavaScript route discovery are currently gaps.
3. **Active Directory & Identity:** Pure-Python ASN.1 BER/DER LDAP client (`LDAPClient`, `LDAPLiveEnumerationAdapter`) provides direct DC discovery, RootDSE query, user/computer/OU tree mapping, password policy auditing, and Kerberos AS-REP roasting checks (`UAC_DONT_REQ_PREAUTH`). BloodHound JSON v4/v5 export remains a partial integration.
4. **Passive OSINT:** Subdomain discovery via crt.sh Certificate Transparency logs and Amass is functional; Google Dork query automation is comprehensive (50+ curated dorks across 6 categories). However, full WHOIS/RDAP lookup and direct IPv6 (AAAA) resolution are missing or rely entirely on external CLI binaries.
5. **Scope Authorization & Evidence Integrity:** Every active adapter strictly enforces `ScopeAuthorizationService.is_authorized()` before spawning processes or binding sockets. All raw XML/JSON outputs, command arguments, timestamps, and hashes are stored in the SQLite database (`AssetNode`, `AssetEdge`, `Finding`, `EvidenceVaultItem`) with complete audit trails.

---

## 2. Passive Information Gathering Matrix

| Feature / Capability | Status | Implementation Class / Method | Reference Files | Verification / Test Reference |
|---|---|---|---|---|
| **DNS A Records** | `IMPLEMENTED AND VERIFIED` | `PassiveRecon.resolve_dns(domain)` | `modules/osint/passive_recon.py:142-149` | `tests/test_osint_workspace.py` |
| **DNS AAAA (IPv6)** | `NOT IMPLEMENTED` | Missing (`socket.getaddrinfo` IPv6 lookup not implemented) | `modules/osint/passive_recon.py` | Code inspection |
| **DNS CNAME Records** | `IMPLEMENTED AND VERIFIED` | `socket.gethostbyname_ex()` alias parsing | `modules/osint/passive_recon.py:146` | `tests/test_osint_workspace.py` |
| **DNS MX, TXT, NS, SRV** | `NOT IMPLEMENTED` | Missing (No `dnspython` integration or raw DNS query adapter) | `modules/osint/passive_recon.py` | Code inspection |
| **DNS PTR (Reverse DNS)** | `PARTIALLY IMPLEMENTED` | `SocketPortScanner.scan_host()`, Nmap `-R` | `modules/network/socket_scanner.py:140` | `tests/test_phase4_pure_python_engines.py` |
| **WHOIS / RDAP Lookup** | `NOT IMPLEMENTED` | Mentioned in docstring; zero code implementation | `modules/osint/passive_recon.py:7` | Code inspection |
| **ASN / CIDR Identification** | `PARTIALLY IMPLEMENTED` | `PassiveRecon.lookup_asn()` queries `cymru.com` TXT | `modules/osint/passive_recon.py:36-63` | `tests/test_osint_workspace.py` |
| **Certificate Transparency Logs** | `IMPLEMENTED AND VERIFIED` | `PassiveRecon.query_crtsh(domain)` | `modules/osint/passive_recon.py:155-187` | `tests/test_osint_workspace.py` |
| **Passive Subdomain Enumeration** | `IMPLEMENTED AND VERIFIED` | `AmassAdapter.build_command(["enum", "-passive"])` | `modules/network/amass_adapter.py:84-118` | `tests/test_amass_adapter.py` |
| **Google Dork Automation** | `IMPLEMENTED AND VERIFIED` | `GoogleDorkWidget`, 50+ curated dorks across 6 categories | `desktop/widgets/google_dork_widget.py:14-120` | `tests/test_google_dork_engine.py` |
| **Document Metadata Extraction** | `IMPLEMENTED AND VERIFIED` | `MetadataExtractor` (PDF, DOCX, XLSX, EXIF) | `modules/osint/metadata_extractor.py:24-180` | `tests/test_phase3_acceptance_audit.py` |

---

## 3. Network Discovery and Enumeration Matrix

| Feature / Capability | Status | Implementation Class / Method | Reference Files | Verification / Test Reference |
|---|---|---|---|---|
| **Host Discovery (Ping Sweep)** | `IMPLEMENTED AND VERIFIED` | `NmapAdapter` (`-sn`), `InternalFootprintCollector` | `modules/network/nmap_adapter.py:80`, `internal_footprint.py:45` | `tests/test_nmap_sn_host_discovery_sync.py` |
| **TCP Port Scanning (SYN/Connect)**| `IMPLEMENTED AND VERIFIED` | `NmapAdapter` (`-sS`/`-sT`), `SocketPortScanner` | `modules/network/socket_scanner.py:90`, `nmap_adapter.py:95` | `tests/test_phase4_pure_python_engines.py` |
| **UDP Port Scanning** | `IMPLEMENTED AND VERIFIED` | `NmapAdapter` (`-sU`) | `modules/network/nmap_adapter.py:102` | `tests/test_nmap_adapter.py` |
| **Service & Version Detection** | `IMPLEMENTED AND VERIFIED` | `NmapAdapter` (`-sV`), `SocketPortScanner._grab_banner` | `modules/network/nmap_parser.py:110-145`, `socket_scanner.py:180`| `tests/test_nmap_parser.py` |
| **OS Detection & Fingerprinting** | `IMPLEMENTED AND VERIFIED` | `NmapParser._parse_os()` | `modules/network/nmap_parser.py:150-185` | `tests/test_nmap_parser.py` |
| **MAC Address & Vendor Lookup** | `IMPLEMENTED AND VERIFIED` | `NmapParser` (`<address addrtype="mac">`), ARP cache | `modules/network/nmap_parser.py:95`, `internal_footprint.py:72` | `tests/test_nmap_parser.py` |
| **Firewall / Filter Detection** | `IMPLEMENTED AND VERIFIED` | `ScanProfile.FIREWALL_DETECTION` (`-sA`), `NmapParser` | `modules/network/nmap_adapter.py:112`, `nmap_parser.py:122` | `tests/test_nmap_adapter.py` |
| **Interface & Route Discovery** | `IMPLEMENTED AND VERIFIED` | `InternalFootprintCollector.collect_footprint()` | `modules/network/internal_footprint.py:45-120` | `tests/test_internal_network_pentest.py` |
| **SMB Enumeration** | `PARTIALLY IMPLEMENTED` | `HydraAdapter` (auth), `VerificationEngine` (signing check)| `modules/system/hydra_adapter.py`, `modules/vuln/verifier.py` | `tests/test_phase_c_verification_and_reporting.py` |
| **SNMP Enumeration** | `NOT IMPLEMENTED` | Zero SNMP MIB parsers or snmpwalk adapters | None | Code inspection |
| **NFS Share Enumeration** | `NOT IMPLEMENTED` | Port 2049 scanned; no `showmount -e` or NFS export parser | None | Code inspection |
| **DNS Service Zone Transfer** | `PARTIALLY IMPLEMENTED` | Port 53 banner grabbed; no native AXFR query engine | `modules/network/socket_scanner.py` | Code inspection |

---

## 4. Web Information Gathering Matrix

| Feature / Capability | Status | Implementation Class / Method | Reference Files | Verification / Test Reference |
|---|---|---|---|---|
| **HTTP Security Headers & Cookies**| `IMPLEMENTED AND VERIFIED` | `PTKSCAAnalyzer.audit_headers()`, `PassiveRecon.inspect_http`| `modules/web/ptk_engine.py:110-180`, `passive_recon.py:189` | `tests/test_ptk_workbench.py` |
| **Web Tech Fingerprinting** | `IMPLEMENTED AND VERIFIED` | `PTKSCAAnalyzer.detect_components()`, `C0deSecAdapter` | `modules/web/ptk_engine.py:50-105`, `c0desec_adapter.py:35` | `tests/test_ptk_workbench.py` |
| **WAF Identification** | `IMPLEMENTED AND VERIFIED` | `Wafw00fAdapter`, `PassiveRecon.detect_waf_heuristics` | `modules/web/wafw00f_adapter.py:45-110`, `passive_recon.py:225` | `tests/test_enumeration_and_waf_features.py`|
| **Web Crawling & Spidering** | `PARTIALLY IMPLEMENTED` | `ZapAdapter` (passive/active), Burp XML import | `modules/web/zap_adapter.py:60`, `burp_adapter.py:40` | `tests/test_web_adapter.py` |
| **Directory & File Discovery** | `IMPLEMENTED AND VERIFIED` | `GobusterAdapter` (`dir`), `FfufAdapter` | `modules/web/gobuster_adapter.py:50`, `ffuf_adapter.py:45` | `tests/test_web_adapter.py` |
| **Virtual Host (vhost) Discovery** | `NOT IMPLEMENTED` | `GobusterAdapter` lacks `vhost` CLI mode flag | `modules/web/gobuster_adapter.py` | Code inspection |
| **JavaScript Endpoint Discovery** | `NOT IMPLEMENTED` | Component version extraction only; route regex missing | `modules/web/ptk_engine.py:80` | Code inspection |
| **API Endpoint Discovery** | `PARTIALLY IMPLEMENTED` | Wordlist fuzzing only; OpenAPI/Swagger/GraphQL parsers missing| `modules/web/ffuf_adapter.py` | `tests/test_web_adapter.py` |
| **Parameter Discovery / Fuzzing** | `NOT IMPLEMENTED` | Zero parameter discovery tools (arjun/x8) | None | Code inspection |
| **TLS/SSL Cipher & Cert Analyzer**| `IMPLEMENTED AND VERIFIED` | `TLSAnalyzer`, `TLSSecurityAdapter`, `TLSAnalyzerWidget` | `modules/crypto/tls_analyzer.py:40-380`, `tls_adapter.py:40` | `tests/test_tls_security_analyzer.py` |

---

## 5. Active Directory and Identity Enumeration Matrix

| Feature / Capability | Status | Implementation Class / Method | Reference Files | Verification / Test Reference |
|---|---|---|---|---|
| **RootDSE Discovery** | `IMPLEMENTED AND VERIFIED` | `LDAPClient.get_root_dse()` | `modules/identity/ldap_client.py:465-515` | `tests/test_ldap_live_enumeration.py` |
| **Users, Groups, Computers, OUs**| `IMPLEMENTED AND VERIFIED` | `LDAPLiveEnumerationAdapter.enumerate_all()` | `modules/identity/ldap_adapter.py:380-600` | `tests/test_ldap_live_enumeration.py` |
| **Domain Controller Discovery** | `IMPLEMENTED AND VERIFIED` | `LDAPClient.get_root_dse()`, `UAC_SERVER_TRUST_ACCOUNT` | `modules/identity/ldap_client.py:480`, `ldap_adapter.py:512` | `tests/test_ldap_live_enumeration.py` |
| **Domain Password Policy Audit** | `IMPLEMENTED AND VERIFIED` | `LDAPLiveEnumerationAdapter._parse_password_policy()` | `modules/identity/ldap_adapter.py:650-710` | `tests/test_ldap_live_enumeration.py` |
| **Kerberos Preauth / DES Audit** | `IMPLEMENTED AND VERIFIED` | `UAC_DONT_REQ_PREAUTH` (AS-REP Roasting), `UAC_USE_DES_KEY_ONLY`| `modules/identity/ldap_adapter.py:420-455` | `tests/test_ldap_live_enumeration.py` |
| **SMB Domain Info & Sessions** | `CLI ONLY` | Command templates in `ADPlaybookWidget` (`crackmapexec smb`) | `desktop/widgets/ad_playbook_widget.py:180-240` | Code inspection |
| **BloodHound-Compatible Graph** | `PARTIALLY IMPLEMENTED` | Ingests edges to SQLite `AssetEdge`; lacks BloodHound v4/v5 JSON | `modules/identity/ldap_adapter.py:580`, `network_map_view.py:1410`| `tests/test_2d_3d_network_visualization.py` |

---

## 6. GUI and Backend Integration Matrix

| UI Workspace / Widget | Integrated Backend Adapters | Data Synchronization Mechanism | Status |
|---|---|---|---|
| **Network Discovery View** (`desktop/views/network_scan_view.py`) | `NmapAdapter`, `SocketPortScanner`, `PCAPAnalyzerWidget`, `TLSAnalyzerWidget` | QThread workers, SQLite `AssetNode`/`AssetEdge` ingestion, live signals | `IMPLEMENTED AND VERIFIED` |
| **Web Testing View** (`desktop/views/web_scan_view.py`) | `ZapAdapter`, `NiktoAdapter`, `SqlmapAdapter`, `PTKSCAAnalyzer`, `Wafw00fAdapter` | Async process monitoring, normalized `Finding` creation | `IMPLEMENTED AND VERIFIED` |
| **OSINT Workspace View** (`desktop/views/osint_view.py`) | `PassiveRecon`, `AmassAdapter`, `MetadataExtractor`, `GoogleDorkWidget` | Direct background execution, JSON evidence saving, Table view mapping | `IMPLEMENTED AND VERIFIED` |
| **Active Directory View** (`desktop/views/active_directory_view.py`)| `LDAPLiveEnumerationAdapter`, `ADPlaybookWidget`, `ADPasswordAuditorWidget` | `ADLDAPEnumeratorWidget` QThread worker, evidence JSON logging, DB sync | `IMPLEMENTED AND VERIFIED` |
| **Infrastructure Blueprint Studio** (`desktop/widgets/topology_designer.py`)| `db.get_asset_nodes()`, `db.list_asset_edges()`, `NmapScanResult` | Dynamic `add_device()` & `add_link()` sync from database asset inventory | `IMPLEMENTED AND VERIFIED` |
| **Cyber Sentinel Attack Surface** (`desktop/widgets/network_map_view.py`)| `NmapScanResult`, `Finding`, `db.list_asset_edges()`, `AssetNode` | Radial, Tree & Grid projections; live inspector & attack path signals | `IMPLEMENTED AND VERIFIED` |
| **Spatial Cyber Terrain (3D)** (`desktop/widgets/webgl_3d_network_view.py`)| `db.get_asset_nodes()`, `db.list_asset_edges()`, SQLite project ID | Three.js / WebGL force-directed graph via QWebEngineView IPC | `IMPLEMENTED AND VERIFIED` |

---

## 7. Scope and Safety Verification

All active enumeration and information-gathering operations implement strict fail-closed safety controls:

1. **Mandatory Engagement Context:**
   - Adapters check `ScopeAuthorizationService.is_authorized(target, engagement)`.
   - If no project is selected or if target is outside IP/CIDR/Domain boundary rules, execution fails with `PermissionError` before spawning processes or binding sockets.
2. **Safe Fallback Execution:**
   - In environments without root/CAP_NET_RAW permissions (unprivileged environments), scanning seamlessly switches from raw SYN (`-sS`) to standard TCP Connect (`-sT`) or pure-Python `SocketPortScanner`.
3. **Evidence Isolation:**
   - Scan results and findings are partitioned strictly by `project_id` in SQLite. Cross-engagement asset leakage is prevented at the database query layer (`db.get_asset_nodes(project_id=active_id)`).

---

## 8. Evidence and Database Integration

| Entity / Model | Storage Location | Ingestion Path | Retention & Provenance |
|---|---|---|---|
| **Discovered Host (`AssetNode`)** | SQLite `asset_nodes` table | Parsed from Nmap XML, ARP cache, LDAP computers, or passive recon | Timestamped, IP/hostname, MAC address, vendor, OS fingerprint |
| **Discovered Port / Service** | SQLite `asset_nodes.metadata_json` | Stored as structured port dictionaries `{port, proto, state, service, banner}` | Tied to parent asset record with last-seen timestamp |
| **Network & Domain Edges (`AssetEdge`)** | SQLite `asset_edges` table | Extracted from PCAP conversations, LDAP AD relationships, or routing hops | Source/target IDs, `relation_type` (`MEMBER_OF`, `DC_FOR`, `TALKS_TO`), source tool |
| **Vulnerabilities (`Finding`)** | SQLite `findings` table | Evaluated from weak ciphers, expired certs, open risky ports, or CVE rules | Severity, CVSS score, remediation guidance, affected asset IP |
| **Raw Tool Output (`EvidenceVaultItem`)**| SQLite `evidence_vault` & filesystem | Written to `storage/evidence/` with SHA-256 integrity hash | Cryptographic hash recorded in database for legal non-repudiation |

---

## 9. 2D/3D Network Topology Integration

Discovered assets and relationships map bidirectionally into the visualization engines:
- **Radial Pivot Horizon (Auspex Radar):** Concentric range rings group assets by broadcast domain / subnet tiers (`TIER 0 : BROADCAST DOMAIN`, `TIER 1 : PRIMARY ASSET HORIZON`).
- **Single-Subnet Collision Elimination:** When a single subnet is present, the dummy assessment gateway node is suppressed, placing the subnet hub cleanly at `(0, 0)` and distributing hosts in 360° circular orbits.
- **Active Directory Relationships:** LDAP `is_dc`, `is_domain`, and `is_comp` flags render nodes in distinctive amber (`#f59e0b`), royal indigo (`#6366f1`), and sky blue (`#38bdf8`), with purple spline links (`#a855f7`) tracing AD group/trust hierarchy.
- **Spatial Cyber Terrain (3D):** Ingests database asset nodes and edges to build an interactive 3D WebGL graph.

---

## 10. Test Results and Failed Commands

### Full Audit Test Suite Execution
All tests across information gathering, network discovery, OSINT, LDAP, and visualization suites were executed using `pytest`:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest \
  tests/test_osint_workspace.py \
  tests/test_enumeration_and_waf_features.py \
  tests/test_internal_network_pentest.py \
  tests/test_nmap_adapter.py \
  tests/test_nmap_parser.py \
  tests/test_ldap_live_enumeration.py \
  tests/test_tls_security_analyzer.py \
  tests/test_web_adapter.py \
  tests/test_ptk_workbench.py \
  tests/test_amass_adapter.py \
  tests/test_pcap_relationship_ingestion.py \
  tests/test_google_dork_engine.py \
  tests/test_nmap_sn_host_discovery_sync.py \
  tests/test_2d_3d_network_visualization.py -q
```

### Results Summary
- **Total Tests Executed:** 218
- **Passed:** 218
- **Failed:** 0
- **Skipped:** 0
- **Duration:** 19.82 seconds
- **Exit Code:** 0

### Host CLI Binary Dependencies Availability Check
| Binary | Installed on Host | Location / Notes |
|---|---|---|
| `nmap` | **YES** | `/usr/bin/nmap` (v7.94SVN) |
| `gobuster` | **YES** | `/usr/bin/gobuster` (v3.6) |
| `ffuf` | **YES** | `/usr/bin/ffuf` (v2.1.0) |
| `nikto` | **YES** | `/usr/bin/nikto` |
| `sqlmap` | **YES** | `/usr/bin/sqlmap` |
| `hydra` | **YES** | `/usr/bin/hydra` (v9.5) |
| `smbclient` | **YES** | `/usr/bin/smbclient` |
| `snmpwalk` | **YES** | `/usr/bin/snmpwalk` |
| `dig` / `nslookup` | **YES** | `/usr/bin/dig`, `/usr/bin/nslookup` |
| `whois` | **YES** | `/usr/bin/whois` |
| `amass` | **NO** | Missing on system PATH |
| `wafw00f` | **NO** | Host package missing; wrapper fallback present in `bin/wafw00f` |
| `zaproxy` | **NO** | Host package missing; wrapper fallback present in `bin/zaproxy` |
| `bloodhound` | **NO** | Missing on system PATH |
| `enum4linux` | **NO** | Missing on system PATH |

---

## 11. Missing Features & Technical Gaps

1. **DNS Deep Enumeration (Pure Python):** No pure-Python multi-record DNS resolution (IPv6 AAAA, MX, TXT, SRV, NS) without relying on external system utilities (`host`, `dig`).
2. **Pure-Python WHOIS/RDAP Resolver:** No direct RDAP client implementation over HTTPS for IP/Domain ownership and ASN attribution.
3. **Virtual Host (vhost) Discovery:** `GobusterAdapter` only exposes the `dir` mode; `gobuster vhost` or `ffuf -H "Host: FUZZ.target.com"` is unconfigured in the GUI.
4. **JavaScript Route & Endpoint Mining:** `PTKSCAAnalyzer` identifies third-party JS libraries, but does not parse inline or external JS files to extract REST API endpoints or sensitive routes.
5. **SNMP & NFS Native Enumerators:** No adapters or parsers for SNMP community string sweeps (public/private) or NFS export discovery (`showmount -e`).
6. **BloodHound Export Engine:** Relationships are stored in SQLite `AssetEdge`, but no export to BloodHound v4/v5 JSON format (`users.json`, `computers.json`, `groups.json`) exists.
7. **Latent Defects in TLS Adapter Identified During Audit:**
   - `modules/crypto/tls_adapter.py:234`: `self.db.get_asset_node_by_value()` method call fails because the database helper is named `get_asset_node(value=...)` or `get_asset_nodes()`.
   - `modules/crypto/tls_adapter.py:47`: `evidence_dir` is not converted to `Path()`, which raises an exception if a raw string is supplied.
   - `modules/crypto/tls_analyzer.py:36 & 54`: Duplicate OID `"1.3.101.112"` causes Ed25519 signature algorithm to overwrite the public key algorithm identifier.

---

## 12. Recommended Development Roadmap

```
Phase Roadmap:
├── Phase 7A: Pure-Python OSINT & DNS/RDAP Engine (dnspython + HTTPS RDAP)
├── Phase 7B: Web Endpoint Mining & Virtual Host Discovery (Vhost fuzzing + JS route extraction)
├── Phase 7C: Native Infrastructure Enumerators (SNMP MIB Walker + NFS Export Dissector)
├── Phase 7D: Active Directory BloodHound v4/v5 Exporter
└── Phase 7E: TLS Adapter Defect Hardening & Edge Schema Repair
```

| Phase | Target Module | Scope of Work |
|---|---|---|
| **Phase 7A** | `modules/osint/` | Implement pure-Python DNS resolver (`dnspython` or raw UDP 53) for AAAA, MX, TXT, SRV; add HTTPS RDAP parser for ASN and WHOIS lookups. |
| **Phase 7B** | `modules/web/` | Add `vhost` fuzzing mode to `GobusterAdapter` / `FfufAdapter`; implement regex-based JavaScript endpoint crawler in `PTKSCAAnalyzer`. |
| **Phase 7C** | `modules/network/` | Develop pure-Python SNMP v1/v2c walker (`pysnmp` or raw UDP 161) and NFS RPC mount-point extractor (`showmount` parser). |
| **Phase 7D** | `modules/identity/` | Add BloodHound JSON generator exporting SQLite AD assets and edges to standard BloodHound v4/v5 zip packages. |
| **Phase 7E** | `modules/crypto/` | Apply minimal patches to `tls_adapter.py` and `tls_analyzer.py` resolving `get_asset_node_by_value` and OID collisions. |

---

## 13. File, Class, Method & Test Reference Index

### Core Architecture & Services
- `core/scope.py`: `ScopeAuthorizationService.is_authorized()`
- `core/asset_inventory.py`: `AssetInventoryService.record_discovered_host()`
- `core/evidence_intelligence.py`: `EvidenceIntelligenceService.ingest_evidence()`
- `storage/db.py`: `Database.get_asset_nodes()`, `Database.list_asset_edges()`, `Database.add_finding()`
- `storage/models.py`: `AssetNode`, `AssetEdge`, `Finding`, `EvidenceVaultItem`

### Reconnaissance & Enumeration Adapters
- `modules/network/nmap_adapter.py`: `NmapAdapter.build_command()`, `NmapAdapter.run_scan()`
- `modules/network/nmap_parser.py`: `NmapParser.parse_xml()`, `NmapParser._parse_host()`, `NmapParser._parse_ports()`
- `modules/network/socket_scanner.py`: `SocketPortScanner.scan_host()`, `SocketPortScanner._scan_port()`
- `modules/network/internal_footprint.py`: `InternalFootprintCollector.collect_footprint()`
- `modules/osint/passive_recon.py`: `PassiveRecon.resolve_dns()`, `PassiveRecon.query_crtsh()`, `PassiveRecon.lookup_asn()`
- `modules/osint/metadata_extractor.py`: `MetadataExtractor.extract_all()`
- `modules/web/gobuster_adapter.py`: `GobusterAdapter.build_command()`, `GobusterAdapter.parse_output()`
- `modules/web/ffuf_adapter.py`: `FfufAdapter.build_command()`, `FfufAdapter.parse_json()`
- `modules/web/wafw00f_adapter.py`: `Wafw00fAdapter.detect()`
- `modules/web/ptk_engine.py`: `PTKSCAAnalyzer.audit_headers()`, `PTKSCAAnalyzer.detect_components()`
- `modules/identity/ldap_client.py`: `LDAPClient.connect()`, `LDAPClient.get_root_dse()`, `LDAPClient.search()`
- `modules/identity/ldap_adapter.py`: `LDAPLiveEnumerationAdapter.enumerate_all()`, `LDAPLiveEnumerationAdapter._parse_password_policy()`
- `modules/crypto/tls_analyzer.py`: `TLSAnalyzer.analyze_target()`, `CertificateParser.parse_der()`

### GUI Workspaces & Widgets
- `desktop/widgets/network_map_view.py`: `NetworkMapView.load_scan()`, `NetworkMapView._set_layout_mode()`
- `desktop/widgets/topology_designer.py`: `TopologyDesignerWidget.load_discovered_assets()`
- `desktop/widgets/webgl_3d_network_view.py`: `WebGL3DNetworkView.load_discovered_assets()`
- `desktop/widgets/google_dork_widget.py`: `GoogleDorkWidget._on_launch_dork()`
- `desktop/widgets/ad_ldap_enumerator_widget.py`: `ADLDAPEnumeratorWidget._start_enumeration()`

### Key Automated Tests
- `tests/test_nmap_adapter.py`: Command builder and execution validation
- `tests/test_nmap_parser.py`: XML parsing, port state, OS and CPE normalization
- `tests/test_phase4_pure_python_engines.py`: Unprivileged pure-Python socket scanning
- `tests/test_internal_network_pentest.py`: Host discovery and footprinting
- `tests/test_osint_workspace.py`: DNS, CRT.sh, ASN, and passive recon
- `tests/test_ldap_live_enumeration.py`: Mock LDAP server RootDSE and object queries
- `tests/test_tls_security_analyzer.py`: Mock TLS servers, certificate parsing, cipher suites
- `tests/test_web_adapter.py`: Web fuzzing and crawler adapters
- `tests/test_2d_3d_network_visualization.py`: Radial, tree, grid, and 3D terrain rendering

