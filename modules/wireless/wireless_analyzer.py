"""Wireless 802.11 and EAPOL 4-Way Handshake Analysis Engine.

Performs offline PCAP analysis of 802.11 wireless network captures:
1. Dissects Beacon, Probe Request, Probe Response, and Deauth frames.
2. Catalogs BSSID, ESSID, Channel, Encryption (Open, WEP, WPA-PSK, WPA2-Enterprise, WPA3-SAE).
3. Detects and reconstructs complete WPA/WPA2 EAPOL 4-Way Handshakes (M1, M2, M3, M4).
4. Detects Rogue AP / Evil Twin and Deauthentication flood anomalies.
5. Exports crackable handshakes to Hashcat mode 22000 format.
6. Enforces Scope Authorization Guard and creates cryptographically hashed Evidence records.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from core.activity_logger import ActivityLogger
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    ValidationStatus,
)


def _mac_to_str(raw: bytes) -> str:
    """Formats 6-byte raw MAC into lowercase colon-separated string."""
    if len(raw) < 6:
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in raw[:6])


@dataclass
class AccessPointInfo:
    """Represents an identified 802.11 Wireless Access Point."""

    bssid: str
    essid: str
    channel: int = 0
    encryption: str = "OPEN"
    cipher: str = "NONE"
    auth_suites: List[str] = field(default_factory=list)
    wps_enabled: bool = False
    beacon_count: int = 0
    clients: Set[str] = field(default_factory=set)
    has_handshake: bool = False
    handshake_status: str = "None"
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class EAPOLHandshake:
    """Tracks EAPOL 4-Way Handshake messages between an AP and Station."""

    bssid: str
    client_mac: str
    essid: str = ""
    m1_anonce: Optional[bytes] = None
    m2_snonce: Optional[bytes] = None
    m2_mic: Optional[bytes] = None
    m2_eapol_frame: Optional[bytes] = None
    m3_seen: bool = False
    m4_seen: bool = False
    is_complete: bool = False
    is_crackable: bool = False
    hashcat_22000: Optional[str] = None


@dataclass
class WirelessAnomaly:
    """Represents a detected wireless anomaly or attack signature."""

    anomaly_type: str  # "EVIL_TWIN", "DEAUTH_FLOOD", "INSECURE_OPEN_NET", "WEP_DEPRECATED"
    severity: FindingSeverity
    title: str
    description: str
    bssid: str
    essid: str
    remediation: str


@dataclass
class WirelessAnalysisResult:
    """Consolidated results from offline wireless PCAP dissection."""

    source_file: str
    total_packets: int
    dot11_packets: int
    access_points: Dict[str, AccessPointInfo] = field(default_factory=dict)
    handshakes: List[EAPOLHandshake] = field(default_factory=list)
    anomalies: List[WirelessAnomaly] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence_id: Optional[int] = None
    evidence_hash: str = ""
    is_authorized: bool = True
    scope_reason: str = "Authorized"


class PurePythonPCAPReader:
    """Standard library PCAP file reader supporting standard, byte-swapped, and nanosecond PCAPs."""

    DLT_EN10MB = 1
    DLT_IEEE802_11 = 105
    DLT_IEEE802_11_RADIO = 127

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.endianness = "<"
        self.is_nanosecond = False
        self.link_type = self.DLT_IEEE802_11_RADIO

    def __iter__(self):
        with open(self.file_path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return

            magic = header[0:4]
            if magic == b"\xa1\xb2\xc3\xd4":
                self.endianness = ">"
            elif magic == b"\xd4\xc3\xb2\xa1":
                self.endianness = "<"
            elif magic == b"\xa1\xb2\x3c\x4d":
                self.endianness = ">"
                self.is_nanosecond = True
            elif magic == b"\x4d\x3c\xb2\xa1":
                self.endianness = "<"
                self.is_nanosecond = True
            else:
                # Unsupported format or pcapng
                return

            (
                _v_maj,
                _v_min,
                _thiszone,
                _sigfigs,
                _snaplen,
                link_type,
            ) = struct.unpack(f"{self.endianness}HHIIII", header[4:24])
            self.link_type = link_type

            # Stream packets
            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                    f"{self.endianness}IIII", rec_hdr
                )
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break

                ts = float(ts_sec) + (float(ts_usec) / (1e9 if self.is_nanosecond else 1e6))
                yield ts, self.link_type, packet_data


class WirelessAnalyzer:
    """Deep inspection engine for 802.11 wireless network frames and handshakes."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def parse_pcap(
        self,
        pcap_path: Path,
        project_id: Optional[int] = None,
        assessment_id: Optional[int] = None,
        evidence_dir: Optional[Path] = None,
    ) -> WirelessAnalysisResult:
        """Parses an offline 802.11 capture file, reconstructing APs, clients, handshakes, and anomalies."""
        pcap_path = Path(pcap_path)
        if not pcap_path.exists() or not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        raw_bytes = pcap_path.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        reader = PurePythonPCAPReader(pcap_path)
        total_packets = 0
        dot11_packets = 0

        aps: Dict[str, AccessPointInfo] = {}
        # Track handshakes by (BSSID, Client MAC)
        handshake_map: Dict[Tuple[str, str], EAPOLHandshake] = {}
        deauth_events: List[Tuple[float, str, str]] = []  # (ts, bssid, client)

        for ts, link_type, pkt in reader:
            total_packets += 1
            dot11_raw = self._extract_80211_frame(link_type, pkt)
            if not dot11_raw or len(dot11_raw) < 24:
                continue

            dot11_packets += 1
            fc = struct.unpack("<H", dot11_raw[0:2])[0]
            type_val = (fc >> 2) & 0x03
            subtype = (fc >> 4) & 0x0F

            if type_val == 0:  # Management Frame
                self._handle_management_frame(
                    subtype, dot11_raw, ts, aps, deauth_events
                )
            elif type_val == 2:  # Data Frame (Check for EAPOL)
                self._handle_data_frame(dot11_raw, aps, handshake_map)

        # Evaluate EAPOL Handshakes and build export strings
        handshakes: List[EAPOLHandshake] = []
        for (bssid, client_mac), hs in handshake_map.items():
            if bssid in aps:
                hs.essid = aps[bssid].essid
            if hs.m1_anonce and hs.m2_snonce and hs.m2_mic:
                hs.is_crackable = True
                if hs.m3_seen or hs.m4_seen:
                    hs.is_complete = True
                hs.hashcat_22000 = self._generate_hashcat_22000(hs)
                if bssid in aps:
                    aps[bssid].has_handshake = True
                    aps[bssid].handshake_status = (
                        "Full (M1-M4)" if hs.is_complete else "Valid Half (M1+M2)"
                    )
            handshakes.append(hs)

        # Anomaly Detection (Evil Twin, Deauth Floods, Insecure Open/WEP)
        anomalies = self._detect_anomalies(aps, deauth_events)

        # Build Normalized Findings
        findings: List[Finding] = []
        if project_id:
            findings = self._generate_findings(
                project_id=project_id,
                aps=aps,
                handshakes=handshakes,
                anomalies=anomalies,
                assessment_id=assessment_id,
            )

        # Scope Authorization Verification
        is_authorized = True
        scope_reason = "All discovered targets in authorized scope"
        authorized_findings: List[Finding] = []

        if project_id and self.db:
            scopes = self.db.list_scopes(project_id)
            project = self.db.get_project(project_id)
            if scopes:
                for f in findings:
                    in_scope = False
                    clean_asset = f.affected_asset.strip().lower()
                    for s in scopes:
                        clean_s = s.target.strip().lower()
                        # Direct match on BSSID MAC or without colons/dashes
                        if clean_s in (clean_asset, clean_asset.replace(":", ""), clean_asset.replace("-", "")):
                            in_scope = True
                            break
                        # Check match against AP ESSID
                        if f.affected_asset in aps and clean_s == aps[f.affected_asset].essid.lower():
                            in_scope = True
                            break

                    if not in_scope:
                        chk = ScopeAuthorizationService.is_target_authorized(
                            f.affected_asset, scopes, project=project
                        )
                        in_scope = chk.is_allowed

                    if in_scope:
                        authorized_findings.append(f)
                    else:
                        is_authorized = False
                        scope_reason = f"Target {f.affected_asset} outside authorized project scope"

        # Evidence Vault Registration
        evidence_entry = None
        if project_id and self.db:
            dest_file = pcap_path
            if evidence_dir:
                evidence_dir.mkdir(parents=True, exist_ok=True)
                dest_file = evidence_dir / f"wireless_{project_id}_{pcap_path.name}"
                if dest_file != pcap_path:
                    dest_file.write_bytes(raw_bytes)

            evidence_entry = self.db.add_evidence(
                Evidence(
                    project_id=project_id,
                    file_path=str(dest_file),
                    sha256_hash=sha256,
                    description=f"Wireless 802.11 network capture: {pcap_path.name} ({len(aps)} APs, {len(handshakes)} handshakes)",
                    mime_type="application/vnd.tcpdump.pcap",
                    assessment_id=assessment_id,
                )
            )

            for f in authorized_findings:
                self.db.upsert_finding_deduplicated(f)

            ActivityLogger(self.db).log(
                project_id=project_id,
                action="wireless_pcap_analyzed",
                outcome="completed",
                details={
                    "source_file": pcap_path.name,
                    "access_points": len(aps),
                    "handshakes": len([h for h in handshakes if h.is_crackable]),
                    "anomalies": len(anomalies),
                    "sha256": sha256,
                },
            )

        return WirelessAnalysisResult(
            source_file=str(pcap_path),
            total_packets=total_packets,
            dot11_packets=dot11_packets,
            access_points=aps,
            handshakes=handshakes,
            anomalies=anomalies,
            findings=authorized_findings if (project_id and self.db) else findings,
            evidence_id=evidence_entry.id if evidence_entry else None,
            evidence_hash=sha256,
            is_authorized=is_authorized,
            scope_reason=scope_reason,
        )

    def _extract_80211_frame(self, link_type: int, raw_packet: bytes) -> Optional[bytes]:
        """Strips Link-Layer encapsulation (e.g. Radiotap header) to get the raw 802.11 frame."""
        if link_type == PurePythonPCAPReader.DLT_IEEE802_11:
            return raw_packet
        elif link_type == PurePythonPCAPReader.DLT_IEEE802_11_RADIO:
            if len(raw_packet) < 4:
                return None
            rad_len = struct.unpack("<H", raw_packet[2:4])[0]
            if len(raw_packet) > rad_len:
                return raw_packet[rad_len:]
        return None

    def _handle_management_frame(
        self,
        subtype: int,
        raw: bytes,
        ts: float,
        aps: Dict[str, AccessPointInfo],
        deauth_events: List[Tuple[float, str, str]],
    ):
        """Processes 802.11 Management frames (Beacons, Probe Responses, Deauthentications)."""
        addr1 = _mac_to_str(raw[4:10])
        addr2 = _mac_to_str(raw[10:16])
        addr3 = _mac_to_str(raw[16:22])

        # Subtype 8: Beacon, Subtype 5: Probe Response
        if subtype in (8, 5):
            bssid = addr3 if addr3 != "00:00:00:00:00:00" else addr2
            if len(raw) < 36:
                return

            cap_info = struct.unpack("<H", raw[34:36])[0]
            is_privacy = bool(cap_info & 0x0010)

            if bssid not in aps:
                aps[bssid] = AccessPointInfo(
                    bssid=bssid,
                    essid="<Hidden>",
                    encryption="WEP" if is_privacy else "OPEN",
                    first_seen=ts,
                    last_seen=ts,
                )

            ap = aps[bssid]
            ap.beacon_count += 1
            ap.last_seen = max(ap.last_seen, ts)

            # Parse Information Elements (IEs) starting at byte 36
            self._parse_information_elements(raw[36:], ap, is_privacy)

        # Subtype 12: Deauthentication, Subtype 10: Disassociation
        elif subtype in (12, 10):
            bssid = addr3 if addr3 != "00:00:00:00:00:00" else addr2
            client = addr1
            deauth_events.append((ts, bssid, client))
            if bssid in aps and client != "ff:ff:ff:ff:ff:ff":
                aps[bssid].clients.add(client)

    def _parse_information_elements(
        self, ies_raw: bytes, ap: AccessPointInfo, is_privacy: bool
    ):
        """Dissects 802.11 IEs for SSID, Channel, RSN (WPA2/WPA3), and Vendor WPA1/WPS."""
        offset = 0
        length = len(ies_raw)
        has_rsn = False
        has_wpa1 = False

        while offset + 2 <= length:
            tag_num = ies_raw[offset]
            tag_len = ies_raw[offset + 1]
            tag_data = ies_raw[offset + 2 : offset + 2 + tag_len]
            offset += 2 + tag_len

            if tag_num == 0:  # SSID
                if tag_data and tag_len > 0:
                    try:
                        ssid_str = tag_data.decode("utf-8")
                    except UnicodeDecodeError:
                        ssid_str = tag_data.decode("latin1", errors="replace")
                    if ssid_str.strip("\x00"):
                        ap.essid = ssid_str

            elif tag_num == 3:  # DS Parameter Set (Channel)
                if tag_len >= 1:
                    ap.channel = tag_data[0]

            elif tag_num == 48:  # RSN Information (WPA2 / WPA3)
                has_rsn = True
                ap.encryption = "WPA2"
                # Check for SAE (WPA3) or CCMP/GCMP
                if b"\x00\x0f\xac\x08" in tag_data:
                    ap.encryption = "WPA3-SAE"
                if b"\x00\x0f\xac\x04" in tag_data:
                    ap.cipher = "CCMP (AES)"
                elif b"\x00\x0f\xac\x02" in tag_data:
                    ap.cipher = "TKIP"
                if b"\x00\x0f\xac\x01" in tag_data:
                    ap.auth_suites.append("802.1X Enterprise")
                if b"\x00\x0f\xac\x02" in tag_data:
                    ap.auth_suites.append("PSK")

            elif tag_num == 221:  # Vendor Specific (WPA1 / WPS)
                if tag_data.startswith(b"\x00\x50\xf2\x01"):  # WPA1 OUI
                    has_wpa1 = True
                    if ap.encryption not in ("WPA2", "WPA3-SAE"):
                        ap.encryption = "WPA"
                        ap.cipher = "TKIP"
                if tag_data.startswith(b"\x00\x50\xf2\x04"):  # WPS OUI
                    ap.wps_enabled = True

        if not is_privacy:
            ap.encryption = "OPEN"
            ap.cipher = "NONE"
        elif not has_rsn and not has_wpa1 and is_privacy:
            ap.encryption = "WEP"
            ap.cipher = "RC4-40/104"

    def _handle_data_frame(
        self,
        raw: bytes,
        aps: Dict[str, AccessPointInfo],
        handshake_map: Dict[Tuple[str, str], EAPOLHandshake],
    ):
        """Detects 802.1X / EAPOL Key Exchange packets in Data frames."""
        fc = struct.unpack("<H", raw[0:2])[0]
        to_ds = (fc >> 8) & 0x01
        from_ds = (fc >> 9) & 0x01

        # Determine BSSID and Client MAC based on DS bits
        if to_ds == 1 and from_ds == 0:
            bssid = _mac_to_str(raw[4:10])
            client_mac = _mac_to_str(raw[10:16])
        elif to_ds == 0 and from_ds == 1:
            client_mac = _mac_to_str(raw[4:10])
            bssid = _mac_to_str(raw[10:16])
        else:
            bssid = _mac_to_str(raw[16:22])
            client_mac = _mac_to_str(raw[4:10])

        if bssid in aps and client_mac != "ff:ff:ff:ff:ff:ff":
            aps[bssid].clients.add(client_mac)

        # Search for EAPOL EtherType 0x888E in frame payload
        eapol_idx = raw.find(b"\x88\x8e")
        if eapol_idx == -1 or len(raw) < eapol_idx + 6:
            return

        eapol_packet = raw[eapol_idx + 2 :]
        if len(eapol_packet) < 4:
            return

        _version, packet_type, _length = struct.unpack("!BBH", eapol_packet[0:4])
        # Packet Type 3 = EAPOL-Key
        if packet_type != 3 or len(eapol_packet) < 99:
            return

        key_desc_type = eapol_packet[4]
        key_info = struct.unpack("!H", eapol_packet[5:7])[0]

        key_mic = bool(key_info & 0x0100)
        secure = bool(key_info & 0x0200)
        key_ack = bool(key_info & 0x0080)
        install = bool(key_info & 0x0040)
        key_type = bool(key_info & 0x0008)  # 1 = Pairwise, 0 = Group

        if not key_type:  # We focus on 4-way Pairwise handshake
            return

        key = (bssid, client_mac)
        if key not in handshake_map:
            handshake_map[key] = EAPOLHandshake(bssid=bssid, client_mac=client_mac)

        hs = handshake_map[key]

        # Nonce is 32 bytes at offset 17..49 in EAPOL-Key body (eapol_packet[17:49])
        nonce = eapol_packet[17:49]
        # MIC is 16 bytes at offset 81..97 in EAPOL-Key body (eapol_packet[81:97])
        mic = eapol_packet[81:97]

        # Message 1: AP -> STA (KeyAck=1, KeyMIC=0, Install=0, Secure=0)
        if key_ack and not key_mic and not install and not secure:
            hs.m1_anonce = nonce

        # Message 2: STA -> AP (KeyAck=0, KeyMIC=1, Install=0, Secure=0)
        elif not key_ack and key_mic and not install and not secure:
            hs.m2_snonce = nonce
            hs.m2_mic = mic
            hs.m2_eapol_frame = eapol_packet

        # Message 3: AP -> STA (KeyAck=1, KeyMIC=1, Install=1, Secure=1)
        elif key_ack and key_mic and install and secure:
            hs.m3_seen = True

        # Message 4: STA -> AP (KeyAck=0, KeyMIC=1, Install=0, Secure=1)
        elif not key_ack and key_mic and not install and secure:
            hs.m4_seen = True

    def _generate_hashcat_22000(self, hs: EAPOLHandshake) -> str:
        """Constructs a standard Hashcat format 22000 (WPA-PBKDF2-PMKID+EAPOL) hash line."""
        if not hs.m2_mic or not hs.m1_anonce or not hs.m2_eapol_frame:
            return ""

        # Format: WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL_CLEARED_MIC*00
        mic_hex = binascii.hexlify(hs.m2_mic).decode("ascii")
        mac_ap = hs.bssid.replace(":", "").lower()
        mac_cli = hs.client_mac.replace(":", "").lower()
        essid_hex = binascii.hexlify(hs.essid.encode("utf-8")).decode("ascii")
        anonce_hex = binascii.hexlify(hs.m1_anonce).decode("ascii")

        # Zero out MIC in EAPOL frame for hashcat verification
        eapol_frame_cleared = bytearray(hs.m2_eapol_frame)
        if len(eapol_frame_cleared) >= 97:
            eapol_frame_cleared[81:97] = b"\x00" * 16
        eapol_hex = binascii.hexlify(eapol_frame_cleared).decode("ascii")

        return f"WPA*02*{mic_hex}*{mac_ap}*{mac_cli}*{essid_hex}*{anonce_hex}*{eapol_hex}*00"

    def _detect_anomalies(
        self,
        aps: Dict[str, AccessPointInfo],
        deauth_events: List[Tuple[float, str, str]],
    ) -> List[WirelessAnomaly]:
        """Detects wireless security weaknesses and active attack indicators."""
        anomalies: List[WirelessAnomaly] = []

        # 1. Evil Twin Detection (Identical ESSID advertised by multiple distinct BSSIDs)
        essid_to_bssids: Dict[str, List[AccessPointInfo]] = {}
        for ap in aps.values():
            if ap.essid and ap.essid != "<Hidden>":
                essid_to_bssids.setdefault(ap.essid, []).append(ap)

        for essid, ap_list in essid_to_bssids.items():
            if len(ap_list) > 1:
                # Check for mismatched security configurations
                encryptions = {ap.encryption for ap in ap_list}
                if len(encryptions) > 1:
                    bssid_str = ", ".join(f"{a.bssid} ({a.encryption})" for a in ap_list)
                    anomalies.append(
                        WirelessAnomaly(
                            anomaly_type="EVIL_TWIN",
                            severity=FindingSeverity.HIGH,
                            title=f"Potential Evil Twin / Rogue AP for ESSID '{essid}'",
                            description=(
                                f"Multiple Access Points advertise identical network name '{essid}' "
                                f"with conflicting encryption types: {bssid_str}. "
                                "This pattern indicates an active rogue access point or honeypot."
                            ),
                            bssid=ap_list[0].bssid,
                            essid=essid,
                            remediation="Inspect physical AP inventory and enforce 802.1X mutual authentication (WPA2/WPA3 Enterprise).",
                        )
                    )

        # 2. Deauthentication Flood Attack Detection (> 15 deauth frames observed)
        if len(deauth_events) >= 15:
            # Group by BSSID
            bssid_deauths: Dict[str, int] = {}
            for _ts, bssid, _client in deauth_events:
                bssid_deauths[bssid] = bssid_deauths.get(bssid, 0) + 1

            for bssid, count in bssid_deauths.items():
                if count >= 15:
                    essid = aps.get(bssid, AccessPointInfo(bssid=bssid, essid="Unknown")).essid
                    anomalies.append(
                        WirelessAnomaly(
                            anomaly_type="DEAUTH_FLOOD",
                            severity=FindingSeverity.MEDIUM,
                            title=f"802.11 Deauthentication Flood against {essid} ({bssid})",
                            description=(
                                f"Recorded {count} 802.11 Deauthentication/Disassociation frames targeting {bssid}. "
                                "This is typical of WPA handshake forcing or Wi-Fi Denial of Service attacks."
                            ),
                            bssid=bssid,
                            essid=essid,
                            remediation="Deploy 802.11w Protected Management Frames (PMF) to cryptographically sign management packets.",
                        )
                    )

        # 3. Insecure Open Networks & Legacy WEP
        for ap in aps.values():
            if ap.encryption == "OPEN":
                anomalies.append(
                    WirelessAnomaly(
                        anomaly_type="INSECURE_OPEN_NET",
                        severity=FindingSeverity.MEDIUM,
                        title=f"Unencrypted Wireless Network: '{ap.essid}' ({ap.bssid})",
                        description=f"Access Point {ap.bssid} advertises ESSID '{ap.essid}' with no layer-2 encryption.",
                        bssid=ap.bssid,
                        essid=ap.essid,
                        remediation="Enable WPA3-Personal or WPA2-Enterprise with AES-CCMP encryption.",
                    )
                )
            elif ap.encryption == "WEP":
                anomalies.append(
                    WirelessAnomaly(
                        anomaly_type="WEP_DEPRECATED",
                        severity=FindingSeverity.HIGH,
                        title=f"Obsolete WEP Encryption in Use: '{ap.essid}' ({ap.bssid})",
                        description=f"Access Point {ap.bssid} uses WEP (RC4), trivially broken via FMS/KoreK IV attacks.",
                        bssid=ap.bssid,
                        essid=ap.essid,
                        remediation="Immediately upgrade router firmware and migrate to WPA2-AES or WPA3.",
                    )
                )

        return anomalies

    def _generate_findings(
        self,
        project_id: int,
        aps: Dict[str, AccessPointInfo],
        handshakes: List[EAPOLHandshake],
        anomalies: List[WirelessAnomaly],
        assessment_id: Optional[int] = None,
    ) -> List[Finding]:
        """Maps wireless discoveries, crackable handshakes, and anomalies to normalized Finding objects."""
        findings: List[Finding] = []

        # 1. Crackable Handshake Findings
        for hs in handshakes:
            if hs.is_crackable:
                status_desc = "full 4-way" if hs.is_complete else "valid half (M1+M2)"
                findings.append(
                    Finding(
                        project_id=project_id,
                        title=f"WPA/WPA2 EAPOL Handshake Captured for '{hs.essid}' ({hs.bssid})",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        affected_asset=hs.bssid,
                        affected_port_service="802.11/wlan",
                        description=(
                            f"Captured a {status_desc} WPA/WPA2 4-Way handshake between AP {hs.bssid} "
                            f"and client {hs.client_mac} for network '{hs.essid}'. "
                            "This handshake can be subjected to offline pre-computed dictionary attacks."
                        ),
                        reproduction_steps=(
                            f"Captured offline in PCAP.\n"
                            f"BSSID: {hs.bssid}\n"
                            f"Client: {hs.client_mac}\n"
                            f"Hashcat Mode 22000 Hash:\n{hs.hashcat_22000 or 'N/A'}"
                        ),
                        remediation="Enforce complex, randomized WPA2 Pre-Shared Keys (>20 characters) or migrate to WPA3-SAE / WPA2-Enterprise.",
                        validation_status=ValidationStatus.CONFIRMED,
                        source_tool="wireless_analyzer",
                        assessment_id=assessment_id,
                    )
                )

        # 2. Anomaly Findings
        for anom in anomalies:
            findings.append(
                Finding(
                    project_id=project_id,
                    title=anom.title,
                    severity=anom.severity,
                    affected_asset=anom.bssid,
                    affected_port_service="802.11/wlan",
                    description=anom.description,
                    reproduction_steps=f"Observed during passive 802.11 wireless analysis for BSSID {anom.bssid}.",
                    remediation=anom.remediation,
                    validation_status=ValidationStatus.OBSERVED,
                    source_tool="wireless_analyzer",
                    assessment_id=assessment_id,
                )
            )

        return findings
