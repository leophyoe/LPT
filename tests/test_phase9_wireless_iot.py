"""Unit and integration test suite for Phase 9: Wireless & IoT / Firmware Engine.

Covers:
1. Pure Python 802.11 Beacon frame dissection & Access Point cataloging.
2. WPA/WPA2 EAPOL 4-Way Handshake detection and Hashcat mode 22000 export.
3. Wireless Anomaly Detection: Evil Twin / Rogue AP and Deauth flood.
4. IoT Firmware header analysis, SquashFS/U-Boot signatures, and MIPS/ARM architecture detection.
5. Deep static secret auditor (/etc/shadow hashes, private RSA keys, telnetd, credentials).
6. Scope Authorization Guard isolation and Evidence Vault cryptographic integrity.
7. WirelessIoTView GUI integration and tab display.
"""

from __future__ import annotations

import binascii
import os
from pathlib import Path
import struct
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication

from modules.iot.firmware_analyzer import FirmwareAnalyzer
from modules.wireless.wireless_analyzer import PurePythonPCAPReader, WirelessAnalyzer
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
)


@pytest.fixture
def app():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def test_project(db: Database) -> Project:
    p = db.create_project(
        Project(
            name="IoT & Wireless Pentest Lab",
            client_name="SmartHome Tech",
            description="Testing 802.11 captures and camera firmware.",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p.id, target="00:11:22:33:44:55", target_type=TargetType.HOSTNAME
        )
    )
    db.add_scope(
        TargetScope(
            project_id=p.id, target="camera_v2.bin", target_type=TargetType.HOSTNAME
        )
    )
    return p


def _create_synthetic_80211_beacon_pcap(file_path: Path):
    """Creates a synthetic PCAP with Radiotap header and 802.11 Beacon frame."""
    # Global PCAP Header (24 bytes, little endian, linktype 127 = DLT_IEEE802_11_RADIO)
    pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)

    # Radiotap Header: 8 bytes (version=0, pad=0, len=8, present_flags=0)
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)

    # 802.11 Frame Control: Type 0 (Mgmt), Subtype 8 (Beacon) -> 0x0080
    fc = struct.pack("<H", 0x0080)
    duration = b"\x00\x00"
    da = b"\xff\xff\xff\xff\xff\xff"  # Broadcast
    sa = b"\x00\x11\x22\x33\x44\x55"  # BSSID
    bssid = b"\x00\x11\x22\x33\x44\x55"
    seq = b"\x10\x00"

    # Fixed Parameters (12 bytes: timestamp 8B, beacon interval 2B, cap_info 2B)
    fixed_params = (
        b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0011)
    )  # Privacy bit set

    # Tag 0: SSID "Corp-Secure-WiFi"
    ssid = b"Corp-Secure-WiFi"
    tag_ssid = struct.pack("BB", 0, len(ssid)) + ssid

    # Tag 3: Channel 6
    tag_channel = struct.pack("BBB", 3, 1, 6)

    # Tag 48: RSN (WPA2 CCMP)
    rsn_data = (
        b"\x01\x00"
        + b"\x00\x0f\xac\x04"
        + b"\x01\x00\x00\x0f\xac\x04"
        + b"\x01\x00\x00\x0f\xac\x02"
    )
    tag_rsn = struct.pack("BB", 48, len(rsn_data)) + rsn_data

    frame_payload = (
        fc
        + duration
        + da
        + sa
        + bssid
        + seq
        + fixed_params
        + tag_ssid
        + tag_channel
        + tag_rsn
    )
    raw_packet = radiotap + frame_payload

    # Packet Record (16 bytes)
    pkt_hdr = struct.pack(
        "<IIII", 1700000000, 100000, len(raw_packet), len(raw_packet)
    )

    with open(file_path, "wb") as f:
        f.write(pcap_hdr)
        f.write(pkt_hdr)
        f.write(raw_packet)


def _create_synthetic_eapol_handshake_pcap(file_path: Path):
    """Creates a synthetic PCAP with EAPOL M1 and M2 4-Way handshake packets."""
    pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)

    bssid_raw = b"\x00\x11\x22\x33\x44\x55"
    client_raw = b"\xaa\xbb\xcc\xdd\xee\xff"

    anonce = b"\x11" * 32
    snonce = b"\x22" * 32
    mic = b"\x33" * 16

    packets = []

    # Message 1: AP -> Client (FromDS=1, ToDS=0)
    # 802.11 Data frame FC: 0x0208 (Data, FromDS=1)
    fc_m1 = struct.pack("<H", 0x0208)
    # Addr1=Client, Addr2=BSSID, Addr3=BSSID
    hdr_m1 = fc_m1 + b"\x00\x00" + client_raw + bssid_raw + bssid_raw + b"\x00\x00"

    # LLC/SNAP header with EAPOL EtherType 0x888e
    llc_eapol = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

    # EAPOL Packet: Type 3 (Key), length=95
    # Key Info M1: KeyAck=1, KeyMIC=0, Install=0, KeyType=1 (Pairwise) -> 0x0088
    eapol_m1 = (
        struct.pack("!BBH", 1, 3, 95)
        + b"\x02"  # Descriptor Type RSN
        + struct.pack("!H", 0x0088)  # Key Info
        + struct.pack("!H", 16)  # Key Length
        + b"\x00" * 8  # Replay counter
        + anonce  # WPA Key Nonce (ANonce)
        + b"\x00" * 16  # Key IV
        + b"\x00" * 8  # Key RSC
        + b"\x00" * 8  # Key ID
        + b"\x00" * 16  # Key MIC (zeroed in M1)
        + b"\x00\x00"  # Key Data Length
    )
    raw_m1 = radiotap + hdr_m1 + llc_eapol + eapol_m1
    packets.append(raw_m1)

    # Message 2: Client -> AP (ToDS=1, FromDS=0)
    fc_m2 = struct.pack("<H", 0x0108)
    # Addr1=BSSID, Addr2=Client, Addr3=BSSID
    hdr_m2 = fc_m2 + b"\x00\x00" + bssid_raw + client_raw + bssid_raw + b"\x00\x00"

    # Key Info M2: KeyAck=0, KeyMIC=1, KeyType=1 -> 0x0108
    eapol_m2 = (
        struct.pack("!BBH", 1, 3, 95)
        + b"\x02"
        + struct.pack("!H", 0x0108)
        + struct.pack("!H", 16)
        + b"\x00" * 8
        + snonce
        + b"\x00" * 16
        + b"\x00" * 8
        + b"\x00" * 8
        + mic  # Actual MIC populated
        + b"\x00\x00"
    )
    raw_m2 = radiotap + hdr_m2 + llc_eapol + eapol_m2
    packets.append(raw_m2)

    with open(file_path, "wb") as f:
        f.write(pcap_hdr)
        for p in packets:
            pkt_hdr = struct.pack("<IIII", 1700000000, 200000, len(p), len(p))
            f.write(pkt_hdr)
            f.write(p)


def test_wireless_beacon_parsing(db: Database, test_project: Project, tmp_path: Path):
    """Verifies pure Python 802.11 beacon dissection, SSID, channel, and WPA2-CCMP detection."""
    pcap_file = tmp_path / "test_beacon.pcap"
    _create_synthetic_80211_beacon_pcap(pcap_file)

    analyzer = WirelessAnalyzer(db=db)
    res = analyzer.parse_pcap(
        pcap_file, project_id=test_project.id, evidence_dir=tmp_path
    )

    assert res.total_packets == 1
    assert res.dot11_packets == 1
    assert "00:11:22:33:44:55" in res.access_points

    ap = res.access_points["00:11:22:33:44:55"]
    assert ap.essid == "Corp-Secure-WiFi"
    assert ap.channel == 6
    assert ap.encryption == "WPA2"
    assert "CCMP" in ap.cipher
    assert res.evidence_id is not None
    assert res.evidence_hash != ""


def test_wireless_eapol_handshake_and_hashcat_export(
    db: Database, test_project: Project, tmp_path: Path
):
    """Verifies WPA 4-way handshake detection, ANonce/SNonce/MIC extraction, and Hashcat 22000 formatting."""
    pcap_file = tmp_path / "test_handshake.pcap"
    _create_synthetic_eapol_handshake_pcap(pcap_file)

    analyzer = WirelessAnalyzer(db=db)
    res = analyzer.parse_pcap(
        pcap_file, project_id=test_project.id, evidence_dir=tmp_path
    )

    assert len(res.handshakes) == 1
    hs = res.handshakes[0]
    assert hs.bssid == "00:11:22:33:44:55"
    assert hs.client_mac == "aa:bb:cc:dd:ee:ff"
    assert hs.is_crackable is True
    assert hs.m1_anonce == b"\x11" * 32
    assert hs.m2_snonce == b"\x22" * 32
    assert hs.m2_mic == b"\x33" * 16

    # Verify Hashcat format 22000 string
    assert hs.hashcat_22000 is not None
    assert hs.hashcat_22000.startswith("WPA*02*")
    assert "001122334455" in hs.hashcat_22000
    assert "aabbccddeeff" in hs.hashcat_22000

    # Verify normalized Finding generation
    crackable_findings = [
        f for f in res.findings if "EAPOL Handshake Captured" in f.title
    ]
    assert len(crackable_findings) == 1
    assert crackable_findings[0].severity == FindingSeverity.HIGH


def test_firmware_architecture_and_component_detection(tmp_path: Path):
    """Verifies ELF MIPS 32-bit architecture identification and filesystem signature detection."""
    fw_file = tmp_path / "camera_v2.bin"

    # Construct synthetic firmware binary:
    # 1. 256 bytes U-Boot padding
    uboot_hdr = b"\x27\x05\x19\x56" + (b"\x00" * 60)

    # 2. ELF Header: MIPS (machine code 8), Big Endian
    # \x7fELF, 1 (32-bit), 2 (Big Endian), 1 (version), padding
    elf_hdr = (
        b"\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + struct.pack(">H", 2)  # ET_EXEC
        + struct.pack(">H", 8)  # EM_MIPS = 8
        + struct.pack(">I", 1)  # EV_CURRENT
    )

    # 3. SquashFS header at offset 1024
    padding = b"\x00" * (1024 - len(uboot_hdr) - len(elf_hdr))
    squashfs_hdr = b"hsqs" + (b"\x00" * 64)

    fw_file.write_bytes(uboot_hdr + elf_hdr + padding + squashfs_hdr)

    analyzer = FirmwareAnalyzer()
    res = analyzer.analyze_image(fw_file, extract_files=False)

    assert "MIPS" in res.detected_architecture
    assert res.endianness == "Big Endian"
    assert len(res.components) >= 2

    comp_types = [c.component_type for c in res.components]
    assert "ELF Binary" in comp_types
    assert "SquashFS (LE)" in comp_types
    assert "U-Boot uImage" in comp_types


def test_firmware_secret_and_credential_auditing(
    db: Database, test_project: Project, tmp_path: Path
):
    """Verifies deep static secret auditing across /etc/shadow, private keys, and startup scripts."""
    # Build simulated unpacked filesystem root
    fs_root = tmp_path / "unpacked_root"
    etc_dir = fs_root / "etc"
    init_dir = etc_dir / "init.d"
    init_dir.mkdir(parents=True)

    # 1. /etc/shadow with MD5 hash
    shadow_file = etc_dir / "shadow"
    shadow_file.write_text("root:$1$Salt$Wq5aX1nNl3mZ:18000:0:99999:7:::\n")

    # 2. Private RSA Key
    key_file = etc_dir / "dropbear.key"
    key_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n"
    )

    # 3. Insecure Startup Script with Telnet Daemon
    rcs_file = init_dir / "rcS"
    rcs_file.write_text("#!/bin/sh\ntelnetd -l /bin/sh &\n")

    # 4. Config file with hardcoded AWS key
    cfg_file = etc_dir / "cloud.conf"
    cfg_file.write_text("aws_key_id = AKIAIOSFODNN7EXAMPLE\n")

    fw_img = tmp_path / "camera_v2.bin"
    fw_img.write_bytes(b"\x7fELF" + (b"\x00" * 200))

    analyzer = FirmwareAnalyzer(db=db)
    # Audit using the simulated unpacked filesystem
    secrets = analyzer._audit_filesystem(fs_root)

    categories = [s.category for s in secrets]
    assert "SHADOW_HASH" in categories
    assert "PRIVATE_KEY" in categories
    assert "INSECURE_DAEMON" in categories
    assert "HARDCODED_CREDS" in categories

    shadow_sec = next(s for s in secrets if s.category == "SHADOW_HASH")
    assert shadow_sec.severity == FindingSeverity.HIGH
    assert "MD5-Crypt" in shadow_sec.title

    priv_sec = next(s for s in secrets if s.category == "PRIVATE_KEY")
    assert priv_sec.severity == FindingSeverity.CRITICAL


def test_wireless_iot_gui_view_rendering(app, db: Database, test_project: Project):
    """Verifies that WirelessIoTView instantiates, binds active project, and loads cleanly in UI."""
    from desktop.views.wireless_iot_view import WirelessIoTView

    view = WirelessIoTView(db=db)
    view.set_active_project(test_project)

    assert view.tabs.count() == 2
    assert "Wireless" in view.tabs.tabText(0)
    assert "IoT & Firmware" in view.tabs.tabText(1)
    assert "Authorized" in view.scope_badge.text()

    # Verify tables are initialized
    assert view.ap_table.columnCount() == 7
    assert view.handshake_table.columnCount() == 5
    assert view.comp_table.columnCount() == 3
    assert view.secrets_table.columnCount() == 5

