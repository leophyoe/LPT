"""Script to capture updated post-redesign screenshots across Dark and Light modes for Phase 2.5."""
import os
import sys

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from pathlib import Path
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QApplication

from desktop.dialogs.ai_settings_dialog import AISettingsDialog
from desktop.dialogs.scanner_preview_dialog import ScannerResultPreviewDialog
from desktop.main_window import MainWindow
from desktop.theme import ThemeManager, ThemeMode
from modules.network.nmap_parser import HostResult, NmapScanResult, PortResult
from storage.db import Database
from storage.models import Finding, FindingSeverity, Project

OUTPUT_DIR = Path("docs/audit/screenshots/phase2_5_redesign")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = QApplication.instance() or QApplication(sys.argv)

db = Database(Path("/tmp/lpt_audit.db"))
projects = db.list_projects()
active_proj = projects[0] if projects else None

def capture_widget(widget, filename, size=QSize(1360, 840)):
    widget.resize(size)
    widget.show()
    app.processEvents()
    pixmap = widget.grab()
    dest = OUTPUT_DIR / filename
    pixmap.save(str(dest))
    print(f"Saved: {dest} ({pixmap.width()}x{pixmap.height()})")

window = MainWindow(db=db)
window.resize(1360, 840)
if active_proj:
    window._on_project_selected(active_proj)

views_to_capture = [
    ("dashboard", "01_dashboard"),
    ("projects", "02_engagements_scope"),
    ("assets", "03_digital_assets"),
    ("enum", "04_network_scan"),
    ("web", "05_web_testing"),
    ("reporting", "06_findings_reports"),
    ("tools", "07_tools_execution"),
    ("cpent_labs", "08_cpent_academy"),
]

for mode, mode_name in [(ThemeMode.DARK, "dark"), (ThemeMode.LIGHT, "light")]:
    print(f"\n--- Capturing Post-Redesign {mode_name.upper()} mode ---")
    ThemeManager.instance().set_theme_mode(mode)
    app.processEvents()

    for route_id, prefix in views_to_capture:
        window.sidebar_nav.route_requested.emit(route_id)
        app.processEvents()
        capture_widget(window, f"{prefix}_{mode_name}.png")

    # Terminal expanded view
    if not getattr(window, "_terminal_expanded", False):
        window._toggle_terminal_expanded()
    app.processEvents()
    capture_widget(window, f"09_terminal_expanded_{mode_name}.png")
    window._toggle_terminal_expanded()
    app.processEvents()

    # Capture Settings Dialog
    settings_dlg = AISettingsDialog(parent=window)
    capture_widget(settings_dlg, f"10_settings_dialog_{mode_name}.png", size=QSize(800, 600))
    settings_dlg.close()

    # Capture Nmap Review 5-Step Ingestion Wizard
    h1 = HostResult(
        ip="10.10.10.5",
        status="up",
        ports=[PortResult(port_id=80, protocol="tcp", state="open", service_name="http")],
    )
    h2 = HostResult(
        ip="10.10.10.25",
        status="up",
        ports=[PortResult(port_id=22, protocol="tcp", state="open", service_name="ssh")],
    )
    h3 = HostResult(
        ip="192.168.100.99",
        status="up",
        ports=[PortResult(port_id=445, protocol="tcp", state="open", service_name="smb")],
    )
    scan_res = NmapScanResult(
        command_args="nmap -sV -sC -T4 10.10.10.0/24",
        hosts=[h1, h2, h3],
    )
    f1 = Finding(
        project_id=active_proj.id if active_proj else 1,
        title="Apache 2.4.49 Path Traversal & RCE",
        severity=FindingSeverity.CRITICAL,
        affected_asset="10.10.10.5",
    )
    f2 = Finding(
        project_id=active_proj.id if active_proj else 1,
        title="OpenSSH Deprecated Key Exchange Algorithm",
        severity=FindingSeverity.LOW,
        affected_asset="10.10.10.25",
    )
    preview_dlg = ScannerResultPreviewDialog(
        tool_name="nmap",
        command="nmap -sV -sC -T4 10.10.10.0/24",
        scan_result=scan_res,
        findings=[f1, f2],
        raw_output="Nmap scan report for 10.10.10.5\nHost is up (0.002s latency).\nNmap done: 256 IP addresses (3 hosts up) scanned in 14.28 seconds",
        db=db,
        project=active_proj,
        parent=window,
    )

    # Capture all 5 wizard steps!
    step_names = [
        ("step1_summary", 0),
        ("step2_hosts", 1),
        ("step3_scope", 2),
        ("step4_findings", 3),
        ("step5_confirm", 4),
    ]
    for s_name, s_idx in step_names:
        preview_dlg.set_step(s_idx)
        app.processEvents()
        capture_widget(preview_dlg, f"11_nmap_wizard_{s_name}_{mode_name}.png", size=QSize(940, 700))

    preview_dlg.close()

print("\nAll post-redesign screenshots captured successfully.")

