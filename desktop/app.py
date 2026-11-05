"""Application entrypoint for launching CyberSecuritySuite desktop interface."""

import os
import sys

# Ensure Chromium WebEngine runs reliably without sandbox restrictions in local Linux environment
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox --disable-gpu")

from pathlib import Path

# Prepend project bin/ and .venv/bin/ to PATH so all tools are available to GUI and terminal
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = PROJECT_ROOT / "bin"
VENV_BIN = PROJECT_ROOT / ".venv" / "bin"
current_path = os.environ.get("PATH", "")
os.environ["PATH"] = f"{BIN_DIR}:{VENV_BIN}:{current_path}"

# Fallback to VNC platform if no graphical display is present on Linux
if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    if not os.environ.get("QT_QPA_PLATFORM"):
        os.environ["QT_QPA_PLATFORM"] = "vnc"
        print("[*] No active display server detected. CyberSecuritySuite GUI started on VNC display (port 5900).")

from PySide6.QtWidgets import QApplication

from core.registry import ToolRegistry
from desktop.main_window import MainWindow
from storage.db import Database


def main():
    """Main execution function."""
    app = QApplication(sys.argv)
    app.setApplicationName("CyberSecuritySuite")
    app.setOrganizationName("CyberSecuritySuite")

    # Use the populated persistent database shared by the GUI and CLI.
    db_path = Path(__file__).resolve().parent.parent / "storage" / "data" / "cybersecuritysuite.db"
    db = Database(db_path)
    registry = ToolRegistry()

    window = MainWindow(db=db, registry=registry)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
