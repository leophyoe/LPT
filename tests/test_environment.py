import sys
import shutil
from pathlib import Path
import PySide6.QtCore


def test_python_version():
    """Verify runtime Python meets minimum requirement (>= 3.11)."""
    assert sys.version_info >= (3, 11)


def test_pyside6_availability():
    """Verify PySide6 / Qt6 is successfully installed and initialized."""
    version = PySide6.QtCore.__version__
    assert version is not None
    assert int(version.split(".")[0]) >= 6


def test_project_structure():
    """Verify that canonical workspace directories exist."""
    root = Path(__file__).resolve().parent.parent
    expected_dirs = [
        "core",
        "modules",
        "desktop",
        "terminal",
        "ai",
        "storage",
        "reports",
        "labs",
        "source",
        "docs",
        "licenses",
        "third_party",
        "tests",
        "scripts",
    ]
    for directory in expected_dirs:
        dir_path = root / directory
        assert dir_path.is_dir(), f"Expected directory {directory} does not exist"


def test_nmap_presence():
    """Verify host system has Nmap available for network discovery workflows."""
    nmap_path = shutil.which("nmap")
    assert nmap_path is not None, "nmap binary not found on system PATH"
