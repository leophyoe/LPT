"""CyberSecuritySuite core module."""

import os
from pathlib import Path

# Ensure project bin/ and .venv/bin/ are on PATH
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_BIN_DIR = str(_PROJECT_ROOT / "bin")
_VENV_BIN = str(_PROJECT_ROOT / ".venv" / "bin")
_CURRENT_PATH = os.environ.get("PATH", "")

if _BIN_DIR not in _CURRENT_PATH.split(os.pathsep):
    os.environ["PATH"] = f"{_BIN_DIR}{os.pathsep}{_VENV_BIN}{os.pathsep}{_CURRENT_PATH}"

