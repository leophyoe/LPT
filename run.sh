#!/usr/bin/env bash
# CyberSecuritySuite Startup Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Prepend bin and virtual environment to PATH
export PATH="$SCRIPT_DIR/bin:$SCRIPT_DIR/.venv/bin:$PATH"

# Prefer the project environment so runtime dependencies stay consistent.
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_EXEC="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXEC="$(command -v python3)"
else
    printf 'Error: Python 3.11 or newer was not found. Create .venv or install Python 3.11+.\n' >&2
    exit 127
fi

if ! "$PYTHON_EXEC" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    printf 'Error: Python 3.11 or newer is required; selected interpreter: %s\n' "$PYTHON_EXEC" >&2
    exit 2
fi

exec "$PYTHON_EXEC" "$SCRIPT_DIR/main.py" "$@"
