"""Root pytest configuration and production database isolation guard.

Strictly prevents automated tests from modifying or silently connecting
to the production SQLite database (`storage/data/cybersecuritysuite.db`).
"""

import hashlib
import os
from pathlib import Path
import sqlite3
import pytest

# Explicitly mark test environment
os.environ["CYBERSECURITYSUITE_ENV"] = "test"
os.environ["QT_QPA_PLATFORM"] = "offscreen"

PRODUCTION_DB_PATH = Path(__file__).resolve().parent.parent / "storage" / "data" / "cybersecuritysuite.db"


def _get_db_hash(path: Path) -> str:
    """Calculates SHA-256 hash of a database file if it exists."""
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _get_db_census(path: Path) -> dict[str, int]:
    """Retrieves exact record counts from all critical tables."""
    if not path.is_file():
        return {}
    conn = sqlite3.connect(str(path))
    cur = conn.cursor()
    tables = [
        "projects",
        "target_scopes",
        "asset_nodes",
        "asset_edges",
        "findings",
        "evidence",
        "observations",
        "tool_executions",
        "engagement_audit_logs",
    ]
    census = {}
    for table in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table};")
            census[table] = cur.fetchone()[0]
        except sqlite3.OperationalError:
            census[table] = -1
    conn.close()
    return census


@pytest.fixture(scope="session", autouse=True)
def guard_production_database(request):
    """Session-level guard: records pre-test checksum and enforces zero-mutation boundary."""
    baseline_exists = PRODUCTION_DB_PATH.is_file()
    baseline_hash = _get_db_hash(PRODUCTION_DB_PATH) if baseline_exists else None
    baseline_size = PRODUCTION_DB_PATH.stat().st_size if baseline_exists else None
    baseline_census = _get_db_census(PRODUCTION_DB_PATH) if baseline_exists else {}

    # Install protective monkeypatch on Database constructor
    from storage.db import Database
    original_init = Database.__init__

    def guarded_init(self, db_path=":memory:"):
        resolved = Path(str(db_path)).resolve()
        prod_resolved = PRODUCTION_DB_PATH.resolve()
        # Allow read-only verification specifically if flagged or test file is test_phase2
        current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
        is_verification_test = "test_production_database" in current_test or "read_only" in current_test
        if resolved == prod_resolved and not is_verification_test:
            raise RuntimeError(
                f"AUTOMATED TEST SAFETY VIOLATION: Test '{current_test}' attempted to connect to "
                f"the production database at {db_path}! Automated tests must strictly use "
                f"isolated temporary databases (Database(':memory:') or Database(tmp_path / '...')). "
                f"Direct production database access is prohibited."
            )
        return original_init(self, db_path)

    Database.__init__ = guarded_init

    yield

    # Restore original init
    Database.__init__ = original_init

    # Post-session verification
    if baseline_exists:
        assert PRODUCTION_DB_PATH.is_file(), "Production database file was deleted during test session!"
        current_hash = _get_db_hash(PRODUCTION_DB_PATH)
        current_size = PRODUCTION_DB_PATH.stat().st_size
        current_census = _get_db_census(PRODUCTION_DB_PATH)

        assert current_hash == baseline_hash, (
            f"PRODUCTION DATABASE MUTATION DETECTED!\n"
            f"Pre-test SHA-256:  {baseline_hash}\n"
            f"Post-test SHA-256: {current_hash}\n"
            f"Pre-test size:     {baseline_size} bytes\n"
            f"Post-test size:    {current_size} bytes\n"
            f"Census diff:       pre={baseline_census} vs post={current_census}"
        )


_session_exit_code = 0


def pytest_sessionfinish(session, exitstatus):
    """Records exit code and closes Qt windows before report printing."""
    global _session_exit_code
    _session_exit_code = int(exitstatus)
    try:
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            app.closeAllWindows()
            app.processEvents()
    except Exception:
        pass


def pytest_unconfigure(config):
    """Ensures clean exit without Shiboken cyclic garbage collection segfault after terminal output."""
    global _session_exit_code
    try:
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            app.quit()
    except Exception:
        pass
    os._exit(_session_exit_code)


