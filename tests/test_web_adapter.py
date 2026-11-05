"""Unit and integration tests for WebSecurityAdapter (c0desec)."""

from unittest.mock import MagicMock
import pytest
import requests

from modules.web.c0desec_adapter import (
    WebScanOptions,
    WebSecurityAdapter,
    redact_secret_value,
)
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
)


@pytest.fixture
def db():
    return Database(":memory:")


def test_redact_secret_value():
    assert redact_secret_value("short") == "[REDACTED]"
    redacted = redact_secret_value("AKIAIOSFODNN7EXAMPLE")
    assert redacted.startswith("AKIA...")
    assert "EXAMPLE" not in redacted
    assert "REDACTED_LEN_20" in redacted


def test_web_adapter_blocks_out_of_scope_target(db: Database):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Scope Guard Web Test"))
    assert project.id is not None

    scopes = [
        TargetScope(
            project_id=project.id,
            target="internal.lab.local",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        )
    ]

    options = WebScanOptions(target_url="https://evil.external.corp")
    success, reason, result, execution = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
    )

    assert success is False
    assert "NOT in the authorized scope list" in reason
    assert result is None
    assert execution is None


def test_web_adapter_detects_headers_cors_and_secrets(db: Database, tmp_path):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Web Target Test"))
    assert project.id is not None

    # Authorize 127.0.0.1
    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    # Create mock session simulating a vulnerable server
    mock_session = MagicMock(spec=requests.Session())

    # Simulated HTML with endpoints and a hardcoded secret
    html_body = """<!DOCTYPE html>
    <html>
    <head><title>Vulnerable Portal</title></head>
    <body>
      <a href="/api/v1/users">Users API</a>
      <a href="/admin/login">Admin Console</a>
      <a href="https://external.malicious.com/tracker">Out of Scope Tracker</a>
      <script>
        var apiKey = "AIzaSyD-DummyGoogleApiKey1234567890";
        var awsKey = "AKIAIOSFODNN7EXAMPLE";
      </script>
    </body>
    </html>"""

    # Mock base GET response
    base_resp = MagicMock()
    base_resp.status_code = 200
    base_resp.text = html_body
    base_resp.headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",  # Version disclosure
    }

    # Mock CORS OPTIONS response
    cors_resp = MagicMock()
    cors_resp.headers = {
        "Access-Control-Allow-Origin": "https://attacker.evil.com",
        "Access-Control-Allow-Credentials": "true",
    }

    def mock_get(url, **kwargs):
        return base_resp

    def mock_options(url, **kwargs):
        return cors_resp

    mock_session.get.side_effect = mock_get
    mock_session.options.side_effect = mock_options

    options = WebScanOptions(
        target_url="http://127.0.0.1:8080",
        check_headers=True,
        check_cors=True,
        check_js_secrets=True,
        discover_endpoints=True,
        check_dns=False,
    )

    output_lines = []

    def on_output(line: str, stream: str):
        output_lines.append(line)

    success, msg, scan_res, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        on_output=on_output,
        evidence_dir=tmp_path / "evidence",
        session=mock_session,
    )

    assert success is True
    assert scan_res is not None
    assert exec_rec is not None
    assert exec_rec.status == ExecutionStatus.COMPLETED

    # Verify discovered endpoints (stays on same host, ignores external tracking link)
    assert "http://127.0.0.1:8080/api/v1/users" in scan_res.endpoints
    assert "http://127.0.0.1:8080/admin/login" in scan_res.endpoints
    assert "https://external.malicious.com/tracker" not in scan_res.endpoints

    # Verify CORS vulnerability detected
    assert scan_res.cors_vulnerable is True

    # Verify Secrets detected and REDACTED
    assert len(scan_res.secrets) >= 1
    for secret in scan_res.secrets:
        assert "[REDACTED" in secret.redacted_preview

    # Verify Findings were generated in DB
    db_findings = db.list_findings(project.id)
    assert len(db_findings) >= 3

    finding_titles = [f.title for f in db_findings]
    assert any("Content-Security-Policy" in t for t in finding_titles)
    assert any("Server Version Disclosure" in t for t in finding_titles)
    assert any("CORS" in t for t in finding_titles)
    assert any("Hardcoded Secret Candidate" in t for t in finding_titles)

    # Verify Evidence was recorded in DB
    evidence_list = db.list_evidence(project.id)
    assert len(evidence_list) == 1
    assert evidence_list[0].execution_id == exec_rec.id
    assert evidence_list[0].mime_type == "application/json"


def test_web_adapter_handles_timeout(db: Database):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Timeout Test Project"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="10.10.10.50",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    mock_session = MagicMock(spec=requests.Session())
    mock_session.get.side_effect = requests.exceptions.Timeout("Connection timed out after 3.0s")

    options = WebScanOptions(
        target_url="http://10.10.10.50:8000",
        timeout=3.0,
        check_dns=False,
    )

    success, msg, scan_res, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        session=mock_session,
    )

    assert success is True
    assert "Timeout after" in msg
    assert exec_rec is not None
    assert exec_rec.status == ExecutionStatus.TIMEOUT


def test_web_adapter_handles_malformed_response(db: Database):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Malformed Response Project"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    mock_session = MagicMock(spec=requests.Session())
    resp = MagicMock()
    resp.status_code = 500
    resp.text = "<<<broken binary corrupt \x00\x01\x02 \x99\xff>>>"
    resp.headers = {}
    mock_session.get.return_value = resp
    mock_session.options.return_value = resp

    options = WebScanOptions(
        target_url="http://127.0.0.1:9999",
        check_dns=False,
    )

    success, msg, scan_res, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        session=mock_session,
    )

    assert success is True
    assert exec_rec.status == ExecutionStatus.COMPLETED
    assert len(scan_res.endpoints) == 0


def test_web_adapter_response_size_limiting(db: Database):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Size Limit Project"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    mock_session = MagicMock(spec=requests.Session())
    resp = MagicMock()
    resp.status_code = 200
    # Simulate 50 KB body
    resp.text = "A" * 50000
    resp.headers = {}
    mock_session.get.return_value = resp
    mock_session.options.return_value = resp

    options = WebScanOptions(
        target_url="http://127.0.0.1:8080",
        max_response_size=1024,  # Cap at 1 KB
        check_dns=False,
    )

    output_lines = []
    success, msg, scan_res, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        on_output=lambda line, stream: output_lines.append(line),
        session=mock_session,
    )

    assert success is True
    assert any("exceeded max size limit" in line for line in output_lines)


def test_web_adapter_cancellation(db: Database):
    adapter = WebSecurityAdapter(db)
    project = db.create_project(Project(name="Cancellation Project"))

    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    # Pre-cancel adapter
    adapter.cancel()

    mock_session = MagicMock(spec=requests.Session())
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html><body>Test</body></html>"
    resp.headers = {}
    mock_session.get.return_value = resp

    options = WebScanOptions(
        target_url="http://127.0.0.1:8080",
        check_dns=False,
    )

    success, msg, scan_res, exec_rec = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        session=mock_session,
    )

    assert success is True
    assert "cancelled" in msg.lower()
    assert exec_rec.status == ExecutionStatus.CANCELLED
