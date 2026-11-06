"""Tests for Terminal Session Recording, Evidence Integrity, and Secret Redaction."""

import os
import tempfile
from pathlib import Path

import pytest

from storage.db import Database
from storage.models import Project
from terminal.recorder import (
    TerminalSessionRecorder,
    redact_sensitive_text,
    strip_ansi,
)


def test_strip_ansi_removes_escape_sequences():
    raw = "\x1B[31m[!] Error: Host down\x1B[0m\r\n\x1B[1;32m[+] 80/tcp open http\x1B[0m\r\n"
    cleaned = strip_ansi(raw)
    assert "\x1B[" not in cleaned
    assert "[!] Error: Host down\n[+] 80/tcp open http\n" == cleaned


def test_redact_sensitive_text():
    # Passwords in parameters
    sample_cmd = "sqlmap -u http://127.0.0.1 --password SuperSecretPass123! -p id"
    redacted = redact_sensitive_text(sample_cmd)
    assert "SuperSecretPass123!" not in redacted
    assert "[REDACTED_PASSWORD]" in redacted

    # Key-value password
    sample_env = "DB_USER=root password=VeryConfidentialToken999;"
    redacted_env = redact_sensitive_text(sample_env)
    assert "VeryConfidentialToken999" not in redacted_env
    assert "[REDACTED_PASSWORD]" in redacted_env

    # Bearer Token
    sample_auth = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SecretPayload"
    redacted_auth = redact_sensitive_text(sample_auth)
    assert "SecretPayload" not in redacted_auth
    assert "Bearer [REDACTED_TOKEN]" in redacted_auth

    # AWS Access Key
    sample_aws = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    redacted_aws = redact_sensitive_text(sample_aws)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted_aws
    assert "[REDACTED_AWS_KEY]" in redacted_aws

    # Private Key
    sample_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    redacted_key = redact_sensitive_text(sample_key)
    assert "MIIEowIBAAKCAQEA0" not in redacted_key
    assert "[REDACTED_PRIVATE_KEY]" in redacted_key

    sample_credentials = (
        "https://alice:url-password-123@example.test "
        "Authorization: Basic dXNlcjpzZWNyZXQ= "
        "Cookie: session=web-session-secret-123 "
        "Authorization: Token auth-token-secret-123 "
        "client_secret=client-secret-123 "
        "github_token=github-secret-123"
    )
    redacted_credentials = redact_sensitive_text(sample_credentials)
    for secret in (
        "url-password-123",
        "dXNlcjpzZWNyZXQ=",
        "web-session-secret-123",
        "auth-token-secret-123",
        "client-secret-123",
        "github-secret-123",
    ):
        assert secret not in redacted_credentials


def test_terminal_session_recorder_lifecycle_and_evidence(tmp_path: Path):
    db = Database(str(tmp_path / "test_recorder.db"))
    proj = db.create_project(Project(name="Recorder Test Lab"))

    recorder = TerminalSessionRecorder(project_id=proj.id, session_id="test_sess_001")
    assert not recorder.is_recording

    # Start recording
    recorder.start(project_id=proj.id, cwd=str(tmp_path))
    assert recorder.is_recording
    assert recorder.started_at is not None

    # Record inputs and outputs
    recorder.record_input("nmap -sV -p 22,80 127.0.0.1\n")
    recorder.record_output("\x1B[32mStarting Nmap 7.80\x1B[0m\r\n")
    recorder.record_output("PORT   STATE SERVICE VERSION\r\n22/tcp open  ssh     OpenSSH 8.2\r\n")
    recorder.record_command("nmap -sV -p 22,80 127.0.0.1", exit_code=0, cwd=str(tmp_path), duration=1.2)

    # Stop recording
    recorder.stop(exit_status=0)
    assert not recorder.is_recording
    assert recorder.ended_at is not None
    assert len(recorder.events) == 3
    assert len(recorder.recorded_commands) == 1

    # Save to evidence
    result = recorder.save_session_as_evidence(db=db, storage_dir=tmp_path / "evidence")
    assert result.sha256_hash != ""
    assert not result.is_duplicate
    assert os.path.exists(result.raw_path)
    assert os.path.exists(result.plain_path)
    assert os.path.exists(result.events_path)

    # Verify bytes match calculated SHA-256
    saved_bytes = Path(result.raw_path).read_bytes()
    import hashlib
    assert hashlib.sha256(saved_bytes).hexdigest() == result.sha256_hash

    # Verify SQLite persistence
    session_rec = db.get_terminal_session("test_sess_001")
    assert session_rec is not None
    assert session_rec.project_id == proj.id
    assert session_rec.sha256_hash == result.sha256_hash
    assert session_rec.command_count == 1
    assert "nmap" in session_rec.commands_json

    ev_list = db.list_evidence(proj.id)
    assert len(ev_list) == 1
    assert ev_list[0].sha256_hash == result.sha256_hash
    assert Path(ev_list[0].file_path).read_bytes() == saved_bytes
    assert db.verify_evidence_integrity(ev_list[0])[0] is True

    # Test Deduplication: saving the same session again does NOT create duplicate Evidence rows
    dup_result = recorder.save_session_as_evidence(db=db, storage_dir=tmp_path / "evidence")
    assert dup_result.is_duplicate
    assert dup_result.sha256_hash == result.sha256_hash
    assert len(db.list_evidence(proj.id)) == 1  # Still 1 evidence row, not 2!


def test_recorder_rejects_saving_without_project(tmp_path: Path):
    db = Database(str(tmp_path / "test_no_proj.db"))
    recorder = TerminalSessionRecorder()
    recorder.record_output("echo test\n")
    with pytest.raises(ValueError, match="Cannot save terminal session evidence without an active project ID"):
        recorder.save_session_as_evidence(db=db)
