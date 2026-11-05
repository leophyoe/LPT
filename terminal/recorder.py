"""Interactive Terminal Session Recording, Evidence Integrity, and Secret Redaction.

Provides:
1. TerminalSessionRecorder: Event stream capture for both PTY terminals and command shells.
2. Separate recording of user input and PTY/stdout output with timestamped event logging.
3. ANSI escape sequence stripping for clean human-readable plain-text exports.
4. Cryptographic SHA-256 hash calculation over exact saved evidence bytes.
5. Sensitive credential and token redaction for report exports (preserving unaltered original evidence).
6. Deduplication to prevent multiple evidence rows when saving the same session repeatedly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    TerminalSessionRecord,
    ToolExecution,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ANSI Escape sequence regex matching CSI, OSC, and single-character control sequences
ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)

# Secret and credential redaction patterns
REDACTION_PATTERNS = [
    # Passwords in CLI args or key-value pairs
    (re.compile(r"(-p|--password)[\s=]+([^\s\"'\n]+)", re.IGNORECASE), r"\1 [REDACTED_PASSWORD]"),
    (re.compile(r"(-u|--user)[\s=]+([A-Za-z0-9_.\-]+):([^\s\"'\n]+)", re.IGNORECASE), r"\1 \2:[REDACTED_PASSWORD]"),
    (re.compile(r"(password|passwd|pwd)[\s:=]+([^\s,;&\"'\n]+)", re.IGNORECASE), r"\1=[REDACTED_PASSWORD]"),
    # Bearer and Auth tokens
    (re.compile(r"(Bearer\s+)([A-Za-z0-9_\-\.]{10,})", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(api[_-]?key|secret[_-]?key|auth[_-]?token)[\s:=]+([A-Za-z0-9_\-]{12,})", re.IGNORECASE), r"\1=[REDACTED_KEY]"),
    # AWS Access Keys
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), r"[REDACTED_AWS_KEY]"),
    # Private Keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), r"[REDACTED_PRIVATE_KEY]"),
]


def strip_ansi(text: str) -> str:
    """Removes ANSI terminal escape sequences and normalizes carriage returns."""
    cleaned = ANSI_ESCAPE_RE.sub("", text)
    # Normalize carriage return and newlines
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    return cleaned


def redact_sensitive_text(text: str) -> str:
    """Redacts passwords, tokens, private keys, and cloud credentials for reporting.
    
    Leaves original evidence untouched; use this function only when preparing
    human-readable exports or assessment reports.
    """
    redacted = text
    for pattern, repl in REDACTION_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


@dataclass
class TerminalEvent:
    """Single input or output event captured during a terminal session."""
    timestamp: str
    event_type: str  # 'input' or 'output'
    data: str


@dataclass
class RecordedCommand:
    """Reliably identifiable command executed during the session."""
    timestamp: str
    command: str
    working_directory: str
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None


@dataclass
class SessionEvidenceResult:
    """Result of saving a recorded terminal session as project evidence."""
    evidence: Evidence
    session_record: TerminalSessionRecord
    sha256_hash: str
    raw_path: str
    plain_path: str
    events_path: str
    is_duplicate: bool = False


class TerminalSessionRecorder:
    """Records interactive PTY and command shell sessions with cryptographic evidence integrity."""

    def __init__(self, project_id: Optional[int] = None, session_id: Optional[str] = None):
        self.session_id: str = session_id or f"sess_{uuid.uuid4().hex[:10]}_{int(time.time())}"
        self.project_id: Optional[int] = project_id
        self.working_directory: str = os.getcwd()
        self.started_at: Optional[str] = None
        self.ended_at: Optional[str] = None
        self.exit_status: Optional[int] = None
        self.is_recording: bool = False

        self.events: List[TerminalEvent] = []
        self.recorded_commands: List[RecordedCommand] = []

        self._raw_output_chunks: List[str] = []
        self._input_chunks: List[str] = []

    def start(self, project_id: Optional[int] = None, cwd: Optional[str] = None) -> None:
        """Starts a new recording session."""
        if project_id is not None:
            self.project_id = project_id
        if cwd:
            self.working_directory = cwd
        self.started_at = _utc_now_iso()
        self.ended_at = None
        self.exit_status = None
        self.is_recording = True
        self.events.clear()
        self.recorded_commands.clear()
        self._raw_output_chunks.clear()
        self._input_chunks.clear()

    def record_input(self, data: str) -> None:
        """Records user input keystrokes or submitted command lines."""
        if not self.is_recording or not data:
            return
        ts = _utc_now_iso()
        self.events.append(TerminalEvent(timestamp=ts, event_type="input", data=data))
        self._input_chunks.append(data)

    def record_output(self, data: str) -> None:
        """Records terminal output stream (stdout/stderr or PTY output)."""
        if not self.is_recording or not data:
            return
        ts = _utc_now_iso()
        self.events.append(TerminalEvent(timestamp=ts, event_type="output", data=data))
        self._raw_output_chunks.append(data)

    def record_command(
        self,
        command: str,
        exit_code: Optional[int] = None,
        cwd: Optional[str] = None,
        duration: Optional[float] = None,
    ) -> None:
        """Records a reliably confirmed command execution boundary."""
        if not self.is_recording:
            return
        clean = command.strip()
        if not clean:
            return
        ts = _utc_now_iso()
        self.recorded_commands.append(
            RecordedCommand(
                timestamp=ts,
                command=clean,
                working_directory=cwd or self.working_directory,
                exit_code=exit_code,
                duration_seconds=duration,
            )
        )

    def stop(self, exit_status: Optional[int] = 0) -> None:
        """Stops active recording session."""
        self.is_recording = False
        self.ended_at = _utc_now_iso()
        self.exit_status = exit_status

    def get_raw_content(self) -> str:
        """Returns the complete raw output string preserving ANSI sequences."""
        return "".join(self._raw_output_chunks)

    def get_plain_text(self) -> str:
        """Returns clean human-readable plain text with ANSI codes stripped."""
        return strip_ansi(self.get_raw_content())

    def get_redacted_text(self) -> str:
        """Returns plain text with sensitive passwords and tokens masked."""
        return redact_sensitive_text(self.get_plain_text())

    def get_input_content(self) -> str:
        """Returns concatenated user input stream."""
        return "".join(self._input_chunks)

    def save_session_as_evidence(
        self,
        db: Database,
        project_id: Optional[int] = None,
        storage_dir: Optional[Path | str] = None,
    ) -> SessionEvidenceResult:
        """Saves session files with SHA-256 integrity and records evidence in SQLite.
        
        Prevents duplicate evidence records if the same session is saved repeatedly.
        """
        p_id = project_id or self.project_id
        if not p_id:
            raise ValueError("Cannot save terminal session evidence without an active project ID.")

        if self.is_recording:
            self.stop(exit_status=0)

        base_dir = Path(storage_dir or "storage/evidence")
        base_dir.mkdir(parents=True, exist_ok=True)

        raw_content = self.get_raw_content()
        plain_content = self.get_plain_text()
        raw_bytes = raw_content.encode("utf-8")

        # 1. Calculate SHA-256 hash over exact raw bytes
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # 2. Write exact raw ANSI evidence file
        raw_file = base_dir / f"session_{self.session_id}.raw"
        raw_file.write_bytes(raw_bytes)

        # 3. Write clean plain-text log
        plain_file = base_dir / f"session_{self.session_id}.txt"
        plain_file.write_text(plain_content, encoding="utf-8")

        # 4. Write structured event log JSON
        events_file = base_dir / f"session_{self.session_id}.json"
        events_data = {
            "session_id": self.session_id,
            "project_id": p_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "working_directory": self.working_directory,
            "exit_status": self.exit_status,
            "sha256_hash": sha256_hash,
            "events_count": len(self.events),
            "commands": [asdict(c) for c in self.recorded_commands],
            "events": [asdict(e) for e in self.events],
        }
        events_file.write_text(json.dumps(events_data, indent=2), encoding="utf-8")

        # 5. Check if an Evidence record with this exact hash already exists for this project (Deduplication)
        existing_evidence = db.get_evidence_by_hash(p_id, sha256_hash)
        is_duplicate = False

        if existing_evidence:
            evidence = existing_evidence
            is_duplicate = True
        else:
            # Create a ToolExecution record to link the evidence
            cmd_summary = (
                self.recorded_commands[0].command
                if self.recorded_commands
                else f"Interactive Terminal Session ({self.session_id})"
            )
            tool_exec = ToolExecution(
                project_id=p_id,
                tool_name="terminal_session",
                command=f"Terminal Session {self.session_id}: {cmd_summary[:60]}",
                status=ExecutionStatus.COMPLETED,
                exit_code=self.exit_status if self.exit_status is not None else 0,
                started_at=self.started_at,
                finished_at=self.ended_at,
                raw_output_path=str(raw_file),
            )
            saved_exec = db.create_execution(tool_exec)

            # Create new Evidence record
            ev = Evidence(
                project_id=p_id,
                execution_id=saved_exec.id,
                file_path=str(raw_file),
                sha256_hash=sha256_hash,
                description=(
                    f"Raw terminal session {self.session_id} recorded from {self.started_at} to {self.ended_at}. "
                    f"Commands: {len(self.recorded_commands)}, Events: {len(self.events)}."
                ),
                mime_type="application/octet-stream",
            )
            evidence = db.add_evidence(ev)

        # 6. Create or update TerminalSessionRecord in database
        commands_json = json.dumps([asdict(c) for c in self.recorded_commands])
        existing_session = db.get_terminal_session(self.session_id)

        session_record = TerminalSessionRecord(
            session_id=self.session_id,
            project_id=p_id,
            started_at=self.started_at or _utc_now_iso(),
            ended_at=self.ended_at,
            working_directory=self.working_directory,
            exit_status=self.exit_status,
            raw_output_path=str(raw_file),
            plain_text_path=str(plain_file),
            sha256_hash=sha256_hash,
            evidence_id=evidence.id,
            execution_id=evidence.execution_id,
            command_count=len(self.recorded_commands),
            commands_json=commands_json,
        )

        if existing_session:
            db.update_terminal_session(session_record)
            session_record.id = existing_session.id
        else:
            session_record = db.create_terminal_session(session_record)

        return SessionEvidenceResult(
            evidence=evidence,
            session_record=session_record,
            sha256_hash=sha256_hash,
            raw_path=str(raw_file),
            plain_path=str(plain_file),
            events_path=str(events_file),
            is_duplicate=is_duplicate,
        )
