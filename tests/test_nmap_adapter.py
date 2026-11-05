"""Unit and integration tests for NmapAdapter."""

import pytest
from modules.network.nmap_adapter import (
    NmapAdapter,
    NmapScanOptions,
    ScanProfile,
)
from storage.db import Database
from storage.models import (
    ExecutionStatus,
    Project,
    TargetScope,
    TargetType,
)
from terminal.runner import ProcessExecutionResult


@pytest.fixture
def db():
    return Database(":memory:")


def test_nmap_adapter_build_command(db: Database):
    adapter = NmapAdapter(db)
    options = NmapScanOptions(
        target="192.168.1.10",
        profile=ScanProfile.SERVICE_VERSION,
        ports="80,443",
    )
    cmd = adapter.build_command(options)

    assert "nmap" in cmd[0]
    assert "-sV" in cmd
    assert "-p" in cmd
    assert "80,443" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    assert cmd[-1] == "192.168.1.10"


def test_nmap_adapter_firewall_detection_command(db: Database):
    adapter = NmapAdapter(db)
    options = NmapScanOptions(
        target="192.168.1.10",
        profile=ScanProfile.FIREWALL_DETECTION,
    )
    cmd = adapter.build_command(options)

    assert "nmap" in cmd[0]
    assert "-sA" in cmd
    assert "-T4" in cmd
    assert "-Pn" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    assert cmd[-1] == "192.168.1.10"


def test_nmap_adapter_blocks_out_of_scope(db: Database):
    adapter = NmapAdapter(db)
    project = db.create_project(Project(name="Scope Guard Test"))
    assert project.id is not None

    scopes = [
        TargetScope(
            project_id=project.id,
            target="192.168.50.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    ]

    options = NmapScanOptions(target="10.0.0.1")
    result = adapter.execute_scan(project.id, options, scopes)

    assert result.is_authorized is False
    assert "NOT in the authorized scope list" in result.scope_reason
    assert result.execution is None


def test_nmap_adapter_reports_invalid_xml_as_failed(db: Database, monkeypatch):
    adapter = NmapAdapter(db)
    project = db.create_project(Project(name="Malformed XML Test"))
    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]
    now = "2026-10-28T00:00:00Z"
    monkeypatch.setattr(
        adapter.runner,
        "run",
        lambda **kwargs: ProcessExecutionResult(
            command=kwargs["command"],
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
            stdout="not valid nmap xml",
            stderr="",
            started_at=now,
            finished_at=now,
            duration_seconds=0.1,
        ),
    )
    output = []

    result = adapter.execute_scan(
        project.id,
        NmapScanOptions(target="127.0.0.1"),
        scopes,
        on_output=lambda chunk, stream: output.append((chunk, stream)),
    )

    assert result.execution is not None
    assert result.execution.status == ExecutionStatus.FAILED
    assert result.scan_result is None
    assert any("Failed to parse Nmap XML" in chunk for chunk, _ in output)


def test_nmap_adapter_runs_safe_local_scan(db: Database, tmp_path):
    """Execute a safe, low-overhead scan against localhost 127.0.0.1."""
    adapter = NmapAdapter(db)
    project = db.create_project(Project(name="Localhost Safe Scan"))
    assert project.id is not None

    scopes = [
        TargetScope(
            project_id=project.id,
            target="127.0.0.1/32",
            target_type=TargetType.IP_ADDRESS,
            is_authorized=True,
        )
    ]

    # Quick ping discovery on localhost (runs in under 1 second)
    options = NmapScanOptions(
        target="127.0.0.1",
        profile=ScanProfile.PING_DISCOVERY,
        timeout=10.0,
    )

    streaming_lines = []

    def on_output(line: str, stream: str):
        streaming_lines.append(line)

    result = adapter.execute_scan(
        project_id=project.id,
        options=options,
        scopes=scopes,
        on_output=on_output,
        evidence_dir=tmp_path / "evidence",
    )

    assert result.is_authorized is True
    assert result.execution is not None
    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.execution.exit_code == 0
    assert result.scan_result is not None
    assert len(result.scan_result.hosts) >= 1
    assert result.scan_result.hosts[0].ip == "127.0.0.1"
    assert result.scan_result.hosts[0].status == "up"

    # Verify execution was saved in database
    db_executions = db.list_executions(project.id)
    assert len(db_executions) == 1
    assert db_executions[0].status == ExecutionStatus.COMPLETED

    # Verify raw XML evidence was saved
    evidence_list = db.list_evidence(project.id)
    assert len(evidence_list) == 1
    assert evidence_list[0].execution_id == result.execution.id


def test_nmap_adapter_udp_scan_command(db: Database):
    adapter = NmapAdapter(db)
    opts = NmapScanOptions(
        target="192.168.1.1",
        profile=ScanProfile.UDP_SCAN,
    )
    cmd = adapter.build_command(opts)
    assert "-sU" in cmd
    assert "-F" in cmd
    assert "-T4" in cmd
    assert "-oX" in cmd
    assert "192.168.1.1" in cmd

