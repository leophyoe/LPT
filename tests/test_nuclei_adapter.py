"""Unit tests for NucleiAdapter."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import hashlib
import json
from pathlib import Path

import pytest
from modules.network.nuclei_adapter import (
    NucleiAdapter,
    NucleiScanOptions,
)
from storage.db import Database
from storage.models import (
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ValidationStatus,
)

SAMPLE_NUCLEI_JSONL = """{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"JNDI lookup evaluation in log messages enables unauthenticated RCE.","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},"type":"http","host":"http://192.168.1.50:8080","ip":"192.168.1.50","matched-at":"http://192.168.1.50:8080"}
{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"medium","description":".git/config was accessible over HTTP.","classification":{}},"type":"http","host":"http://192.168.1.50","ip":"192.168.1.50","matched-at":"http://192.168.1.50/.git/config"}
{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE (Duplicate)","severity":"critical"},"type":"http","host":"http://192.168.1.50:8080","ip":"192.168.1.50"}
"""


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def project(db: Database) -> Project:
    p = db.create_project(Project(name="Nuclei Test Project"))
    db.add_scope(
        TargetScope(
            project_id=p.id,
            target="192.168.1.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    return p


def test_nuclei_parse_jsonl():
    findings = NucleiAdapter.parse_jsonl(SAMPLE_NUCLEI_JSONL, project_id=1, execution_id=5)

    # 3 lines in sample, but line 3 is a duplicate template on the same asset -> deduplicated to 2
    assert len(findings) == 2

    log4j = next(f for f in findings if "cve-2021-44228" in f.title)
    assert log4j.severity == FindingSeverity.CRITICAL
    assert log4j.cvss_score == 10.0
    assert log4j.affected_asset == "192.168.1.50"
    assert "CVE-2021-44228" in log4j.description
    # Crucial CPENT rule: Nuclei discoveries require validation, never auto-confirmed
    assert log4j.validation_status == ValidationStatus.NEEDS_VALIDATION
    assert log4j.source_tool == "nuclei:cve-2021-44228"

    git = next(f for f in findings if "git-config" in f.title)
    assert git.severity == FindingSeverity.MEDIUM
    assert git.validation_status == ValidationStatus.NEEDS_VALIDATION


def test_nuclei_availability_check_and_graceful_missing_binary(db: Database, project: Project):
    adapter = NucleiAdapter(db)
    # If binary is not in PATH or source, adapter must gracefully return is_available=False
    if not adapter.is_available():
        res = adapter.execute_scan(
            project_id=project.id,
            options=NucleiScanOptions(target="192.168.1.50"),
            scopes=db.list_scopes(project.id),
        )
        assert res.is_available is False
        assert "not found" in res.status_reason
        assert "go install" in res.status_reason


def test_nuclei_import_jsonl_provenance_and_scope(db: Database, project: Project, tmp_path: Path):
    adapter = NucleiAdapter(db)
    scopes = db.list_scopes(project.id)

    res = adapter.import_nuclei_jsonl(
        project_id=project.id,
        jsonl_content=SAMPLE_NUCLEI_JSONL,
        scopes=scopes,
        source_filename="external_nuclei.jsonl",
        evidence_dir=tmp_path / "evidence",
    )

    assert res.is_authorized is True
    assert len(res.findings) == 2
    assert res.execution is not None
    assert res.execution.tool_name == "nuclei_import"

    # Evidence record
    evs = db.list_evidence(project.id)
    assert len(evs) == 1
    assert evs[0].mime_type == "application/x-ndjson"
    assert evs[0].sha256_hash == hashlib.sha256(SAMPLE_NUCLEI_JSONL.encode("utf-8")).hexdigest()

    # Findings in database
    db_findings = db.list_findings(project.id)
    assert len(db_findings) == 2


def test_nuclei_import_quarantines_out_of_scope(db: Database, tmp_path: Path):
    adapter = NucleiAdapter(db)
    proj = db.create_project(Project(name="DMZ Project"))
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.0.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
        )
    )
    scopes = db.list_scopes(proj.id)

    # 192.168.1.50 is not in 10.0.0.0/24 -> must be blocked
    res = adapter.import_nuclei_jsonl(
        project_id=proj.id,
        jsonl_content=SAMPLE_NUCLEI_JSONL,
        scopes=scopes,
        source_filename="unauthorized_nuclei.jsonl",
    )

    assert res.is_authorized is False
    assert "outside authorized scope" in res.status_reason

