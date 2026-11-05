"""Unit tests for CPENT Engagement Pack Generator."""

import json
from pathlib import Path

import pytest

from reports.cpent_engagement_pack import CPENTEngagementPackGenerator
from storage.db import Database
from storage.models import (
    Evidence,
    ExecutionStatus,
    Finding,
    FindingSeverity,
    Project,
    TargetScope,
    TargetType,
    ToolExecution,
)


@pytest.fixture
def db():
    return Database(":memory:")


def test_cpent_engagement_pack_generation(db: Database, tmp_path: Path):
    # 1. Setup project
    project = db.create_project(
        Project(
            name="FinSecure Banking Assessment",
            client_name="FinSecure Ltd",
            engagement_id="ENG-2026-0042",
            lead_tester="Senior Pentester Leo",
            authorized_contact="CISO Jane Doe",
            emergency_contact="SecOps Hotline +1-555-0199",
            start_date="2026-11-01",
            end_date="2026-11-15",
            timezone="UTC",
            allowed_hours="08:00-18:00 UTC",
            max_rate_limit=150,
            allow_active_recon=True,
            prohibited_tests="DoS, Physical Access, Social Engineering",
        )
    )
    p_id = project.id
    assert p_id is not None

    # 2. Add scopes
    db.add_scope(
        TargetScope(
            project_id=p_id,
            target="10.20.0.0/24",
            target_type=TargetType.CIDR_RANGE,
            is_authorized=True,
            environment="Staging",
        )
    )

    # 3. Add execution and finding
    ex = db.create_execution(
        ToolExecution(
            project_id=p_id,
            tool_name="nmap",
            command="nmap -sS -p 80,443 10.20.0.10",
            status=ExecutionStatus.COMPLETED,
            exit_code=0,
        )
    )
    f = db.create_finding(
        Finding(
            project_id=p_id,
            title="Exposed Administration Interface",
            severity=FindingSeverity.HIGH,
            affected_asset="10.20.0.10",
            execution_id=ex.id,
        )
    )
    db.add_evidence(
        Evidence(
            project_id=p_id,
            finding_id=f.id,
            execution_id=ex.id,
            file_path="/tmp/evidence_admin.png",
            sha256_hash="abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678",
            description="Screenshot of admin portal",
            mime_type="image/png",
        )
    )

    # 4. Generate Pack
    generator = CPENTEngagementPackGenerator(db)
    files = generator.generate_pack(p_id, tmp_path)

    assert "engagement_letter" in files
    assert "roe" in files
    assert "test_plan" in files
    assert "lta" in files
    assert "ecl" in files
    assert "evidence_manifest" in files

    # Verify content
    el_content = files["engagement_letter"].read_text()
    assert "FinSecure Ltd" in el_content
    assert "ENG-2026-0042" in el_content
    assert "Senior Pentester Leo" in el_content

    roe_content = files["roe"].read_text()
    assert "`150` requests/sec" in roe_content
    assert "SecOps Hotline" in roe_content
    assert "YES" in roe_content  # Active OSINT

    manifest_content = json.loads(files["evidence_manifest"].read_text())
    assert manifest_content["total_evidence_files"] == 1
    assert manifest_content["evidence_records"][0]["sha256_hash"] == "abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678"


def test_cpent_engagement_pack_zip_generation(db: Database, tmp_path: Path):
    import zipfile

    project = db.create_project(
        Project(
            name="Bank Corp CPENT Exam",
            client_name="Bank Corp",
            engagement_id="ENG-2026-9999",
            lead_tester="Senior Pentester Leo",
        )
    )
    generator = CPENTEngagementPackGenerator(db)
    target_zip = tmp_path / "Bank_Corp_Pack.zip"
    out_path = generator.generate_pack_zip(project.id, target_zip)

    assert out_path.exists()
    assert out_path.stat().st_size > 0

    with zipfile.ZipFile(out_path, "r") as zf:
        namelist = zf.namelist()
        assert "README.md" in namelist
        assert "00_Administration/00A_EL/Engagement_Letter.md" in namelist
        assert "00_Administration/00F__ROE/Rules_of_Engagement.md" in namelist
        assert "01_SISGCA/01C_EVD&A/Evidence_Manifest.json" in namelist
        assert "02_SEVA_Tools/Tool_Inventory.md" in namelist

