"""Unit and integration tests for CPENT lab challenge verifier and GUI."""

import hashlib
import pytest

from labs.cpent.curriculum import (
    CPENTLabVerifier,
    CPENTTestItem,
    LabVerificationResult,
)


def test_cpent_lab_flag_verification():
    """Cryptographic challenge flag comparison with SHA-256."""
    real_flag = "CPENT{P1v0t_2_D0ubl3_Ch41n_Win}"
    expected_hash = hashlib.sha256(real_flag.encode("utf-8")).hexdigest()

    item = CPENTTestItem(
        test_id="LAB-PIVOT-01",
        title="Double Pivoting Challenge",
        methodology="Network Pentest",
        category="Pivoting",
        suggested_tools=["ssh", "chisel"],
        expected_flag_hash=expected_hash,
    )

    # 1. Correct flag
    res_correct = CPENTLabVerifier.verify_lab(item, flag_candidate=real_flag)
    assert res_correct.is_verified is True
    assert res_correct.state == "PASSED"
    assert res_correct.evidence_sha256 == expected_hash

    # 2. Incorrect flag
    res_wrong = CPENTLabVerifier.verify_lab(item, flag_candidate="CPENT{WRONG_FLAG}")
    assert res_wrong.is_verified is False
    assert res_wrong.state == "FAILED"
    assert "Flag mismatch" in res_wrong.details

    # 3. Empty flag
    res_empty = CPENTLabVerifier.verify_lab(item, flag_candidate="")
    assert res_empty.is_verified is False
    assert res_empty.state == "FAILED"


def test_cpent_lab_action_audit_file_perms():
    """Verifies that audit_file_perms action returns a valid LabVerificationResult with evidence hash."""
    item = CPENTTestItem(
        test_id="LAB-PRIV-01",
        title="Linux Permissions Privilege Escalation Lab",
        methodology="Internal Network Pentest",
        category="Privilege Escalation",
        suggested_tools=["find", "stat"],
        verification_action="audit_file_perms",
    )
    res = CPENTLabVerifier.verify_lab(item)
    assert res.test_id == "LAB-PRIV-01"
    assert res.is_verified is True
    assert res.state == "PASSED"
    assert len(res.evidence_sha256) == 64
    assert "Audited" in res.details


def test_cpent_lab_action_check_elf():
    """Verifies check_elf action on system binary."""
    item = CPENTTestItem(
        test_id="LAB-BIN-01",
        title="Buffer Overflow & Checksec Lab",
        methodology="Binary Analysis",
        category="Binary Exploitation",
        suggested_tools=["checksec", "gdb"],
        verification_action="check_elf",
        verification_target="/bin/ls",
    )
    res = CPENTLabVerifier.verify_lab(item)
    assert res.test_id == "LAB-BIN-01"
    assert res.is_verified is True
    assert res.state == "PASSED"
    assert "ELF" in res.details

