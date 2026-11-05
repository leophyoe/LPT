"""Unit and integration tests for AssessmentOrchestrator."""

import time
import pytest

from core.assessment_orchestrator import (
    AssessmentOrchestrator,
    AssessmentTestItem,
    TestExecutionState,
)
from storage.db import Database
from storage.models import (
    AssessmentPlan,
    AssessmentStatus,
    Project,
    ProjectStatus,
    ScopeRuleType,
    TargetScope,
    TargetType,
    TestCategory,
)


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def active_project(db: Database) -> Project:
    proj = db.create_project(
        Project(
            name="Orchestration Test Engagement",
            client_name="TestCorp",
            status=ProjectStatus.ACTIVE,
            start_date="2026-01-01",
            end_date="2026-12-31",
        )
    )
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="127.0.0.1",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.ALLOWED,
            is_authorized=True,
        )
    )
    db.add_scope(
        TargetScope(
            project_id=proj.id,
            target="10.99.99.99",
            target_type=TargetType.IP_ADDRESS,
            rule_type=ScopeRuleType.EXCLUDED,
            is_authorized=False,
        )
    )
    return proj


def test_assessment_orchestrator_builds_and_executes_plan(db: Database, active_project: Project):
    """Verifies that orchestrator executes structured test items and records outcomes."""
    plan = db.create_assessment_plan(
        AssessmentPlan(
            project_id=active_project.id,
            title="Local Privilege Escalation Security Audit",
            target="127.0.0.1",
            test_category=TestCategory.PRIVILEGE_ESCALATION,
            acceptance_criteria="No world-writable root configuration files.",
            status=AssessmentStatus.DRAFT,
        )
    )

    orchestrator = AssessmentOrchestrator(db)
    items = orchestrator.build_test_plan_items(plan)
    assert len(items) >= 2
    assert any(i.adapter_name == "verification_engine" for i in items)

    # Execute
    res = orchestrator.execute_assessment(plan=plan, project=active_project)
    assert res.assessment_id.startswith("ASM-")
    assert res.execution_uuid.startswith("EXEC-")
    assert res.status in (TestExecutionState.PASSED, TestExecutionState.FAILED)
    assert res.total_tests == len(items)
    assert len(res.steps) == len(items)

    # Database updated
    updated_plan = db.get_assessment_plan(plan.id)
    assert updated_plan.status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED)


def test_assessment_orchestrator_blocks_unauthorized_target(db: Database, active_project: Project):
    """Orchestrator must fail closed and mark execution BLOCKED for out-of-scope targets."""
    plan = db.create_assessment_plan(
        AssessmentPlan(
            project_id=active_project.id,
            title="Out-of-Scope Target Attempt",
            target="192.168.200.5",
            test_category=TestCategory.PRIVILEGE_ESCALATION,
            acceptance_criteria="Will not run.",
            status=AssessmentStatus.DRAFT,
        )
    )

    orchestrator = AssessmentOrchestrator(db)
    res = orchestrator.execute_assessment(plan=plan, project=active_project)
    assert res.status == TestExecutionState.BLOCKED
    assert res.error is not None
    assert "not in authorized scope" in res.error

    # Plan state in DB
    updated_plan = db.get_assessment_plan(plan.id)
    assert updated_plan.status == AssessmentStatus.BLOCKED


def test_assessment_orchestrator_enforces_prerequisites(db: Database, active_project: Project):
    """Downstream tests must be blocked when their prerequisite dependency fails."""
    plan = db.create_assessment_plan(
        AssessmentPlan(
            project_id=active_project.id,
            title="Prerequisite Dependency Assessment",
            target="127.0.0.1",
            test_category=TestCategory.ACTIVE_DIRECTORY,
            acceptance_criteria="Dependent steps must obey prerequisite outcome.",
            status=AssessmentStatus.DRAFT,
        )
    )

    orchestrator = AssessmentOrchestrator(db)
    # Define custom tests with a prerequisite chain
    test1 = AssessmentTestItem(
        test_id="STEP-1",
        name="Step 1 Initial Check",
        category=TestCategory.ACTIVE_DIRECTORY,
        target="127.0.0.1",
        adapter_name="verification_engine",
        options={"action": "unknown_action_forces_error"},
    )
    test2 = AssessmentTestItem(
        test_id="STEP-2",
        name="Step 2 Dependent Action",
        category=TestCategory.ACTIVE_DIRECTORY,
        target="127.0.0.1",
        adapter_name="verification_engine",
        prerequisites=["STEP-1"],
    )

    res = orchestrator.execute_assessment(
        plan=plan, project=active_project, custom_tests=[test1, test2]
    )
    assert res.total_tests == 2
    step1 = next(s for s in res.steps if s.test_id == "STEP-1")
    step2 = next(s for s in res.steps if s.test_id == "STEP-2")
    assert step1.state == TestExecutionState.ERROR
    # Step 2 must be BLOCKED because Step 1 did not PASS
    assert step2.state == TestExecutionState.BLOCKED
    assert "Prerequisite tests not passed" in step2.blocker_reason


def test_assessment_orchestrator_prevents_duplicate_concurrent_runs(db: Database, active_project: Project):
    """Starting a second run of the same active plan must raise a RuntimeError."""
    plan = db.create_assessment_plan(
        AssessmentPlan(
            project_id=active_project.id,
            title="Concurrency Guard Assessment",
            target="127.0.0.1",
            test_category=TestCategory.PRIVILEGE_ESCALATION,
            status=AssessmentStatus.DRAFT,
        )
    )

    orchestrator = AssessmentOrchestrator(db)

    # Manually register an active run
    fake_run_id = f"ASM-{plan.id}-test"
    with AssessmentOrchestrator._run_lock:
        AssessmentOrchestrator._active_runs[fake_run_id] = None

    # Attempting to execute with plan.id should now be rejected if registered with plan_id
    from core.assessment_orchestrator import AssessmentRunResult
    dummy_run = AssessmentRunResult(
        assessment_id=fake_run_id,
        execution_uuid="EXEC-test",
        project_id=active_project.id,
        plan_id=plan.id,
        status=TestExecutionState.RUNNING,
        started_at="2026-10-22",
    )
    with AssessmentOrchestrator._run_lock:
        AssessmentOrchestrator._active_runs[fake_run_id] = dummy_run

    try:
        with pytest.raises(RuntimeError) as exc_info:
            orchestrator.execute_assessment(plan=plan, project=active_project)
        assert "is already actively running" in str(exc_info.value)
    finally:
        with AssessmentOrchestrator._run_lock:
            AssessmentOrchestrator._active_runs.pop(fake_run_id, None)

