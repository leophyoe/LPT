"""Unit tests for CPENT 30-day study plan."""

from labs.cpent.study_plan import CPENT_30_DAY_PLAN


def test_study_plan_has_30_days():
    assert len(CPENT_30_DAY_PLAN) == 30

    day_numbers = [d.day for d in CPENT_30_DAY_PLAN]
    assert day_numbers == list(range(1, 31))


def test_study_plan_weeks_structure():
    week1_days = [d for d in CPENT_30_DAY_PLAN if d.week == 1]
    assert len(week1_days) == 7

    week2_days = [d for d in CPENT_30_DAY_PLAN if d.week == 2]
    assert len(week2_days) == 7

    week3_days = [d for d in CPENT_30_DAY_PLAN if d.week == 3]
    assert len(week3_days) == 7

    week4_days = [d for d in CPENT_30_DAY_PLAN if d.week == 4]
    assert len(week4_days) == 9  # Days 22 to 30


def test_study_plan_contents():
    day1 = CPENT_30_DAY_PLAN[0]
    assert day1.day == 1
    assert "Pentesting Fundamentals" in day1.title
    assert len(day1.hands_on_tasks) > 0
    assert len(day1.recommended_tools) > 0

    day30 = CPENT_30_DAY_PLAN[-1]
    assert day30.day == 30
    assert "Final Exam Readiness" in day30.title

