#!/usr/bin/env python3

"""Regression tests for Scan Policy Scheduling V1 calculation semantics."""

from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scan_coordination.scheduling import (
    ScheduleValidationError,
    next_cron_occurrence,
)


def expect_schedule_error(operation):
    rejected = False

    try:
        operation()
    except ScheduleValidationError:
        rejected = True

    assert rejected is True


def test_standard_utc_schedule():
    result = next_cron_occurrence(
        "0 9 * * *",
        "UTC",
        datetime(
            2026,
            1,
            10,
            8,
            30,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        1,
        10,
        9,
        0,
        tzinfo=timezone.utc,
    )


def test_occurrence_is_strictly_after_reference():
    result = next_cron_occurrence(
        "0 9 * * *",
        "UTC",
        datetime(
            2026,
            1,
            10,
            9,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        1,
        11,
        9,
        0,
        tzinfo=timezone.utc,
    )


def test_london_winter_conversion():
    result = next_cron_occurrence(
        "0 9 * * *",
        "Europe/London",
        datetime(
            2026,
            1,
            10,
            8,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        1,
        10,
        9,
        0,
        tzinfo=timezone.utc,
    )


def test_london_summer_conversion():
    result = next_cron_occurrence(
        "0 9 * * *",
        "Europe/London",
        datetime(
            2026,
            7,
            10,
            7,
            0,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        7,
        10,
        8,
        0,
        tzinfo=timezone.utc,
    )


def test_london_spring_forward_skips_nonexistent_local_time():
    result = next_cron_occurrence(
        "30 1 * * *",
        "Europe/London",
        datetime(
            2026,
            3,
            29,
            0,
            30,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        3,
        30,
        0,
        30,
        tzinfo=timezone.utc,
    )


def test_london_fall_back_produces_one_occurrence():
    reference = datetime(
        2026,
        10,
        25,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first = next_cron_occurrence(
        "30 1 * * *",
        "Europe/London",
        reference,
    )

    second = next_cron_occurrence(
        "30 1 * * *",
        "Europe/London",
        first,
    )

    assert first == datetime(
        2026,
        10,
        25,
        0,
        30,
        tzinfo=timezone.utc,
    )

    assert second == datetime(
        2026,
        10,
        26,
        1,
        30,
        tzinfo=timezone.utc,
    )


def test_london_fall_back_does_not_use_second_fold():
    result = next_cron_occurrence(
        "30 1 * * *",
        "Europe/London",
        datetime(
            2026,
            10,
            25,
            1,
            15,
            tzinfo=timezone.utc,
        ),
    )

    assert result == datetime(
        2026,
        10,
        26,
        1,
        30,
        tzinfo=timezone.utc,
    )


def test_invalid_timezone_is_rejected():
    expect_schedule_error(
        lambda: next_cron_occurrence(
            "0 9 * * *",
            "Europe/Not-A-Real-Zone",
            datetime(
                2026,
                1,
                10,
                8,
                0,
                tzinfo=timezone.utc,
            ),
        )
    )


def test_naive_reference_time_is_rejected():
    expect_schedule_error(
        lambda: next_cron_occurrence(
            "0 9 * * *",
            "UTC",
            datetime(2026, 1, 10, 8, 0),
        )
    )


def test_non_five_field_cron_is_rejected():
    expect_schedule_error(
        lambda: next_cron_occurrence(
            "0 9 * * * *",
            "UTC",
            datetime(
                2026,
                1,
                10,
                8,
                0,
                tzinfo=timezone.utc,
            ),
        )
    )


def test_impossible_calendar_expression_is_rejected():
    expect_schedule_error(
        lambda: next_cron_occurrence(
            "0 0 31 2 *",
            "UTC",
            datetime(
                2026,
                1,
                1,
                0,
                0,
                tzinfo=timezone.utc,
            ),
        )
    )


def main():
    test_standard_utc_schedule()
    print("PASS: standard UTC cron occurrence is calculated")

    test_occurrence_is_strictly_after_reference()
    print("PASS: next occurrence is strictly after reference time")

    test_london_winter_conversion()
    print("PASS: Europe/London winter occurrence converts correctly")

    test_london_summer_conversion()
    print("PASS: Europe/London summer occurrence converts correctly")

    test_london_spring_forward_skips_nonexistent_local_time()
    print(
        "PASS: Europe/London spring-forward skips nonexistent local time"
    )

    test_london_fall_back_produces_one_occurrence()
    print(
        "PASS: Europe/London fall-back produces one scheduled occurrence"
    )

    test_london_fall_back_does_not_use_second_fold()
    print(
        "PASS: Europe/London fall-back never schedules the second fold"
    )

    test_invalid_timezone_is_rejected()
    print("PASS: invalid IANA timezone is rejected")

    test_naive_reference_time_is_rejected()
    print("PASS: timezone-naive reference time is rejected")

    test_non_five_field_cron_is_rejected()
    print("PASS: non-five-field cron expression is rejected")

    test_impossible_calendar_expression_is_rejected()
    print("PASS: impossible calendar cron expression is rejected")


if __name__ == "__main__":
    main()
