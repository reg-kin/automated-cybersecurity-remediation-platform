#!/usr/bin/env python3

"""Regression tests for scan-policy scheduler runtime behaviour."""

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination import scheduler_runner


class FakeConnection:
    def __init__(self):
        self.enter_count = 0
        self.exit_count = 0
        self.rollback_exit_count = 0
        self.closed = False

    def __enter__(self):
        self.enter_count += 1
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        self.exit_count += 1

        if exc_type is not None:
            self.rollback_exit_count += 1

        return False

    def close(self):
        self.closed = True


def test_env_int():
    name = "SCAN_SCHEDULER_RUNTIME_TEST_INT"

    previous = os.environ.get(name)

    try:
        os.environ.pop(
            name,
            None,
        )

        assert (
            scheduler_runner.env_int(
                name,
                17,
            )
            == 17
        )

        os.environ[name] = "23"

        assert (
            scheduler_runner.env_int(
                name,
                17,
            )
            == 23
        )

        os.environ[name] = "0"

        try:
            scheduler_runner.env_int(
                name,
                17,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "Expected minimum-value validation"
            )

        os.environ[name] = "not-an-integer"

        try:
            scheduler_runner.env_int(
                name,
                17,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "Expected integer validation"
            )

    finally:
        if previous is None:
            os.environ.pop(
                name,
                None,
            )
        else:
            os.environ[name] = previous


def test_run_once_processes_until_no_work():
    conn = FakeConnection()

    results = [
        {
            "action": "CREATED",
            "scan_policy_id": 101,
            "scan_execution_id": 201,
            "scheduled_for": "one",
            "next_run_at": "two",
        },
        {
            "action": "ADVANCED_EXISTING",
            "scan_policy_id": 102,
            "scan_execution_id": 202,
            "scheduled_for": "three",
            "next_run_at": "four",
        },
        None,
    ]

    calls = []

    original_connect = (
        scheduler_runner.db.connect
    )

    original_schedule = (
        scheduler_runner
        .schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = (
            lambda: conn
        )

        def fake_schedule(received_conn):
            assert received_conn is conn
            calls.append(True)
            return results.pop(0)

        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        summary = scheduler_runner.run_once(
            10
        )

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "CREATED": 1,
        "ADVANCED_EXISTING": 1,
    }

    assert len(calls) == 3

    # One independent transaction for each scheduler call,
    # including the final no-work check.
    assert conn.enter_count == 3
    assert conn.exit_count == 3
    assert conn.rollback_exit_count == 0
    assert conn.closed is True


def test_run_once_honours_batch_limit():
    conn = FakeConnection()

    call_count = 0

    original_connect = (
        scheduler_runner.db.connect
    )

    original_schedule = (
        scheduler_runner
        .schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = (
            lambda: conn
        )

        def fake_schedule(received_conn):
            nonlocal call_count

            assert received_conn is conn

            call_count += 1

            return {
                "action": "CREATED",
                "scan_policy_id": call_count,
                "scan_execution_id": (
                    1000 + call_count
                ),
                "scheduled_for": "one",
                "next_run_at": "two",
            }

        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        summary = scheduler_runner.run_once(
            2
        )

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "CREATED": 2,
    }

    assert call_count == 2
    assert conn.enter_count == 2
    assert conn.exit_count == 2
    assert conn.closed is True


def test_run_once_rolls_back_failed_occurrence():
    conn = FakeConnection()

    original_connect = (
        scheduler_runner.db.connect
    )

    original_schedule = (
        scheduler_runner
        .schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = (
            lambda: conn
        )

        def fake_schedule(received_conn):
            assert received_conn is conn

            raise RuntimeError(
                "simulated scheduling failure"
            )

        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        try:
            scheduler_runner.run_once(
                5
            )

        except RuntimeError as exc:
            assert str(exc) == (
                "simulated scheduling failure"
            )

        else:
            raise AssertionError(
                "Expected scheduling failure "
                "to propagate from run_once"
            )

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert conn.enter_count == 1
    assert conn.exit_count == 1
    assert conn.rollback_exit_count == 1
    assert conn.closed is True


def test_invalid_batch_size():
    for value in (
        0,
        -1,
        True,
        "5",
    ):
        try:
            scheduler_runner.run_once(
                value
            )

        except ValueError:
            pass

        else:
            raise AssertionError(
                f"Expected invalid batch_size "
                f"{value!r} to fail"
            )


def main():
    test_env_int()
    test_run_once_processes_until_no_work()
    test_run_once_honours_batch_limit()
    test_run_once_rolls_back_failed_occurrence()
    test_invalid_batch_size()

    print(
        "PASS: scan policy scheduler runtime "
        "regression tests completed successfully."
    )


if __name__ == "__main__":
    main()
