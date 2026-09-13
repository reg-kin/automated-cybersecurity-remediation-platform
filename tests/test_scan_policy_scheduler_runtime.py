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


def test_run_once_initialises_then_processes_due_work():
    conn = FakeConnection()

    initialisation_results = [
        {
            "action": "INITIALISED",
            "scan_policy_id": 100,
            "reference_time": "reference",
            "next_run_at": "future",
        },
        None,
    ]

    scheduling_results = [
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

    initialise_calls = []
    schedule_calls = []

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(received_conn, *, excluded_policy_ids=None):
            assert received_conn is conn
            initialise_calls.append(True)
            return initialisation_results.pop(0)

        def fake_schedule(received_conn, *, excluded_policy_ids=None):
            assert received_conn is conn
            schedule_calls.append(True)
            return scheduling_results.pop(0)

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
        )

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

        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "INITIALISED": 1,
        "CREATED": 1,
        "ADVANCED_EXISTING": 1,
    }

    assert len(initialise_calls) == 2
    assert len(schedule_calls) == 3

    # Every initialisation/scheduling operation is an independent
    # transaction, including each final no-work check.
    assert conn.enter_count == 5
    assert conn.exit_count == 5
    assert conn.rollback_exit_count == 0
    assert conn.closed is True


def test_run_once_batch_limit_includes_initialisation():
    conn = FakeConnection()

    initialise_calls = 0
    schedule_calls = 0

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(received_conn, *, excluded_policy_ids=None):
            nonlocal initialise_calls

            assert received_conn is conn

            initialise_calls += 1

            return {
                "action": "INITIALISED",
                "scan_policy_id": initialise_calls,
                "reference_time": "reference",
                "next_run_at": "future",
            }

        def fake_schedule(received_conn, *, excluded_policy_ids=None):
            nonlocal schedule_calls

            assert received_conn is conn

            schedule_calls += 1

            return None

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
        )

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

        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "INITIALISED": 2,
    }

    assert initialise_calls == 2
    assert schedule_calls == 0

    assert conn.enter_count == 2
    assert conn.exit_count == 2
    assert conn.rollback_exit_count == 0
    assert conn.closed is True


def test_run_once_rolls_back_failed_initialisation():
    conn = FakeConnection()

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(received_conn, *, excluded_policy_ids=None):
            assert received_conn is conn

            raise RuntimeError(
                "simulated initialisation failure"
            )

        def fake_schedule(received_conn, *, excluded_policy_ids=None):
            raise AssertionError(
                "Due scheduling must not run after "
                "initialisation failure"
            )

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
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
                "simulated initialisation failure"
            )

        else:
            raise AssertionError(
                "Expected initialisation failure "
                "to propagate from run_once"
            )

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )

        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert conn.enter_count == 1
    assert conn.exit_count == 1
    assert conn.rollback_exit_count == 1
    assert conn.closed is True


def test_run_once_rolls_back_failed_due_scheduling():
    conn = FakeConnection()

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(received_conn, *, excluded_policy_ids=None):
            assert received_conn is conn
            return None

        def fake_schedule(received_conn, *, excluded_policy_ids=None):
            assert received_conn is conn

            raise RuntimeError(
                "simulated scheduling failure"
            )

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
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

        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )

        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    # First transaction is the successful no-work initialisation
    # check. The second transaction is the failed due-scheduling
    # operation.
    assert conn.enter_count == 2
    assert conn.exit_count == 2
    assert conn.rollback_exit_count == 1
    assert conn.closed is True



def test_run_once_bad_initialisation_does_not_starve_later_policy():
    conn = FakeConnection()

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    initialise_calls = []
    policy_101_initialised = False

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            nonlocal policy_101_initialised

            assert received_conn is conn

            excluded = set(
                excluded_policy_ids or set()
            )
            initialise_calls.append(excluded)

            if 100 not in excluded:
                exc = (
                    scheduler_runner
                    .POLICY_LOCAL_SCHEDULER_ERRORS[0](
                        "invalid cron"
                    )
                )
                exc.scan_policy_id = 100
                exc.scheduler_operation = "INITIALISE"
                raise exc

            if not policy_101_initialised:
                policy_101_initialised = True
                return {
                    "action": "INITIALISED",
                    "scan_policy_id": 101,
                    "reference_time": "reference",
                    "next_run_at": "future",
                }

            return None

        def fake_schedule(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            assert received_conn is conn
            return None

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        summary = scheduler_runner.run_once(5)

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )
        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "INITIALISATION_FAILED": 1,
        "INITIALISED": 1,
    }

    assert initialise_calls == [
        set(),
        {100},
        {100},
    ]

    # Failed policy-local attempt rolls back. The successful
    # initialisation and both no-work checks commit normally.
    assert conn.enter_count == 4
    assert conn.exit_count == 4
    assert conn.rollback_exit_count == 1
    assert conn.closed is True


def test_run_once_bad_due_policy_does_not_starve_later_policy():
    conn = FakeConnection()

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    schedule_calls = []
    policy_201_scheduled = False

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            assert received_conn is conn
            return None

        def fake_schedule(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            nonlocal policy_201_scheduled

            assert received_conn is conn

            excluded = set(
                excluded_policy_ids or set()
            )
            schedule_calls.append(excluded)

            if 200 not in excluded:
                exc = (
                    scheduler_runner
                    .POLICY_LOCAL_SCHEDULER_ERRORS[1](
                        "subject cannot be resolved"
                    )
                )
                exc.scan_policy_id = 200
                exc.scheduler_operation = "SCHEDULE"
                raise exc

            if not policy_201_scheduled:
                policy_201_scheduled = True
                return {
                    "action": "CREATED",
                    "scan_policy_id": 201,
                    "scan_execution_id": 301,
                    "scheduled_for": "one",
                    "next_run_at": "two",
                }

            return None

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        summary = scheduler_runner.run_once(5)

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )
        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "SCHEDULING_FAILED": 1,
        "CREATED": 1,
    }

    assert schedule_calls == [
        set(),
        {200},
        {200},
    ]

    # Initialisation no-work check, failed due attempt,
    # successful due attempt and final due no-work check.
    assert conn.enter_count == 4
    assert conn.exit_count == 4
    assert conn.rollback_exit_count == 1
    assert conn.closed is True



def test_run_once_policy_local_failure_consumes_batch_capacity():
    conn = FakeConnection()

    original_connect = scheduler_runner.db.connect
    original_initialise = (
        scheduler_runner.initialise_next_scan_policy
    )
    original_schedule = (
        scheduler_runner.schedule_next_due_policy
    )

    initialise_calls = 0
    schedule_calls = 0

    try:
        scheduler_runner.db.connect = lambda: conn

        def fake_initialise(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            nonlocal initialise_calls

            assert received_conn is conn
            assert excluded_policy_ids == set()

            initialise_calls += 1

            exc = (
                scheduler_runner
                .POLICY_LOCAL_SCHEDULER_ERRORS[0](
                    "invalid cron"
                )
            )
            exc.scan_policy_id = 100
            exc.scheduler_operation = "INITIALISE"
            raise exc

        def fake_schedule(
            received_conn,
            *,
            excluded_policy_ids=None,
        ):
            nonlocal schedule_calls
            schedule_calls += 1

            raise AssertionError(
                "Due scheduling must not run after the "
                "failed initialisation attempt consumes "
                "the complete batch"
            )

        scheduler_runner.initialise_next_scan_policy = (
            fake_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            fake_schedule
        )

        summary = scheduler_runner.run_once(1)

    finally:
        scheduler_runner.db.connect = (
            original_connect
        )
        scheduler_runner.initialise_next_scan_policy = (
            original_initialise
        )
        scheduler_runner.schedule_next_due_policy = (
            original_schedule
        )

    assert summary == {
        "INITIALISATION_FAILED": 1,
    }

    assert initialise_calls == 1
    assert schedule_calls == 0

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
    test_run_once_initialises_then_processes_due_work()
    test_run_once_batch_limit_includes_initialisation()
    test_run_once_rolls_back_failed_initialisation()
    test_run_once_rolls_back_failed_due_scheduling()
    test_run_once_bad_initialisation_does_not_starve_later_policy()
    test_run_once_bad_due_policy_does_not_starve_later_policy()
    test_run_once_policy_local_failure_consumes_batch_capacity()
    test_invalid_batch_size()

    print(
        "PASS: scan policy scheduler runtime "
        "regression tests completed successfully."
    )


if __name__ == "__main__":
    main()
