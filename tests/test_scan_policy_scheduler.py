#!/usr/bin/env python3

"""Regression tests for deterministic Scan Policy Scheduling V1."""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination.scheduler import (
    _load_next_due_policy,
    _load_next_uninitialised_policy,
    initialise_next_scan_policy,
    schedule_next_due_policy,
)
from scan_coordination.scheduling import next_cron_occurrence
from scan_coordination.service import create_scan_execution
from scan_coordination.subject_resolver import (
    ScanSubjectNotResolvableError,
)


PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.getenv(
        "PG_USER",
        "telemetry_admin",
    ),
    "password": os.getenv(
        "PG_PASSWORD",
        "",
    ),
}


TENANT = "SCAN-POLICY-SCHEDULER-TEST"
NODE_PREFIX = "scan-policy-scheduler-"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM scan_executions
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM scan_policies
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM scan_execution_node_assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM scan_execution_nodes
            WHERE node_code LIKE %s
            """,
            (f"{NODE_PREFIX}%",),
        )


def create_asset(
    conn,
    *,
    canonical_name,
    lifecycle_status="ACTIVE",
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (
                tenant_code,
                asset_type,
                canonical_name,
                inventory_state,
                lifecycle_status
            )
            VALUES (
                %s,
                'HOST',
                %s,
                'PROVISIONAL',
                %s
            )
            RETURNING asset_id
            """,
            (
                TENANT,
                canonical_name,
                lifecycle_status,
            ),
        )

        return cur.fetchone()[0]


def add_identifier(
    conn,
    *,
    asset_id,
    identifier_type,
    identifier_value,
    normalized_value=None,
    confidence="HIGH",
    is_authoritative=False,
):
    if normalized_value is None:
        normalized_value = identifier_value

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO asset_identifiers (
                asset_id,
                tenant_code,
                identifier_type,
                identifier_value,
                normalized_value,
                source,
                confidence,
                is_authoritative,
                is_active
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                'scan_policy_scheduler_test',
                %s,
                %s,
                TRUE
            )
            """,
            (
                asset_id,
                TENANT,
                identifier_type,
                identifier_value,
                normalized_value,
                confidence,
                is_authoritative,
            ),
        )


def create_node(
    conn,
    *,
    node_code,
    scanner_type="nmap_nse",
    execution_model="REMOTE_TARGET",
    priority=10,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_execution_nodes (
                node_code,
                display_name,
                transport_mode,
                is_enabled
            )
            VALUES (
                %s,
                %s,
                'PULL',
                TRUE
            )
            RETURNING execution_node_id
            """,
            (
                node_code,
                node_code,
            ),
        )

        node_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO scan_execution_node_capabilities (
                execution_node_id,
                scanner_type,
                execution_model,
                priority,
                is_enabled
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                TRUE
            )
            """,
            (
                node_id,
                scanner_type,
                execution_model,
                priority,
            ),
        )

    return node_id


def create_policy(
    conn,
    *,
    asset_id,
    profile_name,
    next_run_at,
    scanner_type="nmap_nse",
    schedule_type="CRON",
    schedule_expression="*/5 * * * *",
    schedule_timezone="UTC",
    enabled=True,
):
    if schedule_type == "MANUAL":
        schedule_expression = None
        next_run_at = None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_policies (
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled
            )
            VALUES (
                %s,
                %s,
                %s,
                'GOLD',
                %s,
                '{}'::jsonb,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING scan_policy_id
            """,
            (
                TENANT,
                asset_id,
                scanner_type,
                profile_name,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                enabled,
            ),
        )

        return cur.fetchone()[0]


def load_policy_next_run(conn, *, scan_policy_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT next_run_at
            FROM scan_policies
            WHERE scan_policy_id = %s
            """,
            (scan_policy_id,),
        )

        row = cur.fetchone()

    assert row is not None
    return row[0]


def load_policy_executions(conn, *, scan_policy_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                scan_execution_id,
                status,
                scheduled_for,
                scanner_subject_type,
                scanner_subject_value
            FROM scan_executions
            WHERE scan_policy_id = %s
            ORDER BY scan_execution_id
            """,
            (scan_policy_id,),
        )

        return cur.fetchall()


def make_nmap_policy(
    conn,
    *,
    suffix,
    next_run_at,
    enabled=True,
    schedule_type="CRON",
    with_identifier=True,
):
    asset_id = create_asset(
        conn,
        canonical_name=f"scan-policy-scheduler-{suffix}",
    )

    if with_identifier:
        add_identifier(
            conn,
            asset_id=asset_id,
            identifier_type="IP_ADDRESS",
            identifier_value=f"192.0.2.{suffix}",
            confidence="HIGH",
        )

    policy_id = create_policy(
        conn,
        asset_id=asset_id,
        profile_name=f"scheduler-{suffix}",
        next_run_at=next_run_at,
        enabled=enabled,
        schedule_type=schedule_type,
    )

    return asset_id, policy_id


def test_policy_initialisation(conn):
    """Verify first-occurrence initialisation semantics."""

    clean_database(conn)

    asset_id = create_asset(
        conn,
        canonical_name="initialisation-host",
    )

    # Enabled CRON + NULL is initialised.
    enabled_policy = create_policy(
        conn,
        asset_id=asset_id,
        profile_name="initialisation-enabled",
        scanner_type="nmap_nse",
        next_run_at=None,
    )

    with conn:
        result = initialise_next_scan_policy(conn)

    assert result is not None
    assert result["action"] == "INITIALISED"
    assert result["scan_policy_id"] == enabled_policy

    expected = next_cron_occurrence(
        "*/5 * * * *",
        "UTC",
        result["reference_time"],
    )

    assert result["next_run_at"] == expected
    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=enabled_policy,
        )
        == expected
    )

    # Initialisation itself must never create an execution.
    assert load_policy_executions(
        conn,
        scan_policy_id=enabled_policy,
    ) == []

    # An already initialised policy is not touched.
    with conn:
        result = initialise_next_scan_policy(conn)

    assert result is None

    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=enabled_policy,
        )
        == expected
    )

    # MANUAL policies remain NULL and are ignored.
    manual_policy = create_policy(
        conn,
        asset_id=asset_id,
        profile_name="initialisation-manual",
        scanner_type="nmap_nse",
        schedule_type="MANUAL",
        next_run_at=None,
    )

    with conn:
        result = initialise_next_scan_policy(conn)

    assert result is None
    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=manual_policy,
        )
        is None
    )

    # Disabled CRON policies remain NULL and are ignored.
    disabled_policy = create_policy(
        conn,
        asset_id=asset_id,
        profile_name="initialisation-disabled",
        scanner_type="nmap_nse",
        next_run_at=None,
        enabled=False,
    )

    with conn:
        result = initialise_next_scan_policy(conn)

    assert result is None
    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=disabled_policy,
        )
        is None
    )

    # Invalid schedule calculation must roll the transaction back and
    # preserve the NULL pointer. Persist the deliberately invalid policy
    # first so the failed scheduler transaction cannot roll back the test
    # fixture itself.
    with conn:
        invalid_policy = create_policy(
            conn,
            asset_id=asset_id,
            profile_name="initialisation-invalid",
            scanner_type="nmap_nse",
            next_run_at=None,
            schedule_expression="not a cron expression",
        )

    try:
        with conn:
            initialise_next_scan_policy(conn)
    except Exception:
        pass
    else:
        raise AssertionError(
            "Expected invalid CRON policy initialisation to fail"
        )

    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=invalid_policy,
        )
        is None
    )

    # Prevent the deliberately invalid policy from interfering with the
    # existing scheduler regression flow.
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_policies
                SET is_enabled = FALSE
                WHERE scan_policy_id = %s
                """,
                (invalid_policy,),
            )

    # Cycle-local exclusion skips an earlier uninitialised policy
    # without modifying it and allows the next eligible policy to proceed.
    with conn:
        _, excluded_initialisation_policy = make_nmap_policy(
            conn,
            suffix="31",
            next_run_at=None,
        )
        _, selected_initialisation_policy = make_nmap_policy(
            conn,
            suffix="32",
            next_run_at=None,
        )

    with conn:
        result = initialise_next_scan_policy(
            conn,
            excluded_policy_ids={
                excluded_initialisation_policy,
            },
        )

    assert result is not None
    assert result["action"] == "INITIALISED"
    assert (
        result["scan_policy_id"]
        == selected_initialisation_policy
    )

    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=excluded_initialisation_policy,
        )
        is None
    )

    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=selected_initialisation_policy,
        )
        == result["next_run_at"]
    )

    assert load_policy_executions(
        conn,
        scan_policy_id=excluded_initialisation_policy,
    ) == []

    assert load_policy_executions(
        conn,
        scan_policy_id=selected_initialisation_policy,
    ) == []

    print(
        "PASS: initialisation exclusion selects the next "
        "eligible policy"
    )

    clean_database(conn)


def test_scheduler_skip_locked_concurrency(conn):
    """Verify concurrent scheduler sessions skip already locked policies."""

    clean_database(conn)

    # --------------------------------------------------------------
    # 1. Concurrent initialisation selectors choose different rows.
    # --------------------------------------------------------------
    with conn:
        _, initialisation_policy_1 = make_nmap_policy(
            conn,
            suffix="41",
            next_run_at=None,
        )
        _, initialisation_policy_2 = make_nmap_policy(
            conn,
            suffix="42",
            next_run_at=None,
        )

    conn_a = psycopg2.connect(**PG)
    conn_b = psycopg2.connect(**PG)

    try:
        selected_a = _load_next_uninitialised_policy(conn_a)

        assert selected_a is not None
        assert (
            selected_a["scan_policy_id"]
            == initialisation_policy_1
        )

        # conn_a deliberately remains in its transaction and therefore
        # continues to hold the row lock on initialisation_policy_1.
        selected_b = _load_next_uninitialised_policy(conn_b)

        assert selected_b is not None
        assert (
            selected_b["scan_policy_id"]
            == initialisation_policy_2
        )

        conn_b.rollback()
        conn_a.rollback()

    finally:
        conn_b.close()
        conn_a.close()

    print(
        "PASS: concurrent initialisation selectors use "
        "FOR UPDATE SKIP LOCKED"
    )

    # Neither selector transaction committed a state change.
    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=initialisation_policy_1,
        )
        is None
    )
    assert (
        load_policy_next_run(
            conn,
            scan_policy_id=initialisation_policy_2,
        )
        is None
    )

    clean_database(conn)

    # --------------------------------------------------------------
    # 2. Concurrent due selectors choose different rows.
    # --------------------------------------------------------------
    now = datetime.now(timezone.utc)

    due_1 = (
        now - timedelta(hours=2)
    ).replace(
        second=0,
        microsecond=0,
    )

    due_2 = (
        now - timedelta(hours=1)
    ).replace(
        second=0,
        microsecond=0,
    )

    with conn:
        _, due_policy_1 = make_nmap_policy(
            conn,
            suffix="43",
            next_run_at=due_1,
        )
        _, due_policy_2 = make_nmap_policy(
            conn,
            suffix="44",
            next_run_at=due_2,
        )

    conn_a = psycopg2.connect(**PG)
    conn_b = psycopg2.connect(**PG)

    try:
        selected_a = _load_next_due_policy(conn_a)

        assert selected_a is not None
        assert selected_a["scan_policy_id"] == due_policy_1

        # conn_a deliberately retains its transaction and row lock.
        # conn_b must not wait for that row: SKIP LOCKED must cause it
        # to select the next eligible due policy.
        selected_b = _load_next_due_policy(conn_b)

        assert selected_b is not None
        assert selected_b["scan_policy_id"] == due_policy_2

        conn_b.rollback()
        conn_a.rollback()

    finally:
        conn_b.close()
        conn_a.close()

    print(
        "PASS: concurrent due selectors use "
        "FOR UPDATE SKIP LOCKED"
    )

    clean_database(conn)


def main():
    conn = psycopg2.connect(**PG)

    try:
        test_policy_initialisation(conn)
        test_scheduler_skip_locked_concurrency(conn)

        with conn:
            clean_database(conn)

            create_node(
                conn,
                node_code=f"{NODE_PREFIX}nmap",
            )

        now = datetime.now(timezone.utc)

        # Use minute-aligned occurrences so expected cron calculations are
        # deterministic and independent of test execution seconds.
        due_1 = (
            now - timedelta(hours=2)
        ).replace(
            second=0,
            microsecond=0,
        )

        due_2 = (
            now - timedelta(hours=1)
        ).replace(
            second=0,
            microsecond=0,
        )

        future = (
            now + timedelta(hours=2)
        ).replace(
            second=0,
            microsecond=0,
        )

        # --------------------------------------------------------------
        # 0. Cycle-local exclusion skips the oldest due policy.
        # --------------------------------------------------------------
        with conn:
            _, excluded_due_policy = make_nmap_policy(
                conn,
                suffix="33",
                next_run_at=due_1,
            )
            _, selected_due_policy = make_nmap_policy(
                conn,
                suffix="34",
                next_run_at=due_2,
            )

        with conn:
            result = schedule_next_due_policy(
                conn,
                excluded_policy_ids={
                    excluded_due_policy,
                },
            )

        assert result is not None
        assert result["action"] == "CREATED"
        assert result["scan_policy_id"] == selected_due_policy
        assert result["scheduled_for"] == due_2

        # The excluded occurrence remains completely untouched.
        assert (
            load_policy_next_run(
                conn,
                scan_policy_id=excluded_due_policy,
            )
            == due_1
        )
        assert load_policy_executions(
            conn,
            scan_policy_id=excluded_due_policy,
        ) == []

        selected_executions = load_policy_executions(
            conn,
            scan_policy_id=selected_due_policy,
        )

        assert len(selected_executions) == 1
        assert selected_executions[0][1] == "PENDING"
        assert selected_executions[0][2] == due_2

        print(
            "PASS: due-policy exclusion selects the next "
            "eligible occurrence"
        )

        # Prevent both exclusion-test policies from participating in
        # the existing sequential scheduler regression cases below.
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'SUCCEEDED'
                    WHERE scan_policy_id = %s
                    """,
                    (selected_due_policy,),
                )

                cur.execute(
                    """
                    UPDATE scan_policies
                    SET next_run_at = %s
                    WHERE scan_policy_id IN (%s, %s)
                    """,
                    (
                        future,
                        excluded_due_policy,
                        selected_due_policy,
                    ),
                )

        # --------------------------------------------------------------
        # 1. A due enabled CRON policy creates exactly one execution.
        # --------------------------------------------------------------
        with conn:
            _, policy_id = make_nmap_policy(
                conn,
                suffix="11",
                next_run_at=due_1,
            )

        expected_next = next_cron_occurrence(
            "*/5 * * * *",
            "UTC",
            due_1,
        )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is not None
        assert result["action"] == "CREATED"
        assert result["scan_policy_id"] == policy_id
        assert result["scheduled_for"] == due_1
        assert result["next_run_at"] == expected_next
        assert result["scanner_type"] == "nmap_nse"
        assert result["scanner_subject_type"] == "IP_ADDRESS"
        assert result["scanner_subject_value"] == "192.0.2.11"
        assert result["status"] == "PENDING"

        with conn:
            executions = load_policy_executions(
                conn,
                scan_policy_id=policy_id,
            )

            assert len(executions) == 1
            assert executions[0][1] == "PENDING"
            assert executions[0][2] == due_1
            assert executions[0][3] == "IP_ADDRESS"
            assert executions[0][4] == "192.0.2.11"

            assert load_policy_next_run(
                conn,
                scan_policy_id=policy_id,
            ) == expected_next

        print(
            "PASS: due CRON policy creates one deterministic execution"
        )

        # --------------------------------------------------------------
        # Prevent the first policy from participating in later tests.
        # --------------------------------------------------------------
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'SUCCEEDED'
                    WHERE scan_policy_id = %s
                    """,
                    (policy_id,),
                )

                cur.execute(
                    """
                    UPDATE scan_policies
                    SET next_run_at = %s
                    WHERE scan_policy_id = %s
                    """,
                    (
                        future,
                        policy_id,
                    ),
                )

        # --------------------------------------------------------------
        # 2. A future CRON occurrence is not materialised.
        # --------------------------------------------------------------
        with conn:
            _, future_policy_id = make_nmap_policy(
                conn,
                suffix="12",
                next_run_at=future,
            )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is None

        with conn:
            assert load_policy_executions(
                conn,
                scan_policy_id=future_policy_id,
            ) == []

            assert load_policy_next_run(
                conn,
                scan_policy_id=future_policy_id,
            ) == future

        print("PASS: future CRON policy is not scheduled early")

        # --------------------------------------------------------------
        # 3. MANUAL policies never enter automatic scheduling.
        # --------------------------------------------------------------
        with conn:
            _, manual_policy_id = make_nmap_policy(
                conn,
                suffix="13",
                next_run_at=None,
                schedule_type="MANUAL",
            )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is None

        with conn:
            assert load_policy_executions(
                conn,
                scan_policy_id=manual_policy_id,
            ) == []

            assert load_policy_next_run(
                conn,
                scan_policy_id=manual_policy_id,
            ) is None

        print("PASS: MANUAL policy is excluded from scheduling")

        # --------------------------------------------------------------
        # 4. Disabled CRON policies generate no work.
        # --------------------------------------------------------------
        with conn:
            _, disabled_policy_id = make_nmap_policy(
                conn,
                suffix="14",
                next_run_at=due_1,
                enabled=False,
            )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is None

        with conn:
            assert load_policy_executions(
                conn,
                scan_policy_id=disabled_policy_id,
            ) == []

            assert load_policy_next_run(
                conn,
                scan_policy_id=disabled_policy_id,
            ) == due_1

        print("PASS: disabled CRON policy is excluded from scheduling")

        # --------------------------------------------------------------
        # 5. An active earlier execution defers the next occurrence.
        # --------------------------------------------------------------
        with conn:
            _, active_policy_id = make_nmap_policy(
                conn,
                suffix="15",
                next_run_at=due_2,
            )

            create_scan_execution(
                conn,
                scan_policy_id=active_policy_id,
                scanner_subject_type="IP_ADDRESS",
                scanner_subject_value="192.0.2.15",
                scheduled_for=due_1,
            )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is None

        with conn:
            active_executions = load_policy_executions(
                conn,
                scan_policy_id=active_policy_id,
            )

            assert len(active_executions) == 1
            assert active_executions[0][1] == "PENDING"
            assert active_executions[0][2] == due_1

            assert load_policy_next_run(
                conn,
                scan_policy_id=active_policy_id,
            ) == due_2

        print(
            "PASS: active execution defers due occurrence without "
            "advancing next_run_at"
        )

        # --------------------------------------------------------------
        # 6. Once the earlier execution is terminal, catch-up proceeds.
        # --------------------------------------------------------------
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'SUCCEEDED'
                    WHERE scan_policy_id = %s
                    """,
                    (active_policy_id,),
                )

        expected_catchup_next = next_cron_occurrence(
            "*/5 * * * *",
            "UTC",
            due_2,
        )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is not None
        assert result["action"] == "CREATED"
        assert result["scan_policy_id"] == active_policy_id
        assert result["scheduled_for"] == due_2
        assert result["next_run_at"] == expected_catchup_next

        with conn:
            executions = load_policy_executions(
                conn,
                scan_policy_id=active_policy_id,
            )

            assert len(executions) == 2
            assert executions[0][1] == "SUCCEEDED"
            assert executions[0][2] == due_1
            assert executions[1][1] == "PENDING"
            assert executions[1][2] == due_2

        print(
            "PASS: terminal earlier execution allows deterministic catch-up"
        )

        # Remove this active execution before the remaining tests.
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'SUCCEEDED'
                    WHERE scan_policy_id = %s
                      AND status = 'PENDING'
                    """,
                    (active_policy_id,),
                )

                cur.execute(
                    """
                    UPDATE scan_policies
                    SET next_run_at = %s
                    WHERE scan_policy_id = %s
                    """,
                    (
                        future,
                        active_policy_id,
                    ),
                )

        # --------------------------------------------------------------
        # 7. A stale next_run_at does not recreate an existing terminal
        #    occurrence. It advances the policy instead.
        # --------------------------------------------------------------
        with conn:
            _, stale_policy_id = make_nmap_policy(
                conn,
                suffix="16",
                next_run_at=due_1,
            )

            existing = create_scan_execution(
                conn,
                scan_policy_id=stale_policy_id,
                scanner_subject_type="IP_ADDRESS",
                scanner_subject_value="192.0.2.16",
                scheduled_for=due_1,
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'SUCCEEDED'
                    WHERE scan_execution_id = %s
                    """,
                    (existing["scan_execution_id"],),
                )

        expected_stale_next = next_cron_occurrence(
            "*/5 * * * *",
            "UTC",
            due_1,
        )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is not None
        assert result["action"] == "ADVANCED_EXISTING"
        assert result["scan_policy_id"] == stale_policy_id
        assert (
            result["scan_execution_id"]
            == existing["scan_execution_id"]
        )
        assert result["scheduled_for"] == due_1
        assert result["next_run_at"] == expected_stale_next
        assert result["execution_status"] == "SUCCEEDED"

        with conn:
            executions = load_policy_executions(
                conn,
                scan_policy_id=stale_policy_id,
            )

            assert len(executions) == 1
            assert (
                executions[0][0]
                == existing["scan_execution_id"]
            )

        print(
            "PASS: existing terminal occurrence is not duplicated"
        )

        # Move the stale policy out of the due set.
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_policies
                    SET next_run_at = %s
                    WHERE scan_policy_id = %s
                    """,
                    (
                        future,
                        stale_policy_id,
                    ),
                )

        # --------------------------------------------------------------
        # 8. Subject-resolution failure leaves scheduling state intact.
        # --------------------------------------------------------------
        with conn:
            _, unresolved_policy_id = make_nmap_policy(
                conn,
                suffix="17",
                next_run_at=due_1,
                with_identifier=False,
            )

        try:
            with conn:
                schedule_next_due_policy(conn)

        except ScanSubjectNotResolvableError:
            pass
        else:
            raise AssertionError(
                "Expected unresolved scanner subject to fail scheduling"
            )

        with conn:
            assert load_policy_executions(
                conn,
                scan_policy_id=unresolved_policy_id,
            ) == []

            assert load_policy_next_run(
                conn,
                scan_policy_id=unresolved_policy_id,
            ) == due_1

        print(
            "PASS: subject-resolution failure rolls back occurrence "
            "materialisation and preserves next_run_at"
        )

        # --------------------------------------------------------------
        # 9. One invocation materialises at most one due policy.
        # --------------------------------------------------------------
        with conn:
            # Disable the intentionally unresolved policy so it cannot be
            # selected before these two policies.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_policies
                    SET is_enabled = FALSE
                    WHERE scan_policy_id = %s
                    """,
                    (unresolved_policy_id,),
                )

            _, first_policy_id = make_nmap_policy(
                conn,
                suffix="18",
                next_run_at=due_1,
            )

            _, second_policy_id = make_nmap_policy(
                conn,
                suffix="19",
                next_run_at=due_2,
            )

        with conn:
            result = schedule_next_due_policy(conn)

        assert result is not None
        assert result["scan_policy_id"] == first_policy_id

        with conn:
            first_executions = load_policy_executions(
                conn,
                scan_policy_id=first_policy_id,
            )

            second_executions = load_policy_executions(
                conn,
                scan_policy_id=second_policy_id,
            )

            assert len(first_executions) == 1
            assert second_executions == []

        print(
            "PASS: scheduler invocation materialises only the oldest "
            "schedulable due policy"
        )

        print(
            "PASS: scan policy scheduler regression tests completed "
            "successfully."
        )

    finally:
        try:
            with conn:
                clean_database(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
