#!/usr/bin/env python3

"""Regression tests for deterministic Scan Coordination service."""

import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination.service import (
    ScanCoordinationConflictError,
    ScanCoordinationValidationError,
    ScanLeaseAuthenticationError,
    ScanLeaseExpiredError,
    create_scan_execution,
    expire_overdue_leases,
    lease_next_execution,
    mark_execution_started,
    mark_execution_succeeded,
    select_execution_node,
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


TENANT = "SCAN-COORD-SERVICE-TEST"


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
            WHERE node_code LIKE
                'scan-coord-service-%'
            """
        )


def create_asset(
    conn,
    *,
    canonical_name,
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
                'ACTIVE'
            )
            RETURNING asset_id
            """,
            (
                TENANT,
                canonical_name,
            ),
        )

        return cur.fetchone()[0]


def create_node(
    conn,
    *,
    node_code,
    scanner_type,
    execution_model,
    priority,
    enabled=True,
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
                %s
            )
            RETURNING execution_node_id
            """,
            (
                node_code,
                node_code,
                enabled,
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
    scanner_type,
    profile_name,
    service_tier="GOLD",
):
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
                is_enabled
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                '{"safe_test": true}'::jsonb,
                'MANUAL',
                NULL,
                'UTC',
                TRUE
            )
            RETURNING scan_policy_id
            """,
            (
                TENANT,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
            ),
        )

        return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

            asset_id = create_asset(
                conn,
                canonical_name=(
                    "scan-coordination-service-host"
                ),
            )

            preferred_node_id = create_node(
                conn,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                scanner_type="nmap_nse",
                execution_model="REMOTE_TARGET",
                priority=10,
            )

            create_node(
                conn,
                node_code=(
                    "scan-coord-service-nmap-b"
                ),
                scanner_type="nmap_nse",
                execution_model="REMOTE_TARGET",
                priority=20,
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                profile_name="default",
            )

        # --------------------------------------------------------------
        # Deterministic node selection.
        # --------------------------------------------------------------
        with conn:
            selected = select_execution_node(
                conn,
                scanner_type="nmap_nse",
                execution_model="REMOTE_TARGET",
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert (
            selected["execution_node_id"]
            == preferred_node_id
        )

        print(
            "PASS: execution-node selection prefers the "
            "lowest enabled capability priority"
        )

        # --------------------------------------------------------------
        # Scanner subject semantics are enforced.
        # --------------------------------------------------------------
        invalid_subject_blocked = False

        try:
            with conn:
                create_scan_execution(
                    conn,
                    scan_policy_id=policy_id,
                    scanner_subject_type=(
                        "CONTAINER_IMAGE"
                    ),
                    scanner_subject_value=(
                        "example/image:latest"
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
        except ScanCoordinationValidationError:
            invalid_subject_blocked = True

        assert invalid_subject_blocked is True

        print(
            "PASS: scanner coordination preserves "
            "scanner-specific subject semantics"
        )

        # --------------------------------------------------------------
        # Create one due execution.
        # --------------------------------------------------------------
        with conn:
            execution = create_scan_execution(
                conn,
                scan_policy_id=policy_id,
                scanner_subject_type="IP_ADDRESS",
                scanner_subject_value="192.0.2.55",
                scheduled_for=datetime.now(
                    timezone.utc
                ),
            )

        execution_id = execution[
            "scan_execution_id"
        ]

        assert execution["status"] == "PENDING"
        assert (
            execution["execution_node_id"]
            == preferred_node_id
        )
        assert (
            execution["scanner_parameters"]
            == {"safe_test": True}
        )

        assert execution["service_tier"] == "GOLD"

        # service_tier is execution context, not a live policy lookup.
        # Changing the policy after execution creation must not rewrite
        # the historical execution snapshot.
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_policies
                    SET service_tier = 'BRONZE'
                    WHERE scan_policy_id = %s
                    """,
                    (policy_id,),
                )

                cur.execute(
                    """
                    SELECT service_tier
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (execution_id,),
                )

                stored_execution_tier = cur.fetchone()[0]

        assert stored_execution_tier == "GOLD"

        print(
            "PASS: scan execution snapshots policy, "
            "selected node and resolved scanner subject"
        )

        duplicate_active_blocked = False

        try:
            with conn:
                create_scan_execution(
                    conn,
                    scan_policy_id=policy_id,
                    scanner_subject_type=(
                        "IP_ADDRESS"
                    ),
                    scanner_subject_value=(
                        "192.0.2.55"
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
        except ScanCoordinationConflictError:
            duplicate_active_blocked = True

        assert duplicate_active_blocked is True

        print(
            "PASS: service surfaces the database "
            "one-active-execution invariant"
        )

        # --------------------------------------------------------------
        # Assigned node atomically leases its job.
        # --------------------------------------------------------------
        with conn:
            leased = lease_next_execution(
                conn,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_seconds=300,
            )

        assert leased is not None
        assert (
            leased["scan_execution_id"]
            == execution_id
        )
        assert leased["status"] == "LEASED"
        assert leased["service_tier"] == "GOLD"

        lease_token = leased["lease_token"]

        assert lease_token

        expected_hash = hashlib.sha256(
            lease_token.encode("utf-8")
        ).hexdigest()

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        lease_token_hash,
                        status
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (execution_id,),
                )

                stored_hash, stored_status = (
                    cur.fetchone()
                )

        assert stored_hash == expected_hash
        assert stored_hash != lease_token
        assert stored_status == "LEASED"

        print(
            "PASS: lease returns plaintext bearer token "
            "while PostgreSQL stores only its SHA-256 hash"
        )

        # --------------------------------------------------------------
        # Wrong node and wrong bearer token are rejected.
        # --------------------------------------------------------------
        wrong_node_blocked = False

        try:
            with conn:
                mark_execution_started(
                    conn,
                    scan_execution_id=(
                        execution_id
                    ),
                    node_code=(
                        "scan-coord-service-nmap-b"
                    ),
                    lease_token=lease_token,
                )
        except ScanLeaseAuthenticationError:
            wrong_node_blocked = True

        assert wrong_node_blocked is True

        wrong_token_blocked = False

        try:
            with conn:
                mark_execution_started(
                    conn,
                    scan_execution_id=(
                        execution_id
                    ),
                    node_code=(
                        "scan-coord-service-nmap-a"
                    ),
                    lease_token=(
                        "incorrect-lease-token"
                    ),
                )
        except ScanLeaseAuthenticationError:
            wrong_token_blocked = True

        assert wrong_token_blocked is True

        print(
            "PASS: lease transition requires both "
            "assigned node identity and matching bearer token"
        )

        # --------------------------------------------------------------
        # Valid start and successful completion.
        # --------------------------------------------------------------
        with conn:
            started = mark_execution_started(
                conn,
                scan_execution_id=execution_id,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_token=lease_token,
            )

        assert started["status"] == "RUNNING"
        assert started["started_at"] is not None

        print(
            "PASS: valid lease transitions execution "
            "from LEASED to RUNNING"
        )

        with conn:
            succeeded = mark_execution_succeeded(
                conn,
                scan_execution_id=execution_id,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_token=lease_token,
                execution_metadata={
                    "orchestrator_exit": "clean"
                },
            )

        assert (
            succeeded["status"]
            == "SUCCEEDED"
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        exit_code,
                        lease_token_hash,
                        execution_metadata
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (execution_id,),
                )

                terminal = cur.fetchone()

        assert terminal == (
            "SUCCEEDED",
            0,
            None,
            {"orchestrator_exit": "clean"},
        )

        print(
            "PASS: successful terminal transition "
            "clears the active lease credential"
        )

        stale_completion_blocked = False

        try:
            with conn:
                mark_execution_succeeded(
                    conn,
                    scan_execution_id=(
                        execution_id
                    ),
                    node_code=(
                        "scan-coord-service-nmap-a"
                    ),
                    lease_token=lease_token,
                )
        except ScanCoordinationConflictError:
            stale_completion_blocked = True

        assert stale_completion_blocked is True

        print(
            "PASS: completed execution rejects stale "
            "duplicate terminal reports"
        )

        # --------------------------------------------------------------
        # LOCAL_ASSET scanners require explicit binding.
        # --------------------------------------------------------------
        with conn:
            local_asset_id = create_asset(
                conn,
                canonical_name=(
                    "scan-coordination-local-host"
                ),
            )

            local_node_id = create_node(
                conn,
                node_code=(
                    "scan-coord-service-lynis"
                ),
                scanner_type="lynis",
                execution_model="LOCAL_ASSET",
                priority=10,
            )

            lynis_policy_id = create_policy(
                conn,
                asset_id=local_asset_id,
                scanner_type="lynis",
                profile_name="default",
            )

        no_binding_blocked = False

        try:
            with conn:
                create_scan_execution(
                    conn,
                    scan_policy_id=(
                        lynis_policy_id
                    ),
                    scanner_subject_type=(
                        "LOCAL_ASSET"
                    ),
                    scanner_subject_value=(
                        str(local_asset_id)
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
        except ScanCoordinationConflictError:
            no_binding_blocked = True

        assert no_binding_blocked is True

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO
                        scan_execution_node_assets (
                            execution_node_id,
                            asset_id,
                            tenant_code,
                            is_active
                        )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        TRUE
                    )
                    """,
                    (
                        local_node_id,
                        local_asset_id,
                        TENANT,
                    ),
                )

            local_execution = (
                create_scan_execution(
                    conn,
                    scan_policy_id=(
                        lynis_policy_id
                    ),
                    scanner_subject_type=(
                        "LOCAL_ASSET"
                    ),
                    scanner_subject_value=(
                        str(local_asset_id)
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
            )

        assert (
            local_execution[
                "execution_node_id"
            ]
            == local_node_id
        )

        print(
            "PASS: LOCAL_ASSET execution requires "
            "an active node-to-canonical-asset binding"
        )

        # Make the Lynis execution terminal so it does
        # not interfere with cleanup.
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET status = 'CANCELLED'
                    WHERE scan_execution_id = %s
                    """,
                    (
                        local_execution[
                            "scan_execution_id"
                        ],
                    ),
                )

        # --------------------------------------------------------------
        # Pre-start lease expiry becomes EXPIRED.
        # --------------------------------------------------------------
        with conn:
            retry_execution = (
                create_scan_execution(
                    conn,
                    scan_policy_id=policy_id,
                    scanner_subject_type=(
                        "IP_ADDRESS"
                    ),
                    scanner_subject_value=(
                        "192.0.2.55"
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
            )

        with conn:
            retry_lease = lease_next_execution(
                conn,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_seconds=300,
            )

        assert retry_lease is not None

        retry_id = retry_execution[
            "scan_execution_id"
        ]

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        leased_at =
                            now() - interval '2 minutes',
                        lease_expires_at =
                            now() - interval '1 minute'
                    WHERE scan_execution_id = %s
                    """,
                    (retry_id,),
                )

            result = expire_overdue_leases(
                conn
            )

        assert retry_id in result[
            "expired_before_start"
        ]

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        started_at,
                        completed_at,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (retry_id,),
                )

                expired = cur.fetchone()

        assert expired == (
            "EXPIRED",
            None,
            None,
            None,
        )

        print(
            "PASS: expired pre-start lease becomes "
            "EXPIRED without fabricated execution timestamps"
        )

        stale_expired_token_blocked = False

        try:
            with conn:
                mark_execution_started(
                    conn,
                    scan_execution_id=retry_id,
                    node_code=(
                        "scan-coord-service-nmap-a"
                    ),
                    lease_token=(
                        retry_lease["lease_token"]
                    ),
                )
        except ScanCoordinationConflictError:
            stale_expired_token_blocked = True

        assert stale_expired_token_blocked is True

        print(
            "PASS: expired execution rejects the "
            "former lease holder"
        )

        # --------------------------------------------------------------
        # A RUNNING execution whose lease expires becomes FAILED.
        # --------------------------------------------------------------
        with conn:
            running_execution = (
                create_scan_execution(
                    conn,
                    scan_policy_id=policy_id,
                    scanner_subject_type=(
                        "IP_ADDRESS"
                    ),
                    scanner_subject_value=(
                        "192.0.2.55"
                    ),
                    scheduled_for=datetime.now(
                        timezone.utc
                    ),
                )
            )

        with conn:
            running_lease = lease_next_execution(
                conn,
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_seconds=300,
            )

            mark_execution_started(
                conn,
                scan_execution_id=(
                    running_execution[
                        "scan_execution_id"
                    ]
                ),
                node_code=(
                    "scan-coord-service-nmap-a"
                ),
                lease_token=(
                    running_lease["lease_token"]
                ),
            )

        running_id = running_execution[
            "scan_execution_id"
        ]

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        leased_at =
                            now() - interval '2 minutes',
                        lease_expires_at =
                            now() - interval '1 minute'
                    WHERE scan_execution_id = %s
                    """,
                    (running_id,),
                )

            result = expire_overdue_leases(
                conn
            )

        assert running_id in result[
            "failed_while_running"
        ]

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        started_at IS NOT NULL,
                        completed_at IS NOT NULL,
                        failure_reason,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (running_id,),
                )

                failed = cur.fetchone()

        assert failed == (
            "FAILED",
            True,
            True,
            (
                "Execution lease expired while "
                "scanner was running"
            ),
            None,
        )

        print(
            "PASS: expired RUNNING lease fails the "
            "started execution and records completion"
        )

        # --------------------------------------------------------------
        # Expired credential cannot report success.
        # --------------------------------------------------------------
        expired_running_token_blocked = False

        try:
            with conn:
                mark_execution_succeeded(
                    conn,
                    scan_execution_id=running_id,
                    node_code=(
                        "scan-coord-service-nmap-a"
                    ),
                    lease_token=(
                        running_lease["lease_token"]
                    ),
                )
        except ScanCoordinationConflictError:
            expired_running_token_blocked = True

        assert (
            expired_running_token_blocked
            is True
        )

        print(
            "PASS: stale RUNNING lease cannot "
            "overwrite authoritative FAILED state"
        )

        # --------------------------------------------------------------
        # Caller retains transaction ownership.
        # --------------------------------------------------------------
        rollback_policy_id = None

        try:
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
                        is_enabled
                    )
                    VALUES (
                        %s,
                        %s,
                        'nmap_nse',
                        'STANDARD',
                        'rollback-test',
                        '{}'::jsonb,
                        'MANUAL',
                        NULL,
                        'UTC',
                        TRUE
                    )
                    RETURNING scan_policy_id
                    """,
                    (
                        TENANT,
                        asset_id,
                    ),
                )

                rollback_policy_id = (
                    cur.fetchone()[0]
                )

            create_scan_execution(
                conn,
                scan_policy_id=(
                    rollback_policy_id
                ),
                scanner_subject_type=(
                    "IP_ADDRESS"
                ),
                scanner_subject_value=(
                    "192.0.2.99"
                ),
                scheduled_for=datetime.now(
                    timezone.utc
                ),
            )

            conn.rollback()

        except Exception:
            conn.rollback()
            raise

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_policies
                    WHERE scan_policy_id = %s
                    """,
                    (rollback_policy_id,),
                )

                rollback_count = (
                    cur.fetchone()[0]
                )

        assert rollback_count == 0

        print(
            "PASS: scan coordination service leaves "
            "transaction ownership with caller"
        )

        print(
            "PASS: deterministic Scan Coordination "
            "service regression tests"
        )

    finally:
        try:
            with conn:
                clean_database(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
