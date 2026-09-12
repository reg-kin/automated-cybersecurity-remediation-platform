#!/usr/bin/env python3

"""Database regression tests for Scan Execution Lease Safety V1."""

import os

import psycopg2


PG = {
    "host": os.environ.get("PG_HOST", "127.0.0.1"),
    "port": int(os.environ.get("PG_PORT", "5432")),
    "dbname": os.environ.get(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.environ.get("PG_USER", "telemetry_admin"),
    "password": os.environ.get("PG_PASSWORD", ""),
}


TENANT = "SCAN-LEASE-SAFETY-TEST"
NODE_CODE = "scan-lease-safety-node"
TOKEN_HASH_A = "a" * 64
TOKEN_HASH_B = "b" * 64


def passed(message):
    print(f"PASS: {message}")


def expect_integrity_error(conn, description, operation):
    try:
        with conn:
            with conn.cursor() as cur:
                operation(cur)
    except psycopg2.IntegrityError:
        passed(description)
        return

    raise AssertionError(
        f"Expected database integrity failure: {description}"
    )


def cleanup(conn):
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM scan_executions
                WHERE tenant_code = %s;
                """,
                (TENANT,),
            )

            cur.execute(
                """
                DELETE FROM scan_policies
                WHERE tenant_code = %s;
                """,
                (TENANT,),
            )

            cur.execute(
                """
                DELETE FROM scan_execution_node_assets
                WHERE tenant_code = %s;
                """,
                (TENANT,),
            )

            cur.execute(
                """
                DELETE FROM assets
                WHERE tenant_code = %s;
                """,
                (TENANT,),
            )

            cur.execute(
                """
                DELETE FROM scan_execution_nodes
                WHERE node_code = %s;
                """,
                (NODE_CODE,),
            )


def create_fixture(conn):
    with conn:
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
                    'scan-lease-safety-host',
                    'PROVISIONAL',
                    'ACTIVE'
                )
                RETURNING asset_id;
                """,
                (TENANT,),
            )
            asset_id = cur.fetchone()[0]

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
                    'Scan Lease Safety Node',
                    'PULL',
                    TRUE
                )
                RETURNING execution_node_id;
                """,
                (NODE_CODE,),
            )
            execution_node_id = cur.fetchone()[0]

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
                    'nmap_nse',
                    'REMOTE_TARGET',
                    100,
                    TRUE
                );
                """,
                (execution_node_id,),
            )

            cur.execute(
                """
                INSERT INTO scan_policies (
                    tenant_code,
                    asset_id,
                    scanner_type,
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
                    'lease-safety',
                    '{}'::jsonb,
                    'MANUAL',
                    NULL,
                    'UTC',
                    TRUE
                )
                RETURNING scan_policy_id;
                """,
                (TENANT, asset_id),
            )
            scan_policy_id = cur.fetchone()[0]

    return asset_id, execution_node_id, scan_policy_id


def create_pending_execution(
    conn,
    *,
    asset_id,
    execution_node_id,
    scan_policy_id,
):
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_executions (
                    scan_policy_id,
                    tenant_code,
                    asset_id,
                    scanner_type,
                    execution_node_id,
                    execution_model,
                    scanner_subject_type,
                    scanner_subject_value,
                    scanner_parameters,
                    status,
                    scheduled_for
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'nmap_nse',
                    %s,
                    'REMOTE_TARGET',
                    'IP_ADDRESS',
                    '192.0.2.25',
                    '{}'::jsonb,
                    'PENDING',
                    now()
                )
                RETURNING scan_execution_id;
                """,
                (
                    scan_policy_id,
                    TENANT,
                    asset_id,
                    execution_node_id,
                ),
            )
            return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(**PG)

    try:
        cleanup(conn)

        asset_id, execution_node_id, scan_policy_id = create_fixture(conn)

        execution_id = create_pending_execution(
            conn,
            asset_id=asset_id,
            execution_node_id=execution_node_id,
            scan_policy_id=scan_policy_id,
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s;
                    """,
                    (execution_id,),
                )
                assert cur.fetchone()[0] is None

        passed("new PENDING execution contains no persisted lease token")

        expect_integrity_error(
            conn,
            "PENDING execution cannot carry a lease token hash",
            lambda cur: cur.execute(
                """
                UPDATE scan_executions
                SET lease_token_hash = %s
                WHERE scan_execution_id = %s;
                """,
                (TOKEN_HASH_A, execution_id),
            ),
        )

        expect_integrity_error(
            conn,
            "LEASED execution requires a lease token hash",
            lambda cur: cur.execute(
                """
                UPDATE scan_executions
                SET
                    status = 'LEASED',
                    leased_at = now(),
                    lease_expires_at = now() + interval '5 minutes'
                WHERE scan_execution_id = %s;
                """,
                (execution_id,),
            ),
        )

        expect_integrity_error(
            conn,
            "lease token hash must be a lowercase SHA-256 hexadecimal digest",
            lambda cur: cur.execute(
                """
                UPDATE scan_executions
                SET
                    status = 'LEASED',
                    leased_at = now(),
                    lease_expires_at = now() + interval '5 minutes',
                    lease_token_hash = 'not-a-valid-token-hash'
                WHERE scan_execution_id = %s;
                """,
                (execution_id,),
            ),
        )

        expect_integrity_error(
            conn,
            "active lease expiry must be later than lease start",
            lambda cur: cur.execute(
                """
                UPDATE scan_executions
                SET
                    status = 'LEASED',
                    leased_at = now(),
                    lease_expires_at = now() - interval '1 minute',
                    lease_token_hash = %s
                WHERE scan_execution_id = %s;
                """,
                (TOKEN_HASH_A, execution_id),
            ),
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'LEASED',
                        leased_at = now(),
                        lease_expires_at = now() + interval '5 minutes',
                        lease_token_hash = %s
                    WHERE scan_execution_id = %s;
                    """,
                    (TOKEN_HASH_A, execution_id),
                )

        passed(
            "LEASED execution requires and accepts a valid hashed lease credential"
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'RUNNING',
                        started_at = now()
                    WHERE scan_execution_id = %s;
                    """,
                    (execution_id,),
                )

        passed("RUNNING execution preserves the active lease credential")

        expect_integrity_error(
            conn,
            "terminal execution cannot retain an active lease token hash",
            lambda cur: cur.execute(
                """
                UPDATE scan_executions
                SET
                    status = 'SUCCEEDED',
                    completed_at = now()
                WHERE scan_execution_id = %s;
                """,
                (execution_id,),
            ),
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'SUCCEEDED',
                        completed_at = now(),
                        lease_token_hash = NULL
                    WHERE scan_execution_id = %s;
                    """,
                    (execution_id,),
                )

        passed("successful completion clears the active lease credential")

        expired_execution_id = create_pending_execution(
            conn,
            asset_id=asset_id,
            execution_node_id=execution_node_id,
            scan_policy_id=scan_policy_id,
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'LEASED',
                        leased_at = now(),
                        lease_expires_at = now() + interval '5 minutes',
                        lease_token_hash = %s
                    WHERE scan_execution_id = %s;
                    """,
                    (TOKEN_HASH_B, expired_execution_id),
                )

                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'EXPIRED',
                        lease_token_hash = NULL
                    WHERE scan_execution_id = %s;
                    """,
                    (expired_execution_id,),
                )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        leased_at IS NOT NULL,
                        lease_expires_at IS NOT NULL,
                        started_at,
                        completed_at,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s;
                    """,
                    (expired_execution_id,),
                )

                expired_state = cur.fetchone()

        assert expired_state == (
            "EXPIRED",
            True,
            True,
            None,
            None,
            None,
        )

        passed(
            "pre-start lease expiry preserves lease history without "
            "fabricating execution timestamps"
        )

        passed("expired lease terminates its execution attempt and clears its credential")

        replacement_execution_id = create_pending_execution(
            conn,
            asset_id=asset_id,
            execution_node_id=execution_node_id,
            scan_policy_id=scan_policy_id,
        )

        assert replacement_execution_id != expired_execution_id

        passed(
            "retry after lease expiry is represented by a new scan execution"
        )

        passed("Scan Execution Lease Safety V1 database regression tests")

    finally:
        try:
            cleanup(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
