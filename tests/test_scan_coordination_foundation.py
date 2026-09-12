#!/usr/bin/env python3

"""Regression tests for Scan Coordination Foundation V1."""

import os

import psycopg2
from psycopg2 import errors


PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.getenv("PG_USER", "telemetry_admin"),
    "password": os.getenv("PG_PASSWORD", ""),
}


TENANT_A = "SCAN-COORDINATION-TEST-A"
TENANT_B = "SCAN-COORDINATION-TEST-B"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code IN (%s, %s)
            """,
            (
                TENANT_A,
                TENANT_B,
            ),
        )

        cur.execute(
            """
            DELETE FROM scan_execution_nodes
            WHERE node_code LIKE 'scan-coordination-test-%%'
            """
        )


def create_asset(conn, tenant_code, canonical_name):
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
                tenant_code,
                canonical_name,
            ),
        )

        return cur.fetchone()[0]


def create_node(
    conn,
    node_code,
    *,
    display_name=None,
    transport_mode="PULL",
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_execution_nodes (
                node_code,
                display_name,
                transport_mode
            )
            VALUES (%s, %s, %s)
            RETURNING execution_node_id
            """,
            (
                node_code,
                display_name or node_code,
                transport_mode,
            ),
        )

        return cur.fetchone()[0]


def add_capability(
    conn,
    node_id,
    scanner_type,
    execution_model,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_execution_node_capabilities (
                execution_node_id,
                scanner_type,
                execution_model
            )
            VALUES (%s, %s, %s)
            RETURNING capability_id
            """,
            (
                node_id,
                scanner_type,
                execution_model,
            ),
        )

        return cur.fetchone()[0]


def create_policy(
    conn,
    *,
    tenant_code,
    asset_id,
    scanner_type="nmap_nse",
    service_tier="STANDARD",
    profile_name="default",
    schedule_type="CRON",
    schedule_expression="0 * * * *",
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
                schedule_type,
                schedule_expression
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING scan_policy_id
            """,
            (
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                schedule_type,
                schedule_expression,
            ),
        )

        return cur.fetchone()[0]


def create_execution(
    conn,
    *,
    policy_id,
    tenant_code,
    asset_id,
    node_id,
    scanner_type="nmap_nse",
    service_tier="STANDARD",
    execution_model="REMOTE_TARGET",
    subject_type="IP_ADDRESS",
    subject_value="192.0.2.10",
    status="PENDING",
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_executions (
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                execution_node_id,
                execution_model,
                scanner_subject_type,
                scanner_subject_value,
                status,
                scheduled_for
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                now()
            )
            RETURNING scan_execution_id
            """,
            (
                policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                node_id,
                execution_model,
                subject_type,
                subject_value,
                status,
            ),
        )

        return cur.fetchone()[0]


def expect_integrity_error(operation):
    rejected = False

    try:
        operation()
    except psycopg2.IntegrityError:
        rejected = True

    assert rejected is True


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

        # ------------------------------------------------------------------
        # Execution-node identity
        # ------------------------------------------------------------------

        with conn:
            node_a = create_node(
                conn,
                "scan-coordination-test-node-a",
            )

        def duplicate_node():
            with conn:
                create_node(
                    conn,
                    "scan-coordination-test-node-a",
                )

        expect_integrity_error(duplicate_node)

        print(
            "PASS: scan execution node_code is unique"
        )

        # ------------------------------------------------------------------
        # A node may expose multiple scanner capabilities.
        # ------------------------------------------------------------------

        with conn:
            add_capability(
                conn,
                node_a,
                "nmap_nse",
                "REMOTE_TARGET",
            )

            add_capability(
                conn,
                node_a,
                "nuclei",
                "REMOTE_TARGET",
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scanner_type
                    FROM scan_execution_node_capabilities
                    WHERE execution_node_id = %s
                    ORDER BY scanner_type
                    """,
                    (node_a,),
                )

                capabilities = [
                    row[0]
                    for row in cur.fetchall()
                ]

        assert capabilities == [
            "nmap_nse",
            "nuclei",
        ]

        print(
            "PASS: one execution node may expose multiple scanner capabilities"
        )

        # ------------------------------------------------------------------
        # Duplicate scanner capability for one node is rejected.
        # ------------------------------------------------------------------

        def duplicate_capability():
            with conn:
                add_capability(
                    conn,
                    node_a,
                    "nmap_nse",
                    "REMOTE_TARGET",
                )

        expect_integrity_error(duplicate_capability)

        print(
            "PASS: duplicate node scanner capability is rejected"
        )

        # ------------------------------------------------------------------
        # Scanner catalogue is constrained.
        # ------------------------------------------------------------------

        def invalid_scanner():
            with conn:
                add_capability(
                    conn,
                    node_a,
                    "unsupported_scanner",
                    "REMOTE_TARGET",
                )

        expect_integrity_error(invalid_scanner)

        print(
            "PASS: execution-node capability rejects unsupported scanner types"
        )

        # ------------------------------------------------------------------
        # Execution model is constrained.
        # ------------------------------------------------------------------

        def invalid_execution_model():
            with conn:
                add_capability(
                    conn,
                    node_a,
                    "trivy",
                    "INVALID_MODEL",
                )

        expect_integrity_error(invalid_execution_model)

        print(
            "PASS: execution-node capability rejects invalid execution models"
        )

        # ------------------------------------------------------------------
        # Create tenant-scoped canonical assets.
        # ------------------------------------------------------------------

        with conn:
            asset_a = create_asset(
                conn,
                TENANT_A,
                "scan-coordination-asset-a",
            )

            asset_b = create_asset(
                conn,
                TENANT_B,
                "scan-coordination-asset-b",
            )

        # ------------------------------------------------------------------
        # LOCAL_ASSET bindings use the tenant-scoped canonical asset FK.
        # ------------------------------------------------------------------

        with conn:
            local_node = create_node(
                conn,
                "scan-coordination-test-local-node",
            )

            add_capability(
                conn,
                local_node,
                "lynis",
                "LOCAL_ASSET",
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scan_execution_node_assets (
                        execution_node_id,
                        asset_id,
                        tenant_code
                    )
                    VALUES (%s, %s, %s)
                    RETURNING node_asset_binding_id
                    """,
                    (
                        local_node,
                        asset_a,
                        TENANT_A,
                    ),
                )

                binding_id = cur.fetchone()[0]

        assert binding_id is not None

        print(
            "PASS: LOCAL_ASSET execution node can bind to a canonical "
            "tenant-scoped asset"
        )

        # ------------------------------------------------------------------
        # Cross-tenant asset binding is impossible.
        # ------------------------------------------------------------------

        def cross_tenant_binding():
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO scan_execution_node_assets (
                            execution_node_id,
                            asset_id,
                            tenant_code
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            local_node,
                            asset_a,
                            TENANT_B,
                        ),
                    )

        expect_integrity_error(cross_tenant_binding)

        print(
            "PASS: LOCAL_ASSET node binding enforces tenant isolation"
        )

        # ------------------------------------------------------------------
        # A scan policy is tenant scoped.
        # ------------------------------------------------------------------

        with conn:
            policy_a = create_policy(
                conn,
                tenant_code=TENANT_A,
                asset_id=asset_a,
            )

        assert policy_a is not None

        print(
            "PASS: scan policy can reference its tenant-scoped canonical asset"
        )

        # ------------------------------------------------------------------
        # Service tier is constrained to the canonical scanner vocabulary.
        # ------------------------------------------------------------------

        def invalid_service_tier():
            with conn:
                create_policy(
                    conn,
                    tenant_code=TENANT_A,
                    asset_id=asset_a,
                    scanner_type="nmap_nse",
                    service_tier="PLATINUM",
                    profile_name="invalid-service-tier",
                )

        expect_integrity_error(invalid_service_tier)

        print(
            "PASS: scan policy rejects unsupported service tiers"
        )

        def cross_tenant_policy():
            with conn:
                create_policy(
                    conn,
                    tenant_code=TENANT_B,
                    asset_id=asset_a,
                    profile_name="wrong-tenant",
                )

        expect_integrity_error(cross_tenant_policy)

        print(
            "PASS: scan policy enforces canonical asset tenant isolation"
        )

        # ------------------------------------------------------------------
        # Policy is intentionally independent of execution-node location.
        # ------------------------------------------------------------------

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'scan_policies'
                      AND column_name = 'execution_node_id'
                    """
                )

                execution_node_column_count = cur.fetchone()[0]

        assert execution_node_column_count == 0

        print(
            "PASS: scan policy is not permanently bound to an execution node"
        )

        # ------------------------------------------------------------------
        # Duplicate policy identity is rejected.
        # ------------------------------------------------------------------

        def duplicate_policy():
            with conn:
                create_policy(
                    conn,
                    tenant_code=TENANT_A,
                    asset_id=asset_a,
                )

        expect_integrity_error(duplicate_policy)

        print(
            "PASS: duplicate tenant asset scanner profile policy is rejected"
        )

        # ------------------------------------------------------------------
        # CRON requires a non-empty expression.
        # ------------------------------------------------------------------

        def cron_without_expression():
            with conn:
                create_policy(
                    conn,
                    tenant_code=TENANT_A,
                    asset_id=asset_a,
                    scanner_type="nuclei",
                    profile_name="cron-without-expression",
                    schedule_type="CRON",
                    schedule_expression=None,
                )

        expect_integrity_error(cron_without_expression)

        print(
            "PASS: CRON scan policy requires a schedule expression"
        )

        # ------------------------------------------------------------------
        # MANUAL requires a NULL expression.
        # ------------------------------------------------------------------

        def manual_with_expression():
            with conn:
                create_policy(
                    conn,
                    tenant_code=TENANT_A,
                    asset_id=asset_a,
                    scanner_type="nuclei",
                    profile_name="manual-with-expression",
                    schedule_type="MANUAL",
                    schedule_expression="0 0 * * *",
                )

        expect_integrity_error(manual_with_expression)

        with conn:
            manual_policy = create_policy(
                conn,
                tenant_code=TENANT_A,
                asset_id=asset_a,
                scanner_type="nuclei",
                profile_name="manual",
                schedule_type="MANUAL",
                schedule_expression=None,
            )

        assert manual_policy is not None

        print(
            "PASS: MANUAL scan policy requires a NULL schedule expression"
        )

        # ------------------------------------------------------------------
        # Execution preserves selected node and resolved scanner subject.
        # ------------------------------------------------------------------

        with conn:
            execution_id = create_execution(
                conn,
                policy_id=policy_a,
                tenant_code=TENANT_A,
                asset_id=asset_a,
                node_id=node_a,
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        execution_node_id,
                        execution_model,
                        scanner_subject_type,
                        scanner_subject_value,
                        service_tier,
                        status
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (execution_id,),
                )

                execution_row = cur.fetchone()

        assert execution_row == (
            node_a,
            "REMOTE_TARGET",
            "IP_ADDRESS",
            "192.0.2.10",
            "STANDARD",
            "PENDING",
        )

        print(
            "PASS: scan execution preserves node, execution model, "
            "resolved scanner subject and service tier"
        )

        # ------------------------------------------------------------------
        # Only one active execution may exist per policy.
        # ------------------------------------------------------------------

        def second_pending_execution():
            with conn:
                create_execution(
                    conn,
                    policy_id=policy_a,
                    tenant_code=TENANT_A,
                    asset_id=asset_a,
                    node_id=node_a,
                    subject_value="192.0.2.11",
                )

        expect_integrity_error(second_pending_execution)

        print(
            "PASS: concurrent active executions for one scan policy are rejected"
        )

        # ------------------------------------------------------------------
        # Terminal execution releases the policy for a later execution.
        # ------------------------------------------------------------------

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        status = 'SUCCEEDED',
                        started_at = scheduled_for,
                        completed_at = scheduled_for
                    WHERE scan_execution_id = %s
                    """,
                    (execution_id,),
                )

            later_execution_id = create_execution(
                conn,
                policy_id=policy_a,
                tenant_code=TENANT_A,
                asset_id=asset_a,
                node_id=node_a,
                subject_value="192.0.2.12",
            )

        assert later_execution_id != execution_id

        print(
            "PASS: terminal scan execution permits a later policy execution"
        )

        # ------------------------------------------------------------------
        # Node deletion cascades capabilities when no execution history
        # references the node.
        # ------------------------------------------------------------------

        with conn:
            disposable_node = create_node(
                conn,
                "scan-coordination-test-disposable-node",
            )

            add_capability(
                conn,
                disposable_node,
                "trivy",
                "RESOURCE_TARGET",
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM scan_execution_nodes
                    WHERE execution_node_id = %s
                    """,
                    (disposable_node,),
                )

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_execution_node_capabilities
                    WHERE execution_node_id = %s
                    """,
                    (disposable_node,),
                )

                remaining_capabilities = cur.fetchone()[0]

        assert remaining_capabilities == 0

        print(
            "PASS: deleting an unreferenced execution node cascades "
            "its capabilities"
        )

        # ------------------------------------------------------------------
        # Asset deletion cascades LOCAL_ASSET bindings when there is no
        # historical execution referencing that asset.
        # ------------------------------------------------------------------

        with conn:
            binding_asset = create_asset(
                conn,
                TENANT_A,
                "scan-coordination-binding-only-asset",
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scan_execution_node_assets (
                        execution_node_id,
                        asset_id,
                        tenant_code
                    )
                    VALUES (%s, %s, %s)
                    RETURNING node_asset_binding_id
                    """,
                    (
                        local_node,
                        binding_asset,
                        TENANT_A,
                    ),
                )

                disposable_binding_id = cur.fetchone()[0]

                cur.execute(
                    """
                    DELETE FROM assets
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        binding_asset,
                        TENANT_A,
                    ),
                )

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_execution_node_assets
                    WHERE node_asset_binding_id = %s
                    """,
                    (disposable_binding_id,),
                )

                remaining_bindings = cur.fetchone()[0]

        assert remaining_bindings == 0

        print(
            "PASS: deleting an asset without scan history cascades "
            "its LOCAL_ASSET binding"
        )

        # ------------------------------------------------------------------
        # Historical execution prevents deletion of its execution node.
        # ------------------------------------------------------------------

        def delete_historical_node():
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM scan_execution_nodes
                        WHERE execution_node_id = %s
                        """,
                        (node_a,),
                    )

        expect_integrity_error(delete_historical_node)

        print(
            "PASS: scan execution history prevents deletion of its "
            "execution node"
        )

        # ------------------------------------------------------------------
        # Historical execution prevents deletion of its canonical asset.
        #
        # scan_policy currently cascades from assets, but scan_executions
        # RESTRICT the historical execution path, preserving audit history.
        # ------------------------------------------------------------------

        def delete_historical_asset():
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM assets
                        WHERE asset_id = %s
                          AND tenant_code = %s
                        """,
                        (
                            asset_a,
                            TENANT_A,
                        ),
                    )

        expect_integrity_error(delete_historical_asset)

        print(
            "PASS: scan execution history prevents deletion of its "
            "canonical asset"
        )

        # ------------------------------------------------------------------
        # Cleanup.
        #
        # Historical execution rows must be removed explicitly before their
        # referenced policies/assets/nodes can be removed.
        # ------------------------------------------------------------------

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM scan_executions
                    WHERE tenant_code IN (%s, %s)
                    """,
                    (
                        TENANT_A,
                        TENANT_B,
                    ),
                )

                cur.execute(
                    """
                    DELETE FROM assets
                    WHERE tenant_code IN (%s, %s)
                    """,
                    (
                        TENANT_A,
                        TENANT_B,
                    ),
                )

                cur.execute(
                    """
                    DELETE FROM scan_execution_nodes
                    WHERE node_code LIKE 'scan-coordination-test-%%'
                    """
                )

    finally:
        conn.close()

    print(
        "PASS: Scan Coordination Foundation V1 database regression tests"
    )


if __name__ == "__main__":
    main()
