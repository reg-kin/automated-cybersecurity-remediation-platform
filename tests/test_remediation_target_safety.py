#!/usr/bin/env python3

"""Regression tests for remediation execution-target safety."""

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

TENANT = "TARGET-SAFETY-TEST"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM remediation_executions
            WHERE finding_id IN (
                SELECT finding_id
                FROM unified_security_findings
                WHERE tenant_code = %s
            )
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM unified_security_findings
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM asset_execution_targets
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

def create_asset(
    conn,
    *,
    inventory_state,
    lifecycle_status,
    canonical_name,
):
    with conn.cursor() as cur:
        if inventory_state == "MANAGED":
            cur.execute(
                """
                INSERT INTO assets (
                    tenant_code,
                    asset_type,
                    canonical_name,
                    inventory_state,
                    lifecycle_status,
                    management_authorised_at,
                    management_authorised_by,
                    management_authorisation_reason
                )
                VALUES (
                    %s,
                    'HOST',
                    %s,
                    %s,
                    %s,
                    now(),
                    'target_safety_test',
                    'Authorised for remediation target-safety testing'
                )
                RETURNING asset_id
                """,
                (
                    TENANT,
                    canonical_name,
                    inventory_state,
                    lifecycle_status,
                ),
            )
        else:
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
                    %s,
                    %s
                )
                RETURNING asset_id
                """,
                (
                    TENANT,
                    canonical_name,
                    inventory_state,
                    lifecycle_status,
                ),
            )

        return cur.fetchone()[0]

def add_execution_target(
    conn,
    *,
    asset_id,
    execution_target,
    is_active=True,
):
    with conn.cursor() as cur:
        if is_active:
            cur.execute(
                """
                INSERT INTO asset_execution_targets (
                    asset_id,
                    tenant_code,
                    execution_target,
                    is_active,
                    source,
                    authorised_at,
                    authorised_by,
                    authorisation_reason
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    TRUE,
                    'target_safety_test',
                    now(),
                    'target_safety_test',
                    'Authorised for remediation target-safety testing'
                )
                """,
                (
                    asset_id,
                    TENANT,
                    execution_target,
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO asset_execution_targets (
                    asset_id,
                    tenant_code,
                    execution_target,
                    is_active,
                    source
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    FALSE,
                    'target_safety_test'
                )
                """,
                (
                    asset_id,
                    TENANT,
                    execution_target,
                ),
            )

def create_finding(
    conn,
    *,
    asset_id,
    finding_key,
    target_host,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO unified_security_findings (
                asset_id,
                tenant_code,
                tenant_service_tier,
                target_host,
                engine_source,
                finding_category,
                finding_class,
                finding_key,
                finding_title,
                lifecycle_status,
                detected_at,
                last_seen_at,
                severity_level,
                severity_score,
                engine_metadata
            )
            VALUES (
                %s,
                %s,
                'STANDARD',
                %s,
                'wazuh_vulnerability',
                'vulnerability',
                'package_vulnerability',
                %s,
                'Target safety test',
                'OPEN',
                now(),
                now(),
                'HIGH',
                8.0,
                jsonb_build_object(
                    'package_name',
                    'openssl'
                )
            )
            RETURNING finding_id
            """,
            (
                asset_id,
                TENANT,
                target_host,
                finding_key,
            ),
        )

        return cur.fetchone()[0]


def eligible_count(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM eligible_remediation_queue
            WHERE finding_id = %s
            """,
            (finding_id,),
        )

        return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

        #
        # PROVISIONAL assets must never be permitted to receive an
        # active authorised execution target.
        #
        with conn:
            provisional_asset = create_asset(
                conn,
                inventory_state="PROVISIONAL",
                lifecycle_status="ACTIVE",
                canonical_name="provisional-host",
            )

            provisional_finding = create_finding(
                conn,
                asset_id=provisional_asset,
                finding_key="target-safety-provisional",
                target_host="scanner-provisional-host",
            )

        provisional_target_blocked = False

        try:
            with conn:
                add_execution_target(
                    conn,
                    asset_id=provisional_asset,
                    execution_target="192.0.2.10",
                )
        except errors.RaiseException:
            provisional_target_blocked = True

        assert provisional_target_blocked is True

        assert eligible_count(
            conn,
            provisional_finding,
        ) == 0

        print(
            "PASS: PROVISIONAL asset cannot receive an authorised "
            "execution target and remains ineligible"
        )

        #
        # MANAGED assets without an authorised execution target
        # must remain non-executable.
        #
        with conn:
            no_target_asset = create_asset(
                conn,
                inventory_state="MANAGED",
                lifecycle_status="ACTIVE",
                canonical_name="managed-no-target-host",
            )

            no_target_finding = create_finding(
                conn,
                asset_id=no_target_asset,
                finding_key="target-safety-no-target",
                target_host="scanner-no-target-host",
            )

        assert eligible_count(
            conn,
            no_target_finding,
        ) == 0

        print(
            "PASS: MANAGED asset without execution target is "
            "excluded from eligible remediation"
        )

        #
        # INACTIVE assets must not be executable.
        #
        with conn:
            inactive_asset = create_asset(
                conn,
                inventory_state="MANAGED",
                lifecycle_status="INACTIVE",
                canonical_name="inactive-host",
            )

            add_execution_target(
                conn,
                asset_id=inactive_asset,
                execution_target="192.0.2.11",
            )

            inactive_finding = create_finding(
                conn,
                asset_id=inactive_asset,
                finding_key="target-safety-inactive",
                target_host="scanner-inactive-host",
            )

        assert eligible_count(
            conn,
            inactive_finding,
        ) == 0

        print(
            "PASS: INACTIVE asset is excluded from eligible remediation"
        )

        #
        # RETIRED assets must not be executable.
        #
        with conn:
            retired_asset = create_asset(
                conn,
                inventory_state="MANAGED",
                lifecycle_status="RETIRED",
                canonical_name="retired-host",
            )

            add_execution_target(
                conn,
                asset_id=retired_asset,
                execution_target="192.0.2.12",
            )

            retired_finding = create_finding(
                conn,
                asset_id=retired_asset,
                finding_key="target-safety-retired",
                target_host="scanner-retired-host",
            )

        assert eligible_count(
            conn,
            retired_finding,
        ) == 0

        print(
            "PASS: RETIRED asset is excluded from eligible remediation"
        )

        #
        # Exactly one active target on a MANAGED + ACTIVE asset
        # makes the routed finding eligible.
        #
        with conn:
            managed_asset = create_asset(
                conn,
                inventory_state="MANAGED",
                lifecycle_status="ACTIVE",
                canonical_name="managed-active-host",
            )

            add_execution_target(
                conn,
                asset_id=managed_asset,
                execution_target="192.0.2.20",
            )

            managed_finding = create_finding(
                conn,
                asset_id=managed_asset,
                finding_key="target-safety-managed",
                target_host="scanner-managed-host",
            )

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    execution_target,
                    target_host
                FROM eligible_remediation_queue
                WHERE finding_id = %s
                """,
                (managed_finding,),
            )

            row = cur.fetchone()

        assert row is not None
        assert row[0] == "192.0.2.20"
        assert row[1] == "scanner-managed-host"

        print(
            "PASS: MANAGED ACTIVE asset with one authorised target "
            "is eligible and preserves scanner target evidence"
        )

        #
        # The database must prevent two simultaneously active targets
        # for the same asset.
        #
        duplicate_blocked = False

        try:
            with conn:
                add_execution_target(
                    conn,
                    asset_id=managed_asset,
                    execution_target="192.0.2.21",
                )
        except errors.UniqueViolation:
            duplicate_blocked = True

        assert duplicate_blocked is True

        print(
            "PASS: database prevents multiple active execution "
            "targets for one asset"
        )

        print(
            "PASS: remediation execution-target safety regression tests"
        )

    finally:
        try:
            with conn:
                clean_database(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
