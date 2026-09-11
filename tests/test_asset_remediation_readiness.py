#!/usr/bin/env python3

"""Regression tests for asset remediation readiness controls."""

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

TENANT = "ASSET-READINESS-TEST"

def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

def create_provisional_asset(conn, canonical_name):
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

def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

        #
        # A PROVISIONAL asset cannot be promoted to MANAGED without
        # explicit management authorisation metadata.
        #
        with conn:
            asset_id = create_provisional_asset(
                conn,
                "promotion-without-authorisation",
            )

        promotion_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE assets
                        SET inventory_state = 'MANAGED'
                        WHERE asset_id = %s
                          AND tenant_code = %s
                        """,
                        (
                            asset_id,
                            TENANT,
                        ),
                    )
        except errors.RaiseException:
            promotion_blocked = True

        assert promotion_blocked is True

        print(
            "PASS: PROVISIONAL asset cannot become MANAGED "
            "without explicit authorisation"
        )

        #
        # A PROVISIONAL asset may become MANAGED when complete
        # management authorisation metadata is supplied.
        #
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE assets
                    SET inventory_state = 'MANAGED',
                        management_authorised_at = now(),
                        management_authorised_by = %s,
                        management_authorisation_reason = %s
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        "asset_readiness_test",
                        "Approved for automated remediation testing",
                        asset_id,
                        TENANT,
                    ),
                )

                cur.execute(
                    """
                    SELECT
                        inventory_state,
                        management_authorised_at,
                        management_authorised_by,
                        management_revoked_at
                    FROM assets
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        asset_id,
                        TENANT,
                    ),
                )

                row = cur.fetchone()

        assert row[0] == "MANAGED"
        assert row[1] is not None
        assert row[2] == "asset_readiness_test"
        assert row[3] is None

        print(
            "PASS: explicitly authorised asset can become MANAGED"
        )


        #
        # An active execution target cannot be created without
        # explicit target authorisation metadata.
        #
        target_authorisation_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
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
                            '192.0.2.230',
                            TRUE,
                            'asset_readiness_test'
                        )
                        """,
                        (
                            asset_id,
                            TENANT,
                        ),
                    )
        except errors.RaiseException:
            target_authorisation_blocked = True

        assert target_authorisation_blocked is True

        print(
            "PASS: active execution target requires explicit "
            "authorisation"
        )

        #
        # A fully authorised active execution target is permitted
        # for an explicitly authorised MANAGED asset.
        #
        with conn:
            with conn.cursor() as cur:
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
                        '192.0.2.230',
                        TRUE,
                        'asset_readiness_test',
                        now(),
                        %s,
                        %s
                    )
                    RETURNING execution_target_id
                    """,
                    (
                        asset_id,
                        TENANT,
                        "asset_readiness_test",
                        "Approved remediation management endpoint",
                    ),
                )

                execution_target_id = cur.fetchone()[0]

                cur.execute(
                    """
                    SELECT
                        is_active,
                        authorised_at,
                        authorised_by,
                        revoked_at
                    FROM asset_execution_targets
                    WHERE execution_target_id = %s
                    """,
                    (execution_target_id,),
                )

                target_row = cur.fetchone()

        assert target_row[0] is True
        assert target_row[1] is not None
        assert target_row[2] == "asset_readiness_test"
        assert target_row[3] is None

        print(
            "PASS: explicitly authorised active execution target "
            "is permitted"
        )

        #
        # An authorised execution target cannot be deactivated
        # without explicit revocation metadata.
        #
        target_revocation_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE asset_execution_targets
                        SET is_active = FALSE
                        WHERE execution_target_id = %s
                        """,
                        (execution_target_id,),
                    )
        except errors.RaiseException:
            target_revocation_blocked = True

        assert target_revocation_blocked is True

        print(
            "PASS: authorised execution target cannot be "
            "deactivated without revocation metadata"
        )

        #
        # An authorised execution target may be deactivated when
        # complete revocation metadata is supplied.
        #
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE asset_execution_targets
                    SET is_active = FALSE,
                        revoked_at = now(),
                        revoked_by = %s,
                        revocation_reason = %s
                    WHERE execution_target_id = %s
                    """,
                    (
                        "asset_readiness_test",
                        "Execution target revoked for readiness testing",
                        execution_target_id,
                    ),
                )

                cur.execute(
                    """
                    SELECT
                        is_active,
                        revoked_at,
                        revoked_by,
                        revocation_reason
                    FROM asset_execution_targets
                    WHERE execution_target_id = %s
                    """,
                    (execution_target_id,),
                )

                revoked_target_row = cur.fetchone()

        assert revoked_target_row[0] is False
        assert revoked_target_row[1] is not None
        assert revoked_target_row[2] == "asset_readiness_test"
        assert revoked_target_row[3] == (
            "Execution target revoked for readiness testing"
        )

        print(
            "PASS: authorised execution target can be explicitly "
            "revoked"
        )

        #
        # A previously authorised MANAGED asset cannot leave MANAGED
        # without explicit management revocation metadata.
        #
        management_revocation_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE assets
                        SET inventory_state = 'UNMANAGED'
                        WHERE asset_id = %s
                          AND tenant_code = %s
                        """,
                        (
                            asset_id,
                            TENANT,
                        ),
                    )
        except errors.RaiseException:
            management_revocation_blocked = True

        assert management_revocation_blocked is True

        print(
            "PASS: authorised MANAGED asset cannot leave MANAGED "
            "without management revocation metadata"
        )

        #
        # A previously authorised MANAGED asset may leave MANAGED
        # when complete management revocation metadata is supplied.
        #
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE assets
                    SET inventory_state = 'UNMANAGED',
                        management_revoked_at = now(),
                        management_revoked_by = %s,
                        management_revocation_reason = %s
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        "asset_readiness_test",
                        "Management authorisation revoked for testing",
                        asset_id,
                        TENANT,
                    ),
                )

                cur.execute(
                    """
                    SELECT
                        inventory_state,
                        management_revoked_at,
                        management_revoked_by,
                        management_revocation_reason
                    FROM assets
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        asset_id,
                        TENANT,
                    ),
                )

                revoked_asset_row = cur.fetchone()

        assert revoked_asset_row[0] == "UNMANAGED"
        assert revoked_asset_row[1] is not None
        assert revoked_asset_row[2] == "asset_readiness_test"
        assert revoked_asset_row[3] == (
            "Management authorisation revoked for testing"
        )

        print(
            "PASS: authorised MANAGED asset can be explicitly "
            "revoked and moved to UNMANAGED"
        )

        #
        # Valid remediation-readiness audit events may be inserted.
        #
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO asset_remediation_audit (
                        asset_id,
                        tenant_code,
                        execution_target_id,
                        event_type,
                        performed_by,
                        reason,
                        event_metadata
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        'EXECUTION_TARGET_REVOKED',
                        %s,
                        %s,
                        %s::jsonb
                    )
                    RETURNING audit_id
                    """,
                    (
                        asset_id,
                        TENANT,
                        execution_target_id,
                        "asset_readiness_test",
                        "Execution target revoked during readiness testing",
                        '{"test": true}',
                    ),
                )

                audit_id = cur.fetchone()[0]

        assert audit_id is not None

        print(
            "PASS: valid remediation-readiness audit event "
            "can be inserted"
        )

        #
        # Audit events are append-only and cannot be updated.
        #
        audit_update_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE asset_remediation_audit
                        SET reason = 'Modified reason'
                        WHERE audit_id = %s
                        """,
                        (audit_id,),
                    )
        except errors.RaiseException:
            audit_update_blocked = True

        assert audit_update_blocked is True

        print(
            "PASS: remediation-readiness audit event cannot "
            "be updated"
        )

        #
        # Audit events are append-only and cannot be deleted.
        #
        audit_delete_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM asset_remediation_audit
                        WHERE audit_id = %s
                        """,
                        (audit_id,),
                    )
        except errors.RaiseException:
            audit_delete_blocked = True

        assert audit_delete_blocked is True

        print(
            "PASS: remediation-readiness audit event cannot "
            "be deleted"
        )

        #
        # Audit event metadata must be a JSON object.
        #
        invalid_metadata_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO asset_remediation_audit (
                            asset_id,
                            tenant_code,
                            event_type,
                            performed_by,
                            reason,
                            event_metadata
                        )
                        VALUES (
                            %s,
                            %s,
                            'ASSET_RETIRED',
                            %s,
                            %s,
                            %s::jsonb
                        )
                        """,
                        (
                            asset_id,
                            TENANT,
                            "asset_readiness_test",
                            "Invalid metadata regression test",
                            '["not-an-object"]',
                        ),
                    )
        except errors.CheckViolation:
            invalid_metadata_blocked = True

        assert invalid_metadata_blocked is True

        print(
            "PASS: remediation-readiness audit metadata "
            "must be a JSON object"
        )

    finally:
        conn.close()


if __name__ == "__main__":
    main()
