#!/usr/bin/env python3

"""Regression tests for administrative remediation-readiness management."""

import os
import sys
from pathlib import Path

import psycopg2


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from readiness_management.service import (
    authorise_asset_management,
    authorise_execution_target,
    get_asset_readiness,
    get_asset_readiness_history,
    replace_execution_target,
    revoke_asset_management,
    revoke_execution_target,
)


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

TENANT = "ADMIN-READINESS-MGMT-TEST"
ACTOR = "administrative_readiness_test"


def clean_database(conn):
    """Remove operational test assets without mutating append-only audit history."""

    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )


def create_provisional_asset(conn):
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
                'admin-readiness-test-host',
                'PROVISIONAL',
                'ACTIVE'
            )
            RETURNING asset_id
            """,
            (TENANT,),
        )

        return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(**PG)

    try:
        #
        # ------------------------------------------------------------------
        # 1. Create an ordinary discovered PROVISIONAL asset.
        # ------------------------------------------------------------------
        #
        with conn:
            clean_database(conn)
            asset_id = create_provisional_asset(conn)

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["asset"]["inventory_state"] == "PROVISIONAL"
        assert readiness["asset_management_authorised"] is False
        assert readiness["execution_target_authorised"] is False
        assert readiness["remediation_ready"] is False
        assert readiness["active_execution_target"] is None

        print(
            "PASS: newly discovered PROVISIONAL asset is not "
            "remediation-ready"
        )

        #
        # ------------------------------------------------------------------
        # 2. Explicitly authorise asset management.
        # ------------------------------------------------------------------
        #
        with conn:
            result = authorise_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason=(
                    "Asset ownership and management authority "
                    "verified for regression testing"
                ),
            )

        assert result["asset_id"] == asset_id
        assert result["tenant_code"] == TENANT
        assert result["inventory_state"] == "MANAGED"
        assert result["management_authorised_at"] is not None
        assert result["management_authorised_by"] == ACTOR
        assert result["audit_id"] is not None

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["asset_management_authorised"] is True
        assert readiness["execution_target_authorised"] is False
        assert readiness["remediation_ready"] is False

        print(
            "PASS: authorised MANAGED asset is still not ready "
            "without an execution target"
        )

        #
        # ------------------------------------------------------------------
        # 3. Duplicate current asset authorisation must be rejected.
        # ------------------------------------------------------------------
        #
        duplicate_asset_authorisation_blocked = False

        try:
            with conn:
                authorise_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    performed_by=ACTOR,
                    reason="Duplicate authorisation regression test",
                )
        except ValueError:
            duplicate_asset_authorisation_blocked = True

        assert duplicate_asset_authorisation_blocked is True

        print(
            "PASS: duplicate current asset management authorisation "
            "is rejected"
        )

        #
        # ------------------------------------------------------------------
        # 4. Explicitly authorise the first execution target.
        # ------------------------------------------------------------------
        #
        first_target = "192.0.2.240"

        with conn:
            target_result = authorise_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                execution_target=first_target,
                performed_by=ACTOR,
                reason=(
                    "Approved management-plane endpoint for "
                    "regression testing"
                ),
            )

        first_target_id = target_result["execution_target_id"]

        assert first_target_id is not None
        assert target_result["execution_target"] == first_target
        assert target_result["is_active"] is True
        assert target_result["authorised_at"] is not None
        assert target_result["authorised_by"] == ACTOR

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["asset_management_authorised"] is True
        assert readiness["execution_target_authorised"] is True
        assert readiness["remediation_ready"] is True

        active_target = readiness["active_execution_target"]

        assert active_target is not None
        assert active_target["execution_target_id"] == first_target_id
        assert active_target["execution_target"] == first_target

        print(
            "PASS: authorised asset plus authorised execution target "
            "becomes remediation-ready"
        )

        #
        # ------------------------------------------------------------------
        # 5. A second active execution target must be rejected.
        # ------------------------------------------------------------------
        #
        second_active_target_blocked = False

        try:
            with conn:
                authorise_execution_target(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    execution_target="192.0.2.241",
                    performed_by=ACTOR,
                    reason=(
                        "Second-active-target regression test"
                    ),
                )
        except ValueError:
            second_active_target_blocked = True

        assert second_active_target_blocked is True

        print(
            "PASS: service rejects a second simultaneously active "
            "execution target"
        )

        #
        # ------------------------------------------------------------------
        # 6. Atomically replace the execution target.
        # ------------------------------------------------------------------
        #
        replacement_target = "192.0.2.242"

        with conn:
            replacement_result = replace_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                execution_target=replacement_target,
                performed_by=ACTOR,
                reason=(
                    "Management endpoint changed during "
                    "regression testing"
                ),
            )

        replacement_target_id = replacement_result[
            "execution_target_id"
        ]

        assert replacement_target_id is not None
        assert replacement_target_id != first_target_id
        assert replacement_result[
            "previous_execution_target_id"
        ] == first_target_id
        assert replacement_result[
            "previous_execution_target"
        ] == first_target
        assert replacement_result[
            "execution_target"
        ] == replacement_target
        assert replacement_result["is_active"] is True

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["remediation_ready"] is True
        assert readiness["active_execution_target"][
            "execution_target"
        ] == replacement_target

        assert len(
            [
                target
                for target in readiness["execution_targets"]
                if target["is_active"]
            ]
        ) == 1

        historical_first = next(
            target
            for target in readiness["execution_targets"]
            if target["execution_target_id"] == first_target_id
        )

        assert historical_first["is_active"] is False
        assert historical_first["revoked_at"] is not None
        assert historical_first["revoked_by"] == ACTOR

        print(
            "PASS: execution target replacement is atomic and "
            "preserves exactly one active target"
        )

        #
        # ------------------------------------------------------------------
        # 7. The currently active target cannot be replaced with itself.
        # ------------------------------------------------------------------
        #
        self_replacement_blocked = False

        try:
            with conn:
                replace_execution_target(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    execution_target=replacement_target,
                    performed_by=ACTOR,
                    reason="Self-replacement regression test",
                )
        except ValueError:
            self_replacement_blocked = True

        assert self_replacement_blocked is True

        print(
            "PASS: replacing an execution target with itself "
            "is rejected"
        )

        #
        # ------------------------------------------------------------------
        # 8. Asset management cannot be revoked while an execution
        #    target remains active.
        # ------------------------------------------------------------------
        #
        unsafe_asset_revocation_blocked = False

        try:
            with conn:
                revoke_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    performed_by=ACTOR,
                    reason=(
                        "Unsafe revocation regression test"
                    ),
                )
        except ValueError:
            unsafe_asset_revocation_blocked = True

        assert unsafe_asset_revocation_blocked is True

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["remediation_ready"] is True

        print(
            "PASS: asset management cannot be revoked while an "
            "execution target remains active"
        )

        #
        # ------------------------------------------------------------------
        # 9. Revoke the active execution target.
        # ------------------------------------------------------------------
        #
        with conn:
            revoke_target_result = revoke_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason=(
                    "Execution authority withdrawn during "
                    "regression testing"
                ),
            )

        assert revoke_target_result[
            "execution_target_id"
        ] == replacement_target_id
        assert revoke_target_result["is_active"] is False
        assert revoke_target_result["revoked_at"] is not None
        assert revoke_target_result["revoked_by"] == ACTOR

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["asset_management_authorised"] is True
        assert readiness["execution_target_authorised"] is False
        assert readiness["remediation_ready"] is False
        assert readiness["active_execution_target"] is None

        print(
            "PASS: revoking the active execution target immediately "
            "removes remediation readiness"
        )

        #
        # ------------------------------------------------------------------
        # 10. Explicitly revoke asset management.
        # ------------------------------------------------------------------
        #
        with conn:
            revoke_asset_result = revoke_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason=(
                    "Asset removed from managed remediation scope "
                    "during regression testing"
                ),
            )

        assert revoke_asset_result["inventory_state"] == "UNMANAGED"
        assert revoke_asset_result["management_revoked_at"] is not None
        assert revoke_asset_result["management_revoked_by"] == ACTOR

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["asset"]["inventory_state"] == "UNMANAGED"
        assert readiness["asset_management_authorised"] is False
        assert readiness["execution_target_authorised"] is False
        assert readiness["remediation_ready"] is False

        print(
            "PASS: explicit asset management revocation moves the "
            "asset to UNMANAGED and keeps it ineligible"
        )

        #
        # ------------------------------------------------------------------
        # 11. Verify complete administrative audit history.
        # ------------------------------------------------------------------
        #
        with conn:
            history = get_asset_readiness_history(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        event_types = [
            event["event_type"]
            for event in history
        ]

        assert event_types == [
            "ASSET_MANAGED",
            "EXECUTION_TARGET_AUTHORISED",
            "EXECUTION_TARGET_REPLACED",
            "EXECUTION_TARGET_REVOKED",
            "ASSET_MANAGEMENT_REVOKED",
        ]

        for event in history:
            assert event["asset_id"] == asset_id
            assert event["tenant_code"] == TENANT
            assert event["performed_by"] == ACTOR
            assert str(event["reason"]).strip()
            assert isinstance(event["event_metadata"], dict)
            assert event["created_at"] is not None

        assert history[0]["execution_target_id"] is None

        assert history[1][
            "execution_target_id"
        ] == first_target_id

        assert history[2][
            "execution_target_id"
        ] == replacement_target_id

        assert history[2]["event_metadata"][
            "previous_execution_target_id"
        ] == first_target_id

        assert history[2]["event_metadata"][
            "new_execution_target_id"
        ] == replacement_target_id

        assert history[3][
            "execution_target_id"
        ] == replacement_target_id

        assert history[4]["execution_target_id"] is None

        print(
            "PASS: administrative readiness transitions produce the "
            "expected append-only audit history"
        )

        #
        # ------------------------------------------------------------------
        # 12. Historical target re-authorisation.
        #
        # The database uniqueness constraint prevents inserting the same
        # (asset_id, execution_target) twice. The service must therefore
        # reactivate the existing historical row rather than insert a
        # duplicate.
        # ------------------------------------------------------------------
        #
        with conn:
            reauthorise_asset = authorise_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason=(
                    "Asset returned to managed remediation scope"
                ),
            )

        assert reauthorise_asset["inventory_state"] == "MANAGED"

        with conn:
            reauthorised_target = authorise_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                execution_target=first_target,
                performed_by=ACTOR,
                reason=(
                    "Previously used management endpoint "
                    "re-authorised"
                ),
            )

        assert reauthorised_target[
            "execution_target_id"
        ] == first_target_id

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["remediation_ready"] is True
        assert readiness["active_execution_target"][
            "execution_target_id"
        ] == first_target_id
        assert readiness["active_execution_target"][
            "execution_target"
        ] == first_target

        print(
            "PASS: historical execution target can be safely "
            "re-authorised without creating a duplicate row"
        )

        #
        # ------------------------------------------------------------------
        # 13. Tenant isolation.
        #
        # An administrative caller must not be able to address an asset
        # through a different tenant_code, even when the numeric asset_id
        # is otherwise valid.
        # ------------------------------------------------------------------
        #
        tenant_isolation_blocked = False

        try:
            with conn:
                authorise_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code="DIFFERENT-TENANT",
                    performed_by=ACTOR,
                    reason="Cross-tenant access regression test",
                )
        except ValueError:
            tenant_isolation_blocked = True

        assert tenant_isolation_blocked is True

        with conn:
            readiness = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
            )

        assert readiness["remediation_ready"] is True
        assert readiness["asset"]["inventory_state"] == "MANAGED"

        print(
            "PASS: administrative readiness operations enforce "
            "tenant isolation"
        )

        #
        # ------------------------------------------------------------------
        # 14. Administrative inputs must be non-blank.
        #
        # Actor attribution, reason, tenant identity, execution target and
        # source are security-relevant administrative inputs. Whitespace-only
        # values must therefore be rejected before any state transition.
        # ------------------------------------------------------------------
        #
        validation_cases = [
            (
                "tenant_code",
                lambda: authorise_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code="   ",
                    performed_by=ACTOR,
                    reason="Input validation regression test",
                ),
            ),
            (
                "performed_by",
                lambda: authorise_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    performed_by="   ",
                    reason="Input validation regression test",
                ),
            ),
            (
                "reason",
                lambda: authorise_asset_management(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    performed_by=ACTOR,
                    reason="   ",
                ),
            ),
            (
                "execution_target",
                lambda: authorise_execution_target(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    execution_target="   ",
                    performed_by=ACTOR,
                    reason="Input validation regression test",
                ),
            ),
            (
                "source",
                lambda: authorise_execution_target(
                    conn,
                    asset_id=asset_id,
                    tenant_code=TENANT,
                    execution_target="10.0.0.250",
                    performed_by=ACTOR,
                    reason="Input validation regression test",
                    source="   ",
                ),
            ),
        ]

        for field_name, operation in validation_cases:
            blocked = False

            try:
                operation()
            except ValueError:
                blocked = True

            assert blocked is True, (
                f"blank {field_name} was not rejected"
            )

        print(
            "PASS: administrative readiness operations reject "
            "blank security-relevant inputs"
        )

        #
        # ------------------------------------------------------------------
        # 15. Caller-owned transaction rollback.
        #
        # The readiness-management service must not commit independently.
        # An asset-state transition and its audit event must therefore both
        # disappear when the caller rolls the transaction back.
        # ------------------------------------------------------------------
        #
        with conn:
            rollback_asset_id = create_provisional_asset(conn)

        rollback_forced = False

        try:
            authorise_asset_management(
                conn,
                asset_id=rollback_asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason="Caller-owned rollback regression test",
            )

            raise RuntimeError("force readiness-management rollback")

        except RuntimeError as exc:
            assert str(exc) == (
                "force readiness-management rollback"
            )

            conn.rollback()
            rollback_forced = True

        assert rollback_forced is True

        with conn:
            rollback_readiness = get_asset_readiness(
                conn,
                asset_id=rollback_asset_id,
                tenant_code=TENANT,
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM asset_remediation_audit
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        rollback_asset_id,
                        TENANT,
                    ),
                )

                rollback_audit_count = cur.fetchone()[0]

        assert rollback_readiness[
            "asset"
        ]["inventory_state"] == "PROVISIONAL"

        assert rollback_readiness[
            "asset_management_authorised"
        ] is False

        assert rollback_readiness[
            "remediation_ready"
        ] is False

        assert rollback_audit_count == 0

        print(
            "PASS: readiness management leaves transaction ownership "
            "with the caller and rolls back state plus audit atomically"
        )

        #
        # ------------------------------------------------------------------
        # 16. Final cleanup.
        # ------------------------------------------------------------------
        #
        with conn:
            # The active target must first be explicitly revoked because
            # PR #32 forbids silently deactivating authorised targets.
            revoke_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason="Regression test cleanup",
            )

            revoke_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=TENANT,
                performed_by=ACTOR,
                reason="Regression test cleanup",
            )

        with conn:
            clean_database(conn)

        print(
            "PASS: administrative readiness management regression "
            "completed successfully"
        )

    finally:
        conn.close()


if __name__ == "__main__":
    main()
