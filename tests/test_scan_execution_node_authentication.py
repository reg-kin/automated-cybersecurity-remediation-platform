#!/usr/bin/env python3

"""Regression tests for Scan Execution Node Authentication V1."""

import hashlib
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2.errors import CheckViolation


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination.node_auth import (
    ScanNodeAuthenticationError,
    ScanNodeCredentialConflictError,
    ScanNodeCredentialNotFoundError,
    ScanNodeNotFoundError,
    authenticate_node_credential,
    issue_node_credential,
    revoke_node_credential,
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


NODE_CODE = "scan-node-auth-test"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM scan_execution_nodes
            WHERE node_code = %s
            """,
            (NODE_CODE,),
        )


def create_execution_node(conn):
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
                'Scan Node Authentication Regression Node',
                'PULL',
                TRUE
            )
            RETURNING execution_node_id
            """,
            (NODE_CODE,),
        )

        return cur.fetchone()[0]


def passed(message):
    print(f"PASS: {message}")


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)
            execution_node_id = create_execution_node(conn)

        # ------------------------------------------------------------------
        # 1. Credential issuance returns plaintext once and stores only hash.
        # ------------------------------------------------------------------
        with conn:
            first = issue_node_credential(
                conn,
                execution_node_id=execution_node_id,
            )

        assert first["execution_node_id"] == execution_node_id
        assert first["node_code"] == NODE_CODE
        assert first["credential_id"] is not None
        assert first["credential"]

        first_token = first["credential"]
        first_id = first["credential_id"]

        expected_hash = hashlib.sha256(
            first_token.encode("utf-8")
        ).hexdigest()

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        credential_hash,
                        is_active,
                        revoked_at,
                        last_used_at
                    FROM scan_execution_node_credentials
                    WHERE credential_id = %s
                    """,
                    (first_id,),
                )

                stored = cur.fetchone()

        assert stored == (
            expected_hash,
            True,
            None,
            None,
        )

        assert stored[0] != first_token

        passed(
            "credential issuance returns plaintext while PostgreSQL "
            "stores only its SHA-256 digest"
        )

        # ------------------------------------------------------------------
        # 2. Database rejects malformed credential hashes.
        # ------------------------------------------------------------------
        malformed_hash_blocked = False

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO scan_execution_node_credentials (
                            execution_node_id,
                            credential_hash,
                            is_active
                        )
                        VALUES (
                            %s,
                            'not-a-valid-sha256-digest',
                            TRUE
                        )
                        """,
                        (execution_node_id,),
                    )
        except CheckViolation:
            malformed_hash_blocked = True

        assert malformed_hash_blocked is True

        passed(
            "database rejects malformed execution-node credential hashes"
        )

        # ------------------------------------------------------------------
        # 3. Valid credential authenticates and derives node identity.
        # ------------------------------------------------------------------
        with conn:
            authenticated = authenticate_node_credential(
                conn,
                credential=first_token,
            )

        assert authenticated["credential_id"] == first_id
        assert (
            authenticated["execution_node_id"]
            == execution_node_id
        )
        assert authenticated["node_code"] == NODE_CODE
        assert authenticated["transport_mode"] == "PULL"
        assert (
            authenticated["credential_last_used_at"]
            is not None
        )
        assert authenticated["node_last_seen_at"] is not None

        passed(
            "valid credential authenticates and derives execution-node identity"
        )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        last_used_at,
                        (
                            SELECT last_seen_at
                            FROM scan_execution_nodes
                            WHERE execution_node_id = %s
                        )
                    FROM scan_execution_node_credentials
                    WHERE credential_id = %s
                    """,
                    (
                        execution_node_id,
                        first_id,
                    ),
                )

                usage = cur.fetchone()

        assert usage[0] is not None
        assert usage[1] is not None

        passed(
            "successful authentication records credential use and node presence"
        )

        # ------------------------------------------------------------------
        # 4. Unknown credential is rejected.
        # ------------------------------------------------------------------
        invalid_blocked = False

        try:
            with conn:
                authenticate_node_credential(
                    conn,
                    credential=(
                        "this-is-a-validly-presented-but-unknown-token"
                    ),
                )
        except ScanNodeAuthenticationError:
            invalid_blocked = True

        assert invalid_blocked is True

        passed("unknown execution-node credential is rejected")

        # ------------------------------------------------------------------
        # 5. Multiple active credentials support controlled rotation.
        # ------------------------------------------------------------------
        with conn:
            second = issue_node_credential(
                conn,
                execution_node_id=execution_node_id,
            )

        second_token = second["credential"]
        second_id = second["credential_id"]

        assert second_id != first_id
        assert second_token != first_token

        with conn:
            first_auth = authenticate_node_credential(
                conn,
                credential=first_token,
            )

            second_auth = authenticate_node_credential(
                conn,
                credential=second_token,
            )

        assert first_auth["execution_node_id"] == execution_node_id
        assert second_auth["execution_node_id"] == execution_node_id

        passed(
            "multiple active node credentials permit controlled rotation"
        )

        # ------------------------------------------------------------------
        # 6. Explicit revocation invalidates only the selected credential.
        # ------------------------------------------------------------------
        with conn:
            revoked = revoke_node_credential(
                conn,
                execution_node_id=execution_node_id,
                credential_id=first_id,
            )

        assert revoked["credential_id"] == first_id
        assert revoked["is_active"] is False
        assert revoked["revoked_at"] is not None

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        is_active,
                        revoked_at IS NOT NULL,
                        credential_hash
                    FROM scan_execution_node_credentials
                    WHERE credential_id = %s
                    """,
                    (first_id,),
                )

                revoked_state = cur.fetchone()

        assert revoked_state == (
            False,
            True,
            expected_hash,
        )

        passed(
            "credential revocation preserves hashed history and marks "
            "the credential inactive"
        )

        revoked_auth_blocked = False

        try:
            with conn:
                authenticate_node_credential(
                    conn,
                    credential=first_token,
                )
        except ScanNodeAuthenticationError:
            revoked_auth_blocked = True

        assert revoked_auth_blocked is True

        with conn:
            still_valid = authenticate_node_credential(
                conn,
                credential=second_token,
            )

        assert still_valid["credential_id"] == second_id

        passed(
            "revoked credential cannot authenticate while replacement "
            "credential remains valid"
        )

        # ------------------------------------------------------------------
        # 7. Duplicate revocation is rejected.
        # ------------------------------------------------------------------
        duplicate_revocation_blocked = False

        try:
            with conn:
                revoke_node_credential(
                    conn,
                    execution_node_id=execution_node_id,
                    credential_id=first_id,
                )
        except ScanNodeCredentialConflictError:
            duplicate_revocation_blocked = True

        assert duplicate_revocation_blocked is True

        passed("duplicate credential revocation is rejected")

        # ------------------------------------------------------------------
        # 8. Credential cannot be revoked through another node identity.
        # ------------------------------------------------------------------
        with conn:
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
                        'scan-node-auth-other',
                        'Other Scan Node',
                        'PULL',
                        TRUE
                    )
                    RETURNING execution_node_id
                    """
                )

                other_node_id = cur.fetchone()[0]

        cross_node_blocked = False

        try:
            with conn:
                revoke_node_credential(
                    conn,
                    execution_node_id=other_node_id,
                    credential_id=second_id,
                )
        except ScanNodeCredentialNotFoundError:
            cross_node_blocked = True

        assert cross_node_blocked is True

        passed(
            "credential administration is bound to its execution node"
        )

        # ------------------------------------------------------------------
        # 9. Disabled node cannot authenticate.
        # ------------------------------------------------------------------
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_execution_nodes
                    SET is_enabled = FALSE
                    WHERE execution_node_id = %s
                    """,
                    (execution_node_id,),
                )

        disabled_node_blocked = False

        try:
            with conn:
                authenticate_node_credential(
                    conn,
                    credential=second_token,
                )
        except ScanNodeAuthenticationError:
            disabled_node_blocked = True

        assert disabled_node_blocked is True

        passed(
            "disabled execution node cannot authenticate with an "
            "otherwise active credential"
        )

        # ------------------------------------------------------------------
        # 10. Re-enable node; active replacement credential works again.
        # ------------------------------------------------------------------
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_execution_nodes
                    SET is_enabled = TRUE
                    WHERE execution_node_id = %s
                    """,
                    (execution_node_id,),
                )

            restored = authenticate_node_credential(
                conn,
                credential=second_token,
            )

        assert restored["credential_id"] == second_id

        passed(
            "active credential becomes usable again after node re-enablement"
        )

        # ------------------------------------------------------------------
        # 11. Non-existent node cannot receive credentials.
        # ------------------------------------------------------------------
        missing_node_blocked = False

        try:
            with conn:
                issue_node_credential(
                    conn,
                    execution_node_id=9223372036854775807,
                )
        except ScanNodeNotFoundError:
            missing_node_blocked = True

        assert missing_node_blocked is True

        passed("credential cannot be issued for a non-existent node")

        # ------------------------------------------------------------------
        # 12. Caller owns transaction boundary.
        # ------------------------------------------------------------------
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
                    'scan-node-auth-rollback',
                    'Rollback Scan Node',
                    'PULL',
                    TRUE
                )
                RETURNING execution_node_id
                """
            )

            rollback_node_id = cur.fetchone()[0]

        issued_for_rollback = issue_node_credential(
            conn,
            execution_node_id=rollback_node_id,
        )

        rollback_credential_id = issued_for_rollback[
            "credential_id"
        ]

        conn.rollback()

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_execution_nodes
                    WHERE execution_node_id = %s
                    """,
                    (rollback_node_id,),
                )

                rollback_node_count = cur.fetchone()[0]

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_execution_node_credentials
                    WHERE credential_id = %s
                    """,
                    (rollback_credential_id,),
                )

                rollback_credential_count = cur.fetchone()[0]

        assert rollback_node_count == 0
        assert rollback_credential_count == 0

        passed(
            "node-authentication service leaves transaction ownership "
            "with caller"
        )

        # ------------------------------------------------------------------
        # 13. Credential rows cascade when an unreferenced node is deleted.
        # ------------------------------------------------------------------
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM scan_execution_nodes
                    WHERE node_code = 'scan-node-auth-other'
                    """
                )

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM scan_execution_node_credentials
                    WHERE execution_node_id = %s
                    """,
                    (other_node_id,),
                )

                orphan_count = cur.fetchone()[0]

        assert orphan_count == 0

        passed(
            "credentials cannot outlive their execution-node identity"
        )

        passed(
            "Scan Execution Node Authentication V1 regression tests"
        )

    finally:
        try:
            with conn:
                clean_database(conn)

                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM scan_execution_nodes
                        WHERE node_code IN (
                            'scan-node-auth-other',
                            'scan-node-auth-rollback'
                        )
                        """
                    )
        finally:
            conn.close()


if __name__ == "__main__":
    main()
