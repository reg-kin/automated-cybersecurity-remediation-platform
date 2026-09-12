"""Execution-node authentication for Scan Coordination.

This module authenticates distributed scan execution nodes.

It deliberately does not:
- authenticate individual scan executions;
- replace per-execution lease credentials;
- create or modify scan policies;
- lease scan executions;
- invoke scanner orchestrators;
- construct security findings.

Plaintext node credentials are returned only when issued. PostgreSQL stores
only SHA-256 hexadecimal digests.

The caller owns transaction boundaries. Functions in this module do not
commit or roll back the supplied PostgreSQL connection.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any


class ScanNodeAuthError(ValueError):
    """Base exception for expected execution-node authentication failures."""


class ScanNodeAuthValidationError(ScanNodeAuthError):
    """Authentication-management request data is invalid."""


class ScanNodeNotFoundError(ScanNodeAuthError):
    """The requested execution node does not exist."""


class ScanNodeCredentialNotFoundError(ScanNodeAuthError):
    """The requested execution-node credential does not exist."""


class ScanNodeCredentialConflictError(ScanNodeAuthError):
    """The requested credential transition conflicts with current state."""


class ScanNodeAuthenticationError(ScanNodeAuthError):
    """The presented execution-node credential is not authorised."""


def _require_nonblank(value: Any, field_name: str) -> str:
    if value is None or not str(value).strip():
        raise ScanNodeAuthValidationError(
            f"{field_name} must be non-blank"
        )

    return str(value).strip()


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ScanNodeAuthValidationError(
            f"{field_name} must be a positive integer"
        )

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanNodeAuthValidationError(
            f"{field_name} must be a positive integer"
        ) from exc

    if parsed <= 0:
        raise ScanNodeAuthValidationError(
            f"{field_name} must be a positive integer"
        )

    return parsed


def _hash_credential(credential: str) -> str:
    return hashlib.sha256(
        credential.encode("utf-8")
    ).hexdigest()


def _generate_credential() -> str:
    """Generate an opaque credential with 256 bits of random entropy."""

    return secrets.token_urlsafe(32)


def _get_node_for_update(
    conn,
    *,
    execution_node_id: int,
) -> dict:
    execution_node_id = _require_positive_int(
        execution_node_id,
        "execution_node_id",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                execution_node_id,
                node_code,
                display_name,
                transport_mode,
                is_enabled,
                last_seen_at
            FROM scan_execution_nodes
            WHERE execution_node_id = %s
            FOR UPDATE
            """,
            (execution_node_id,),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanNodeNotFoundError(
            f"Execution node {execution_node_id} does not exist"
        )

    return {
        "execution_node_id": row[0],
        "node_code": row[1],
        "display_name": row[2],
        "transport_mode": row[3],
        "is_enabled": row[4],
        "last_seen_at": row[5],
    }


def issue_node_credential(
    conn,
    *,
    execution_node_id: int,
) -> dict:
    """Issue a new authentication credential for one execution node.

    The returned plaintext credential must be delivered securely to the
    execution node. It cannot subsequently be recovered from PostgreSQL.
    """

    node = _get_node_for_update(
        conn,
        execution_node_id=execution_node_id,
    )

    plaintext_credential = _generate_credential()
    credential_hash = _hash_credential(
        plaintext_credential
    )

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
                %s,
                TRUE
            )
            RETURNING
                credential_id,
                created_at
            """,
            (
                node["execution_node_id"],
                credential_hash,
            ),
        )

        row = cur.fetchone()

    return {
        "credential_id": row[0],
        "execution_node_id": node["execution_node_id"],
        "node_code": node["node_code"],
        "credential": plaintext_credential,
        "created_at": row[1],
    }


def revoke_node_credential(
    conn,
    *,
    execution_node_id: int,
    credential_id: int,
) -> dict:
    """Revoke one active credential belonging to an execution node."""

    execution_node_id = _require_positive_int(
        execution_node_id,
        "execution_node_id",
    )
    credential_id = _require_positive_int(
        credential_id,
        "credential_id",
    )

    # Locking the node keeps administrative transitions for one node ordered.
    node = _get_node_for_update(
        conn,
        execution_node_id=execution_node_id,
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                credential_id,
                execution_node_id,
                is_active,
                created_at,
                revoked_at,
                last_used_at
            FROM scan_execution_node_credentials
            WHERE credential_id = %s
              AND execution_node_id = %s
            FOR UPDATE
            """,
            (
                credential_id,
                node["execution_node_id"],
            ),
        )

        credential_row = cur.fetchone()

        if credential_row is None:
            raise ScanNodeCredentialNotFoundError(
                f"Credential {credential_id} does not exist for "
                f"execution node {execution_node_id}"
            )

        if credential_row[2] is not True:
            raise ScanNodeCredentialConflictError(
                f"Credential {credential_id} is already revoked"
            )

        cur.execute(
            """
            UPDATE scan_execution_node_credentials
            SET
                is_active = FALSE,
                revoked_at = now()
            WHERE credential_id = %s
              AND execution_node_id = %s
              AND is_active = TRUE
            RETURNING
                revoked_at,
                last_used_at
            """,
            (
                credential_id,
                node["execution_node_id"],
            ),
        )

        revoked_row = cur.fetchone()

    if revoked_row is None:
        raise ScanNodeCredentialConflictError(
            f"Credential {credential_id} could not be revoked"
        )

    return {
        "credential_id": credential_id,
        "execution_node_id": node["execution_node_id"],
        "node_code": node["node_code"],
        "is_active": False,
        "revoked_at": revoked_row[0],
        "last_used_at": revoked_row[1],
    }


def authenticate_node_credential(
    conn,
    *,
    credential: str,
) -> dict:
    """Authenticate one execution node from an opaque bearer credential.

    Successful authentication atomically updates both credential.last_used_at
    and execution_node.last_seen_at.

    Disabled nodes and revoked/unknown credentials are deliberately reported
    through the same authentication failure class.
    """

    credential = _require_nonblank(
        credential,
        "credential",
    )

    credential_hash = _hash_credential(
        credential
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_execution_node_credentials c
            SET last_used_at = now()
            FROM scan_execution_nodes n
            WHERE c.credential_hash = %s
              AND c.is_active = TRUE
              AND c.revoked_at IS NULL
              AND n.execution_node_id = c.execution_node_id
              AND n.is_enabled = TRUE
            RETURNING
                c.credential_id,
                c.execution_node_id,
                n.node_code,
                n.display_name,
                n.transport_mode,
                c.last_used_at
            """,
            (credential_hash,),
        )

        row = cur.fetchone()

        if row is None:
            raise ScanNodeAuthenticationError(
                "Invalid execution-node credential"
            )

        cur.execute(
            """
            UPDATE scan_execution_nodes
            SET last_seen_at = now()
            WHERE execution_node_id = %s
            RETURNING last_seen_at
            """,
            (row[1],),
        )

        node_last_seen = cur.fetchone()[0]

    return {
        "credential_id": row[0],
        "execution_node_id": row[1],
        "node_code": row[2],
        "display_name": row[3],
        "transport_mode": row[4],
        "credential_last_used_at": row[5],
        "node_last_seen_at": node_last_seen,
    }
