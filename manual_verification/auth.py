"""Tenant-scoped reviewer authentication for Manual Verification.

Credentials are independent of scan execution-node credentials.
Only SHA-256 token hashes are persisted. Plaintext tokens are
returned once, when issued.

The caller owns transaction boundaries.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone


class ManualReviewerAuthError(ValueError):
    """Base class for expected reviewer credential errors."""


class ReviewerCredentialValidationError(ManualReviewerAuthError):
    """Invalid credential-management input."""


class ReviewerAuthenticationError(ManualReviewerAuthError):
    """Unknown, inactive, revoked, or expired credential."""


class ReviewerCredentialNotFoundError(ManualReviewerAuthError):
    """Credential does not exist within the specified tenant."""


class ReviewerCredentialConflictError(ManualReviewerAuthError):
    """Credential cannot undergo the requested transition."""


def _nonblank(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ReviewerCredentialValidationError(
            f"{name} must be a non-blank string"
        )
    return value.strip()


def _positive_int(value, name):
    if isinstance(value, bool):
        raise ReviewerCredentialValidationError(
            f"{name} must be a positive integer"
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ReviewerCredentialValidationError(
            f"{name} must be a positive integer"
        ) from exc
    if parsed <= 0:
        raise ReviewerCredentialValidationError(
            f"{name} must be a positive integer"
        )
    return parsed


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_reviewer_credential(
    conn,
    *,
    reviewer_id,
    tenant_code,
    expires_at=None,
):
    """Issue a tenant-scoped bearer token, returned only once."""

    reviewer_id = _nonblank(reviewer_id, "reviewer_id")
    tenant_code = _nonblank(tenant_code, "tenant_code")

    if len(reviewer_id) > 200 or len(tenant_code) > 100:
        raise ReviewerCredentialValidationError(
            "Reviewer or tenant identifier exceeds its maximum length"
        )

    if expires_at is not None:
        if (
            not isinstance(expires_at, datetime)
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
        ):
            raise ReviewerCredentialValidationError(
                "expires_at must be a timezone-aware datetime"
            )
        if expires_at <= datetime.now(timezone.utc):
            raise ReviewerCredentialValidationError(
                "expires_at must be in the future"
            )

    token = secrets.token_urlsafe(32)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO manual_verification_reviewer_credentials (
                reviewer_id,
                tenant_code,
                token_hash,
                expires_at
            )
            VALUES (%s, %s, %s, %s)
            RETURNING credential_id, created_at
            """,
            (
                reviewer_id,
                tenant_code,
                _hash_token(token),
                expires_at,
            ),
        )
        credential_id, created_at = cur.fetchone()

    return {
        "credential_id": credential_id,
        "reviewer_id": reviewer_id,
        "tenant_code": tenant_code,
        "credential": token,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def authenticate_reviewer_credential(conn, *, credential):
    """Resolve reviewer identity and tenant from an active bearer token."""

    token = _nonblank(credential, "credential")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                credential_id,
                reviewer_id,
                tenant_code
            FROM manual_verification_reviewer_credentials
            WHERE token_hash = %s
              AND is_active = TRUE
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            FOR UPDATE
            """,
            (_hash_token(token),),
        )
        row = cur.fetchone()

    if row is None:
        raise ReviewerAuthenticationError(
            "Invalid reviewer credential"
        )

    return {
        "credential_id": row[0],
        "reviewer_id": row[1],
        "tenant_code": row[2],
    }


def revoke_reviewer_credential(
    conn,
    *,
    credential_id,
    tenant_code,
):
    """Revoke one credential within its authorised tenant."""

    credential_id = _positive_int(
        credential_id, "credential_id"
    )
    tenant_code = _nonblank(tenant_code, "tenant_code")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT is_active, revoked_at
            FROM manual_verification_reviewer_credentials
            WHERE credential_id = %s
              AND tenant_code = %s
            FOR UPDATE
            """,
            (credential_id, tenant_code),
        )
        row = cur.fetchone()

        if row is None:
            raise ReviewerCredentialNotFoundError(
                "Reviewer credential not found"
            )

        if not row[0] or row[1] is not None:
            raise ReviewerCredentialConflictError(
                "Reviewer credential is already revoked"
            )

        cur.execute(
            """
            UPDATE manual_verification_reviewer_credentials
            SET is_active = FALSE,
                revoked_at = now()
            WHERE credential_id = %s
              AND tenant_code = %s
              AND is_active = TRUE
              AND revoked_at IS NULL
            RETURNING revoked_at
            """,
            (credential_id, tenant_code),
        )
        revoked = cur.fetchone()

    if revoked is None:
        raise ReviewerCredentialConflictError(
            "Reviewer credential could not be revoked"
        )

    return {
        "credential_id": credential_id,
        "tenant_code": tenant_code,
        "is_active": False,
        "revoked_at": revoked[0],
    }
