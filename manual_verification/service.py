"""Tenant-scoped Manual Verification lifecycle operations.

Callers must manage transaction commit and rollback.
"""

from datetime import datetime, timezone

from psycopg2.extras import Json

from remediation.shared.db import (
    complete_verification,
    update_execution_status,
)


class ManualVerificationError(ValueError):
    """Invalid or conflicting manual verification operation."""


def create_review(
    conn,
    *,
    tenant_code,
    finding_id,
    execution_id,
    verification_id,
    verification_result,
):
    """Complete Stage 2 as inconclusive and create a pending review.

    The caller must execute this operation within a transaction.
    """

    if not isinstance(tenant_code, str) or not tenant_code.strip():
        raise ManualVerificationError("tenant_code is required")

    if not isinstance(verification_result, dict):
        raise ManualVerificationError(
            "verification_result must be a JSON object"
        )

    if (
        verification_result.get("verification_status") != "INCONCLUSIVE"
        or "present" not in verification_result
        or verification_result["present"] is not None
        or not isinstance(
            verification_result.get("verification_reason"), str
        )
        or not verification_result["verification_reason"].strip()
    ):
        raise ManualVerificationError(
            "Explicit INCONCLUSIVE verification evidence is required"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                f.lifecycle_status,
                e.status,
                v.status,
                v.stage
            FROM unified_security_findings f
            JOIN remediation_executions e
              ON e.finding_id = f.finding_id
            JOIN remediation_verifications v
              ON v.execution_id = e.execution_id
             AND v.finding_id = f.finding_id
            WHERE f.finding_id = %s
              AND f.tenant_code = %s
              AND e.execution_id = %s
              AND v.verification_id = %s
            FOR UPDATE OF f, e, v
            """,
            (
                finding_id,
                tenant_code.strip(),
                execution_id,
                verification_id,
            ),
        )
        row = cur.fetchone()

        if row is None:
            raise ManualVerificationError(
                "Tenant-scoped verification context not found"
            )

        finding_status, execution_status, verification_status, stage = row

        if (
            finding_status != "IN_REMEDIATION"
            or execution_status != "VERIFYING"
            or verification_status != "PENDING"
            or stage != 2
        ):
            raise ManualVerificationError(
                "Verification context is not eligible for manual review"
            )

    complete_verification(
        conn,
        verification_id,
        "INCONCLUSIVE",
        verification_result,
    )

    update_execution_status(
        conn,
        execution_id,
        "AWAITING_MANUAL_VERIFICATION",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO manual_verification_reviews (
                tenant_code,
                finding_id,
                execution_id,
                verification_id
            )
            VALUES (%s, %s, %s, %s)
            RETURNING review_id
            """,
            (
                tenant_code.strip(),
                finding_id,
                execution_id,
                verification_id,
            ),
        )
        return cur.fetchone()[0]


def record_decision(
    conn,
    *,
    review_id,
    tenant_code,
    reviewer_id,
    decision,
    justification,
    evidence,
):
    """Record a tenant-scoped reviewer decision atomically."""

    from remediation.shared.db import (
        resolve_finding,
        reopen_failed,
    )

    for name, value in (
        ("tenant_code", tenant_code),
        ("reviewer_id", reviewer_id),
        ("justification", justification),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ManualVerificationError(f"{name} is required")

    if decision not in (
        "REMEDIATED",
        "STILL_PRESENT",
        "INCONCLUSIVE",
    ):
        raise ManualVerificationError("Invalid reviewer decision")

    if not isinstance(evidence, dict):
        raise ManualVerificationError(
            "evidence must be a JSON object"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                r.finding_id,
                r.execution_id,
                r.status,
                e.status,
                f.lifecycle_status
            FROM manual_verification_reviews r
            JOIN remediation_executions e
              ON e.execution_id = r.execution_id
            JOIN unified_security_findings f
              ON f.finding_id = r.finding_id
            WHERE r.review_id = %s
              AND r.tenant_code = %s
            FOR UPDATE OF r, e, f
            """,
            (review_id, tenant_code.strip()),
        )

        row = cur.fetchone()

        if row is None:
            raise ManualVerificationError(
                "Tenant-scoped manual review not found"
            )

        finding_id, execution_id, review_status, execution_status, finding_status = row

        if (
            review_status != "PENDING"
            or execution_status != "AWAITING_MANUAL_VERIFICATION"
            or finding_status != "IN_REMEDIATION"
        ):
            raise ManualVerificationError(
                "Manual review is no longer eligible for a decision"
            )

        cur.execute(
            """
            INSERT INTO manual_verification_decisions (
                review_id,
                tenant_code,
                reviewer_id,
                decision,
                justification,
                evidence
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING decision_id
            """,
            (
                review_id,
                tenant_code.strip(),
                reviewer_id.strip(),
                decision,
                justification.strip(),
                Json(evidence),
            ),
        )

        decision_id = cur.fetchone()[0]

    if decision == "REMEDIATED":
        update_execution_status(
            conn,
            execution_id,
            "SUCCESS",
            completed_at=datetime.now(timezone.utc),
        )
        resolve_finding(conn, finding_id)

    elif decision == "STILL_PRESENT":
        update_execution_status(
            conn,
            execution_id,
            "FAILED",
            error_message="Manual verification: finding still present",
            completed_at=datetime.now(timezone.utc),
        )
        if not reopen_failed(
            conn,
            finding_id,
            "Manual verification: finding still present",
        ):
            raise ManualVerificationError(
                "Could not reopen finding"
            )

    if decision != "INCONCLUSIVE":
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE manual_verification_reviews
                SET status = 'COMPLETED',
                    completed_at = now()
                WHERE review_id = %s
                  AND tenant_code = %s
                  AND status = 'PENDING'
                """,
                (review_id, tenant_code.strip()),
            )

            if cur.rowcount != 1:
                raise ManualVerificationError(
                    "Could not complete manual review"
                )

    return decision_id
