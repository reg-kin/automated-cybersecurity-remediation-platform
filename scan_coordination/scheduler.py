"""Deterministic scan-policy scheduling service.

This module materialises due CRON policy occurrences as scan executions.

It deliberately does not:
- invoke scanners;
- parse scanner-native evidence;
- determine finding_class;
- construct Unified Security Findings;
- perform risk contextualisation;
- authorise remediation;
- resolve canonical assets from scanner evidence.

The caller owns the database transaction. Creating an execution and advancing
the policy's next_run_at therefore occur atomically when the caller commits.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scan_coordination.scheduling import next_cron_occurrence
from scan_coordination.service import create_scan_execution
from scan_coordination.subject_resolver import resolve_scanner_subject


ACTIVE_EXECUTION_STATUSES = (
    "PENDING",
    "LEASED",
    "RUNNING",
)


class ScanSchedulerError(RuntimeError):
    """Base error for scan-policy scheduling."""


class ScanSchedulerStateError(ScanSchedulerError):
    """Raised when persisted scheduler state violates scheduler invariants."""


def _load_next_due_policy(conn) -> dict[str, Any] | None:
    """Lock and return one schedulable due CRON policy.

    Policies with an active execution are deliberately excluded.

    This gives V1 deferred catch-up semantics:

        - next_run_at is not advanced while an earlier execution is active;
        - once that execution becomes terminal, the still-due occurrence can
          be materialised;
        - other due policies are not blocked by that policy.

    FOR UPDATE SKIP LOCKED allows multiple scheduler workers to select
    different due policies safely.
    """

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                p.scan_policy_id,
                p.tenant_code,
                p.asset_id,
                p.scanner_type,
                p.schedule_expression,
                p.schedule_timezone,
                p.next_run_at
            FROM scan_policies AS p
            WHERE p.is_enabled IS TRUE
              AND p.schedule_type = 'CRON'
              AND p.next_run_at IS NOT NULL
              AND p.next_run_at <= now()
              AND NOT EXISTS (
                    SELECT 1
                    FROM scan_executions AS e
                    WHERE e.scan_policy_id = p.scan_policy_id
                      AND e.status IN (
                          'PENDING',
                          'LEASED',
                          'RUNNING'
                      )
              )
            ORDER BY
                p.next_run_at ASC,
                p.scan_policy_id ASC
            LIMIT 1
            FOR UPDATE OF p SKIP LOCKED
            """
        )

        row = cur.fetchone()

    if row is None:
        return None

    return {
        "scan_policy_id": row[0],
        "tenant_code": row[1],
        "asset_id": row[2],
        "scanner_type": row[3],
        "schedule_expression": row[4],
        "schedule_timezone": row[5],
        "next_run_at": row[6],
    }


def _load_existing_occurrence(
    conn,
    *,
    scan_policy_id: int,
    scheduled_for: datetime,
) -> dict[str, Any] | None:
    """Return an execution already materialised for one policy occurrence."""

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                scan_execution_id,
                status
            FROM scan_executions
            WHERE scan_policy_id = %s
              AND scheduled_for = %s
            """,
            (
                scan_policy_id,
                scheduled_for,
            ),
        )

        row = cur.fetchone()

    if row is None:
        return None

    return {
        "scan_execution_id": row[0],
        "status": row[1],
    }


def _calculate_following_occurrence(
    *,
    schedule_expression: str,
    schedule_timezone: str,
    scheduled_for: datetime,
) -> datetime:
    """Calculate the occurrence strictly following scheduled_for."""

    if not isinstance(scheduled_for, datetime):
        raise ScanSchedulerStateError(
            "Persisted next_run_at must be a datetime"
        )

    if (
        scheduled_for.tzinfo is None
        or scheduled_for.utcoffset() is None
    ):
        raise ScanSchedulerStateError(
            "Persisted next_run_at must be timezone-aware"
        )

    return next_cron_occurrence(
        schedule_expression,
        schedule_timezone,
        scheduled_for,
    )


def _advance_policy(
    conn,
    *,
    scan_policy_id: int,
    expected_next_run_at: datetime,
    new_next_run_at: datetime,
) -> None:
    """Advance next_run_at while verifying the locked state is unchanged."""

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_policies
            SET
                next_run_at = %s,
                updated_at = now()
            WHERE scan_policy_id = %s
              AND next_run_at = %s
            """,
            (
                new_next_run_at,
                scan_policy_id,
                expected_next_run_at,
            ),
        )

        if cur.rowcount != 1:
            raise ScanSchedulerStateError(
                f"Scan policy {scan_policy_id} next_run_at changed "
                "unexpectedly while scheduling"
            )


def schedule_next_due_policy(conn) -> dict[str, Any] | None:
    """Materialise one due CRON policy occurrence.

    Returns None when there is currently no schedulable due policy.

    The caller must commit on success or roll back on failure.

    Transactional behaviour:

        1. lock the oldest schedulable due policy;
        2. treat its current next_run_at as the intended scheduled occurrence;
        3. calculate the following cron occurrence;
        4. resolve the scanner-native execution subject;
        5. create exactly one PENDING scan execution;
        6. advance next_run_at.

    Existing-occurrence recovery:

    The database uniqueness constraint on

        (scan_policy_id, scheduled_for)

    is the authoritative idempotency backstop. If the current occurrence
    already has a terminal execution, the scheduler does not recreate it.
    Instead it advances next_run_at to the following cron occurrence.

    An active execution is filtered out before policy locking and therefore
    leaves next_run_at unchanged until that execution becomes terminal.
    """

    policy = _load_next_due_policy(conn)

    if policy is None:
        return None

    scan_policy_id = policy["scan_policy_id"]
    scheduled_for = policy["next_run_at"]

    next_run_at = _calculate_following_occurrence(
        schedule_expression=policy["schedule_expression"],
        schedule_timezone=policy["schedule_timezone"],
        scheduled_for=scheduled_for,
    )

    existing = _load_existing_occurrence(
        conn,
        scan_policy_id=scan_policy_id,
        scheduled_for=scheduled_for,
    )

    if existing is not None:
        if existing["status"] in ACTIVE_EXECUTION_STATUSES:
            # This should normally be impossible because the due-policy query
            # excludes policies with active executions. Keep the invariant
            # explicit in case persisted state changes within future designs.
            raise ScanSchedulerStateError(
                f"Scan policy {scan_policy_id} occurrence "
                f"{scheduled_for.isoformat()} is already active"
            )

        _advance_policy(
            conn,
            scan_policy_id=scan_policy_id,
            expected_next_run_at=scheduled_for,
            new_next_run_at=next_run_at,
        )

        return {
            "action": "ADVANCED_EXISTING",
            "scan_policy_id": scan_policy_id,
            "scan_execution_id": existing["scan_execution_id"],
            "scheduled_for": scheduled_for,
            "next_run_at": next_run_at,
            "execution_status": existing["status"],
        }

    subject = resolve_scanner_subject(
        conn,
        scan_policy_id=scan_policy_id,
    )

    execution = create_scan_execution(
        conn,
        scan_policy_id=scan_policy_id,
        scanner_subject_type=subject["scanner_subject_type"],
        scanner_subject_value=subject["scanner_subject_value"],
        scheduled_for=scheduled_for,
    )

    _advance_policy(
        conn,
        scan_policy_id=scan_policy_id,
        expected_next_run_at=scheduled_for,
        new_next_run_at=next_run_at,
    )

    return {
        "action": "CREATED",
        "scan_policy_id": scan_policy_id,
        "scan_execution_id": execution["scan_execution_id"],
        "scheduled_for": scheduled_for,
        "next_run_at": next_run_at,
        "scanner_type": execution["scanner_type"],
        "scanner_subject_type": execution[
            "scanner_subject_type"
        ],
        "scanner_subject_value": execution[
            "scanner_subject_value"
        ],
        "execution_node_id": execution["execution_node_id"],
        "status": execution["status"],
    }
