#!/usr/bin/env python3
"""Automated remediation deferred Stage 2 verification reconciler.

Consumes deferred_verification_jobs created by remediation controllers after
Stage 1 passes for asynchronous scanners (currently Wazuh Vulnerability
Detection and Wazuh SCA).

Safety properties:
- Only SUCCESS scanner-refresh watermarks completed after evidence_after qualify.
- Jobs are leased with SKIP LOCKED for multi-worker safety.
- Lease ownership is revalidated before terminal transitions.
- No fresh authoritative evidence reschedules the job; it never fails remediation.
- Presence in a fresh refresh fails Stage 2 and reopens the finding.
- Absence resolves only when the refresh scope is authoritative.
- Filtered Wazuh vulnerability refreshes may prove presence, but never absence.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from psycopg2.extras import Json, RealDictCursor

from remediation.shared import db

LOG = logging.getLogger("regis.deferred_reconciler")

SUPPORTED_ENGINES = {"wazuh_vulnerability", "wazuh_sca"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def make_worker_id() -> str:
    configured = os.getenv("DEFERRED_WORKER_ID", "").strip()
    if configured:
        return configured
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def setup_logging() -> None:
    level = os.getenv("DEFERRED_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def normalise_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, tuple):
        return [str(x) for x in value]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        try:
            decoded = json.loads(s)
            if isinstance(decoded, list):
                return [str(x) for x in decoded]
        except Exception:
            pass
        return [x.strip() for x in s.split(",") if x.strip()]
    return [str(value)]


def lease_jobs(conn, worker_id: str, batch_size: int, lease_seconds: int) -> List[Dict[str, Any]]:
    """Lease due jobs, recovering expired leases as well."""
    sql = """
    WITH candidates AS (
        SELECT deferred_job_id
        FROM deferred_verification_jobs
        WHERE (
                status = 'PENDING'
                AND COALESCE(not_before, created_at) <= now()
                AND COALESCE(next_check_at, now()) <= now()
              )
           OR (
                status = 'LEASED'
                AND lease_until IS NOT NULL
                AND lease_until < now()
              )
        ORDER BY COALESCE(next_check_at, created_at), deferred_job_id
        FOR UPDATE SKIP LOCKED
        LIMIT %s
    )
    UPDATE deferred_verification_jobs j
       SET status = 'LEASED',
           lease_owner = %s,
           lease_until = now() + (%s * interval '1 second'),
           updated_at = now()
      FROM candidates c
     WHERE j.deferred_job_id = c.deferred_job_id
    RETURNING j.*
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (batch_size, worker_id, lease_seconds))
        return [dict(r) for r in cur.fetchall()]


def load_job_context(conn, job_id: int, worker_id: str) -> Optional[Dict[str, Any]]:
    """Load a leased job plus immutable execution/finding context."""
    sql = """
    SELECT
        j.*,
        e.status AS execution_status,
        e.result AS execution_result,
        f.lifecycle_status AS finding_lifecycle_status,
        f.tenant_code,
        f.engine_source AS finding_engine_source,
        f.finding_class,
        f.finding_key,
        f.target_host,
        f.last_seen_at,
        f.engine_metadata,
        v.status AS verification_status,
        v.stage AS verification_stage
    FROM deferred_verification_jobs j
    JOIN remediation_executions e ON e.execution_id = j.execution_id
    JOIN unified_security_findings f ON f.finding_id = j.finding_id
    JOIN remediation_verifications v ON v.verification_id = j.verification_id
    WHERE j.deferred_job_id = %s
      AND j.status = 'LEASED'
      AND j.lease_owner = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (job_id, worker_id))
        row = cur.fetchone()
        return dict(row) if row else None


def latest_success_watermark(conn, ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the newest fresh, successful, tenant-compatible watermark not yet consumed."""
    sql = """
    SELECT *
    FROM scanner_refresh_watermarks
    WHERE engine_source = %s
      AND scanner_subject_type = %s
      AND scanner_subject_id = %s
      AND refresh_status = 'SUCCESS'
      AND refresh_completed_at > %s
      AND watermark_id > COALESCE(%s, 0)
      AND metadata->>'tenant_code' = %s
    ORDER BY refresh_completed_at DESC, watermark_id DESC
    LIMIT 1
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            sql,
            (
                ctx["engine_source"],
                ctx["scanner_subject_type"],
                ctx["scanner_subject_id"],
                ctx["evidence_after"],
                ctx.get("last_watermark_id"),
                ctx["tenant_code"],
            ),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def validate_context(ctx: Dict[str, Any]) -> Optional[str]:
    if ctx["engine_source"] not in SUPPORTED_ENGINES:
        return f"Unsupported deferred verification engine: {ctx['engine_source']}"
    if ctx["finding_engine_source"] != ctx["engine_source"]:
        return (
            "Deferred job engine does not match finding engine: "
            f"job={ctx['engine_source']} finding={ctx['finding_engine_source']}"
        )
    if ctx["verification_stage"] != 2:
        return f"Deferred verification row is not Stage 2: {ctx['verification_stage']}"
    if ctx["verification_status"] != "PENDING":
        return f"Deferred Stage 2 verification is not PENDING: {ctx['verification_status']}"
    if ctx["execution_status"] != "VERIFYING":
        return f"Deferred execution is not VERIFYING: {ctx['execution_status']}"
    if ctx["finding_lifecycle_status"] != "IN_REMEDIATION":
        return f"Deferred finding is not IN_REMEDIATION: {ctx['finding_lifecycle_status']}"
    return None


def evaluate_presence(ctx: Dict[str, Any], watermark: Dict[str, Any]) -> Tuple[bool, bool, str, Dict[str, Any]]:
    """Return (present, absence_authoritative, reason, evidence)."""
    finding_meta = ctx.get("engine_metadata") or {}
    watermark_meta = watermark.get("metadata") or {}

    current_refresh_id = str(finding_meta.get("refresh_id") or "")
    watermark_refresh_id = str(watermark.get("refresh_id") or "")
    current_agent = str(finding_meta.get("agent_id") or "")
    subject_id = str(ctx.get("scanner_subject_id") or "")

    exact_refresh_present = (
        current_refresh_id == watermark_refresh_id
        and current_agent == subject_id
    )

    # If the same finding was observed after the selected successful refresh,
    # it is unsafe to resolve it merely because its current refresh_id no
    # longer equals that watermark. Treat later observation as PRESENT.
    seen_after_watermark = False
    last_seen_at = ctx.get("last_seen_at")
    refresh_completed_at = watermark.get("refresh_completed_at")
    if (
        current_agent == subject_id
        and last_seen_at is not None
        and refresh_completed_at is not None
        and last_seen_at > refresh_completed_at
    ):
        seen_after_watermark = True

    present = exact_refresh_present or seen_after_watermark

    absence_authoritative = True
    scope_reason = "complete successful refresh"

    if ctx["engine_source"] == "wazuh_vulnerability":
        severity_filter = normalise_list(watermark_meta.get("severity_filter"))
        if severity_filter:
            absence_authoritative = False
            scope_reason = "filtered vulnerability refresh cannot prove absence"

    evidence = {
        "verification_strategy": "DEFERRED",
        "verification_source": ctx["engine_source"],
        "scanner_subject_type": ctx["scanner_subject_type"],
        "scanner_subject_id": ctx["scanner_subject_id"],
        "watermark_id": watermark["watermark_id"],
        "refresh_id": watermark["refresh_id"],
        "refresh_started_at": watermark.get("refresh_started_at").isoformat() if watermark.get("refresh_started_at") else None,
        "refresh_completed_at": watermark.get("refresh_completed_at").isoformat() if watermark.get("refresh_completed_at") else None,
        "evidence_after": ctx.get("evidence_after").isoformat() if ctx.get("evidence_after") else None,
        "finding_id": ctx["finding_id"],
        "finding_key": ctx["finding_key"],
        "finding_class": ctx["finding_class"],
        "present": present,
        "exact_refresh_present": exact_refresh_present,
        "seen_after_watermark": seen_after_watermark,
        "finding_last_seen_at": last_seen_at.isoformat() if last_seen_at else None,
        "absence_authoritative": absence_authoritative,
        "scope_reason": scope_reason,
        "watermark_metadata": watermark_meta,
        "evaluated_at": utcnow().isoformat(),
    }
    return present, absence_authoritative, scope_reason, evidence


def reschedule_job(
    conn,
    job_id: int,
    worker_id: str,
    retry_seconds: int,
    reason: str,
    last_watermark_id: Optional[int] = None,
) -> bool:
    sql = """
    UPDATE deferred_verification_jobs
       SET status = 'PENDING',
           next_check_at = now() + (%s * interval '1 second'),
           check_count = COALESCE(check_count, 0) + 1,
           lease_owner = NULL,
           lease_until = NULL,
           last_watermark_id = COALESCE(%s, last_watermark_id),
           last_error = %s,
           updated_at = now()
     WHERE deferred_job_id = %s
       AND status = 'LEASED'
       AND lease_owner = %s
       AND lease_until > now()
    """
    with conn.cursor() as cur:
        cur.execute(sql, (retry_seconds, last_watermark_id, reason, job_id, worker_id))
        return cur.rowcount == 1


def finish_job(conn, ctx: Dict[str, Any], worker_id: str, passed: bool, evidence: Dict[str, Any]) -> bool:
    """Complete Stage 2, execution, finding and job in one transaction."""
    job_id = ctx["deferred_job_id"]
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Revalidate lease under row lock immediately before terminal writes.
        cur.execute(
            """
            SELECT deferred_job_id, status, lease_owner, lease_until
            FROM deferred_verification_jobs
            WHERE deferred_job_id = %s
            FOR UPDATE
            """,
            (job_id,),
        )
        lease = cur.fetchone()
        if not lease:
            return False
        if lease["status"] != "LEASED" or lease["lease_owner"] != worker_id:
            return False
        if lease["lease_until"] is None or lease["lease_until"] <= utcnow():
            return False

        verification_status = "PASSED" if passed else "FAILED"
        cur.execute(
            "SELECT complete_remediation_verification(%s::bigint,%s::text,%s::jsonb) AS ok",
            (ctx["verification_id"], verification_status, Json(evidence)),
        )
        row = cur.fetchone()
        if not row or row["ok"] is not True:
            raise RuntimeError(f"Could not complete verification {ctx['verification_id']}")

        merged_result = {
            "deferred_stage2": evidence,
        }

        if passed:
            cur.execute(
                """
                UPDATE remediation_executions
                   SET status = 'SUCCESS',
                       result = COALESCE(result, '{}'::jsonb) || %s::jsonb,
                       error_message = NULL,
                       completed_at = now()
                 WHERE execution_id = %s
                   AND status = 'VERIFYING'
                """,
                (Json(merged_result), ctx["execution_id"]),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"Execution {ctx['execution_id']} is no longer VERIFYING")
            cur.execute("SELECT resolve_finding(%s::bigint) AS ok", (ctx["finding_id"],))
            row = cur.fetchone()
            if not row or row["ok"] is not True:
                raise RuntimeError(f"Could not resolve finding {ctx['finding_id']}")
            last_error = None
        else:
            error = "Deferred Stage 2 scanner verification found the original finding still present"
            cur.execute(
                """
                UPDATE remediation_executions
                   SET status = 'FAILED',
                       result = COALESCE(result, '{}'::jsonb) || %s::jsonb,
                       error_message = %s,
                       completed_at = now()
                 WHERE execution_id = %s
                   AND status = 'VERIFYING'
                """,
                (Json(merged_result), error, ctx["execution_id"]),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"Execution {ctx['execution_id']} is no longer VERIFYING")
            cur.execute(
                "SELECT reopen_failed_remediation(%s::bigint,%s::text) AS ok",
                (ctx["finding_id"], error),
            )
            row = cur.fetchone()
            if not row or row["ok"] is not True:
                raise RuntimeError(f"Could not reopen finding {ctx['finding_id']}")
            last_error = error

        cur.execute(
            """
            UPDATE deferred_verification_jobs
               SET status = 'COMPLETED',
                   completed_at = now(),
                   last_watermark_id = %s,
                   last_error = %s,
                   lease_owner = NULL,
                   lease_until = NULL,
                   updated_at = now()
             WHERE deferred_job_id = %s
               AND status = 'LEASED'
               AND lease_owner = %s
            """,
            (evidence["watermark_id"], last_error, job_id, worker_id),
        )
        if cur.rowcount != 1:
            raise RuntimeError(f"Deferred job {job_id} lease was lost before completion")
        return True


def process_job(conn, leased_job: Dict[str, Any], worker_id: str, retry_seconds: int) -> str:
    job_id = leased_job["deferred_job_id"]
    ctx = load_job_context(conn, job_id, worker_id)
    if not ctx:
        LOG.warning("job=%s lease no longer owned", job_id)
        return "lease_lost"

    invalid = validate_context(ctx)
    if invalid:
        with conn:
            ok = reschedule_job(conn, job_id, worker_id, retry_seconds, invalid)
        LOG.error("job=%s invalid context; rescheduled: %s", job_id, invalid)
        return "rescheduled_invalid_context" if ok else "lease_lost"

    watermark = latest_success_watermark(conn, ctx)
    if not watermark:
        reason = "No fresh SUCCESS scanner refresh after evidence_after"
        with conn:
            ok = reschedule_job(conn, job_id, worker_id, retry_seconds, reason)
        LOG.info("job=%s no fresh watermark; rescheduled", job_id)
        return "rescheduled_no_evidence" if ok else "lease_lost"

    present, absence_authoritative, scope_reason, evidence = evaluate_presence(ctx, watermark)

    if not present and not absence_authoritative:
        reason = f"Fresh watermark {watermark['watermark_id']} not authoritative for absence: {scope_reason}"
        with conn:
            ok = reschedule_job(
                conn,
                job_id,
                worker_id,
                retry_seconds,
                reason,
                last_watermark_id=watermark["watermark_id"],
            )
        LOG.warning("job=%s watermark=%s cannot prove absence; rescheduled", job_id, watermark["watermark_id"])
        return "rescheduled_scope" if ok else "lease_lost"

    passed = not present
    with conn:
        ok = finish_job(conn, ctx, worker_id, passed, evidence)
    if not ok:
        LOG.warning("job=%s lease lost before terminal transition", job_id)
        return "lease_lost"

    if passed:
        LOG.info(
            "job=%s execution=%s finding=%s PASSED using watermark=%s refresh=%s",
            job_id,
            ctx["execution_id"],
            ctx["finding_id"],
            watermark["watermark_id"],
            watermark["refresh_id"],
        )
        return "passed"

    LOG.info(
        "job=%s execution=%s finding=%s FAILED: finding still present in watermark=%s refresh=%s",
        job_id,
        ctx["execution_id"],
        ctx["finding_id"],
        watermark["watermark_id"],
        watermark["refresh_id"],
    )
    return "failed_present"


def run_once(worker_id: str, batch_size: int, lease_seconds: int, retry_seconds: int) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    conn = db.connect()
    try:
        with conn:
            jobs = lease_jobs(conn, worker_id, batch_size, lease_seconds)
        LOG.info("worker=%s leased_jobs=%d", worker_id, len(jobs))
        for job in jobs:
            try:
                result = process_job(conn, job, worker_id, retry_seconds)
            except Exception:
                conn.rollback()
                LOG.exception("job=%s unhandled reconciliation error", job.get("deferred_job_id"))
                # Best effort release/reschedule while lease is still ours.
                try:
                    with conn:
                        reschedule_job(
                            conn,
                            job["deferred_job_id"],
                            worker_id,
                            retry_seconds,
                            "Unhandled reconciler error; inspect reconciler logs",
                        )
                    result = "rescheduled_exception"
                except Exception:
                    conn.rollback()
                    LOG.exception("job=%s could not be rescheduled after exception", job.get("deferred_job_id"))
                    result = "exception"
            counts[result] = counts.get(result, 0) + 1
        return counts
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Regis deferred Stage 2 reconciler")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    args = parser.parse_args()

    setup_logging()
    batch_size = env_int("DEFERRED_BATCH_SIZE", 20)
    lease_seconds = env_int("DEFERRED_LEASE_SECONDS", 120)
    retry_seconds = env_int("DEFERRED_RETRY_SECONDS", 60)
    poll_seconds = env_int("DEFERRED_POLL_SECONDS", 30)
    worker_id = make_worker_id()

    if args.loop and args.once:
        parser.error("Choose only one of --once or --loop")

    if not args.loop:
        summary = run_once(worker_id, batch_size, lease_seconds, retry_seconds)
        print(json.dumps({"worker_id": worker_id, "results": summary}, sort_keys=True))
        return 0

    LOG.info(
        "starting deferred reconciler worker=%s batch=%d lease=%ds retry=%ds poll=%ds",
        worker_id,
        batch_size,
        lease_seconds,
        retry_seconds,
        poll_seconds,
    )
    while True:
        try:
            run_once(worker_id, batch_size, lease_seconds, retry_seconds)
        except Exception:
            LOG.exception("reconciliation cycle failed")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
