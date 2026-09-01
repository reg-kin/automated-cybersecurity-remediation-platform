import psycopg2
from psycopg2 import errors
from psycopg2.extras import Json

from .config import PG


ACTIVE_EXECUTION_CONSTRAINT = (
    "uq_one_active_execution_per_finding"
)


class ActiveRemediationExistsError(Exception):
    """
    Raised when an attempt is made to create a second active
    remediation execution for the same finding.
    """

    def __init__(self, finding_id):
        self.finding_id = finding_id

        super().__init__(
            f"Finding {finding_id} already has "
            "an active remediation execution"
        )


def connect():
    return psycopg2.connect(**PG)


def get_finding(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                finding_id,
                lifecycle_status,
                engine_source,
                finding_class,
                finding_key,
                target_host,
                engine_metadata
            FROM unified_security_findings
            WHERE finding_id = %s
            """,
            (finding_id,),
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                f"Finding {finding_id} does not exist"
            )

        return {
            "finding_id": row[0],
            "lifecycle_status": row[1],
            "engine_source": row[2],
            "finding_class": row[3],
            "finding_key": row[4],
            "target_host": row[5],
            "engine_metadata": row[6] or {},
        }

def get_remediation_rule(conn, rule_id):
    """
    Retrieve the authoritative remediation rule used for
    controller-side execution preflight.

    The caller-supplied remediation fields are not authoritative.
    They must agree with this persisted rule before a finding can
    be claimed or an execution can be created.
    """

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                rule_id,
                rule_name,
                finding_class,
                capability,
                playbook_name,
                remediation_action,
                required_parameters,
                automation_tier,
                approval_required,
                enabled
            FROM remediation_rules
            WHERE rule_id = %s
            """,
            (rule_id,),
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                f"Remediation rule {rule_id} does not exist"
            )

        required_parameters = row[6] or []

        if not isinstance(required_parameters, list):
            raise ValueError(
                f"Remediation rule {rule_id} has invalid "
                "required_parameters; expected a JSON array"
            )

        return {
            "rule_id": row[0],
            "rule_name": row[1],
            "finding_class": row[2],
            "capability": row[3],
            "playbook_name": row[4],
            "remediation_action": row[5],
            "required_parameters": required_parameters,
            "automation_tier": row[7],
            "approval_required": row[8],
            "enabled": row[9],
        }

def ensure_claimed(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT lifecycle_status
            FROM unified_security_findings
            WHERE finding_id = %s
            FOR UPDATE
            """,
            (finding_id,),
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                f"Finding {finding_id} does not exist"
            )

        if row[0] == "OPEN":
            cur.execute(
                "SELECT claim_finding(%s::bigint)",
                (finding_id,),
            )

            ok = cur.fetchone()[0]

            if not ok:
                raise RuntimeError(
                    f"Finding {finding_id} "
                    "could not be claimed"
                )

        elif row[0] != "IN_REMEDIATION":
            raise RuntimeError(
                f"Finding {finding_id} "
                "is not remediable from state "
                f"{row[0]}"
            )


def create_execution(conn, p):
    """
    Create a remediation execution.

    Normal immediate remediations begin as QUEUED.

    Approval-gated remediations may begin as
    AWAITING_APPROVAL.

    RUNNING is deliberately not accepted as an initial state;
    moving into RUNNING is a separate state transition and is
    what causes the remediation-attempt trigger to count the
    attempt.
    """

    initial_status = p.get(
        "initial_status",
        "QUEUED",
    )

    if initial_status not in {
        "QUEUED",
        "AWAITING_APPROVAL",
    }:
        raise ValueError(
            f"Invalid initial execution status: "
            f"{initial_status}"
        )

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO remediation_executions (
                    finding_id,
                    rule_id,
                    capability,
                    target_host,
                    playbook_name,
                    remediation_action,
                    automation_tier,
                    status,
                    execution_parameters,
                    started_at
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
                    NULL
                )
                RETURNING execution_id
                """,
                (
                    p["finding_id"],
                    p.get("rule_id"),
                    p["capability"],
                    p["target_host"],
                    p["playbook_name"],
                    p["remediation_action"],
                    p["automation_tier"],
                    initial_status,
                    Json(
                        p.get(
                            "execution_parameters"
                        ) or {}
                    ),
                ),
            )

            return cur.fetchone()[0]

    except errors.UniqueViolation as exc:
        constraint_name = getattr(
            exc.diag,
            "constraint_name",
            None,
        )

        if (
            constraint_name
            == ACTIVE_EXECUTION_CONSTRAINT
        ):
            raise ActiveRemediationExistsError(
                p["finding_id"]
            ) from exc

        # Some other UNIQUE constraint failed.
        # Do not misrepresent it as an
        # active-remediation conflict.
        raise


def get_execution(conn, execution_id):
    """
    Retrieve an execution without taking a row lock.

    Used by the API to determine which persisted capability
    owns an approval request. The controller performs the
    authoritative locked read before changing state.
    """

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                execution_id,
                finding_id,
                rule_id,
                capability,
                target_host,
                playbook_name,
                remediation_action,
                automation_tier,
                status,
                attempt_counted,
                execution_parameters,
                started_at,
                completed_at
            FROM remediation_executions
            WHERE execution_id = %s
            """,
            (execution_id,),
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                f"Execution {execution_id} "
                "does not exist"
            )

        return {
            "execution_id": row[0],
            "finding_id": row[1],
            "rule_id": row[2],
            "capability": row[3],
            "target_host": row[4],
            "playbook_name": row[5],
            "remediation_action": row[6],
            "automation_tier": row[7],
            "status": row[8],
            "attempt_counted": row[9],
            "execution_parameters": (
                row[10] or {}
            ),
            "started_at": row[11],
            "completed_at": row[12],
        }


def get_execution_for_approval(
    conn,
    execution_id,
):
    """
    Retrieve and lock an execution that is being considered
    for approval.

    FOR UPDATE serialises concurrent approval requests so
    only one request can transition AWAITING_APPROVAL to
    RUNNING.
    """

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                execution_id,
                finding_id,
                rule_id,
                capability,
                target_host,
                playbook_name,
                remediation_action,
                automation_tier,
                status,
                attempt_counted,
                execution_parameters
            FROM remediation_executions
            WHERE execution_id = %s
            FOR UPDATE
            """,
            (execution_id,),
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                f"Execution {execution_id} "
                "does not exist"
            )

        return {
            "execution_id": row[0],
            "finding_id": row[1],
            "rule_id": row[2],
            "capability": row[3],
            "target_host": row[4],
            "playbook_name": row[5],
            "remediation_action": row[6],
            "automation_tier": row[7],
            "status": row[8],
            "attempt_counted": row[9],
            "execution_parameters": (
                row[10] or {}
            ),
        }


def update_execution_status(
    conn,
    execution_id,
    status,
    **fields,
):
    allowed = {
        "ansible_job_id",
        "result",
        "error_message",
        "started_at",
        "completed_at",
    }

    sets = ["status=%s"]
    vals = [status]

    for key, value in fields.items():
        if key not in allowed:
            continue

        sets.append(f"{key}=%s")

        vals.append(
            Json(value)
            if key == "result"
            else value
        )

    vals.append(execution_id)

    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE remediation_executions
            SET {", ".join(sets)}
            WHERE execution_id = %s
            """,
            vals,
        )

        if cur.rowcount != 1:
            raise RuntimeError(
                f"Could not update execution "
                f"{execution_id}"
            )



def cancel_awaiting_approval(
    conn,
    execution_id,
):
    """
    Atomically cancel an approval-gated remediation that
    has not started.

    Allowed transition:

        remediation_executions:
            AWAITING_APPROVAL -> CANCELLED

        unified_security_findings:
            IN_REMEDIATION -> OPEN

    Cancellation is not a remediation attempt and does not
    create verification evidence.
    """

    with conn.cursor() as cur:
        #
        # Lock the execution first. This serialises
        # cancellation against approval.
        #
        cur.execute(
            """
            SELECT
                execution_id,
                finding_id,
                status,
                attempt_counted,
                ansible_job_id,
                started_at,
                completed_at
            FROM remediation_executions
            WHERE execution_id = %s
            FOR UPDATE
            """,
            (execution_id,),
        )

        execution = cur.fetchone()

        if not execution:
            raise ValueError(
                f"Execution {execution_id} "
                "does not exist"
            )

        (
            _execution_id,
            finding_id,
            status,
            attempt_counted,
            ansible_job_id,
            started_at,
            completed_at,
        ) = execution

        if status != "AWAITING_APPROVAL":
            raise RuntimeError(
                f"Execution {execution_id} "
                f"cannot be cancelled from status "
                f"{status}"
            )

        #
        # An execution awaiting approval must genuinely
        # be pre-execution. Refuse cancellation if these
        # invariants have somehow already been violated.
        #
        if attempt_counted:
            raise RuntimeError(
                f"Execution {execution_id} "
                "has already counted a remediation attempt"
            )

        if ansible_job_id is not None:
            raise RuntimeError(
                f"Execution {execution_id} "
                "already has an Ansible job"
            )

        if started_at is not None:
            raise RuntimeError(
                f"Execution {execution_id} "
                "has already started"
            )

        if completed_at is not None:
            raise RuntimeError(
                f"Execution {execution_id} "
                "is already completed"
            )

        #
        # Lock the corresponding finding in the same
        # transaction.
        #
        cur.execute(
            """
            SELECT
                finding_id,
                lifecycle_status
            FROM unified_security_findings
            WHERE finding_id = %s
            FOR UPDATE
            """,
            (finding_id,),
        )

        finding = cur.fetchone()

        if not finding:
            raise RuntimeError(
                f"Finding {finding_id} "
                "does not exist"
            )

        lifecycle_status = finding[1]

        if lifecycle_status != "IN_REMEDIATION":
            raise RuntimeError(
                f"Finding {finding_id} "
                f"cannot be reopened by cancellation "
                f"from lifecycle status "
                f"{lifecycle_status}"
            )

        #
        # Cancellation is a terminal execution state,
        # but it is not an execution failure.
        #
        cur.execute(
            """
            UPDATE remediation_executions
            SET
                status = 'CANCELLED',
                completed_at = NOW()
            WHERE execution_id = %s
              AND status = 'AWAITING_APPROVAL'
            """,
            (execution_id,),
        )

        if cur.rowcount != 1:
            raise RuntimeError(
                f"Could not cancel execution "
                f"{execution_id}"
            )

        #
        # Return the finding to the remediation queue.
        # Do not alter remediation_attempts,
        # recurrence_count, last_error, remediated_at,
        # or verification timestamps.
        #
        cur.execute(
            """
            UPDATE unified_security_findings
            SET lifecycle_status = 'OPEN'
            WHERE finding_id = %s
              AND lifecycle_status = 'IN_REMEDIATION'
            """,
            (finding_id,),
        )

        if cur.rowcount != 1:
            raise RuntimeError(
                f"Could not reopen finding "
                f"{finding_id}"
            )

        return {
            "success": True,
            "execution_id": execution_id,
            "finding_id": finding_id,
            "status": "CANCELLED",
            "finding_status": "OPEN",
        }


def begin_verification(
    conn,
    finding_id,
    execution_id,
    stage,
    vtype,
    source,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT begin_remediation_verification(
                %s::bigint,
                %s::bigint,
                %s::smallint,
                %s::text,
                %s::text
            )
            """,
            (
                finding_id,
                execution_id,
                stage,
                vtype,
                source,
            ),
        )

        return int(cur.fetchone()[0])


def complete_verification(
    conn,
    verification_id,
    status,
    result,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT complete_remediation_verification(
                %s::bigint,
                %s::text,
                %s::jsonb
            )
            """,
            (
                verification_id,
                status,
                Json(result or {}),
            ),
        )

        if cur.fetchone()[0] is not True:
            raise RuntimeError(
                f"Could not complete verification "
                f"{verification_id}"
            )


def resolve_finding(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT resolve_finding(
                %s::bigint
            )
            """,
            (finding_id,),
        )

        if cur.fetchone()[0] is not True:
            raise RuntimeError(
                f"Could not resolve finding "
                f"{finding_id}"
            )


def reopen_failed(
    conn,
    finding_id,
    error,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT reopen_failed_remediation(
                %s::bigint,
                %s::text
            )
            """,
            (
                finding_id,
                error,
            ),
        )

        return bool(cur.fetchone()[0])

# ===========================================================================
# Deferred Stage 2 Verification
# ===========================================================================


def record_scanner_refresh_watermark(
    conn,
    *,
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    refresh_id,
    refresh_completed_at,
    refresh_started_at=None,
    refresh_status="SUCCESS",
    metadata=None,
):
    """
    Persist an authoritative scanner refresh boundary.

    A SUCCESS watermark means the scanner integration has completed processing
    an authoritative state refresh for the specified scanner subject.

    IMPORTANT:
    The caller must not write a SUCCESS watermark until the scanner-derived
    finding/state updates associated with that refresh have been committed or
    are part of the same transaction.
    """

    if not engine_source:
        raise ValueError("engine_source is required")

    if not scanner_subject_type:
        raise ValueError("scanner_subject_type is required")

    if not scanner_subject_id:
        raise ValueError("scanner_subject_id is required")

    if not refresh_id:
        raise ValueError("refresh_id is required")

    if refresh_completed_at is None:
        raise ValueError("refresh_completed_at is required")

    if refresh_status not in ("SUCCESS", "FAILED"):
        raise ValueError(
            "refresh_status must be SUCCESS or FAILED"
        )

    if metadata is None:
        metadata = {}

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scanner_refresh_watermarks (
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id,
                refresh_started_at,
                refresh_completed_at,
                refresh_status,
                metadata
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s::jsonb
            )
            ON CONFLICT (
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id
            )
            DO UPDATE SET
                refresh_started_at =
                    EXCLUDED.refresh_started_at,
                refresh_completed_at =
                    EXCLUDED.refresh_completed_at,
                refresh_status =
                    EXCLUDED.refresh_status,
                metadata =
                    EXCLUDED.metadata
            RETURNING
                watermark_id,
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id,
                refresh_started_at,
                refresh_completed_at,
                refresh_status,
                metadata,
                created_at
            """,
            (
                engine_source,
                scanner_subject_type,
                str(scanner_subject_id),
                refresh_id,
                refresh_started_at,
                refresh_completed_at,
                refresh_status,
                Json(metadata),
            ),
        )

        return cur.fetchone()


def create_deferred_verification_job(
    conn,
    *,
    execution_id,
    finding_id,
    verification_id,
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    evidence_after,
    not_before=None,
    next_check_at=None,
):
    """
    Create the asynchronous Stage 2 work item for an execution.

    There may be only one deferred job per execution_id.

    This function is intentionally idempotent: if a deferred job already
    exists for the execution, the existing row is returned instead of
    creating a duplicate.
    """

    if execution_id is None:
        raise ValueError("execution_id is required")

    if finding_id is None:
        raise ValueError("finding_id is required")

    if verification_id is None:
        raise ValueError("verification_id is required")

    if not engine_source:
        raise ValueError("engine_source is required")

    if not scanner_subject_type:
        raise ValueError("scanner_subject_type is required")

    if not scanner_subject_id:
        raise ValueError("scanner_subject_id is required")

    if evidence_after is None:
        raise ValueError("evidence_after is required")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO deferred_verification_jobs (
                execution_id,
                finding_id,
                verification_id,
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                evidence_after,
                not_before,
                next_check_at
            )
            VALUES (
                %s::bigint,
                %s::bigint,
                %s::bigint,
                %s,
                %s,
                %s,
                %s,
                COALESCE(%s, NOW()),
                COALESCE(%s, NOW())
            )
            ON CONFLICT (execution_id)
            DO NOTHING
            RETURNING
                deferred_job_id,
                execution_id,
                finding_id,
                verification_id,
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                evidence_after,
                status,
                not_before,
                next_check_at,
                check_count,
                lease_owner,
                lease_until,
                last_watermark_id,
                last_error,
                completed_at,
                created_at,
                updated_at
            """,
            (
                execution_id,
                finding_id,
                verification_id,
                engine_source,
                scanner_subject_type,
                str(scanner_subject_id),
                evidence_after,
                not_before,
                next_check_at,
            ),
        )

        row = cur.fetchone()

        if row is not None:
            return row

        # Idempotent replay: return the previously-created job.
        cur.execute(
            """
            SELECT
                deferred_job_id,
                execution_id,
                finding_id,
                verification_id,
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                evidence_after,
                status,
                not_before,
                next_check_at,
                check_count,
                lease_owner,
                lease_until,
                last_watermark_id,
                last_error,
                completed_at,
                created_at,
                updated_at
            FROM deferred_verification_jobs
            WHERE execution_id = %s::bigint
            """,
            (execution_id,),
        )

        return cur.fetchone()


def lease_deferred_verification_jobs(
    conn,
    *,
    lease_owner,
    limit=100,
    lease_seconds=300,
):
    """
    Atomically claim ready deferred-verification jobs.

    FOR UPDATE SKIP LOCKED allows multiple reconciler processes to operate
    without processing the same job concurrently.

    Expired LEASED jobs are reclaimable, making worker crashes recoverable.
    """

    if not lease_owner:
        raise ValueError("lease_owner is required")

    limit = int(limit)
    lease_seconds = int(lease_seconds)

    if limit < 1:
        raise ValueError("limit must be >= 1")

    if lease_seconds < 1:
        raise ValueError("lease_seconds must be >= 1")

    with conn.cursor() as cur:
        cur.execute(
            """
            WITH candidates AS (
                SELECT deferred_job_id
                FROM deferred_verification_jobs
                WHERE
                    (
                        status = 'PENDING'
                        OR (
                            status = 'LEASED'
                            AND lease_until < NOW()
                        )
                    )
                    AND not_before <= NOW()
                    AND next_check_at <= NOW()
                ORDER BY
                    next_check_at,
                    deferred_job_id
                FOR UPDATE SKIP LOCKED
                LIMIT %s
            )
            UPDATE deferred_verification_jobs AS j
            SET
                status = 'LEASED',
                lease_owner = %s,
                lease_until =
                    NOW()
                    + (%s * INTERVAL '1 second'),
                check_count = j.check_count + 1,
                updated_at = NOW()
            FROM candidates AS c
            WHERE
                j.deferred_job_id =
                    c.deferred_job_id
            RETURNING
                j.deferred_job_id,
                j.execution_id,
                j.finding_id,
                j.verification_id,
                j.engine_source,
                j.scanner_subject_type,
                j.scanner_subject_id,
                j.evidence_after,
                j.status,
                j.not_before,
                j.next_check_at,
                j.check_count,
                j.lease_owner,
                j.lease_until,
                j.last_watermark_id,
                j.last_error,
                j.completed_at,
                j.created_at,
                j.updated_at
            """,
            (
                limit,
                lease_owner,
                lease_seconds,
            ),
        )

        return cur.fetchall()


def get_latest_successful_refresh(
    conn,
    *,
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    evidence_after=None,
):
    """
    Return the newest successful authoritative scanner refresh.

    When evidence_after is provided, only a refresh completed strictly after
    the remediation evidence boundary is eligible.
    """

    if not engine_source:
        raise ValueError("engine_source is required")

    if not scanner_subject_type:
        raise ValueError("scanner_subject_type is required")

    if not scanner_subject_id:
        raise ValueError("scanner_subject_id is required")

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                watermark_id,
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id,
                refresh_started_at,
                refresh_completed_at,
                refresh_status,
                metadata,
                created_at
            FROM scanner_refresh_watermarks
            WHERE
                engine_source = %s
                AND scanner_subject_type = %s
                AND scanner_subject_id = %s
                AND refresh_status = 'SUCCESS'
                AND (
                    %s IS NULL
                    OR refresh_completed_at > %s
                )
            ORDER BY
                refresh_completed_at DESC,
                watermark_id DESC
            LIMIT 1
            """,
            (
                engine_source,
                scanner_subject_type,
                str(scanner_subject_id),
                evidence_after,
                evidence_after,
            ),
        )

        return cur.fetchone()


def reschedule_deferred_verification_job(
    conn,
    *,
    deferred_job_id,
    lease_owner,
    next_check_at,
    last_watermark_id=None,
    last_error=None,
):
    """
    Release a leased job back to PENDING.

    Used when no fresh authoritative scanner evidence is available yet.

    This is not a remediation failure.
    """

    if deferred_job_id is None:
        raise ValueError("deferred_job_id is required")

    if not lease_owner:
        raise ValueError("lease_owner is required")

    if next_check_at is None:
        raise ValueError("next_check_at is required")

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE deferred_verification_jobs
            SET
                status = 'PENDING',
                next_check_at = %s,
                lease_owner = NULL,
                lease_until = NULL,
                last_watermark_id =
                    COALESCE(
                        %s::bigint,
                        last_watermark_id
                    ),
                last_error = %s,
                updated_at = NOW()
            WHERE
                deferred_job_id = %s::bigint
                AND status = 'LEASED'
                AND lease_owner = %s
            RETURNING
                deferred_job_id,
                execution_id,
                finding_id,
                verification_id,
                status,
                next_check_at,
                check_count,
                last_watermark_id,
                last_error,
                updated_at
            """,
            (
                next_check_at,
                last_watermark_id,
                last_error,
                deferred_job_id,
                lease_owner,
            ),
        )

        row = cur.fetchone()

        if row is None:
            raise RuntimeError(
                "Deferred verification job is no longer "
                "leased by this worker"
            )

        return row


def complete_deferred_verification_job(
    conn,
    *,
    deferred_job_id,
    lease_owner,
    last_watermark_id,
):
    """
    Mark deferred orchestration work complete.

    IMPORTANT:
    This function does NOT complete remediation_verifications and does NOT
    change the execution/finding lifecycle.

    The reconciler must first persist the authoritative Stage 2 security
    result and final execution/finding transition within the same database
    transaction, then mark this job COMPLETED.
    """

    if deferred_job_id is None:
        raise ValueError("deferred_job_id is required")

    if not lease_owner:
        raise ValueError("lease_owner is required")

    if last_watermark_id is None:
        raise ValueError("last_watermark_id is required")

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE deferred_verification_jobs
            SET
                status = 'COMPLETED',
                last_watermark_id = %s::bigint,
                lease_owner = NULL,
                lease_until = NULL,
                last_error = NULL,
                completed_at = NOW(),
                updated_at = NOW()
            WHERE
                deferred_job_id = %s::bigint
                AND status = 'LEASED'
                AND lease_owner = %s
            RETURNING
                deferred_job_id,
                execution_id,
                finding_id,
                verification_id,
                status,
                check_count,
                last_watermark_id,
                completed_at,
                updated_at
            """,
            (
                last_watermark_id,
                deferred_job_id,
                lease_owner,
            ),
        )

        row = cur.fetchone()

        if row is None:
            raise RuntimeError(
                "Deferred verification job is no longer "
                "leased by this worker"
            )

        return row
