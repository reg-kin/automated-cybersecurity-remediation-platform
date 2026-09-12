"""Deterministic scan-coordination domain service.

This module owns coordination state transitions only.

It deliberately does not:
- invoke scanners;
- parse scanner-native evidence;
- determine finding_class;
- construct Unified Security Findings;
- perform risk contextualisation;
- authorise remediation;
- resolve scanner-native subjects from canonical assets.

The caller owns transaction boundaries. Functions in this module do not
commit or roll back the supplied PostgreSQL connection.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Any

from psycopg2 import IntegrityError
from psycopg2.extras import Json


SCANNER_EXECUTION_MODELS = {
    "openvas": "CONTROL_PLANE",
    "nuclei": "REMOTE_TARGET",
    "nmap_nse": "REMOTE_TARGET",
    "lynis": "LOCAL_ASSET",
    "trivy": "RESOURCE_TARGET",
    "wazuh_vulnerability": "CONTROL_PLANE",
    "wazuh_sca": "CONTROL_PLANE",
}

SCANNER_SUBJECT_TYPES = {
    "openvas": {"OPENVAS_TASK"},
    "nuclei": {
        "IP_ADDRESS",
        "HOSTNAME",
        "FQDN",
        "URL",
    },
    "nmap_nse": {
        "IP_ADDRESS",
        "HOSTNAME",
        "FQDN",
    },
    "lynis": {"LOCAL_ASSET"},
    "trivy": {
        "CONTAINER_IMAGE",
        "FILESYSTEM",
    },
    "wazuh_vulnerability": {"WAZUH_AGENT_ID"},
    "wazuh_sca": {"WAZUH_AGENT_ID"},
}

DEFAULT_LEASE_SECONDS = 300
MIN_LEASE_SECONDS = 30
MAX_LEASE_SECONDS = 3600


class ScanCoordinationError(ValueError):
    """Base exception for expected scan-coordination failures."""


class ScanCoordinationValidationError(ScanCoordinationError):
    """Request data is invalid."""


class ScanCoordinationNotFoundError(ScanCoordinationError):
    """The requested scan-coordination object does not exist."""


class ScanCoordinationConflictError(ScanCoordinationError):
    """The requested operation conflicts with current coordination state."""


class ScanLeaseAuthenticationError(ScanCoordinationError):
    """Lease credentials do not authorise the requested transition."""


class ScanLeaseExpiredError(ScanCoordinationConflictError):
    """The execution lease is no longer valid."""


def _require_nonblank(value: Any, field_name: str) -> str:
    if value is None or not str(value).strip():
        raise ScanCoordinationValidationError(
            f"{field_name} must be non-blank"
        )

    return str(value).strip()


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ScanCoordinationValidationError(
            f"{field_name} must be a positive integer"
        )

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanCoordinationValidationError(
            f"{field_name} must be a positive integer"
        ) from exc

    if parsed <= 0:
        raise ScanCoordinationValidationError(
            f"{field_name} must be a positive integer"
        )

    return parsed


def _require_metadata_object(value: Any, field_name: str) -> dict:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise ScanCoordinationValidationError(
            f"{field_name} must be a dictionary"
        )

    return value


def _require_scanner_type(scanner_type: Any) -> str:
    scanner_type = _require_nonblank(
        scanner_type,
        "scanner_type",
    )

    if scanner_type not in SCANNER_EXECUTION_MODELS:
        raise ScanCoordinationValidationError(
            f"Unsupported scanner_type: {scanner_type}"
        )

    return scanner_type


def _require_subject_type(
    *,
    scanner_type: str,
    scanner_subject_type: Any,
) -> str:
    scanner_subject_type = _require_nonblank(
        scanner_subject_type,
        "scanner_subject_type",
    )

    allowed = SCANNER_SUBJECT_TYPES[scanner_type]

    if scanner_subject_type not in allowed:
        raise ScanCoordinationValidationError(
            f"{scanner_subject_type} is not a valid scanner subject type "
            f"for {scanner_type}"
        )

    return scanner_subject_type


def _require_lease_seconds(value: Any) -> int:
    if value is None:
        return DEFAULT_LEASE_SECONDS

    seconds = _require_positive_int(
        value,
        "lease_seconds",
    )

    if not MIN_LEASE_SECONDS <= seconds <= MAX_LEASE_SECONDS:
        raise ScanCoordinationValidationError(
            "lease_seconds must be between "
            f"{MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS}"
        )

    return seconds


def _hash_lease_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _generate_lease_token() -> str:
    # 32 random bytes provides 256 bits of entropy.
    return secrets.token_urlsafe(32)


def _get_policy_for_execution(
    conn,
    *,
    scan_policy_id: int,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                p.scan_policy_id,
                p.tenant_code,
                p.asset_id,
                p.scanner_type,
                p.profile_name,
                p.scanner_parameters,
                p.schedule_type,
                p.schedule_expression,
                p.schedule_timezone,
                p.next_run_at,
                p.is_enabled,
                a.lifecycle_status
            FROM scan_policies p
            JOIN assets a
              ON a.asset_id = p.asset_id
             AND a.tenant_code = p.tenant_code
            WHERE p.scan_policy_id = %s
            FOR UPDATE OF p
            """,
            (scan_policy_id,),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanCoordinationNotFoundError(
            f"Scan policy {scan_policy_id} does not exist"
        )

    return {
        "scan_policy_id": row[0],
        "tenant_code": row[1],
        "asset_id": row[2],
        "scanner_type": row[3],
        "profile_name": row[4],
        "scanner_parameters": row[5],
        "schedule_type": row[6],
        "schedule_expression": row[7],
        "schedule_timezone": row[8],
        "next_run_at": row[9],
        "is_enabled": row[10],
        "asset_lifecycle_status": row[11],
    }


def select_execution_node(
    conn,
    *,
    scanner_type: str,
    execution_model: str,
    asset_id: int,
    tenant_code: str,
) -> dict:
    """Select the highest-priority compatible enabled execution node.

    Lower numeric priority values are preferred.

    LOCAL_ASSET execution additionally requires an active tenant-scoped
    node-to-asset binding.
    """

    scanner_type = _require_scanner_type(scanner_type)
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    asset_id = _require_positive_int(
        asset_id,
        "asset_id",
    )

    expected_model = SCANNER_EXECUTION_MODELS[scanner_type]

    if execution_model != expected_model:
        raise ScanCoordinationValidationError(
            f"{scanner_type} requires execution model {expected_model}, "
            f"not {execution_model}"
        )

    if execution_model == "LOCAL_ASSET":
        sql = """
            SELECT
                n.execution_node_id,
                n.node_code,
                n.display_name,
                n.transport_mode,
                c.execution_model,
                c.priority
            FROM scan_execution_nodes n
            JOIN scan_execution_node_capabilities c
              ON c.execution_node_id = n.execution_node_id
            JOIN scan_execution_node_assets b
              ON b.execution_node_id = n.execution_node_id
             AND b.asset_id = %s
             AND b.tenant_code = %s
             AND b.is_active = TRUE
            WHERE n.is_enabled = TRUE
              AND c.is_enabled = TRUE
              AND c.scanner_type = %s
              AND c.execution_model = %s
            ORDER BY
                c.priority ASC,
                n.execution_node_id ASC
            LIMIT 1
            FOR UPDATE OF n
        """
        params = (
            asset_id,
            tenant_code,
            scanner_type,
            execution_model,
        )
    else:
        sql = """
            SELECT
                n.execution_node_id,
                n.node_code,
                n.display_name,
                n.transport_mode,
                c.execution_model,
                c.priority
            FROM scan_execution_nodes n
            JOIN scan_execution_node_capabilities c
              ON c.execution_node_id = n.execution_node_id
            WHERE n.is_enabled = TRUE
              AND c.is_enabled = TRUE
              AND c.scanner_type = %s
              AND c.execution_model = %s
            ORDER BY
                c.priority ASC,
                n.execution_node_id ASC
            LIMIT 1
            FOR UPDATE OF n
        """
        params = (
            scanner_type,
            execution_model,
        )

    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()

    if row is None:
        if execution_model == "LOCAL_ASSET":
            raise ScanCoordinationConflictError(
                f"No enabled {scanner_type} execution node is actively "
                f"bound to tenant {tenant_code} asset {asset_id}"
            )

        raise ScanCoordinationConflictError(
            f"No enabled execution node provides "
            f"{scanner_type}/{execution_model}"
        )

    return {
        "execution_node_id": row[0],
        "node_code": row[1],
        "display_name": row[2],
        "transport_mode": row[3],
        "execution_model": row[4],
        "priority": row[5],
    }


def create_scan_execution(
    conn,
    *,
    scan_policy_id: int,
    scanner_subject_type: str,
    scanner_subject_value: str,
    scheduled_for: datetime,
) -> dict:
    """Create one PENDING scan execution from an existing scan policy.

    The scanner subject must already have been resolved by scanner-specific
    coordination/adapter logic. This service validates that the subject type
    is compatible with the scanner but does not derive the subject itself.
    """

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )

    if not isinstance(scheduled_for, datetime):
        raise ScanCoordinationValidationError(
            "scheduled_for must be a datetime"
        )

    scanner_subject_value = _require_nonblank(
        scanner_subject_value,
        "scanner_subject_value",
    )

    policy = _get_policy_for_execution(
        conn,
        scan_policy_id=scan_policy_id,
    )

    if not policy["is_enabled"]:
        raise ScanCoordinationConflictError(
            f"Scan policy {scan_policy_id} is disabled"
        )

    if policy["asset_lifecycle_status"] != "ACTIVE":
        raise ScanCoordinationConflictError(
            f"Asset {policy['asset_id']} is not ACTIVE"
        )

    scanner_type = _require_scanner_type(
        policy["scanner_type"]
    )

    scanner_subject_type = _require_subject_type(
        scanner_type=scanner_type,
        scanner_subject_type=scanner_subject_type,
    )

    execution_model = SCANNER_EXECUTION_MODELS[
        scanner_type
    ]

    node = select_execution_node(
        conn,
        scanner_type=scanner_type,
        execution_model=execution_model,
        asset_id=policy["asset_id"],
        tenant_code=policy["tenant_code"],
    )

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_executions (
                    scan_policy_id,
                    tenant_code,
                    asset_id,
                    scanner_type,
                    execution_node_id,
                    execution_model,
                    scanner_subject_type,
                    scanner_subject_value,
                    scanner_parameters,
                    status,
                    scheduled_for
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
                    'PENDING',
                    %s
                )
                RETURNING
                    scan_execution_id,
                    created_at
                """,
                (
                    policy["scan_policy_id"],
                    policy["tenant_code"],
                    policy["asset_id"],
                    scanner_type,
                    node["execution_node_id"],
                    execution_model,
                    scanner_subject_type,
                    scanner_subject_value,
                    Json(policy["scanner_parameters"]),
                    scheduled_for,
                ),
            )

            row = cur.fetchone()

    except IntegrityError as exc:
        # The database remains authoritative for the partial unique
        # active-execution invariant.
        if getattr(exc, "diag", None) is not None:
            if (
                exc.diag.constraint_name
                == "uq_scan_policy_active_execution"
            ):
                raise ScanCoordinationConflictError(
                    f"Scan policy {scan_policy_id} already has an "
                    "active execution"
                ) from exc

        raise

    return {
        "scan_execution_id": row[0],
        "scan_policy_id": policy["scan_policy_id"],
        "tenant_code": policy["tenant_code"],
        "asset_id": policy["asset_id"],
        "scanner_type": scanner_type,
        "execution_node_id": node["execution_node_id"],
        "node_code": node["node_code"],
        "execution_model": execution_model,
        "scanner_subject_type": scanner_subject_type,
        "scanner_subject_value": scanner_subject_value,
        "scanner_parameters": policy["scanner_parameters"],
        "status": "PENDING",
        "scheduled_for": scheduled_for,
        "created_at": row[1],
    }


def _get_node_for_update(
    conn,
    *,
    node_code: str,
) -> dict:
    node_code = _require_nonblank(
        node_code,
        "node_code",
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
            WHERE node_code = %s
            FOR UPDATE
            """,
            (node_code,),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanCoordinationNotFoundError(
            f"Execution node {node_code} does not exist"
        )

    return {
        "execution_node_id": row[0],
        "node_code": row[1],
        "display_name": row[2],
        "transport_mode": row[3],
        "is_enabled": row[4],
        "last_seen_at": row[5],
    }


def lease_next_execution(
    conn,
    *,
    node_code: str,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> dict | None:
    """Atomically lease one due PENDING execution assigned to a node.

    The plaintext bearer token is returned exactly from this operation.
    Only its SHA-256 digest is persisted.
    """

    lease_seconds = _require_lease_seconds(
        lease_seconds
    )

    node = _get_node_for_update(
        conn,
        node_code=node_code,
    )

    if not node["is_enabled"]:
        raise ScanCoordinationConflictError(
            f"Execution node {node_code} is disabled"
        )

    # A lease request also proves that the node is alive.
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_execution_nodes
            SET last_seen_at = now()
            WHERE execution_node_id = %s
            """,
            (node["execution_node_id"],),
        )

        cur.execute(
            """
            SELECT
                scan_execution_id
            FROM scan_executions
            WHERE execution_node_id = %s
              AND status = 'PENDING'
              AND scheduled_for <= now()
            ORDER BY
                scheduled_for ASC,
                scan_execution_id ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """,
            (node["execution_node_id"],),
        )

        candidate = cur.fetchone()

        if candidate is None:
            return None

        scan_execution_id = candidate[0]
        lease_token = _generate_lease_token()
        lease_token_hash = _hash_lease_token(
            lease_token
        )

        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'LEASED',
                leased_at = now(),
                lease_expires_at =
                    now() + (%s * interval '1 second'),
                lease_token_hash = %s
            WHERE scan_execution_id = %s
              AND status = 'PENDING'
            RETURNING
                scan_execution_id,
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                execution_node_id,
                execution_model,
                scanner_subject_type,
                scanner_subject_value,
                scanner_parameters,
                status,
                scheduled_for,
                leased_at,
                lease_expires_at
            """,
            (
                lease_seconds,
                lease_token_hash,
                scan_execution_id,
            ),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanCoordinationConflictError(
            f"Execution {scan_execution_id} could not be leased"
        )

    return {
        "scan_execution_id": row[0],
        "scan_policy_id": row[1],
        "tenant_code": row[2],
        "asset_id": row[3],
        "scanner_type": row[4],
        "execution_node_id": row[5],
        "node_code": node["node_code"],
        "execution_model": row[6],
        "scanner_subject_type": row[7],
        "scanner_subject_value": row[8],
        "scanner_parameters": row[9],
        "status": row[10],
        "scheduled_for": row[11],
        "leased_at": row[12],
        "lease_expires_at": row[13],
        "lease_token": lease_token,
    }


def _lock_execution_for_lease_transition(
    conn,
    *,
    scan_execution_id: int,
    node_code: str,
    lease_token: str,
    required_status: str,
) -> dict:
    scan_execution_id = _require_positive_int(
        scan_execution_id,
        "scan_execution_id",
    )

    node_code = _require_nonblank(
        node_code,
        "node_code",
    )

    lease_token = _require_nonblank(
        lease_token,
        "lease_token",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                e.scan_execution_id,
                e.status,
                e.execution_node_id,
                n.node_code,
                e.lease_token_hash,
                e.leased_at,
                e.lease_expires_at,
                e.started_at,
                now()
            FROM scan_executions e
            JOIN scan_execution_nodes n
              ON n.execution_node_id = e.execution_node_id
            WHERE e.scan_execution_id = %s
            FOR UPDATE OF e
            """,
            (scan_execution_id,),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanCoordinationNotFoundError(
            f"Scan execution {scan_execution_id} does not exist"
        )

    state = {
        "scan_execution_id": row[0],
        "status": row[1],
        "execution_node_id": row[2],
        "node_code": row[3],
        "lease_token_hash": row[4],
        "leased_at": row[5],
        "lease_expires_at": row[6],
        "started_at": row[7],
        "database_now": row[8],
    }

    if state["node_code"] != node_code:
        raise ScanLeaseAuthenticationError(
            "Execution is not leased to this execution node"
        )

    if state["status"] != required_status:
        raise ScanCoordinationConflictError(
            f"Execution {scan_execution_id} is {state['status']}; "
            f"expected {required_status}"
        )

    stored_hash = state["lease_token_hash"]

    if stored_hash is None:
        raise ScanLeaseAuthenticationError(
            "Execution has no active lease credential"
        )

    supplied_hash = _hash_lease_token(
        lease_token
    )

    if not hmac.compare_digest(
        stored_hash,
        supplied_hash,
    ):
        raise ScanLeaseAuthenticationError(
            "Invalid lease credential"
        )

    if (
        state["lease_expires_at"] is None
        or state["database_now"]
        >= state["lease_expires_at"]
    ):
        raise ScanLeaseExpiredError(
            f"Lease for execution {scan_execution_id} has expired"
        )

    return state


def mark_execution_started(
    conn,
    *,
    scan_execution_id: int,
    node_code: str,
    lease_token: str,
) -> dict:
    """Transition one valid LEASED execution to RUNNING."""

    state = _lock_execution_for_lease_transition(
        conn,
        scan_execution_id=scan_execution_id,
        node_code=node_code,
        lease_token=lease_token,
        required_status="LEASED",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'RUNNING',
                started_at = now()
            WHERE scan_execution_id = %s
            RETURNING
                started_at,
                lease_expires_at
            """,
            (state["scan_execution_id"],),
        )

        row = cur.fetchone()

    return {
        "scan_execution_id": state[
            "scan_execution_id"
        ],
        "status": "RUNNING",
        "started_at": row[0],
        "lease_expires_at": row[1],
    }


def mark_execution_succeeded(
    conn,
    *,
    scan_execution_id: int,
    node_code: str,
    lease_token: str,
    execution_metadata: dict | None = None,
) -> dict:
    """Complete one RUNNING execution successfully."""

    execution_metadata = _require_metadata_object(
        execution_metadata,
        "execution_metadata",
    )

    state = _lock_execution_for_lease_transition(
        conn,
        scan_execution_id=scan_execution_id,
        node_code=node_code,
        lease_token=lease_token,
        required_status="RUNNING",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'SUCCEEDED',
                completed_at = now(),
                exit_code = 0,
                failure_reason = NULL,
                execution_metadata = %s,
                lease_token_hash = NULL
            WHERE scan_execution_id = %s
            RETURNING completed_at
            """,
            (
                Json(execution_metadata),
                state["scan_execution_id"],
            ),
        )

        row = cur.fetchone()

    return {
        "scan_execution_id": state[
            "scan_execution_id"
        ],
        "status": "SUCCEEDED",
        "completed_at": row[0],
        "exit_code": 0,
        "execution_metadata": execution_metadata,
    }


def mark_execution_failed(
    conn,
    *,
    scan_execution_id: int,
    node_code: str,
    lease_token: str,
    failure_reason: str,
    exit_code: int | None = None,
    execution_metadata: dict | None = None,
) -> dict:
    """Complete one RUNNING execution as FAILED."""

    failure_reason = _require_nonblank(
        failure_reason,
        "failure_reason",
    )

    execution_metadata = _require_metadata_object(
        execution_metadata,
        "execution_metadata",
    )

    if exit_code is not None:
        if isinstance(exit_code, bool):
            raise ScanCoordinationValidationError(
                "exit_code must be an integer or None"
            )

        try:
            exit_code = int(exit_code)
        except (TypeError, ValueError) as exc:
            raise ScanCoordinationValidationError(
                "exit_code must be an integer or None"
            ) from exc

    state = _lock_execution_for_lease_transition(
        conn,
        scan_execution_id=scan_execution_id,
        node_code=node_code,
        lease_token=lease_token,
        required_status="RUNNING",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'FAILED',
                completed_at = now(),
                exit_code = %s,
                failure_reason = %s,
                execution_metadata = %s,
                lease_token_hash = NULL
            WHERE scan_execution_id = %s
            RETURNING completed_at
            """,
            (
                exit_code,
                failure_reason,
                Json(execution_metadata),
                state["scan_execution_id"],
            ),
        )

        row = cur.fetchone()

    return {
        "scan_execution_id": state[
            "scan_execution_id"
        ],
        "status": "FAILED",
        "completed_at": row[0],
        "exit_code": exit_code,
        "failure_reason": failure_reason,
        "execution_metadata": execution_metadata,
    }


def expire_overdue_leases(
    conn,
) -> dict:
    """Fail closed any expired active scan leases.

    A LEASED execution never started, so it becomes EXPIRED and retains
    no fabricated started_at/completed_at timestamps.

    A RUNNING execution did start. If its lease expires before a valid
    terminal report is accepted, it becomes FAILED with completed_at set.
    """

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'EXPIRED',
                lease_token_hash = NULL
            WHERE status = 'LEASED'
              AND lease_expires_at <= now()
            RETURNING scan_execution_id
            """
        )

        expired_ids = [
            row[0]
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            UPDATE scan_executions
            SET
                status = 'FAILED',
                completed_at = now(),
                failure_reason =
                    'Execution lease expired while scanner was running',
                lease_token_hash = NULL
            WHERE status = 'RUNNING'
              AND lease_expires_at <= now()
            RETURNING scan_execution_id
            """
        )

        failed_ids = [
            row[0]
            for row in cur.fetchall()
        ]

    return {
        "expired_before_start": expired_ids,
        "failed_while_running": failed_ids,
    }
