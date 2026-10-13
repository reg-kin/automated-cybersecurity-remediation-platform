"""Administrative scan-policy management service.

This module owns application-level administrative lifecycle transitions for
Scan Policy Administration V1.

It deliberately does not:
- create scan executions;
- select execution nodes;
- resolve scanner subjects;
- invoke scanners;
- parse scanner-native evidence;
- construct Unified Security Findings;
- determine finding_class;
- perform risk contextualisation;
- authorise remediation;
- calculate next scheduled occurrences.

The caller owns transaction boundaries. Functions in this module do not
commit or roll back the supplied PostgreSQL connection.

PostgreSQL remains the final persistence-enforcement boundary for scan-policy
and administrative-audit invariants.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg2 import IntegrityError
from psycopg2.extras import Json

from scan_coordination.scheduling import (
    ScheduleValidationError,
    validate_cron_schedule,
)
from scan_coordination.service import SCANNER_EXECUTION_MODELS


SERVICE_TIERS = {
    "GOLD",
    "STANDARD",
    "BRONZE",
}

SCHEDULE_TYPES = {
    "CRON",
    "MANUAL",
}

_UNSET = object()


class ScanPolicyAdministrationError(ValueError):
    """Base exception for expected scan-policy administration failures."""


class ScanPolicyAdministrationValidationError(
    ScanPolicyAdministrationError
):
    """Administrative request data is invalid."""


class ScanPolicyNotFoundError(ScanPolicyAdministrationError):
    """The tenant-scoped scan policy does not exist."""


class ScanPolicyAssetNotFoundError(ScanPolicyAdministrationError):
    """The tenant-scoped canonical asset does not exist."""


class ScanPolicyAdministrationConflictError(
    ScanPolicyAdministrationError
):
    """The requested transition conflicts with current policy state."""


def _require_nonblank(value: Any, field_name: str) -> str:
    if value is None or not str(value).strip():
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be non-blank"
        )

    return str(value).strip()


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be a positive integer"
        )

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be a positive integer"
        ) from exc

    if parsed <= 0:
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be a positive integer"
        )

    return parsed


def _require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be a boolean"
        )

    return value


def _require_scanner_parameters(value: Any) -> dict:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise ScanPolicyAdministrationValidationError(
            "scanner_parameters must be a dictionary"
        )

    return value


def _require_scanner_type(value: Any) -> str:
    scanner_type = _require_nonblank(
        value,
        "scanner_type",
    )

    if scanner_type not in SCANNER_EXECUTION_MODELS:
        raise ScanPolicyAdministrationValidationError(
            f"Unsupported scanner_type: {scanner_type}"
        )

    return scanner_type


def _require_service_tier(value: Any) -> str:
    service_tier = _require_nonblank(
        value,
        "service_tier",
    ).upper()

    if service_tier not in SERVICE_TIERS:
        raise ScanPolicyAdministrationValidationError(
            f"Unsupported service_tier: {service_tier}"
        )

    return service_tier


def _require_schedule_type(value: Any) -> str:
    schedule_type = _require_nonblank(
        value,
        "schedule_type",
    ).upper()

    if schedule_type not in SCHEDULE_TYPES:
        raise ScanPolicyAdministrationValidationError(
            f"Unsupported schedule_type: {schedule_type}"
        )

    return schedule_type


def _validate_schedule_configuration(
    *,
    schedule_type: Any,
    schedule_expression: Any,
    schedule_timezone: Any,
) -> tuple[str, str | None, str]:
    schedule_type = _require_schedule_type(schedule_type)

    schedule_timezone = _require_nonblank(
        schedule_timezone,
        "schedule_timezone",
    )

    if schedule_type == "MANUAL":
        if schedule_expression is not None:
            raise ScanPolicyAdministrationValidationError(
                "MANUAL scan policy requires schedule_expression to be null"
            )

        return (
            schedule_type,
            None,
            schedule_timezone,
        )

    try:
        expression, timezone_name = validate_cron_schedule(
            schedule_expression,
            schedule_timezone,
        )
    except ScheduleValidationError as exc:
        raise ScanPolicyAdministrationValidationError(
            str(exc)
        ) from exc

    return (
        schedule_type,
        expression,
        timezone_name,
    )


def _policy_from_row(row) -> dict:
    return {
        "scan_policy_id": row[0],
        "tenant_code": row[1],
        "asset_id": row[2],
        "scanner_type": row[3],
        "service_tier": row[4],
        "profile_name": row[5],
        "scanner_parameters": row[6] or {},
        "schedule_type": row[7],
        "schedule_expression": row[8],
        "schedule_timezone": row[9],
        "next_run_at": row[10],
        "is_enabled": row[11],
        "created_at": row[12],
        "updated_at": row[13],
    }


def _audit_snapshot(policy: dict) -> dict:
    def serialise(value):
        if isinstance(value, datetime):
            return value.isoformat()

        return value

    return {
        key: serialise(value)
        for key, value in policy.items()
    }


def _get_asset_for_update(
    conn,
    *,
    asset_id: int,
    tenant_code: str,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                asset_id,
                tenant_code,
                inventory_state,
                lifecycle_status
            FROM assets
            WHERE asset_id = %s
              AND tenant_code = %s
            FOR UPDATE
            """,
            (
                asset_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanPolicyAssetNotFoundError(
            f"Asset {asset_id} does not exist for tenant {tenant_code}"
        )

    return {
        "asset_id": row[0],
        "tenant_code": row[1],
        "inventory_state": row[2],
        "lifecycle_status": row[3],
    }


def _get_policy(
    conn,
    *,
    scan_policy_id: int,
    tenant_code: str,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            FROM scan_policies
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanPolicyNotFoundError(
            f"Scan policy {scan_policy_id} does not exist "
            f"for tenant {tenant_code}"
        )

    return _policy_from_row(row)


def _get_policy_for_update(
    conn,
    *,
    scan_policy_id: int,
    tenant_code: str,
) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            FROM scan_policies
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            FOR UPDATE
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanPolicyNotFoundError(
            f"Scan policy {scan_policy_id} does not exist "
            f"for tenant {tenant_code}"
        )

    return _policy_from_row(row)


def _insert_audit(
    conn,
    *,
    scan_policy_id: int,
    tenant_code: str,
    action: str,
    performed_by: str,
    reason: str,
    before_state: dict | None,
    after_state: dict,
) -> dict:
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    if before_state is not None and not isinstance(before_state, dict):
        raise ScanPolicyAdministrationValidationError(
            "before_state must be a dictionary or null"
        )

    if not isinstance(after_state, dict):
        raise ScanPolicyAdministrationValidationError(
            "after_state must be a dictionary"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_policy_admin_audit (
                scan_policy_id,
                tenant_code,
                action,
                performed_by,
                reason,
                before_state,
                after_state
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING
                audit_id,
                created_at
            """,
            (
                scan_policy_id,
                tenant_code,
                action,
                performed_by,
                reason,
                (
                    Json(before_state)
                    if before_state is not None
                    else None
                ),
                Json(after_state),
            ),
        )

        row = cur.fetchone()

    return {
        "audit_id": row[0],
        "created_at": row[1],
    }


def create_scan_policy(
    conn,
    *,
    tenant_code: Any,
    asset_id: Any,
    scanner_type: Any,
    service_tier: Any,
    profile_name: Any = "default",
    scanner_parameters: Any = None,
    schedule_type: Any = "CRON",
    schedule_expression: Any = None,
    schedule_timezone: Any = "UTC",
    is_enabled: Any = True,
    performed_by: Any,
    reason: Any,
) -> dict:
    """Create one tenant-scoped scan policy and its CREATE audit event."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    asset_id = _require_positive_int(
        asset_id,
        "asset_id",
    )
    scanner_type = _require_scanner_type(scanner_type)
    service_tier = _require_service_tier(service_tier)
    profile_name = _require_nonblank(
        profile_name,
        "profile_name",
    )
    scanner_parameters = _require_scanner_parameters(
        scanner_parameters
    )
    is_enabled = _require_bool(
        is_enabled,
        "is_enabled",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    (
        schedule_type,
        schedule_expression,
        schedule_timezone,
    ) = _validate_schedule_configuration(
        schedule_type=schedule_type,
        schedule_expression=schedule_expression,
        schedule_timezone=schedule_timezone,
    )

    asset = _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    if asset["lifecycle_status"] != "ACTIVE":
        raise ScanPolicyAdministrationConflictError(
            f"Asset {asset_id} must be ACTIVE before a scan policy "
            "can be created"
        )

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_policies (
                    tenant_code,
                    asset_id,
                    scanner_type,
                    service_tier,
                    profile_name,
                    scanner_parameters,
                    schedule_type,
                    schedule_expression,
                    schedule_timezone,
                    next_run_at,
                    is_enabled
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
                    NULL,
                    %s
                )
                RETURNING
                    scan_policy_id,
                    tenant_code,
                    asset_id,
                    scanner_type,
                    service_tier,
                    profile_name,
                    scanner_parameters,
                    schedule_type,
                    schedule_expression,
                    schedule_timezone,
                    next_run_at,
                    is_enabled,
                    created_at,
                    updated_at
                """,
                (
                    tenant_code,
                    asset_id,
                    scanner_type,
                    service_tier,
                    profile_name,
                    Json(scanner_parameters),
                    schedule_type,
                    schedule_expression,
                    schedule_timezone,
                    is_enabled,
                ),
            )

            row = cur.fetchone()
    except IntegrityError as exc:
        if getattr(exc, "diag", None) is not None:
            if exc.diag.constraint_name == "uq_scan_policy_identity":
                raise ScanPolicyAdministrationConflictError(
                    "A scan policy already exists for tenant "
                    f"{tenant_code}, asset {asset_id}, scanner "
                    f"{scanner_type}, profile {profile_name}"
                ) from exc

        raise

    policy = _policy_from_row(row)

    audit = _insert_audit(
        conn,
        scan_policy_id=policy["scan_policy_id"],
        tenant_code=tenant_code,
        action="CREATE",
        performed_by=performed_by,
        reason=reason,
        before_state=None,
        after_state=_audit_snapshot(policy),
    )

    return {
        **policy,
        "audit_id": audit["audit_id"],
    }


def get_scan_policy(
    conn,
    *,
    scan_policy_id: Any,
    tenant_code: Any,
) -> dict:
    """Return one tenant-scoped scan policy."""

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )

    return _get_policy(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
    )


def list_scan_policies(
    conn,
    *,
    tenant_code: Any,
) -> list[dict]:
    """Return all scan policies for one tenant."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            FROM scan_policies
            WHERE tenant_code = %s
            ORDER BY scan_policy_id
            """,
            (tenant_code,),
        )

        rows = cur.fetchall()

    return [
        _policy_from_row(row)
        for row in rows
    ]


def update_scan_policy_configuration(
    conn,
    *,
    scan_policy_id: Any,
    tenant_code: Any,
    performed_by: Any,
    reason: Any,
    scanner_parameters: Any = _UNSET,
    service_tier: Any = _UNSET,
    schedule_type: Any = _UNSET,
    schedule_expression: Any = _UNSET,
    schedule_timezone: Any = _UNSET,
) -> dict:
    """Update mutable policy configuration and audit the transition."""

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    policy = _get_policy_for_update(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
    )

    new_scanner_parameters = policy["scanner_parameters"]
    new_service_tier = policy["service_tier"]
    new_schedule_type = policy["schedule_type"]
    new_schedule_expression = policy["schedule_expression"]
    new_schedule_timezone = policy["schedule_timezone"]

    if scanner_parameters is not _UNSET:
        new_scanner_parameters = _require_scanner_parameters(
            scanner_parameters
        )

    if service_tier is not _UNSET:
        new_service_tier = _require_service_tier(
            service_tier
        )

    schedule_type_changed = schedule_type is not _UNSET
    schedule_expression_changed = schedule_expression is not _UNSET
    schedule_timezone_changed = schedule_timezone is not _UNSET

    if schedule_type_changed:
        new_schedule_type = _require_schedule_type(
            schedule_type
        )

        if new_schedule_type == "MANUAL":
            if (
                schedule_expression_changed
                and schedule_expression is not None
            ):
                raise ScanPolicyAdministrationValidationError(
                    "MANUAL scan policy requires "
                    "schedule_expression to be null"
                )

            new_schedule_expression = None

    if schedule_expression_changed:
        new_schedule_expression = schedule_expression

    if schedule_timezone_changed:
        new_schedule_timezone = schedule_timezone

    (
        new_schedule_type,
        new_schedule_expression,
        new_schedule_timezone,
    ) = _validate_schedule_configuration(
        schedule_type=new_schedule_type,
        schedule_expression=new_schedule_expression,
        schedule_timezone=new_schedule_timezone,
    )

    schedule_configuration_changed = (
        new_schedule_type != policy["schedule_type"]
        or new_schedule_expression != policy["schedule_expression"]
        or new_schedule_timezone != policy["schedule_timezone"]
    )

    configuration_changed = (
        new_scanner_parameters != policy["scanner_parameters"]
        or new_service_tier != policy["service_tier"]
        or schedule_configuration_changed
    )

    if not configuration_changed:
        raise ScanPolicyAdministrationConflictError(
            f"Scan policy {scan_policy_id} configuration is unchanged"
        )

    next_run_at = (
        None
        if schedule_configuration_changed
        else policy["next_run_at"]
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_policies
            SET scanner_parameters = %s,
                service_tier = %s,
                schedule_type = %s,
                schedule_expression = %s,
                schedule_timezone = %s,
                next_run_at = %s
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            RETURNING
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            """,
            (
                Json(new_scanner_parameters),
                new_service_tier,
                new_schedule_type,
                new_schedule_expression,
                new_schedule_timezone,
                next_run_at,
                scan_policy_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    updated = _policy_from_row(row)

    audit = _insert_audit(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
        action="UPDATE_CONFIGURATION",
        performed_by=performed_by,
        reason=reason,
        before_state=_audit_snapshot(policy),
        after_state=_audit_snapshot(updated),
    )

    return {
        **updated,
        "audit_id": audit["audit_id"],
    }


def disable_scan_policy(
    conn,
    *,
    scan_policy_id: Any,
    tenant_code: Any,
    performed_by: Any,
    reason: Any,
) -> dict:
    """Disable one scan policy and clear automatic scheduling state."""

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    policy = _get_policy_for_update(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
    )

    if not policy["is_enabled"]:
        raise ScanPolicyAdministrationConflictError(
            f"Scan policy {scan_policy_id} is already disabled"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_policies
            SET is_enabled = FALSE,
                next_run_at = NULL
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            RETURNING
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    updated = _policy_from_row(row)

    audit = _insert_audit(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
        action="DISABLE",
        performed_by=performed_by,
        reason=reason,
        before_state=_audit_snapshot(policy),
        after_state=_audit_snapshot(updated),
    )

    return {
        **updated,
        "audit_id": audit["audit_id"],
    }


def enable_scan_policy(
    conn,
    *,
    scan_policy_id: Any,
    tenant_code: Any,
    performed_by: Any,
    reason: Any,
) -> dict:
    """Enable one scan policy and leave CRON initialisation to the scheduler."""

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    policy = _get_policy_for_update(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
    )

    if policy["is_enabled"]:
        raise ScanPolicyAdministrationConflictError(
            f"Scan policy {scan_policy_id} is already enabled"
        )

    asset = _get_asset_for_update(
        conn,
        asset_id=policy["asset_id"],
        tenant_code=tenant_code,
    )

    if asset["lifecycle_status"] != "ACTIVE":
        raise ScanPolicyAdministrationConflictError(
            f"Asset {policy['asset_id']} must be ACTIVE before scan "
            f"policy {scan_policy_id} can be enabled"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_policies
            SET is_enabled = TRUE,
                next_run_at = NULL
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            RETURNING
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled,
                created_at,
                updated_at
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    updated = _policy_from_row(row)

    audit = _insert_audit(
        conn,
        scan_policy_id=scan_policy_id,
        tenant_code=tenant_code,
        action="ENABLE",
        performed_by=performed_by,
        reason=reason,
        before_state=_audit_snapshot(policy),
        after_state=_audit_snapshot(updated),
    )

    return {
        **updated,
        "audit_id": audit["audit_id"],
    }


def get_scan_policy_history(
    conn,
    *,
    scan_policy_id: Any,
    tenant_code: Any,
) -> list[dict]:
    """Return append-only administrative history for one scan policy.

    Audit history remains readable even if the live scan-policy row no longer
    exists, because scan_policy_admin_audit is deliberately independent of the
    live policy table.
    """

    scan_policy_id = _require_positive_int(
        scan_policy_id,
        "scan_policy_id",
    )
    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                audit_id,
                scan_policy_id,
                tenant_code,
                action,
                performed_by,
                reason,
                before_state,
                after_state,
                created_at
            FROM scan_policy_admin_audit
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            ORDER BY audit_id
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        rows = cur.fetchall()

    if rows:
        return [
            {
                "audit_id": row[0],
                "scan_policy_id": row[1],
                "tenant_code": row[2],
                "action": row[3],
                "performed_by": row[4],
                "reason": row[5],
                "before_state": row[6],
                "after_state": row[7],
                "created_at": row[8],
            }
            for row in rows
        ]

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1
            FROM scan_policies
            WHERE scan_policy_id = %s
              AND tenant_code = %s
            """,
            (
                scan_policy_id,
                tenant_code,
            ),
        )

        policy_exists = cur.fetchone() is not None

    if not policy_exists:
        raise ScanPolicyNotFoundError(
            f"Scan policy {scan_policy_id} does not exist "
            f"for tenant {tenant_code}"
        )

    return []
