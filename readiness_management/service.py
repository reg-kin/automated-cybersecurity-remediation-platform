"""Administrative remediation-readiness management service.

This module owns application-level administrative transitions for
Asset Remediation Readiness V1.

It deliberately does not perform:
- asset discovery or resolution;
- scanner ingestion;
- remediation routing;
- risk prioritisation;
- remediation execution;
- execution approval.

PostgreSQL remains the final enforcement boundary for all readiness
invariants established by migration 016_asset_remediation_readiness.sql.
"""

from psycopg2.extras import Json


def _require_nonblank(value, field_name):
    if value is None or not str(value).strip():
        raise ValueError(f"{field_name} must be non-blank")

    return str(value).strip()


def _get_asset_for_update(conn, *, asset_id, tenant_code):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                asset_id,
                tenant_code,
                inventory_state,
                lifecycle_status,
                management_authorised_at,
                management_authorised_by,
                management_authorisation_reason,
                management_revoked_at,
                management_revoked_by,
                management_revocation_reason
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
        raise ValueError(
            f"Asset {asset_id} does not exist for tenant {tenant_code}"
        )

    return {
        "asset_id": row[0],
        "tenant_code": row[1],
        "inventory_state": row[2],
        "lifecycle_status": row[3],
        "management_authorised_at": row[4],
        "management_authorised_by": row[5],
        "management_authorisation_reason": row[6],
        "management_revoked_at": row[7],
        "management_revoked_by": row[8],
        "management_revocation_reason": row[9],
    }


def _get_asset(conn, *, asset_id, tenant_code):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                asset_id,
                tenant_code,
                inventory_state,
                lifecycle_status,
                management_authorised_at,
                management_authorised_by,
                management_authorisation_reason,
                management_revoked_at,
                management_revoked_by,
                management_revocation_reason
            FROM assets
            WHERE asset_id = %s
              AND tenant_code = %s
            """,
            (
                asset_id,
                tenant_code,
            ),
        )

        row = cur.fetchone()

    if row is None:
        raise ValueError(
            f"Asset {asset_id} does not exist for tenant {tenant_code}"
        )

    return {
        "asset_id": row[0],
        "tenant_code": row[1],
        "inventory_state": row[2],
        "lifecycle_status": row[3],
        "management_authorised_at": row[4],
        "management_authorised_by": row[5],
        "management_authorisation_reason": row[6],
        "management_revoked_at": row[7],
        "management_revoked_by": row[8],
        "management_revocation_reason": row[9],
    }


def _get_execution_targets(conn, *, asset_id, tenant_code):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                execution_target_id,
                execution_target,
                is_active,
                source,
                authorised_at,
                authorised_by,
                authorisation_reason,
                revoked_at,
                revoked_by,
                revocation_reason,
                created_at,
                updated_at
            FROM asset_execution_targets
            WHERE asset_id = %s
              AND tenant_code = %s
            ORDER BY execution_target_id
            """,
            (
                asset_id,
                tenant_code,
            ),
        )

        rows = cur.fetchall()

    return [
        {
            "execution_target_id": row[0],
            "execution_target": row[1],
            "is_active": row[2],
            "source": row[3],
            "authorised_at": row[4],
            "authorised_by": row[5],
            "authorisation_reason": row[6],
            "revoked_at": row[7],
            "revoked_by": row[8],
            "revocation_reason": row[9],
            "created_at": row[10],
            "updated_at": row[11],
        }
        for row in rows
    ]


def _get_execution_targets_for_update(conn, *, asset_id, tenant_code):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                execution_target_id,
                execution_target,
                is_active,
                source,
                authorised_at,
                authorised_by,
                authorisation_reason,
                revoked_at,
                revoked_by,
                revocation_reason,
                created_at,
                updated_at
            FROM asset_execution_targets
            WHERE asset_id = %s
              AND tenant_code = %s
            ORDER BY execution_target_id
            FOR UPDATE
            """,
            (
                asset_id,
                tenant_code,
            ),
        )

        rows = cur.fetchall()

    return [
        {
            "execution_target_id": row[0],
            "execution_target": row[1],
            "is_active": row[2],
            "source": row[3],
            "authorised_at": row[4],
            "authorised_by": row[5],
            "authorisation_reason": row[6],
            "revoked_at": row[7],
            "revoked_by": row[8],
            "revocation_reason": row[9],
            "created_at": row[10],
            "updated_at": row[11],
        }
        for row in rows
    ]


def _insert_audit(
    conn,
    *,
    asset_id,
    tenant_code,
    event_type,
    performed_by,
    reason,
    execution_target_id=None,
    event_metadata=None,
):
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )

    metadata = {} if event_metadata is None else event_metadata

    if not isinstance(metadata, dict):
        raise ValueError("event_metadata must be a dictionary")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO asset_remediation_audit (
                asset_id,
                tenant_code,
                execution_target_id,
                event_type,
                performed_by,
                reason,
                event_metadata
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
            RETURNING audit_id, created_at
            """,
            (
                asset_id,
                tenant_code,
                execution_target_id,
                event_type,
                performed_by,
                reason,
                Json(metadata),
            ),
        )

        row = cur.fetchone()

    return {
        "audit_id": row[0],
        "created_at": row[1],
    }


def authorise_asset_management(
    conn,
    *,
    asset_id,
    tenant_code,
    performed_by,
    reason,
):
    """Explicitly authorise an asset for managed remediation."""

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

    asset = _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    if asset["lifecycle_status"] != "ACTIVE":
        raise ValueError(
            f"Asset {asset_id} must be ACTIVE before management "
            "can be authorised"
        )

    if (
        asset["inventory_state"] == "MANAGED"
        and asset["management_authorised_at"] is not None
        and asset["management_revoked_at"] is None
    ):
        raise ValueError(
            f"Asset {asset_id} is already authorised as MANAGED"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE assets
            SET inventory_state = 'MANAGED',
                management_authorised_at = now(),
                management_authorised_by = %s,
                management_authorisation_reason = %s,
                management_revoked_at = NULL,
                management_revoked_by = NULL,
                management_revocation_reason = NULL,
                updated_at = now()
            WHERE asset_id = %s
              AND tenant_code = %s
            RETURNING management_authorised_at
            """,
            (
                performed_by,
                reason,
                asset_id,
                tenant_code,
            ),
        )

        authorised_at = cur.fetchone()[0]

    audit = _insert_audit(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
        event_type="ASSET_MANAGED",
        performed_by=performed_by,
        reason=reason,
        event_metadata={
            "previous_inventory_state": asset["inventory_state"],
            "new_inventory_state": "MANAGED",
        },
    )

    return {
        "asset_id": asset_id,
        "tenant_code": tenant_code,
        "inventory_state": "MANAGED",
        "management_authorised_at": authorised_at,
        "management_authorised_by": performed_by,
        "audit_id": audit["audit_id"],
    }


def revoke_asset_management(
    conn,
    *,
    asset_id,
    tenant_code,
    performed_by,
    reason,
):
    """Revoke management authorisation for an asset."""

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

    asset = _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    if (
        asset["inventory_state"] != "MANAGED"
        or asset["management_authorised_at"] is None
        or asset["management_revoked_at"] is not None
    ):
        raise ValueError(
            f"Asset {asset_id} does not have current management "
            "authorisation"
        )

    targets = _get_execution_targets_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    active_targets = [
        target
        for target in targets
        if target["is_active"]
    ]

    if active_targets:
        raise ValueError(
            f"Asset {asset_id} still has an active execution target; "
            "revoke the execution target before revoking asset management"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE assets
            SET inventory_state = 'UNMANAGED',
                management_revoked_at = now(),
                management_revoked_by = %s,
                management_revocation_reason = %s,
                updated_at = now()
            WHERE asset_id = %s
              AND tenant_code = %s
            RETURNING management_revoked_at
            """,
            (
                performed_by,
                reason,
                asset_id,
                tenant_code,
            ),
        )

        revoked_at = cur.fetchone()[0]

    audit = _insert_audit(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
        event_type="ASSET_MANAGEMENT_REVOKED",
        performed_by=performed_by,
        reason=reason,
        event_metadata={
            "previous_inventory_state": "MANAGED",
            "new_inventory_state": "UNMANAGED",
        },
    )

    return {
        "asset_id": asset_id,
        "tenant_code": tenant_code,
        "inventory_state": "UNMANAGED",
        "management_revoked_at": revoked_at,
        "management_revoked_by": performed_by,
        "audit_id": audit["audit_id"],
    }


def authorise_execution_target(
    conn,
    *,
    asset_id,
    tenant_code,
    execution_target,
    performed_by,
    reason,
    source="ADMINISTRATIVE_READINESS_V1",
):
    """Provision and authorise one remediation execution target."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    execution_target = _require_nonblank(
        execution_target,
        "execution_target",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )
    source = _require_nonblank(
        source,
        "source",
    )

    asset = _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    if asset["inventory_state"] != "MANAGED":
        raise ValueError(
            f"Asset {asset_id} must be MANAGED before an execution "
            "target can be authorised"
        )

    if asset["lifecycle_status"] != "ACTIVE":
        raise ValueError(
            f"Asset {asset_id} must be ACTIVE before an execution "
            "target can be authorised"
        )

    if (
        asset["management_authorised_at"] is None
        or asset["management_revoked_at"] is not None
    ):
        raise ValueError(
            f"Asset {asset_id} does not have current management "
            "authorisation"
        )

    targets = _get_execution_targets_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    active_targets = [
        target
        for target in targets
        if target["is_active"]
    ]

    if active_targets:
        raise ValueError(
            f"Asset {asset_id} already has an active execution target"
        )

    existing = next(
        (
            target
            for target in targets
            if target["execution_target"] == execution_target
        ),
        None,
    )

    with conn.cursor() as cur:
        if existing is None:
            cur.execute(
                """
                INSERT INTO asset_execution_targets (
                    asset_id,
                    tenant_code,
                    execution_target,
                    is_active,
                    source,
                    authorised_at,
                    authorised_by,
                    authorisation_reason
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    TRUE,
                    %s,
                    now(),
                    %s,
                    %s
                )
                RETURNING
                    execution_target_id,
                    authorised_at
                """,
                (
                    asset_id,
                    tenant_code,
                    execution_target,
                    source,
                    performed_by,
                    reason,
                ),
            )
        else:
            cur.execute(
                """
                UPDATE asset_execution_targets
                SET is_active = TRUE,
                    source = %s,
                    authorised_at = now(),
                    authorised_by = %s,
                    authorisation_reason = %s,
                    revoked_at = NULL,
                    revoked_by = NULL,
                    revocation_reason = NULL,
                    updated_at = now()
                WHERE execution_target_id = %s
                RETURNING
                    execution_target_id,
                    authorised_at
                """,
                (
                    source,
                    performed_by,
                    reason,
                    existing["execution_target_id"],
                ),
            )

        row = cur.fetchone()

    execution_target_id = row[0]
    authorised_at = row[1]

    audit = _insert_audit(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
        execution_target_id=execution_target_id,
        event_type="EXECUTION_TARGET_AUTHORISED",
        performed_by=performed_by,
        reason=reason,
        event_metadata={
            "execution_target": execution_target,
            "source": source,
        },
    )

    return {
        "asset_id": asset_id,
        "tenant_code": tenant_code,
        "execution_target_id": execution_target_id,
        "execution_target": execution_target,
        "is_active": True,
        "authorised_at": authorised_at,
        "authorised_by": performed_by,
        "audit_id": audit["audit_id"],
    }


def revoke_execution_target(
    conn,
    *,
    asset_id,
    tenant_code,
    performed_by,
    reason,
):
    """Revoke the currently active remediation execution target."""

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

    _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    targets = _get_execution_targets_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    active_targets = [
        target
        for target in targets
        if target["is_active"]
    ]

    if len(active_targets) != 1:
        raise ValueError(
            f"Asset {asset_id} must have exactly one active execution "
            "target to revoke"
        )

    target = active_targets[0]

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE asset_execution_targets
            SET is_active = FALSE,
                revoked_at = now(),
                revoked_by = %s,
                revocation_reason = %s,
                updated_at = now()
            WHERE execution_target_id = %s
            RETURNING revoked_at
            """,
            (
                performed_by,
                reason,
                target["execution_target_id"],
            ),
        )

        revoked_at = cur.fetchone()[0]

    audit = _insert_audit(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
        execution_target_id=target["execution_target_id"],
        event_type="EXECUTION_TARGET_REVOKED",
        performed_by=performed_by,
        reason=reason,
        event_metadata={
            "execution_target": target["execution_target"],
        },
    )

    return {
        "asset_id": asset_id,
        "tenant_code": tenant_code,
        "execution_target_id": target["execution_target_id"],
        "execution_target": target["execution_target"],
        "is_active": False,
        "revoked_at": revoked_at,
        "revoked_by": performed_by,
        "audit_id": audit["audit_id"],
    }


def replace_execution_target(
    conn,
    *,
    asset_id,
    tenant_code,
    execution_target,
    performed_by,
    reason,
    source="ADMINISTRATIVE_READINESS_V1",
):
    """Atomically replace the currently active execution target."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )
    execution_target = _require_nonblank(
        execution_target,
        "execution_target",
    )
    performed_by = _require_nonblank(
        performed_by,
        "performed_by",
    )
    reason = _require_nonblank(
        reason,
        "reason",
    )
    source = _require_nonblank(
        source,
        "source",
    )

    asset = _get_asset_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    if asset["inventory_state"] != "MANAGED":
        raise ValueError(
            f"Asset {asset_id} must be MANAGED before its execution "
            "target can be replaced"
        )

    if asset["lifecycle_status"] != "ACTIVE":
        raise ValueError(
            f"Asset {asset_id} must be ACTIVE before its execution "
            "target can be replaced"
        )

    if (
        asset["management_authorised_at"] is None
        or asset["management_revoked_at"] is not None
    ):
        raise ValueError(
            f"Asset {asset_id} does not have current management "
            "authorisation"
        )

    targets = _get_execution_targets_for_update(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    active_targets = [
        target
        for target in targets
        if target["is_active"]
    ]

    if len(active_targets) != 1:
        raise ValueError(
            f"Asset {asset_id} must have exactly one active execution "
            "target before replacement"
        )

    previous = active_targets[0]

    if previous["execution_target"] == execution_target:
        raise ValueError(
            "Replacement execution target must differ from the "
            "currently active target"
        )

    existing_replacement = next(
        (
            target
            for target in targets
            if target["execution_target"] == execution_target
        ),
        None,
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE asset_execution_targets
            SET is_active = FALSE,
                revoked_at = now(),
                revoked_by = %s,
                revocation_reason = %s,
                updated_at = now()
            WHERE execution_target_id = %s
            """,
            (
                performed_by,
                reason,
                previous["execution_target_id"],
            ),
        )

        if existing_replacement is None:
            cur.execute(
                """
                INSERT INTO asset_execution_targets (
                    asset_id,
                    tenant_code,
                    execution_target,
                    is_active,
                    source,
                    authorised_at,
                    authorised_by,
                    authorisation_reason
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    TRUE,
                    %s,
                    now(),
                    %s,
                    %s
                )
                RETURNING
                    execution_target_id,
                    authorised_at
                """,
                (
                    asset_id,
                    tenant_code,
                    execution_target,
                    source,
                    performed_by,
                    reason,
                ),
            )
        else:
            cur.execute(
                """
                UPDATE asset_execution_targets
                SET is_active = TRUE,
                    source = %s,
                    authorised_at = now(),
                    authorised_by = %s,
                    authorisation_reason = %s,
                    revoked_at = NULL,
                    revoked_by = NULL,
                    revocation_reason = NULL,
                    updated_at = now()
                WHERE execution_target_id = %s
                RETURNING
                    execution_target_id,
                    authorised_at
                """,
                (
                    source,
                    performed_by,
                    reason,
                    existing_replacement["execution_target_id"],
                ),
            )

        row = cur.fetchone()

    replacement_id = row[0]
    authorised_at = row[1]

    audit = _insert_audit(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
        execution_target_id=replacement_id,
        event_type="EXECUTION_TARGET_REPLACED",
        performed_by=performed_by,
        reason=reason,
        event_metadata={
            "previous_execution_target_id": (
                previous["execution_target_id"]
            ),
            "previous_execution_target": (
                previous["execution_target"]
            ),
            "new_execution_target_id": replacement_id,
            "new_execution_target": execution_target,
            "source": source,
        },
    )

    return {
        "asset_id": asset_id,
        "tenant_code": tenant_code,
        "previous_execution_target_id": (
            previous["execution_target_id"]
        ),
        "previous_execution_target": (
            previous["execution_target"]
        ),
        "execution_target_id": replacement_id,
        "execution_target": execution_target,
        "is_active": True,
        "authorised_at": authorised_at,
        "authorised_by": performed_by,
        "audit_id": audit["audit_id"],
    }


def get_asset_readiness(
    conn,
    *,
    asset_id,
    tenant_code,
):
    """Return the current administrative remediation-readiness state."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )

    asset = _get_asset(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    targets = _get_execution_targets(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    active_targets = [
        target
        for target in targets
        if target["is_active"]
    ]

    asset_authorised = (
        asset["inventory_state"] == "MANAGED"
        and asset["lifecycle_status"] == "ACTIVE"
        and asset["management_authorised_at"] is not None
        and asset["management_revoked_at"] is None
    )

    target_authorised = (
        len(active_targets) == 1
        and active_targets[0]["authorised_at"] is not None
        and active_targets[0]["revoked_at"] is None
    )

    return {
        "asset": asset,
        "execution_targets": targets,
        "active_execution_target": (
            active_targets[0]
            if len(active_targets) == 1
            else None
        ),
        "asset_management_authorised": asset_authorised,
        "execution_target_authorised": target_authorised,
        "remediation_ready": (
            asset_authorised
            and target_authorised
        ),
    }


def get_asset_readiness_history(
    conn,
    *,
    asset_id,
    tenant_code,
):
    """Return append-only remediation-readiness history for an asset."""

    tenant_code = _require_nonblank(
        tenant_code,
        "tenant_code",
    )

    _get_asset(
        conn,
        asset_id=asset_id,
        tenant_code=tenant_code,
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                audit_id,
                asset_id,
                tenant_code,
                execution_target_id,
                event_type,
                performed_by,
                reason,
                event_metadata,
                created_at
            FROM asset_remediation_audit
            WHERE asset_id = %s
              AND tenant_code = %s
            ORDER BY audit_id
            """,
            (
                asset_id,
                tenant_code,
            ),
        )

        rows = cur.fetchall()

    return [
        {
            "audit_id": row[0],
            "asset_id": row[1],
            "tenant_code": row[2],
            "execution_target_id": row[3],
            "event_type": row[4],
            "performed_by": row[5],
            "reason": row[6],
            "event_metadata": row[7] or {},
            "created_at": row[8],
        }
        for row in rows
    ]
