"""Curated organisational and business context for canonical assets."""

from typing import Any, Dict, Optional


ENUM_VALUES = {
    "environment": {
        "DEVELOPMENT",
        "TEST",
        "STAGING",
        "PRODUCTION",
        "CORPORATE",
        "UNKNOWN",
    },
    "criticality": {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    },
    "data_classification": {
        "PUBLIC",
        "INTERNAL",
        "CONFIDENTIAL",
        "RESTRICTED",
        "UNKNOWN",
    },
    "internet_exposure": {
        "INTERNAL",
        "EXTERNALLY_REACHABLE",
        "INTERNET_FACING",
        "UNKNOWN",
    },
    "confidentiality_requirement": {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    },
    "integrity_requirement": {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    },
    "availability_requirement": {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    },
}


TEXT_FIELDS = {
    "business_service",
    "business_unit",
    "owner",
    "technical_owner",
    "network_zone",
}


CONTEXT_FIELDS = (
    "environment",
    "business_service",
    "business_unit",
    "owner",
    "technical_owner",
    "criticality",
    "data_classification",
    "internet_exposure",
    "network_zone",
    "confidentiality_requirement",
    "integrity_requirement",
    "availability_requirement",
)


DEFAULT_CONTEXT = {
    "environment": "UNKNOWN",
    "business_service": None,
    "business_unit": None,
    "owner": None,
    "technical_owner": None,
    "criticality": "UNKNOWN",
    "data_classification": "UNKNOWN",
    "internet_exposure": "UNKNOWN",
    "network_zone": None,
    "confidentiality_requirement": "UNKNOWN",
    "integrity_requirement": "UNKNOWN",
    "availability_requirement": "UNKNOWN",
}


CONTEXT_SELECT_COLUMNS = (
    "asset_id",
    "tenant_code",
    *CONTEXT_FIELDS,
    "context_source",
    "created_at",
    "updated_at",
)


def _normalise_required_text(
    value: Any,
    *,
    field_name: str,
) -> str:
    if value is None:
        raise ValueError(
            f"{field_name} must not be empty"
        )

    normalised = str(value).strip()

    if not normalised:
        raise ValueError(
            f"{field_name} must not be empty"
        )

    return normalised


def _normalise_optional_text(
    value: Any,
) -> Optional[str]:
    if value is None:
        return None

    normalised = str(value).strip()

    if not normalised:
        return None

    return normalised


def _normalise_enum(
    field_name: str,
    value: Any,
) -> str:
    normalised = _normalise_required_text(
        value,
        field_name=field_name,
    ).upper()

    allowed = ENUM_VALUES[field_name]

    if normalised not in allowed:
        raise ValueError(
            f"Invalid {field_name}: {value!r}"
        )

    return normalised


def _normalise_context(
    context: Dict[str, Any],
) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise TypeError(
            "context must be a dictionary"
        )

    unknown_fields = (
        set(context)
        - set(CONTEXT_FIELDS)
    )

    if unknown_fields:
        unknown = ", ".join(
            sorted(unknown_fields)
        )
        raise ValueError(
            f"Unknown asset context field(s): {unknown}"
        )

    normalised = {}

    for field_name, value in context.items():
        if field_name in ENUM_VALUES:
            normalised[field_name] = _normalise_enum(
                field_name,
                value,
            )
            continue

        if field_name in TEXT_FIELDS:
            normalised[field_name] = (
                _normalise_optional_text(value)
            )
            continue

        raise ValueError(
            f"Unsupported asset context field: "
            f"{field_name}"
        )

    return normalised


def _assert_asset_exists(
    cur,
    *,
    tenant_code: str,
    asset_id: int,
) -> None:
    cur.execute(
        """
        SELECT 1
        FROM assets
        WHERE asset_id = %s
          AND tenant_code = %s
        """,
        (
            asset_id,
            tenant_code,
        ),
    )

    if cur.fetchone() is None:
        raise LookupError(
            "Asset does not exist for tenant"
        )


def _row_to_context(row) -> Dict[str, Any]:
    return dict(
        zip(
            CONTEXT_SELECT_COLUMNS,
            row,
        )
    )


def _get_asset_context(
    cur,
    *,
    tenant_code: str,
    asset_id: int,
) -> Optional[Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            asset_id,
            tenant_code,
            environment,
            business_service,
            business_unit,
            owner,
            technical_owner,
            criticality,
            data_classification,
            internet_exposure,
            network_zone,
            confidentiality_requirement,
            integrity_requirement,
            availability_requirement,
            context_source,
            created_at,
            updated_at
        FROM asset_context
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
        return None

    return _row_to_context(row)


def get_asset_context(
    conn,
    *,
    tenant_code,
    asset_id,
):
    """Return curated context for one tenant-scoped asset."""

    tenant_code = _normalise_required_text(
        tenant_code,
        field_name="tenant_code",
    )

    with conn.cursor() as cur:
        _assert_asset_exists(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )

        return _get_asset_context(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )


def set_asset_context(
    conn,
    *,
    tenant_code,
    asset_id,
    context,
    context_source="MANUAL",
):
    """
    Create or partially update curated context for an existing asset.

    This function does not commit or roll back the caller's transaction.
    """

    tenant_code = _normalise_required_text(
        tenant_code,
        field_name="tenant_code",
    )

    context_source = _normalise_required_text(
        context_source,
        field_name="context_source",
    )

    changes = _normalise_context(context)

    with conn.cursor() as cur:
        _assert_asset_exists(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )

        existing = _get_asset_context(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )

        if existing is None:
            merged = dict(DEFAULT_CONTEXT)
        else:
            merged = {
                field_name: existing[field_name]
                for field_name in CONTEXT_FIELDS
            }

        merged.update(changes)

        cur.execute(
            """
            INSERT INTO asset_context (
                asset_id,
                tenant_code,
                environment,
                business_service,
                business_unit,
                owner,
                technical_owner,
                criticality,
                data_classification,
                internet_exposure,
                network_zone,
                confidentiality_requirement,
                integrity_requirement,
                availability_requirement,
                context_source
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
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            ON CONFLICT (asset_id)
            DO UPDATE SET
                environment = EXCLUDED.environment,
                business_service = EXCLUDED.business_service,
                business_unit = EXCLUDED.business_unit,
                owner = EXCLUDED.owner,
                technical_owner = EXCLUDED.technical_owner,
                criticality = EXCLUDED.criticality,
                data_classification = EXCLUDED.data_classification,
                internet_exposure = EXCLUDED.internet_exposure,
                network_zone = EXCLUDED.network_zone,
                confidentiality_requirement =
                    EXCLUDED.confidentiality_requirement,
                integrity_requirement =
                    EXCLUDED.integrity_requirement,
                availability_requirement =
                    EXCLUDED.availability_requirement,
                context_source = EXCLUDED.context_source,
                updated_at = now()
            """,
            (
                asset_id,
                tenant_code,
                merged["environment"],
                merged["business_service"],
                merged["business_unit"],
                merged["owner"],
                merged["technical_owner"],
                merged["criticality"],
                merged["data_classification"],
                merged["internet_exposure"],
                merged["network_zone"],
                merged[
                    "confidentiality_requirement"
                ],
                merged[
                    "integrity_requirement"
                ],
                merged[
                    "availability_requirement"
                ],
                context_source,
            ),
        )

        return _get_asset_context(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )


def clear_asset_context(
    conn,
    *,
    tenant_code,
    asset_id,
):
    """
    Remove curated context without deleting the canonical asset.

    This function does not commit or roll back the caller's transaction.
    """

    tenant_code = _normalise_required_text(
        tenant_code,
        field_name="tenant_code",
    )

    with conn.cursor() as cur:
        _assert_asset_exists(
            cur,
            tenant_code=tenant_code,
            asset_id=asset_id,
        )

        cur.execute(
            """
            DELETE FROM asset_context
            WHERE asset_id = %s
              AND tenant_code = %s
            """,
            (
                asset_id,
                tenant_code,
            ),
        )
