"""Reassessment of finding risk after curated asset context changes."""

from typing import Any, Dict, Tuple

from asset_management.context import (
    clear_asset_context,
    get_asset_context,
    set_asset_context,
)
from risk_management.contextualiser import contextualise_risk
from risk_management.persistence import upsert_risk_assessment


def reassess_asset_findings(
    conn,
    *,
    tenant_code: str,
    asset_id: int,
) -> int:
    """
    Recalculate current risk assessments for findings bound to an asset.

    The current curated asset context is applied to every tenant-scoped
    finding associated with the asset.

    Transaction ownership remains with the caller.
    """

    asset_context = get_asset_context(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                finding_id,
                tenant_service_tier,
                severity_score,
                severity_level
            FROM unified_security_findings
            WHERE tenant_code = %s
              AND asset_id = %s
            ORDER BY finding_id
            """,
            (
                tenant_code,
                asset_id,
            ),
        )

        findings = cur.fetchall()

    for (
        finding_id,
        tenant_service_tier,
        severity_score,
        severity_level,
    ) in findings:
        assessment = contextualise_risk(
            severity_score=severity_score,
            severity_level=severity_level,
            asset_id=asset_id,
            asset_context=asset_context,
        )

        assessment["assessment_factors"][
            "tenant_service_tier"
        ] = tenant_service_tier

        upsert_risk_assessment(
            conn,
            finding_id=finding_id,
            tenant_code=tenant_code,
            assessment=assessment,
        )

    return len(findings)


def set_asset_context_and_reassess(
    conn,
    *,
    tenant_code: str,
    asset_id: int,
    context: Dict[str, Any],
    context_source: str = "MANUAL",
) -> Tuple[Dict[str, Any], int]:
    """
    Set curated asset context and reassess its existing findings.

    Both operations execute within the caller's transaction.

    Transaction ownership remains with the caller.
    """

    updated_context = set_asset_context(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
        context=context,
        context_source=context_source,
    )

    reassessed_count = reassess_asset_findings(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
    )

    return updated_context, reassessed_count


def clear_asset_context_and_reassess(
    conn,
    *,
    tenant_code: str,
    asset_id: int,
) -> int:
    """
    Clear curated asset context and reassess its existing findings.

    Both operations execute within the caller's transaction.

    Transaction ownership remains with the caller.
    """

    clear_asset_context(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
    )

    return reassess_asset_findings(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
    )
