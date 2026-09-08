"""Persistence for current deterministic finding risk assessments."""

from typing import Any, Dict

from psycopg2.extras import Json


def upsert_risk_assessment(
    conn,
    *,
    finding_id: int,
    tenant_code: str,
    assessment: Dict[str, Any],
) -> None:
    """Persist the current deterministic risk assessment for a finding.

    Transaction ownership remains with the caller.
    """

    if not isinstance(assessment, dict):
        raise TypeError("assessment must be a dictionary")

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO finding_risk_assessments (
                finding_id,
                tenant_code,
                asset_id,
                assessment_status,
                base_severity_score,
                base_severity_level,
                contextual_risk_score,
                contextual_risk_level,
                assessment_factors,
                context_snapshot,
                assessment_model
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            ON CONFLICT (finding_id)
            DO UPDATE SET
                tenant_code = EXCLUDED.tenant_code,
                asset_id = EXCLUDED.asset_id,
                assessment_status = EXCLUDED.assessment_status,
                base_severity_score = EXCLUDED.base_severity_score,
                base_severity_level = EXCLUDED.base_severity_level,
                contextual_risk_score = EXCLUDED.contextual_risk_score,
                contextual_risk_level = EXCLUDED.contextual_risk_level,
                assessment_factors = EXCLUDED.assessment_factors,
                context_snapshot = EXCLUDED.context_snapshot,
                assessment_model = EXCLUDED.assessment_model,
                assessed_at = now(),
                updated_at = now()
            """,
            (
                finding_id,
                tenant_code,
                assessment.get("asset_id"),
                assessment["assessment_status"],
                assessment.get("base_severity_score"),
                assessment.get("base_severity_level"),
                assessment.get("contextual_risk_score"),
                assessment.get("contextual_risk_level"),
                Json(assessment["assessment_factors"]),
                (
                    Json(assessment["context_snapshot"])
                    if assessment.get("context_snapshot") is not None
                    else None
                ),
                assessment["assessment_model"],
            ),
        )
