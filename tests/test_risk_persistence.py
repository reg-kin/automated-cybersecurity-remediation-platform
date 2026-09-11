#!/usr/bin/env python3

"""Regression tests for deterministic risk-assessment persistence."""

import os
import sys
from pathlib import Path

import psycopg2


REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from risk_management.persistence import upsert_risk_assessment

PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.getenv("PG_USER", "telemetry_admin"),
    "password": os.getenv("PG_PASSWORD", ""),
}

TENANT = "RISK-PERSISTENCE-TEST"


def create_finding(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO unified_security_findings (
                tenant_code,
                tenant_service_tier,
                target_host,
                engine_source,
                finding_category,
                finding_class,
                finding_key,
                finding_title,
                lifecycle_status,
                detected_at,
                last_seen_at,
                severity_level,
                severity_score,
                engine_metadata
            )
            VALUES (
                %s,
                'STANDARD',
                '192.0.2.100',
                'wazuh_sca',
                'compliance_drift',
                'access_control_configuration',
                'risk-persistence-test',
                'Risk persistence test',
                'OPEN',
                now(),
                now(),
                'HIGH',
                8.0,
                '{}'::jsonb
            )
            RETURNING finding_id
            """,
            (TENANT,),
        )

        return cur.fetchone()[0]


def assessment(score, level):
    return {
        "asset_id": None,
        "assessment_status": "PARTIAL",
        "base_severity_score": 8.0,
        "base_severity_level": "HIGH",
        "contextual_risk_score": score,
        "contextual_risk_level": level,
        "assessment_factors": {
            "technical_severity_source": "severity_score",
            "effective_technical_severity": 8.0,
        },
        "context_snapshot": None,
        "assessment_model": "CONTEXTUAL_RISK_V1",
    }


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM unified_security_findings
                    WHERE tenant_code = %s
                    """,
                    (TENANT,),
                )

            finding_id = create_finding(conn)

            upsert_risk_assessment(
                conn,
                finding_id=finding_id,
                tenant_code=TENANT,
                assessment=assessment(4.8, "MEDIUM"),
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        assessment_status,
                        base_severity_score,
                        contextual_risk_score,
                        contextual_risk_level,
                        assessment_model
                    FROM finding_risk_assessments
                    WHERE finding_id = %s
                    """,
                    (finding_id,),
                )

                row = cur.fetchone()

            assert row is not None
            assert row[0] == "PARTIAL"
            assert float(row[1]) == 8.0
            assert float(row[2]) == 4.8
            assert row[3] == "MEDIUM"
            assert row[4] == "CONTEXTUAL_RISK_V1"

            print(
                "PASS: current risk assessment is persisted"
            )

            upsert_risk_assessment(
                conn,
                finding_id=finding_id,
                tenant_code=TENANT,
                assessment=assessment(7.2, "HIGH"),
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*),
                        MAX(contextual_risk_score),
                        MAX(contextual_risk_level)
                    FROM finding_risk_assessments
                    WHERE finding_id = %s
                    """,
                    (finding_id,),
                )

                row = cur.fetchone()

            assert row[0] == 1
            assert float(row[1]) == 7.2
            assert row[2] == "HIGH"

            print(
                "PASS: re-assessment updates one current risk row"
            )

        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM unified_security_findings
                    WHERE tenant_code = %s
                    """,
                    (TENANT,),
                )

    finally:
        conn.close()

    print(
        "PASS: deterministic risk persistence regression tests"
    )


if __name__ == "__main__":
    main()
