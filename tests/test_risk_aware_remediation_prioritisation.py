#!/usr/bin/env python3

"""Regression tests for risk-aware remediation prioritisation."""

import os

import psycopg2


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


TENANT = "RISK-PRIORITISATION-TEST"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM unified_security_findings
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )


def create_finding(
    conn,
    *,
    finding_key,
    detected_at,
):
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
                '192.0.2.210',
                'wazuh_vulnerability',
                'vulnerability',
                'package_vulnerability',
                %s,
                'Risk prioritisation test',
                'OPEN',
                %s,
                %s,
                'HIGH',
                8.0,
                '{}'::jsonb
            )
            RETURNING finding_id
            """,
            (
                TENANT,
                finding_key,
                detected_at,
                detected_at,
            ),
        )

        return cur.fetchone()[0]


def create_assessment(
    conn,
    *,
    finding_id,
    status,
    score=None,
    level=None,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO finding_risk_assessments (
                finding_id,
                tenant_code,
                assessment_status,
                base_severity_score,
                base_severity_level,
                contextual_risk_score,
                contextual_risk_level,
                assessment_factors,
                assessment_model
            )
            VALUES (
                %s,
                %s,
                %s,
                CASE
                    WHEN %s = 'UNSCORABLE'
                    THEN NULL
                    ELSE 8.0
                END,
                CASE
                    WHEN %s = 'UNSCORABLE'
                    THEN NULL
                    ELSE 'HIGH'
                END,
                %s,
                %s,
                '{}'::jsonb,
                'CONTEXTUAL_RISK_V1'
            )
            """,
            (
                finding_id,
                TENANT,
                status,
                status,
                status,
                score,
                level,
            ),
        )


def fetch_prioritised_ids(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                finding_id
            FROM prioritised_remediation_queue
            WHERE tenant_code = %s
            ORDER BY
                has_contextual_risk DESC,
                contextual_risk_score DESC NULLS LAST,
                detected_at ASC,
                finding_id ASC
            """,
            (TENANT,),
        )

        return [row[0] for row in cur.fetchall()]


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

            high_id = create_finding(
                conn,
                finding_key="risk-priority-high",
                detected_at="2026-09-09 09:04:00+00",
            )

            partial_id = create_finding(
                conn,
                finding_key="risk-priority-partial",
                detected_at="2026-09-09 09:03:00+00",
            )

            equal_older_id = create_finding(
                conn,
                finding_key="risk-priority-equal-older",
                detected_at="2026-09-09 09:01:00+00",
            )

            equal_newer_id = create_finding(
                conn,
                finding_key="risk-priority-equal-newer",
                detected_at="2026-09-09 09:02:00+00",
            )

            unscorable_id = create_finding(
                conn,
                finding_key="risk-priority-unscorable",
                detected_at="2026-09-09 08:00:00+00",
            )

            no_assessment_id = create_finding(
                conn,
                finding_key="risk-priority-no-assessment",
                detected_at="2026-09-09 08:01:00+00",
            )

            create_assessment(
                conn,
                finding_id=high_id,
                status="ASSESSED",
                score=9.1,
                level="CRITICAL",
            )

            create_assessment(
                conn,
                finding_id=partial_id,
                status="PARTIAL",
                score=8.0,
                level="HIGH",
            )

            create_assessment(
                conn,
                finding_id=equal_older_id,
                status="ASSESSED",
                score=7.0,
                level="HIGH",
            )

            create_assessment(
                conn,
                finding_id=equal_newer_id,
                status="ASSESSED",
                score=7.0,
                level="HIGH",
            )

            create_assessment(
                conn,
                finding_id=unscorable_id,
                status="UNSCORABLE",
            )

            ordered_ids = fetch_prioritised_ids(conn)

            expected = [
                high_id,
                partial_id,
                equal_older_id,
                equal_newer_id,
                unscorable_id,
                no_assessment_id,
            ]

            assert ordered_ids == expected, (
                "Unexpected remediation priority order: "
                f"{ordered_ids}; expected {expected}"
            )

            print(
                "PASS: contextual risk determines remediation queue ordering"
            )

            #
            # PARTIAL is a scored assessment and must not be demoted merely
            # because its context is incomplete.
            #
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        assessment_status,
                        contextual_risk_score,
                        has_contextual_risk
                    FROM prioritised_remediation_queue
                    WHERE finding_id = %s
                    """,
                    (partial_id,),
                )

                row = cur.fetchone()

            assert row is not None
            assert row[0] == "PARTIAL"
            assert float(row[1]) == 8.0
            assert row[2] is True

            print(
                "PASS: PARTIAL scored assessments remain prioritised"
            )

            #
            # UNSCORABLE findings remain visible but carry no contextual
            # score and are not treated as contextually prioritised.
            #
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        assessment_status,
                        contextual_risk_score,
                        has_contextual_risk
                    FROM prioritised_remediation_queue
                    WHERE finding_id = %s
                    """,
                    (unscorable_id,),
                )

                row = cur.fetchone()

            assert row is not None
            assert row[0] == "UNSCORABLE"
            assert row[1] is None
            assert row[2] is False

            print(
                "PASS: UNSCORABLE findings remain visible without "
                "fabricated contextual risk"
            )

            #
            # A finding without a risk assessment must also remain visible.
            #
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        assessment_status,
                        contextual_risk_score,
                        has_contextual_risk
                    FROM prioritised_remediation_queue
                    WHERE finding_id = %s
                    """,
                    (no_assessment_id,),
                )

                row = cur.fetchone()

            assert row is not None
            assert row[0] is None
            assert row[1] is None
            assert row[2] is False

            print(
                "PASS: findings without risk assessments remain visible"
            )

        with conn:
            clean_database(conn)

    finally:
        conn.close()

    print(
        "PASS: risk-aware remediation prioritisation regression tests"
    )


if __name__ == "__main__":
    main()
