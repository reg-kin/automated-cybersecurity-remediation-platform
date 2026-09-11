#!/usr/bin/env python3

"""Regression tests for risk reassessment after asset-context changes."""

import os
import sys
from pathlib import Path

import psycopg2


REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from risk_management.reassessment import (
    clear_asset_context_and_reassess,
    reassess_asset_findings,
    set_asset_context_and_reassess,
)


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

TENANT = "RISK-REASSESSMENT-TEST"
OTHER_TENANT = "RISK-REASSESSMENT-OTHER"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM unified_security_findings
            WHERE tenant_code IN (%s, %s)
            """,
            (
                TENANT,
                OTHER_TENANT,
            ),
        )

        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code IN (%s, %s)
            """,
            (
                TENANT,
                OTHER_TENANT,
            ),
        )


def create_asset(
    conn,
    *,
    tenant_code,
    canonical_name,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (
                tenant_code,
                asset_type,
                canonical_name,
                inventory_state,
                lifecycle_status,
                management_authorised_at,
                management_authorised_by,
                management_authorisation_reason
            )
            VALUES (
                %s,
                'HOST',
                %s,
                'MANAGED',
                'ACTIVE',
                now(),
                'risk_reassessment_test',
                'Authorised for risk reassessment regression testing'
            )
            RETURNING asset_id
            """,
            (
                tenant_code,
                canonical_name,
            ),
        )

        return cur.fetchone()[0]


def create_finding(
    conn,
    *,
    tenant_code,
    asset_id,
    finding_key,
    severity_level,
    severity_score,
    service_tier="STANDARD",
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
                engine_metadata,
                asset_id
            )
            VALUES (
                %s,
                %s,
                '192.0.2.200',
                'wazuh_vulnerability',
                'vulnerability',
                'package_vulnerability',
                %s,
                'Risk reassessment test',
                'OPEN',
                now(),
                now(),
                %s,
                %s,
                '{}'::jsonb,
                %s
            )
            RETURNING finding_id
            """,
            (
                tenant_code,
                service_tier,
                finding_key,
                severity_level,
                severity_score,
                asset_id,
            ),
        )

        return cur.fetchone()[0]


def fetch_assessment(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                asset_id,
                assessment_status,
                base_severity_score,
                base_severity_level,
                contextual_risk_score,
                contextual_risk_level,
                assessment_factors,
                context_snapshot,
                assessment_model
            FROM finding_risk_assessments
            WHERE finding_id = %s
            """,
            (finding_id,),
        )

        return cur.fetchone()


def fetch_assessment_count(conn, finding_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM finding_risk_assessments
            WHERE finding_id = %s
            """,
            (finding_id,),
        )

        return cur.fetchone()[0]


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

        #
        # Create one canonical asset and two existing findings:
        # one technically scorable and one unscorable.
        #
        with conn:
            asset_id = create_asset(
                conn,
                tenant_code=TENANT,
                canonical_name="risk-reassessment-host",
            )

            vulnerability_id = create_finding(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
                finding_key="risk-reassessment-vulnerability",
                severity_level="HIGH",
                severity_score=8.1,
                service_tier="STANDARD",
            )

            unscorable_id = create_finding(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
                finding_key="risk-reassessment-unscorable",
                severity_level=None,
                severity_score=None,
                service_tier="GOLD",
            )

            count = reassess_asset_findings(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
            )

            assert count == 2

            vulnerability = fetch_assessment(
                conn,
                vulnerability_id,
            )

            assert vulnerability is not None
            assert vulnerability[0] == asset_id
            assert vulnerability[1] == "PARTIAL"
            assert float(vulnerability[2]) == 8.1
            assert vulnerability[3] == "HIGH"
            assert float(vulnerability[4]) == 4.86
            assert vulnerability[5] == "MEDIUM"
            assert vulnerability[6][
                "tenant_service_tier"
            ] == "STANDARD"
            assert vulnerability[7] is None
            assert vulnerability[8] == "CONTEXTUAL_RISK_V1"

            unscorable = fetch_assessment(
                conn,
                unscorable_id,
            )

            assert unscorable is not None
            assert unscorable[0] == asset_id
            assert unscorable[1] == "UNSCORABLE"
            assert unscorable[2] is None
            assert unscorable[3] is None
            assert unscorable[4] is None
            assert unscorable[5] is None
            assert unscorable[6][
                "tenant_service_tier"
            ] == "GOLD"
            assert unscorable[7] is None

            print(
                "PASS: findings start with risk based on "
                "technical evidence only"
            )

        #
        # Setting maximum curated context must immediately reassess
        # existing findings without scanner re-ingestion.
        #
        with conn:
            context, count = set_asset_context_and_reassess(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
                context={
                    "environment": "PRODUCTION",
                    "criticality": "CRITICAL",
                    "data_classification": "RESTRICTED",
                    "internet_exposure": "INTERNET_FACING",
                    "confidentiality_requirement": "CRITICAL",
                    "integrity_requirement": "CRITICAL",
                    "availability_requirement": "CRITICAL",
                },
                context_source="REASSESSMENT_TEST",
            )

            assert count == 2
            assert context["environment"] == "PRODUCTION"
            assert context["criticality"] == "CRITICAL"

            vulnerability = fetch_assessment(
                conn,
                vulnerability_id,
            )

            assert vulnerability[1] == "ASSESSED"
            assert float(vulnerability[4]) == 8.86
            assert vulnerability[5] == "HIGH"
            assert vulnerability[7] is not None
            assert vulnerability[7][
                "environment"
            ] == "PRODUCTION"
            assert vulnerability[7][
                "criticality"
            ] == "CRITICAL"
            assert vulnerability[7][
                "context_source"
            ] == "REASSESSMENT_TEST"

            unscorable = fetch_assessment(
                conn,
                unscorable_id,
            )

            assert unscorable[1] == "UNSCORABLE"
            assert unscorable[4] is None
            assert unscorable[5] is None
            assert unscorable[7] is not None
            assert unscorable[7][
                "criticality"
            ] == "CRITICAL"

            assert (
                fetch_assessment_count(
                    conn,
                    vulnerability_id,
                )
                == 1
            )

            assert (
                fetch_assessment_count(
                    conn,
                    unscorable_id,
                )
                == 1
            )

            print(
                "PASS: setting curated context automatically "
                "reassesses existing findings"
            )

        #
        # A partial context update must recalculate current risk rather
        # than create another assessment row.
        #
        with conn:
            context, count = set_asset_context_and_reassess(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
                context={
                    "environment": "DEVELOPMENT",
                    "criticality": "LOW",
                    "data_classification": "PUBLIC",
                    "internet_exposure": "INTERNAL",
                    "confidentiality_requirement": "LOW",
                    "integrity_requirement": "LOW",
                    "availability_requirement": "LOW",
                },
                context_source="REASSESSMENT_TEST_UPDATE",
            )

            assert count == 2
            assert context["environment"] == "DEVELOPMENT"
            assert context["criticality"] == "LOW"

            vulnerability = fetch_assessment(
                conn,
                vulnerability_id,
            )

            assert vulnerability[1] == "ASSESSED"
            assert float(vulnerability[4]) == 5.81
            assert vulnerability[5] == "MEDIUM"
            assert vulnerability[7][
                "environment"
            ] == "DEVELOPMENT"
            assert vulnerability[7][
                "criticality"
            ] == "LOW"

            assert (
                fetch_assessment_count(
                    conn,
                    vulnerability_id,
                )
                == 1
            )

            print(
                "PASS: context updates replace the current "
                "risk assessment"
            )

        #
        # Clearing context must remove organisational contribution while
        # retaining the asset binding and technical assessment.
        #
        with conn:
            count = clear_asset_context_and_reassess(
                conn,
                tenant_code=TENANT,
                asset_id=asset_id,
            )

            assert count == 2

            vulnerability = fetch_assessment(
                conn,
                vulnerability_id,
            )

            assert vulnerability[0] == asset_id
            assert vulnerability[1] == "PARTIAL"
            assert float(vulnerability[4]) == 4.86
            assert vulnerability[5] == "MEDIUM"
            assert vulnerability[7] is None

            unscorable = fetch_assessment(
                conn,
                unscorable_id,
            )

            assert unscorable[0] == asset_id
            assert unscorable[1] == "UNSCORABLE"
            assert unscorable[4] is None
            assert unscorable[5] is None
            assert unscorable[7] is None

            assert (
                fetch_assessment_count(
                    conn,
                    vulnerability_id,
                )
                == 1
            )

            assert (
                fetch_assessment_count(
                    conn,
                    unscorable_id,
                )
                == 1
            )

            print(
                "PASS: clearing context returns findings to "
                "technical-only risk"
            )

        #
        # Tenant scoping must prevent another tenant from operating on
        # this asset.
        #
        with conn:
            try:
                reassess_asset_findings(
                    conn,
                    tenant_code=OTHER_TENANT,
                    asset_id=asset_id,
                )
            except LookupError:
                pass
            else:
                raise AssertionError(
                    "Wrong tenant must not reassess another "
                    "tenant's asset"
                )

            print(
                "PASS: risk reassessment is tenant scoped"
            )

        #
        # An existing asset with no findings is a valid no-op.
        #
        with conn:
            empty_asset_id = create_asset(
                conn,
                tenant_code=TENANT,
                canonical_name="risk-reassessment-empty-host",
            )

            count = reassess_asset_findings(
                conn,
                tenant_code=TENANT,
                asset_id=empty_asset_id,
            )

            assert count == 0

            print(
                "PASS: asset without findings is a safe no-op"
            )

        #
        # The service must not commit the caller's transaction.
        #
        rollback_asset_id = None

        try:
            rollback_asset_id = create_asset(
                conn,
                tenant_code=TENANT,
                canonical_name="risk-reassessment-rollback-host",
            )

            set_asset_context_and_reassess(
                conn,
                tenant_code=TENANT,
                asset_id=rollback_asset_id,
                context={
                    "criticality": "CRITICAL",
                },
                context_source="ROLLBACK_TEST",
            )

            raise RuntimeError(
                "force caller rollback"
            )
        except RuntimeError as exc:
            assert str(exc) == "force caller rollback"
            conn.rollback()

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM assets
                WHERE asset_id = %s
                  AND tenant_code = %s
                """,
                (
                    rollback_asset_id,
                    TENANT,
                ),
            )

            assert cur.fetchone()[0] == 0

        print(
            "PASS: reassessment leaves transaction ownership "
            "with caller"
        )

        with conn:
            clean_database(conn)

    finally:
        conn.close()

    print(
        "PASS: asset-context risk reassessment regression tests"
    )


if __name__ == "__main__":
    main()
