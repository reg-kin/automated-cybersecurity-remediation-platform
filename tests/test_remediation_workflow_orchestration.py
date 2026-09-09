#!/usr/bin/env python3

"""Regression tests for remediation workflow orchestration V1."""

import os
from pathlib import Path
import sys

import psycopg2


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


from remediation import dispatcher
from remediation.shared import db
from remediation.shared.workflow_payload import (
    build_controller_payload,
)


PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "regis_release_smoke_test",
    ),
    "user": os.getenv("PG_USER", "telemetry_admin"),
    "password": os.getenv("PG_PASSWORD", ""),
}


TENANT = "WORKFLOW-ORCHESTRATION-TEST"


def clean_database(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM remediation_executions
            WHERE finding_id IN (
                SELECT finding_id
                FROM unified_security_findings
                WHERE tenant_code = %s
            )
            """,
            (TENANT,),
        )

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
    package_name,
    fixed_version,
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
                '192.0.2.220',
                'wazuh_vulnerability',
                'vulnerability',
                'package_vulnerability',
                %s,
                'Workflow orchestration test',
                'OPEN',
                %s,
                %s,
                'HIGH',
                8.0,
                jsonb_build_object(
                    'package_name',
                    %s,
                    'fixed_version',
                    %s
                )
            )
            RETURNING finding_id
            """,
            (
                TENANT,
                finding_key,
                detected_at,
                detected_at,
                package_name,
                fixed_version,
            ),
        )

        return cur.fetchone()[0]


def create_assessment(
    conn,
    *,
    finding_id,
    score,
    level,
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
                'ASSESSED',
                8.0,
                'HIGH',
                %s,
                %s,
                '{}'::jsonb,
                'CONTEXTUAL_RISK_V1'
            )
            """,
            (
                finding_id,
                TENANT,
                score,
                level,
            ),
        )


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

            high_id = create_finding(
                conn,
                finding_key="workflow-priority-high",
                detected_at="2026-09-09 10:02:00+00",
                package_name="openssl",
                fixed_version="3.0.13-test",
            )

            lower_id = create_finding(
                conn,
                finding_key="workflow-priority-lower",
                detected_at="2026-09-09 10:01:00+00",
                package_name="libssl3",
                fixed_version="3.0.13-test",
            )

            create_assessment(
                conn,
                finding_id=high_id,
                score=9.2,
                level="CRITICAL",
            )

            create_assessment(
                conn,
                finding_id=lower_id,
                score=7.4,
                level="HIGH",
            )

        #
        # Highest contextual risk must be selected first.
        #
        with conn:
            selected = dispatcher.select_next(conn)

        assert selected is not None
        assert selected["finding_id"] == high_id
        assert selected["has_contextual_risk"] is True
        assert float(
            selected["contextual_risk_score"]
        ) == 9.2

        print(
            "PASS: orchestration selects the highest-priority "
            "eligible remediation"
        )

        #
        # Queue row must already contain the deterministic route.
        #
        assert selected["rule_id"] is not None
        assert selected["capability"] == "os_patching"
        assert selected["playbook_name"] == "os_patching.yml"
        assert selected["remediation_action"] == "patch_package"
        assert selected["automation_tier"] == "TIER_1"
        assert selected["approval_required"] is False

        print(
            "PASS: selected queue row contains authoritative "
            "remediation route"
        )

        #
        # The selected queue row must build the existing controller
        # request without another routing decision.
        #
        payload = build_controller_payload(selected)

        assert payload["finding_id"] == high_id
        assert payload["rule_id"] == selected["rule_id"]

        assert payload["execution_parameters"] == {
            "package_name": "openssl",
            "fixed_version": "3.0.13-test",
        }

        print(
            "PASS: selected queue row builds a deterministic "
            "controller payload"
        )

        #
        # The existing controller/database boundary atomically
        # claims the finding and creates its first active execution.
        #
        create_payload = dict(payload)
        create_payload["initial_status"] = "QUEUED"

        with conn:
            db.ensure_claimed(
                conn,
                high_id,
            )

            first_execution_id = db.create_execution(
                conn,
                create_payload,
            )

        assert first_execution_id is not None

        print(
            "PASS: orchestration delivery creates the first "
            "active remediation execution"
        )

        #
        # At-least-once delivery may submit the same finding again.
        # ensure_claimed() deliberately permits an already
        # IN_REMEDIATION finding to continue to create_execution().
        # The partial UNIQUE index must then reject the second
        # active execution and the helper must expose the specific
        # ActiveRemediationExistsError.
        #
        try:
            with conn:
                db.ensure_claimed(
                    conn,
                    high_id,
                )

                db.create_execution(
                    conn,
                    create_payload,
                )
        except db.ActiveRemediationExistsError as exc:
            assert exc.finding_id == high_id
        else:
            raise AssertionError(
                "Expected ActiveRemediationExistsError for "
                "duplicate active execution"
            )

        #
        # The failed duplicate transaction must leave exactly one
        # active execution for the finding.
        #
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*),
                        MIN(execution_id),
                        MIN(status)
                    FROM remediation_executions
                    WHERE finding_id = %s
                      AND status IN (
                          'QUEUED',
                          'AWAITING_APPROVAL',
                          'RUNNING',
                          'STAGE1_PASSED',
                          'VERIFYING'
                      )
                    """,
                    (high_id,),
                )

                (
                    active_count,
                    persisted_execution_id,
                    persisted_status,
                ) = cur.fetchone()

        assert active_count == 1
        assert persisted_execution_id == first_execution_id
        assert persisted_status == "QUEUED"

        print(
            "PASS: duplicate delivery is rejected with exactly "
            "one active execution preserved"
        )

        #
        # Claiming OPEN -> IN_REMEDIATION removes the finding from
        # both open_remediation_queue and the derived prioritised
        # remediation queue.
        #
        with conn:
            next_selected = dispatcher.select_next(conn)

        assert next_selected is not None
        assert next_selected["finding_id"] == lower_id

        print(
            "PASS: claimed finding leaves the prioritised "
            "remediation queue"
        )

        print(
            "PASS: next eligible finding becomes the next "
            "orchestration candidate"
        )

    finally:
        try:
            with conn:
                clean_database(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
