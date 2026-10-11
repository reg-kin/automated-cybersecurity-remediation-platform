import os
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

import psycopg2

from remediation.controllers import base
from remediation.shared import db


TEST_DATABASE = "regis_manual_verification_test"
PASSWORD_FILE = Path("/tmp/regis_manual_verification_test_password")


class ManualVerificationControllerIntegrationTest(unittest.TestCase):

    def test_inconclusive_creates_pending_manual_review(self):
        password = PASSWORD_FILE.read_text().strip()

        conn = psycopg2.connect(
            host="127.0.0.1",
            port=5432,
            dbname=TEST_DATABASE,
            user="manual_verification_test_runner",
            password=password,
        )

        finding_id = None

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT finding_class
                    FROM remediation_rules
                    WHERE rule_id = 1
                    """
                )
                rule = cur.fetchone()
                self.assertIsNotNone(rule)

            finding_class = rule[0]
            finding_key = f"manual-controller-{uuid.uuid4().hex}"

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
                        lifecycle_status
                    )
                    VALUES (
                        'MANUAL-CONTROLLER-TEST',
                        'TIER_2',
                        'manual-test-host',
                        'openvas',
                        'vulnerability',
                        %s,
                        %s,
                        'Manual controller integration test',
                        'IN_REMEDIATION'
                    )
                    RETURNING finding_id
                    """,
                    (finding_class, finding_key),
                )
                finding_id = cur.fetchone()[0]

            payload = {
                "finding_id": finding_id,
                "rule_id": 1,
                "capability": "os_patching",
                "target_host": "manual-test-host",
                "scanner_target_host": "manual-test-host",
                "playbook_name": "test.yml",
                "remediation_action": "test",
                "automation_tier": "TIER_2",
                "engine_source": "openvas",
                "finding_class": finding_class,
                "finding_key": finding_key,
                "engine_metadata": {},
                "execution_parameters": {},
            }

            execution_id = db.create_execution(conn, payload)

            ansible_result = {
                "success": True,
                "verification": {"passed": True},
            }
            scanner_result = {
                "verification_status": "INCONCLUSIVE",
                "present": None,
                "verification_reason": "Scanner evidence insufficient",
            }

            controller = object.__new__(base.BaseController)

            with (
                patch.object(base.db, "connect", return_value=conn),
                patch.object(base, "run_ansible", return_value=ansible_result),
                patch.object(base, "run_stage2", return_value=scanner_result),
                patch.object(base, "SKIP_STAGE2", False),
            ):
                result = controller.execute_existing(
                    payload,
                    execution_id,
                )

            self.assertEqual(
                result["status"],
                "AWAITING_MANUAL_VERIFICATION",
            )
            self.assertFalse(result["success"])
            self.assertIsNotNone(
                result["manual_verification_review_id"]
            )

            conn = psycopg2.connect(
                host="127.0.0.1",
                port=5432,
                dbname=TEST_DATABASE,
                user="manual_verification_test_runner",
                password=password,
            )

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status
                    FROM remediation_executions
                    WHERE execution_id = %s
                    """,
                    (execution_id,),
                )
                self.assertEqual(
                    cur.fetchone()[0],
                    "AWAITING_MANUAL_VERIFICATION",
                )

                cur.execute(
                    """
                    SELECT lifecycle_status
                    FROM unified_security_findings
                    WHERE finding_id = %s
                    """,
                    (finding_id,),
                )
                self.assertEqual(
                    cur.fetchone()[0],
                    "IN_REMEDIATION",
                )

                cur.execute(
                    """
                    SELECT status
                    FROM remediation_verifications
                    WHERE execution_id = %s AND stage = 2
                    """,
                    (execution_id,),
                )
                self.assertEqual(cur.fetchone()[0], "INCONCLUSIVE")

            print("PASS: Controller created pending manual verification review")

        finally:
            if not conn.closed:
                conn.rollback()
                conn.close()

            if finding_id is not None:
                cleanup_conn = psycopg2.connect(
                    host="127.0.0.1",
                    port=5432,
                    dbname=TEST_DATABASE,
                    user="manual_verification_test_runner",
                    password=password,
                )
                try:
                    with cleanup_conn:
                        with cleanup_conn.cursor() as cur:
                            cur.execute(
                                """
                                DELETE FROM manual_verification_decisions
                                WHERE review_id IN (
                                    SELECT review_id
                                    FROM manual_verification_reviews
                                    WHERE finding_id = %s
                                )
                                """,
                                (finding_id,),
                            )
                            cur.execute(
                                "DELETE FROM manual_verification_reviews WHERE finding_id = %s",
                                (finding_id,),
                            )
                            cur.execute(
                                "DELETE FROM remediation_verifications WHERE finding_id = %s",
                                (finding_id,),
                            )
                            cur.execute(
                                "DELETE FROM remediation_executions WHERE finding_id = %s",
                                (finding_id,),
                            )
                            cur.execute(
                                "DELETE FROM unified_security_findings WHERE finding_id = %s",
                                (finding_id,),
                            )
                finally:
                    cleanup_conn.close()


if __name__ == "__main__":
    unittest.main()
