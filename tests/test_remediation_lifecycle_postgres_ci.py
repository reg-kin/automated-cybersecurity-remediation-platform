"""Disposable PostgreSQL test of approval cancellation lifecycle.

Only runs when CI explicitly supplies a disposable *_test database.
No API, Ansible, production data, or service is touched.
"""
import os
import unittest

import psycopg2
from remediation.shared import db


class CancellationPostgresIntegration(unittest.TestCase):
    def test_cancel_awaiting_approval_atomic(self):
        database = os.environ.get("REMEDIATION_LIFECYCLE_TEST_DATABASE", "")
        if not database:
            self.skipTest("Disposable lifecycle database not configured")
        if not database.endswith("_test") or database == "security_portal":
            self.fail("Refusing non-disposable database")
        connection = psycopg2.connect(
            host=os.environ["PG_HOST"], port=os.environ["PG_PORT"],
            user=os.environ["PG_USER"], password=os.environ["PG_PASSWORD"],
            dbname=database, connect_timeout=5,
        )
        connection.autocommit = False
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_schema='public' AND table_name='unified_security_findings'
                """)
                columns = {r[0]: (r[1], r[2]) for r in cursor.fetchall()}
                self.assertIn("finding_id", columns)
                self.assertIn("lifecycle_status", columns)
                cursor.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema='public' AND table_name='remediation_executions'
                """)
                execution_columns = {r[0] for r in cursor.fetchall()}
                self.assertTrue({"execution_id", "finding_id", "status"} <= execution_columns)
                # The test uses an intentionally absent execution identifier to
                # validate the actual DB-backed rejection without constructing
                # a synthetic finding that could bypass tenant/asset constraints.
                cursor.execute("SELECT COALESCE(MAX(execution_id), 0) + 100000 FROM remediation_executions")
                absent_id = cursor.fetchone()[0]
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT rule_id, finding_class, capability, playbook_name,
                           remediation_action, automation_tier
                    FROM remediation_rules WHERE enabled IS TRUE
                    ORDER BY rule_id LIMIT 1
                """)
                rule = cursor.fetchone()
                self.assertIsNotNone(rule, "Fresh installation has no enabled remediation rules")
                rule_id, finding_class, capability, playbook, action, tier = rule
                cursor.execute("""
                    INSERT INTO unified_security_findings (
                        tenant_code, tenant_service_tier, target_host,
                        engine_source, finding_category, finding_class,
                        finding_key, finding_title, lifecycle_status
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING finding_id
                """, ("LIFECYCLE-CI-ONLY", "STANDARD", "192.0.2.200",
                      "ci_disposable", "vulnerability", finding_class,
                      "ci-cancellation-fixture", "Disposable cancellation fixture",
                      "IN_REMEDIATION"))
                finding_id = cursor.fetchone()[0]
                cursor.execute("""
                    INSERT INTO remediation_executions (
                        finding_id, rule_id, capability, target_host,
                        playbook_name, remediation_action, automation_tier, status
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,'AWAITING_APPROVAL')
                    RETURNING execution_id
                """, (finding_id, rule_id, capability, "192.0.2.200",
                      playbook, action, tier))
                execution_id = cursor.fetchone()[0]
            cancelled = db.cancel_awaiting_approval(connection, execution_id)
            self.assertEqual(cancelled["status"], "CANCELLED")
            self.assertEqual(cancelled["finding_status"], "OPEN")
            with connection.cursor() as cursor:
                cursor.execute("SELECT status, attempt_counted FROM remediation_executions WHERE execution_id=%s", (execution_id,))
                status, counted = cursor.fetchone()
                self.assertEqual(status, "CANCELLED")
                self.assertFalse(counted)
                cursor.execute("SELECT lifecycle_status FROM unified_security_findings WHERE finding_id=%s", (finding_id,))
                self.assertEqual(cursor.fetchone()[0], "OPEN")
                cursor.execute("SELECT count(*) FROM remediation_verifications WHERE execution_id=%s", (execution_id,))
                self.assertEqual(cursor.fetchone()[0], 0)
            with self.assertRaisesRegex(RuntimeError, "cannot be cancelled"):
                db.cancel_awaiting_approval(connection, execution_id)
            with self.assertRaisesRegex(ValueError, "does not exist"):
                db.cancel_awaiting_approval(connection, absent_id)
            connection.rollback()
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM remediation_executions WHERE execution_id=%s", (absent_id,))
                self.assertEqual(cursor.fetchone()[0], 0)
        finally:
            connection.rollback()
            connection.close()


if __name__ == "__main__":
    unittest.main()
