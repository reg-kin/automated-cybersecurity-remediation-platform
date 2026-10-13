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
