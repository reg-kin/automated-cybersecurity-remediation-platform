"""PostgreSQL integration tests for scan-policy administration.

Requires:
    SCAN_POLICY_TEST_DATABASE
    PG_HOST
    PG_PORT
    PG_USER
    PG_PASSWORD

Only disposable databases with names ending in _test are permitted.
Every test transaction is rolled back.
"""

import os
import unittest

import psycopg2

from scan_policy_administration import service


class ScanPolicyPostgresIntegrationTests(unittest.TestCase):

    def test_administrative_lifecycle(self):
        database = os.environ.get("SCAN_POLICY_TEST_DATABASE", "")

        if not database:
            self.skipTest("SCAN_POLICY_TEST_DATABASE is not configured")

        if not database.endswith("_test"):
            self.fail("Integration tests require a disposable *_test database")

        connection = psycopg2.connect(
            host=os.environ["PG_HOST"],
            port=os.environ["PG_PORT"],
            user=os.environ["PG_USER"],
            password=os.environ["PG_PASSWORD"],
            dbname=database,
            connect_timeout=5,
        )

        connection.autocommit = False

        tenant = "SCAN-POLICY-INTEGRATION-A"
        other_tenant = "SCAN-POLICY-INTEGRATION-B"

        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database()")
                self.assertEqual(cursor.fetchone()[0], database)

                cursor.execute(
                    """
                    INSERT INTO assets (
                        tenant_code,
                        asset_type,
                        canonical_name
                    )
                    VALUES (%s, %s, %s)
                    RETURNING asset_id
                    """,
                    (
                        tenant,
                        "HOST",
                        "scan-policy-integration-host",
                    ),
                )
                asset_id = cursor.fetchone()[0]

            policy = service.create_scan_policy(
                connection,
                tenant_code=tenant,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                service_tier="STANDARD",
                profile_name="postgres-integration",
                scanner_parameters={},
                schedule_type="MANUAL",
                schedule_expression=None,
                schedule_timezone="UTC",
                is_enabled=False,
                performed_by="integration-test",
                reason="PostgreSQL lifecycle regression test",
            )

            policy_id = policy["scan_policy_id"]
            self.assertFalse(policy["is_enabled"])

            updated = service.update_scan_policy_configuration(
                connection,
                scan_policy_id=policy_id,
                tenant_code=tenant,
                performed_by="integration-test",
                reason="Test configuration update",
                service_tier="GOLD",
            )
            self.assertEqual(updated["service_tier"], "GOLD")

            enabled = service.enable_scan_policy(
                connection,
                scan_policy_id=policy_id,
                tenant_code=tenant,
                performed_by="integration-test",
                reason="Test enable transition",
            )
            self.assertTrue(enabled["is_enabled"])
            self.assertIsNone(enabled["next_run_at"])

            disabled = service.disable_scan_policy(
                connection,
                scan_policy_id=policy_id,
                tenant_code=tenant,
                performed_by="integration-test",
                reason="Test disable transition",
            )
            self.assertFalse(disabled["is_enabled"])
            self.assertIsNone(disabled["next_run_at"])

            with self.assertRaises(service.ScanPolicyNotFoundError):
                service.get_scan_policy(
                    connection,
                    scan_policy_id=policy_id,
                    tenant_code=other_tenant,
                )

            history = service.get_scan_policy_history(
                connection,
                scan_policy_id=policy_id,
                tenant_code=tenant,
            )

            self.assertEqual(len(history), 4)
            self.assertEqual(
                {record["action"] for record in history},
                {
                    "CREATE",
                    "UPDATE_CONFIGURATION",
                    "ENABLE",
                    "DISABLE",
                },
            )

            with self.assertRaises(service.ScanPolicyNotFoundError):
                service.get_scan_policy_history(
                    connection,
                    scan_policy_id=policy_id,
                    tenant_code=other_tenant,
                )

        finally:
            connection.rollback()
            connection.close()


if __name__ == "__main__":
    unittest.main()
