#!/usr/bin/env python3
"""Regression tests for tenant-scoped scan-policy administration."""

import unittest
from unittest.mock import MagicMock

from scan_policy_administration import service


class ScanPolicyTenantIsolationTests(unittest.TestCase):

    def setUp(self):
        self.conn = MagicMock()
        self.cursor = (
            self.conn.cursor.return_value
            .__enter__.return_value
        )
        self.cursor.fetchone.return_value = None
        self.cursor.fetchall.return_value = []

    def test_cross_tenant_operations(self):
        operations = [
            (
                service.get_scan_policy,
                {},
            ),
            (
                service.update_scan_policy_configuration,
                {
                    "performed_by": "test-admin",
                    "reason": "Integration test",
                    "service_tier": "GOLD",
                },
            ),
            (
                service.enable_scan_policy,
                {
                    "performed_by": "test-admin",
                    "reason": "Integration test",
                },
            ),
            (
                service.disable_scan_policy,
                {
                    "performed_by": "test-admin",
                    "reason": "Integration test",
                },
            ),
        ]

        for operation, additional_args in operations:
            with self.subTest(operation=operation.__name__):
                self.cursor.reset_mock()

                with self.assertRaises(
                    service.ScanPolicyNotFoundError
                ):
                    operation(
                        self.conn,
                        scan_policy_id=12345,
                        tenant_code="TENANT-B",
                        **additional_args,
                    )

                self.assertTrue(
                    any(
                        "tenant_code = %s" in call.args[0]
                        and "TENANT-B" in call.args[1]
                        for call in self.cursor.execute.call_args_list
                    ),
                    f"{operation.__name__} did not issue "
                    "a tenant-scoped query",
                )

    def test_cross_tenant_list_returns_no_policies(self):
        result = service.list_scan_policies(
            self.conn,
            tenant_code="TENANT-B",
        )

        self.assertEqual(result, [])
        self.assertTrue(
            any(
                "tenant_code = %s" in call.args[0]
                and "TENANT-B" in call.args[1]
                for call in self.cursor.execute.call_args_list
            )
        )


    def test_audit_history_tenant_isolation(self):
        self.cursor.fetchall.return_value = []
        self.cursor.fetchone.return_value = None

        with self.assertRaises(service.ScanPolicyNotFoundError):
            service.get_scan_policy_history(
                self.conn,
                scan_policy_id=12345,
                tenant_code="TENANT-B",
            )

        self.assertEqual(self.cursor.execute.call_count, 2)

        for call in self.cursor.execute.call_args_list:
            self.assertIn("tenant_code = %s", call.args[0])
            self.assertEqual(call.args[1], (12345, "TENANT-B"))

    def test_history_survives_deleted_policy(self):
        from datetime import datetime, timezone

        created_at = datetime(2026, 10, 13, tzinfo=timezone.utc)

        self.cursor.fetchall.return_value = [
            (
                101,
                12345,
                "TENANT-A",
                "CREATE",
                "test-admin",
                "Initial configuration",
                None,
                {"scanner_type": "nmap_nse"},
                created_at,
            )
        ]

        result = service.get_scan_policy_history(
            self.conn,
            scan_policy_id=12345,
            tenant_code="TENANT-A",
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["action"], "CREATE")
        self.assertEqual(result[0]["tenant_code"], "TENANT-A")
        self.assertEqual(result[0]["created_at"], created_at)

        self.assertEqual(self.cursor.execute.call_count, 1)
        self.assertIn(
            "FROM scan_policy_admin_audit",
            self.cursor.execute.call_args[0][0],
        )
        self.assertEqual(
            self.cursor.execute.call_args[0][1],
            (12345, "TENANT-A"),
        )


    def test_audit_record_creation(self):
        from datetime import datetime, timezone
        from psycopg2.extras import Json

        created_at = datetime(2026, 10, 13, tzinfo=timezone.utc)
        self.cursor.fetchone.return_value = (501, created_at)

        actions = (
            "CREATE",
            "UPDATE_CONFIGURATION",
            "ENABLE",
            "DISABLE",
        )

        for action in actions:
            with self.subTest(action=action):
                self.cursor.reset_mock()

                result = service._insert_audit(
                    self.conn,
                    scan_policy_id=12345,
                    tenant_code="TENANT-A",
                    action=action,
                    performed_by="test-admin",
                    reason="Regression test",
                    before_state=None,
                    after_state={"is_enabled": True},
                )

                self.assertEqual(result["audit_id"], 501)
                self.assertEqual(result["created_at"], created_at)

                sql, params = self.cursor.execute.call_args.args

                self.assertIn(
                    "INSERT INTO scan_policy_admin_audit",
                    sql,
                )
                self.assertEqual(params[0], 12345)
                self.assertEqual(params[1], "TENANT-A")
                self.assertEqual(params[2], action)
                self.assertEqual(params[3], "test-admin")
                self.assertEqual(params[4], "Regression test")
                self.assertIsNone(params[5])
                self.assertIsInstance(params[6], Json)
                self.assertEqual(
                    params[6].adapted,
                    {"is_enabled": True},
                )


if __name__ == "__main__":
    unittest.main()
