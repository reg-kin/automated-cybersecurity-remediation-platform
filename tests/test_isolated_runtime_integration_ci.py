#!/usr/bin/env python3
"""Isolated Flask runtime tests: no sockets, database or Ansible execution."""
import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "verification"))


class IsolatedRuntimeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = "ci-runtime-token-only"
        cls.environment = patch.dict(os.environ, {
            "CONTROLLER_TOKEN": cls.token,
            "VERIFICATION_TOKEN": cls.token,
        })
        cls.environment.start()
        cls.controller = importlib.import_module("remediation.controller_api")
        cls.gateway = importlib.import_module("verification_gateway")

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()

    def test_controller_rejects_unauthenticated_execution_without_database(self):
        client = self.controller.app.test_client()
        with patch.object(self.controller.db, "connect", side_effect=AssertionError("database touched")):
            for headers in ({}, {"Authorization": "Bearer incorrect"}):
                response = client.post("/remediate", json={"capability": "os_patching"}, headers=headers)
                self.assertEqual(response.status_code, 401)
            response = client.post("/remediate", json={"capability": "invalid"},
                                   headers={"Authorization": "Bearer " + self.token})
            self.assertEqual(response.status_code, 400)

    def test_controller_authorised_request_uses_stub_only(self):
        client = self.controller.app.test_client()
        class Stub:
            def execute(self, payload):
                return {"success": True, "status": "AWAITING_APPROVAL"}
        with patch.dict(self.controller.CONTROLLERS, {"ci_stub": Stub()}):
            response = client.post("/remediate", json={"capability": "ci_stub"},
                                   headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["status"], "AWAITING_APPROVAL")

    def test_controller_approval_requires_auth_before_database(self):
        client = self.controller.app.test_client()
        with patch.object(self.controller.db, "connect", side_effect=AssertionError("database touched")):
            for endpoint in ("/executions/17/approve", "/executions/17/cancel"):
                for headers in ({}, {"Authorization": "Bearer incorrect"}):
                    response = client.post(endpoint, json={}, headers=headers)
                    self.assertEqual(response.status_code, 401)

    def test_controller_approval_reads_authoritative_execution(self):
        client = self.controller.app.test_client()
        class Connection:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def close(self):
                pass
        class Stub:
            def approve(self, execution_id):
                return {"success": True, "execution_id": execution_id}
        connection = Connection()
        with patch.object(self.controller.db, "connect", return_value=connection), \\
             patch.object(self.controller.db, "get_execution",
                          return_value={"capability": "ci_stub"}) as get_execution, \\
             patch.dict(self.controller.CONTROLLERS, {"ci_stub": Stub()}):
            response = client.post("/executions/17/approve",
                                   json={"capability": "os_patching", "execution_target": "malicious"},
                                   headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["execution_id"], 17)
        get_execution.assert_called_once_with(connection, 17)

    def test_gateway_rejects_unauthorised_and_fails_closed(self):
        client = self.gateway.app.test_client()
        with patch.object(self.gateway, "dispatch", side_effect=AssertionError("dispatch touched")):
            self.assertEqual(client.post("/verify", json={}).status_code, 401)
            self.assertEqual(client.post("/verify", json={},
                             headers={"Authorization": "Bearer wrong"}).status_code, 401)
        with patch.object(self.gateway, "dispatch", side_effect=RuntimeError("injected verification failure")):
            response = client.post("/verify", json={"finding_id": 1},
                                   headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["verification_status"], "FAILED")
        self.assertIs(response.get_json()["present"], True)

    def test_gateway_authorised_dispatch_is_isolated(self):
        client = self.gateway.app.test_client()
        with patch.object(self.gateway, "dispatch", return_value={
            "present": False, "verification_status": "PASSED"
        }) as dispatch:
            response = client.post("/verify", json={"finding_id": 12},
                                   headers={"Authorization": "Bearer " + self.token})
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.get_json()["present"], False)
        dispatch.assert_called_once_with({"finding_id": 12})


if __name__ == "__main__":
    unittest.main()
