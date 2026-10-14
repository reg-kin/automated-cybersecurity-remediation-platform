#!/usr/bin/env python3
"""Offline readiness composition tests; no real services or secrets."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from assess_offline_readiness import assess_offline_readiness


class OfflineReadinessTests(unittest.TestCase):
    def setUp(self):
        self.app = Path("/tmp/disposable-app")
        self.units = Path("/tmp/disposable-units")
        self.mapping = {name: Path("/tmp") / Path(name).name
                        for name in ENVIRONMENT_FILE_TEMPLATES}
        self.patches = [
            patch("provisioning_journal.assert_not_deployable", return_value={
                "application": str(self.app),
                "completed_stages": ["preflight", "python", "ownership", "environment", "units"]
            }),
            patch("verify_python_ownership.verify_python_environment", return_value=True),
            patch("verify_python_ownership.verify_staged_ownership", return_value=True),
            patch("service_provisioning.inspect_service_provisioning", return_value={
                "unit_names": ["test.service"]
            }),
            patch("verified_provisioning._verify_file"),
            patch("verify_complete_provisioning._verify_exact_copy"),
            patch("assess_offline_readiness.verify_deployment_configuration",
                  return_value={"configured_files": 6, "activation_authorized": False}),
            patch("assess_offline_readiness.verify_service_identity_access",
                  return_value={"service_identity_access": "STATIC_CHECK_PASSED",
                                "activation_authorized": False}),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def run_check(self):
        return assess_offline_readiness(
            "/tmp/journal", self.app, self.units, self.mapping, uid=1001, gid=1001
        )

    def test_offline_pass_never_authorizes_activation(self):
        result = self.run_check()
        self.assertEqual(result["offline_readiness"], "PASSED")
        self.assertFalse(result["activation_authorized"])
        self.assertFalse(result["credentials_authenticated"])
        self.assertFalse(result["runtime_services_tested"])
        self.assertFalse(result["end_to_end_remediation_tested"])
        self.assertEqual(result["dispatcher_timer_activation"], "FORBIDDEN")

    def test_rejects_unconfigured_secrets(self):
        with patch("assess_offline_readiness.verify_deployment_configuration",
                   side_effect=RuntimeError("Missing deployment setting")):
            with self.assertRaisesRegex(RuntimeError, "Missing deployment setting"):
                self.run_check()

    def test_rejects_inaccessible_service_account(self):
        with patch("assess_offline_readiness.verify_service_identity_access",
                   side_effect=RuntimeError("cannot traverse")):
            with self.assertRaisesRegex(RuntimeError, "cannot traverse"):
                self.run_check()

    def test_rejects_modified_unit(self):
        with patch("verify_complete_provisioning._verify_exact_copy",
                   side_effect=RuntimeError("content mismatch")):
            with self.assertRaisesRegex(RuntimeError, "content mismatch"):
                self.run_check()

    def test_rejects_incomplete_journal(self):
        with patch("provisioning_journal.assert_not_deployable",
                   side_effect=RuntimeError("INCOMPLETE")):
            with self.assertRaisesRegex(RuntimeError, "INCOMPLETE"):
                self.run_check()


if __name__ == "__main__":
    unittest.main()
