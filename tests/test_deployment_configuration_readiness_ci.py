#!/usr/bin/env python3
"""Isolated checks for deployment configuration readiness, no real credentials."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from verify_deployment_configuration import MANDATORY, verify_deployment_configuration


class ConfigurationReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = {}
        for canonical, template in ENVIRONMENT_FILE_TEMPLATES.items():
            path = root / Path(canonical).name
            lines = [f"{key}=TEST_ONLY_NOT_A_REAL_SECRET" for key in MANDATORY[canonical]]
            if canonical.endswith("remediation-controller.env"):
                lines.append("TEST_SKIP_STAGE2=false")
            path.write_text("\n".join(lines) + "\n")
            path.chmod(0o640)
            self.paths[canonical] = path

    def check(self):
        return verify_deployment_configuration(
            self.paths, uid=os.geteuid(), gid=os.getegid()
        )

    def test_configured_is_not_activation_authorization(self):
        self.assertEqual(self.check(), {"configured_files": 6, "activation_authorized": False})

    def test_rejects_placeholder(self):
        path = self.paths["/etc/remediation-controller.env"]
        path.write_text(path.read_text().replace("CONTROLLER_TOKEN=TEST_ONLY_NOT_A_REAL_SECRET", "CONTROLLER_TOKEN=CHANGE_ME"))
        with self.assertRaisesRegex(RuntimeError, "CONTROLLER_TOKEN"):
            self.check()

    def test_rejects_missing_password(self):
        path = self.paths["/etc/scan-policy-scheduler.env"]
        path.write_text(path.read_text().replace("PG_PASSWORD=TEST_ONLY_NOT_A_REAL_SECRET", "PG_PASSWORD="))
        with self.assertRaisesRegex(RuntimeError, "PG_PASSWORD"):
            self.check()

    def test_rejects_stage2_bypass(self):
        path = self.paths["/etc/remediation-controller.env"]
        path.write_text(path.read_text().replace("TEST_SKIP_STAGE2=false", "TEST_SKIP_STAGE2=true"))
        with self.assertRaisesRegex(RuntimeError, "bypass"):
            self.check()

    def test_rejects_world_readable(self):
        next(iter(self.paths.values())).chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            self.check()

    def test_rejects_symlink(self):
        path = next(iter(self.paths.values()))
        replacement = path.with_suffix(".real")
        path.rename(replacement)
        path.symlink_to(replacement)
        with self.assertRaises(OSError):
            self.check()

    def test_rejects_duplicate_keys(self):
        path = self.paths["/etc/remediation-dispatcher.env"]
        path.write_text(path.read_text() + "PG_USER=another\n")
        with self.assertRaisesRegex(RuntimeError, "Duplicate"):
            self.check()


if __name__ == "__main__":
    unittest.main()
