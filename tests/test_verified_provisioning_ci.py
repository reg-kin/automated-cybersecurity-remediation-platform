#!/usr/bin/env python3
"""Offline integration tests for verified provisioning adapters."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from verified_provisioning import (
    verified_preflight, verified_environment, verified_units,
)


class VerifiedProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="verified-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.application = self.base / "app"
        self.application.mkdir(mode=0o700)
        shutil.copytree(ROOT / "deployment", self.application / "deployment")
        shutil.copy2(ROOT / "requirements.txt", self.application / "requirements.txt")
        self.units = self.base / "units"
        self.units.mkdir(mode=0o700)
        self.env = self.base / "env"
        self.env.mkdir(mode=0o700)
        self.destinations = {
            canonical: self.env / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }

    def test_verified_preflight_and_provisioning(self):
        self.assertTrue(verified_preflight(
            self.application, self.units, self.destinations
        ))
        self.assertTrue(verified_environment(
            self.application, self.destinations, os.geteuid(), os.getegid()
        ))
        self.assertTrue(verified_units(
            self.application, self.units, os.geteuid(), os.getegid()
        ))
        self.assertGreater(len(list(self.units.iterdir())), 0)
        self.assertEqual(len(list(self.env.iterdir())), len(self.destinations))

    def test_post_write_verification_rejects_wrong_mode(self):
        from provision_environment import provision_environment_files
        def wrong_mode(*args, **kwargs):
            created = provision_environment_files(*args, **kwargs)
            created[0].chmod(0o600)
            return created
        with patch("verified_provisioning.provision_environment_files", side_effect=wrong_mode):
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                verified_environment(
                    self.application, self.destinations, os.geteuid(), os.getegid()
                )

    def test_preflight_rejects_existing_unit_before_write(self):
        (self.units / "remediation-controller.service").write_text("EXISTING")
        with self.assertRaisesRegex(RuntimeError, "Existing systemd unit"):
            verified_preflight(self.application, self.units, self.destinations)
        self.assertEqual(
            (self.units / "remediation-controller.service").read_text(), "EXISTING"
        )


if __name__ == "__main__":
    unittest.main()
