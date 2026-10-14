#!/usr/bin/env python3
"""Fault-injection tests for provisioning rollback in isolated directories."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from provision_environment import provision_environment_files
from provision_service_units import provision_service_units


class ProvisioningRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="provision-rollback-ci-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = self.base / "env"
        self.env.mkdir(mode=0o700)
        self.units = self.base / "units"
        self.units.mkdir(mode=0o700)

    def failing_chown(self):
        original = os.fchown
        calls = {"count": 0}
        def fail_on_second(fd, uid, gid):
            calls["count"] += 1
            if calls["count"] == 2:
                raise OSError("INJECTED second-file failure")
            return original(fd, uid, gid)
        return fail_on_second

    def test_environment_partial_failure_rolls_back(self):
        mapping = {
            canonical: self.env / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }
        with patch("provision_environment.os.fchown", side_effect=self.failing_chown()):
            with self.assertRaisesRegex(OSError, "INJECTED"):
                provision_environment_files(ROOT, mapping, os.geteuid(), os.getegid())
        self.assertEqual(list(self.env.iterdir()), [])

    def test_units_partial_failure_rolls_back(self):
        with patch("provision_service_units.os.fchown", side_effect=self.failing_chown()):
            with self.assertRaisesRegex(OSError, "INJECTED"):
                provision_service_units(ROOT, self.units, os.geteuid(), os.getegid())
        self.assertEqual(list(self.units.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
