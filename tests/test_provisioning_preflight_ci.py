#!/usr/bin/env python3
"""Integrated provisioning preflight regression tests, no production writes."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from provisioning_preflight import preflight_provisioning


class ProvisioningPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="provisioning-preflight-ci-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.app = self.base / "app"
        self.app.mkdir(mode=0o700)
        shutil.copytree(ROOT / "deployment", self.app / "deployment")
        shutil.copy2(ROOT / "requirements.txt", self.app / "requirements.txt")
        self.units = self.base / "units"
        self.units.mkdir(mode=0o700)
        self.env = self.base / "env"
        self.env.mkdir(mode=0o700)
        self.mapping = {
            canonical: self.env / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }

    def check(self):
        return preflight_provisioning(self.app, self.units, self.mapping)

    def test_all_provisioning_targets_pass_without_writes(self):
        result = self.check()
        self.assertGreater(result["units"], 0)
        self.assertEqual(result["environment_files"], len(ENVIRONMENT_FILE_TEMPLATES))
        self.assertEqual(result["actions_performed"], 0)
        self.assertEqual(result["dispatcher_timer_activation"], "FORBIDDEN")
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(list(self.env.iterdir()), [])
        self.assertFalse((self.app / "venv").exists())

    def test_existing_unit_blocks_preflight(self):
        (self.units / "remediation-controller.service").write_text("ORIGINAL")
        with self.assertRaisesRegex(RuntimeError, "Existing systemd unit"):
            self.check()

    def test_existing_environment_blocks_preflight(self):
        next(iter(self.mapping.values())).write_text("ORIGINAL")
        with self.assertRaisesRegex(RuntimeError, "Existing environment file"):
            self.check()

    def test_existing_venv_blocks_preflight(self):
        (self.app / "venv").mkdir()
        with self.assertRaisesRegex(RuntimeError, "Existing virtual environment"):
            self.check()

    def test_unpinned_dependency_blocks_preflight(self):
        (self.app / "requirements.txt").write_text("flask>=3\n")
        with self.assertRaisesRegex(RuntimeError, "explicitly pinned"):
            self.check()


if __name__ == "__main__":
    unittest.main()
