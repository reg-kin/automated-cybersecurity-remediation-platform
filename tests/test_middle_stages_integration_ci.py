#!/usr/bin/env python3
"""Integrated middle-stage tests on private, disposable filesystem trees."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provisioning_journal import begin_provisioning, advance_provisioning, inspect_provisioning
from provisioning_middle_stages import execute_middle_stages


class MiddleStagesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="middle-stage-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "journal-dir"
        self.private.mkdir(mode=0o700)
        self.app = self.root / "app"
        self.app.mkdir(mode=0o700)
        (self.app / "requirements.txt").write_text("flask==3.1.3\n")
        self.journal = self.private / "state.json"
        begin_provisioning(self.journal, application=self.app)
        advance_provisioning(self.journal, "preflight", evidence_confirmed=True)

    def run_stages(self):
        return execute_middle_stages(
            self.journal, self.app, uid=os.geteuid(), gid=os.getegid(),
            installer=[sys.executable, "-m", "pip"],
        )

    def test_real_ownership_with_mocked_python_install(self):
        # Mock network-dependent pip only; the actual ownership walk runs.
        with patch("provisioning_middle_stages.provision_python_environment") as provision, \
             patch("provisioning_middle_stages.verify_python_environment", return_value=True):
            result = self.run_stages()
        self.assertEqual(provision.call_count, 1)
        self.assertEqual(result["completed_stages"], ["preflight", "python", "ownership"])
        self.assertEqual(result["state"], "INCOMPLETE")

    def test_python_failure_blocks_ownership_and_retry(self):
        with patch("provisioning_middle_stages.provision_python_environment",
                   side_effect=RuntimeError("INJECTED pip failure")):
            with self.assertRaisesRegex(RuntimeError, "INJECTED"):
                self.run_stages()
        self.assertEqual(inspect_provisioning(self.journal)["completed_stages"], ["preflight"])

    def test_ownership_failure_preserves_python_boundary(self):
        with patch("provisioning_middle_stages.provision_python_environment"), \
             patch("provisioning_middle_stages.verify_python_environment", return_value=True), \
             patch("provisioning_middle_stages.prepare_staged_application_ownership",
                   side_effect=RuntimeError("INJECTED ownership failure")):
            with self.assertRaisesRegex(RuntimeError, "INJECTED"):
                self.run_stages()
        self.assertEqual(inspect_provisioning(self.journal)["completed_stages"],
                         ["preflight", "python"])
        with self.assertRaisesRegex(RuntimeError, "automatic resume"):
            self.run_stages()


if __name__ == "__main__":
    unittest.main()
