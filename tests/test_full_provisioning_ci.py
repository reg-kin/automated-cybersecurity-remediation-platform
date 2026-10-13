#!/usr/bin/env python3
"""Disposable filesystem tests for the full five-stage provisioning flow."""
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
from provisioning_journal import inspect_provisioning
from provision_staged_application import (
    provision_staged_application, inspect_staged_application,
)


class FullProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="full-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "application"
        self.app.mkdir(mode=0o700)
        shutil.copytree(ROOT / "deployment", self.app / "deployment")
        shutil.copy2(ROOT / "requirements.txt", self.app / "requirements.txt")
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.journal = self.private / "journal.json"
        self.units = self.root / "units"
        self.units.mkdir(mode=0o700)
        self.env = self.root / "env"
        self.env.mkdir(mode=0o700)
        self.mapping = {
            canonical: self.env / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }

    def run_full(self):
        return provision_staged_application(
            self.journal, self.app, self.units, self.mapping,
            uid=os.geteuid(), gid=os.getegid(),
        )

    def test_full_stage_journal_with_isolated_python_stub(self):
        # Only Python's dependency installation is stubbed; real preflight,
        # ownership preparation, environment, units, and journal are exercised.
        with patch("provisioning_middle_stages.provision_python_environment"), \
             patch("provisioning_middle_stages.verify_python_environment", return_value=True), \
             patch("verify_complete_provisioning.verify_python_environment", return_value=True):
            result = self.run_full()
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["completed_stages"],
                         ["preflight", "python", "ownership", "environment", "units"])
        self.assertEqual(len(list(self.env.iterdir())), len(self.mapping))
        self.assertGreater(len(list(self.units.iterdir())), 0)
        self.assertEqual(inspect_staged_application(self.journal)[
            "dispatcher_timer_activation"], "FORBIDDEN")

    def test_full_stages_with_real_python_dependencies(self):
        # Real venv and real pinned package installation; all five stages run.
        result = self.run_full()
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["completed_stages"],
                         ["preflight", "python", "ownership", "environment", "units"])
        self.assertEqual(inspect_staged_application(self.journal)[
            "dispatcher_timer_activation"], "FORBIDDEN")

    def test_completed_journal_does_not_hide_tampered_unit(self):
        from verify_complete_provisioning import verify_complete_provisioning
        result = self.run_full()
        self.assertEqual(result["state"], "COMPLETE")
        unit = next(self.units.glob("*.service"))
        unit.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            verify_complete_provisioning(
                self.journal, self.app, self.units, self.mapping,
                uid=os.geteuid(), gid=os.getegid()
            )

    def test_completed_journal_does_not_hide_unit_content_tampering(self):
        from verify_complete_provisioning import verify_complete_provisioning
        self.assertEqual(self.run_full()["state"], "COMPLETE")
        unit = next(self.units.glob("*.service"))
        unit.write_text("MALICIOUS UNIT CONTENT")
        with self.assertRaisesRegex(RuntimeError, "content mismatch"):
            verify_complete_provisioning(
                self.journal, self.app, self.units, self.mapping,
                uid=os.geteuid(), gid=os.getegid()
            )

    def test_completed_journal_does_not_hide_environment_content_tampering(self):
        from verify_complete_provisioning import verify_complete_provisioning
        self.assertEqual(self.run_full()["state"], "COMPLETE")
        target = next(self.env.iterdir())
        target.write_text("MALICIOUS ENV CONTENT")
        with self.assertRaisesRegex(RuntimeError, "content mismatch"):
            verify_complete_provisioning(
                self.journal, self.app, self.units, self.mapping,
                uid=os.geteuid(), gid=os.getegid()
            )

    def test_python_failure_blocks_all_later_stages(self):
        with patch("provisioning_middle_stages.provision_python_environment",
                   side_effect=RuntimeError("INJECTED dependency failure")):
            with self.assertRaisesRegex(RuntimeError, "INJECTED"):
                self.run_full()
        self.assertEqual(inspect_provisioning(self.journal)["completed_stages"],
                         ["preflight"])
        self.assertEqual(list(self.env.iterdir()), [])
        self.assertEqual(list(self.units.iterdir()), [])
        with self.assertRaises((FileExistsError, RuntimeError)):
            self.run_full()

    def test_environment_failure_blocks_units_and_completion(self):
        with patch("provisioning_middle_stages.provision_python_environment"), \
             patch("provisioning_middle_stages.verify_python_environment", return_value=True), \
             patch("provisioning_final_stages.verified_environment",
                   side_effect=RuntimeError("INJECTED environment failure")):
            with self.assertRaisesRegex(RuntimeError, "INJECTED"):
                self.run_full()
        self.assertEqual(inspect_provisioning(self.journal)["completed_stages"],
                         ["preflight", "python", "ownership"])
        self.assertEqual(list(self.units.iterdir()), [])

    def test_existing_unit_rejected_before_journal(self):
        (self.units / "remediation-controller.service").write_text("EXISTING")
        with self.assertRaisesRegex(RuntimeError, "Existing systemd unit"):
            self.run_full()
        self.assertFalse(self.journal.exists())


if __name__ == "__main__":
    unittest.main()
