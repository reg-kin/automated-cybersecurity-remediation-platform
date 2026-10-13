#!/usr/bin/env python3
"""Isolated integration of real file provisioning with journal transitions."""
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
from provisioning_journal import begin_provisioning, advance_provisioning, inspect_provisioning
from provisioning_final_stages import execute_final_provisioning_stages


class FinalProvisioningIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="final-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.application = self.base / "app"
        self.application.mkdir(mode=0o700)
        shutil.copytree(ROOT / "deployment", self.application / "deployment")
        self.units = self.base / "units"
        self.units.mkdir(mode=0o700)
        self.env = self.base / "env"
        self.env.mkdir(mode=0o700)
        self.mapping = {
            canonical: self.env / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }
        self.journal = self.private / "journal.json"
        begin_provisioning(self.journal, application=self.application)
        for stage in ("preflight", "python", "ownership"):
            advance_provisioning(self.journal, stage, evidence_confirmed=True)

    def execute(self):
        return execute_final_provisioning_stages(
            self.journal, self.application, self.units, self.mapping,
            uid=os.geteuid(), gid=os.getegid(),
        )

    def test_real_file_creation_and_journal_completion(self):
        result = self.execute()
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["completed_stages"][-2:], ["environment", "units"])
        self.assertTrue(all(p.is_file() for p in self.mapping.values()))
        self.assertGreater(len(list(self.units.iterdir())), 0)

    def test_unit_failure_leaves_incomplete_and_blocks_retry(self):
        with patch("provisioning_final_stages.verified_units",
                   side_effect=RuntimeError("INJECTED unit failure")):
            with self.assertRaisesRegex(RuntimeError, "INJECTED"):
                self.execute()
        record = inspect_provisioning(self.journal)
        self.assertEqual(record["state"], "INCOMPLETE")
        self.assertEqual(record["completed_stages"][-1], "environment")
        self.assertTrue(all(p.is_file() for p in self.mapping.values()))
        with self.assertRaisesRegex(RuntimeError, "prerequisite"):
            self.execute()

    def test_missing_prerequisite_stage_rejected(self):
        # A journal for a different application must never authorize writes.
        with self.assertRaisesRegex(RuntimeError, "prerequisite"):
            execute_final_provisioning_stages(
                self.journal, self.base / "different", self.units, self.mapping,
                uid=os.geteuid(), gid=os.getegid(),
            )
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(list(self.env.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
