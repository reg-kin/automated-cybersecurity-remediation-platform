#!/usr/bin/env python3
"""Guard against false completion claims from externally supplied stage callbacks.

These tests do not provision a live application. The coordinator currently
accepts a boolean from the callback rather than independently verifying state.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provisioning_coordinator import execute_provisioning_stages
from provisioning_journal import STAGES, inspect_provisioning


class CoordinatorEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coordinator-evidence-ci-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.journal = self.private / "journal.json"

    def test_no_false_success_without_independent_verifier(self):
        operations = {stage: (lambda: True) for stage in STAGES}
        verifiers = {stage: (lambda: True) for stage in STAGES}
        verifiers["environment"] = lambda: False
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            execute_provisioning_stages(
                self.journal, self.private / "app", operations, verifiers=verifiers
            )
        record = inspect_provisioning(self.journal)
        self.assertEqual(record["completed_stages"], list(STAGES[:3]))
        self.assertEqual(record["state"], "INCOMPLETE")

    def test_missing_verifiers_rejected_without_journal(self):
        operations = {stage: (lambda: True) for stage in STAGES}
        with self.assertRaisesRegex(RuntimeError, "verifier"):
            execute_provisioning_stages(self.journal, self.private / "app", operations)
        self.assertFalse(self.journal.exists())


if __name__ == "__main__":
    unittest.main()
