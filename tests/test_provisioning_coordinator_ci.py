#!/usr/bin/env python3
"""Coordinator tests: isolated callbacks, no production provisioning."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provisioning_journal import STAGES, inspect_provisioning
from provisioning_coordinator import (
    execute_provisioning_stages, inspect_interrupted_provisioning,
)


class ProvisioningCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coordinator-ci-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.journal = self.private / "journal.json"
        self.application = self.private / "application"

    def verifiers(self):
        return {stage: (lambda: True) for stage in STAGES}

    def test_verified_stages_complete_in_order(self):
        called = []
        operations = {stage: (lambda stage=stage: called.append(stage) or True)
                      for stage in STAGES}
        result = execute_provisioning_stages(
            self.journal, self.application, operations, verifiers=self.verifiers()
        )
        self.assertEqual(called, list(STAGES))
        self.assertEqual(result["state"], "COMPLETE")
        self.assertEqual(result["completed_stages"], list(STAGES))

    def test_failure_blocks_later_stages_and_resume(self):
        called = []
        def operation(stage):
            called.append(stage)
            if stage == "ownership":
                raise RuntimeError("INJECTED interruption")
            return True
        operations = {stage: (lambda stage=stage: operation(stage))
                      for stage in STAGES}
        with self.assertRaisesRegex(RuntimeError, "INJECTED"):
            execute_provisioning_stages(self.journal, self.application, operations)
        self.assertEqual(called, list(STAGES[:3]))
        state = inspect_interrupted_provisioning(self.journal)
        self.assertEqual(state["completed_stages"], list(STAGES[:2]))
        self.assertTrue(state["manual_reconciliation_required"])
        with self.assertRaises(FileExistsError):
            execute_provisioning_stages(self.journal, self.application, operations)
        self.assertEqual(called, list(STAGES[:3]))

    def test_unverified_result_blocks_deployment(self):
        operations = {stage: (lambda: True) for stage in STAGES}
        operations["python"] = lambda: None
        with self.assertRaisesRegex(RuntimeError, "not verified"):
            execute_provisioning_stages(self.journal, self.application, operations)
        self.assertEqual(
            inspect_provisioning(self.journal)["completed_stages"], ["preflight"]
        )

    def test_missing_stage_rejected_before_journal_creation(self):
        with self.assertRaisesRegex(RuntimeError, "Exactly one callable"):
            execute_provisioning_stages(
                self.journal, self.application, {"preflight": lambda: True}, verifiers=self.verifiers()
            )
        self.assertFalse(self.journal.exists())


if __name__ == "__main__":
    unittest.main()
