#!/usr/bin/env python3
"""Provisioning transaction marker tests; no service operations."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provisioning_journal import (
    begin_provisioning, inspect_provisioning, assert_not_deployable, advance_provisioning, STAGES
)


class ProvisioningJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="provision-journal-ci-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.journal = self.private / "provisioning.json"

    def test_incomplete_transaction_blocks_deployment(self):
        begin_provisioning(self.journal, application=self.private / "application")
        self.assertEqual(inspect_provisioning(self.journal)["state"], "INCOMPLETE")
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(RuntimeError, "deployment prohibited"):
            assert_not_deployable(self.journal)

    def test_existing_journal_cannot_be_replaced(self):
        begin_provisioning(self.journal, application=self.private / "application")
        before = self.journal.read_bytes()
        with self.assertRaises(FileExistsError):
            begin_provisioning(self.journal, application=self.private / "application")
        self.assertEqual(self.journal.read_bytes(), before)

    def test_symlink_journal_rejected(self):
        target = self.private / "other"
        target.write_text("UNCHANGED")
        self.journal.symlink_to(target)
        with self.assertRaises(OSError):
            begin_provisioning(self.journal, application=self.private / "application")
        self.assertEqual(target.read_text(), "UNCHANGED")

    def test_corrupt_journal_rejected(self):
        self.journal.write_text('{"state": "COMPLETE"}')
        self.journal.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "Invalid provisioning journal"):
            inspect_provisioning(self.journal)

    def test_stage_order_and_explicit_evidence(self):
        begin_provisioning(self.journal, application=self.private / "application")
        with self.assertRaisesRegex(RuntimeError, "evidence"):
            advance_provisioning(self.journal, "preflight")
        with self.assertRaisesRegex(RuntimeError, "exact order"):
            advance_provisioning(self.journal, "ownership", evidence_confirmed=True)
        for stage in STAGES[:-1]:
            record = advance_provisioning(self.journal, stage, evidence_confirmed=True)
            self.assertEqual(record["state"], "INCOMPLETE")
            with self.assertRaisesRegex(RuntimeError, "deployment prohibited"):
                assert_not_deployable(self.journal)
        record = advance_provisioning(self.journal, STAGES[-1], evidence_confirmed=True)
        self.assertEqual(record["state"], "COMPLETE")
        self.assertEqual(assert_not_deployable(self.journal)["completed_stages"], list(STAGES))
        with self.assertRaisesRegex(RuntimeError, "already closed"):
            advance_provisioning(self.journal, "preflight", evidence_confirmed=True)

    def test_transition_preserves_private_permissions(self):
        begin_provisioning(self.journal, application=self.private / "application")
        advance_provisioning(self.journal, "preflight", evidence_confirmed=True)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(inspect_provisioning(self.journal)["completed_stages"], ["preflight"])

    def test_world_readable_journal_rejected(self):
        begin_provisioning(self.journal, application=self.private / "application")
        self.journal.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "Unsafe provisioning journal"):
            inspect_provisioning(self.journal)


if __name__ == "__main__":
    unittest.main()
