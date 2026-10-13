#!/usr/bin/env python3
"""Ownership preparation tests use only temporary directories and current UID."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from prepare_ownership import prepare_staged_application_ownership


class OwnershipPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ownership-ci-")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "application"
        self.app.mkdir(mode=0o700)
        (self.app / "module").mkdir()
        (self.app / "module" / "service.py").write_text("print('safe')")

    def prepare(self):
        return prepare_staged_application_ownership(
            self.app, os.geteuid(), os.getegid()
        )

    def test_private_tree_prepared(self):
        self.assertEqual(self.prepare(), 3)
        self.assertEqual(self.app.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.app / "module" / "service.py").read_text(), "print('safe')")

    def test_symlink_descendant_rejected_before_mutation(self):
        (self.app / "external").symlink_to(self.app.parent)
        with self.assertRaisesRegex(RuntimeError, "unsafe filesystem entry"):
            self.prepare()

    def test_nonprivate_root_rejected(self):
        self.app.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "caller-owned and private"):
            self.prepare()

    def test_invalid_identity_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "Invalid service identity"):
            prepare_staged_application_ownership(self.app, -1, os.getegid())

    def test_relative_path_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "absolute"):
            prepare_staged_application_ownership(Path("relative"), os.geteuid(), os.getegid())


if __name__ == "__main__":
    unittest.main()
