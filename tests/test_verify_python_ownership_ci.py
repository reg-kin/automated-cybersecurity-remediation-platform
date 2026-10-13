#!/usr/bin/env python3
"""Isolated read-only Python and ownership verifier tests."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from verify_python_ownership import verify_python_environment, verify_staged_ownership


class PythonOwnershipVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="verify-python-owner-ci-")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "application"
        self.app.mkdir(mode=0o700)

    def test_valid_private_staged_tree(self):
        (self.app / "requirements.txt").write_text("flask==3.1.3\n")
        self.assertTrue(verify_staged_ownership(
            self.app, os.geteuid(), os.getegid()
        ))

    def test_staged_tree_rejects_symlink(self):
        (self.app / "link").symlink_to(self.app)
        with self.assertRaisesRegex(RuntimeError, "Unsafe staged"):
            verify_staged_ownership(self.app, os.geteuid(), os.getegid())

    def test_missing_venv_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "virtual environment"):
            verify_python_environment(self.app)

    def test_venv_artifacts_verified_without_executing_python(self):
        venv = self.app / "venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        (venv / "bin/python").symlink_to(sys.executable)
        self.assertTrue(verify_python_environment(self.app))

    def test_venv_rejects_missing_configuration(self):
        (self.app / "venv" / "bin").mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, "configuration"):
            verify_python_environment(self.app)


if __name__ == "__main__":
    unittest.main()
