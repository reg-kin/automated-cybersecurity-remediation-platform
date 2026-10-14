#!/usr/bin/env python3
"""Real Python venv installation and verification in an isolated temporary tree.

No production paths, databases, services, or network-dependent mock installers.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provision_python import provision_python_environment
from verify_python_ownership import verify_python_environment
from prepare_ownership import prepare_staged_application_ownership
from verify_python_ownership import verify_staged_ownership


class RealPythonEnvironmentTests(unittest.TestCase):
    def test_real_pinned_requirements_and_ownership(self):
        with tempfile.TemporaryDirectory(prefix="real-python-ci-") as root:
            app = Path(root) / "app"
            app.mkdir(mode=0o700)
            (app / "requirements.txt").write_bytes(
                (ROOT / "requirements.txt").read_bytes()
            )
            provision_python_environment(app)
            self.assertTrue(verify_python_environment(app))
            prepare_staged_application_ownership(app, os.geteuid(), os.getegid())
            self.assertTrue(verify_staged_ownership(app, os.geteuid(), os.getegid()))


if __name__ == "__main__":
    unittest.main()
