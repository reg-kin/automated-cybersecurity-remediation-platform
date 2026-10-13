#!/usr/bin/env python3
"""Python provisioning tests never download packages or create a real venv."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provision_python import provision_python_environment


class PythonProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="python-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "app"
        self.app.mkdir(mode=0o700)
        (self.app / "requirements.txt").write_text("flask==3.1.3\nrequests==2.33.0\n")

    def test_pinned_requirements_install_command(self):
        with patch("provision_python.subprocess.run") as run:
            result = provision_python_environment(self.app, installer=["/bin/true"])
        self.assertEqual(result, self.app / "venv")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], [
            "/bin/true", "install", "--requirement", str(self.app / "requirements.txt")
        ])

    def test_unpinned_requirements_rejected(self):
        (self.app / "requirements.txt").write_text("requests>=2\n")
        with patch("provision_python.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "pinned"):
                provision_python_environment(self.app)
        run.assert_not_called()

    def test_existing_venv_rejected(self):
        (self.app / "venv").mkdir()
        with patch("provision_python.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "must not be overwritten"):
                provision_python_environment(self.app)
        run.assert_not_called()

    def test_symlink_requirements_rejected(self):
        (self.app / "requirements.txt").unlink()
        (self.app / "requirements.txt").symlink_to(self.app.parent / "outside")
        with patch("provision_python.subprocess.run") as run:
            with self.assertRaises(OSError):
                provision_python_environment(self.app)
        run.assert_not_called()

    def test_unsafe_app_permissions_rejected(self):
        self.app.chmod(0o777)
        with patch("provision_python.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "permissions unsafe"):
                provision_python_environment(self.app)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
