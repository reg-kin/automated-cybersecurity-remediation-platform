#!/usr/bin/env python3
"""Disposable static service identity access checks."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from verify_service_identity_access import verify_service_identity_access


class ServiceIdentityAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.app = root / "app"
        self.app.mkdir(mode=0o700)
        (self.app / "venv" / "bin").mkdir(parents=True)
        (self.app / "venv" / "pyvenv.cfg").write_text("home=/usr/bin\n")
        (self.app / "venv" / "bin" / "python").write_text("test")
        (self.app / "venv" / "bin" / "python").chmod(0o700)
        (self.app / "requirements.txt").write_text("flask==3.1.3\n")
        (self.app / "deployment" / "systemd").mkdir(parents=True)
        (self.app / "deployment" / "systemd" / "test.service").write_text("[Service]\n")
        self.env = {}
        env_dir = root / "environment"
        env_dir.mkdir(mode=0o700)
        for canonical in ENVIRONMENT_FILE_TEMPLATES:
            path = env_dir / Path(canonical).name
            path.write_text("TOKEN=EXAMPLE\n")
            path.chmod(0o640)
            self.env[canonical] = path

    def verify(self, uid=None, gid=None):
        with patch("verify_service_identity_access.inspect_service_provisioning",
                   return_value={"unit_names": ["test.service"]}):
            return verify_service_identity_access(
                self.app, self.env, uid=os.geteuid() if uid is None else uid,
                gid=os.getegid() if gid is None else gid
            )

    def test_static_access_never_authorizes_activation(self):
        result = self.verify()
        self.assertEqual(result["service_identity_access"], "STATIC_CHECK_PASSED")
        self.assertFalse(result["activation_authorized"])
        self.assertFalse(result["runtime_execution_verified"])

    def test_wrong_identity_cannot_traverse_private_root(self):
        with self.assertRaisesRegex(RuntimeError, "traverse"):
            self.verify(uid=os.geteuid() + 10000, gid=os.getegid() + 10000)

    def test_missing_python_rejected(self):
        (self.app / "venv" / "bin" / "python").unlink()
        with self.assertRaisesRegex(RuntimeError, "Missing runtime prerequisite"):
            self.verify()

    def test_unreadable_requirement_rejected(self):
        (self.app / "requirements.txt").chmod(0)
        with self.assertRaisesRegex(RuntimeError, "cannot read prerequisite"):
            self.verify()

    def test_interpreter_not_executable_rejected(self):
        (self.app / "venv" / "bin" / "python").chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "cannot execute"):
            self.verify()

    def test_parent_directory_not_traversable_rejected(self):
        (self.app / "venv" / "bin").chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "cannot traverse parent"):
            self.verify()

    def test_environment_parent_not_traversable_rejected(self):
        parent = next(iter(self.env.values())).parent
        self.addCleanup(parent.chmod, 0o700)
        parent.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "cannot traverse parent"):
            self.verify()

    def test_incorrect_environment_permissions_rejected(self):
        next(iter(self.env.values())).chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "cannot read environment"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
