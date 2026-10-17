"""Fail-closed, read-only reference-host preflight regression tests."""
import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from inspect_reference_host import inspect_host, main


class ReferenceHostPreflightTests(unittest.TestCase):
    def test_rejects_relative_path(self):
        with self.assertRaisesRegex(RuntimeError, "absolute"):
            inspect_host("relative")

    def test_rejects_unsupported_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "Systemd units require"):
                inspect_host(directory)

    def test_rejects_symlink_application(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "app"
            target.mkdir()
            link = pathlib.Path(directory) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                inspect_host(link)

    def test_cli_fails_closed_without_reference_host(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main(["--application", directory]), 1)

    def test_no_service_activation_paths(self):
        source = (ROOT / "install" / "inspect_reference_host.py").read_text()
        for forbidden in ("subprocess.", "systemctl ", "os.system(", "os.chown(", "os.chmod("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
