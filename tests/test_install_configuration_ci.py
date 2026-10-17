#!/usr/bin/env python3
"""Isolated regression tests for installation configuration safety."""
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import (
    validate_api_port_conflicts,
    validate_environment_file_conflicts,
    validate_systemd_unit_conflicts,
    provision_environment_file,
)


class ConfigurationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="config-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.systemd = self.root / "source" / "deployment" / "systemd"
        self.systemd.mkdir(parents=True)

    def test_systemd_conflict_rejected(self):
        (self.systemd / "example.service").write_text("[Unit]\nDescription=Test\n")
        occupied = self.root / "units"
        occupied.mkdir()
        (occupied / "example.service").write_text("existing")
        with patch("pathlib.Path.__new__", wraps=Path.__new__):
            pass
        # Existing service must never be overwritten; test using a temporary
        # systemd directory by intercepting only the conflict function's Path.
        from install_application import validate_systemd_unit_conflicts
        original = Path
        def mapped_path(value, *args, **kwargs):
            if str(value) == "/etc/systemd/system":
                return occupied
            return original(value, *args, **kwargs)
        with patch("install_application.Path", side_effect=mapped_path):
            with self.assertRaisesRegex(RuntimeError, "must not be overwritten"):
                validate_systemd_unit_conflicts(self.root / "source")
        self.assertEqual((occupied / "example.service").read_text(), "existing")

    def test_existing_environment_file_rejected(self):
        occupied = self.root / "existing.env"
        occupied.write_text("KEEP=1\n")
        with patch(
            "install_application.ENVIRONMENT_FILE_TEMPLATES",
            {str(occupied): "ignored.example"},
        ):
            with self.assertRaisesRegex(RuntimeError, "must not be overwritten"):
                validate_environment_file_conflicts()
        self.assertEqual(occupied.read_text(), "KEEP=1\n")

    def test_environment_creation_is_exclusive_and_private(self):
        template = self.root / "template.env"
        template.write_text("EXAMPLE=value\n")
        destination = self.root / "configured.env"
        provision_environment_file(template, destination, os.geteuid(), os.getegid())
        self.assertEqual(destination.read_text(), "EXAMPLE=value\n")
        self.assertEqual(destination.stat().st_mode & 0o777, 0o640)
        with self.assertRaises(FileExistsError):
            provision_environment_file(template, destination, os.geteuid(), os.getegid())
        self.assertEqual(destination.read_text(), "EXAMPLE=value\n")

    def test_environment_symlink_is_rejected(self):
        template = self.root / "template.env"
        template.write_text("EXAMPLE=value\n")
        target = self.root / "untouched.env"
        target.write_text("KEEP=1\n")
        destination = self.root / "configured.env"
        destination.symlink_to(target)
        with self.assertRaises(OSError):
            provision_environment_file(template, destination, os.geteuid(), os.getegid())
        self.assertEqual(target.read_text(), "KEEP=1\n")

    def test_occupied_api_port_is_rejected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen()
            (self.systemd / "example.service").write_text(
                "[Service]\nExecStart=/bin/example --bind 127.0.0.1:"
                + str(port) + "\n"
            )
            with self.assertRaisesRegex(RuntimeError, "already occupied"):
                validate_api_port_conflicts(self.root / "source")

    def test_environment_bound_controller_port_is_checked(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            env = self.systemd / "env"
            env.mkdir()
            (env / "remediation-controller.env.example").write_text(
                f"CONTROLLER_HOST=127.0.0.1\nCONTROLLER_PORT={port}\n")
            (self.systemd / "controller.service").write_text(
                "EnvironmentFile=/etc/remediation-controller.env\n"
                "ExecStart=/bin/example --bind ${CONTROLLER_HOST}:${CONTROLLER_PORT}\n")
            with self.assertRaisesRegex(RuntimeError, "already occupied"):
                validate_api_port_conflicts(self.root / "source")

    def test_available_api_port_is_accepted(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        (self.systemd / "example.service").write_text(
            "[Service]\nExecStart=/bin/example --bind 127.0.0.1:"
            + str(port) + "\n"
        )
        self.assertEqual(validate_api_port_conflicts(self.root / "source"), 1)


if __name__ == "__main__":
    unittest.main()
