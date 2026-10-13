#!/usr/bin/env python3
"""Isolated tests for offline unit provisioning; no systemd interaction."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from provision_service_units import provision_service_units


class OfflineUnitProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="unit-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / "units"
        self.destination.mkdir(mode=0o700)

    def test_provision_is_offline_and_preserves_timer_as_file(self):
        names = provision_service_units(
            ROOT, self.destination, os.geteuid(), os.getegid()
        )
        self.assertIn("remediation-dispatcher.timer", names)
        self.assertTrue((self.destination / "remediation-dispatcher.timer").is_file())
        self.assertEqual((self.destination / "remediation-dispatcher.timer").stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), names)

    def test_existing_unit_blocks_all_writes(self):
        name = "remediation-controller.service"
        existing = self.destination / name
        existing.write_text("ORIGINAL")
        with self.assertRaisesRegex(RuntimeError, "must not be overwritten"):
            provision_service_units(ROOT, self.destination, os.geteuid(), os.getegid())
        self.assertEqual(existing.read_text(), "ORIGINAL")
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), [name])

    def test_symlink_destination_rejected(self):
        link = self.destination.parent / "linked"
        link.symlink_to(self.destination, target_is_directory=True)
        with self.assertRaises(OSError):
            provision_service_units(ROOT, link, os.geteuid(), os.getegid())

    def test_second_provisioning_rejected(self):
        provision_service_units(ROOT, self.destination, os.geteuid(), os.getegid())
        with self.assertRaisesRegex(RuntimeError, "must not be overwritten"):
            provision_service_units(ROOT, self.destination, os.geteuid(), os.getegid())


if __name__ == "__main__":
    unittest.main()
