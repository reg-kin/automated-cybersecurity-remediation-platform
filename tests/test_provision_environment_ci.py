#!/usr/bin/env python3
"""Offline environment provisioning regression tests."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from install_application import ENVIRONMENT_FILE_TEMPLATES
from provision_environment import provision_environment_files


class EnvironmentProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="env-provision-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "env"
        self.target.mkdir(mode=0o700)
        self.destinations = {
            canonical: self.target / Path(canonical).name
            for canonical in ENVIRONMENT_FILE_TEMPLATES
        }

    def test_exclusive_private_provisioning(self):
        paths = provision_environment_files(
            ROOT, self.destinations, os.geteuid(), os.getegid()
        )
        self.assertEqual(len(paths), len(ENVIRONMENT_FILE_TEMPLATES))
        for canonical, relative in ENVIRONMENT_FILE_TEMPLATES.items():
            target = self.destinations[canonical]
            self.assertEqual(target.read_bytes(), (ROOT / relative).read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_existing_file_blocks_all_writes(self):
        existing = next(iter(self.destinations.values()))
        existing.write_text("DO_NOT_CHANGE")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            provision_environment_files(
                ROOT, self.destinations, os.geteuid(), os.getegid()
            )
        self.assertEqual(existing.read_text(), "DO_NOT_CHANGE")
        self.assertEqual(sorted(p.name for p in self.target.iterdir()), [existing.name])

    def test_symlink_target_is_rejected(self):
        target = self.root / "original"
        target.write_text("ORIGINAL")
        next(iter(self.destinations.values())).symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            provision_environment_files(
                ROOT, self.destinations, os.geteuid(), os.getegid()
            )
        self.assertEqual(target.read_text(), "ORIGINAL")

    def test_incomplete_mapping_rejected(self):
        mapping = dict(self.destinations)
        mapping.pop(next(iter(mapping)))
        with self.assertRaisesRegex(RuntimeError, "complete and exact"):
            provision_environment_files(ROOT, mapping, os.geteuid(), os.getegid())
        self.assertEqual(list(self.target.iterdir()), [])

    def test_second_provisioning_rejected(self):
        provision_environment_files(ROOT, self.destinations, os.geteuid(), os.getegid())
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            provision_environment_files(ROOT, self.destinations, os.geteuid(), os.getegid())


if __name__ == "__main__":
    unittest.main()
