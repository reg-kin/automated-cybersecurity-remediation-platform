#!/usr/bin/env python3
"""Isolated, non-production integration tests for authenticated release publication."""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))

from package_release import build_release
from install_release import (
    install_authenticated_application,
    publish_authenticated_release,
)


class ReleasePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.revision = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "release.tar"
        self.staging = self.root / "staging"
        self.destination = self.root / "published" / "application"
        self.staging.mkdir(mode=0o700)
        self.destination.parent.mkdir(mode=0o755)
        self.count, self.digest = build_release(
            ROOT, self.revision, self.archive
        )

    def file_digests(self):
        return {
            str(p.relative_to(self.destination)): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in self.destination.rglob("*")
            if p.is_file()
        }

    def test_publish_and_reject_overwrite(self):
        result, count = publish_authenticated_release(
            self.archive, self.digest, self.destination, self.staging
        )
        self.assertEqual(result, self.destination)
        self.assertEqual(count, self.count)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        before = self.file_digests()
        self.assertEqual(len(before), self.count)
        self.assertEqual(list(self.staging.iterdir()), [])
        with self.assertRaises((RuntimeError, OSError)):
            publish_authenticated_release(
                self.archive, self.digest, self.destination, self.staging
            )
        self.assertEqual(self.file_digests(), before)
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_wrong_archive_digest_rejected(self):
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            publish_authenticated_release(
                self.archive, "0" * 64, self.destination, self.staging
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_production_rejects_disposable_destination(self):
        with self.assertRaisesRegex(
            RuntimeError, "Unsupported installation destination"
        ):
            install_authenticated_application(
                self.archive, self.digest, self.destination, self.staging
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_reproducible_package(self):
        second = self.root / "release-again.tar"
        count, digest = build_release(ROOT, self.revision, second)
        self.assertEqual(count, self.count)
        self.assertEqual(digest, self.digest)
        self.assertEqual(second.read_bytes(), self.archive.read_bytes())


if __name__ == "__main__":
    unittest.main()
