#!/usr/bin/env python3
"""Production entry-point safety tests; never write /opt or systemd."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "install"))
from production_release import main, validate_staging_parent, publish_production_release


class ProductionReleaseSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="production-release-ci-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)

    def test_staging_must_be_private(self):
        self.assertEqual(validate_staging_parent(self.staging), self.staging)
        self.staging.chmod(0o755)
        with self.assertRaises(RuntimeError):
            validate_staging_parent(self.staging)

    def test_symlink_staging_refused(self):
        link = self.root / "staging-link"
        link.symlink_to(self.staging, target_is_directory=True)
        with self.assertRaises(OSError):
            validate_staging_parent(link)

    def test_default_cli_never_publishes(self):
        with patch("production_release.validate_production_release", return_value=12) as validate:
            with patch("production_release.publish_production_release") as publish:
                result = main([
                    "--archive", "/tmp/test.tar",
                    "--sha256", "0" * 64,
                    "--staging-parent", str(self.staging),
                ])
        self.assertEqual(result, 0)
        validate.assert_called_once()
        publish.assert_not_called()

    def test_publication_requires_exact_confirmation(self):
        with patch("production_release.publish_production_release") as publish:
            with self.assertRaises(SystemExit) as caught:
                main([
                    "--archive", "/tmp/test.tar",
                    "--sha256", "0" * 64,
                    "--staging-parent", str(self.staging),
                    "--publish-application-only",
                ])
        self.assertEqual(caught.exception.code, 2)
        publish.assert_not_called()

    def test_publication_rejects_nonproduction_destination(self):
        with self.assertRaises(RuntimeError):
            publish_production_release(
                self.root / "archive.tar", "0" * 64,
                self.root / "application", self.staging,
            )


if __name__ == "__main__":
    unittest.main()
