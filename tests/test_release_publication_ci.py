#!/usr/bin/env python3
"""Isolated, non-production integration tests for authenticated release publication."""
import hashlib
import io
import os
import tarfile
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
    parse_release_manifest,
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


    def altered_archive(self, transform):
        """Write a deliberately malformed but correctly SHA-256-pinned TAR."""
        malicious = self.root / "altered.tar"
        with tarfile.open(self.archive, "r:") as source:
            members = []
            for member in source.getmembers():
                payload = source.extractfile(member).read() if member.isfile() else None
                members.append((member, payload))
        members = transform(members)
        with tarfile.open(malicious, "w") as output:
            for member, payload in members:
                output.addfile(member, io.BytesIO(payload) if payload is not None else None)
        return malicious, hashlib.sha256(malicious.read_bytes()).hexdigest()

    def assert_rejected_without_publication(self, archive, digest):
        with self.assertRaises((RuntimeError, OSError, ValueError, tarfile.TarError)):
            publish_authenticated_release(
                archive, digest, self.destination, self.staging
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_archive_traversal_rejected(self):
        def transform(members):
            members[0][0].name = "application/../../escape"
            return members
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_absolute_path_rejected(self):
        def transform(members):
            members[0][0].name = "/tmp/escape"
            return members
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_symlink_rejected(self):
        def transform(members):
            member, _ = members[0]
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            member.size = 0
            members[0] = (member, None)
            return members
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_duplicate_member_rejected(self):
        def transform(members):
            return members + [members[0]]
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_unlisted_file_rejected(self):
        def transform(members):
            payload = b"unexpected"
            member = tarfile.TarInfo("application/install/unlisted-ci-file.txt")
            member.size = len(payload)
            return members + [(member, payload)]
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_unexpected_root_rejected(self):
        def transform(members):
            payload = b"unexpected"
            member = tarfile.TarInfo("unexpected-root.txt")
            member.size = len(payload)
            return members + [(member, payload)]
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_archive_manifest_checksum_mismatch_rejected(self):
        def transform(members):
            for index, (member, payload) in enumerate(members):
                if member.name == "SHA256SUMS":
                    altered = bytearray(payload)
                    altered[0] = ord("0") if altered[0] != ord("0") else ord("1")
                    members[index] = (member, bytes(altered))
                    break
            else:
                self.fail("Release manifest missing")
            return members
        self.assert_rejected_without_publication(*self.altered_archive(transform))

    def test_preflight_failure_cleans_staging(self):
        def reject(_source, _destination):
            raise RuntimeError("Deliberate preflight rejection")
        with self.assertRaisesRegex(RuntimeError, "Deliberate preflight"):
            publish_authenticated_release(
                self.archive, self.digest, self.destination, self.staging,
                preflight=reject,
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_untrusted_staging_permissions_rejected(self):
        self.staging.chmod(0o755)
        with self.assertRaises(RuntimeError):
            publish_authenticated_release(
                self.archive, self.digest, self.destination, self.staging
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_manifest_rejects_traversal_and_duplicate_paths(self):
        digest = "0" * 64
        for manifest in (
            f"{digest}  ../escape\\n",
            f"{digest}  safe\\n{digest}  safe\\n",
            f"{digest}  /absolute\\n",
        ):
            with self.subTest(manifest=manifest):
                with self.assertRaises(RuntimeError):
                    parse_release_manifest(manifest.encode("ascii"))


    def test_preflight_checks_authenticated_extracted_source(self):
        observed = []
        def inspect(source, destination):
            observed.append((source, destination))
            self.assertTrue((source / "requirements.txt").is_file())
            self.assertTrue(
                (source / "deployment/systemd/remediation-controller.service").is_file()
            )
            self.assertNotEqual(source.resolve(), ROOT.resolve())
            raise RuntimeError("Preflight inspection completed")
        with self.assertRaisesRegex(RuntimeError, "Preflight inspection completed"):
            publish_authenticated_release(
                self.archive, self.digest, self.destination, self.staging,
                preflight=inspect,
            )
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][1], self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_preflight_refuses_existing_destination(self):
        self.destination.mkdir(mode=0o700)
        marker = self.destination / "keep.txt"
        marker.write_text("preserve")
        def inspect(source, destination):
            self.assertTrue((source / "requirements.txt").is_file())
            if destination.exists():
                raise RuntimeError("Destination already exists")
        with self.assertRaisesRegex(RuntimeError, "Destination already exists"):
            publish_authenticated_release(
                self.archive, self.digest, self.destination, self.staging,
                preflight=inspect,
            )
        self.assertEqual(marker.read_text(), "preserve")
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_reproducible_package(self):
        second = self.root / "release-again.tar"
        count, digest = build_release(ROOT, self.revision, second)
        self.assertEqual(count, self.count)
        self.assertEqual(digest, self.digest)
        self.assertEqual(second.read_bytes(), self.archive.read_bytes())


if __name__ == "__main__":
    unittest.main()
