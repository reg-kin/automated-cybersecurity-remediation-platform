"""Local regression checks for the database and release file manifests."""
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'install'))
import database
from install_application import (
    INSTALL_DIRECTORIES, INSTALL_FILES, REQUIRED_FILES, copy_application_files,
)
from install_release import publish_authenticated_release, validate_release_members
from package_release import build_release


class ReleaseManifestTests(unittest.TestCase):
    def test_smoke_uses_ordered_installer_manifest_through_025(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        start = script.index('# Read the installer')
        end = script.index('\ncleanup()', start)
        snippet = script[start:end]
        result = subprocess.run(
            ['bash', '-c', snippet + '\nprintf "%s\\n" "${SQL_FILES[@]}"'],
            env={'PYTHON': sys.executable, 'ROOT_DIR': str(ROOT)},
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.splitlines(), database.SQL_FILES)
        self.assertEqual(len(database.SQL_FILES), 25)
        self.assertTrue(database.SQL_FILES[-1].startswith('database/migrations/025_'))

    def test_smoke_manifest_failure_stops_before_database_work(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        snippet = script[script.index('# Read the installer'):script.index('\ncleanup()')]
        result = subprocess.run(
            ['bash', '-c', snippet + '\necho SHOULD_NOT_RUN'],
            env={'PYTHON': '/bin/false', 'ROOT_DIR': str(ROOT)},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('SHOULD_NOT_RUN', result.stdout)

    def build_fixture(self, root, guide=True):
        source = root / 'source'
        source.mkdir()
        for directory in INSTALL_DIRECTORIES:
            (source / directory).mkdir()
            (source / directory / 'fixture.txt').write_text('fixture\n')
        for name in set(INSTALL_FILES) | set(REQUIRED_FILES):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n')
        docs = source / 'docs'
        docs.mkdir()
        (docs / 'unrelated.md').write_text('excluded\n')
        (source / 'deployment' / 'excluded.key').write_text('synthetic excluded fixture\n')
        if guide:
            target = docs / 'UBUNTU_NATIVE_DEPLOYMENT.md'
            target.write_text('native deployment guide\n')
        def archive_source(args, stdout, check):
            with tarfile.open(fileobj=stdout, mode='w') as archive:
                for path in sorted(source.rglob('*')):
                    archive.add(path, arcname=str(path.relative_to(source)), recursive=False)
        revision = 'a' * 40
        output = root / 'release.tar'
        with patch('package_release.subprocess.check_output', return_value=revision), \
                patch('package_release.subprocess.run', side_effect=archive_source):
            count, digest = build_release(source, revision, output)
        return output, count, digest

    def test_guide_packaged_verified_and_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, count, digest = self.build_fixture(root)
            self.assertEqual(validate_release_members(archive), count)
            with tarfile.open(archive) as package:
                names = package.getnames()
                guide = 'application/docs/UBUNTU_NATIVE_DEPLOYMENT.md'
                self.assertIn(guide, names)
                self.assertNotIn('application/docs/unrelated.md', names)
                self.assertNotIn('application/deployment/excluded.key', names)
                content = package.extractfile(guide).read()
                manifest = package.extractfile('SHA256SUMS').read().decode()
                self.assertIn(hashlib.sha256(content).hexdigest() + '  docs/UBUNTU_NATIVE_DEPLOYMENT.md', manifest)
                members = [(member, package.extractfile(member).read()) for member in package]
            staging = root / 'staging'
            staging.mkdir(mode=0o700)
            destination, installed = publish_authenticated_release(
                archive, digest, root / 'application', staging)
            self.assertEqual(installed, count)
            self.assertEqual((destination / 'docs/UBUNTU_NATIVE_DEPLOYMENT.md').read_bytes(), content)
            altered = root / 'altered.tar'
            with tarfile.open(altered, 'w') as package:
                for member, payload in members:
                    if member.name == guide:
                        payload = b'altered guide\n'
                        member.size = len(payload)
                    package.addfile(member, io.BytesIO(payload))
            with self.assertRaises(RuntimeError):
                publish_authenticated_release(altered, hashlib.sha256(altered.read_bytes()).hexdigest(), root / 'rejected', staging)
            self.assertFalse((root / 'rejected').exists())

    def test_guide_and_docs_directory_symlinks_are_excluded(self):
        for link_parent in (False, True):
            with self.subTest(link_parent=link_parent), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.build_fixture(root, guide=False)
                source = root / 'source'
                docs = source / 'docs'
                if link_parent:
                    docs.rename(root / 'external-docs')
                    (root / 'external-docs/UBUNTU_NATIVE_DEPLOYMENT.md').write_text('fixture')
                    docs.symlink_to(root / 'external-docs', target_is_directory=True)
                else:
                    (docs / 'UBUNTU_NATIVE_DEPLOYMENT.md').symlink_to(docs / 'unrelated.md')
                destination = root / 'copied'
                copy_application_files(source, destination)
                self.assertFalse((destination / 'docs').exists())

    def test_older_source_without_guide_still_packages_and_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, count, digest = self.build_fixture(root, guide=False)
            self.assertEqual(validate_release_members(archive), count)
            staging = root / 'staging'
            staging.mkdir(mode=0o700)
            destination, installed = publish_authenticated_release(archive, digest, root / 'application', staging)
            self.assertEqual(installed, count)
            self.assertFalse((destination / 'docs').exists())


if __name__ == '__main__':
    unittest.main()
