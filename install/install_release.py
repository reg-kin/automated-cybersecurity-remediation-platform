#!/usr/bin/env python3
"""Authenticate and validate an application release archive."""

import argparse
import tempfile
import hashlib
import os
import re
import stat
import tarfile
from pathlib import Path

from install_application import (
    INSTALL_DIRECTORIES,
    INSTALL_FILES,
    REQUIRED_FILES,
)



# Conservative limits for the initial application release format.
# These limits must be checked before extracting archive members.
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_RELEASE_FILES = 10000
MAX_MEMBER_BYTES = 128 * 1024 * 1024






def parse_release_manifest(manifest_bytes):
    """Parse a strict SHA256SUMS manifest into relative-path digests."""
    if len(manifest_bytes) > 1024 * 1024:
        raise RuntimeError("Release manifest exceeds maximum size.")

    try:
        manifest = manifest_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("Release manifest must be ASCII.") from error

    entries = {}

    for line in manifest.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  (.+)",
            line,
        )

        if not match:
            raise RuntimeError("Malformed release manifest entry.")

        digest, name = match.groups()
        path = Path(name)

        if (
            path.is_absolute()
            or "\\" in name
            or any(
                part in ("", ".", "..")
                for part in name.split("/")
            )
            or name in entries
        ):
            raise RuntimeError("Unsafe or duplicate manifest path.")

        entries[name] = digest

        if len(entries) > MAX_RELEASE_FILES:
            raise RuntimeError("Release manifest contains too many files.")

    if not entries:
        raise RuntimeError("Release manifest is empty.")

    return entries

def create_authenticated_snapshot(
    archive_path,
    expected_sha256,
    trusted_directory,
):
    """Copy and authenticate a release inside a private directory."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError("Invalid expected SHA-256 digest.")

    trusted_directory = Path(trusted_directory)

    metadata = trusted_directory.lstat()

    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("Snapshot directory is not a directory.")

    if metadata.st_mode & 0o077:
        raise RuntimeError(
            "Snapshot directory must not be accessible to group or others."
        )

    if metadata.st_uid != os.geteuid():
        raise RuntimeError(
            "Snapshot directory must be owned by the effective user."
        )

    descriptor = os.open(
        archive_path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )

    snapshot_path = None

    try:
        source_metadata = os.fstat(descriptor)

        if not stat.S_ISREG(source_metadata.st_mode):
            raise RuntimeError("Release source is not a regular file.")

        if source_metadata.st_size > MAX_ARCHIVE_BYTES:
            raise RuntimeError("Release archive exceeds maximum size.")

        output_descriptor, output_name = tempfile.mkstemp(
            prefix="authenticated-release-",
            suffix=".tar",
            dir=trusted_directory,
        )

        snapshot_path = Path(output_name)
        digest = hashlib.sha256()
        copied = 0

        try:
            with os.fdopen(
                descriptor, "rb", closefd=False
            ) as source:
                with os.fdopen(output_descriptor, "wb") as target:
                    while True:
                        block = source.read(1024 * 1024)

                        if not block:
                            break

                        copied += len(block)

                        if copied > MAX_ARCHIVE_BYTES:
                            raise RuntimeError(
                                "Release archive exceeds maximum size."
                            )

                        digest.update(block)
                        target.write(block)

                    target.flush()
                    os.fsync(target.fileno())

            if digest.hexdigest() != expected_sha256:
                raise RuntimeError("Release archive SHA-256 mismatch.")

            return snapshot_path

        except BaseException:
            snapshot_path.unlink(missing_ok=True)
            raise

    finally:
        os.close(descriptor)



def extract_authenticated_release(
    snapshot_path,
    expected_sha256,
    staging_parent,
):
    """Extract an authenticated release into a new private staging directory."""
    import shutil

    staging_parent = Path(staging_parent)
    metadata = staging_parent.lstat()

    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise RuntimeError("Untrusted staging parent directory.")

    staging = Path(tempfile.mkdtemp(
        prefix="release-extraction-",
        dir=staging_parent,
    ))

    try:
        private_archive = create_authenticated_snapshot(
            snapshot_path,
            expected_sha256,
            staging,
        )

        descriptor = os.open(
            private_archive,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        )

        try:
            archive_metadata = os.fstat(descriptor)

            if not stat.S_ISREG(archive_metadata.st_mode):
                raise RuntimeError(
                    "Private release archive is not a regular file."
                )

            if archive_metadata.st_size > MAX_ARCHIVE_BYTES:
                raise RuntimeError(
                    "Private release archive exceeds maximum size."
                )

            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                digest = hashlib.sha256()

                for block in iter(
                    lambda: stream.read(1024 * 1024), b""
                ):
                    digest.update(block)

                if digest.hexdigest() != expected_sha256:
                    raise RuntimeError(
                        "Private release archive SHA-256 mismatch."
                    )

                stream.seek(0)

                expected_count = _verify_release_stream(
                    stream,
                    expected_sha256,
                )

                stream.seek(0)

                application = staging / "application"
                application.mkdir(mode=0o700)

                actual_digests = {}
                extracted_bytes = 0

                with tarfile.open(
                    fileobj=stream,
                    mode="r:",
                ) as archive:
                    members = archive.getmembers()

                    manifest_members = [
                        member for member in members
                        if member.name == "SHA256SUMS"
                    ]

                    if len(manifest_members) != 1:
                        raise RuntimeError("Invalid release manifest count.")

                    manifest_member = manifest_members[0]

                    if (
                        not manifest_member.isfile()
                        or manifest_member.size > 1024 * 1024
                    ):
                        raise RuntimeError("Invalid release manifest.")

                    manifest_stream = archive.extractfile(manifest_member)

                    if manifest_stream is None:
                        raise RuntimeError("Release manifest unreadable.")

                    expected_digests = parse_release_manifest(
                        manifest_stream.read(1024 * 1024 + 1)
                    )

                    for member in members:
                        if member.name == "SHA256SUMS":
                            continue

                        if not member.isfile():
                            if member.isdir():
                                continue
                            raise RuntimeError("Unsupported archive member.")

                        if not member.name.startswith("application/"):
                            raise RuntimeError("Unexpected archive member.")

                        relative = member.name[len("application/"):]

                        if relative not in expected_digests:
                            raise RuntimeError(
                                f"File absent from release manifest: {relative}"
                            )

                        if relative in actual_digests:
                            raise RuntimeError("Duplicate extracted file.")

                        target = application / relative
                        target.parent.mkdir(
                            parents=True,
                            exist_ok=True,
                            mode=0o700,
                        )

                        source = archive.extractfile(member)

                        if source is None:
                            raise RuntimeError("Archive member unreadable.")

                        digest = hashlib.sha256()
                        written = 0

                        with target.open("xb") as output:
                            while True:
                                block = source.read(1024 * 1024)

                                if not block:
                                    break

                                written += len(block)
                                extracted_bytes += len(block)

                                if (
                                    written > MAX_MEMBER_BYTES
                                    or extracted_bytes > MAX_EXTRACTED_BYTES
                                    or written > member.size
                                ):
                                    raise RuntimeError(
                                        "Extracted data exceeds permitted limits."
                                    )

                                digest.update(block)
                                output.write(block)

                        if written != member.size:
                            raise RuntimeError("Archive member size mismatch.")

                        actual_digests[relative] = digest.hexdigest()

                        if actual_digests[relative] != expected_digests[relative]:
                            raise RuntimeError(
                                f"Release file checksum mismatch: {relative}"
                            )

        finally:
            os.close(descriptor)

        if actual_digests != expected_digests:
            raise RuntimeError("Release manifest file set mismatch.")

        if len(actual_digests) != expected_count:
            raise RuntimeError("Release file count mismatch.")

        private_archive.unlink()

        return application, len(actual_digests)

    except BaseException:
        shutil.rmtree(staging)
        raise

def authenticate_release(archive_path, expected_sha256):
    """Verify the complete archive before accepting its contents."""
    archive_path = Path(archive_path)

    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError(
            "Expected SHA-256 must contain exactly 64 lowercase hex characters."
        )

    descriptor = os.open(
        archive_path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )

    try:
        metadata = os.fstat(descriptor)

        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Release archive is not a regular file.")

        digest = hashlib.sha256()

        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for block in iter(
                lambda: source.read(1024 * 1024), b""
            ):
                digest.update(block)

        actual_sha256 = digest.hexdigest()

    finally:
        os.close(descriptor)

    if actual_sha256 != expected_sha256:
        raise RuntimeError("Release archive SHA-256 mismatch.")

    return actual_sha256


def validate_release_members(archive_path):
    """Reject unexpected archive members and unsafe file types."""
    archive_path = Path(archive_path)

    permitted_roots = set(INSTALL_DIRECTORIES)
    permitted_files = set(INSTALL_FILES)

    names = set()
    application_files = set()
    manifest_found = False

    with tarfile.open(archive_path, "r") as archive:
        for member in archive:
            name = member.name
            path = Path(name)

            if (
                not name
                or path.is_absolute()
                or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or not (member.isfile() or member.isdir())
                or name in names
            ):
                raise RuntimeError(
                    f"Unsafe release archive member: {name}"
                )

            names.add(name)

            if name == "SHA256SUMS":
                if not member.isfile():
                    raise RuntimeError("Invalid release manifest.")
                manifest_found = True
                continue

            if not name.startswith("application/"):
                raise RuntimeError(
                    f"Unexpected release archive member: {name}"
                )

            relative = name[len("application/"):]
            parts = Path(relative).parts

            if not parts:
                raise RuntimeError("Invalid application member.")

            if (
                parts[0] not in permitted_roots
                and relative not in permitted_files
            ):
                raise RuntimeError(
                    f"Unexpected application file: {relative}"
                )

            if member.isfile():
                application_files.add(relative)

    if not manifest_found:
        raise RuntimeError("Release manifest is missing.")

    missing = sorted(
        set(REQUIRED_FILES) - application_files
    )

    if missing:
        raise RuntimeError(
            f"Required application files missing: {missing}"
        )

    return len(application_files)



def _verify_release_stream(source, expected_sha256):
    """Validate an authenticated release stream."""
    permitted_roots = set(INSTALL_DIRECTORIES)
    permitted_files = set(INSTALL_FILES)

    names = set()
    application_files = set()
    manifest_found = False
    manifest_entries = None
    regular_file_names = set()
    total_extracted_bytes = 0
    file_count = 0

    with tarfile.open(fileobj=source, mode="r:") as archive:
        for member in archive:
            if member.isfile():
                file_count += 1
                total_extracted_bytes += member.size

                if member.size > MAX_MEMBER_BYTES:
                    raise RuntimeError(
                        "Release member exceeds maximum size."
                    )

                if file_count > MAX_RELEASE_FILES:
                    raise RuntimeError(
                        "Release contains too many files."
                    )

                if total_extracted_bytes > MAX_EXTRACTED_BYTES:
                    raise RuntimeError(
                        "Release exceeds extracted-data limit."
                    )

            name = member.name
            path = Path(name)

            if (
                not name
                or path.is_absolute()
                or "\\\\" in name
                or any(
                    part in ("", ".", "..")
                    for part in name.split("/")
                )
                or not (member.isfile() or member.isdir())
                or name in names
            ):
                raise RuntimeError(
                    f"Unsafe release member: {name}"
                )

            names.add(name)

            if member.isfile():
                regular_file_names.add(name)

            if name == "SHA256SUMS":
                if not member.isfile():
                    raise RuntimeError("Invalid release manifest.")

                if member.size > 1024 * 1024:
                    raise RuntimeError("Release manifest too large.")

                stream = archive.extractfile(member)

                if stream is None:
                    raise RuntimeError("Release manifest unreadable.")

                manifest_entries = parse_release_manifest(
                    stream.read(1024 * 1024 + 1)
                )

                manifest_found = True
                continue

            if not name.startswith("application/"):
                raise RuntimeError(
                    f"Unexpected release member: {name}"
                )

            relative = name[len("application/"):]
            parts = Path(relative).parts

            if not parts or (
                parts[0] not in permitted_roots
                and relative not in permitted_files
            ):
                raise RuntimeError(
                    f"Unexpected application file: {relative}"
                )

            if member.isfile():
                application_files.add(relative)

    if not manifest_found:
        raise RuntimeError("Release manifest missing.")

    for name in names:
        parts = name.split("/")

        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])

            if parent in names and parent in regular_file_names:
                raise RuntimeError(
                    f"Regular file used as directory: {parent}"
                )

    if manifest_entries is None:
        raise RuntimeError("Release manifest unreadable.")

    if set(manifest_entries) != application_files:
        raise RuntimeError(
            "Release manifest file set mismatch."
        )

    missing = sorted(
        set(REQUIRED_FILES) - application_files
    )

    if missing:
        raise RuntimeError(
            f"Required application files missing: {missing}"
        )

    return len(application_files)


def verify_release(archive_path, expected_sha256):
    """Authenticate and validate an archive through one open descriptor."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError("Invalid expected SHA-256 digest.")

    descriptor = os.open(
        archive_path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )

    try:
        metadata = os.fstat(descriptor)

        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Release archive is not a regular file.")

        if metadata.st_size > MAX_ARCHIVE_BYTES:
            raise RuntimeError("Release archive exceeds maximum size.")

        with os.fdopen(descriptor, "rb", closefd=False) as source:
            digest = hashlib.sha256()

            for block in iter(
                lambda: source.read(1024 * 1024), b""
            ):
                digest.update(block)

            if digest.hexdigest() != expected_sha256:
                raise RuntimeError("Release archive SHA-256 mismatch.")

            source.seek(0)

            return _verify_release_stream(
                source,
                expected_sha256,
            )

    finally:
        os.close(descriptor)


def stage_verified_application(
    extracted_application,
    staging_parent,
):
    """Copy an extracted release into a private, verified staging area."""
    from install_application import (
        copy_application_files,
        generate_release_manifest,
        verify_release_manifest,
    )

    extracted_application = Path(extracted_application).resolve(
        strict=True
    )
    staging_parent = Path(staging_parent)

    parent_metadata = staging_parent.lstat()

    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise RuntimeError("Application staging parent is not a directory.")

    if parent_metadata.st_uid != os.geteuid():
        raise RuntimeError("Application staging parent owner mismatch.")

    if parent_metadata.st_mode & 0o077:
        raise RuntimeError(
            "Application staging parent must deny group and other access."
        )

    import shutil

    staging = Path(
        tempfile.mkdtemp(
            prefix="application-install-",
            dir=staging_parent,
        )
    )

    try:
        # Establish the reference digests from the authenticated
        # extracted application, before copying any files.
        reference_directory = staging / "reference"
        reference_directory.mkdir(mode=0o700)

        # Generate reference digests from the authenticated source
        # without modifying the extracted application directory.
        reference_manifest, reference_count = generate_release_manifest(
            extracted_application,
            output_path=reference_directory / "SHA256SUMS",
        )

        destination = staging / "application"

        count = copy_application_files(
            extracted_application,
            destination,
        )

        # The published directory must remain private until
        # installation ownership and permissions are configured.
        destination_metadata = destination.lstat()

        if not stat.S_ISDIR(destination_metadata.st_mode):
            raise RuntimeError(
                "Staged application is not a directory."
            )

        if destination_metadata.st_uid != os.geteuid():
            raise RuntimeError(
                "Staged application owner mismatch."
            )

        destination.chmod(0o700)

        if count != reference_count:
            raise RuntimeError(
                "Staged application file count mismatch."
            )

        verified_count = verify_release_manifest(
            destination,
            reference_manifest,
        )

        if verified_count != count:
            raise RuntimeError(
                "Staged application file count mismatch."
            )

        return destination, verified_count

    except BaseException:
        shutil.rmtree(staging)
        raise



def publish_staged_application(staged_application, destination):
    """Publish using pinned parent directories and no-replace semantics."""
    import ctypes

    staged_application = Path(staged_application)
    destination = Path(destination)

    if not staged_application.is_absolute():
        raise RuntimeError("Staged application path must be absolute.")

    if not destination.is_absolute():
        raise RuntimeError("Publication destination must be absolute.")

    if staged_application.name in ("", ".", ".."):
        raise RuntimeError("Invalid staged application name.")

    if destination.name in ("", ".", ".."):
        raise RuntimeError("Invalid publication destination name.")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    source_parent_fd = os.open(staged_application.parent, flags)

    try:
        destination_parent_fd = os.open(destination.parent, flags)

        try:
            source_parent_stat = os.fstat(source_parent_fd)
            destination_parent_stat = os.fstat(destination_parent_fd)

            if source_parent_stat.st_uid != os.geteuid():
                raise RuntimeError("Staging parent owner mismatch.")

            if destination_parent_stat.st_uid != os.geteuid():
                raise RuntimeError("Publication parent owner mismatch.")

            if source_parent_stat.st_mode & 0o077:
                raise RuntimeError(
                    "Staging parent must deny group and other access."
                )

            if destination_parent_stat.st_mode & 0o022:
                raise RuntimeError(
                    "Publication parent must deny group and other write access."
                )

            if source_parent_stat.st_dev != destination_parent_stat.st_dev:
                raise RuntimeError(
                    "Staging and publication must share a filesystem."
                )

            source_stat = os.stat(
                staged_application.name,
                dir_fd=source_parent_fd,
                follow_symlinks=False,
            )

            if not stat.S_ISDIR(source_stat.st_mode):
                raise RuntimeError("Staged application is not a directory.")

            if source_stat.st_uid != os.geteuid():
                raise RuntimeError("Staged application owner mismatch.")

            if source_stat.st_mode & 0o077:
                raise RuntimeError(
                    "Staged application must deny group and other access."
                )

            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = getattr(libc, "renameat2", None)

            if renameat2 is None:
                raise RuntimeError(
                    "Linux renameat2 unavailable; publication refused."
                )

            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int

            RENAME_NOREPLACE = 1

            result = renameat2(
                source_parent_fd,
                os.fsencode(staged_application.name),
                destination_parent_fd,
                os.fsencode(destination.name),
                RENAME_NOREPLACE,
            )

            if result != 0:
                error_number = ctypes.get_errno()
                raise OSError(
                    error_number,
                    os.strerror(error_number),
                    str(destination),
                )

            return destination

        finally:
            os.close(destination_parent_fd)

    finally:
        os.close(source_parent_fd)




def publish_authenticated_release(
    archive_path,
    expected_sha256,
    destination,
    staging_parent,
    preflight=None,
):
    """Authenticate, stage, verify and exclusively publish an application."""
    from install_application import verify_release_manifest

    import shutil

    destination = Path(destination)
    staging_parent = Path(staging_parent)

    if not staging_parent.is_absolute():
        raise RuntimeError(
            "Installation staging parent must be an absolute path."
        )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    parent_fd = os.open(staging_parent, flags)

    try:
        parent_metadata = os.fstat(parent_fd)

        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise RuntimeError(
                "Installation staging parent is not a directory."
            )

        if parent_metadata.st_uid != os.geteuid():
            raise RuntimeError(
                "Installation staging parent owner mismatch."
            )

        if parent_metadata.st_mode & 0o077:
            raise RuntimeError(
                "Installation staging parent must deny group and other access."
            )

        extraction_root = Path(
            tempfile.mkdtemp(
                prefix="release-install-",
                dir=f"/proc/self/fd/{parent_fd}",
            )
        ).resolve(strict=True)

    finally:
        os.close(parent_fd)

    try:
        extraction_parent = extraction_root / "extraction"
        application_parent = extraction_root / "application-staging"

        extraction_parent.mkdir(mode=0o700)
        application_parent.mkdir(mode=0o700)

        extracted_application, extracted_count = (
            extract_authenticated_release(
                archive_path,
                expected_sha256,
                extraction_parent,
            )
        )

        if preflight is not None:
            preflight(extracted_application, destination)

        staged_application, staged_count = (
            stage_verified_application(
                extracted_application,
                application_parent,
            )
        )

        if staged_count != extracted_count:
            raise RuntimeError(
                "Extracted and staged application file counts differ."
            )

        reference_manifest = (
            staged_application.parent / "reference" / "SHA256SUMS"
        )

        verified_count = verify_release_manifest(
            staged_application,
            reference_manifest,
        )

        if verified_count != extracted_count:
            raise RuntimeError(
                "Pre-publication application verification failed."
            )

        result = publish_staged_application(
            staged_application,
            destination,
        )

        return result, verified_count

    finally:
        shutil.rmtree(extraction_root)


def install_authenticated_application(
    archive_path,
    expected_sha256,
    destination,
    staging_parent,
):
    """Apply production preflight before authenticated publication."""
    from install_application import validate_installation_source

    destination = Path(destination)

    return publish_authenticated_release(
        archive_path,
        expected_sha256,
        destination,
        staging_parent,
        preflight=validate_installation_source,
    )



def main():
    parser = argparse.ArgumentParser(
        description="Authenticate an application release archive."
    )

    parser.add_argument("--archive", required=True)
    parser.add_argument("--sha256", required=True)

    args = parser.parse_args()

    count = verify_release(
        args.archive,
        args.sha256,
    )

    print(f"PASS: Release archive SHA-256 verified: {args.sha256}")
    print(f"PASS: Release structure validated: {count} files")
    print("VALIDATION ONLY: No installation performed.")


if __name__ == "__main__":
    main()
