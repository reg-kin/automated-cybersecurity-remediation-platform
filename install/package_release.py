#!/usr/bin/env python3
"""Build a reproducible application release from a committed Git revision."""

import argparse
import hashlib
import io
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from install_application import (
    stage_application_files,
    verify_release_manifest,
)


def build_release(repository, revision, output):
    repository = Path(repository).resolve()
    output = Path(output).absolute()

    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("A full 40-character Git commit SHA is required.")

    if output.exists() or output.is_symlink():
        raise RuntimeError(f"Release output already exists: {output}")

    resolved = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "--verify",
         f"{revision}^{{commit}}"],
        text=True,
    ).strip()

    if resolved != revision:
        raise RuntimeError("Git revision does not match the requested commit.")

    with tempfile.TemporaryDirectory(
        prefix="remediation-release-build-"
    ) as temporary:
        root = Path(temporary)
        archive = root / "source.tar"
        extracted = root / "source"
        extracted.mkdir()

        with archive.open("wb") as stream:
            subprocess.run(
                ["git", "-C", str(repository), "archive",
                 "--format=tar", revision],
                stdout=stream,
                check=True,
            )

        with tarfile.open(archive, "r") as source_archive:
            members = source_archive.getmembers()

            for member in members:
                path = Path(member.name)

                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not (member.isfile() or member.isdir())
                ):
                    raise RuntimeError(
                        f"Unsafe archive member: {member.name}"
                    )

            source_archive.extractall(
                extracted,
                members=members,
                filter="data",
            )

        staging = root / "stage"
        application, count = stage_application_files(
            extracted, staging
        )

        manifest = staging / "SHA256SUMS"
        verify_release_manifest(application, manifest)

        temporary_output = root / "release.tar"

        with tarfile.open(temporary_output, "w") as package:
            for file in sorted(application.rglob("*")):
                if not file.is_file():
                    continue

                relative = Path("application") / file.relative_to(
                    application
                )

                info = tarfile.TarInfo(relative.as_posix())
                info.size = file.stat().st_size
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""

                with file.open("rb") as stream:
                    package.addfile(info, stream)

            data = manifest.read_bytes()
            info = tarfile.TarInfo("SHA256SUMS")
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""

            package.addfile(info, io.BytesIO(data))

        digest = hashlib.sha256(
            temporary_output.read_bytes()
        ).hexdigest()

        # Publish only a fully written archive. The temporary file and
        # final output must share a filesystem for atomic hard linking.
        temporary_path = None

        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".remediation-release-",
                suffix=".tmp",
                dir=output.parent,
            )
            temporary_path = Path(temporary_name)

            with os.fdopen(descriptor, "wb") as destination:
                with temporary_output.open("rb") as source:
                    for block in iter(
                        lambda: source.read(1024 * 1024), b""
                    ):
                        destination.write(block)

                destination.flush()
                os.fsync(destination.fileno())

            os.chmod(temporary_path, 0o644)

            # Atomic publication without replacing an existing file.
            os.link(temporary_path, output, follow_symlinks=False)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    return count, digest


def main():
    parser = argparse.ArgumentParser(
        description="Package a committed application release."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    count, digest = build_release(
        args.repository,
        args.revision,
        args.output,
    )

    print(f"PASS: Packaged {count} application files.")
    print(f"SHA-256: {digest}")
    print(f"Release: {args.output}")


if __name__ == "__main__":
    main()
