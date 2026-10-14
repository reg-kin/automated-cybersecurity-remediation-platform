#!/usr/bin/env python3
"""Fail-closed production installation plan; never activates services.

This entry point deliberately performs validation only. Publication, ownership,
dependency installation, and systemd activation require a separate reviewed
privileged deployment transaction.
"""
import argparse
import os
import stat
from pathlib import Path

from install_application import DEFAULT_DESTINATION, validate_installation_source
from install_release import publish_authenticated_release, verify_release


def validate_staging_parent(path):
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError("Staging parent must be an absolute path.")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise RuntimeError("Staging parent must be owned by caller and mode 0700.")
    finally:
        os.close(fd)
    return path


def validate_production_release(archive, sha256, destination, staging_parent):
    """Validate archive and target without publishing or changing configuration."""
    destination = Path(destination)
    if destination != DEFAULT_DESTINATION:
        raise RuntimeError("Unsupported installation destination.")
    validate_staging_parent(staging_parent)
    count = verify_release(archive, sha256)
    return count


def publish_production_release(archive, sha256, destination, staging_parent):
    """Publish authenticated application only; no service installation or activation.

    Requires explicit opt-in from the caller, which must arrange privileged
    ownership/configuration/dependency provisioning in a later reviewed phase.
    """
    validate_production_release(archive, sha256, destination, staging_parent)
    return publish_authenticated_release(
        archive, sha256, Path(destination), Path(staging_parent),
        preflight=validate_installation_source,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate or publish an authenticated release.")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--destination", default=str(DEFAULT_DESTINATION))
    parser.add_argument("--staging-parent", required=True)
    parser.add_argument("--publish-application-only", action="store_true")
    parser.add_argument("--confirm-destination")
    args = parser.parse_args(argv)

    if args.publish_application_only:
        if args.confirm_destination != args.destination:
            parser.error("--confirm-destination must exactly match --destination")
        destination, count = publish_production_release(
            args.archive, args.sha256, args.destination, args.staging_parent
        )
        print(f"PASS: Authenticated application published: {destination} ({count} files)")
        print("NOT CONFIGURED: No environment, ownership, dependencies or systemd changes.")
    else:
        count = validate_production_release(
            args.archive, args.sha256, args.destination, args.staging_parent
        )
        print(f"PASS: Release archive verified: {count} files")
        print("VALIDATION ONLY: No installation or service changes performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
