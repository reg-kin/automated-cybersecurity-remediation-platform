#!/usr/bin/env python3
"""Fail-closed offline provisioning of service unit files.

Only creates files in explicitly supplied destination directories; no systemctl
invocation, enablement, startup, account creation, or package installation.
"""
import os
import stat
from pathlib import Path

from service_provisioning import inspect_service_provisioning


def provision_service_units(source, destination, uid, gid, *, native=False):
    """Copy validated service/timer manifests exclusively, preserving existing files.

    Destination must be a caller-owned, non-symlink directory. A pre-existing
    destination unit is a hard failure before any writes.
    """
    source = Path(source).resolve(strict=True)
    destination = Path(destination)
    inventory = inspect_service_provisioning(source, native=native)
    if not destination.is_absolute():
        raise RuntimeError("Unit destination must be absolute.")
    parent_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent_fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise RuntimeError("Unit destination owner or permissions unsafe.")
        names = inventory["unit_names"]
        for name in names:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RuntimeError(f"Existing systemd unit must not be overwritten: {name}")
        created = []
        try:
            for name in names:
                source_path = source / "deployment/systemd" / name
                if name in ("ansible-runner.service", "verification-gateway.service"):
                    source_path = source / "deployment/systemd/native" / name
                source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    source_metadata = os.fstat(source_fd)
                    if not stat.S_ISREG(source_metadata.st_mode):
                        raise RuntimeError(f"Unsafe unit source: {name}")
                    target_fd = os.open(
                        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=parent_fd,
                    )
                    created.append((name, os.fstat(target_fd)))
                    try:
                        with os.fdopen(source_fd, "rb", closefd=False) as inp:
                            with os.fdopen(target_fd, "wb", closefd=False) as out:
                                while True:
                                    block = inp.read(65536)
                                    if not block:
                                        break
                                    out.write(block)
                                out.flush()
                                os.fchmod(target_fd, 0o644)
                                os.fchown(target_fd, uid, gid)
                    finally:
                        os.close(target_fd)
                finally:
                    os.close(source_fd)
            return names
        except BaseException:
            for name, identity in reversed(created):
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                        os.unlink(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            raise
    finally:
        os.close(parent_fd)
