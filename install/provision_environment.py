#!/usr/bin/env python3
"""Offline, exclusive environment-file provisioning with rollback.

Does not start services, load configuration, or interact with systemd.
"""
import os
import stat
from pathlib import Path

from install_application import environment_templates


def provision_environment_files(source, destinations, uid, gid, *, native=False):
    """Provision the exact declared template set to caller-provided paths.

    destinations maps the canonical /etc paths to isolated or production paths.
    Every destination must have an existing, trusted parent; all targets must
    be absent before any write. No credentials are generated.
    """
    templates = environment_templates(native=native)
    source = Path(source).resolve(strict=True)
    if set(destinations) != set(templates):
        raise RuntimeError("Environment destination mapping must be complete and exact.")
    prepared = []
    seen = set()
    for canonical, relative in sorted(templates.items()):
        template = source / relative
        if template.is_symlink() or not template.is_file():
            raise RuntimeError(f"Missing safe environment template: {relative}")
        destination = Path(destinations[canonical])
        if not destination.is_absolute() or destination in seen:
            raise RuntimeError("Invalid or duplicate environment destination.")
        seen.add(destination)
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(parent_fd)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                raise RuntimeError(f"Unsafe environment destination parent: {destination.parent}")
            try:
                os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError(f"Environment destination already exists: {destination}")
        finally:
            os.close(parent_fd)
        prepared.append((template, destination))
    created = []
    try:
        for template, destination in prepared:
            template_fd = os.open(template, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                if not stat.S_ISREG(os.fstat(template_fd).st_mode):
                    raise RuntimeError(f"Unsafe environment template: {template}")
                parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    target_fd = os.open(
                        destination.name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=parent_fd,
                    )
                    created.append((destination, os.fstat(target_fd)))
                    try:
                        with os.fdopen(template_fd, "rb", closefd=False) as inp:
                            with os.fdopen(target_fd, "wb", closefd=False) as out:
                                while True:
                                    chunk = inp.read(65536)
                                    if not chunk:
                                        break
                                    out.write(chunk)
                                out.flush()
                                os.fchmod(target_fd, 0o640)
                                os.fchown(target_fd, uid, gid)
                    finally:
                        os.close(target_fd)
                finally:
                    os.close(parent_fd)
            finally:
                os.close(template_fd)
        return [destination for _, destination in prepared]
    except BaseException:
        for destination, identity in reversed(created):
            try:
                metadata = destination.lstat()
                if (metadata.st_dev, metadata.st_ino) == (identity.st_dev, identity.st_ino):
                    destination.unlink()
            except FileNotFoundError:
                pass
        raise
