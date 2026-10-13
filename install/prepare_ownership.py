#!/usr/bin/env python3
"""Fail-closed ownership preparation for a private, staged application.

This component never changes a live installation or invokes systemd.
"""
import os
import stat
from pathlib import Path
from venv_link_safety import validate_venv_interpreter_link


def prepare_staged_application_ownership(application, uid, gid):
    """Assign ownership to a private tree using no-follow descriptor operations.

    Only a caller-owned, mode-0700 directory is eligible. All descendants are
    inspected before mutation; symlinks are permitted only for the Python\n    virtual environment interpreter pointing to a trusted system interpreter.\n    Symlinks are never followed for ownership changes.
    The staged root remains private after preparation. This is intentionally
    not a recursive chown helper for arbitrary paths.
    """
    application = Path(application)
    if not application.is_absolute() or application.is_symlink():
        raise RuntimeError("Application must be an absolute non-symlink directory.")
    if not isinstance(uid, int) or not isinstance(gid, int) or uid < 0 or gid < 0:
        raise RuntimeError("Invalid service identity.")
    root_fd = os.open(application, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_stat = os.fstat(root_fd)
        if root_stat.st_uid != os.geteuid() or root_stat.st_mode & 0o077:
            raise RuntimeError("Staged application must be caller-owned and private.")
        entries = []
        for current, dirs, files in os.walk(application, topdown=True, followlinks=False):
            for name in dirs + files:
                path = Path(current) / name
                metadata = path.lstat()
                if metadata.st_dev != root_stat.st_dev:
                    raise RuntimeError("Staged application crosses filesystem boundary.")
                if metadata.st_uid != os.geteuid():
                    raise RuntimeError("Staged application contains foreign-owned files.")
                if stat.S_ISLNK(metadata.st_mode):
                    # Standard venv interpreter links may be absolute or relative.
                    # Do not chown links or follow their targets. The caller must
                    # separately validate the venv interpreter before execution.
                    if path.parent != application / "venv" / "bin" or name not in (
                        "python", "python3", "python3.12"
                    ):
                        raise RuntimeError("Staged application contains unexpected symlink.")
                    validate_venv_interpreter_link(application, path)
                    continue
                if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                    raise RuntimeError("Staged application contains unsafe filesystem entry.")
                entries.append((path, metadata.st_dev, metadata.st_ino, stat.S_ISDIR(metadata.st_mode)))
        for path, device, inode, directory in entries:
            flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
            fd = os.open(path, flags)
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) != (device, inode):
                    raise RuntimeError("Staged application changed during ownership preparation.")
                os.fchown(fd, uid, gid)
            finally:
                os.close(fd)
        os.fchown(root_fd, uid, gid)
        return len(entries) + 1
    finally:
        os.close(root_fd)
