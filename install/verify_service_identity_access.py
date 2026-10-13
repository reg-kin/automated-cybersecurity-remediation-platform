#!/usr/bin/env python3
"""Read-only runtime access verification for the intended service identity.

No privilege switching, systemctl invocation, or access to production services.
"""
import os
import stat
from pathlib import Path

from install_application import ENVIRONMENT_FILE_TEMPLATES
from service_provisioning import inspect_service_provisioning


def _permission(meta, uid, gid, owner_bit, group_bit, other_bit):
    # POSIX DAC selects exactly one class: owner, else group, else other.
    # Combining classes with OR would incorrectly grant owner access through
    # group/other bits when the owner permission itself is absent.
    mode = stat.S_IMODE(meta.st_mode)
    if meta.st_uid == uid:
        return bool(mode & owner_bit)
    if meta.st_gid == gid:
        return bool(mode & group_bit)
    return bool(mode & other_bit)


def _can_read(meta, uid, gid):
    return _permission(meta, uid, gid, stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH)


def _can_traverse(meta, uid, gid):
    return _permission(meta, uid, gid, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH)


def _verify_path_traversal(path, uid, gid):
    # The runtime identity must be able to traverse every parent, not just
    # the application root. This deliberately does not resolve symlinks.
    for parent in reversed(path.parents):
        metadata = parent.stat()
        if not stat.S_ISDIR(metadata.st_mode) or not _can_traverse(metadata, uid, gid):
            raise RuntimeError(f"Service account cannot traverse parent: {parent}")


def _can_execute(meta, uid, gid):
    return _permission(meta, uid, gid, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH)


def verify_service_identity_access(application, environment_destinations, *, uid, gid):
    """Check staged files can be read/traversed by uid/gid, not only owned.

    This is a static POSIX mode check; ACLs, LSM policies, supplemental
    groups, parent directories outside the app and actual execution must
    still be verified on the target host.
    """
    app = Path(application)
    if not app.is_absolute() or app.is_symlink():
        raise RuntimeError("Unsafe staged application path.")
    if set(environment_destinations) != set(ENVIRONMENT_FILE_TEMPLATES):
        raise RuntimeError("Incomplete service environment inventory.")
    _verify_path_traversal(app, uid, gid)
    root = app.lstat()
    if not stat.S_ISDIR(root.st_mode) or not _can_traverse(root, uid, gid):
        raise RuntimeError("Service account cannot traverse staged application.")
    required = [
        app / "requirements.txt",
        app / "venv" / "pyvenv.cfg",
        app / "venv" / "bin" / "python",
    ]
    required.extend(app / "deployment" / "systemd" / name for name in
                    inspect_service_provisioning(app)["unit_names"])
    for path in required:
        _verify_path_traversal(path, uid, gid)
        if not path.exists():
            raise RuntimeError(f"Missing runtime prerequisite: {path}")
        meta = path.stat()
        if not stat.S_ISREG(meta.st_mode) or not _can_read(meta, uid, gid):
            raise RuntimeError(f"Service account cannot read prerequisite: {path}")
        if path == app / "venv" / "bin" / "python" and not _can_execute(meta, uid, gid):
            raise RuntimeError("Service account cannot execute Python interpreter.")
    for canonical, location in environment_destinations.items():
        path = Path(location)
        _verify_path_traversal(path, uid, gid)
        if not path.is_absolute() or path.is_symlink():
            raise RuntimeError(f"Unsafe environment path: {canonical}")
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                or meta.st_gid != gid or stat.S_IMODE(meta.st_mode) != 0o640
                or not _can_read(meta, uid, gid)):
            raise RuntimeError(f"Service account cannot read environment: {canonical}")
    return {"service_identity_access": "STATIC_CHECK_PASSED",
            "runtime_execution_verified": False, "activation_authorized": False}
