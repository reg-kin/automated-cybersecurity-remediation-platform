#!/usr/bin/env python3
"""Read-only runtime access verification for the intended service identity.

No privilege switching, systemctl invocation, or access to production services.
"""
import os
import stat
from pathlib import Path

from install_application import ENVIRONMENT_FILE_TEMPLATES
from service_provisioning import inspect_service_provisioning


def _can_read(meta, uid, gid):
    bits = stat.S_IMODE(meta.st_mode)
    return bool(
        (meta.st_uid == uid and bits & stat.S_IRUSR)
        or (meta.st_gid == gid and bits & stat.S_IRGRP)
        or (bits & stat.S_IROTH)
    )


def _can_traverse(meta, uid, gid):
    bits = stat.S_IMODE(meta.st_mode)
    return bool(
        (meta.st_uid == uid and bits & stat.S_IXUSR)
        or (meta.st_gid == gid and bits & stat.S_IXGRP)
        or (bits & stat.S_IXOTH)
    )


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
        if not path.exists():
            raise RuntimeError(f"Missing runtime prerequisite: {path}")
        meta = path.stat()
        if not stat.S_ISREG(meta.st_mode) or not _can_read(meta, uid, gid):
            raise RuntimeError(f"Service account cannot read prerequisite: {path}")
    for canonical, location in environment_destinations.items():
        path = Path(location)
        if not path.is_absolute() or path.is_symlink():
            raise RuntimeError(f"Unsafe environment path: {canonical}")
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                or meta.st_gid != gid or stat.S_IMODE(meta.st_mode) != 0o640
                or not _can_read(meta, uid, gid)):
            raise RuntimeError(f"Service account cannot read environment: {canonical}")
    return {"service_identity_access": "STATIC_CHECK_PASSED",
            "runtime_execution_verified": False, "activation_authorized": False}
