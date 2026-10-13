#!/usr/bin/env python3
"""Read-only verification of staged ownership and Python venv prerequisites.

No dependency installation, chown, or systemd activity.
"""
import os
import stat
from pathlib import Path


def verify_python_environment(application):
    """Verify essential venv artifacts; not a substitute for package integrity."""
    app = Path(application)
    if not app.is_absolute() or app.is_symlink():
        raise RuntimeError("Unsafe application path.")
    venv = app / "venv"
    if venv.is_symlink() or not venv.is_dir():
        raise RuntimeError("Missing safe virtual environment.")
    cfg = venv / "pyvenv.cfg"
    python = venv / "bin/python"
    if cfg.is_symlink() or not cfg.is_file():
        raise RuntimeError("Missing safe virtual environment configuration.")
    # CPython venv commonly uses a symlink for bin/python, so resolve and
    # require an existing executable instead of prohibiting all symlinks.
    if not python.exists() or not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError("Missing executable virtual environment Python.")
    return True


def verify_staged_ownership(application, uid, gid):
    """Verify a private staged tree's ownership without modifying it."""
    app = Path(application)
    if not app.is_absolute() or app.is_symlink():
        raise RuntimeError("Unsafe staged application path.")
    root = app.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != uid
            or root.st_gid != gid or root.st_mode & 0o077):
        raise RuntimeError("Staged application root ownership or mode invalid.")
    for current, dirs, files in os.walk(app, followlinks=False):
        for name in dirs + files:
            entry = Path(current) / name
            metadata = entry.lstat()
            if (metadata.st_uid != uid or metadata.st_gid != gid
                    or not (stat.S_ISDIR(metadata.st_mode)
                            or stat.S_ISREG(metadata.st_mode))):
                raise RuntimeError(f"Unsafe staged application entry: {entry}")
    return True
