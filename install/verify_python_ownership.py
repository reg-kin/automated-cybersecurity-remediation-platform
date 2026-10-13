#!/usr/bin/env python3
"""Read-only verification of staged ownership and Python venv prerequisites.

No dependency installation, chown, or systemd activity.
"""
import os
import stat
import json
import re
import subprocess
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
    requirements = app / "requirements.txt"
    if requirements.is_symlink() or not requirements.is_file():
        raise RuntimeError("Missing safe pinned requirements.")
    expected = {}
    for line in requirements.read_text().splitlines():
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)", line.strip())
        if match is None:
            raise RuntimeError("Invalid pinned requirement.")
        key = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if key in expected:
            raise RuntimeError("Duplicate pinned requirement.")
        expected[key] = match.group(2)
    if not expected:
        raise RuntimeError("Empty pinned requirements.")
    script = (
        "import importlib.metadata as m, json;"
        "print(json.dumps({d.metadata['Name']: d.version for d in m.distributions()}))"
    )
    result = subprocess.run(
        [str(python), "-c", script], capture_output=True, text=True,
        check=True, timeout=30,
    )
    installed = {
        re.sub(r"[-_.]+", "-", name).lower(): version
        for name, version in json.loads(result.stdout).items()
    }
    missing = {
        name: version for name, version in expected.items()
        if installed.get(name) != version
    }
    if missing:
        raise RuntimeError("Virtual environment missing pinned packages: "
                           + ", ".join(sorted(missing)))
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
            if stat.S_ISLNK(metadata.st_mode):
                if (entry.parent != app / "venv" / "bin"
                        or name not in ("python", "python3", "python3.12")):
                    raise RuntimeError(f"Unsafe staged application entry: {entry}")
                continue
            if (metadata.st_uid != uid or metadata.st_gid != gid
                    or not (stat.S_ISDIR(metadata.st_mode)
                            or stat.S_ISREG(metadata.st_mode))):
                raise RuntimeError(f"Unsafe staged application entry: {entry}")
    return True
