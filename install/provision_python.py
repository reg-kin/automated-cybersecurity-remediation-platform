#!/usr/bin/env python3
"""Explicit, isolated Python environment provisioning.

Never runs automatically during archive publication. The caller must opt in.
"""
import os
import stat
import subprocess
import sys
from pathlib import Path


def provision_python_environment(application, *, python_executable=sys.executable, installer=None):
    """Create a fresh venv and install pinned requirements without shell execution.

    The caller supplies an installer command for offline CI tests; production
    defaults to the venv pip. No activation of systemd services occurs.
    A partially created venv is preserved for diagnosis, never overwritten.
    """
    application = Path(application)
    if not application.is_absolute() or application.is_symlink():
        raise RuntimeError("Application must be an absolute non-symlink directory.")
    app_fd = os.open(application, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(app_fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise RuntimeError("Application directory ownership or permissions unsafe.")
        requirements = application / "requirements.txt"
        req_fd = os.open(requirements, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(req_fd).st_mode):
                raise RuntimeError("Requirements must be a regular file.")
            with os.fdopen(req_fd, "r", closefd=False) as inp:
                lines = inp.readlines()
        finally:
            os.close(req_fd)
        if not lines or any(
            not line.strip() or line.lstrip().startswith("#")
            or not __import__("re").fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*", line.strip()
            ) for line in lines
        ):
            raise RuntimeError("Requirements must contain only pinned package versions.")
        try:
            os.stat("venv", dir_fd=app_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("Existing virtual environment must not be overwritten.")
        python_executable = str(Path(python_executable).resolve(strict=True))
        subprocess.run([python_executable, "-m", "venv", str(application / "venv")], check=True)
        pip_command = list(installer) if installer is not None else [
            str(application / "venv/bin/python"), "-m", "pip",
        ]
        if not pip_command:
            raise RuntimeError("Installer command must not be empty.")
        subprocess.run(
            pip_command + ["install", "--requirement", str(requirements)],
            check=True,
            cwd=str(application),
        )
        return application / "venv"
    finally:
        os.close(app_fd)
