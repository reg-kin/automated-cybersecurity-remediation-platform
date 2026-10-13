#!/usr/bin/env python3
"""Restrict virtual-environment interpreter links to trusted interpreter paths.

Ownership preparation never follows symlinks. This validator checks the target
before accepting a narrowly allowed venv/bin/python* link.
"""
import os
import stat
from pathlib import Path

INTERPRETER_NAMES = frozenset(("python", "python3", "python3.12"))


def validate_venv_interpreter_link(application, path):
    app = Path(application)
    link = Path(path)
    if link.parent != app / "venv" / "bin" or link.name not in INTERPRETER_NAMES:
        raise RuntimeError("Unexpected staged application symlink.")
    if not link.is_symlink():
        raise RuntimeError("Expected interpreter symlink.")
    raw = os.readlink(link)
    # A venv may chain python -> python3 -> /usr/bin/python3.12.
    # Resolve each hop with a strict bound; never accept dangling or cyclic links.
    target = link.resolve(strict=True)
    if not target.is_file():
        raise RuntimeError("Interpreter link target is not a regular file.")
    # Only an existing system interpreter is permitted outside the venv.
    system_roots = (Path("/usr/bin"), Path("/usr/local/bin"))
    if not any(target.is_relative_to(root) for root in system_roots):
        raise RuntimeError("Interpreter link escapes trusted system directories.")
    metadata = target.stat()
    if (not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or not os.access(target, os.X_OK)):
        raise RuntimeError("Interpreter target ownership or permissions unsafe.")
    if not raw:
        raise RuntimeError("Empty interpreter symlink.")
    return True
