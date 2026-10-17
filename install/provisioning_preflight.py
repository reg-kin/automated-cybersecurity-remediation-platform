#!/usr/bin/env python3
"""Read-only provisioning preflight for a verified application tree.

No file creation, chown, subprocess invocation, or service activation.
"""
import os
import re
import stat
from pathlib import Path

from install_application import environment_templates
from service_provisioning import inspect_service_provisioning


def preflight_provisioning(application, unit_destination, environment_destinations, *, native=False):
    """Inspect all provisioning targets before any privileged write.

    This is not a transaction: it is a prerequisite inventory. Revalidate
    immediately before any later mutation because filesystem state may change.
    """
    application = Path(application)
    if not application.is_absolute() or application.is_symlink():
        raise RuntimeError("Application must be an absolute non-symlink directory.")
    app_fd = os.open(application, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(app_fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise RuntimeError("Application directory owner or mode unsafe.")
    finally:
        os.close(app_fd)
    inventory = inspect_service_provisioning(application, native=native)
    requirements = application / "requirements.txt"
    requirement_files = [requirements]
    if native:
        requirement_files.append(application / "deployment/requirements-native.txt")
    all_lines = []
    for requirements in requirement_files:
        req_fd = os.open(requirements, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(req_fd).st_mode):
                raise RuntimeError("Unsafe requirements file.")
            with os.fdopen(req_fd, "r", closefd=False) as stream:
                lines = stream.read().splitlines()
        finally:
            os.close(req_fd)
        if not lines or any(not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*",
            line.strip()) for line in lines):
            raise RuntimeError("Requirements must be explicitly pinned.")
        all_lines.extend(lines)
    lines = all_lines
    if set(environment_destinations) != set(environment_templates(native=native)):
        raise RuntimeError("Environment destination mapping must be complete.")
    targets = [Path(unit_destination)] + [Path(p) for p in environment_destinations.values()]
    if any(not path.is_absolute() for path in targets):
        raise RuntimeError("Provisioning destinations must be absolute.")
    if len(set(targets)) != len(targets):
        raise RuntimeError("Duplicate provisioning destinations.")
    unit_dir = Path(unit_destination)
    if unit_dir.is_symlink() or not unit_dir.is_dir():
        raise RuntimeError("Unsafe systemd destination directory.")
    for path in [unit_dir] + [p.parent for p in targets[1:]]:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                raise RuntimeError(f"Unsafe provisioning directory: {path}")
        finally:
            os.close(fd)
    for name in inventory["unit_names"]:
        if (unit_dir / name).exists() or (unit_dir / name).is_symlink():
            raise RuntimeError(f"Existing systemd unit: {name}")
    for target in targets[1:]:
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"Existing environment file: {target}")
    if (application / "venv").exists() or (application / "venv").is_symlink():
        raise RuntimeError("Existing virtual environment.")
    return {
        "units": len(inventory["unit_names"]),
        "environment_files": len(environment_destinations),
        "pinned_requirements": len(lines),
        "dispatcher_timer_activation": "FORBIDDEN",
        "actions_performed": 0,
    }
