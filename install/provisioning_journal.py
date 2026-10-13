#!/usr/bin/env python3
"""Explicit fail-closed provisioning transaction journal.

The journal records durable stage boundaries and does not execute provisioning
or enable services. An interrupted transaction remains blocked for inspection.
"""
import json
import os
import stat
from pathlib import Path

STAGES = ("preflight", "python", "ownership", "environment", "units")
TERMINAL = "COMPLETE"


def _write_new_journal(path, record):
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError("Journal path must be absolute.")
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise RuntimeError("Journal directory must be caller-owned and private.")
        target_fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=fd,
        )
        try:
            payload = (json.dumps(record, sort_keys=True) + "\n").encode()
            os.write(target_fd, payload)
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def begin_provisioning(journal, *, application):
    """Create a new exclusive transaction marker; never reuse a prior journal."""
    application = Path(application)
    if not application.is_absolute():
        raise RuntimeError("Application must be absolute.")
    record = {
        "version": 1,
        "application": str(application),
        "state": "INCOMPLETE",
        "completed_stages": [],
        "dispatcher_timer_activation": "FORBIDDEN",
    }
    _write_new_journal(journal, record)
    return record


def inspect_provisioning(journal):
    """Read existing journal without following a symlink or trusting its contents."""
    path = Path(journal)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("Unsafe provisioning journal.")
        with os.fdopen(fd, "r", closefd=False) as stream:
            record = json.load(stream)
    finally:
        os.close(fd)
    if (not isinstance(record, dict)
        or record.get("version") != 1
        or record.get("dispatcher_timer_activation") != "FORBIDDEN"
        or record.get("state") not in ("INCOMPLETE", TERMINAL)
        or not isinstance(record.get("completed_stages"), list)
        or record["completed_stages"] not in
            [list(STAGES[:i]) for i in range(len(STAGES) + 1)]
        or (record["state"] == TERMINAL
            and record["completed_stages"] != list(STAGES))):
        raise RuntimeError("Invalid provisioning journal state.")
    return record


def assert_not_deployable(journal):
    """Fail closed unless a separately reviewed transaction is complete."""
    record = inspect_provisioning(journal)
    if record["state"] != TERMINAL:
        raise RuntimeError("Provisioning incomplete; deployment prohibited.")
    return record
