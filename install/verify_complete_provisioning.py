#!/usr/bin/env python3
"""Reconcile the full provisioned filesystem against a completed journal.

Journal completion alone is not sufficient evidence of current readiness.
No services are started or enabled.
"""
from pathlib import Path
import os
import stat

from provisioning_journal import assert_not_deployable
from verify_python_ownership import verify_python_environment, verify_staged_ownership
from verified_provisioning import _verify_file
from service_provisioning import inspect_service_provisioning
from install_application import ENVIRONMENT_FILE_TEMPLATES


def _verify_exact_copy(source, destination):
    for path in (source, destination):
        if path.is_symlink():
            raise RuntimeError(f"Provisioned file is a symlink: {path}")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        target_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not all(stat.S_ISREG(os.fstat(fd).st_mode) for fd in (source_fd, target_fd)):
                raise RuntimeError("Provisioned content is not a regular file.")
            while True:
                left = os.read(source_fd, 65536)
                right = os.read(target_fd, 65536)
                if left != right:
                    raise RuntimeError(f"Provisioned file content mismatch: {destination}")
                if not left:
                    break
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def verify_complete_provisioning(
    journal, application, unit_destination, environment_destinations, *, uid, gid
):
    app = Path(application)
    record = assert_not_deployable(journal)
    if record["application"] != str(app):
        raise RuntimeError("Provisioning journal application mismatch.")
    if set(environment_destinations) != set(ENVIRONMENT_FILE_TEMPLATES):
        raise RuntimeError("Environment destination inventory mismatch.")
    if verify_python_environment(app) is not True:
        raise RuntimeError("Python environment verification failed.")
    if verify_staged_ownership(app, uid, gid) is not True:
        raise RuntimeError("Staged application ownership verification failed.")
    for canonical, target in environment_destinations.items():
        _verify_file(target, uid=uid, gid=gid, mode=0o640)
        _verify_exact_copy(app / ENVIRONMENT_FILE_TEMPLATES[canonical], Path(target))
    for name in inspect_service_provisioning(app)["unit_names"]:
        target = Path(unit_destination) / name
        _verify_file(target, uid=uid, gid=gid, mode=0o644)
        _verify_exact_copy(app / "deployment/systemd" / name, target)
    return record
