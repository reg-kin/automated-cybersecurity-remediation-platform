#!/usr/bin/env python3
"""Reconcile the full provisioned filesystem against a completed journal.

Journal completion alone is not sufficient evidence of current readiness.
No services are started or enabled.
"""
from pathlib import Path

from provisioning_journal import assert_not_deployable
from verify_python_ownership import verify_python_environment, verify_staged_ownership
from verified_provisioning import _verify_file
from service_provisioning import inspect_service_provisioning
from install_application import ENVIRONMENT_FILE_TEMPLATES


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
    for target in environment_destinations.values():
        _verify_file(target, uid=uid, gid=gid, mode=0o640)
    for name in inspect_service_provisioning(app)["unit_names"]:
        _verify_file(Path(unit_destination) / name, uid=uid, gid=gid, mode=0o644)
    return record
