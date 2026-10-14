#!/usr/bin/env python3
"""Offline coordinator integration with actual environment and unit provisioning.

Python and ownership stages are intentionally not represented by fake success.
This harness exercises the final two stages after the preceding stages have
been independently prepared and recorded in an isolated journal.
"""
import os
from pathlib import Path

from provisioning_journal import STAGES, advance_provisioning, inspect_provisioning
from verified_provisioning import verified_environment, verified_units, _verify_file
from service_provisioning import inspect_service_provisioning
from install_application import ENVIRONMENT_FILE_TEMPLATES


def execute_final_provisioning_stages(
    journal, application, unit_destination, environment_destinations, *, uid, gid
):
    """Provision environment and units only after earlier journal stages.

    Refuses automatic recovery. An interrupted run must be reconciled
    manually, even when some files already exist.
    """
    record = inspect_provisioning(journal)
    if (record["state"] != "INCOMPLETE"
            or record["completed_stages"] != list(STAGES[:3])
            or record["application"] != str(Path(application))):
        raise RuntimeError("Verified prerequisite stages are required.")
    if not verified_environment(application, environment_destinations, uid, gid):
        raise RuntimeError("Environment provisioning not verified.")
    for canonical, target in environment_destinations.items():
        if canonical not in ENVIRONMENT_FILE_TEMPLATES:
            raise RuntimeError("Unknown environment destination.")
        _verify_file(target, uid=uid, gid=gid, mode=0o640)
    advance_provisioning(journal, "environment", evidence_confirmed=True)
    if not verified_units(application, unit_destination, uid, gid):
        raise RuntimeError("Unit provisioning not verified.")
    for name in inspect_service_provisioning(application)["unit_names"]:
        _verify_file(Path(unit_destination) / name, uid=uid, gid=gid, mode=0o644)
    return advance_provisioning(journal, "units", evidence_confirmed=True)
