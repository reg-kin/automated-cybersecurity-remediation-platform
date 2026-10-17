#!/usr/bin/env python3
"""Build verified provisioning callbacks for an isolated application tree.

No service activation or production entry point. The caller must explicitly
supply destinations and identities. Python installation is deliberately not
wired here until ownership/order and offline dependency policy are reviewed.
"""
import os
import stat
from pathlib import Path

from provisioning_preflight import preflight_provisioning
from provision_environment import provision_environment_files
from provision_service_units import provision_service_units
from service_provisioning import inspect_service_provisioning
from install_application import environment_templates


def _verify_file(path, *, uid, gid, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                or meta.st_gid != gid or stat.S_IMODE(meta.st_mode) != mode):
            raise RuntimeError(f"Provisioned file verification failed: {path}")
    finally:
        os.close(fd)


def verified_preflight(application, unit_destination, destinations, *, native=False):
    result = preflight_provisioning(application, unit_destination, destinations, native=native)
    return (result["actions_performed"] == 0
            and result["dispatcher_timer_activation"] == "FORBIDDEN")


def verified_environment(application, destinations, uid, gid, *, native=False):
    created = provision_environment_files(application, destinations, uid, gid, native=native)
    if set(created) != {Path(p) for p in destinations.values()}:
        raise RuntimeError("Environment provisioning returned incomplete paths.")
    for canonical, target in destinations.items():
        if canonical not in environment_templates(native=native):
            raise RuntimeError("Unknown environment destination.")
        _verify_file(target, uid=uid, gid=gid, mode=0o640)
    return True


def verified_units(application, unit_destination, uid, gid, *, native=False):
    expected = inspect_service_provisioning(application, native=native)["unit_names"]
    created = provision_service_units(application, unit_destination, uid, gid, native=native)
    if set(created) != set(expected):
        raise RuntimeError("Systemd provisioning returned incomplete unit set.")
    for name in expected:
        _verify_file(Path(unit_destination) / name, uid=uid, gid=gid, mode=0o644)
    return True
