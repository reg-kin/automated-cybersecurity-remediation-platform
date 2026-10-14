#!/usr/bin/env python3
"""Read-only reference-host compatibility check. Never starts services."""
import argparse
import os
import platform
import sys
from pathlib import Path

from install_application import DEFAULT_DESTINATION, ENVIRONMENT_FILE_TEMPLATES
from service_provisioning import inspect_service_provisioning


def inspect_host(application):
    app = Path(application)
    if not app.is_absolute() or app.is_symlink() or not app.is_dir():
        raise RuntimeError("Application must be an existing absolute non-symlink directory.")
    if app != DEFAULT_DESTINATION:
        raise RuntimeError("Systemd units require /opt/automated-remediation.")
    inventory = inspect_service_provisioning(app)
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Reference environment requires Python 3.12.")
    if platform.system() != "Linux":
        raise RuntimeError("Reference environment requires Linux.")
    if not Path("/etc/os-release").is_file():
        raise RuntimeError("Cannot identify host OS.")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if not any(line == "ID=ubuntu" for line in os_release.splitlines()) or not any(
        line in ('VERSION_ID="24.04"', "VERSION_ID=24.04")
        for line in os_release.splitlines()
    ):
        raise RuntimeError("Reference environment requires Ubuntu 24.04.")
    for required in ("venv/bin/python", "venv/bin/gunicorn"):
        target = app / required
        if not target.exists():
            raise RuntimeError("Missing installed executable: " + required)
    missing = [name for name in ENVIRONMENT_FILE_TEMPLATES if not Path(name).is_file()]
    if missing:
        raise RuntimeError("Missing canonical environment files: " + ", ".join(missing))
    import pwd
    import grp
    account = pwd.getpwnam("automated-remediation")
    if grp.getgrgid(account.pw_gid).gr_name != "automated-remediation":
        raise RuntimeError("Service account primary group mismatch.")
    for unit in inventory["unit_names"]:
        if not (Path("/etc/systemd/system") / unit).is_file():
            raise RuntimeError("Missing installed systemd unit: " + unit)
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect reference host without modifying it.")
    parser.add_argument("--application", default=str(DEFAULT_DESTINATION))
    args = parser.parse_args(argv)
    try:
        inventory = inspect_host(args.application)
    except (OSError, RuntimeError, KeyError) as exc:
        print("NOT READY:", exc, file=sys.stderr)
        return 1
    print("PASS: Reference host structural prerequisites; units:", len(inventory["unit_names"]))
    print("NOT VERIFIED: Secrets, PostgreSQL, Redis, scanners, network, systemd status or remediation.")
    print("NOT AUTHORIZED: No services started; dispatcher timer remains forbidden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
