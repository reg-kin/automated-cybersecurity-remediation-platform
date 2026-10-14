#!/usr/bin/env python3
"""Read-only deployment configuration readiness gate.

Offline provisioning intentionally installs examples, not live secrets.
This gate must be run separately after an administrator configures the files.
It never prints secret values, executes services, or accesses databases.
"""
import os
import re
import stat
from pathlib import Path

from install_application import ENVIRONMENT_FILE_TEMPLATES

MANDATORY = {
    "/etc/readiness-admin-api.env": ("PG_USER", "PG_PASSWORD", "READINESS_ADMIN_TOKEN", "READINESS_ADMIN_PRINCIPAL"),
    "/etc/remediation-controller.env": ("PG_USER", "PG_PASSWORD", "CONTROLLER_TOKEN", "ANSIBLE_RUNNER_TOKEN", "VERIFICATION_TOKEN"),
    "/etc/remediation-dispatcher.env": ("PG_USER", "PG_PASSWORD", "CONTROLLER_TOKEN"),
    "/etc/remediation-rq-worker.env": ("RQ_REDIS_URL",),
    "/etc/scan-policy-admin-api.env": ("PG_USER", "PG_PASSWORD", "SCAN_POLICY_ADMIN_TOKEN", "SCAN_POLICY_ADMIN_PRINCIPAL"),
    "/etc/scan-policy-scheduler.env": ("PG_USER", "PG_PASSWORD"),
}


def verify_deployment_configuration(destinations, *, uid, gid):
    """Validate configured secrets and ownership without revealing their contents.

    This is a necessary prerequisite, not proof of credential validity or
    permission to activate systemd services.
    """
    if set(destinations) != set(ENVIRONMENT_FILE_TEMPLATES):
        raise RuntimeError("Incomplete deployment configuration inventory.")
    if set(MANDATORY) != set(ENVIRONMENT_FILE_TEMPLATES):
        raise RuntimeError("Configuration schema does not match template inventory.")
    for canonical, location in destinations.items():
        path = Path(location)
        if not path.is_absolute():
            raise RuntimeError("Configuration path must be absolute.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
                    or meta.st_gid != gid or stat.S_IMODE(meta.st_mode) != 0o640):
                raise RuntimeError(f"Unsafe configuration metadata: {canonical}")
            with os.fdopen(os.dup(fd), "r", encoding="utf-8") as stream:
                lines = stream.read(65537)
            if len(lines) > 65536:
                raise RuntimeError(f"Configuration exceeds size limit: {canonical}")
        finally:
            os.close(fd)
        values = {}
        for raw in lines.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
            if match is None:
                raise RuntimeError(f"Malformed configuration line: {canonical}")
            key, value = match.groups()
            if key in values:
                raise RuntimeError(f"Duplicate configuration key: {canonical}/{key}")
            values[key] = value.strip()
        for key in MANDATORY[canonical]:
            value = values.get(key, "")
            if not value or "CHANGE_ME" in value.upper():
                raise RuntimeError(f"Missing deployment setting: {canonical}/{key}")
        if values.get("TEST_SKIP_STAGE2", "false").lower() != "false":
            raise RuntimeError("Stage 2 verification bypass must be disabled.")
    return {"configured_files": len(destinations), "activation_authorized": False}
