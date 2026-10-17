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

from install_application import environment_templates

MANDATORY = {
    "/etc/readiness-admin-api.env": ("PG_USER", "PG_PASSWORD", "READINESS_ADMIN_TOKEN", "READINESS_ADMIN_PRINCIPAL"),
    "/etc/remediation-controller.env": ("PG_USER", "PG_PASSWORD", "CONTROLLER_TOKEN", "ANSIBLE_RUNNER_TOKEN", "VERIFICATION_TOKEN"),
    "/etc/remediation-dispatcher.env": ("PG_USER", "PG_PASSWORD", "CONTROLLER_TOKEN"),
    "/etc/remediation-rq-worker.env": ("RQ_REDIS_URL",),
    "/etc/scan-policy-admin-api.env": ("PG_USER", "PG_PASSWORD", "SCAN_POLICY_ADMIN_TOKEN", "SCAN_POLICY_ADMIN_PRINCIPAL"),
    "/etc/scan-policy-scheduler.env": ("PG_USER", "PG_PASSWORD"),
}


NATIVE_MANDATORY = {
    "/etc/ansible-runner.env": ("ANSIBLE_RUNNER_TOKEN", "ALLOWED_PLAYBOOKS", "ANSIBLE_PLAYBOOK_DIR", "ANSIBLE_RUNNER_HOST", "ANSIBLE_RUNNER_PORT"),
    "/etc/verification-gateway.env": ("VERIFICATION_TOKEN", "VERIFICATION_HOST", "VERIFICATION_PORT"),
}


def verify_deployment_configuration(destinations, *, uid, gid, native=False):
    """Validate configured secrets and ownership without revealing their contents.

    This is a necessary prerequisite, not proof of credential validity or
    permission to activate systemd services.
    """
    templates = environment_templates(native=native)
    mandatory = {**MANDATORY, **(NATIVE_MANDATORY if native else {})}
    if set(destinations) != set(templates):
        raise RuntimeError("Incomplete deployment configuration inventory.")
    if set(mandatory) != set(templates):
        raise RuntimeError("Configuration schema does not match template inventory.")
    configurations = {}
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
        for key in mandatory[canonical]:
            value = values.get(key, "")
            if not value or "CHANGE_ME" in value.upper():
                raise RuntimeError(f"Missing deployment setting: {canonical}/{key}")
        configurations[canonical] = values
        if values.get("TEST_SKIP_STAGE2", "false").lower() != "false":
            raise RuntimeError("Stage 2 verification bypass must be disabled.")
    if native:
        from urllib.parse import urlsplit
        controller = configurations["/etc/remediation-controller.env"]
        for file, prefix, url_key, endpoint in (
            ("/etc/ansible-runner.env", "ANSIBLE_RUNNER", "ANSIBLE_RUNNER_URL", "/run"),
            ("/etc/verification-gateway.env", "VERIFICATION", "VERIFICATION_URL", "/verify"),
        ):
            server = configurations[file]
            try:
                port = int(server[prefix + "_PORT"])
                url = urlsplit(controller.get(url_key, ""))
                valid = (1 <= port <= 65535 and url.scheme == "http"
                         and url.hostname == server[prefix + "_HOST"]
                         and url.port == port and url.path == endpoint)
            except ValueError:
                valid = False
            if not valid:
                raise RuntimeError(f"Native endpoint mismatch: {url_key}")
            if controller[prefix + "_TOKEN"] != server[prefix + "_TOKEN"]:
                raise RuntimeError(f"Native authentication mismatch: {prefix}")
    return {"configured_files": len(destinations), "activation_authorized": False}
