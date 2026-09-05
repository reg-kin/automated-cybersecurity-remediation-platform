#!/usr/bin/env python3

import os
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "ansible-runner" / "server.py"
PLAYBOOK_DIR = ROOT / "ansible" / "playbooks"

os.environ["ANSIBLE_RUNNER_TOKEN"] = "test-runner-token"
os.environ["ANSIBLE_PLAYBOOK_DIR"] = str(PLAYBOOK_DIR)
os.environ["ALLOWED_PLAYBOOKS"] = "os_patching.yml"

namespace = runpy.run_path(
    str(SERVER)
)

validate_target_host = namespace[
    "validate_target_host"
]


# Normal managed-host targets remain valid.
assert validate_target_host(
    "192.0.2.10"
) == "192.0.2.10"

assert validate_target_host(
    "2001:db8::10"
) == "2001:db8::10"

assert validate_target_host(
    "host.example.test"
) == "host.example.test"


# Hostnames reserved for the local machine must not be remediation targets.
for target in (
    "localhost",
    "LOCALHOST",
    "node.localhost",
):
    try:
        validate_target_host(target)
    except ValueError as exc:
        assert "loopback" in str(exc).lower()
    else:
        raise AssertionError(
            f"Loopback hostname was accepted: {target}"
        )


# All IPv4 and IPv6 loopback addresses must be rejected, not only the
# conventional 127.0.0.1 and ::1 spellings.
for target in (
    "127.0.0.1",
    "127.0.0.2",
    "127.255.255.254",
    "::1",
):
    try:
        validate_target_host(target)
    except ValueError as exc:
        assert "loopback" in str(exc).lower()
    else:
        raise AssertionError(
            f"Loopback address was accepted: {target}"
        )


print(
    "PASS: Ansible Runner rejects loopback remediation targets"
)
