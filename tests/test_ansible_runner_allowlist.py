#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "ansible-runner" / "server.py"
PLAYBOOK_DIR = ROOT / "ansible" / "playbooks"

PRODUCTION_PLAYBOOKS = {
    "os_patching.yml",
    "container_image.yml",
    "cis_hardening.yml",
    "service_config.yml",
    "web_application.yml",
    "file_integrity.yml",
    "security_incident.yml",
}

TEST_PLAYBOOKS = {
    "controller_test.yml",
    "controller_positive_test.yml",
    "controller_stage1_fail_test.yml",
    "controller_duplicate_test.yml",
    "controller_approval_test.yml",
}


def run_server_import(
    allowed_playbooks=None,
    code=None,
):
    env = os.environ.copy()

    env.pop(
        "ALLOWED_PLAYBOOKS",
        None,
    )
    env["ANSIBLE_RUNNER_TOKEN"] = "test-runner-token"

    env["ANSIBLE_PLAYBOOK_DIR"] = str(
        PLAYBOOK_DIR
    )

    if allowed_playbooks is not None:
        env["ALLOWED_PLAYBOOKS"] = (
            allowed_playbooks
        )

    if code is None:
        code = f'''
import json
import runpy

namespace = runpy.run_path(
    {str(SERVER)!r}
)

print(
    json.dumps(
        sorted(namespace["ALLOWED_PLAYBOOKS"])
    )
)
'''

    return subprocess.run(
        [
            sys.executable,
            "-c",
            code,
        ],
        env=env,
        text=True,
        capture_output=True,
    )


# Missing configuration must fail closed.
result = run_server_import()

assert result.returncode != 0
assert (
    "ALLOWED_PLAYBOOKS must contain at least one playbook"
    in result.stderr
)


# Blank configuration must also fail closed.
result = run_server_import(
    "   ,   "
)

assert result.returncode != 0
assert (
    "ALLOWED_PLAYBOOKS must contain at least one playbook"
    in result.stderr
)


# Path-like entries must be rejected at startup.
result = run_server_import(
    "os_patching.yml,../controller_test.yml"
)

assert result.returncode != 0
assert (
    "contains invalid playbook names"
    in result.stderr
)


# Valid configuration must become the exact runtime allowlist.
configured = (
    " os_patching.yml, "
    "container_image.yml,"
    "cis_hardening.yml,"
    "service_config.yml,"
    "web_application.yml,"
    "file_integrity.yml,"
    "security_incident.yml "
)

result = run_server_import(
    configured
)

assert result.returncode == 0, result.stderr

runtime_allowlist = set(
    json.loads(
        result.stdout.strip()
    )
)

assert runtime_allowlist == PRODUCTION_PLAYBOOKS
assert runtime_allowlist.isdisjoint(
    TEST_PLAYBOOKS
)


# A production playbook present on disk must remain executable.
# A test playbook present on disk must still be rejected because it is
# not in the configured runtime allowlist.
validation_code = f'''
import runpy

namespace = runpy.run_path(
    {str(SERVER)!r}
)

validate_playbook = namespace[
    "validate_playbook"
]

production_path = validate_playbook(
    "os_patching.yml"
)

assert production_path.endswith(
    "/os_patching.yml"
)

try:
    validate_playbook(
        "controller_test.yml"
    )
except ValueError as exc:
    assert (
        "Unsupported playbook"
        in str(exc)
    )
else:
    raise AssertionError(
        "Test playbook was executable through the Runner API"
    )

print("PASS")
'''

result = run_server_import(
    ",".join(
        sorted(PRODUCTION_PLAYBOOKS)
    ),
    validation_code,
)

assert result.returncode == 0, (
    result.stdout
    + result.stderr
)

assert result.stdout.strip() == "PASS"


print(
    "PASS: Ansible Runner uses the configured fail-closed "
    "production playbook allowlist"
)
