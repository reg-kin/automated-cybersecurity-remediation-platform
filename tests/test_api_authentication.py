#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNNER_SERVER = ROOT / "ansible-runner" / "server.py"
PLAYBOOK_DIR = ROOT / "ansible" / "playbooks"

CONTROLLER_TEST_TOKEN = "controller-test-token"
RUNNER_TEST_TOKEN = "runner-test-token"


def run_python(code, env):
    return subprocess.run(
        [
            sys.executable,
            "-c",
            code,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def controller_env(token_marker=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env.pop("CONTROLLER_TOKEN", None)

    if token_marker is not None:
        env["CONTROLLER_TOKEN"] = token_marker

    return env


def runner_env(token_marker=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    env["ALLOWED_PLAYBOOKS"] = "os_patching.yml"
    env["ANSIBLE_PLAYBOOK_DIR"] = str(PLAYBOOK_DIR)

    env.pop("ANSIBLE_RUNNER_TOKEN", None)

    if token_marker is not None:
        env["ANSIBLE_RUNNER_TOKEN"] = token_marker

    return env


# ---------------------------------------------------------------------------
# Controller API startup must fail closed when its token is absent.
# ---------------------------------------------------------------------------

result = run_python(
    "import remediation.controller_api",
    controller_env(),
)

assert result.returncode != 0
assert (
    "CONTROLLER_TOKEN must be configured with a non-empty value"
    in result.stderr
), result.stderr


# Blank/whitespace controller tokens must also fail closed.
result = run_python(
    "import remediation.controller_api",
    controller_env("   "),
)

assert result.returncode != 0
assert (
    "CONTROLLER_TOKEN must be configured with a non-empty value"
    in result.stderr
), result.stderr


# Controller authentication must reject missing/wrong credentials and accept
# only the configured Bearer token.
controller_auth_code = f'''
import remediation.controller_api as controller_api

app = controller_api.app

with app.test_request_context("/remediate"):
    assert controller_api.authorised() is False

with app.test_request_context(
    "/remediate",
    headers={{"Authorization": "Bearer wrong-token"}},
):
    assert controller_api.authorised() is False

with app.test_request_context(
    "/remediate",
    headers={{
        "Authorization": "Bearer {CONTROLLER_TEST_TOKEN}"
    }},
):
    assert controller_api.authorised() is True

print("PASS")
'''

result = run_python(
    controller_auth_code,
    controller_env(CONTROLLER_TEST_TOKEN),
)

assert result.returncode == 0, (
    result.stdout
    + result.stderr
)
assert result.stdout.strip() == "PASS"


# ---------------------------------------------------------------------------
# Ansible Runner API startup must fail closed when its token is absent.
# ---------------------------------------------------------------------------

runner_import_code = f'''
import runpy

runpy.run_path(
    {str(RUNNER_SERVER)!r}
)
'''

result = run_python(
    runner_import_code,
    runner_env(),
)

assert result.returncode != 0
assert (
    "ANSIBLE_RUNNER_TOKEN must be configured with a non-empty value"
    in result.stderr
), result.stderr


# Blank/whitespace Runner tokens must also fail closed.
result = run_python(
    runner_import_code,
    runner_env("   "),
)

assert result.returncode != 0
assert (
    "ANSIBLE_RUNNER_TOKEN must be configured with a non-empty value"
    in result.stderr
), result.stderr


# Runner authentication must reject missing/wrong credentials and accept only
# the configured Bearer token.
runner_auth_code = f'''
import runpy

namespace = runpy.run_path(
    {str(RUNNER_SERVER)!r}
)

app = namespace["app"]
authorised = namespace["authorised"]

with app.test_request_context("/run"):
    assert authorised() is False

with app.test_request_context(
    "/run",
    headers={{"Authorization": "Bearer wrong-token"}},
):
    assert authorised() is False

with app.test_request_context(
    "/run",
    headers={{
        "Authorization": "Bearer {RUNNER_TEST_TOKEN}"
    }},
):
    assert authorised() is True

print("PASS")
'''

result = run_python(
    runner_auth_code,
    runner_env(RUNNER_TEST_TOKEN),
)

assert result.returncode == 0, (
    result.stdout
    + result.stderr
)
assert result.stdout.strip() == "PASS"


print(
    "PASS: Controller and Ansible Runner APIs require "
    "mandatory Bearer authentication"
)
