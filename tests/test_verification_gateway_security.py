#!/usr/bin/env python3

"""
Regression tests for verification-gateway authentication.

The gateway must:
  * refuse to initialise without VERIFICATION_TOKEN;
  * ignore the obsolete REGIS_VERIFICATION_TOKEN variable;
  * default to loopback binding;
  * reject missing and incorrect Bearer tokens;
  * accept the configured Bearer token.
"""

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

VERIFICATION_DIR = (
    ROOT
    / "verification"
)


def run_import(
    *,
    token=None,
    old_token=None,
    code=None,
):

    env = os.environ.copy()

    env["PYTHONPATH"] = str(
        VERIFICATION_DIR
    )

    env.pop(
        "VERIFICATION_TOKEN",
        None,
    )

    env.pop(
        "REGIS_VERIFICATION_TOKEN",
        None,
    )

    env.pop(
        "VERIFICATION_HOST",
        None,
    )

    env.pop(
        "VERIFICATION_PORT",
        None,
    )

    if token is not None:
        env[
            "VERIFICATION_TOKEN"
        ] = token

    if old_token is not None:
        env[
            "REGIS_VERIFICATION_TOKEN"
        ] = old_token

    command = (
        code
        or "import verification_gateway"
    )

    return subprocess.run(
        [
            sys.executable,
            "-c",
            command,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


missing = run_import()

assert missing.returncode != 0

assert (
    "VERIFICATION_TOKEN must be "
    "configured and non-empty"
    in missing.stderr
)


obsolete_only = run_import(
    old_token=("obsolete-" + "token"),
)

assert obsolete_only.returncode != 0

assert (
    "VERIFICATION_TOKEN must be "
    "configured and non-empty"
    in obsolete_only.stderr
)


authenticated = run_import(
    token=("test-verification-" + "token"),
    code=r'''
import verification_gateway as gateway

assert gateway.HOST == "127.0.0.1"
assert gateway.PORT == 8090

gateway.dispatch = lambda payload: {
    "present": False,
    "verification_status": "PASSED",
}

client = gateway.app.test_client()

response = client.post(
    "/verify",
    json={},
)

assert response.status_code == 401

response = client.post(
    "/verify",
    headers={
        "Authorization":
            "Bearer wrong-token"
    },
    json={},
)

assert response.status_code == 401

response = client.post(
    "/verify",
    headers={
        "Authorization":
            "Bearer test-verification-token"
    },
    json={},
)

assert response.status_code == 200

health = client.get("/health")

assert health.status_code == 200

assert (
    health.get_json()["service"]
    == "verification-gateway"
)
''',
)

if authenticated.returncode != 0:

    print(
        authenticated.stdout,
        end="",
    )

    print(
        authenticated.stderr,
        end="",
        file=sys.stderr,
    )

    raise SystemExit(
        authenticated.returncode
    )


print(
    "PASS: verification gateway "
    "fails closed and requires "
    "Bearer authentication"
)
