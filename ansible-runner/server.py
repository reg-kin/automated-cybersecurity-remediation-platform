#!/usr/bin/env python3

import hmac
import ipaddress
import json
import os
import re
import subprocess
import uuid

from flask import Flask, jsonify, request


app = Flask(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

PLAYBOOK_DIR = os.getenv(
    "ANSIBLE_PLAYBOOK_DIR",
    ""
)

RUNNER_TOKEN = os.getenv(
    "ANSIBLE_RUNNER_TOKEN",
    ""
)

ANSIBLE_TIMEOUT = int(
    os.getenv(
        "ANSIBLE_TIMEOUT",
        "1800"
    )
)


def load_allowed_playbooks():
    """
    Load the API playbook allowlist from ALLOWED_PLAYBOOKS.

    The allowlist is mandatory. Each entry must be a plain playbook basename;
    path traversal and path-like values are rejected at startup.
    """

    raw = os.getenv(
        "ALLOWED_PLAYBOOKS",
        ""
    )

    entries = [
        entry.strip()
        for entry in raw.split(",")
        if entry.strip()
    ]

    if not entries:
        raise RuntimeError(
            "ALLOWED_PLAYBOOKS must contain at least one playbook"
        )

    invalid = [
        entry
        for entry in entries
        if (
            entry in {".", ".."}
            or os.path.basename(entry) != entry
            or "/" in entry
            or "\\" in entry
        )
    ]

    if invalid:
        raise RuntimeError(
            "ALLOWED_PLAYBOOKS contains invalid playbook names: "
            + ", ".join(sorted(invalid))
        )

    return set(entries)


# Only explicitly configured playbooks can be requested through the API.
ALLOWED_PLAYBOOKS = load_allowed_playbooks()


# ============================================================================
# AUTHENTICATION
# ============================================================================

if not RUNNER_TOKEN or not RUNNER_TOKEN.strip():
    raise RuntimeError(
        "ANSIBLE_RUNNER_TOKEN must be configured with a non-empty value"
    )


def authorised():
    """Validate the mandatory Bearer token."""

    auth_header = request.headers.get(
        "Authorization",
        "",
    )

    expected = f"Bearer {RUNNER_TOKEN}"

    return hmac.compare_digest(
        auth_header,
        expected,
    )


# ============================================================================
# VALIDATION
# ============================================================================

def validate_playbook(playbook):

    if not isinstance(playbook, str):
        raise ValueError(
            "playbook must be a string"
        )

    if playbook not in ALLOWED_PLAYBOOKS:
        raise ValueError(
            f"Unsupported playbook: {playbook}"
        )

    playbook_path = os.path.join(
        PLAYBOOK_DIR,
        playbook
    )

    playbook_path = os.path.realpath(
        playbook_path
    )

    playbook_root = os.path.realpath(
        PLAYBOOK_DIR
    )

    if not playbook_path.startswith(
        playbook_root + os.sep
    ):
        raise ValueError(
            "Invalid playbook path"
        )

    if not os.path.isfile(
        playbook_path
    ):
        raise ValueError(
            f"Playbook does not exist: {playbook_path}"
        )

    return playbook_path

def validate_target_host(target_host):
    """
    Accept:
      - IPv4
      - IPv6
      - localhost
      - DNS hostnames

    Reject strings containing shell/inventory syntax.
    """

    if not isinstance(
        target_host,
        str
    ):

        raise ValueError(
            "target_host must be a string"
        )

    target_host = target_host.strip()

    if not target_host:
        raise ValueError(
            "target_host cannot be empty"
        )

    # The Runner is an orchestration service for managed hosts. It must
    # never execute remediation against its own loopback interface.
    hostname_lower = target_host.lower()

    if (
        hostname_lower == "localhost"
        or hostname_lower.endswith(".localhost")
    ):
        raise ValueError(
            "Loopback target_host is not permitted"
        )

    # First try IP validation.
    try:

        target_ip = ipaddress.ip_address(
            target_host
        )

    except ValueError:
        target_ip = None

    if target_ip is not None:

        if target_ip.is_loopback:
            raise ValueError(
                "Loopback target_host is not permitted"
            )

        return target_host

    # Otherwise allow a conservative DNS hostname.
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\."
        r")*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    if not hostname_pattern.fullmatch(
        target_host
    ):

        raise ValueError(
            f"Invalid target_host: {target_host}"
        )

    return target_host


def validate_extra_vars(extra_vars):
    """
    Ansible --extra-vars receives JSON.

    Require a JSON object rather than accepting arbitrary strings,
    arrays or scalar values.
    """

    if extra_vars is None:
        return {}

    if not isinstance(
        extra_vars,
        dict
    ):

        raise ValueError(
            "extra_vars must be a JSON object"
        )

    return extra_vars


# ============================================================================
# HEALTH ENDPOINT
# ============================================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():
    """
    Health endpoint for systemd/n8n/controller diagnostics.
    """

    return jsonify({
        "status": "ok",
        "service": "ansible-runner",
        "playbook_directory": PLAYBOOK_DIR,
        "allowed_playbooks": sorted(
            ALLOWED_PLAYBOOKS
        ),
    })


# ============================================================================
# RUN ENDPOINT
# ============================================================================

@app.route(
    "/run",
    methods=["POST"]
)
def run_playbook():

    # ----------------------------------------------------------------------
    # Authentication
    # ----------------------------------------------------------------------

    if not authorised():

        return jsonify({
            "success": False,
            "status": "unauthorised",
            "error": "Invalid or missing Bearer token",
        }), 401

    # ----------------------------------------------------------------------
    # Parse JSON request
    # ----------------------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict
    ):

        return jsonify({
            "success": False,
            "status": "invalid_request",
            "error": "Request body must be a JSON object",
        }), 400

    playbook = data.get(
        "playbook"
    )

    target_host = data.get(
        "target_host"
    )

    extra_vars = data.get(
        "extra_vars",
        {}
    )

    # ----------------------------------------------------------------------
    # Validate request
    # ----------------------------------------------------------------------

    try:

        playbook_path = validate_playbook(
            playbook
        )

        target_host = validate_target_host(
            target_host
        )

        extra_vars = validate_extra_vars(
            extra_vars
        )

    except ValueError as exc:

        return jsonify({
            "success": False,
            "status": "invalid_request",
            "error": str(exc),
        }), 400

    # ----------------------------------------------------------------------
    # Generate job identifier
    # ----------------------------------------------------------------------

    job_id = str(
        uuid.uuid4()
    )

    # ----------------------------------------------------------------------
    # Build Ansible inventory
    #
    # The trailing comma means:
    #
    # 10.20.30.15,
    #
    # is treated as a one-host inline inventory.
    # ----------------------------------------------------------------------

    inventory = f"{target_host},"

    # ----------------------------------------------------------------------
    # Encode extra_vars safely as JSON
    # ----------------------------------------------------------------------

    extra_vars_json = json.dumps(
        extra_vars,
        separators=(",", ":")
    )

    # ----------------------------------------------------------------------
    # Construct ansible-playbook command
    # ----------------------------------------------------------------------

    cmd = [
        "ansible-playbook",
        playbook_path,
        "-i",
        inventory,
    ]

    cmd.extend([
        "--extra-vars",
        extra_vars_json,
    ])

    # ----------------------------------------------------------------------
    # Environment
    # ----------------------------------------------------------------------

    env = os.environ.copy()

    env[
        "ANSIBLE_DEPRECATION_WARNINGS"
    ] = "False"

    env[
        "ANSIBLE_NOCOLOR"
    ] = "True"

    # ----------------------------------------------------------------------
    # Execute Ansible
    # ----------------------------------------------------------------------

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=ANSIBLE_TIMEOUT,
            env=env,
        )

        success = (
            result.returncode == 0
        )

        # --------------------------------------------------------------
        # Stage 1 contract
        #
        # The Ansible roles/playbooks contain assertions/checks for the
        # immediate post-remediation state.
        #
        # Therefore:
        #
        # ansible-playbook rc = 0
        #     ->
        # Stage 1 passed
        #
        # rc != 0
        #     ->
        # Stage 1 failed
        #
        # Stage 2 scanner verification is NOT done here.
        # --------------------------------------------------------------

        verification = {
            "passed": success,
            "verification_type": (
                "ANSIBLE_LOCAL"
            ),
            "playbook": playbook,
            "target_host": target_host,
            "remediation_action": (
                extra_vars.get(
                    "remediation_action"
                )
            ),
            "finding_id": (
                extra_vars.get(
                    "finding_id"
                )
            ),
            "execution_id": (
                extra_vars.get(
                    "execution_id"
                )
            ),
            "exit_code": (
                result.returncode
            ),
        }

        if success:

            return jsonify({
                "success": True,
                "status": "successful",
                "job_id": job_id,
                "rc": result.returncode,
                "stdout": (
                    result.stdout or ""
                ),
                "stderr": (
                    result.stderr or ""
                ),
                "verification": verification,
            }), 200

        return jsonify({
            "success": False,
            "status": "failed",
            "job_id": job_id,
            "rc": result.returncode,
            "stdout": (
                result.stdout or ""
            ),
            "stderr": (
                result.stderr or ""
            ),
            "error": (
                "Ansible playbook execution failed"
            ),
            "verification": verification,
        }), 200

    # ----------------------------------------------------------------------
    # Timeout
    # ----------------------------------------------------------------------

    except subprocess.TimeoutExpired as exc:

        return jsonify({
            "success": False,
            "status": "failed",
            "job_id": job_id,
            "rc": -1,
            "stdout": (
                exc.stdout or ""
            ),
            "stderr": (
                exc.stderr or ""
            ),
            "error": (
                f"Ansible execution exceeded "
                f"{ANSIBLE_TIMEOUT} seconds"
            ),
            "verification": {
                "passed": False,
                "verification_type": (
                    "ANSIBLE_LOCAL"
                ),
                "reason": "timeout",
                "finding_id": (
                    extra_vars.get(
                        "finding_id"
                    )
                ),
                "execution_id": (
                    extra_vars.get(
                        "execution_id"
                    )
                ),
            },
        }), 200

    # ----------------------------------------------------------------------
    # Unexpected listener failure
    # ----------------------------------------------------------------------

    except Exception as exc:

        return jsonify({
            "success": False,
            "status": "error",
            "job_id": job_id,
            "rc": -1,
            "stdout": "",
            "stderr": str(exc),
            "error": (
                "Unexpected Ansible Runner "
                "webhook failure"
            ),
            "verification": {
                "passed": False,
                "verification_type": (
                    "ANSIBLE_LOCAL"
                ),
                "finding_id": (
                    extra_vars.get(
                        "finding_id"
                    )
                ),
                "execution_id": (
                    extra_vars.get(
                        "execution_id"
                    )
                ),
            },
        }), 200


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":

    app.run(
        host=os.getenv(
            "ANSIBLE_RUNNER_HOST",
            "127.0.0.1"
        ),
        port=int(
            os.getenv(
                "ANSIBLE_RUNNER_PORT",
                "8080"
            )
        ),
    )
