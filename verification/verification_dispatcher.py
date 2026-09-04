#!/usr/bin/env python3

import json
import os
import subprocess
import sys


ORCHESTRATORS = {
    "openvas": os.getenv(
        "OPENVAS_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/openvas_orchestrator.py",
    ),
    "nmap_nse": os.getenv(
        "NMAP_NSE_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/nmap_orchestrator.py",
    ),
    "wazuh_vulnerability": os.getenv(
        "WAZUH_VULN_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/wazuh_vuln_orchestrator.py",
    ),
    "wazuh_sca": os.getenv(
        "WAZUH_SCA_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/wazuh_sca_orchestrator.py",
    ),
    "lynis": os.getenv(
        "LYNIS_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/lynis_orchestrator.py",
    ),
    "nuclei": os.getenv(
        "NUCLEI_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/nuclei_orchestrator.py",
    ),
    "trivy": os.getenv(
        "TRIVY_ORCHESTRATOR",
        "/opt/automated-remediation/scanner_orchestrators/trivy_orchestrator.py",
    ),
}


MAX_TARGET_HOST_LENGTH = 2048
MAX_FINDING_KEY_LENGTH = 4096
MAX_FINDING_CLASS_LENGTH = 128
MAX_ENGINE_METADATA_JSON_LENGTH = 65536

MIN_SCANNER_VERIFY_TIMEOUT = 1
MAX_SCANNER_VERIFY_TIMEOUT = 7200


def _clean_required_string(name, value, max_length):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{name} is required")

    if len(value) > max_length:
        raise ValueError(
            f"{name} exceeds maximum length of {max_length}"
        )

    if "\x00" in value or "\r" in value or "\n" in value:
        raise ValueError(
            f"{name} contains prohibited control characters"
        )

    return value


def _scanner_timeout():
    raw = os.getenv(
        "SCANNER_VERIFY_TIMEOUT",
        "1800",
    ).strip()

    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError(
            "SCANNER_VERIFY_TIMEOUT must be an integer"
        ) from exc

    if not (
        MIN_SCANNER_VERIFY_TIMEOUT
        <= timeout
        <= MAX_SCANNER_VERIFY_TIMEOUT
    ):
        raise RuntimeError(
            "SCANNER_VERIFY_TIMEOUT must be between "
            f"{MIN_SCANNER_VERIFY_TIMEOUT} and "
            f"{MAX_SCANNER_VERIFY_TIMEOUT} seconds"
        )

    return timeout


def dispatch(p):
    if not isinstance(p, dict):
        raise ValueError(
            "Verification payload must be a JSON object"
        )

    finding_id = p.get("finding_id")
    execution_id = p.get("execution_id")

    if finding_id in (None, ""):
        raise ValueError(
            "Missing verification field: finding_id"
        )

    if execution_id in (None, ""):
        raise ValueError(
            "Missing verification field: execution_id"
        )

    target_host = _clean_required_string(
        "target_host",
        p.get("target_host"),
        MAX_TARGET_HOST_LENGTH,
    )

    engine_source = _clean_required_string(
        "engine_source",
        p.get("engine_source"),
        64,
    ).lower()

    finding_class = _clean_required_string(
        "finding_class",
        p.get("finding_class"),
        MAX_FINDING_CLASS_LENGTH,
    )

    finding_key = _clean_required_string(
        "finding_key",
        p.get("finding_key"),
        MAX_FINDING_KEY_LENGTH,
    )

    orchestrator = ORCHESTRATORS.get(
        engine_source
    )

    if not orchestrator:
        raise ValueError(
            "No verification orchestrator configured for "
            f"engine_source={engine_source}"
        )

    if not os.path.isfile(orchestrator):
        raise FileNotFoundError(
            f"Orchestrator does not exist: {orchestrator}"
        )

    engine_metadata = p.get(
        "engine_metadata"
    )

    if engine_metadata is None:
        engine_metadata = {}

    if not isinstance(
        engine_metadata,
        dict,
    ):
        raise ValueError(
            "engine_metadata must be a JSON object"
        )

    metadata_json = json.dumps(
        engine_metadata,
        separators=(",", ":"),
    )

    if (
        len(metadata_json)
        > MAX_ENGINE_METADATA_JSON_LENGTH
    ):
        raise ValueError(
            "engine_metadata exceeds maximum serialised "
            f"length of {MAX_ENGINE_METADATA_JSON_LENGTH}"
        )

    command = [
        sys.executable,
        orchestrator,
        "--mode",
        "verify",
        "--verification-request-stdin",
        "--json",
    ]

    verification_request = json.dumps(
        {
            "target_host": target_host,
            "finding_key": finding_key,
            "finding_class": finding_class,
            "engine_metadata": engine_metadata,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )

    result = subprocess.run(
        command,
        input=verification_request,
        capture_output=True,
        text=True,
        timeout=_scanner_timeout(),
        check=False,
    )

    if result.returncode != 0:
        return {
            "finding_id": finding_id,
            "execution_id": execution_id,
            "engine_source": engine_source,
            "finding_class": finding_class,
            "finding_key": finding_key,
            "target_host": target_host,
            "present": True,
            "verification_status": "FAILED",
            "verification_error": (
                "Scanner orchestrator exited with return "
                f"code {result.returncode}"
            ),
            "scanner_result": {
                "present": True,
                "scanner": engine_source,
                "target_host": target_host,
                "finding_key": finding_key,
                "finding_class": finding_class,
                "evidence": {},
                "verification_error": (
                    result.stderr.strip()
                ),
                "return_code": result.returncode,
            },
        }

    try:
        scanner_result = json.loads(
            result.stdout.strip()
        )
    except Exception as exc:
        raise RuntimeError(
            f"{engine_source} returned invalid JSON: "
            f"{result.stdout[:500]}"
        ) from exc

    present = scanner_result.get(
        "present"
    )

    if not isinstance(
        present,
        bool,
    ):
        raise RuntimeError(
            f"{engine_source} verification result "
            "missing boolean present"
        )

    return {
        "finding_id": finding_id,
        "execution_id": execution_id,
        "engine_source": engine_source,
        "finding_class": finding_class,
        "finding_key": finding_key,
        "target_host": target_host,
        "present": present,
        "verification_status": (
            "FAILED"
            if present
            else "PASSED"
        ),
        "verified_at": scanner_result.get(
            "verified_at"
        ),
        "scanner_result": scanner_result,
    }
