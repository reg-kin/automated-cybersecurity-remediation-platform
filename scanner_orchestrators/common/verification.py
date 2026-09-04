"""
Shared Stage-2 verification request transport helpers.

The verification dispatcher sends the canonical verification request as one
JSON object on stdin. Scanner-specific verification semantics remain inside
the individual scanner orchestrators.
"""

import json
import sys
from typing import Any, Dict


MAX_VERIFICATION_REQUEST_SIZE = 73728

MAX_TARGET_HOST_LENGTH = 2048
MAX_FINDING_KEY_LENGTH = 4096
MAX_FINDING_CLASS_LENGTH = 128
MAX_ENGINE_METADATA_JSON_LENGTH = 65536


def _required_string(
    payload: Dict[str, Any],
    name: str,
    max_length: int,
) -> str:
    value = payload.get(name)

    if not isinstance(value, str):
        raise ValueError(
            f"verification request field '{name}' must be a string"
        )

    value = value.strip()

    if not value:
        raise ValueError(
            f"verification request field '{name}' is required"
        )

    if len(value) > max_length:
        raise ValueError(
            f"verification request field '{name}' exceeds "
            f"maximum length of {max_length}"
        )

    if any(
        char in value
        for char in ("\x00", "\r", "\n")
    ):
        raise ValueError(
            f"verification request field '{name}' contains "
            "prohibited control characters"
        )

    return value


def read_verification_request() -> Dict[str, Any]:
    raw = sys.stdin.read(
        MAX_VERIFICATION_REQUEST_SIZE + 1
    )

    if not raw:
        raise ValueError(
            "verification request stdin is empty"
        )

    if len(raw) > MAX_VERIFICATION_REQUEST_SIZE:
        raise ValueError(
            "verification request exceeds maximum size"
        )

    try:
        payload = json.loads(raw)

    except json.JSONDecodeError as exc:
        raise ValueError(
            "verification request stdin is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            "verification request stdin must contain a JSON object"
        )

    target_host = _required_string(
        payload,
        "target_host",
        MAX_TARGET_HOST_LENGTH,
    )

    finding_key = _required_string(
        payload,
        "finding_key",
        MAX_FINDING_KEY_LENGTH,
    )

    finding_class = _required_string(
        payload,
        "finding_class",
        MAX_FINDING_CLASS_LENGTH,
    )

    engine_metadata = payload.get(
        "engine_metadata",
        {},
    )

    if not isinstance(engine_metadata, dict):
        raise ValueError(
            "verification request field 'engine_metadata' "
            "must contain a JSON object"
        )

    engine_metadata_json = json.dumps(
        engine_metadata,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    if len(
        engine_metadata_json
    ) > MAX_ENGINE_METADATA_JSON_LENGTH:
        raise ValueError(
            "verification request field 'engine_metadata' "
            "exceeds maximum serialised size"
        )

    return {
        "target_host": target_host,
        "finding_key": finding_key,
        "finding_class": finding_class,
        "engine_metadata": engine_metadata,
        "engine_metadata_json": engine_metadata_json,
    }
