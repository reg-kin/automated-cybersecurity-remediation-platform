#!/usr/bin/env python3

import importlib.util
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR_DIR = REPO_ROOT / "scanner_orchestrators"
ORCHESTRATOR_PATH = ORCHESTRATOR_DIR / "wazuh_sca_orchestrator.py"


def load_orchestrator(wazuh_api_url=None):
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

    spec = importlib.util.spec_from_file_location(
        "wazuh_sca_orchestrator_config_test",
        ORCHESTRATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load orchestrator: {ORCHESTRATOR_PATH}"
        )

    module = importlib.util.module_from_spec(spec)

    environment = {}

    if wazuh_api_url is not None:
        environment["WAZUH_API_URL"] = wazuh_api_url

    with (
        patch.dict(
            os.environ,
            environment,
            clear=True,
        ),
        patch.object(
            logging.handlers,
            "RotatingFileHandler",
            return_value=logging.NullHandler(),
        ),
    ):
        spec.loader.exec_module(module)

    return module


def assert_configuration_rejected(value, expected_message):
    orchestrator = load_orchestrator(value)

    try:
        orchestrator.require_wazuh_api_url()
    except RuntimeError as exc:
        assert str(exc) == expected_message
    else:
        raise AssertionError(
            f"WAZUH_API_URL value {value!r} was unexpectedly accepted."
        )


def main():
    # Importing the orchestrator must remain safe even when the API URL
    # is not configured. Validation occurs only when API access is needed.
    orchestrator = load_orchestrator()

    assert orchestrator.WAZUH_URL == ""

    try:
        orchestrator.require_wazuh_api_url()
    except RuntimeError as exc:
        assert str(exc) == (
            "WAZUH_API_URL must be configured with a non-empty value."
        )
    else:
        raise AssertionError(
            "Missing WAZUH_API_URL was unexpectedly accepted."
        )

    assert_configuration_rejected(
        "   ",
        "WAZUH_API_URL must be configured with a non-empty value.",
    )

    assert_configuration_rejected(
        "wazuh.example.test:55000",
        "WAZUH_API_URL must start with http:// or https://.",
    )

    orchestrator = load_orchestrator(
        "https://wazuh.example.test:55000"
    )

    assert (
        orchestrator.require_wazuh_api_url()
        == "https://wazuh.example.test:55000"
    )

    orchestrator = load_orchestrator(
        "  https://wazuh.example.test:55000/  "
    )

    assert (
        orchestrator.require_wazuh_api_url()
        == "https://wazuh.example.test:55000/"
    )

    source = ORCHESTRATOR_PATH.read_text(
        encoding="utf-8"
    )

    assert "161.97.115.174" not in source

    print(
        "PASS: Wazuh SCA API URL requires explicit neutral configuration"
    )


if __name__ == "__main__":
    main()
