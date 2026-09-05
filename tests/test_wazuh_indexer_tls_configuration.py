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
ORCHESTRATOR_PATH = ORCHESTRATOR_DIR / "wazuh_vuln_orchestrator.py"


def load_orchestrator(
    indexer_url=None,
    ca_bundle=None,
):
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

    spec = importlib.util.spec_from_file_location(
        "wazuh_vuln_orchestrator_tls_test",
        ORCHESTRATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load orchestrator: {ORCHESTRATOR_PATH}"
        )

    module = importlib.util.module_from_spec(spec)

    environment = {
        "LOG_DIR": "/tmp/wazuh-indexer-tls-test",
    }

    if indexer_url is not None:
        environment["WAZUH_INDEXER_URL"] = indexer_url

    if ca_bundle is not None:
        environment["WAZUH_INDEXER_CA_BUNDLE"] = ca_bundle

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


def assert_configuration_rejected(
    value,
    expected_message,
):
    orchestrator = load_orchestrator(
        indexer_url=value
    )

    try:
        orchestrator.require_wazuh_indexer_url()
    except RuntimeError as exc:
        assert str(exc) == expected_message
    else:
        raise AssertionError(
            f"WAZUH_INDEXER_URL value {value!r} was unexpectedly accepted."
        )


def main():
    orchestrator = load_orchestrator()

    assert (
        orchestrator.INDEXER_URL
        == "https://127.0.0.1:9200"
    )

    assert (
        orchestrator.require_wazuh_indexer_url()
        == "https://127.0.0.1:9200"
    )

    assert_configuration_rejected(
        "",
        "WAZUH_INDEXER_URL must be configured with a non-empty value.",
    )

    assert_configuration_rejected(
        "   ",
        "WAZUH_INDEXER_URL must be configured with a non-empty value.",
    )

    assert_configuration_rejected(
        "http://127.0.0.1:9200",
        "WAZUH_INDEXER_URL must start with https://.",
    )

    assert_configuration_rejected(
        "wazuh-indexer.example.test:9200",
        "WAZUH_INDEXER_URL must start with https://.",
    )

    orchestrator = load_orchestrator(
        indexer_url="https://wazuh-indexer.example.test:9200",
    )

    assert (
        orchestrator.require_wazuh_indexer_url()
        == "https://wazuh-indexer.example.test:9200"
    )

    session = orchestrator.get_session()

    assert session.verify is True

    orchestrator = load_orchestrator(
        indexer_url="https://wazuh-indexer.example.test:9200",
        ca_bundle="/etc/ssl/certs/wazuh-indexer-ca.pem",
    )

    session = orchestrator.get_session()

    assert (
        session.verify
        == "/etc/ssl/certs/wazuh-indexer-ca.pem"
    )

    source = ORCHESTRATOR_PATH.read_text(
        encoding="utf-8"
    )

    assert "disable_warnings" not in source
    assert "InsecureRequestWarning" not in source
    assert "session.verify = False" not in source

    print(
        "PASS: Wazuh Indexer requires HTTPS and mandatory TLS verification"
    )


if __name__ == "__main__":
    main()
