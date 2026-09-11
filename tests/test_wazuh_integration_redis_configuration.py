#!/usr/bin/env python3

import ast
import json
import os
import runpy
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


INTEGRATION = Path(
    "integrations/wazuh/integrations/custom-security-findings"
)


def load_redis_configuration():
    source = INTEGRATION.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(INTEGRATION))

    selected_nodes = []

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(
                alias.name == "os"
                for alias in node.names
            ):
                selected_nodes.append(node)

        elif isinstance(node, ast.Assign):
            names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            }

            if names & {"REDIS_HOST", "REDIS_PORT"}:
                selected_nodes.append(node)

    namespace = {}

    exec(
        compile(
            ast.Module(
                body=selected_nodes,
                type_ignores=[],
            ),
            str(INTEGRATION),
            "exec",
        ),
        namespace,
    )

    return (
        namespace.get("REDIS_HOST"),
        namespace.get("REDIS_PORT"),
    )


def test_default_endpoint():
    with patch.dict(
        os.environ,
        {},
        clear=True,
    ):
        host, port = load_redis_configuration()

    assert host == "127.0.0.1", (
        f"Unexpected default REDIS_HOST: {host!r}"
    )

    assert port == 6379, (
        f"Unexpected default REDIS_PORT: {port!r}"
    )


def test_environment_override():
    with patch.dict(
        os.environ,
        {
            "REDIS_HOST": "redis.example.test",
            "REDIS_PORT": "6380",
        },
        clear=True,
    ):
        host, port = load_redis_configuration()

    assert host == "redis.example.test", (
        "REDIS_HOST environment override was not honoured"
    )

    assert port == 6380, (
        "REDIS_PORT environment override was not honoured"
    )


def test_full_log_preserves_native_json_types():
    canonical_payload = {
        "tenant_code": "Customer1",
        "engine_source": "wazuh_vulnerability",
        "severity_score": 7.5,
        "ai_analysis": None,
        "engine_metadata": {
            "targeted_verification_supported": False,
        },
    }

    alert = {
        "rule": {"id": "100501"},
        "full_log": json.dumps(canonical_payload),
        "data": {
            "tenant_code": "Customer1",
            "engine_source": "wazuh_vulnerability",
            "severity_score": "7.500000",
            "ai_analysis": "null",
            "engine_metadata": {
                "targeted_verification_supported": "false",
            },
        },
    }

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
    ) as handle:
        json.dump(alert, handle)
        alert_path = handle.name

    queue = MagicMock()
    job = MagicMock()
    job.id = "test-job"
    queue.enqueue.return_value = job

    try:
        with patch.object(sys, "argv", [str(INTEGRATION), alert_path]), \
             patch("logging.basicConfig"), \
             patch("rq.Queue", return_value=queue), \
             patch("redis.Redis"):
            try:
                runpy.run_path(str(INTEGRATION), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
    finally:
        os.unlink(alert_path)

    queued_payload = queue.enqueue.call_args.args[1]

    assert queued_payload["ai_analysis"] is None
    assert queued_payload["severity_score"] == 7.5
    assert isinstance(queued_payload["severity_score"], float)
    assert queued_payload["engine_metadata"]["targeted_verification_supported"] is False


def main():
    test_default_endpoint()
    test_environment_override()
    test_full_log_preserves_native_json_types()

    print(
        "PASS: Wazuh integration Redis endpoint is "
        "environment-configurable with backward-compatible defaults"
    )


if __name__ == "__main__":
    main()
