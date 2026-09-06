#!/usr/bin/env python3

import ast
import os
from pathlib import Path
from unittest.mock import patch


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


def main():
    test_default_endpoint()
    test_environment_override()

    print(
        "PASS: Wazuh integration Redis endpoint is "
        "environment-configurable with backward-compatible defaults"
    )


if __name__ == "__main__":
    main()
