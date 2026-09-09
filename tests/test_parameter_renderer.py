#!/usr/bin/env python3

from copy import deepcopy
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


from remediation.shared.parameter_renderer import (
    ParameterRenderError,
    render_parameter_template,
)


def expect_render_error(fn, expected):
    try:
        fn()
    except ParameterRenderError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(
            "Expected ParameterRenderError containing: "
            f"{expected}"
        )


# ---------------------------------------------------------------------------
# Literal deterministic parameters
# ---------------------------------------------------------------------------

literal_template = {
    "mode": "0600",
    "path": "/etc/crontab",
    "group": "root",
    "owner": "root",
    "control_type": "file_permission",
}

literal_result = render_parameter_template(
    literal_template,
    {},
    [
        "control_type",
        "path",
        "owner",
        "group",
        "mode",
    ],
)

assert literal_result == literal_template
assert literal_result is not literal_template


# ---------------------------------------------------------------------------
# Single and multiple engine_metadata substitutions
# ---------------------------------------------------------------------------

package_result = render_parameter_template(
    {
        "package_name": (
            "{{ engine_metadata.package_name }}"
        ),
        "fixed_version": (
            "{{ engine_metadata.fixed_version }}"
        ),
    },
    {
        "package_name": "openssl",
        "fixed_version": "3.0.13-0ubuntu3.5",
    },
    ["package_name"],
)

assert package_result == {
    "package_name": "openssl",
    "fixed_version": "3.0.13-0ubuntu3.5",
}


# ---------------------------------------------------------------------------
# Preserve JSON value types
# ---------------------------------------------------------------------------

typed_result = render_parameter_template(
    {
        "port": "{{ engine_metadata.port }}",
        "enabled": "{{ engine_metadata.enabled }}",
        "tasks": "{{ engine_metadata.tasks }}",
    },
    {
        "port": 443,
        "enabled": False,
        "tasks": [
            "task_a",
            "task_b",
        ],
    },
    [
        "port",
        "enabled",
        "tasks",
    ],
)

assert typed_result["port"] == 443
assert typed_result["enabled"] is False
assert typed_result["tasks"] == [
    "task_a",
    "task_b",
]


# ---------------------------------------------------------------------------
# Nested JSON structures remain deterministic
# ---------------------------------------------------------------------------

nested_result = render_parameter_template(
    {
        "config": {
            "path": "{{ engine_metadata.config_file }}",
            "restart": True,
        }
    },
    {
        "config_file": "/etc/example.conf",
    },
    [],
)

assert nested_result == {
    "config": {
        "path": "/etc/example.conf",
        "restart": True,
    }
}


# ---------------------------------------------------------------------------
# Missing referenced metadata fails closed
# ---------------------------------------------------------------------------

expect_render_error(
    lambda: render_parameter_template(
        {
            "package_name": (
                "{{ engine_metadata.package_name }}"
            )
        },
        {},
        ["package_name"],
    ),
    "Missing engine_metadata value",
)


# ---------------------------------------------------------------------------
# Required null and blank values fail closed
# ---------------------------------------------------------------------------

expect_render_error(
    lambda: render_parameter_template(
        {
            "package_name": (
                "{{ engine_metadata.package_name }}"
            )
        },
        {
            "package_name": None,
        },
        ["package_name"],
    ),
    "is null",
)

expect_render_error(
    lambda: render_parameter_template(
        {
            "package_name": (
                "{{ engine_metadata.package_name }}"
            )
        },
        {
            "package_name": "   ",
        },
        ["package_name"],
    ),
    "is blank",
)


# ---------------------------------------------------------------------------
# Required parameter absent from rendered result
# ---------------------------------------------------------------------------

expect_render_error(
    lambda: render_parameter_template(
        {},
        {},
        ["package_name"],
    ),
    "Missing required remediation parameter",
)


# ---------------------------------------------------------------------------
# Unsupported template namespaces and expressions fail closed
# ---------------------------------------------------------------------------

expect_render_error(
    lambda: render_parameter_template(
        {
            "value": "{{ finding.target_host }}"
        },
        {},
        [],
    ),
    "Unsupported parameter template expression",
)

expect_render_error(
    lambda: render_parameter_template(
        {
            "value": (
                "{{ engine_metadata.package_name | upper }}"
            )
        },
        {
            "package_name": "openssl",
        },
        [],
    ),
    "Unsupported parameter template expression",
)

expect_render_error(
    lambda: render_parameter_template(
        {
            "value": (
                "prefix-{{ engine_metadata.package_name }}"
            )
        },
        {
            "package_name": "openssl",
        },
        [],
    ),
    "Unsupported parameter template expression",
)


# ---------------------------------------------------------------------------
# Malformed input objects fail closed
# ---------------------------------------------------------------------------

expect_render_error(
    lambda: render_parameter_template(
        [],
        {},
        [],
    ),
    "parameter_template must be a JSON object",
)

expect_render_error(
    lambda: render_parameter_template(
        {},
        [],
        [],
    ),
    "engine_metadata must be a JSON object",
)

expect_render_error(
    lambda: render_parameter_template(
        {},
        {},
        [""],
    ),
    "invalid parameter name",
)

expect_render_error(
    lambda: render_parameter_template(
        {},
        {},
        {},
    ),
    "required_parameters must be a list",
)

expect_render_error(
    lambda: render_parameter_template(
        {},
        {},
        "",
    ),
    "required_parameters must be a list",
)

# ---------------------------------------------------------------------------
# Renderer must never mutate authoritative source objects
# ---------------------------------------------------------------------------

source_template = {
    "package_name": "{{ engine_metadata.package_name }}",
    "nested": {
        "literal": [
            "one",
            "two",
        ]
    },
}

source_metadata = {
    "package_name": "openssl",
}

original_template = deepcopy(source_template)
original_metadata = deepcopy(source_metadata)

rendered = render_parameter_template(
    source_template,
    source_metadata,
    ["package_name"],
)

assert rendered["package_name"] == "openssl"
assert source_template == original_template
assert source_metadata == original_metadata


print(
    "PASS: deterministic remediation parameter rendering "
    "regression tests"
)
