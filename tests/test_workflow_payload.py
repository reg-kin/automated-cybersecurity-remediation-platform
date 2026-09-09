#!/usr/bin/env python3

from copy import deepcopy
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


from remediation.shared.parameter_renderer import (
    ParameterRenderError,
)
from remediation.shared.workflow_payload import (
    WorkflowPayloadError,
    build_controller_payload,
)


def make_queue_row():
    return {
        "finding_id": 42,
        "rule_id": 7,
        "tenant_code": "CUSTOMER_A",
        "target_host": "10.20.30.15",
        "engine_source": "wazuh_vulnerability",
        "finding_class": "package_vulnerability",
        "finding_key": "CVE-2023-4863",
        "finding_title": "Vulnerable libwebp package",
        "capability": "os_patching",
        "playbook_name": "os_patching.yml",
        "remediation_action": "patch_package",
        "automation_tier": "TIER_1",
        "approval_required": False,
        "parameter_template": {
            "package_name": (
                "{{ engine_metadata.package_name }}"
            ),
            "fixed_version": (
                "{{ engine_metadata.fixed_version }}"
            ),
        },
        "required_parameters": [
            "package_name",
        ],
        "engine_metadata": {
            "package_name": "libwebp7",
            "fixed_version": "1.3.2",
        },
        "has_contextual_risk": True,
        "contextual_risk_score": 9.1,
    }


row = make_queue_row()
original = deepcopy(row)

payload = build_controller_payload(row)

assert payload == {
    "finding_id": 42,
    "rule_id": 7,
    "tenant_code": "CUSTOMER_A",
    "target_host": "10.20.30.15",
    "engine_source": "wazuh_vulnerability",
    "finding_class": "package_vulnerability",
    "finding_key": "CVE-2023-4863",
    "finding_title": "Vulnerable libwebp package",
    "capability": "os_patching",
    "playbook_name": "os_patching.yml",
    "remediation_action": "patch_package",
    "automation_tier": "TIER_1",
    "approval_required": False,
    "engine_metadata": {
        "package_name": "libwebp7",
        "fixed_version": "1.3.2",
    },
    "execution_parameters": {
        "package_name": "libwebp7",
        "fixed_version": "1.3.2",
    },
}

assert row == original


# ---------------------------------------------------------------------------
# Literal specialised remediation rule
# ---------------------------------------------------------------------------

literal = make_queue_row()

literal["parameter_template"] = {
    "mode": "0600",
    "path": "/etc/crontab",
    "group": "root",
    "owner": "root",
    "control_type": "file_permission",
}

literal["required_parameters"] = [
    "control_type",
    "path",
    "owner",
    "group",
    "mode",
]

literal["engine_metadata"] = {}

literal_payload = build_controller_payload(literal)

assert literal_payload["execution_parameters"] == {
    "mode": "0600",
    "path": "/etc/crontab",
    "group": "root",
    "owner": "root",
    "control_type": "file_permission",
}


# ---------------------------------------------------------------------------
# Queue risk fields must not leak into controller execution payload
# ---------------------------------------------------------------------------

assert "has_contextual_risk" not in payload
assert "contextual_risk_score" not in payload


# ---------------------------------------------------------------------------
# Missing authoritative queue fields fail closed
# ---------------------------------------------------------------------------

broken = make_queue_row()
del broken["rule_id"]

try:
    build_controller_payload(broken)
except WorkflowPayloadError as exc:
    assert "rule_id" in str(exc)
else:
    raise AssertionError(
        "Expected WorkflowPayloadError for missing rule_id"
    )


# ---------------------------------------------------------------------------
# Parameter rendering failures propagate and prevent payload construction
# ---------------------------------------------------------------------------

broken = make_queue_row()
broken["engine_metadata"] = {}

try:
    build_controller_payload(broken)
except ParameterRenderError as exc:
    assert "package_name" in str(exc)
else:
    raise AssertionError(
        "Expected ParameterRenderError for missing metadata"
    )


# ---------------------------------------------------------------------------
# approval_required must remain an authoritative boolean
# ---------------------------------------------------------------------------

for invalid_approval_required in (
    "false",
    "true",
    0,
    1,
    None,
):
    broken = make_queue_row()
    broken["approval_required"] = invalid_approval_required

    try:
        build_controller_payload(broken)
    except WorkflowPayloadError as exc:
        assert "approval_required must be a boolean" in str(exc)
    else:
        raise AssertionError(
            "Expected WorkflowPayloadError for non-boolean "
            "approval_required"
        )


# ---------------------------------------------------------------------------
# Non-dictionary queue rows fail closed
# ---------------------------------------------------------------------------

try:
    build_controller_payload([])
except WorkflowPayloadError as exc:
    assert "mapping" in str(exc)
else:
    raise AssertionError(
        "Expected WorkflowPayloadError for non-mapping row"
    )


print(
    "PASS: remediation workflow controller payload "
    "regression tests"
)
