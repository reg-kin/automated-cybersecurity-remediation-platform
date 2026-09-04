#!/usr/bin/env python3

from pathlib import Path
from unittest.mock import Mock, patch
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from remediation.controllers import base


class DummyConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def close(self):
        pass


class RuntimeTestController(base.BaseController):
    capability = "os_patching"


controller = RuntimeTestController()


def finding(**overrides):
    value = {
        "finding_id": 101,
        "lifecycle_status": "OPEN",
        "engine_source": "nuclei",
        "finding_class": "os_package_vulnerability",
        "finding_key": "finding-key-101",
        "target_host": "192.0.2.10",
        "engine_metadata": {},
    }
    value.update(overrides)
    return value


def rule(**overrides):
    value = {
        "rule_id": 201,
        "rule_name": "runtime-test-rule",
        "finding_class": "os_package_vulnerability",
        "capability": "os_patching",
        "playbook_name": "os_patching.yml",
        "remediation_action": "patch_package",
        "required_parameters": [],
        "automation_tier": "TIER_1",
        "approval_required": False,
        "enabled": True,
    }
    value.update(overrides)
    return value


def payload(**overrides):
    value = {
        "finding_id": 101,
        "rule_id": 201,
        "target_host": "192.0.2.10",
        "engine_source": "nuclei",
        "finding_class": "os_package_vulnerability",
        "finding_key": "finding-key-101",
        "capability": "os_patching",
        "playbook_name": "os_patching.yml",
        "remediation_action": "patch_package",
        "automation_tier": "TIER_1",
        "approval_required": False,
        "execution_parameters": {},
        "engine_metadata": {},
    }
    value.update(overrides)
    return value


def expect_value_error(fn, expected):
    try:
        fn()
    except ValueError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(
            f"Expected ValueError containing: {expected}"
        )


# ---------------------------------------------------------------------------
# Authoritative finding and rule validation
# ---------------------------------------------------------------------------

expect_value_error(
    lambda: controller.validate(
        payload(target_host="192.0.2.99"),
        rule(),
        finding(),
    ),
    "does not match finding",
)

expect_value_error(
    lambda: controller.validate(
        payload(playbook_name="service_config.yml"),
        rule(),
        finding(),
    ),
    "does not match remediation rule",
)

expect_value_error(
    lambda: controller.validate(
        payload(),
        rule(enabled=False),
        finding(),
    ),
    "is disabled",
)

expect_value_error(
    lambda: controller.validate(
        payload(
            automation_tier="TIER_3",
            approval_required=False,
        ),
        rule(
            automation_tier="TIER_3",
            approval_required=False,
        ),
        finding(),
    ),
    "TIER_3 remediation must require human approval",
)

expect_value_error(
    lambda: controller.validate(
        payload(approved=True),
        rule(),
        finding(),
    ),
    "cannot self-approve",
)

expect_value_error(
    lambda: controller.validate(
        payload(
            remediation_action="manual_escalation"
        ),
        rule(
            remediation_action="manual_escalation"
        ),
        finding(),
    ),
    "cannot be executed",
)


# ---------------------------------------------------------------------------
# Approval gate: persist execution but do not invoke Ansible
# ---------------------------------------------------------------------------

approval_rule = rule(
    automation_tier="TIER_3",
    approval_required=True,
)

approval_payload = payload(
    automation_tier="TIER_3",
    approval_required=True,
)

create_execution = Mock(return_value=301)
run_ansible = Mock()

with (
    patch.object(
        base.db,
        "connect",
        side_effect=lambda: DummyConnection(),
    ),
    patch.object(
        base.db,
        "get_remediation_rule",
        return_value=approval_rule,
    ),
    patch.object(
        base.db,
        "get_finding",
        return_value=finding(),
    ),
    patch.object(
        base.db,
        "ensure_claimed",
    ),
    patch.object(
        base.db,
        "create_execution",
        create_execution,
    ),
    patch.object(
        base,
        "run_ansible",
        run_ansible,
    ),
):
    result = controller.execute(
        approval_payload
    )

assert result == {
    "success": True,
    "execution_id": 301,
    "status": "AWAITING_APPROVAL",
    "approval_required": True,
    "executed": False,
}

run_ansible.assert_not_called()

created_payload = (
    create_execution.call_args.args[1]
)

assert (
    created_payload["initial_status"]
    == "AWAITING_APPROVAL"
)


# ---------------------------------------------------------------------------
# Stage 1 failure: fail execution, reopen finding, never run Stage 2
# ---------------------------------------------------------------------------

update_status = Mock()
complete_verification = Mock()
reopen_failed = Mock()
run_stage2 = Mock()

with (
    patch.object(
        base.db,
        "connect",
        return_value=DummyConnection(),
    ),
    patch.object(
        base.db,
        "begin_verification",
        return_value=401,
    ),
    patch.object(
        base.db,
        "complete_verification",
        complete_verification,
    ),
    patch.object(
        base.db,
        "update_execution_status",
        update_status,
    ),
    patch.object(
        base.db,
        "reopen_failed",
        reopen_failed,
    ),
    patch.object(
        base,
        "run_ansible",
        return_value={
            "success": False,
            "job_id": "job-stage1-fail",
            "verification": {
                "passed": False,
                "reason": "controlled failure",
            },
        },
    ),
    patch.object(
        base,
        "run_stage2",
        run_stage2,
    ),
    patch.object(
        base,
        "SKIP_STAGE2",
        False,
    ),
):
    result = controller.execute_existing(
        payload(),
        302,
    )

assert result["success"] is False
assert result["stage1"]["status"] == "FAILED"

run_stage2.assert_not_called()
reopen_failed.assert_called_once()

statuses = [
    call.args[2]
    for call in update_status.call_args_list
]

assert statuses == [
    "RUNNING",
    "FAILED",
]

assert any(
    call.args[2] == "FAILED"
    for call in complete_verification.call_args_list
)


# ---------------------------------------------------------------------------
# Immediate Stage 2 success: absence is required to resolve the finding
# ---------------------------------------------------------------------------

update_status = Mock()
resolve_finding = Mock()
reopen_failed = Mock()

with (
    patch.object(
        base.db,
        "connect",
        return_value=DummyConnection(),
    ),
    patch.object(
        base.db,
        "begin_verification",
        side_effect=[501, 502],
    ),
    patch.object(
        base.db,
        "complete_verification",
    ),
    patch.object(
        base.db,
        "update_execution_status",
        update_status,
    ),
    patch.object(
        base.db,
        "resolve_finding",
        resolve_finding,
    ),
    patch.object(
        base.db,
        "reopen_failed",
        reopen_failed,
    ),
    patch.object(
        base,
        "run_ansible",
        return_value={
            "success": True,
            "job_id": "job-stage2-success",
            "verification": {
                "passed": True,
            },
        },
    ),
    patch.object(
        base,
        "run_stage2",
        return_value={
            "verification_status": "PASSED",
            "present": False,
        },
    ),
    patch.object(
        base,
        "SKIP_STAGE2",
        False,
    ),
):
    result = controller.execute_existing(
        payload(),
        303,
    )

assert result["success"] is True
resolve_finding.assert_called_once()
reopen_failed.assert_not_called()

statuses = [
    call.args[2]
    for call in update_status.call_args_list
]

assert statuses == [
    "RUNNING",
    "STAGE1_PASSED",
    "VERIFYING",
    "SUCCESS",
]


# ---------------------------------------------------------------------------
# Immediate Stage 2 failure: finding still present
# ---------------------------------------------------------------------------

update_status = Mock()
resolve_finding = Mock()
reopen_failed = Mock()

with (
    patch.object(
        base.db,
        "connect",
        return_value=DummyConnection(),
    ),
    patch.object(
        base.db,
        "begin_verification",
        side_effect=[601, 602],
    ),
    patch.object(
        base.db,
        "complete_verification",
    ),
    patch.object(
        base.db,
        "update_execution_status",
        update_status,
    ),
    patch.object(
        base.db,
        "resolve_finding",
        resolve_finding,
    ),
    patch.object(
        base.db,
        "reopen_failed",
        reopen_failed,
    ),
    patch.object(
        base,
        "run_ansible",
        return_value={
            "success": True,
            "job_id": "job-stage2-present",
            "verification": {
                "passed": True,
            },
        },
    ),
    patch.object(
        base,
        "run_stage2",
        return_value={
            "verification_status": "FAILED",
            "present": True,
        },
    ),
    patch.object(
        base,
        "SKIP_STAGE2",
        False,
    ),
):
    result = controller.execute_existing(
        payload(),
        304,
    )

assert result["success"] is False
assert (
    result["error"]
    == "Stage 2 scanner verification failed"
)

resolve_finding.assert_not_called()
reopen_failed.assert_called_once()

statuses = [
    call.args[2]
    for call in update_status.call_args_list
]

assert statuses[-1] == "FAILED"


# ---------------------------------------------------------------------------
# Stage 2 infrastructure error must fail closed
# ---------------------------------------------------------------------------

update_status = Mock()
reopen_failed = Mock()

with (
    patch.object(
        base.db,
        "connect",
        return_value=DummyConnection(),
    ),
    patch.object(
        base.db,
        "begin_verification",
        side_effect=[701, 702],
    ),
    patch.object(
        base.db,
        "complete_verification",
    ),
    patch.object(
        base.db,
        "update_execution_status",
        update_status,
    ),
    patch.object(
        base.db,
        "reopen_failed",
        reopen_failed,
    ),
    patch.object(
        base,
        "run_ansible",
        return_value={
            "success": True,
            "job_id": "job-stage2-error",
            "verification": {
                "passed": True,
            },
        },
    ),
    patch.object(
        base,
        "run_stage2",
        side_effect=RuntimeError(
            "verification gateway unavailable"
        ),
    ),
    patch.object(
        base,
        "SKIP_STAGE2",
        False,
    ),
):
    result = controller.execute_existing(
        payload(),
        305,
    )

assert result["success"] is False
assert (
    "verification gateway unavailable"
    in result["error"]
)

reopen_failed.assert_called_once()

statuses = [
    call.args[2]
    for call in update_status.call_args_list
]

assert statuses[-1] == "FAILED"


# ---------------------------------------------------------------------------
# Deferred Wazuh Stage 2: create pending work and never call gateway
# ---------------------------------------------------------------------------

update_status = Mock()
create_deferred = Mock(
    return_value=(801,)
)
run_stage2 = Mock()

deferred_payload = payload(
    engine_source="wazuh_vulnerability",
    engine_metadata={
        "verification_capability":
            "asynchronous_state_refresh",
        "targeted_verification_supported": False,
        "agent_id": "007",
    },
)

with (
    patch.object(
        base.db,
        "connect",
        return_value=DummyConnection(),
    ),
    patch.object(
        base.db,
        "begin_verification",
        side_effect=[8011, 8012],
    ),
    patch.object(
        base.db,
        "complete_verification",
    ),
    patch.object(
        base.db,
        "update_execution_status",
        update_status,
    ),
    patch.object(
        base.db,
        "create_deferred_verification_job",
        create_deferred,
    ),
    patch.object(
        base,
        "run_ansible",
        return_value={
            "success": True,
            "job_id": "job-deferred",
            "verification": {
                "passed": True,
            },
        },
    ),
    patch.object(
        base,
        "run_stage2",
        run_stage2,
    ),
    patch.object(
        base,
        "SKIP_STAGE2",
        False,
    ),
):
    result = controller.execute_existing(
        deferred_payload,
        306,
    )

assert result["success"] is True
assert result["executed"] is True
assert result["status"] == "VERIFYING"
assert (
    result["verification_strategy"]
    == "DEFERRED"
)
assert result["stage2"]["status"] == "PENDING"
assert (
    result["stage2"]["deferred_job_id"]
    == 801
)

run_stage2.assert_not_called()
create_deferred.assert_called_once()

deferred_args = (
    create_deferred.call_args.kwargs
)

assert deferred_args["execution_id"] == 306
assert deferred_args["finding_id"] == 101
assert deferred_args["verification_id"] == 8012
assert (
    deferred_args["engine_source"]
    == "wazuh_vulnerability"
)
assert (
    deferred_args["scanner_subject_type"]
    == "wazuh_agent"
)
assert (
    deferred_args["scanner_subject_id"]
    == "007"
)

statuses = [
    call.args[2]
    for call in update_status.call_args_list
]

assert statuses == [
    "RUNNING",
    "STAGE1_PASSED",
    "VERIFYING",
]


print(
    "PASS: remediation controller runtime enforces "
    "authoritative routing, approval, Stage 1, immediate "
    "Stage 2 and deferred Stage 2 semantics"
)
