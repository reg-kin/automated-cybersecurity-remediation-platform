from copy import deepcopy

from remediation.shared.parameter_renderer import (
    render_parameter_template,
)


class WorkflowPayloadError(ValueError):
    """
    Raised when a prioritised remediation queue row cannot be
    converted into a valid controller request.
    """


_REQUIRED_QUEUE_FIELDS = (
    "finding_id",
    "rule_id",
    "tenant_code",
    "target_host",
    "engine_source",
    "finding_class",
    "finding_key",
    "finding_title",
    "capability",
    "playbook_name",
    "remediation_action",
    "automation_tier",
    "approval_required",
    "parameter_template",
    "required_parameters",
)


def build_controller_payload(queue_row):
    """
    Convert one authoritative prioritised_remediation_queue row
    into the request contract expected by POST /remediate.

    This function performs no routing, prioritisation, approval,
    database mutation, execution, or network activity.
    """

    if not isinstance(queue_row, dict):
        raise WorkflowPayloadError(
            "queue_row must be a mapping"
        )

    missing = [
        field
        for field in _REQUIRED_QUEUE_FIELDS
        if field not in queue_row
    ]

    if missing:
        raise WorkflowPayloadError(
            "Missing prioritised remediation queue fields: "
            + ", ".join(missing)
        )

    engine_metadata = queue_row.get("engine_metadata")

    if engine_metadata is None:
        engine_metadata = {}

    execution_parameters = render_parameter_template(
        queue_row["parameter_template"],
        engine_metadata,
        queue_row["required_parameters"],
    )

    approval_required = queue_row["approval_required"]

    if not isinstance(approval_required, bool):
        raise WorkflowPayloadError(
            "approval_required must be a boolean"
        )

    return {
        "finding_id": queue_row["finding_id"],
        "rule_id": queue_row["rule_id"],
        "tenant_code": queue_row["tenant_code"],
        "target_host": queue_row["target_host"],
        "engine_source": queue_row["engine_source"],
        "finding_class": queue_row["finding_class"],
        "finding_key": queue_row["finding_key"],
        "finding_title": queue_row["finding_title"],
        "capability": queue_row["capability"],
        "playbook_name": queue_row["playbook_name"],
        "remediation_action": queue_row["remediation_action"],
        "automation_tier": queue_row["automation_tier"],
        "approval_required": approval_required,
        "engine_metadata": deepcopy(engine_metadata),
        "execution_parameters": execution_parameters,
    }
