from copy import deepcopy
import re


class ParameterRenderError(ValueError):
    """
    Raised when a remediation parameter template cannot be
    rendered deterministically and safely.
    """


_ENGINE_METADATA_PLACEHOLDER = re.compile(
    r"^\{\{\s*engine_metadata\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$"
)


def _render_value(value, engine_metadata):
    """
    Render a single template value.

    V1 deliberately supports only exact placeholders of the form:

        {{ engine_metadata.key }}

    A placeholder occupies the complete string value. Arbitrary
    expressions, filters, function calls, embedded interpolation,
    and other template namespaces are not supported.
    """

    if isinstance(value, dict):
        return {
            key: _render_value(item, engine_metadata)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _render_value(item, engine_metadata)
            for item in value
        ]

    if not isinstance(value, str):
        return deepcopy(value)

    match = _ENGINE_METADATA_PLACEHOLDER.fullmatch(value)

    if match:
        key = match.group(1)

        if key not in engine_metadata:
            raise ParameterRenderError(
                "Missing engine_metadata value required by "
                f"parameter template: {key}"
            )

        return deepcopy(engine_metadata[key])

    if "{{" in value or "}}" in value:
        raise ParameterRenderError(
            "Unsupported parameter template expression: "
            f"{value}"
        )

    return value


def _validate_required_parameters(
    rendered,
    required_parameters,
):
    if not isinstance(required_parameters, list):
        raise ParameterRenderError(
            "required_parameters must be a list"
        )

    for name in required_parameters:
        if not isinstance(name, str) or not name:
            raise ParameterRenderError(
                "required_parameters contains an invalid "
                "parameter name"
            )

        if name not in rendered:
            raise ParameterRenderError(
                f"Missing required remediation parameter: {name}"
            )

        value = rendered[name]

        if value is None:
            raise ParameterRenderError(
                f"Required remediation parameter is null: {name}"
            )

        if isinstance(value, str) and not value.strip():
            raise ParameterRenderError(
                f"Required remediation parameter is blank: {name}"
            )


def render_parameter_template(
    parameter_template,
    engine_metadata,
    required_parameters=None,
):
    """
    Deterministically render remediation execution parameters.

    parameter_template:
        JSON-compatible object persisted in remediation_rules.

    engine_metadata:
        Scanner/orchestrator metadata associated with the finding.

    required_parameters:
        Names declared by remediation_rules.required_parameters.

    Returns:
        A new dictionary suitable for the controller's
        execution_parameters field.

    The source objects are never modified.
    """

    if not isinstance(parameter_template, dict):
        raise ParameterRenderError(
            "parameter_template must be a JSON object"
        )

    if engine_metadata is None:
        engine_metadata = {}

    if not isinstance(engine_metadata, dict):
        raise ParameterRenderError(
            "engine_metadata must be a JSON object"
        )

    rendered = {
        key: _render_value(value, engine_metadata)
        for key, value in parameter_template.items()
    }

    if required_parameters is None:
        required_parameters = []

    _validate_required_parameters(
        rendered,
        required_parameters,
    )

    return rendered
