from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


class ScannerAdapterError(ValueError):
    """Base error for scan execution adapter failures."""


class ScannerAdapterValidationError(ScannerAdapterError):
    """Raised when a leased scan job cannot be safely translated."""


ORCHESTRATOR_FILES = {
    "openvas": "openvas_orchestrator.py",
    "nuclei": "nuclei_orchestrator.py",
    "nmap_nse": "nmap_orchestrator.py",
    "lynis": "lynis_orchestrator.py",
    "trivy": "trivy_orchestrator.py",
    "wazuh_vulnerability": "wazuh_vuln_orchestrator.py",
    "wazuh_sca": "wazuh_sca_orchestrator.py",
}


EXPECTED_EXECUTION_MODELS = {
    "openvas": "CONTROL_PLANE",
    "nuclei": "REMOTE_TARGET",
    "nmap_nse": "REMOTE_TARGET",
    "lynis": "LOCAL_ASSET",
    "trivy": "RESOURCE_TARGET",
    "wazuh_vulnerability": "CONTROL_PLANE",
    "wazuh_sca": "CONTROL_PLANE",
}


ALLOWED_SUBJECT_TYPES = {
    "openvas": {"OPENVAS_TASK"},
    "nuclei": {
        "IP_ADDRESS",
        "HOSTNAME",
        "FQDN",
        "URL",
    },
    "nmap_nse": {
        "IP_ADDRESS",
        "HOSTNAME",
        "FQDN",
    },
    "lynis": {"LOCAL_ASSET"},
    "trivy": {
        "CONTAINER_IMAGE",
        "FILESYSTEM",
    },
    "wazuh_vulnerability": {
        "WAZUH_AGENT_ID",
    },
    "wazuh_sca": {
        "WAZUH_AGENT_ID",
    },
}


ALLOWED_PARAMETER_KEYS = {
    "openvas": set(),
    "nuclei": {
        "task_name",
        "severities",
        "tags",
        "scan_mode",
        "template_id",
    },
    "nmap_nse": {
        "task_name",
        "scan_mode",
        "nse_script",
        "finding_key",
        "ports",
    },
    "lynis": {
        "target_host",
        "filter_mode",
        "task_name",
    },
    "trivy": {
        "scan_type",
        "scanner",
        "scanners",
        "severity",
        "ignore_unfixed",
        "license_full",
    },
    "wazuh_vulnerability": {
        "severities",
    },
    "wazuh_sca": set(),
}


def _require_nonblank(
    value: Any,
    *,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise ScannerAdapterValidationError(
            f"{field_name} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ScannerAdapterValidationError(
            f"{field_name} cannot be empty"
        )

    return cleaned


def _optional_nonblank(
    value: Any,
    *,
    field_name: str,
) -> Optional[str]:
    if value is None:
        return None

    return _require_nonblank(
        value,
        field_name=field_name,
    )


def _require_boolean(
    value: Any,
    *,
    field_name: str,
) -> bool:
    if not isinstance(value, bool):
        raise ScannerAdapterValidationError(
            f"{field_name} must be a boolean"
        )

    return value


def _normalise_parameters(
    scanner_type: str,
    scanner_parameters: Any,
) -> Dict[str, Any]:
    if not isinstance(
        scanner_parameters,
        Mapping,
    ):
        raise ScannerAdapterValidationError(
            "scanner_parameters must be an object"
        )

    parameters = dict(scanner_parameters)

    unknown = (
        set(parameters)
        - ALLOWED_PARAMETER_KEYS[scanner_type]
    )

    if unknown:
        raise ScannerAdapterValidationError(
            "Unsupported scanner parameter(s) "
            f"for {scanner_type}: "
            + ", ".join(sorted(unknown))
        )

    return parameters


def _base_command(
    *,
    scanner_type: str,
    repository_root: Path,
    python_executable: str,
) -> List[str]:
    orchestrator_path = (
        repository_root
        / "scanner_orchestrators"
        / ORCHESTRATOR_FILES[scanner_type]
    )

    if not orchestrator_path.is_file():
        raise ScannerAdapterValidationError(
            "Scanner orchestrator not found: "
            f"{orchestrator_path}"
        )

    return [
        python_executable,
        str(orchestrator_path),
        "--mode",
        "scan",
    ]


def _append_option(
    command: List[str],
    option: str,
    value: Optional[str],
) -> None:
    if value is not None:
        command.extend([option, value])


def _build_openvas(
    *,
    command: List[str],
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    if parameters:
        raise ScannerAdapterValidationError(
            "OpenVAS scan execution does not "
            "accept scanner_parameters"
        )

    command.extend(
        [
            "--task-name",
            subject_value,
            "--json",
        ]
    )

    return command


def _build_nuclei(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    task_name = _require_nonblank(
        parameters.get("task_name"),
        field_name=(
            "scanner_parameters.task_name"
        ),
    )

    scan_mode = _optional_nonblank(
        parameters.get("scan_mode"),
        field_name=(
            "scanner_parameters.scan_mode"
        ),
    )

    if scan_mode is None:
        scan_mode = "default"

    if scan_mode not in {
        "default",
        "specific",
    }:
        raise ScannerAdapterValidationError(
            "Nuclei scan_mode must be "
            "'default' or 'specific'"
        )

    template_id = _optional_nonblank(
        parameters.get("template_id"),
        field_name=(
            "scanner_parameters.template_id"
        ),
    )

    if (
        scan_mode == "specific"
        and template_id is None
    ):
        raise ScannerAdapterValidationError(
            "Nuclei scan_mode 'specific' "
            "requires template_id"
        )

    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--task-name",
            task_name,
            "--target-host",
            subject_value,
            "--scan-mode",
            scan_mode,
        ]
    )

    _append_option(
        command,
        "--severities",
        _optional_nonblank(
            parameters.get("severities"),
            field_name=(
                "scanner_parameters.severities"
            ),
        ),
    )

    _append_option(
        command,
        "--tags",
        _optional_nonblank(
            parameters.get("tags"),
            field_name=(
                "scanner_parameters.tags"
            ),
        ),
    )

    _append_option(
        command,
        "--template-id",
        template_id,
    )

    command.append("--json")

    return command


def _build_nmap(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    task_name = _require_nonblank(
        parameters.get("task_name"),
        field_name=(
            "scanner_parameters.task_name"
        ),
    )

    scan_mode = _optional_nonblank(
        parameters.get("scan_mode"),
        field_name=(
            "scanner_parameters.scan_mode"
        ),
    )

    if scan_mode is None:
        scan_mode = "vuln_only"

    if scan_mode not in {
        "vuln_only",
        "all_vuln",
        "specific",
    }:
        raise ScannerAdapterValidationError(
            "Nmap scan_mode must be one of: "
            "vuln_only, all_vuln, specific"
        )

    nse_script = _optional_nonblank(
        parameters.get("nse_script"),
        field_name=(
            "scanner_parameters.nse_script"
        ),
    )

    if (
        scan_mode == "specific"
        and nse_script is None
    ):
        raise ScannerAdapterValidationError(
            "Nmap scan_mode 'specific' "
            "requires nse_script"
        )

    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--task-name",
            task_name,
            "--target-host",
            subject_value,
            "--scan-mode",
            scan_mode,
        ]
    )

    _append_option(
        command,
        "--nse-script",
        nse_script,
    )

    _append_option(
        command,
        "--finding-key",
        _optional_nonblank(
            parameters.get("finding_key"),
            field_name=(
                "scanner_parameters.finding_key"
            ),
        ),
    )

    _append_option(
        command,
        "--ports",
        _optional_nonblank(
            parameters.get("ports"),
            field_name=(
                "scanner_parameters.ports"
            ),
        ),
    )

    command.append("--json")

    return command


def _build_lynis(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    parameters: Dict[str, Any],
) -> List[str]:
    target_host = _require_nonblank(
        parameters.get("target_host"),
        field_name=(
            "scanner_parameters.target_host"
        ),
    )

    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--target-host",
            target_host,
        ]
    )

    _append_option(
        command,
        "--filter-mode",
        _optional_nonblank(
            parameters.get("filter_mode"),
            field_name=(
                "scanner_parameters.filter_mode"
            ),
        ),
    )

    _append_option(
        command,
        "--task-name",
        _optional_nonblank(
            parameters.get("task_name"),
            field_name=(
                "scanner_parameters.task_name"
            ),
        ),
    )

    command.append("--json")

    return command


def _build_trivy(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    subject_type: str,
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    scan_type = _require_nonblank(
        parameters.get("scan_type"),
        field_name=(
            "scanner_parameters.scan_type"
        ),
    )

    expected_subject = {
        "image": "CONTAINER_IMAGE",
        "folder": "FILESYSTEM",
    }.get(scan_type)

    if expected_subject is None:
        raise ScannerAdapterValidationError(
            "Trivy scan_type must be "
            "'image' or 'folder'"
        )

    if subject_type != expected_subject:
        raise ScannerAdapterValidationError(
            "Trivy scan_type does not match "
            "scanner_subject_type"
        )

    scanner = _optional_nonblank(
        parameters.get("scanner"),
        field_name=(
            "scanner_parameters.scanner"
        ),
    )

    scanners_value = parameters.get(
        "scanners"
    )

    scanners: Optional[str] = None

    if scanners_value is not None:
        if isinstance(
            scanners_value,
            str,
        ):
            scanners = _require_nonblank(
                scanners_value,
                field_name=(
                    "scanner_parameters.scanners"
                ),
            )

        elif (
            isinstance(
                scanners_value,
                Sequence,
            )
            and not isinstance(
                scanners_value,
                (str, bytes),
            )
        ):
            scanner_items = [
                _require_nonblank(
                    item,
                    field_name=(
                        "scanner_parameters.scanners"
                    ),
                )
                for item in scanners_value
            ]

            if not scanner_items:
                raise ScannerAdapterValidationError(
                    "scanner_parameters.scanners "
                    "cannot be empty"
                )

            scanners = ",".join(
                scanner_items
            )

        else:
            raise ScannerAdapterValidationError(
                "scanner_parameters.scanners must "
                "be a string or array of strings"
            )

    if (
        scanner is not None
        and scanners is not None
    ):
        raise ScannerAdapterValidationError(
            "Trivy accepts either scanner "
            "or scanners, not both"
        )

    valid_scanners = {
        "vuln",
        "misconfig",
        "secret",
        "license",
    }

    if (
        scanner is not None
        and scanner not in valid_scanners
    ):
        raise ScannerAdapterValidationError(
            "Unsupported Trivy scanner: "
            f"{scanner}"
        )

    if scanners is not None:
        scanner_set = {
            value.strip()
            for value in scanners.split(",")
            if value.strip()
        }

        invalid = (
            scanner_set
            - valid_scanners
        )

        if invalid:
            raise ScannerAdapterValidationError(
                "Unsupported Trivy scanner(s): "
                + ", ".join(sorted(invalid))
            )

    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--scan-type",
            scan_type,
            "--target",
            subject_value,
        ]
    )

    _append_option(
        command,
        "--scanner",
        scanner,
    )

    _append_option(
        command,
        "--scanners",
        scanners,
    )

    _append_option(
        command,
        "--severity",
        _optional_nonblank(
            parameters.get("severity"),
            field_name=(
                "scanner_parameters.severity"
            ),
        ),
    )

    if "ignore_unfixed" in parameters:
        if _require_boolean(
            parameters["ignore_unfixed"],
            field_name=(
                "scanner_parameters.ignore_unfixed"
            ),
        ):
            command.append(
                "--ignore-unfixed"
            )

    if "license_full" in parameters:
        if _require_boolean(
            parameters["license_full"],
            field_name=(
                "scanner_parameters.license_full"
            ),
        ):
            command.append(
                "--license-full"
            )

    command.append("--json")

    return command


def _build_wazuh_vulnerability(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--agent-id",
            subject_value,
        ]
    )

    _append_option(
        command,
        "--severities",
        _optional_nonblank(
            parameters.get("severities"),
            field_name=(
                "scanner_parameters.severities"
            ),
        ),
    )

    command.append("--json")

    return command


def _build_wazuh_sca(
    *,
    command: List[str],
    tenant_code: str,
    service_tier: str,
    subject_value: str,
    parameters: Dict[str, Any],
) -> List[str]:
    if parameters:
        raise ScannerAdapterValidationError(
            "Wazuh SCA scan execution does not "
            "accept scanner_parameters"
        )

    command.extend(
        [
            "--tenant-code",
            tenant_code,
            "--service-tier",
            service_tier,
            "--agent-id",
            subject_value,
            "--json",
        ]
    )

    return command


def build_scanner_command(
    *,
    scanner_type: Any,
    tenant_code: Any,
    service_tier: Any,
    execution_model: Any,
    scanner_subject_type: Any,
    scanner_subject_value: Any,
    scanner_parameters: Any,
    repository_root: Optional[
        Path
    ] = None,
    python_executable: Optional[
        str
    ] = None,
) -> List[str]:
    scanner_type = _require_nonblank(
        scanner_type,
        field_name="scanner_type",
    )

    if scanner_type not in ORCHESTRATOR_FILES:
        raise ScannerAdapterValidationError(
            f"Unsupported scanner_type: {scanner_type}"
        )

    tenant_code = _require_nonblank(
        tenant_code,
        field_name="tenant_code",
    )

    service_tier = _require_nonblank(
        service_tier,
        field_name="service_tier",
    )

    if service_tier not in {
        "GOLD",
        "STANDARD",
        "BRONZE",
    }:
        raise ScannerAdapterValidationError(
            "service_tier must be one of: "
            "GOLD, STANDARD, BRONZE"
        )

    execution_model = _require_nonblank(
        execution_model,
        field_name="execution_model",
    )

    expected_execution_model = (
        EXPECTED_EXECUTION_MODELS[
            scanner_type
        ]
    )

    if (
        execution_model
        != expected_execution_model
    ):
        raise ScannerAdapterValidationError(
            "execution_model does not match "
            f"scanner_type {scanner_type}"
        )

    scanner_subject_type = _require_nonblank(
        scanner_subject_type,
        field_name="scanner_subject_type",
    )

    if (
        scanner_subject_type
        not in ALLOWED_SUBJECT_TYPES[
            scanner_type
        ]
    ):
        raise ScannerAdapterValidationError(
            "scanner_subject_type is not valid "
            f"for scanner_type {scanner_type}"
        )

    scanner_subject_value = _require_nonblank(
        scanner_subject_value,
        field_name=(
            "scanner_subject_value"
        ),
    )

    parameters = _normalise_parameters(
        scanner_type,
        scanner_parameters,
    )

    if repository_root is None:
        repository_root = (
            Path(__file__)
            .resolve()
            .parents[1]
        )

    repository_root = Path(
        repository_root
    ).resolve()

    if python_executable is None:
        python_executable = sys.executable

    python_executable = _require_nonblank(
        python_executable,
        field_name="python_executable",
    )

    command = _base_command(
        scanner_type=scanner_type,
        repository_root=repository_root,
        python_executable=python_executable,
    )

    if scanner_type == "openvas":
        return _build_openvas(
            command=command,
            subject_value=(
                scanner_subject_value
            ),
            parameters=parameters,
        )

    if scanner_type == "nuclei":
        return _build_nuclei(
            command=command,
            tenant_code=tenant_code,
            service_tier=service_tier,
            subject_value=(
                scanner_subject_value
            ),
            parameters=parameters,
        )

    if scanner_type == "nmap_nse":
        return _build_nmap(
            command=command,
            tenant_code=tenant_code,
            service_tier=service_tier,
            subject_value=(
                scanner_subject_value
            ),
            parameters=parameters,
        )

    if scanner_type == "lynis":
        return _build_lynis(
            command=command,
            tenant_code=tenant_code,
            service_tier=service_tier,
            parameters=parameters,
        )

    if scanner_type == "trivy":
        return _build_trivy(
            command=command,
            tenant_code=tenant_code,
            service_tier=service_tier,
            subject_type=(
                scanner_subject_type
            ),
            subject_value=(
                scanner_subject_value
            ),
            parameters=parameters,
        )

    if scanner_type == (
        "wazuh_vulnerability"
    ):
        return (
            _build_wazuh_vulnerability(
                command=command,
                tenant_code=tenant_code,
                service_tier=service_tier,
                subject_value=(
                    scanner_subject_value
                ),
                parameters=parameters,
            )
        )

    if scanner_type == "wazuh_sca":
        return _build_wazuh_sca(
            command=command,
            tenant_code=tenant_code,
            service_tier=service_tier,
            subject_value=(
                scanner_subject_value
            ),
            parameters=parameters,
        )

    raise ScannerAdapterValidationError(
        f"Unsupported scanner_type: {scanner_type}"
    )
