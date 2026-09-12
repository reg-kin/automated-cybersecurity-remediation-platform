#!/usr/bin/env python3

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from scan_coordination.scanner_adapters import (
    ScannerAdapterValidationError,
    build_scanner_command,
)


def expect_validation_error(
    *,
    description,
    **kwargs,
):
    try:
        build_scanner_command(
            repository_root=ROOT,
            python_executable=sys.executable,
            **kwargs,
        )
    except ScannerAdapterValidationError:
        print(
            f"PASS: {description}"
        )
        return

    raise AssertionError(
        f"Expected validation error: {description}"
    )


def assert_command_contains(
    command,
    *expected,
):
    for value in expected:
        assert value in command, (
            f"Expected {value!r} in command: "
            f"{command!r}"
        )


def assert_option_value(
    command,
    option,
    expected_value,
):
    index = command.index(
        option
    )

    assert command[
        index + 1
    ] == expected_value


def main():
    # --------------------------------------------------------------
    # OpenVAS
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="openvas",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="CONTROL_PLANE",
        scanner_subject_type="OPENVAS_TASK",
        scanner_subject_value=(
            "TEST-TENANT__GOLD__Daily_External"
        ),
        scanner_parameters={},
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert command[0] == sys.executable
    assert (
        command[1]
        == str(
            ROOT
            / "scanner_orchestrators"
            / "openvas_orchestrator.py"
        )
    )
    assert_option_value(
        command,
        "--mode",
        "scan",
    )
    assert_option_value(
        command,
        "--task-name",
        "TEST-TENANT__GOLD__Daily_External",
    )
    assert "--json" in command

    print(
        "PASS: OpenVAS adapter preserves task/report semantics"
    )

    expect_validation_error(
        description=(
            "OpenVAS rejects arbitrary scanner parameters"
        ),
        scanner_type="openvas",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="CONTROL_PLANE",
        scanner_subject_type="OPENVAS_TASK",
        scanner_subject_value="task-a",
        scanner_parameters={
            "target": "192.0.2.10",
        },
    )

    # --------------------------------------------------------------
    # Nuclei
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="nuclei",
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="URL",
        scanner_subject_value=(
            "https://example.invalid"
        ),
        scanner_parameters={
            "task_name": "nuclei-baseline",
            "scan_mode": "specific",
            "template_id": "http/test-template",
            "severities": "critical,high",
            "tags": "cve,tech",
        },
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--tenant-code",
        "TEST-TENANT",
    )
    assert_option_value(
        command,
        "--service-tier",
        "STANDARD",
    )
    assert_option_value(
        command,
        "--task-name",
        "nuclei-baseline",
    )
    assert_option_value(
        command,
        "--target-host",
        "https://example.invalid",
    )
    assert_option_value(
        command,
        "--scan-mode",
        "specific",
    )
    assert_option_value(
        command,
        "--template-id",
        "http/test-template",
    )
    assert_option_value(
        command,
        "--severities",
        "critical,high",
    )
    assert_option_value(
        command,
        "--tags",
        "cve,tech",
    )

    print(
        "PASS: Nuclei adapter builds explicit safe argv"
    )

    expect_validation_error(
        description=(
            "Nuclei requires task_name"
        ),
        scanner_type="nuclei",
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="URL",
        scanner_subject_value=(
            "https://example.invalid"
        ),
        scanner_parameters={},
    )

    expect_validation_error(
        description=(
            "Nuclei specific mode requires template_id"
        ),
        scanner_type="nuclei",
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="URL",
        scanner_subject_value=(
            "https://example.invalid"
        ),
        scanner_parameters={
            "task_name": "specific-test",
            "scan_mode": "specific",
        },
    )

    # --------------------------------------------------------------
    # Nmap NSE
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "nmap-baseline",
            "scan_mode": "specific",
            "nse_script": "ssl-enum-ciphers",
            "ports": "443",
        },
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--task-name",
        "nmap-baseline",
    )
    assert_option_value(
        command,
        "--target-host",
        "192.0.2.55",
    )
    assert_option_value(
        command,
        "--scan-mode",
        "specific",
    )
    assert_option_value(
        command,
        "--nse-script",
        "ssl-enum-ciphers",
    )
    assert_option_value(
        command,
        "--ports",
        "443",
    )

    print(
        "PASS: Nmap NSE adapter builds scanner-specific argv"
    )

    expect_validation_error(
        description=(
            "Nmap rejects non-existent safe scan mode"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "bad-mode",
            "scan_mode": "safe",
        },
    )

    expect_validation_error(
        description=(
            "Nmap specific mode requires nse_script"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "specific-test",
            "scan_mode": "specific",
        },
    )

    # --------------------------------------------------------------
    # Lynis
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="lynis",
        tenant_code="TEST-TENANT",
        service_tier="BRONZE",
        execution_model="LOCAL_ASSET",
        scanner_subject_type="LOCAL_ASSET",
        scanner_subject_value="asset-123",
        scanner_parameters={
            "target_host": "host-a.example.invalid",
            "filter_mode": "warnings_only",
            "task_name": "host-compliance",
        },
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--target-host",
        "host-a.example.invalid",
    )
    assert_option_value(
        command,
        "--filter-mode",
        "warnings_only",
    )
    assert_option_value(
        command,
        "--task-name",
        "host-compliance",
    )

    assert "asset-123" not in command

    print(
        "PASS: Lynis adapter preserves LOCAL_ASSET locality semantics"
    )

    expect_validation_error(
        description=(
            "Lynis requires target_host metadata"
        ),
        scanner_type="lynis",
        tenant_code="TEST-TENANT",
        service_tier="BRONZE",
        execution_model="LOCAL_ASSET",
        scanner_subject_type="LOCAL_ASSET",
        scanner_subject_value="asset-123",
        scanner_parameters={},
    )

    # --------------------------------------------------------------
    # Trivy
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="trivy",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="RESOURCE_TARGET",
        scanner_subject_type="CONTAINER_IMAGE",
        scanner_subject_value=(
            "example/app:latest"
        ),
        scanner_parameters={
            "scan_type": "image",
            "scanners": [
                "vuln",
                "misconfig",
            ],
            "severity": "HIGH,CRITICAL",
            "ignore_unfixed": True,
            "license_full": False,
        },
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--scan-type",
        "image",
    )
    assert_option_value(
        command,
        "--target",
        "example/app:latest",
    )
    assert_option_value(
        command,
        "--scanners",
        "vuln,misconfig",
    )
    assert_option_value(
        command,
        "--severity",
        "HIGH,CRITICAL",
    )
    assert "--ignore-unfixed" in command
    assert "--license-full" not in command

    print(
        "PASS: Trivy adapter maps resource scan parameters safely"
    )

    expect_validation_error(
        description=(
            "Trivy image scans require CONTAINER_IMAGE subject"
        ),
        scanner_type="trivy",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="RESOURCE_TARGET",
        scanner_subject_type="FILESYSTEM",
        scanner_subject_value="/srv/example",
        scanner_parameters={
            "scan_type": "image",
        },
    )

    expect_validation_error(
        description=(
            "Trivy boolean parameters reject strings"
        ),
        scanner_type="trivy",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="RESOURCE_TARGET",
        scanner_subject_type="FILESYSTEM",
        scanner_subject_value="/srv/example",
        scanner_parameters={
            "scan_type": "folder",
            "ignore_unfixed": "false",
        },
    )

    expect_validation_error(
        description=(
            "Trivy rejects scanner and scanners together"
        ),
        scanner_type="trivy",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="RESOURCE_TARGET",
        scanner_subject_type="CONTAINER_IMAGE",
        scanner_subject_value="example/app:latest",
        scanner_parameters={
            "scan_type": "image",
            "scanner": "vuln",
            "scanners": ["misconfig"],
        },
    )

    # --------------------------------------------------------------
    # Wazuh Vulnerability
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type=(
            "wazuh_vulnerability"
        ),
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        execution_model="CONTROL_PLANE",
        scanner_subject_type=(
            "WAZUH_AGENT_ID"
        ),
        scanner_subject_value="001",
        scanner_parameters={
            "severities": (
                "critical,high"
            ),
        },
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--agent-id",
        "001",
    )
    assert_option_value(
        command,
        "--severities",
        "critical,high",
    )

    print(
        "PASS: Wazuh vulnerability adapter preserves agent inventory semantics"
    )

    # --------------------------------------------------------------
    # Wazuh SCA
    # --------------------------------------------------------------
    command = build_scanner_command(
        scanner_type="wazuh_sca",
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        execution_model="CONTROL_PLANE",
        scanner_subject_type=(
            "WAZUH_AGENT_ID"
        ),
        scanner_subject_value="002",
        scanner_parameters={},
        repository_root=ROOT,
        python_executable=sys.executable,
    )

    assert_option_value(
        command,
        "--agent-id",
        "002",
    )

    print(
        "PASS: Wazuh SCA adapter preserves agent collection semantics"
    )

    # --------------------------------------------------------------
    # Shared security validation
    # --------------------------------------------------------------
    expect_validation_error(
        description=(
            "unknown scanner parameters are rejected"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "test",
            "arbitrary_flag": (
                "--script=unsafe"
            ),
        },
    )

    expect_validation_error(
        description=(
            "execution model mismatch is rejected"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="CONTROL_PLANE",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "test",
        },
    )

    expect_validation_error(
        description=(
            "subject mismatch is rejected"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="GOLD",
        execution_model="REMOTE_TARGET",
        scanner_subject_type=(
            "CONTAINER_IMAGE"
        ),
        scanner_subject_value="example/app",
        scanner_parameters={
            "task_name": "test",
        },
    )

    expect_validation_error(
        description=(
            "unsupported service tier is rejected"
        ),
        scanner_type="nmap_nse",
        tenant_code="TEST-TENANT",
        service_tier="PLATINUM",
        execution_model="REMOTE_TARGET",
        scanner_subject_type="IP_ADDRESS",
        scanner_subject_value="192.0.2.55",
        scanner_parameters={
            "task_name": "test",
        },
    )

    print(
        "PASS: scanner adapters use closed scanner-specific command contracts"
    )

    print(
        "OK: scan execution scanner adapter regression tests passed."
    )


if __name__ == "__main__":
    main()
