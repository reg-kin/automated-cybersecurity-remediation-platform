#!/usr/bin/env python3

"""
Regression tests for verification command-boundary hardening.

These tests verify that request-derived scanner targets cannot become
command-line options or contain unsafe control characters, while preserving
legitimate scanner-specific target forms such as URLs and image references.
"""

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "scanner_orchestrators"


def load_module(name, relative_path):
    path = ROOT / relative_path

    scanner_path_added = False

    if str(SCANNER_DIR) not in sys.path:
        sys.path.insert(
            0,
            str(SCANNER_DIR),
        )
        scanner_path_added = True

    try:
        spec = importlib.util.spec_from_file_location(
            name,
            path,
        )

        module = importlib.util.module_from_spec(
            spec
        )

        assert spec.loader is not None

        with patch(
            "os.makedirs"
        ), patch(
            "logging.handlers.RotatingFileHandler"
        ):
            spec.loader.exec_module(
                module
            )

        return module

    finally:
        if scanner_path_added:
            sys.path.remove(
                str(SCANNER_DIR)
            )

def assert_raises_value_error(
    callable_,
    expected_text,
):
    try:
        callable_()
    except ValueError as exc:
        assert expected_text in str(exc), (
            f"Expected {expected_text!r} in {str(exc)!r}"
        )
        return

    raise AssertionError(
        "Expected ValueError"
    )


def test_nmap_rejects_option_like_target():
    nmap = load_module(
        "test_safety_nmap",
        "scanner_orchestrators/nmap_orchestrator.py",
    )

    with patch.object(
        nmap.subprocess,
        "run",
    ) as mocked_run:
        assert_raises_value_error(
            lambda: nmap.run_nmap(
                target_host="--script=unsafe",
                scan_mode="specific",
                nse_script="http-title",
            ),
            "must not begin with '-'",
        )

        mocked_run.assert_not_called()


def test_nmap_rejects_control_character_target():
    nmap = load_module(
        "test_safety_nmap_control",
        "scanner_orchestrators/nmap_orchestrator.py",
    )

    with patch.object(
        nmap.subprocess,
        "run",
    ) as mocked_run:
        assert_raises_value_error(
            lambda: nmap.run_nmap(
                target_host="example.test\n--script=unsafe",
                scan_mode="specific",
                nse_script="http-title",
            ),
            "prohibited control characters",
        )

        mocked_run.assert_not_called()


def test_nuclei_rejects_option_like_verification_target():
    nuclei = load_module(
        "test_safety_nuclei",
        "scanner_orchestrators/nuclei_orchestrator.py",
    )

    assert_raises_value_error(
        lambda: nuclei.build_verify_command(
            verification_target="--target-file",
            template_id="http-missing-security-headers",
        ),
        "must not begin with '-'",
    )


def test_nuclei_preserves_url_target():
    nuclei = load_module(
        "test_safety_nuclei_url",
        "scanner_orchestrators/nuclei_orchestrator.py",
    )

    command = nuclei.build_verify_command(
        verification_target="https://example.test/path?q=1",
        template_id="http-missing-security-headers",
    )

    target_index = command.index(
        "-target"
    )

    assert (
        command[target_index + 1]
        == "https://example.test/path?q=1"
    )


def test_trivy_rejects_option_like_target():
    trivy = load_module(
        "test_safety_trivy",
        "scanner_orchestrators/trivy_orchestrator.py",
    )

    with patch.object(
        trivy.subprocess,
        "run",
    ) as mocked_run:
        assert_raises_value_error(
            lambda: trivy.execute_trivy(
                scan_type="image",
                target="--help",
                scanners={"vuln"},
            ),
            "must not begin with '-'",
        )

        mocked_run.assert_not_called()


def test_trivy_preserves_image_reference():
    trivy = load_module(
        "test_safety_trivy_image",
        "scanner_orchestrators/trivy_orchestrator.py",
    )

    command = trivy.build_trivy_command(
        scan_type="image",
        target="nginx:1.25",
        scanners={"vuln"},
    )

    assert command[-1] == "nginx:1.25"


def test_dispatcher_rejects_control_characters_before_execution():
    dispatcher = load_module(
        "test_safety_dispatcher",
        "verification/verification_dispatcher.py",
    )

    payload = {
        "finding_id": 1,
        "execution_id": 2,
        "target_host": "example.test\n--help",
        "engine_source": "nmap_nse",
        "finding_class": "network_service_vulnerability",
        "finding_key": "TEST-KEY",
        "engine_metadata": {},
    }

    with patch.object(
        dispatcher.subprocess,
        "run",
    ) as mocked_run:
        assert_raises_value_error(
            lambda: dispatcher.dispatch(
                payload
            ),
            "prohibited control characters",
        )

        mocked_run.assert_not_called()


def test_dispatcher_rejects_oversized_metadata_before_execution():
    dispatcher = load_module(
        "test_safety_dispatcher_metadata",
        "verification/verification_dispatcher.py",
    )

    payload = {
        "finding_id": 1,
        "execution_id": 2,
        "target_host": "example.test",
        "engine_source": "nmap_nse",
        "finding_class": "network_service_vulnerability",
        "finding_key": "TEST-KEY",
        "engine_metadata": {
            "value": "x" * 70000,
        },
    }

    fake_orchestrator = ROOT / (
        "scanner_orchestrators/"
        "nmap_orchestrator.py"
    )

    with patch.dict(
        dispatcher.ORCHESTRATORS,
        {
            "nmap_nse":
                str(fake_orchestrator)
        },
    ):
        with patch.object(
            dispatcher.subprocess,
            "run",
        ) as mocked_run:
            assert_raises_value_error(
                lambda: dispatcher.dispatch(
                    payload
                ),
                "engine_metadata exceeds maximum",
            )

            mocked_run.assert_not_called()


def test_dispatcher_rejects_invalid_timeout():
    dispatcher = load_module(
        "test_safety_dispatcher_timeout",
        "verification/verification_dispatcher.py",
    )

    with patch.dict(
        os.environ,
        {
            "SCANNER_VERIFY_TIMEOUT":
                "999999"
        },
    ):
        try:
            dispatcher._scanner_timeout()
        except RuntimeError as exc:
            assert (
                "must be between"
                in str(exc)
            )
        else:
            raise AssertionError(
                "Expected RuntimeError"
            )


def main():
    tests = [
        test_nmap_rejects_option_like_target,
        test_nmap_rejects_control_character_target,
        test_nuclei_rejects_option_like_verification_target,
        test_nuclei_preserves_url_target,
        test_trivy_rejects_option_like_target,
        test_trivy_preserves_image_reference,
        test_dispatcher_rejects_control_characters_before_execution,
        test_dispatcher_rejects_oversized_metadata_before_execution,
        test_dispatcher_rejects_invalid_timeout,
    ]

    for test in tests:
        test()
        print(
            f"PASS: {test.__name__}"
        )

    print(
        "PASS: verification command-boundary "
        "security regression tests"
    )


if __name__ == "__main__":
    main()
