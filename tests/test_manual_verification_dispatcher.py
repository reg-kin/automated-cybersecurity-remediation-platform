#!/usr/bin/env python3
"""Regression tests for Stage 2 verification result classification."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "manual_verification_test_dispatcher",
    ROOT / "verification/verification_dispatcher.py",
)
dispatcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatcher)

ORCHESTRATOR = str(
    ROOT / "scanner_orchestrators/nmap_orchestrator.py"
)

PAYLOAD = {
    "finding_id": 101,
    "execution_id": 202,
    "target_host": "example.test",
    "engine_source": "nmap_nse",
    "finding_class": "network_service_vulnerability",
    "finding_key": "TEST-FINDING",
    "engine_metadata": {},
}


def run_dispatch(scanner_result, returncode=0):
    completed = SimpleNamespace(
        returncode=returncode,
        stdout=json.dumps(scanner_result),
        stderr="scanner execution failed" if returncode else "",
    )

    with patch.dict(
        dispatcher.ORCHESTRATORS,
        {"nmap_nse": ORCHESTRATOR},
    ):
        with patch.object(
            dispatcher.subprocess,
            "run",
            return_value=completed,
        ):
            return dispatcher.dispatch(PAYLOAD)


def expect_runtime_error(scanner_result):
    try:
        run_dispatch(scanner_result)
    except RuntimeError:
        return
    raise AssertionError("Expected RuntimeError")


def test_passed():
    result = run_dispatch({"present": False})
    assert result["verification_status"] == "PASSED"
    assert result["present"] is False


def test_failed():
    result = run_dispatch({"present": True})
    assert result["verification_status"] == "FAILED"
    assert result["present"] is True


def test_inconclusive():
    result = run_dispatch({
        "verification_status": "INCONCLUSIVE",
        "present": None,
        "verification_reason": "Insufficient independent evidence",
        "evidence": {"host": "example.test"},
    })
    assert result["verification_status"] == "INCONCLUSIVE"
    assert result["present"] is None
    assert result["verification_reason"] == (
        "Insufficient independent evidence"
    )


def test_inconclusive_requires_explicit_null():
    expect_runtime_error({
        "verification_status": "INCONCLUSIVE",
        "verification_reason": "Insufficient evidence",
    })
    expect_runtime_error({
        "verification_status": "INCONCLUSIVE",
        "present": False,
        "verification_reason": "Insufficient evidence",
    })


def test_inconclusive_requires_reason():
    expect_runtime_error({
        "verification_status": "INCONCLUSIVE",
        "present": None,
    })
    expect_runtime_error({
        "verification_status": "INCONCLUSIVE",
        "present": None,
        "verification_reason": "   ",
    })


def test_malformed_results():
    expect_runtime_error([])
    expect_runtime_error({"verification_status": "PASSED"})
    expect_runtime_error({"present": None})


def test_nonzero_exit_fails_closed():
    result = run_dispatch({
        "verification_status": "INCONCLUSIVE",
        "present": None,
        "verification_reason": "Insufficient evidence",
    }, returncode=1)
    assert result["verification_status"] == "FAILED"
    assert result["present"] is True


if __name__ == "__main__":
    tests = [
        test_passed,
        test_failed,
        test_inconclusive,
        test_inconclusive_requires_explicit_null,
        test_inconclusive_requires_reason,
        test_malformed_results,
        test_nonzero_exit_fails_closed,
    ]
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print("PASS: manual verification dispatcher regression tests")
