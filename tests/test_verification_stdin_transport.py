#!/usr/bin/env python3

import io
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(REPO_ROOT),
    )


from scanner_orchestrators.common.verification import (
    read_verification_request,
)


def expect_value_error(payload):
    original_stdin = sys.stdin

    try:
        sys.stdin = io.StringIO(payload)

        try:
            read_verification_request()

        except ValueError:
            return

        raise AssertionError(
            "Expected ValueError"
        )

    finally:
        sys.stdin = original_stdin


def test_valid_request():
    payload = {
        "target_host": "https://example.test/path",
        "finding_key": "CVE-2026-1234",
        "finding_class": "web_application_vulnerability",
        "engine_metadata": {
            "template_id": "example-template",
        },
    }

    original_stdin = sys.stdin

    try:
        sys.stdin = io.StringIO(
            json.dumps(payload)
        )

        result = read_verification_request()

    finally:
        sys.stdin = original_stdin

    assert (
        result["target_host"]
        == payload["target_host"]
    )

    assert (
        result["finding_key"]
        == payload["finding_key"]
    )

    assert (
        result["finding_class"]
        == payload["finding_class"]
    )

    assert (
        result["engine_metadata"]
        == payload["engine_metadata"]
    )

    assert (
        json.loads(
            result["engine_metadata_json"]
        )
        == payload["engine_metadata"]
    )


def test_invalid_json():
    expect_value_error(
        "{not-json"
    )


def test_non_object():
    expect_value_error(
        '["not", "an", "object"]'
    )


def test_missing_required_field():
    expect_value_error(
        json.dumps(
            {
                "target_host": "example.test",
                "finding_key": "CVE-2026-1234",
                "engine_metadata": {},
            }
        )
    )


def test_control_character():
    expect_value_error(
        json.dumps(
            {
                "target_host": "example.test\n--help",
                "finding_key": "CVE-2026-1234",
                "finding_class": "cve",
                "engine_metadata": {},
            }
        )
    )


def test_metadata_must_be_object():
    expect_value_error(
        json.dumps(
            {
                "target_host": "example.test",
                "finding_key": "CVE-2026-1234",
                "finding_class": "cve",
                "engine_metadata": [],
            }
        )
    )


if __name__ == "__main__":
    tests = [
        test_valid_request,
        test_invalid_json,
        test_non_object,
        test_missing_required_field,
        test_control_character,
        test_metadata_must_be_object,
    ]

    for test in tests:
        test()

        print(
            f"PASS: {test.__name__}"
        )

    print(
        "PASS: verification stdin transport regression tests"
    )
