#!/usr/bin/env python3

"""
Regression test for Lynis -> Unified Security Finding normalisation.

The test exercises the existing production report loader, report-line
parser, classifier, Unified Finding builder and Lynis validation logic.
It does not execute Lynis and does not modify production behaviour.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "scanner_orchestrators"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "lynis"

sys.path.insert(0, str(SCANNER_DIR))


def import_lynis_orchestrator():
    """
    Import the production orchestrator without allowing its import-time
    RotatingFileHandler setup to write to /var/log.
    """

    with patch(
        "logging.handlers.RotatingFileHandler",
        return_value=logging.NullHandler(),
    ):
        import lynis_orchestrator

    return lynis_orchestrator


def test_authentication_warning_normalization() -> None:
    lynis = import_lynis_orchestrator()

    fixture_path = (
        FIXTURE_DIR
        / "authentication_warning.dat"
    )

    original_report_path = lynis.LYNIS_REPORT_PATH

    try:
        lynis.LYNIS_REPORT_PATH = str(
            fixture_path
        )

        parsed_findings = (
            lynis.load_report_findings()
        )

    finally:
        lynis.LYNIS_REPORT_PATH = (
            original_report_path
        )

    assert len(parsed_findings) == 1

    parsed = parsed_findings[0]

    assert parsed["finding_id"] == "AUTH-9282"
    assert parsed["finding_type"] == "warning"

    assert (
        parsed["description"]
        == (
            "Configure password aging and "
            "authentication policy"
        )
    )

    assert parsed["additional_fields"] == [
        "hardening"
    ]

    assert (
        parsed["raw_record"]
        == (
            "AUTH-9282|Configure password aging "
            "and authentication policy|hardening"
        )
    )

    payload = lynis.build_unified_finding(
        parsed=parsed,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        target_host="192.0.2.30",
        task_name="Lynis Authentication Regression Test",
    )

    assert payload["tenant_code"] == "TEST-TENANT"

    assert (
        payload["tenant_service_tier"]
        == "STANDARD"
    )

    assert payload["target_host"] == "192.0.2.30"

    assert payload["engine_source"] == "lynis"

    assert (
        payload["finding_category"]
        == "compliance_drift"
    )

    assert (
        payload["finding_class"]
        == "authentication_configuration"
    )

    assert payload["finding_key"] == "AUTH-9282"

    assert (
        payload["finding_title"]
        == "Lynis Warning (AUTH-9282)"
    )

    assert payload["lifecycle_status"] == "OPEN"

    assert payload["compliance_result"] == "FAIL"

    assert payload["severity_level"] is None
    assert payload["severity_score"] is None

    metadata = payload["engine_metadata"]

    assert (
        metadata["task_name"]
        == "Lynis Authentication Regression Test"
    )

    assert (
        metadata["lynis_test_id"]
        == "AUTH-9282"
    )

    assert metadata["finding_type"] == "warning"

    assert (
        metadata["description"]
        == (
            "Configure password aging and "
            "authentication policy"
        )
    )

    assert metadata["additional_fields"] == [
        "hardening"
    ]

    assert (
        metadata["raw_record"]
        == (
            "AUTH-9282|Configure password aging "
            "and authentication policy|hardening"
        )
    )

    assert payload["ai_analysis"] is None


def main() -> int:
    test_authentication_warning_normalization()

    print(
        "PASS: Lynis authentication warning "
        "normalises to the expected "
        "Unified Security Finding"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
