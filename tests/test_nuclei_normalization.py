#!/usr/bin/env python3

"""
Regression tests for Nuclei -> Unified Security Finding normalisation.

These tests exercise the existing production normalize_finding() function.
They do not execute the Nuclei scanner and do not modify production
orchestrator behaviour.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "scanner_orchestrators"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "nuclei"

sys.path.insert(0, str(SCANNER_DIR))


def import_nuclei_orchestrator():
    """
    Import the production orchestrator without allowing its import-time
    RotatingFileHandler setup to write to /var/log.
    """

    with (
        patch("os.makedirs"),
        patch(
            "logging.handlers.RotatingFileHandler",
            return_value=logging.NullHandler(),
        ),
    ):
        import nuclei_orchestrator

    return nuclei_orchestrator


def load_fixture(name: str) -> dict:
    path = FIXTURE_DIR / name

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def expected_fingerprint(matched_at: str) -> str:
    normalised = (
        matched_at
        .strip()
        .rstrip("/")
        .lower()
    )

    return hashlib.sha256(
        normalised.encode("utf-8")
    ).hexdigest()[:16]


def test_xss_normalization() -> None:
    nuclei = import_nuclei_orchestrator()

    native_finding = load_fixture(
        "xss_finding.json"
    )

    matched_at = (
        "https://example.test/search?q=test"
    )

    expected_key = (
        "NUCLEI:"
        "reflected-xss:"
        f"{expected_fingerprint(matched_at)}"
    )

    payload = nuclei.normalize_finding(
        finding=native_finding,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        task_name="Nuclei_Regression_Test",
        target_host="example.test",
        scan_mode="TEST",
    )

    assert payload["tenant_code"] == "TEST-TENANT"
    assert payload["tenant_service_tier"] == "STANDARD"
    assert payload["target_host"] == "example.test"

    assert payload["engine_source"] == "nuclei"
    assert payload["finding_category"] == "vulnerability"
    assert payload["finding_class"] == "xss_vulnerability"
    assert payload["lifecycle_status"] == "OPEN"

    assert (
        payload["finding_title"]
        == "Reflected Cross-Site Scripting"
    )

    assert payload["finding_key"] == expected_key

    assert payload["severity_level"] == "HIGH"

    metadata = payload["engine_metadata"]

    assert metadata["template_id"] == "reflected-xss"
    assert metadata["matched_at"] == matched_at
    assert (
        metadata["verification_target"]
        == "https://example.test"
    )
    assert metadata["matcher_name"] == "xss-reflection"
    assert metadata["type"] == "http"
    assert metadata["host"] == "https://example.test"

    assert payload["ai_analysis"] is None


def main() -> int:
    test_xss_normalization()

    print(
        "PASS: Nuclei XSS native finding normalises "
        "to the expected Unified Security Finding"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
