#!/usr/bin/env python3

"""
Regression tests for Trivy -> Unified Security Finding normalisation.

These tests exercise the existing production normalize_report() function.
They do not execute the Trivy scanner and do not modify production
orchestrator behaviour.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCANNER_DIR = ROOT / "scanner_orchestrators"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "trivy"

sys.path.insert(0, str(SCANNER_DIR))


def import_trivy_orchestrator():
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
        import trivy_orchestrator

    return trivy_orchestrator


def load_fixture(name: str) -> dict:
    path = FIXTURE_DIR / name

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def test_os_package_vulnerability_normalization() -> None:
    trivy = import_trivy_orchestrator()

    report = load_fixture(
        "os_package_vulnerability.json"
    )

    findings = trivy.normalize_report(
        report=report,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        scan_type="image",
        original_target="nginx:1.25",
        enabled_scanners={"vuln"},
    )

    assert len(findings) == 1

    payload = findings[0]

    assert payload["tenant_code"] == "TEST-TENANT"
    assert payload["tenant_service_tier"] == "STANDARD"
    assert payload["target_host"] == "nginx:1.25"

    assert payload["engine_source"] == "trivy"
    assert payload["finding_category"] == "vulnerability"
    assert (
        payload["finding_class"]
        == "container_image_vulnerability"
    )
    assert payload["lifecycle_status"] == "OPEN"

    assert (
        payload["finding_key"]
        == "CVE-2024-1234:libssl3"
    )

    assert (
        payload["finding_title"]
        == (
            "CVE-2024-1234 - libssl3: "
            "Test OpenSSL vulnerability"
        )
    )

    assert payload["severity_level"] == "HIGH"
    assert payload["severity_score"] == 8.1

    metadata = payload["engine_metadata"]

    assert metadata["scanner"] == "vuln"
    assert metadata["scan_type"] == "image"
    assert metadata["scan_target"] == "nginx:1.25"

    assert (
        metadata["result_target"]
        == "nginx:1.25 (debian 12)"
    )
    assert metadata["result_class"] == "os-pkgs"
    assert metadata["result_type"] == "debian"

    assert metadata["cve_id"] == "CVE-2024-1234"
    assert metadata["package_name"] == "libssl3"

    assert (
        metadata["installed_version"]
        == "3.0.11-1"
    )
    assert metadata["fixed_version"] == "3.0.12-1"

    assert metadata["raw_severity"] == "HIGH"

    assert payload["ai_analysis"] is None


def main() -> int:
    test_os_package_vulnerability_normalization()

    print(
        "PASS: Trivy OS package vulnerability normalises "
        "to the expected Unified Security Finding"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
