#!/usr/bin/env python3

import importlib.util
import logging
import logging.handlers
import os
import sys
import tempfile
import types
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR_DIR = REPO_ROOT / "scanner_orchestrators"
ORCHESTRATOR_PATH = (
    ORCHESTRATOR_DIR
    / "openvas_orchestrator.py"
)
FIXTURE_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "openvas"
    / "network_service_vulnerability.xml"
)


def install_gvm_stubs():
    """
    python-gvm is not required to test OpenVAS result normalisation.

    The production orchestrator imports its GMP classes at module import
    time, so provide minimal test-only modules without changing production
    behaviour.
    """

    gvm_module = types.ModuleType("gvm")
    connections_module = types.ModuleType("gvm.connections")
    protocols_module = types.ModuleType("gvm.protocols")
    gmp_module = types.ModuleType("gvm.protocols.gmp")

    class DummyUnixSocketConnection:
        def __init__(self, *args, **kwargs):
            pass

    class DummyGmp:
        def __init__(self, *args, **kwargs):
            pass

    connections_module.UnixSocketConnection = (
        DummyUnixSocketConnection
    )
    gmp_module.Gmp = DummyGmp

    gvm_module.connections = connections_module
    gvm_module.protocols = protocols_module
    protocols_module.gmp = gmp_module

    return {
        "gvm": gvm_module,
        "gvm.connections": connections_module,
        "gvm.protocols": protocols_module,
        "gvm.protocols.gmp": gmp_module,
    }


def load_orchestrator():
    sys.path.insert(
        0,
        str(ORCHESTRATOR_DIR),
    )

    spec = importlib.util.spec_from_file_location(
        "openvas_orchestrator",
        ORCHESTRATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load orchestrator: {ORCHESTRATOR_PATH}"
        )

    module = importlib.util.module_from_spec(spec)

    gvm_stubs = install_gvm_stubs()

    with tempfile.TemporaryDirectory() as log_dir:
        with patch.dict(
            os.environ,
            {
                "OPENVAS_USER":
                    "test-user",
                "OPENVAS_PASSWORD":
                    "test-password",
                "LOG_DIR":
                    log_dir,
            },
        ):
            with patch.dict(
                sys.modules,
                gvm_stubs,
            ):
                with patch.object(
                    logging.handlers,
                    "RotatingFileHandler",
                    return_value=logging.NullHandler(),
                ):
                    spec.loader.exec_module(module)

    return module


def main():
    orchestrator = load_orchestrator()

    result = ET.parse(
        FIXTURE_PATH
    ).getroot()

    finding = orchestrator.normalise_result(
        result=result,
        tenant_code="TEST-TENANT",
        service_tier="STANDARD",
        scan_name="Daily_External_Scan",
        task_name=(
            "TEST-TENANT__STANDARD__"
            "Daily_External_Scan"
        ),
        task_id="test-task-001",
        report_id="test-report-001",
    )

    # ------------------------------------------------------------------
    # Canonical Unified Security Finding identity
    # ------------------------------------------------------------------

    assert finding["tenant_code"] == "TEST-TENANT"

    assert (
        finding["tenant_service_tier"]
        == "STANDARD"
    )

    assert finding["target_host"] == "192.0.2.50"

    assert finding["engine_source"] == "openvas"

    assert finding["finding_category"] == "vulnerability"

    assert (
        finding["finding_class"]
        == "network_service_vulnerability"
    )

    assert finding["finding_key"] == "CVE-2024-5678"

    assert (
        finding["finding_title"]
        == "OpenSSL Vulnerability Test"
    )

    assert finding["lifecycle_status"] == "OPEN"
    assert finding["compliance_result"] is None
    assert finding["ai_analysis"] is None

    # ------------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------------

    assert finding["severity_level"] == "HIGH"
    assert finding["severity_score"] == 8.1

    # ------------------------------------------------------------------
    # OpenVAS scanner-native identity
    # ------------------------------------------------------------------

    metadata = finding["engine_metadata"]

    assert (
        metadata["task_name"]
        == "TEST-TENANT__STANDARD__Daily_External_Scan"
    )

    assert (
        metadata["scan_name"]
        == "Daily_External_Scan"
    )

    assert metadata["openvas_task_id"] == "test-task-001"

    assert (
        metadata["openvas_report_id"]
        == "test-report-001"
    )

    assert (
        metadata["openvas_result_id"]
        == "test-openvas-result-001"
    )

    assert (
        metadata["nvt_oid"]
        == "1.3.6.1.4.1.25623.1.0.999999"
    )

    assert metadata["scanned_port"] == "443/tcp"

    assert metadata["cves"] == [
        "CVE-2024-5678"
    ]

    assert metadata["primary_cve"] == "CVE-2024-5678"

    assert metadata["requires_gmp_fetch"] is False

    assert (
        metadata["description"]
        == (
            "A synthetic remotely reachable OpenSSL "
            "vulnerability for regression testing."
        )
    )

    # ------------------------------------------------------------------
    # Stage-2 identity matching
    #
    # The same native result must match the finding identity retained
    # by normalise_result().
    # ------------------------------------------------------------------

    assert orchestrator.result_matches_original_finding(
        result=result,
        target_host=finding["target_host"],
        finding_key=finding["finding_key"],
        original_nvt_oid=metadata["nvt_oid"],
        original_port=metadata["scanned_port"],
    ) is True

    print(
        "PASS: OpenVAS network-service vulnerability "
        "normalises to the expected Unified Security Finding"
    )


if __name__ == "__main__":
    main()
