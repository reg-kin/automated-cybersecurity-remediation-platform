#!/usr/bin/env python3

import importlib.util
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR_DIR = REPO_ROOT / "scanner_orchestrators"
ORCHESTRATOR_PATH = ORCHESTRATOR_DIR / "wazuh_sca_orchestrator.py"
FIXTURE_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "wazuh_sca"
    / "cis_crontab_permissions.json"
)


def load_orchestrator():
    sys.path.insert(0, str(ORCHESTRATOR_DIR))

    spec = importlib.util.spec_from_file_location(
        "wazuh_sca_orchestrator",
        ORCHESTRATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load orchestrator: {ORCHESTRATOR_PATH}"
        )

    module = importlib.util.module_from_spec(spec)

    with patch.object(
        logging.handlers,
        "RotatingFileHandler",
        return_value=logging.NullHandler(),
    ):
        spec.loader.exec_module(module)

    return module


def main():
    orchestrator = load_orchestrator()

    with FIXTURE_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        fixture = json.load(handle)

    agent_identity = fixture["agent_identity"]
    policy = fixture["policy"]
    check = fixture["check"]

    # Protect the scanner-native identity used by both normalisation and
    # Stage-2 verification.
    assert policy["policy_id"] == "cis_ubuntu24-04"
    assert str(check["id"]) == "35594"

    finding = orchestrator.build_finding(
        tenant="TEST-TENANT",
        tier="STANDARD",
        agent_id="007",
        agent_identity=agent_identity,
        policy=policy,
        item=check,
        refresh_id="test-refresh-001",
        refresh_started_at="2026-09-03T12:00:00+00:00",
    )

    # ------------------------------------------------------------------
    # Canonical Unified Security Finding identity
    # ------------------------------------------------------------------

    assert finding["tenant_code"] == "TEST-TENANT"
    assert finding["tenant_service_tier"] == "STANDARD"
    assert finding["target_host"] == "192.0.2.40"

    assert finding["engine_source"] == "wazuh_sca"
    assert finding["finding_category"] == "compliance_drift"

    assert (
        finding["finding_class"]
        == "access_control_configuration"
    )

    assert (
        finding["finding_key"]
        == "cis_ubuntu24-04:35594"
    )

    assert (
        finding["finding_title"]
        == "Ensure permissions on /etc/crontab are configured"
    )

    assert finding["lifecycle_status"] == "OPEN"
    assert finding["compliance_result"] == "FAIL"

    # Wazuh SCA currently does not assign canonical severity.
    assert finding["severity_level"] is None
    assert finding["severity_score"] is None

    assert finding["ai_analysis"] is None

    # ------------------------------------------------------------------
    # Scanner-native metadata
    # ------------------------------------------------------------------

    metadata = finding["engine_metadata"]

    assert metadata["task_name"] == "Wazuh SCA Assessment"

    assert metadata["agent_id"] == "007"
    assert metadata["agent_name"] == "ubuntu24-test"
    assert metadata["agent_ip"] == "192.0.2.40"

    assert metadata["policy_id"] == "cis_ubuntu24-04"
    assert (
        metadata["policy_name"]
        == "CIS Ubuntu Linux 24.04 LTS Benchmark"
    )

    assert metadata["check_id"] == 35594
    assert metadata["raw_result"] == "failed"

    assert metadata["file"] == "/etc/crontab"

    assert metadata["compliance"]["cis"] == "4.1.2.1"

    # ------------------------------------------------------------------
    # Deferred Stage-2 verification contract
    # ------------------------------------------------------------------

    assert (
        metadata["verification_capability"]
        == "asynchronous_state_refresh"
    )

    assert (
        metadata["targeted_verification_supported"]
        is False
    )

    assert metadata["refresh_id"] == "test-refresh-001"

    assert (
        metadata["refresh_started_at"]
        == "2026-09-03T12:00:00+00:00"
    )

    # The finding key must preserve the same policy/check identity that
    # Stage-2 verification derives from scanner metadata.
    assert finding["finding_key"] == (
        f"{metadata['policy_id']}:{metadata['check_id']}"
    )

    resolved_identity = (
        orchestrator.resolve_verification_identity(
            finding["finding_key"],
            metadata,
        )
    )

    assert resolved_identity == (
        "007",
        "cis_ubuntu24-04",
        "35594",
    )

    print(
        "PASS: Wazuh SCA CIS crontab permissions check "
        "normalises to the expected Unified Security Finding"
    )


if __name__ == "__main__":
    main()
