#!/usr/bin/env python3

import copy
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(
    0,
    str(ROOT / "scanner_orchestrators"),
)

from common.finding import build_unified_finding


def load_worker():
    path = ROOT / "worker" / "enricher_worker.py"

    spec = importlib.util.spec_from_file_location(
        "enricher_worker_schema_test",
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "Unable to load enrichment worker"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


worker = load_worker()


def expect_schema_failure(payload):
    try:
        worker.validate_unified_finding_schema(
            payload
        )
    except ValueError:
        return

    raise AssertionError(
        "Expected Unified Finding schema validation to fail"
    )


finding = build_unified_finding(
    tenant_code="TEST",
    tenant_service_tier="GOLD",
    target_host="server.example.test",
    engine_source="nuclei",
    finding_category="vulnerability",
    finding_class="xss_vulnerability",
    finding_key="test-xss-finding",
    finding_title="Test XSS finding",
    detected_at="2026-09-04T12:00:00+00:00",
    compliance_result=None,
    severity_level="HIGH",
    severity_score=8.0,
    engine_metadata={
        "template_id": "test-template",
    },
)

expected_fields = {
    "tenant_code",
    "tenant_service_tier",
    "target_host",
    "engine_source",
    "finding_category",
    "finding_class",
    "finding_key",
    "finding_title",
    "lifecycle_status",
    "detected_at",
    "remediated_at",
    "last_verified_at",
    "compliance_result",
    "severity_level",
    "severity_score",
    "engine_metadata",
    "ai_analysis",
}

assert set(finding) == expected_fields

worker.validate_unified_finding_schema(
    finding
)

missing_detected = copy.deepcopy(
    finding
)
missing_detected.pop(
    "detected_at"
)
expect_schema_failure(
    missing_detected
)

null_detected = copy.deepcopy(
    finding
)
null_detected["detected_at"] = None
expect_schema_failure(
    null_detected
)

missing_nullable_key = copy.deepcopy(
    finding
)
missing_nullable_key.pop(
    "ai_analysis"
)
expect_schema_failure(
    missing_nullable_key
)

nullable_fields = copy.deepcopy(
    finding
)
nullable_fields["remediated_at"] = None
nullable_fields["last_verified_at"] = None
nullable_fields["compliance_result"] = None
nullable_fields["severity_level"] = None
nullable_fields["severity_score"] = None
nullable_fields["ai_analysis"] = None

worker.validate_unified_finding_schema(
    nullable_fields
)

bad_score = copy.deepcopy(
    finding
)
bad_score["severity_score"] = 10.1
expect_schema_failure(
    bad_score
)

bad_metadata = copy.deepcopy(
    finding
)
bad_metadata["engine_metadata"] = [
    "not",
    "an",
    "object",
]
expect_schema_failure(
    bad_metadata
)

bad_timestamp = copy.deepcopy(
    finding
)
bad_timestamp["detected_at"] = "not-a-timestamp"

# JSON Schema draft-07 treats format validation as implementation-dependent.
# The worker therefore performs authoritative timestamp parsing before any
# persistence or recurrence decision.
try:
    worker.parse_detected_timestamp(
        bad_timestamp["detected_at"]
    )
except ValueError:
    pass
else:
    raise AssertionError(
        "Worker accepted an invalid detected_at timestamp"
    )

try:
    worker.parse_detected_timestamp(
        None
    )
except ValueError:
    pass
else:
    raise AssertionError(
        "Worker manufactured missing detected_at"
    )

# Prove the actual ingestion entry point rejects a finding without
# detected_at before PostgreSQL or Ollama can be reached.
worker.config = lambda: {
    "recurrence_grace_seconds": 300,
}

worker.setup = lambda _config: None

try:
    worker.process_ai_enrichment(
        missing_detected
    )
except ValueError as exc:
    assert (
        "schema validation failed"
        in str(exc).lower()
    )
else:
    raise AssertionError(
        "Ingestion accepted a finding without detected_at"
    )

try:
    worker.process_ai_enrichment(
        bad_timestamp
    )
except ValueError as exc:
    assert (
        "invalid timestamp value"
        in str(exc).lower()
    )
else:
    raise AssertionError(
        "Ingestion accepted an invalid detected_at timestamp"
    )

print(
    "PASS: Unified Finding schema matches the canonical envelope "
    "and ingestion rejects missing scanner timestamps"
)
