#!/usr/bin/env python3

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from remediation import deferred_reconciler as reconciler


class DummyConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


NOW = datetime(
    2026,
    9,
    4,
    12,
    0,
    tzinfo=timezone.utc,
)


def context(**overrides):
    value = {
        "deferred_job_id": 901,
        "execution_id": 902,
        "finding_id": 903,
        "verification_id": 904,
        "engine_source": "wazuh_vulnerability",
        "scanner_subject_type": "wazuh_agent",
        "scanner_subject_id": "007",
        "evidence_after": NOW - timedelta(minutes=10),
        "last_watermark_id": None,
        "execution_status": "VERIFYING",
        "execution_result": {},
        "finding_lifecycle_status": "IN_REMEDIATION",
        "tenant_code": "TEST-TENANT",
        "finding_engine_source":
            "wazuh_vulnerability",
        "finding_class":
            "os_package_vulnerability",
        "finding_key": "finding-key-903",
        "target_host": "192.0.2.20",
        "last_seen_at": NOW - timedelta(minutes=20),
        "engine_metadata": {
            "agent_id": "007",
            "refresh_id": "old-refresh",
        },
        "verification_status": "PENDING",
        "verification_stage": 2,
    }
    value.update(overrides)
    return value


def watermark(**overrides):
    value = {
        "watermark_id": 1001,
        "engine_source": "wazuh_vulnerability",
        "scanner_subject_type": "wazuh_agent",
        "scanner_subject_id": "007",
        "refresh_id": "fresh-refresh",
        "refresh_started_at":
            NOW - timedelta(minutes=5),
        "refresh_completed_at":
            NOW - timedelta(minutes=1),
        "refresh_status": "SUCCESS",
        "metadata": {
            "tenant_code": "TEST-TENANT",
        },
    }
    value.update(overrides)
    return value


# ---------------------------------------------------------------------------
# Context validity
# ---------------------------------------------------------------------------

invalid = reconciler.validate_context(
    context(engine_source="nuclei")
)

assert invalid is not None
assert "Unsupported deferred verification engine" in invalid

invalid = reconciler.validate_context(
    context(verification_status="PASSED")
)

assert invalid is not None
assert "is not PENDING" in invalid

invalid = reconciler.validate_context(
    context(execution_status="SUCCESS")
)

assert invalid is not None
assert "is not VERIFYING" in invalid


# ---------------------------------------------------------------------------
# Exact fresh-refresh presence must fail
# ---------------------------------------------------------------------------

ctx = context(
    engine_metadata={
        "agent_id": "007",
        "refresh_id": "fresh-refresh",
    },
)

wm = watermark()

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        ctx,
        wm,
    )
)

assert present is True
assert evidence["exact_refresh_present"] is True
assert evidence["present"] is True


# ---------------------------------------------------------------------------
# A later observation after the watermark also proves presence
# ---------------------------------------------------------------------------

ctx = context(
    last_seen_at=NOW,
    engine_metadata={
        "agent_id": "007",
        "refresh_id": "different-refresh",
    },
)

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        ctx,
        wm,
    )
)

assert present is True
assert evidence["seen_after_watermark"] is True


# ---------------------------------------------------------------------------
# Complete Wazuh vulnerability refresh can prove absence
# ---------------------------------------------------------------------------

ctx = context(
    last_seen_at=NOW - timedelta(minutes=20),
    engine_metadata={
        "agent_id": "007",
        "refresh_id": "older-refresh",
    },
)

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        ctx,
        wm,
    )
)

assert present is False
assert authoritative is True
assert evidence["absence_authoritative"] is True


# ---------------------------------------------------------------------------
# Filtered vulnerability refresh cannot prove absence
# ---------------------------------------------------------------------------

filtered = watermark(
    metadata={
        "tenant_code": "TEST-TENANT",
        "severity_filter": [
            "high",
            "critical",
        ],
    }
)

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        ctx,
        filtered,
    )
)

assert present is False
assert authoritative is False
assert (
    "cannot prove absence"
    in reason
)


# ---------------------------------------------------------------------------
# Filtering does not weaken positive evidence
# ---------------------------------------------------------------------------

ctx_present = context(
    engine_metadata={
        "agent_id": "007",
        "refresh_id": "fresh-refresh",
    },
)

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        ctx_present,
        filtered,
    )
)

assert present is True


# ---------------------------------------------------------------------------
# Wazuh SCA complete refresh can prove absence
# ---------------------------------------------------------------------------

sca_ctx = context(
    engine_source="wazuh_sca",
    finding_engine_source="wazuh_sca",
    finding_class="compliance_control_failure",
    last_seen_at=NOW - timedelta(minutes=20),
    engine_metadata={
        "agent_id": "007",
        "refresh_id": "older-sca-refresh",
    },
)

sca_wm = watermark(
    engine_source="wazuh_sca",
    refresh_id="fresh-sca-refresh",
)

present, authoritative, reason, evidence = (
    reconciler.evaluate_presence(
        sca_ctx,
        sca_wm,
    )
)

assert present is False
assert authoritative is True


# ---------------------------------------------------------------------------
# No fresh watermark is not remediation failure: reschedule
# ---------------------------------------------------------------------------

reschedule = Mock(return_value=True)
finish = Mock()

with (
    patch.object(
        reconciler,
        "load_job_context",
        return_value=context(),
    ),
    patch.object(
        reconciler,
        "latest_success_watermark",
        return_value=None,
    ),
    patch.object(
        reconciler,
        "reschedule_job",
        reschedule,
    ),
    patch.object(
        reconciler,
        "finish_job",
        finish,
    ),
):
    result = reconciler.process_job(
        DummyConnection(),
        {"deferred_job_id": 901},
        "worker-a",
        60,
    )

assert result == "rescheduled_no_evidence"
reschedule.assert_called_once()
finish.assert_not_called()


# ---------------------------------------------------------------------------
# Non-authoritative absence is rescheduled and watermark consumed
# ---------------------------------------------------------------------------

reschedule = Mock(return_value=True)
finish = Mock()

with (
    patch.object(
        reconciler,
        "load_job_context",
        return_value=context(),
    ),
    patch.object(
        reconciler,
        "latest_success_watermark",
        return_value=filtered,
    ),
    patch.object(
        reconciler,
        "reschedule_job",
        reschedule,
    ),
    patch.object(
        reconciler,
        "finish_job",
        finish,
    ),
):
    result = reconciler.process_job(
        DummyConnection(),
        {"deferred_job_id": 901},
        "worker-a",
        60,
    )

assert result == "rescheduled_scope"
finish.assert_not_called()

assert (
    reschedule.call_args.kwargs[
        "last_watermark_id"
    ]
    == filtered["watermark_id"]
)


# ---------------------------------------------------------------------------
# Authoritative absence completes Stage 2 successfully
# ---------------------------------------------------------------------------

finish = Mock(return_value=True)

with (
    patch.object(
        reconciler,
        "load_job_context",
        return_value=context(),
    ),
    patch.object(
        reconciler,
        "latest_success_watermark",
        return_value=wm,
    ),
    patch.object(
        reconciler,
        "finish_job",
        finish,
    ),
):
    result = reconciler.process_job(
        DummyConnection(),
        {"deferred_job_id": 901},
        "worker-a",
        60,
    )

assert result == "passed"

assert (
    finish.call_args.args[3]
    is True
)


# ---------------------------------------------------------------------------
# Authoritative presence completes Stage 2 as failure
# ---------------------------------------------------------------------------

finish = Mock(return_value=True)

with (
    patch.object(
        reconciler,
        "load_job_context",
        return_value=ctx_present,
    ),
    patch.object(
        reconciler,
        "latest_success_watermark",
        return_value=wm,
    ),
    patch.object(
        reconciler,
        "finish_job",
        finish,
    ),
):
    result = reconciler.process_job(
        DummyConnection(),
        {"deferred_job_id": 901},
        "worker-a",
        60,
    )

assert result == "failed_present"

assert (
    finish.call_args.args[3]
    is False
)


# ---------------------------------------------------------------------------
# Lost lease prevents terminal transition
# ---------------------------------------------------------------------------

with (
    patch.object(
        reconciler,
        "load_job_context",
        return_value=context(),
    ),
    patch.object(
        reconciler,
        "latest_success_watermark",
        return_value=wm,
    ),
    patch.object(
        reconciler,
        "finish_job",
        return_value=False,
    ),
):
    result = reconciler.process_job(
        DummyConnection(),
        {"deferred_job_id": 901},
        "worker-a",
        60,
    )

assert result == "lease_lost"


print(
    "PASS: deferred verification runtime requires fresh "
    "authoritative scanner evidence and preserves safe "
    "reschedule, presence, absence and lease semantics"
)
