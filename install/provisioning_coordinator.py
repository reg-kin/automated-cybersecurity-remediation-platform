#!/usr/bin/env python3
"""Explicit provisioning coordinator with fail-closed interruption behavior.

The coordinator is not a production CLI. Each stage is supplied as an
independently verified callable; failures leave the journal INCOMPLETE.
"""
from pathlib import Path

from provisioning_journal import (
    STAGES, advance_provisioning, assert_not_deployable,
    begin_provisioning, inspect_provisioning,
)


def execute_provisioning_stages(journal, application, operations):
    """Execute every stage in order, recording completion after its verification.

    Each operation must return True only after it has performed and verified its
    stage. No stage is resumed or repeated automatically after interruption.
    An existing journal blocks new execution, including COMPLETE journals.
    """
    if set(operations) != set(STAGES) or any(not callable(operations[s]) for s in STAGES):
        raise RuntimeError("Exactly one callable per provisioning stage is required.")
    begin_provisioning(journal, application=application)
    for stage in STAGES:
        verified = operations[stage]()
        if verified is not True:
            raise RuntimeError(
                f"Provisioning stage {stage} not verified; deployment prohibited."
            )
        advance_provisioning(journal, stage, evidence_confirmed=True)
    return assert_not_deployable(journal)


def inspect_interrupted_provisioning(journal):
    """Return inspection-only state; never restart, undo, or enable services."""
    record = inspect_provisioning(journal)
    return {
        "state": record["state"],
        "completed_stages": list(record["completed_stages"]),
        "manual_reconciliation_required": record["state"] != "COMPLETE",
        "dispatcher_timer_activation": "FORBIDDEN",
    }
