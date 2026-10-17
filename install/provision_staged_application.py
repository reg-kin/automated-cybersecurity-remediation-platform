#!/usr/bin/env python3
"""Offline full-stage provisioning entry point, without service activation.

Only a previously staged, private application and caller-supplied destinations
are eligible. The journal is exclusive and cannot be resumed automatically.
"""
from pathlib import Path

from provisioning_journal import (
    begin_provisioning, advance_provisioning, inspect_provisioning,
    assert_not_deployable,
)
from verified_provisioning import verified_preflight
from provisioning_middle_stages import execute_middle_stages
from provisioning_final_stages import execute_final_provisioning_stages
from verify_complete_provisioning import verify_complete_provisioning


def provision_staged_application(
    journal, application, unit_destination, environment_destinations,
    *, uid, gid, installer=None, native=False,
):
    """Execute all five journal stages on a private staging tree.

    This is not a production installation CLI and never enables or starts
    systemd units. Partial failures remain INCOMPLETE for manual reconciliation.
    """
    app = Path(application)
    if not app.is_absolute() or app.is_symlink():
        raise RuntimeError("Application must be an absolute non-symlink path.")
    if not verified_preflight(app, unit_destination, environment_destinations, native=native):
        raise RuntimeError("Read-only preflight verification failed.")
    begin_provisioning(journal, application=app, native=native)
    advance_provisioning(journal, "preflight", evidence_confirmed=True, native=native)
    execute_middle_stages(
        journal, app, uid=uid, gid=gid, native=native, installer=installer
    )
    execute_final_provisioning_stages(
        journal, app, unit_destination, environment_destinations,
        uid=uid, gid=gid, native=native,
    )
    return verify_complete_provisioning(
        journal, app, unit_destination, environment_destinations, uid=uid, gid=gid, native=native
    )


def inspect_staged_application(journal):
    """Inspection only; never implicitly resume or activate a deployment."""
    record = inspect_provisioning(journal)
    return {
        "application": record["application"],
        "state": record["state"],
        "completed_stages": list(record["completed_stages"]),
        "requires_manual_reconciliation": record["state"] != "COMPLETE",
        "dispatcher_timer_activation": "FORBIDDEN",
    }
