#!/usr/bin/env python3
"""Verified Python and ownership journal stages for a private staging tree.

The application must remain private. The stage runner never resumes an
interrupted transaction or activates any service.
"""
from pathlib import Path

from provisioning_journal import STAGES, inspect_provisioning, advance_provisioning
from provision_python import provision_python_environment
from prepare_ownership import prepare_staged_application_ownership
from verify_python_ownership import verify_python_environment, verify_staged_ownership


def execute_python_ownership_stages(journal, application, *, uid, gid, installer=None):
    """Provision Python as caller, then transfer ownership to service identity.

    A complete preflight must already be recorded. No automatic retry is
    attempted after any partial stage failure.
    """
    app = Path(application)
    record = inspect_provisioning(journal)
    if (record["state"] != "INCOMPLETE"
            or record["completed_stages"] != list(STAGES[:1])
            or record["application"] != str(app)):
        raise RuntimeError("Verified preflight journal stage required.")
    provision_python_environment(app, installer=installer)
    if verify_python_environment(app) is not True:
        raise RuntimeError("Python environment verification failed.")
    advance_provisioning(journal, "python", evidence_confirmed=True)
    prepare_staged_application_ownership(app, uid, gid)
    if verify_staged_ownership(app, uid, gid) is not True:
        raise RuntimeError("Ownership verification failed.")
    return advance_provisioning(journal, "ownership", evidence_confirmed=True)
