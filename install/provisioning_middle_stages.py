#!/usr/bin/env python3
"""Execute and verify the middle stages of an isolated provisioning transaction.

Requires a separately verified preflight journal stage. No resume, service
activation, or automatic cleanup is attempted after a partial failure.
"""
from pathlib import Path
from provisioning_journal import inspect_provisioning, advance_provisioning
from provision_python import provision_python_environment
from prepare_ownership import prepare_staged_application_ownership
from verify_python_ownership import verify_python_environment, verify_staged_ownership


def execute_middle_stages(journal, application, *, uid, gid, installer=None):
    application = Path(application)
    record = inspect_provisioning(journal)
    if (record["state"] != "INCOMPLETE"
            or record["completed_stages"] != ["preflight"]
            or record["application"] != str(application)):
        raise RuntimeError("Verified preflight required; automatic resume prohibited.")
    provision_python_environment(application, installer=installer)
    if verify_python_environment(application) is not True:
        raise RuntimeError("Python package verification failed.")
    advance_provisioning(journal, "python", evidence_confirmed=True)
    prepare_staged_application_ownership(application, uid, gid)
    if verify_staged_ownership(application, uid, gid) is not True:
        raise RuntimeError("Staged ownership verification failed.")
    return advance_provisioning(journal, "ownership", evidence_confirmed=True)
