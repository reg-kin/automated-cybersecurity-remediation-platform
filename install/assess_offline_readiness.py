#!/usr/bin/env python3
"""Read-only, fail-closed post-configuration installation readiness report.

This intentionally does not invoke systemd, connect to databases, or authorize
activation. Call only after isolated staging and credential configuration.
"""
from pathlib import Path

from verify_complete_provisioning import verify_complete_provisioning
from verify_deployment_configuration import verify_deployment_configuration
from verify_service_identity_access import verify_service_identity_access


def assess_offline_readiness(
    journal, application, unit_destination, environment_destinations, *, uid, gid, native=False
):
    """Return an explicit offline-only assessment or fail on the first defect.

    Provisioning integrity compares example configuration bytes. Real configured
    credentials differ from examples, so first verify staged artifacts, then
    configure credentials, and use this function only for *post-configuration*
    readiness: the completed journal and provisioned unit files are checked
    independently, without requiring example environment file equality.
    """
    # Journal and application ownership must be verified without treating a
    # journal COMPLETE flag as authorization for production activation.
    from provisioning_journal import assert_not_deployable
    from verify_python_ownership import verify_python_environment, verify_staged_ownership
    from verified_provisioning import _verify_file
    from verify_complete_provisioning import _verify_exact_copy
    from service_provisioning import inspect_service_provisioning
    from install_application import environment_templates

    app = Path(application)
    record = assert_not_deployable(journal, native=native)
    if record["application"] != str(app):
        raise RuntimeError("Provisioning journal application mismatch.")
    if set(environment_destinations) != set(environment_templates(native=native)):
        raise RuntimeError("Incomplete environment inventory.")
    if verify_python_environment(app, native=native) is not True:
        raise RuntimeError("Python environment verification failed.")
    if verify_staged_ownership(app, uid, gid) is not True:
        raise RuntimeError("Application ownership verification failed.")
    for name in inspect_service_provisioning(app, native=native)["unit_names"]:
        destination = Path(unit_destination) / name
        _verify_file(destination, uid=uid, gid=gid, mode=0o644)
        directory = app / "deployment/systemd"
        if name in ("ansible-runner.service", "verification-gateway.service"):
            directory /= "native"
        _verify_exact_copy(directory / name, destination)
    configuration = verify_deployment_configuration(
        environment_destinations, uid=uid, gid=gid, native=native
    )
    access = verify_service_identity_access(
        app, environment_destinations, uid=uid, gid=gid, native=native
    )
    return {
        "offline_readiness": "PASSED",
        "completed_stages": record["completed_stages"],
        "configured_files": configuration["configured_files"],
        "service_identity_access": access["service_identity_access"],
        "credentials_authenticated": False,
        "runtime_services_tested": False,
        "end_to_end_remediation_tested": False,
        "activation_authorized": False,
        "dispatcher_timer_activation": "FORBIDDEN",
    }
