# Production installation readiness and controlled handover

This branch provides an **offline staged provisioning workflow**, not an unattended production installer or authorization to start services. The release and database workflows use disposable CI resources. A passing CI run does not validate a production host, live credentials, database migrations against production data, or network access.

## Supported stages

1. Inspect a private staged application, exact pinned requirements, unit manifests, and absent destinations.
2. Create the Python virtual environment and verify pinned installed distributions.
3. Prepare and verify application ownership, rejecting unexpected symlinks.
4. Copy six **example** environment files exclusively, with restricted permissions.
5. Copy validated systemd unit files exclusively, without invoking systemctl.

A private, exclusive journal records stage boundaries. An interrupted transaction remains incomplete and is **never automatically resumed**. A completed journal must be checked against the current artifacts using `verify_complete_provisioning`; that verifier requires the provisioned environment files to match the templates byte-for-byte. It is therefore a **staging integrity** check, not a live-configuration validator.

## Required separate production decisions and checks

- Resolve pre-existing ports, unit names, deployment paths, service-account access, network dependencies, and existing services. Never overwrite production files to bypass preflight.
- Prepare an approved release and a **fresh isolated database**; review migrations and backups before considering production data.
- Configure deployment-specific secrets in the six environment files; examples contain `CHANGE_ME`, empty passwords, or local defaults. Never commit secrets or treat example files as usable production configuration.
- Run `verify_deployment_configuration` against the configured files. It checks required non-placeholder values, owner/group, mode 0640, and disabled Stage 2 test bypass. It does **not** verify credential correctness, endpoint reachability, or authorize activation.
- Independently validate actual service-account read access, systemd unit syntax and runtime dependencies, API authentication, PostgreSQL permissions, scanner connectivity, remediation authorization boundaries, and Stage 1/Stage 2 verification against a **disposable target**.
- Require a reviewed change window and explicit operator approval for any `systemctl daemon-reload`, enable, or start operation. **Never automatically enable or start `remediation-dispatcher.timer`.**

## Interrupted installation and recovery

Stop on any exception; do not rerun the same transaction against partly populated targets. Preserve the private journal and logs for inspection. Record the completed stages, compare file identities and contents, and identify which objects were created. The environment and unit writers roll back their own newly created files when a write fails, but **there is no cross-stage atomic rollback**. Ownership preparation and pip installation may leave partial state. Recovery requires a reviewed cleanup or a new private staging directory and a **new** journal; do not delete existing systemd units or environment files without proving they belong to the failed transaction. Never edit a journal to mark an unverified stage complete.

## Completion criterion

CI passing establishes only tested code behavior. Production readiness additionally requires validated secrets, access and service health checks, end-to-end remediation and verification tests, documented rollback, and operator approval. Production database and active services are out of scope for automated CI.
