# Production installation readiness and controlled handover

This branch provides an **offline staged provisioning workflow**, not an unattended production installer or authorization to start services. The release and database workflows use disposable CI resources. A passing CI run does not validate a production host, live credentials, database migrations against production data, or network access.

## Public clean-system installation path (current supported boundary)

The supported reference environment for the tested installer is Ubuntu 24.04,
Python 3.12 and PostgreSQL 16. Use a **new, isolated machine and an empty,
separately created database**. The steps below are deliberately limited to
operations exposed by the repository's actual CLI entry points; they do not
constitute a running production deployment.

1. Clone the release candidate for inspection (replace the branch with the
   published release tag when one exists):

   ```sh
   git clone --branch feature/production-installation-readiness \\
     https://github.com/reg-kin/automated-cybersecurity-remediation-platform.git
   cd automated-cybersecurity-remediation-platform
   ```

2. Install the pinned Python dependencies in an isolated environment before
   using the database installation CLI:

   ```sh
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   ```

3. Provision an **already created, empty PostgreSQL database** with an account
   permitted to install the schema. Set `PG_HOST`, `PG_PORT`, `PG_USER` and
   `PG_PASSWORD` privately in the shell environment; never commit credentials.
   Replace `YOUR_EMPTY_DATABASE` with its actual name:

   ```sh
   .venv/bin/python install/install_database.py \\
     --database YOUR_EMPTY_DATABASE \\
     --confirm-database YOUR_EMPTY_DATABASE
   ```

   This command changes **only the explicitly named database** and is for
   fresh installations, not upgrades. Do not run it against a populated or
   production database. If it fails, stop and inspect the error; do not try
   to bypass the installer's refusal checks.

4. For a release archive, `install/package_release.py` requires a full,
   committed 40-character Git SHA and a new output filename. The resulting
   SHA-256 digest must be retained alongside the archive. The separate
   `install/production_release.py` command validates the archive using
   `--archive`, `--sha256`, `--staging-parent` and the supported destination
   `/opt/automated-remediation`. The staging parent must already exist, be
   owned by the invoking user and be private (mode 0700). Its default mode is
   **validation only**; `--publish-application-only` additionally requires
   `--confirm-destination /opt/automated-remediation` and publishes files
   without configuring or activating services. Do not publish over an
   existing installation.

5. The remaining stages—Python environment provisioning, application
   ownership, six configured environment files, systemd unit provisioning,
   runtime credentials/connectivity, and service activation—are
   **operator-controlled**. The staged provisioning function
   `install/provision_staged_application.py` is a Python API. The explicit
   `install/provision_offline_cli.py` wrapper provides preflight by default
   and requires `--provision --confirm-application` to perform the same
   offline stages. It requires explicit caller-provided paths,
   user/group IDs and a private journal. Do not invoke it against live
   system paths without a reviewed deployment procedure. It never starts
   services or authorizes the remediation dispatcher timer.

**Current result:** The repository supports validated *offline release
preparation and fresh database installation*, not a fully documented,
self-contained production activation from `git clone`. A full production
installation claim requires an executable operator runbook covering the
remaining stages and runtime validation; this guide intentionally does not
invent missing commands or credentials.

## Deployment handoff: exact remaining integration boundary

The provisioning API and its `install/provision_offline_cli.py` wrapper can
execute the five offline stages, but neither is a complete production
deployment command. Its callable signature is:

```python
provision_staged_application(
    journal, application, unit_destination, environment_destinations,
    uid=service_uid, gid=service_gid,
)
```

The CLI accepts `--application`, `--unit-destination`,
`--environment-map` (a JSON object mapping the exact six canonical environment
paths to explicit absolute destinations), `--journal`, `--uid`, and `--gid`.
By default it only runs the read-only preflight. To write staged files the
operator must additionally provide `--provision` and
`--confirm-application` equal to the application path. The wrapper calls the
existing verified provisioning function; it does not bypass its fail-closed
journal or exclusive destination checks. Use isolated destinations first.

The caller must supply an existing private staged application tree, an absent
journal path inside a private directory, the full six-entry mapping from
`ENVIRONMENT_FILE_TEMPLATES`, an existing unit destination, and the intended
service identity. The function provisions Python packages, ownership,
environment **examples** and unit files, and verifies the completed journal.
It does not create the service account, configure real secrets, connect to
scanners, install external services, or activate systemd. It cannot resume an
interrupted transaction.

**Integration constraint:** The supplied systemd units use fixed paths under
`/opt/automated-remediation` and `/etc/*.env`. A private staged application
and isolated CI destinations do not by themselves satisfy those runtime paths.
Do not copy or enable those units until the actual destination, environment
files, service account and dependent services have been reconciled. In
particular, do not enable `remediation-dispatcher.timer` during installation.

**Production acceptance evidence required before advertising an operational
installation:** a documented, operator-approved fresh-host provisioning and
activation procedure, with actual runtime credential/connectivity checks and
at least one controlled end-to-end remediation/independent verification on a
disposable target. Existing CI proves the offline stages and database path;
it does **not** prove this final operational boundary. This is a defined
release gate, not a request for unrelated features or optional test suites.

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
- After changing the provisioned example environment files into configured files, run `assess_offline_readiness` to reconcile the completed journal, pinned packages, ownership, exact systemd unit contents, configuration completeness, and static service-account access. It intentionally does not compare configured secret files to their original examples, and returns `activation_authorized: false` even when all offline gates pass.\n- Run `verify_deployment_configuration` against the configured files. It checks required non-placeholder values, owner/group, mode 0640, and disabled Stage 2 test bypass. It does **not** verify credential correctness, endpoint reachability, or authorize activation.
- Independently validate actual service-account read access, systemd unit syntax and runtime dependencies, API authentication, PostgreSQL permissions, scanner connectivity, remediation authorization boundaries, and Stage 1/Stage 2 verification against a **disposable target**.
- Require a reviewed change window and explicit operator approval for any `systemctl daemon-reload`, enable, or start operation. **Never automatically enable or start `remediation-dispatcher.timer`.**

## Interrupted installation and recovery

Stop on any exception; do not rerun the same transaction against partly populated targets. Preserve the private journal and logs for inspection. Record the completed stages, compare file identities and contents, and identify which objects were created. The environment and unit writers roll back their own newly created files when a write fails, but **there is no cross-stage atomic rollback**. Ownership preparation and pip installation may leave partial state. Recovery requires a reviewed cleanup or a new private staging directory and a **new** journal; do not delete existing systemd units or environment files without proving they belong to the failed transaction. Never edit a journal to mark an unverified stage complete.

## Completion criterion

CI passing establishes only tested code behavior. Production readiness additionally requires validated secrets, access and service health checks, end-to-end remediation and verification tests, documented rollback, and operator approval. Production database and active services are out of scope for automated CI.
