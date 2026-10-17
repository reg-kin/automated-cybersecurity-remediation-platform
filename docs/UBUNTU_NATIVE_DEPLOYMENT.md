# Ubuntu 24.04 native runtime installation

Docker and Compose are optional. The existing Compose deployment remains available;
this opt-in profile runs the Ansible Runner and Stage 2 verification gateway with
Gunicorn and systemd alongside the existing controller, scanner worker and APIs.
It preserves the database installer, remediation workflow, unified finding schema,
and both verification stages. This is an operator runbook, not an automatic
activation or an upgrade procedure.

## Prerequisites and dependencies

Use Ubuntu 24.04, Python 3.12 and PostgreSQL 16. On the intended host, provision
packages explicitly (these commands change the host and are not part of offline
provisioning):

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends python3.12 python3.12-venv postgresql-client-16 openssh-client sshpass ca-certificates redis-server
```

PostgreSQL may be a separately managed server; install `postgresql-16` only if
hosting it locally. Redis must be available at the worker's configured URL.
Install and configure only the scanners used by your deployment, using the paths
in `deployment/systemd/env/verification-scanner.env.example`. Scanner executables,
feeds, scanner credentials and remote Wazuh/OpenVAS endpoints are external
prerequisites; installing Python requirements does not provision them.

Use the existing [release staging and fresh database procedure](../install/PRODUCTION_READINESS.md).
Do not rerun the fresh database installer on a populated database. Keep its SQL
manifest and order unchanged. Create the `automated-remediation` service user and
group through your host account management process. The final application path
remains `/opt/automated-remediation`, with its Python environment at `venv`.

The native profile installs `requirements.txt` plus
`deployment/requirements-native.txt` into that environment. The latter adds the
pinned Ansible distribution without importing the conflicting Gunicorn and
psycopg2 pins from the container-specific Runner requirements. For a manually
prepared fresh environment the equivalent is:

```sh
python3.12 -m venv /opt/automated-remediation/venv
/opt/automated-remediation/venv/bin/python -m pip install -r /opt/automated-remediation/requirements.txt -r /opt/automated-remediation/deployment/requirements-native.txt
/opt/automated-remediation/venv/bin/python -m pip check
```

The existing `ansible/requirements.yml` lists collections used by the playbooks.
Check installed collections with `venv/bin/ansible-galaxy collection list`; install
any missing collections into a directory readable by the service identity. The
presence of `community.docker` in that list does not require Docker unless you
select a playbook that operates on Docker. Provision the service identity's SSH
credentials, trusted host keys, target login and required target-side privileges
separately. Native units use `/var/lib/automated-remediation` as HOME, created by
systemd via StateDirectory; prepare SSH material there before activation. Do not
disable host-key checking. Review the playbook allowlist before accepting jobs.

## Offline provisioning and readiness

`install/provision_offline_cli.py` retains its default six environments / nine
units. Pass `--native` to select eight environments / eleven units. The additional
units live in `deployment/systemd/native/`; they are copied into the same explicit
unit destination, never enabled or started. Existing files are never overwritten.
The journal and interruption behavior are unchanged.

Prepare the private staged application, private journal parent, trusted empty unit
destination and trusted environment destination directory as described in the
existing installation guide. Create a JSON map of **all eight** canonical paths
to absolute destination paths: the original six from
`install_application.ENVIRONMENT_FILE_TEMPLATES`, plus `/etc/ansible-runner.env`
and `/etc/verification-gateway.env`. Example invocation (replace every path and
numeric ID for your prepared staging area):

```sh
python3 install/provision_offline_cli.py --native \
  --application /private/staged-application --unit-destination /private/units \
  --environment-map /private/environment-map.json --journal /private/journal.json \
  --uid 10001 --gid 10001
```

This is read-only preflight. Add `--provision --confirm-application
/private/staged-application` to explicitly perform the offline stages, including
Python dependency installation. The staged tree must still belong to the caller
before ownership preparation. A COMPLETE journal verifies example files, not live
credentials or authorization to activate. Do not run provisioning over an existing
installation; use a separately reviewed additive change for existing hosts.

Configure the environment files privately after provisioning and retain mode
0640 with the intended owner/group. Native readiness uses the existing Python API:

```python
from verify_deployment_configuration import verify_deployment_configuration
# Run with install/ on sys.path; destinations is the reviewed eight-path map.
verify_deployment_configuration(destinations, uid=service_uid, gid=service_gid, native=True)
```

`assess_offline_readiness(..., native=True)` also checks the selected units,
Python environment and service identity access after configuration.

The configuration gate reads only the explicitly supplied configuration files and prints no values.
It rejects placeholders, missing required settings, unsafe metadata, Stage 2
bypass, and mismatched native endpoint/token pairs. It does not prove connectivity.

| Service | Bind settings | Caller configuration |
| --- | --- | --- |
| Controller | CONTROLLER_HOST=127.0.0.1, CONTROLLER_PORT=9000 | Dispatcher CONTROLLER_REMEDIATE_URL, same CONTROLLER_TOKEN |
| Runner | ANSIBLE_RUNNER_HOST=127.0.0.1, ANSIBLE_RUNNER_PORT=8081 | Controller ANSIBLE_RUNNER_URL ends in /run, same ANSIBLE_RUNNER_TOKEN |
| Verification gateway | VERIFICATION_HOST=127.0.0.1, VERIFICATION_PORT=18091 | Controller VERIFICATION_URL ends in /verify, same VERIFICATION_TOKEN |

The native unit bind flags consume those environment settings. These ports match
the existing controller template without changing the standalone development
server defaults. All mutation endpoints require Bearer authentication. Keep
`TEST_SKIP_STAGE2=false`. Copy the scanner-specific settings required by Stage 2
into `/etc/verification-gateway.env` from the existing scanner/Wazuh templates;
comment references in the template do not load files automatically. Maintain
separate reviewed credentials and the Runner's mandatory `ALLOWED_PLAYBOOKS`.
Keep services on loopback; remote exposure requires a separately configured TLS
and access-control boundary.

## Activation handoff and smoke validation

Review configured files, dependency availability, SSH access and scanner reachability
before publishing to the fixed application path and installing units in systemd's
unit directory. An administrator must explicitly authorize daemon reload and
service activation in the host's deployment procedure. No installer command here
enables services or timers. Leave remediation and scheduling timers inactive until
end-to-end validation authorizes automated execution. Existing installation and
rollback boundaries still apply; this change does not manage production upgrades.

For a **disposable test PostgreSQL server only**, the release smoke test supports:

```sh
SMOKE_PG_MODE=native PGHOST=127.0.0.1 PGPORT=5432 PG_USER=smoke_admin \
  PGPASSFILE=/private/test-pgpass ./tests/release_smoke_test.sh
```

The administrator must have permission to create databases and roles. Native mode
uses local `psql` and standard libpq connection/authentication variables; the Python
database regressions use the same PGHOST/PGPORT and a generated temporary role.
The default `SMOKE_PG_MODE=docker` retains `PG_CONTAINER=portal-datastore` and
`PG_USER=telemetry_admin`. Docker and Compose are not required in native mode.
Both modes retain the same SQL reconstruction and database assertions. A random
invocation suffix is appended to TEST_DB (default prefix
`automated_remediation_release_smoke_test`); the resulting identifier must fit
PostgreSQL's 63-byte identifier limit (42 ASCII bytes for the prefix plus
the underscore and 20 hexadecimal suffix bytes). Roles also use a random
invocation identifier.
Endpoints must be a single TCP host and numeric port. Service overrides,
PGHOSTADDR, PGOPTIONS, authentication-mechanism overrides and connection
strings are refused; password files, TLS settings and SCRAM remain supported.
Administrative psql uses `-w`
(no password prompts), `-X`, explicit endpoints and a five-second connection
timeout. Docker administrative SQL uses container TCP port 5432; PGHOST/PGPORT
must reach that same server from the host for Python tests. Authentication must
already be configured privately; the smoke test does not provision credentials.

Python regressions require explicit disposable-database confirmation and compare
the database OID and fresh 20-hex invocation marker with administrative SQL
before mutation. Native mode also requires matching server address and port.
Docker mode allows NAT to change the observed address/port; matching loopback
addresses alone never establish endpoint equivalence. Cleanup retains the role
whenever its database has not been safely removed.
Cleanup requires acknowledged creation and matching recorded OIDs and
invocation markers. Failed or ambiguous CREATE outcomes are left for manual
review, even if creation actually committed. Cleanup errors produce a failing
exit status and recovery identifiers. Cleanup is best effort, not a guarantee;
retain the reported identifiers and inspect ownership before manual recovery.
Do not use a production server for smoke validation.
