# Reference-host structural preflight

Use only on a **new isolated Ubuntu 24.04 host**. This is a read-only
structural diagnostic, not deployment authorization or a complete operational
validation. It must not be used to justify changing the existing VPS.

After the authenticated release is published to
`/opt/automated-remediation`, the Python 3.12 environment is provisioned,
the service identity and six canonical environment files are configured,
and the reviewed systemd units are copied to `/etc/systemd/system`, run:

```sh
python3 /opt/automated-remediation/install/inspect_reference_host.py
```

The check refuses unexpected application paths and unsupported OS/Python
versions, and verifies the expected unit inventory, required executables,
service account and existence of the six canonical environment files.
It does **not** inspect secret values, authenticate database/scanner access,
verify unit syntax, start services, or run remediation. A PASS means only
that the listed structural prerequisites were found.

Follow the separate gates in `install/PRODUCTION_READINESS.md` before any
operator-approved service activation. Never activate
`remediation-dispatcher.timer` as part of this process.

## Shell continuation clarification

For the clone command, the following single-line equivalent avoids any
Markdown line-continuation ambiguity:

```sh
git clone --branch main https://github.com/reg-kin/automated-cybersecurity-remediation-platform.git
```

For a fresh database, the equivalent one-line command is:

```sh
.venv/bin/python install/install_database.py --database YOUR_EMPTY_DATABASE --confirm-database YOUR_EMPTY_DATABASE
```

These commands are examples for a **disposable host and an empty database**,
not instructions to run against production resources.
