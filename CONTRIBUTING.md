# Contributing

Contributions are welcome.

## Development Principles

Changes should preserve the platform's core architectural boundaries:

1. Scanner orchestrators normalise source data into the Unified Security Finding.
2. Scanner orchestrators determine `finding_class`.
3. AI enrichment provides risk context only.
4. Remediation routing remains deterministic.
5. n8n acts as an orchestration and human-workflow layer.
6. Remediation controllers execute one of the defined remediation capabilities.
7. Stage 1 verification validates execution locally.
8. Stage 2 verification uses the authoritative originating scanner where supported.
9. Scanner refresh control events are not Unified Security Findings.
10. Secrets must never be committed.

## Pull Requests

Before submitting a pull request:

- ensure Python files compile;
- run the repository tests;
- validate database migrations against a clean PostgreSQL database;
- do not include credentials or environment-specific secrets;
- document architectural changes;
- update tests when behaviour changes.

Changes to finding classes, database schema, remediation routing or verification
semantics should include corresponding migration, schema and test updates.

## Coding Style

Prefer explicit, deterministic behaviour over implicit inference.

Security-sensitive failures should fail closed.

Do not silently downgrade verification or bypass approval requirements.
