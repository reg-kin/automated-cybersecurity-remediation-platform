# Production installation validation — bounded handover

## Decision

**Offline installation and disposable CI validation: completed, subject to the latest branch-head workflows passing.**

**Production activation: NOT AUTHORISED.** This document is a handover of tested scope and remaining operational prerequisites, not permission to deploy, modify the existing production database, or start services.

## Evidence and scope

The feature branch runs two independent GitHub Actions workflows on Ubuntu 24.04:

- **Release installation regression**: Python 3.12 syntax, whitespace, pinned dependency installation, isolated Flask controller/verification-gateway runtime tests, authentication and approval/cancellation handling, offline provisioning, staged ownership, configuration and static service-account access, rollback and journal fail-closed checks.
- **Fresh PostgreSQL installation**: disposable PostgreSQL 16, migration/install checks, nonempty-database reinstall rejection, atomic rollback of a deliberately failing migration, protected database-name refusal, scan-policy integration, and remediation lifecycle tests.

The disposable remediation lifecycle tests cover actual cancellation of an awaiting-approval execution, reopening its finding without counting an attempt or creating verification records, repeated-cancellation rejection, the database's unique-active-execution constraint, Stage 1 and Stage 2 verification evidence persistence, and refusal to overwrite terminal verification results. Stage 2 FAILED evidence does not by itself mark the finding RESOLVED.

These tests **do not** execute Ansible on a host, authenticate against real scanner APIs, exercise all controllers end to end, or demonstrate a successful real remediation. Simulated Stage 1 PASSED evidence is test data only.

## Release-candidate boundary

No additional optional CI suites are required for this **offline/disposable validation handover**. If branch-head CI fails, fix that failure before considering this scope validated. Any new feature or broader runtime integration belongs in separately scoped work.

## Required operator-controlled production gates

1. Resolve existing service/unit, port, filesystem and execution-target conflicts before provisioning. Do not overwrite existing production resources.
2. Review release identity, migration plan, production backups, and a fresh isolated database destination. Never run these CI tests against `security_portal`.
3. Provision actual six environment configurations and secrets outside Git; run the offline readiness assessor and validate real service-account permissions, credential authentication and connectivity.
4. Validate runtime systemd dependencies, API access, scanner access, management-plane authorization, and an approved **disposable host** end-to-end remediation including genuine Stage 1 and Stage 2 verification.
5. Approve a change window and rollback procedure before any production activation. Keep `remediation-dispatcher.timer` disabled unless separately authorized.

**Until those gates are completed, the correct status is: offline CI validated / production readiness blocked.**
