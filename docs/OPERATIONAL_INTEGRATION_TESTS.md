# Operational Integration Test Record

## Purpose

This document records operational integration tests performed against the
Automated Cybersecurity Remediation Platform.

Tests are distinguished from code review, configuration inspection, mocked
unit tests, and unverified capabilities.

## Test environment

- Test date: 2026-10-09
- Development branch: `feature/post-release-integration-validation`
- Published release baseline: `v0.3.0-beta.1`
- VPS hostname: `vmi3031128`
- Target laptop hostname: `regis`
- Runner container: `ansible-runner`
- Runner host endpoint: `127.0.0.1:8081`
- Runner container endpoint: `127.0.0.1:8080`
- Ansible target alias: `192.168.0.198`
- SSH destination: `172.22.0.1:22198`
- SSH user: `regis`

## Test results

| ID | Capability | Result | Evidence |
|---|---|---|---|
| INT-001 | Runner host port binding | PASS | Docker published `127.0.0.1:8081->8080/tcp` |
| INT-002 | Unauthenticated Runner API request | PASS | HTTP 401 |
| INT-003 | Authenticated malformed request | PASS | HTTP 400 |
| INT-004 | Mandatory playbook allowlist | CONFIGURATION VERIFIED | `controller_positive_test.yml` present in configured allowlist |
| INT-005 | Runner SSH connectivity | PASS | Remote `true` command exited 0 |
| INT-006 | Ansible module execution | PASS | `ansible.builtin.ping` returned `pong`, `changed=false` |
| INT-007 | Initial positive-path remediation attempt | FAIL — TEST SETUP | Marker was mistakenly created on VPS instead of laptop |
| INT-008 | Corrected positive-path remediation | PASS | Runner job `d2801dc4-2445-4495-96cb-b93d0361137f`, rc=0 |
| INT-009 | Immediate Stage 1 verification | PASS | `ANSIBLE_LOCAL`, `passed=true` |
| INT-010 | Independent post-remediation verification | PASS | Separate SSH check confirmed marker absent on laptop |

## Positive-path remediation test

### Playbook

`controller_positive_test.yml`

### Target

SSH alias `192.168.0.198`, resolving through the existing SSH
configuration to the Ubuntu laptop.

### Disposable test artifact

`/tmp/regis-stage2-positive/regis-marker.txt`

### Initial attempt

- Runner job ID: `c04c0650-fa06-44ad-a5cd-b816a00676a7`
- HTTP status: 200
- Ansible exit code: 2
- Runner success: false
- Stage 1 verification: failed
- Root cause: The prerequisite marker was created on the VPS, not the laptop.
- Result: The playbook stopped at its prerequisite assertion.
- No remediation action was performed.

### Corrected attempt

The marker was created on the laptop through the Runner's existing SSH
connection before repeating the test.

- Runner job ID: `d2801dc4-2445-4495-96cb-b93d0361137f`
- HTTP status: 200
- Ansible exit code: 0
- Runner success: true
- Stage 1 verification type: `ANSIBLE_LOCAL`
- Stage 1 verification passed: true
- Ansible recap: `ok=5 changed=1 unreachable=0 failed=0`

The playbook confirmed the marker existed, removed it, and verified its
absence.

A subsequent independent SSH command confirmed:

`PASS: Test marker is absent on regis`

### Scope of successful validation

This test establishes live execution through the Ansible Runner API,
SSH connectivity, Ansible playbook execution, a controlled file-removal
remediation action, and immediate Stage 1 verification.

It does not establish that the platform's remediation controller,
finding lifecycle, database integration, or Stage 2 scanner verification
operated during this test.

## Observations and limitations

1. The Runner API may return HTTP 200 even when a playbook fails.
   Clients must inspect the response's `success`, `status`, `rc`, and
   `verification` fields.
2. SSH emitted warnings when attempting to update
   `/root/.ssh/known_hosts` on a read-only mount. Remote execution
   nevertheless succeeded. This warning requires separate investigation.
3. The Runner uses dynamic single-host inventory construction.
4. Target-host syntax validation is implemented in the Runner API;
   managed-asset authorisation was not established by these tests.
5. Playbook allowlist membership was inspected, but an actual
   disallowed-playbook rejection test was not performed.
6. The authenticated malformed-request test was issued against the
   container-local API endpoint.

## Capabilities not yet validated live

- Rejection of unauthorised execution targets through the complete workflow
- Complete database-backed remediation lifecycle through final resolution
- Automatic recovery after Stage 1 verification initialisation failure
- Stage 2 verification using a fresh scanner observation
- End-to-end scanner finding ingestion and orchestration
- Failure handling across the complete remediation workflow
- Production vulnerability or compliance remediation

## Controller-to-Runner integration validation

### Environment and scope

- Date: 2026-10-09
- Controller endpoint: `127.0.0.1:9001` (isolated Gunicorn instance)
- Controller source: Git working tree
- Database: `regis_controller_integration_test`
- Production Controller: not modified or restarted
- Stage 2 configuration: `TEST_SKIP_STAGE2=true`
- Tenant: `CONTROLLER-LIVE-INT-TEST`
- Finding ID: `2`
- Remediation rule ID: `45`
- Authorised execution target: Ubuntu laptop, SSH alias `192.168.0.198`
- Playbook: `controller_positive_test.yml`
- Disposable marker: `/tmp/regis-stage2-positive/regis-marker.txt`

### Test results

| ID | Capability | Result | Evidence |
|---|---|---|---|
| INT-011 | Controller-to-Runner remediation invocation | PASS | `POST /remediate`, HTTP 200, execution `2`, Ansible exit code `0` |
| INT-012 | Database-backed Stage 1 verification | PASS | Execution `2`: `STAGE1_PASSED`; verification stage `1`, `ANSIBLE_LOCAL`, source `ansible`, `PASSED` |
| INT-013 | Remediation on authorised laptop target | PASS | Playbook target `192.168.0.198`; Controller response `success=true` |
| INT-014 | Independent endpoint verification | PASS | Separate SSH check: `PASS: Test marker removed from Ubuntu laptop` |

### Initial failure and corrective actions

The first Controller request returned HTTP 500 because the isolated
PostgreSQL database lacked
`begin_remediation_verification(bigint,bigint,smallint,text,text)`.
The failure occurred before Ansible execution.

Execution `1` was left `RUNNING` and finding `2` was left
`IN_REMEDIATION`. Both were recovered in the isolated database:
execution `1` was marked `FAILED`, and finding `2` was reopened.

Corrective changes in the Git working tree:

- `database/migrations/022_remediation_verification_functions.sql`
  introduces `begin_remediation_verification` and
  `complete_remediation_verification`.
- Migration `022` was applied successfully to the isolated database only.
- `remediation/controllers/base.py` now handles Stage 1 verification
  initialisation exceptions by failing the execution and reopening the
  finding through the failure-recovery path.

The isolated Controller was restarted from the Git working tree, using
the existing Python virtual environment, isolated database, and Stage 2
test configuration. The production Controller and production database
were not changed.

### Successful Controller retest

The disposable marker was recreated on the laptop before the retest.

The Controller returned HTTP 200 with:

- Execution ID: `2`
- `success`: `true`
- Ansible exit code: `0`
- Stage 1 verification: `PASSED`
- Stage 2: `SKIPPED_TEST_MODE`

A separate SSH check confirmed the marker had been removed from the
laptop. PostgreSQL independently confirmed:

- Execution `2`: `STAGE1_PASSED`
- Finding `2` associated with execution `2`
- Verification stage `1`: `PASSED`
- Verification type: `ANSIBLE_LOCAL`
- Verification source: `ansible`
- Verified at: `2026-10-09 19:20:49.574969+00`

### Limitations and remaining validation

This test confirms Controller-to-Runner execution, the controlled
remediation action on the laptop, immediate Stage 1 verification, and
persistence of the Stage 1 result in the isolated database.

It does not demonstrate Stage 2 scanner verification, final finding
resolution, end-to-end scanner ingestion, or production remediation.

The missing-function failure was observed and manually recovered.
The newly added automatic recovery path has not yet been independently
failure-injection tested.

The migration and Python correction have not been deployed to
production. The existing Runner SSH `known_hosts` read-only warnings
remain non-fatal.

## Documentation policy

For every subsequent integration test, record:

- Date and environment
- Capability and test identifier
- Preconditions and exact commands
- Expected and actual results
- PASS, FAIL, or NOT TESTED
- Execution identifiers and relevant evidence
- Root cause and corrective action for failures
- Explicit limitations

Update this document and commit the evidence before moving to the
next major integration capability.
