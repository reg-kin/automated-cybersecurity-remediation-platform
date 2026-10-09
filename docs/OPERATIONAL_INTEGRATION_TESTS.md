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

- Full remediation-controller-to-Runner integration
- Authorised execution-target enforcement through the complete workflow
- Database-backed remediation execution lifecycle
- Stage 2 verification using a fresh scanner observation
- End-to-end scanner finding ingestion and orchestration
- Failure handling across the complete remediation workflow
- Production vulnerability or compliance remediation

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
