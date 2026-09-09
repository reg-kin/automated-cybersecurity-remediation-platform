# Project Status

## Maturity

Automated Cybersecurity Remediation Platform is currently a pre-production,
release-candidate-stage project.

The core remediation architecture has been implemented and key execution paths
have been validated, including live deferred Wazuh SCA Stage 2 verification.

It should not yet be described as production-ready across every supported
scanner and remediation capability.

## Implemented Scanner Orchestrators

- OpenVAS
- Nmap / NSE
- Nuclei
- Lynis
- Trivy
- Wazuh SCA
- Wazuh Vulnerability Detection

## Planned Scanner Orchestrators

- Wazuh File Integrity Monitoring
- Wazuh Rootcheck / rootkit detection

## Out of Scope

- Snyk

Snyk is not part of the current platform implementation.

## Remediation Capabilities

The platform defines seven remediation capabilities:

- os_patching
- container_image
- cis_hardening
- service_config
- web_application
- file_integrity
- security_incident

The presence of a remediation capability does not imply that every scanner
integration feeding that capability has already been implemented or
production-tested.

## Risk Contextualisation and Remediation Prioritisation

Deterministic Risk Contextualisation V1 is implemented.

The platform persists one current contextual risk assessment per finding
using the `CONTEXTUAL_RISK_V1` model and supports `ASSESSED`, `PARTIAL`,
and `UNSCORABLE` states.

Risk-Aware Remediation Prioritisation V1 is also implemented.

The platform exposes `prioritised_remediation_queue`, which orders
already-routed remediation findings using current contextual risk while
preserving deterministic remediation-rule selection.

Implemented ordering is:

```text
usable contextual risk first
-> higher contextual risk score
-> older detected_at
-> lower finding_id
```

Remediation Workflow Orchestration V1 is now implemented at the application-contract and regression-test level.

The platform can deterministically select the next eligible item from `prioritised_remediation_queue`, construct the existing controller payload, render remediation parameters safely, and rely on the existing controller/database boundary to prevent duplicate active executions.

The production Python remediation dispatcher is implemented and regression-tested. n8n is reserved for optional integration and notification workflows.

SLA policy, service-tier prioritisation, threat-intelligence weighting, risk-driven approval policy, batch dispatch, and parallel dispatch also remain outside V1.

## Remediation Workflow Orchestration

Remediation Workflow Orchestration V1 has been regression-tested against the disposable PostgreSQL release-test database.

Current tests verify deterministic next-item selection, controller payload construction, safe parameter rendering, queue removal after claim, duplicate-delivery rejection, and exactly one active remediation execution per finding.

The database and controller remain the authoritative concurrency and execution-state boundary. No separate dispatcher locking, claim table, or lease mechanism is used.

The production Python remediation dispatcher is the core V1 remediation-delivery component. n8n is not required for core remediation execution and remains optional for integrations, notifications, and report distribution.

## Verification

Two-stage remediation verification is supported.

Stage 1 validates the remediation execution.

Stage 2 uses the originating security scanner as the authoritative verification
source where supported.

Wazuh SCA and Wazuh Vulnerability Detection use an asynchronous refresh model
because targeted synchronous verification is not available.

## Known Hardening Work

Remaining work before a production v1.0 release includes:

- validation across all material scanner/remediation paths;
- FIM orchestrator implementation;
- rootcheck orchestrator implementation;
- retry/backoff tuning for deferred verification;
- service credential hardening;
- TLS verification hardening for Wazuh Indexer communication;
- SSH deployment hardening;
- container privilege review;
- operational monitoring and alerting;
- Python remediation dispatcher deployment validation;
- formal installation and upgrade testing.
