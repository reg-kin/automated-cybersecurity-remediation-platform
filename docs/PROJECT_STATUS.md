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
- n8n workflow validation;
- formal installation and upgrade testing.
