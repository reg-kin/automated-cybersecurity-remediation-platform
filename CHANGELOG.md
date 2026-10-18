# Changelog

All notable changes to the Automated Cybersecurity Remediation Platform will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning for release numbering.

## [Unreleased]

### Added

### Changed

### Fixed

- Restored the implemented OpenVAS/GVMD scanner orchestrator that was
  inadvertently omitted from the v0.1.0 repository contents.

### Security

## [1.0.0] - Release candidate (date to be set on publication)

### Release scope
- Versioned public portfolio baseline for the implemented cybersecurity remediation platform.
- Documentation clarifying engineering achievements, installation boundaries and operational limitations.
- No new production activation or claim of universal production readiness.

### Capabilities included
- Unified Security Finding model, deterministic finding-class assignment and 43-class remediation catalogue.
- OpenVAS, Nmap NSE, Nuclei, Lynis, Trivy, Wazuh SCA and Wazuh Vulnerability Detection orchestrators.
- Asset management, contextual risk assessment, remediation readiness and scan coordination.
- Approval-aware Ansible remediation with immediate and deferred two-stage verification.
- PostgreSQL migration tooling, isolated installation/provisioning checks and release packaging.

### Validation summary
- Fresh PostgreSQL installation and offline staged provisioning validated in disposable CI.
- Existing selected live remediation and scanner verification evidence retained; no new live validation implied.
- End-to-end operational acceptance across all scanner and remediation capabilities is not claimed.

### Known limitations
- Deployment-specific configuration, external scanners and service activation require operator setup.
- Wazuh FIM and Rootcheck orchestrators are not implemented.
- Refer to README, docs/PROJECT_STATUS.md and install/PRODUCTION_READINESS.md for current support boundaries.

## [0.1.0] - 2026-09-02

### Added

- Initial public pre-production release of the Automated Cybersecurity Remediation Platform.
- Unified Security Finding model with 43 canonical finding classes.
- Deterministic PostgreSQL-backed remediation routing.
- 43 generic remediation rules covering all canonical finding classes.
- Specialised Wazuh SCA remediation rule for CIS Ubuntu 24.04 check 35594.
- Seven remediation capabilities:
  - `os_patching`
  - `container_image`
  - `cis_hardening`
  - `service_config`
  - `web_application`
  - `file_integrity`
  - `security_incident`
- Scanner orchestrators for:
  - OpenVAS
  - Nmap/NSE
  - Nuclei
  - Lynis
  - Trivy
  - Wazuh SCA
  - Wazuh Vulnerability Detection
- AI-assisted risk enrichment using a dedicated enrichment worker.
- Separation between AI risk enrichment and deterministic remediation routing.
- PostgreSQL-backed finding, execution, verification, and remediation lifecycle management.
- Ansible-based remediation execution.
- Seven remediation controller implementations.
- Stage 1 local remediation verification.
- Stage 2 scanner-authoritative remediation verification.
- Immediate verification support for scanners capable of targeted verification.
- Deferred asynchronous verification model for Wazuh.
- Scanner refresh completion control-event processing.
- Immutable scanner refresh finding receipts.
- Deferred verification reconciliation.
- Wazuh integration rules for security findings and scanner refresh events.
- Redis/RQ queues for AI enrichment and scanner control-event processing.
- n8n and Ansible Runner deployment configuration.
- Systemd service definitions and safe environment-file examples.
- JSON Schema validation for Unified Security Findings.
- Finding-class and remediation-rule consistency validation.
- Approval-aware remediation lifecycle.
- Recurrence handling for previously resolved findings.
- Apache License 2.0.
- Security policy and contribution guidelines.
- Project status and architecture documentation.

### Validated

- Deterministic remediation routing.
- Approval workflow behaviour.
- Duplicate remediation protection.
- Remediation retry behaviour.
- Stage 1 success and failure handling.
- Stage 2 success, failure, and scanner-unavailable handling.
- Recurrence handling.
- Ansible Runner failure and rejection handling.
- Production-style Wazuh SCA end-to-end remediation.
- Asynchronous Wazuh scanner refresh verification.
- Authoritative finding-absence verification following remediation.
- Clean PostgreSQL database reconstruction from repository SQL.
- Exact 43-class catalogue coverage.
- 44 seeded remediation rules comprising 43 generic rules and one specialised Wazuh SCA rule.

### Known Limitations

- This is a pre-production release and is not yet considered production-hardened.
- Wazuh FIM orchestration is planned but not yet implemented.
- Wazuh Rootcheck orchestration is planned but not yet implemented.
- Snyk integration is out of scope.
- Broader end-to-end validation across all scanner and remediation paths remains required.
- Additional TLS and deployment hardening remains.
- Deferred-verification polling/backoff requires further operational tuning.
- CI/CD automation has not yet been fully established.
