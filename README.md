# Regis Security Automated Remediation Platform

Regis Security Automated Remediation Platform is an open-source security
automation platform for detecting, contextualising, routing, remediating and
verifying security findings across vulnerability, configuration and compliance
tooling.

The platform combines security scanners, deterministic remediation routing,
AI-assisted risk contextualisation, Ansible-based remediation and independent
post-remediation verification.

> **Project status:** Pre-production. The core architecture and key execution
> paths have been implemented and tested, including live asynchronous Wazuh SCA
> remediation verification. The project is not yet considered production-ready
> across every scanner and remediation capability.

See [Project Status](docs/PROJECT_STATUS.md) for current implementation and
hardening status.

---

## Architecture

The platform separates detection, risk contextualisation, remediation
selection, execution and verification.

```text
Security scanners / security engines
              |
              v
      Scanner orchestrators
              |
              | Unified Security Finding
              v
          Wazuh routing
              |
              v
             Redis
        /             \
       /               \
ai-enrichment      scanner-control
       |               |
       v               v
 Ollama worker    Refresh-control
       |            ingestion
       +-------+-------+
               |
               v
          PostgreSQL
               |
               v
        Deterministic routing
               |
               v
              n8n
      orchestration / approval
               |
               v
      Remediation Controller API
               |
               v
        Capability controller
               |
               v
          Ansible Runner
               |
               v
          Managed target
               |
        +------+------+
        |             |
        v             v
     Stage 1       Stage 2
     Ansible       originating
     verification  scanner

AI does not decide the remediation route. Scanner orchestrators determine the
finding class, and PostgreSQL remediation rules deterministically select the
remediation capability and action.

Core Design Principles
Unified findings

Scanner-specific output is normalised into a Unified Security Finding before
entering the main remediation pipeline.

The schema provides a common contract across supported security engines while
retaining source-specific evidence in engine_metadata.

Deterministic remediation

Remediation routing is controlled by PostgreSQL remediation rules.

Ollama enriches findings with risk context but does not determine
finding_class, select a remediation capability or choose an Ansible
playbook.

Independent verification

Successful execution does not automatically mean successful remediation.

The platform implements two verification stages:

Stage 1 — local/Ansible verification that the remediation action was
executed successfully.
Stage 2 — independent verification using the originating security
scanner where supported.

For scanner-backed findings, Stage 2 is authoritative.

Finding Categories

The Unified Security Finding supports four primary categories:

vulnerability
compliance_drift
integrity_drift
rootkit

The platform defines a controlled catalogue of 43 finding classes.

The canonical catalogue is maintained in the database seed and Unified
Security Finding schema.

Scanner Orchestrators
| Security engine               | Status      | Notes                                        |
| ----------------------------- | ----------- | -------------------------------------------- |
| OpenVAS                       | Implemented | Vulnerability scanning                       |
| Nmap / NSE                    | Implemented | Network and service findings                 |
| Nuclei                        | Implemented | Template-driven security findings            |
| Lynis                         | Implemented | Host hardening/compliance findings           |
| Trivy                         | Implemented | Container and dependency findings            |
| Wazuh SCA                     | Implemented | Asynchronous Stage 2 verification supported  |
| Wazuh Vulnerability Detection | Implemented | Runs with local/private Wazuh Indexer access |


Planned
| Security engine                 | Status                           |
| ------------------------------- | -------------------------------- |
| Wazuh File Integrity Monitoring | Orchestrator not yet implemented |
| Wazuh Rootcheck                 | Orchestrator not yet implemented |


Out of scope

Snyk is not used by the current platform implementation.

Seven Remediation Capabilities

The remediation layer is divided into seven stable capabilities:
| Capability          | Purpose                                            |
| ------------------- | -------------------------------------------------- |
| `os_patching`       | Operating-system/package vulnerability remediation |
| `container_image`   | Container image and dependency remediation         |
| `cis_hardening`     | CIS and host-hardening remediation                 |
| `service_config`    | Service and security configuration remediation     |
| `web_application`   | Web/application security remediation               |
| `file_integrity`    | File-integrity restoration/remediation             |
| `security_incident` | Security-event/rootkit response actions            |


Each capability has a controller responsible for invoking the appropriate
Ansible remediation implementation and coordinating verification.

A capability being present does not mean that every possible scanner
integration feeding that capability has already been implemented.

AI Risk Contextualisation

Ollama is used for risk contextualisation.

AI enrichment is deliberately separated from deterministic remediation
routing.

The AI analysis contains:

risk_summary
business_context_impact
confidence_score
analyzed_at

AI output cannot independently select a remediation capability or bypass
approval and verification controls.

Wazuh Asynchronous Verification

Wazuh SCA and Wazuh Vulnerability Detection require a different Stage 2 model
because their authoritative state is produced through asynchronous scanner
refreshes rather than targeted synchronous rescans.

The platform therefore separates:

Unified Security Finding

from:

scanner_refresh_complete

control events.

A refresh completion is not a security finding and is not sent through AI
risk enrichment.

Refresh evidence

The asynchronous verification implementation uses:

scanner refresh completion records;
immutable per-refresh finding receipts;
successful scanner refresh watermarks;
deferred verification jobs;
a deferred Stage 2 reconciler.

A successful refresh watermark is created only after the expected findings for
that refresh have been received.

This prevents a completion event from being interpreted as authoritative before
all corresponding findings have been processed.

Authoritative absence
For an eligible complete scanner refresh:
finding present
    -> Stage 2 FAILED
    -> execution FAILED
    -> finding OPEN

finding absent
    -> Stage 2 PASSED
    -> execution SUCCESS
    -> finding RESOLVED

If fresh authoritative evidence is unavailable, verification remains deferred
rather than assuming success.

See the project documentation for the detailed asynchronous Wazuh verification
model.

Wazuh Integration

Custom Wazuh rules are provided under:

integrations/wazuh/rules/

The current Regis rule chain uses rules 100500 through 100507.

Scanner refresh completion events are routed separately from ordinary findings:

normal security finding
    -> ai-enrichment

scanner_refresh_complete
    -> scanner-control

An example Wazuh integration configuration is provided under:

integrations/wazuh/examples/

Wazuh Vulnerability Deployment

The Wazuh vulnerability orchestrator is intended to run on a trusted system
with local or private access to the Wazuh Indexer.

A typical deployment is:
Wazuh Manager
    |
    +-- wazuh_vuln_orchestrator.py
    |
    +-- Wazuh Indexer
        127.0.0.1:9200

Public Internet exposure of the Wazuh Indexer API is not required.

Credentials must be supplied through local environment/configuration and must
never be committed to the repository.

n8n and Ansible Runner

The reference deployment runs n8n and the Ansible Runner listener from the
same Docker Compose project.

Both attach to the external Docker network:

portal-network

The reference deployment exposes:

n8n             127.0.0.1:5678
Ansible Runner  127.0.0.1:8081

The remediation controller communicates with the Ansible Runner listener over
its local endpoint.

The Compose definition is available under:

deployment/docker/n8n-ansible/

Create the external network before starting the stack if it does not already
exist:

docker network create portal-network

Copy .env.example to a local .env and configure the required values before
starting the services.

Production .env files must not be committed.

Database

PostgreSQL stores:

unified security findings;
finding-class catalogue;
deterministic remediation rules;
remediation executions;
Stage 1 and Stage 2 verification records;
scanner refresh completions;
immutable scanner refresh finding receipts;
scanner refresh watermarks;
deferred verification jobs.

The database installation is defined through version-controlled schema,
seed and migration files rather than a dump of the production database.

Installation order

Apply the database files in the following order:
database/001_schema.sql
database/002_seed_finding_classes.sql
database/003_seed_remediation_rules.sql
database/migrations/004_deferred_verification.sql
database/migrations/005_scanner_refresh_completions.sql
database/migrations/006_scanner_refresh_finding_receipts.sql
database/010_harden_remediation_routing.sql

The schema has been validated by constructing a clean PostgreSQL validation
database from the repository SQL.

Remediation Lifecycle

A typical finding progresses through:
OPEN
  |
  v
IN_REMEDIATION
  |
  +---- remediation/verification failure ----> OPEN
  |
  +---- authoritative verification success --> RESOLVED

Supported finding lifecycle states are:

OPEN
IN_REMEDIATION
RESOLVED
FALSE_POSITIVE

Remediation execution states include:

QUEUED
AWAITING_APPROVAL
RUNNING
STAGE1_PASSED
VERIFYING
SUCCESS
FAILED
CANCELLED

Approval and Automation

Remediation rules define the automation tier and whether human approval is
required.

n8n is intended to provide the workflow layer for:

remediation queue handling;
approval workflows;
human intervention;
parameter rendering;
notifications;
operational workflow integration.

The n8n workflow layer remains an area requiring additional validation before
the platform is considered production-ready.

Repository Structure

ansible/
    playbooks/
    roles/

ansible-runner/
    Dockerfile
    server.py

database/
    migrations/
    001_schema.sql
    002_seed_finding_classes.sql
    003_seed_remediation_rules.sql
    010_harden_remediation_routing.sql

deployment/
    docker/
    systemd/

docs/

integrations/
    wazuh/

remediation/
    controllers/
    shared/
    controller_api.py
    deferred_reconciler.py

scanner_orchestrators/

schema/
    unified_security_finding.schema.json

tests/

verification/

worker/

Configuration and Secrets

Never commit production credentials.

Configuration examples use placeholder values such as:
CHANGE_ME
Sensitive configuration includes:

PostgreSQL passwords;
controller API tokens;
Ansible Runner tokens;
verification gateway tokens;
Wazuh Indexer credentials;
SSH private keys;
scanner API credentials;
n8n secrets.

Environment-specific files should be created locally from the provided
examples.
Security Considerations

This project performs privileged security remediation and should be deployed
only in controlled environments.

Operators should apply least privilege to:

SSH access;
Ansible credentials;
container privileges;
database accounts;
scanner credentials;
API tokens;
firewall policy;
reverse proxies.

Do not expose internal controller, database, Redis, Ansible Runner or scanner
interfaces directly to the Internet unless explicitly required and properly
secured.

See SECURITY.md.

Testing

The repository contains consistency checks and validation assets under:
tests/
Before publishing or deploying changes:

compile all Python source;
run the repository consistency checks;
validate database migrations against a clean PostgreSQL database;
verify the finding-class catalogue remains consistent;
verify deterministic routing;
perform a credential/secret scan;
test affected remediation and verification paths.

The asynchronous Wazuh SCA path has been validated through a live remediation
cycle including Stage 1 remediation, fresh scanner refresh, immutable receipt
collection, watermark promotion and authoritative Stage 2 resolution.

Current Limitations

The project remains pre-production.

Known work before a production v1.0 release includes:

implementing the Wazuh FIM orchestrator;
implementing the Wazuh Rootcheck orchestrator;
validating all material scanner/remediation combinations;
validating the production n8n workflows;
tuning deferred-verification retry/backoff behaviour;
hardening Wazuh Indexer TLS verification;
reviewing SSH key deployment;
reviewing container privileges;
operational monitoring and alerting;
formal installation, upgrade and recovery testing.

See Project Status for the current maturity statement.

Contributing

See CONTRIBUTING.md.

Security vulnerabilities should be reported according to
SECURITY.md, not through public GitHub issues.

Licence

Licensed under the Apache License, Version 2.0.

See LICENSE.
