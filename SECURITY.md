# Security Policy

## Reporting Security Issues

Please do not report security vulnerabilities through public GitHub issues.

If you discover a vulnerability affecting Regis Security Remediation Platform,
report it privately to the project maintainer.

Do not include production credentials, customer information, API tokens,
private keys, scanner credentials, or other sensitive data in a public issue.

## Supported Versions

The project is currently under active pre-production development.

Security fixes are provided for the latest published version.

## Credential Management

The repository must never contain:

- production passwords;
- API tokens;
- private SSH keys;
- scanner credentials;
- PostgreSQL credentials;
- Wazuh Indexer credentials;
- n8n secrets;
- customer-specific configuration.

Use the provided `.env.example` files and configure secrets locally.

## Deployment Security

The reference deployment binds internal services such as the remediation
controller, Ansible Runner and n8n to loopback interfaces where appropriate.

Operators are responsible for securing:

- reverse proxies;
- SSH access;
- firewall policy;
- TLS certificates;
- PostgreSQL;
- Redis;
- scanner infrastructure;
- Ansible credentials;
- Wazuh Indexer access.

The Wazuh vulnerability orchestrator is intended to run from a trusted host
with local or private access to the Wazuh Indexer. Public exposure of the
Indexer API is not required.
