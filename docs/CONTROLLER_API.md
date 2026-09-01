# Controller API

## Health

`GET /health`

## Remediate

`POST /remediate`

Example:

```json
{
  "finding_id": 42,
  "rule_id": 7,
  "tenant_code": "CUSTOMER_A",
  "target_host": "10.20.30.15",
  "engine_source": "wazuh",
  "finding_class": "package_vulnerability",
  "finding_key": "CVE-2023-4863",
  "finding_title": "Vulnerable libwebp package",
  "capability": "os_patching",
  "playbook_name": "os_patching.yml",
  "remediation_action": "patch_package",
  "automation_tier": "TIER_1",
  "approval_required": false,
  "engine_metadata": {
    "package_name": "libwebp7",
    "fixed_version": "1.3.2"
  },
  "execution_parameters": {
    "package_name": "libwebp7",
    "fixed_version": "1.3.2"
  }
}
```
