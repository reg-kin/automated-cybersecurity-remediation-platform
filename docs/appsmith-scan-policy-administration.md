# Scan Policy Administration
## Appsmith Interface — Implementation and Functional Test Record

**Project:** Automated Cybersecurity Remediation Platform  
**Organisation:** Regis Security Consulting  
**Component:** Scan Policy Administration  
**Interface:** Appsmith Community Edition  
**Document version:** 1.1  
**Document date:** 8 October 2026  
**Implementation status:** Complete  
**Functional test status:** Passed (user-confirmed)  
**Production security acceptance:** Not established by these functional tests

## 1. Purpose and scope

The Scan Policy Administration interface provides an administrative control surface for configuring and managing scan policies associated with assets and tenants. It supports policy listing, history inspection, creation, modification, enabling and disabling.

It does **not** itself perform scanning, coordinate execution leases, ingest findings or remediate vulnerabilities. Policy deletion is outside the stated V1 scope.

## 2. Architecture

**Appsmith → Scan Policy Administration API → backend policy-management logic → PostgreSQL**

| Component | Recorded implementation |
|---|---|
| Frontend | Appsmith Community Edition |
| Container image | `appsmith/appsmith-ce:release` |
| Appsmith deployment directory | `/opt/regis-security/appsmith/stacks` |
| Appsmith host binding | `127.0.0.1:8082` |
| Docker network | `portal-network` |
| Administration API address | `http://172.22.0.1:9102` |
| Authentication | Bearer token |
| Database | PostgreSQL, `security_portal` |
| Database container | `portal-datastore` |

Appsmith uses the administration API rather than direct database writes. Credentials and bearer tokens are intentionally excluded from this record.

## 3. Implemented Appsmith queries

The completed interface was confirmed to contain the following queries:

| Query | Function | Functional test |
|---|---|---|
| `get_scan_policies` | Retrieve policies | PASS |
| `get_scan_policy_history` | Retrieve selected policy's administrative history | PASS |
| `create_scan_policy` | Create policy | PASS |
| `update_scan_policy` | Update policy | PASS — user-confirmed |
| `enable_scan_policy` | Enable policy | PASS — user-confirmed |
| `disable_scan_policy` | Disable policy | PASS — user-confirmed |

The existence of all six queries was confirmed from the Appsmith editor screenshot on 8 October 2026. Successful update, enable and disable operations were subsequently confirmed by the user. Exact request bodies and endpoint paths for those three operations should be captured from the deployed query definitions before treating this document as a configuration-rebuild specification.

## 4. Read-only API operations

### 4.1 List scan policies

**Query:** `get_scan_policies`  
**HTTP method:** `GET`  
**Endpoint:** `/admin/scan-policies`  
**Recorded tenant context:** `tenant_code=Customer1`

The query returns a `scan_policies` collection. The policy table (`Table1`) was configured with:

```javascript
{{ get_scan_policies.data.scan_policies }}
```

The 8 October 2026 screenshot shows a successful response containing scan policy records.

### 4.2 Retrieve administrative history

**Query:** `get_scan_policy_history`  
**HTTP method:** `GET`  
**Endpoint pattern:** `/admin/scan-policies/{scan_policy_id}/history`  
**Tenant context:** `tenant_code=Customer1` in the previously tested configuration

The history table (`Table2`) was configured with:

```javascript
{{ get_scan_policy_history.data.history }}
```

The policy table's row-selection action invokes:

```javascript
{{ get_scan_policy_history.run() }}
```

This selection-to-history workflow was tested successfully.

## 5. Create policy operation

**Query:** `create_scan_policy`  
**HTTP method:** `POST`  
**Endpoint:** `/admin/scan-policies`

The create-policy form was recorded with the following widgets:

| Widget ID | Purpose |
|---|---|
| `inpTenantCode` | Tenant code |
| `inpAssetId` | Asset ID |
| `selScannerType` | Scanner selection |
| `selServiceTier` | Service tier |
| `selScheduleType` | Schedule type |
| `inpScheduleExpression` | Schedule expression |
| `inpScheduleTimezone` | Timezone |
| `txtScannerParameters` | Scanner parameters JSON |
| `inpProfileName` | Profile name |
| `txtReason` | Administrative reason |
| `swEnabled` | Initial enabled state |

The form submission control was identified during implementation as `Button1`.

Required fields established during the earlier API integration included `tenant_code`, `asset_id`, `scanner_type`, `service_tier` and `reason`. Additional optional fields are subject to backend validation.

### Example of a successfully tested configuration

```json
{
  "tenant_code": "Customer1",
  "asset_id": 1,
  "scanner_type": "lynis",
  "service_tier": "STANDARD",
  "profile_name": "appsmith-create-test-6",
  "scanner_parameters": {},
  "schedule_type": "CRON",
  "schedule_expression": "0 3 * * *",
  "schedule_timezone": "Europe/London",
  "enabled": true,
  "reason": "Administrative scan policy creation test"
}
```

**Note:** The example reason is illustrative, not a verified verbatim value from the original request.

The recorded successful response established:

| Field | Value |
|---|---|
| Scan policy ID | `7` |
| Tenant | `Customer1` |
| Asset ID | `1` |
| Scanner | `lynis` |
| Service tier | `STANDARD` |
| Profile | `appsmith-create-test-6` |
| Schedule | `CRON` — `0 3 * * *` |
| Timezone | `Europe/London` |
| Enabled | `true` |
| Scanner parameters | `{}` |
| Audit ID | `9` |
| `next_run_at` | `NULL` |

**Result: PASS.** Creation and audit recording were verified. A `NULL` next-run timestamp does not demonstrate that the scheduler subsequently dispatched a scan.

## 6. Update, enable and disable

The completed Appsmith interface contains three distinct state-changing queries:

- `update_scan_policy` — modify an existing policy configuration.
- `enable_scan_policy` — enable an existing policy.
- `disable_scan_policy` — disable an existing policy.

**Functional test result: PASS for all three operations**, as confirmed by the user on 8 October 2026.

The exact HTTP methods, endpoint paths, request payloads, widget event handlers and audit event names for these three queries have not been independently transcribed from the deployed query definitions in this documentation session. They must not be inferred from query names. Export or inspect the deployed Appsmith configuration to add those details if a full rebuild/runbook is required.

## 7. Scheduling and policy state

The interface supports schedule type, expression, timezone and enabled state. A successfully created test policy used CRON `0 3 * * *` with `Europe/London`, conventionally indicating 03:00 daily under standard five-field CRON interpretation.

An enabled policy is an administrative configuration state; it does not by itself prove scan dispatch, successful execution or ingestion of results. Scanner coordination, lease management and actual execution remain separate platform capabilities.

## 8. Validation and security boundaries

The Appsmith form provides input validation and administrative controls, while the backend must enforce all authoritative requirements, including:

- Authentication and administrative authorisation.
- Tenant and asset access boundaries.
- Supported scanner types, service tiers and parameter formats.
- Schedule expression and timezone validity.
- Duplicate/conflicting policy handling.
- Safe state transitions and transactional persistence.
- Administrative actor attribution and audit logging.

Earlier integration work observed `401 Unauthorized`, `400 Bad Request` and `409 Conflict` responses, followed by successful `201 Created` policy creation after correcting request and authentication issues. Those observations are not a substitute for exhaustive negative-path or security testing.

## 9. Administrative history

The history view displays policy-related administrative events for the selected policy. Its selection-driven retrieval was tested. A creation response included audit ID `9`, providing evidence that an administrative audit record was created.

Administrative audit history is distinct from scanner execution history. Audit retention, integrity and full coverage have not been independently verified in this functional UI record.

## 10. Functional test matrix

| Test case | Result | Evidence basis |
|---|---|---|
| Retrieve scan policies | PASS | Previous Appsmith test; successful screenshot response |
| Populate policy table | PASS | Previous Appsmith test |
| Select policy and retrieve history | PASS | Previous Appsmith test |
| Display administrative history | PASS | Previous Appsmith test |
| Create a CRON-based policy | PASS | Recorded successful creation |
| Persist scanner parameters and enabled state | PASS | Recorded creation response |
| Create administrative audit record | PASS | Recorded audit ID |
| Update an existing policy | PASS | User-confirmed |
| Enable an existing policy | PASS | User-confirmed |
| Disable an existing policy | PASS | User-confirmed |
| Observe backend validation/conflict responses | OBSERVED | Earlier API integration |
| Verify scheduled scan dispatch | NOT TESTED IN THIS UI RECORD | Separate scan-coordination concern |
| Production security acceptance | NOT ESTABLISHED | Requires separate assessment |

## 11. Operational safeguards

1. Keep bearer credentials out of Appsmith exports, screenshots, source control and documentation.
2. Enforce tenant-scoped authorisation on the backend, not only in Appsmith query parameters.
3. Validate scanner-specific parameters and schedule expressions server-side.
4. Maintain immutable or appropriately protected administrative audit records.
5. Revalidate policy eligibility at scan-dispatch time.
6. Use dedicated test policies for future functional tests; enabling policies on real assets may initiate operational scanning.
7. Treat UI functional success separately from production security acceptance and scheduler/execution validation.

## 12. Completion statement

**Scan Policy Administration is functionally complete for the six verified query workflows:** listing, history retrieval, creation, update, enable and disable. All three state-changing operations beyond creation have been explicitly confirmed as tested successfully by the user.

The completed interface provides policy administration; it does not establish successful scheduled scan execution or comprehensive production security acceptance.

**Implementation status: COMPLETE**  
**Functional test status: PASSED**  
**Production security acceptance: NOT ESTABLISHED**

---

**End of document — Version 1.1**
