# Asset Remediation Readiness Administration

## Appsmith Interface — Implementation and Functional Test Record

| Document field | Value |
|---|---|
| Project | Automated Cybersecurity Remediation Platform |
| Organisation | Regis Security Consulting |
| Component | Asset Remediation Readiness Administration |
| Interface | Appsmith |
| Document version | 1.0 |
| Validation date | 8 October 2026 |
| Implementation status | Complete for the documented UI scope |
| Functional testing | Passed for the documented scenarios |
| Production security acceptance | Not established by these tests |

## 1. Purpose and scope

The interface allows administrators to manage the administrative prerequisites for automated remediation on individual assets. It provides operations to authorise and revoke asset management, authorise, replace and revoke execution targets, and view current readiness and administrative history.

The interface does **not** perform asset discovery, scanner execution, finding ingestion, remediation approval or remediation execution. It is an administrative control surface, not a remediation engine.

## 2. Integration architecture

```text
Appsmith UI
    |
    | Bearer-authenticated HTTP requests
    v
Readiness Administration API (Flask / Gunicorn)
    |
    v
Readiness Management service
    |
    v
PostgreSQL (security_portal)
```

| Component | Recorded configuration |
|---|---|
| Appsmith datasource | `Readiness Administration API` |
| API address accessible from Appsmith | `http://172.22.0.1:9100` |
| Backend systemd service | `regis-readiness-admin-api.service` |
| Backend listeners | `127.0.0.1:9100` and `172.22.0.1:9100` |
| Readiness implementation | `readiness_management/service.py` |
| Backend environment file | `/etc/regis-readiness-admin.env` |
| Database | `security_portal` |
| PostgreSQL container | `portal-datastore` |
| Authentication | Bearer token configured in the Appsmith datasource |

No bearer token, database password or other secret is included in this document. The API address is an internal connectivity detail, not a recommendation to expose the service publicly.

## 3. Appsmith widgets

### 3.1 Inputs

| Widget | Appsmith identifier | Purpose |
|---|---|---|
| Asset ID | `inpReadinessAssetId` | Identifies the asset |
| Tenant Code | `inpReadinessTenantCode` | Tenant context |
| Administrative Reason | `inpReadinessReason` | Reason for state-changing operations |
| Execution Target | `inpExecutionTarget` | Target to authorise or use as a replacement |

The reason is required for administrative changes. The execution-target input is used when authorising or replacing a target; it is not required for revocation.

### 3.2 Actions and display

| UI control | Appsmith identifier | Purpose |
|---|---|---|
| Check Readiness | `btnCheckReadiness` | Refreshes readiness and history |
| Authorise Asset Management | `btnAuthoriseAssetManagement` | Authorises management |
| Revoke Asset Management | `btnRevokeAssetManagement` | Revokes management |
| Authorise Execution Target | `btnAuthoriseExecutionTarget` | Authorises an execution target |
| Revoke Execution Target | `btnRevokeExecutionTarget` | Revokes an execution target |
| Replace Execution Target | `btnReplaceExecutionTarget` | Replaces an active execution target |
| Audit History Table | `tblReadinessHistory` | Displays administrative history |

Readiness display widgets use fields from `get_asset_readiness.data.readiness`, including asset identity, inventory and lifecycle state, management authorisation, execution-target authorisation, active target and overall remediation readiness.

The audit history table's data binding is:

```javascript
{{ get_asset_readiness_history.data?.history || [] }}
```

## 4. Read-only API queries

The endpoints below are relative to the Appsmith datasource base URL.

### `get_asset_readiness`

- **Method:** `GET`
- **Path:** `/admin/assets/{{inpReadinessAssetId.text}}/readiness`
- **Query parameter:** `tenant_code={{inpReadinessTenantCode.text.trim()}}`

### `get_asset_readiness_history`

- **Method:** `GET`
- **Path:** `/admin/assets/{{inpReadinessAssetId.text}}/readiness/history`
- **Query parameter:** `tenant_code={{inpReadinessTenantCode.text.trim()}}`

`btnCheckReadiness` runs both queries and provides success/error feedback.

## 5. State-changing API queries

All five administrative mutations use `POST`.

| Appsmith query | Relative endpoint |
|---|---|
| `authorise_asset_management` | `/admin/assets/{{inpReadinessAssetId.text}}/management/authorise` |
| `revoke_asset_management` | `/admin/assets/{{inpReadinessAssetId.text}}/management/revoke` |
| `authorise_execution_target` | `/admin/assets/{{inpReadinessAssetId.text}}/execution-target/authorise` |
| `revoke_execution_target` | `/admin/assets/{{inpReadinessAssetId.text}}/execution-target/revoke` |
| `replace_execution_target` | `/admin/assets/{{inpReadinessAssetId.text}}/execution-target/replace` |

### 5.1 Management authorisation/revocation and target revocation payload

```javascript
{{
  {
    tenant_code: inpReadinessTenantCode.text.trim(),
    reason: inpReadinessReason.text.trim()
  }
}}
```

### 5.2 Target authorisation/replacement payload

```javascript
{{
  {
    tenant_code: inpReadinessTenantCode.text.trim(),
    execution_target: inpExecutionTarget.text.trim(),
    reason: inpReadinessReason.text.trim()
  }
}}
```

The API derives administrative actor identity from its authenticated context rather than trusting a client-provided `performed_by` field.

## 6. Workflow and UI controls

### 6.1 Authorise asset management

The operation authorises administrative management for an eligible active asset. The tested result was an asset in the `MANAGED` inventory state with an authorisation timestamp and an audit record.

### 6.2 Revoke asset management

The interface prevents revocation while an execution target remains authorised. The backend must independently enforce its own preconditions. The test confirmed transition to `UNMANAGED`, followed by successful reauthorisation to `MANAGED`.

### 6.3 Authorise execution target

The Appsmith button is disabled unless the retrieved asset and tenant match the inputs, the asset is `MANAGED` and `ACTIVE`, management is authorised, no active execution target exists, and the required target and reason are supplied.

### 6.4 Replace execution target

The Appsmith button is disabled unless the retrieved asset and tenant match the inputs, the asset is `MANAGED` and `ACTIVE`, management is authorised, an active execution target exists, and a nonempty, different replacement target and reason are supplied.

The replacement test confirmed that the new target became active and the administrative history recorded the replacement. The service is responsible for enforcing the change atomically.

The configured button handler was:

```javascript
{{
  replace_execution_target.run(
    () => {
      get_asset_readiness.run();
      get_asset_readiness_history.run();
      resetWidget("inpExecutionTarget", true);
      resetWidget("inpReadinessReason", true);
      showAlert("Execution target replaced successfully", "success");
    },
    () => {
      showAlert(
        "Execution target replacement failed. Check the current asset state, replacement target and administrative reason.",
        "error"
      );
    }
  )
}}
```

### 6.5 Revoke execution target

The interface requires an existing authorised target and a nonempty reason. Following success, the UI refreshes readiness and history and clears the administrative reason. The test confirmed the target was removed, remediation readiness became `NO`, the revocation was audited and the revoke button became disabled.

### 6.6 General post-operation behaviour

Successful mutations refresh the readiness and audit-history queries, clear relevant form inputs and show a success notification. Failures show an error notification. Frontend validation is a usability measure and must never substitute for backend enforcement.

## 7. Readiness interpretation

The tested states included:

| Asset management authorised | Execution target authorised | Observed remediation ready |
|---|---|---|
| YES | NO | NO |
| YES | YES | YES |

These are observations from the controlled test, not a complete specification of every readiness rule. `Remediation Ready: YES` is an administrative eligibility indication; it does not itself authorise a specific remediation execution or prove target safety and reachability.

## 8. Audit history

`get_asset_readiness_history` populates `tblReadinessHistory`. During the tests, administrative history was observed for management authorisation/revocation and execution-target authorisation, replacement and revocation. The final revocation event was `EXECUTION_TARGET_REVOKED`.

The tests did not independently establish audit retention, tamper resistance or completeness under concurrency or failure conditions.

## 9. Controlled functional test

### 9.1 Test asset

| Property | Value |
|---|---|
| Asset ID | `2` |
| Tenant | `READINESS-UI-TEST` |
| Asset type | `APPLICATION` |
| Canonical name | `https://readiness-ui.test` |
| Original temporary execution target | `readiness-ui.invalid` |
| Replacement temporary execution target | `replacement-readiness-ui.invalid` |

The `.invalid` top-level domain is reserved for intentionally invalid names. This reduced the chance of targeting a real host, but temporary execution-target authorisation still created a remediation-ready administrative state. No scans or remediations were intentionally initiated during these UI tests.

Earlier database checks found no unified findings, scan executions or scan policies for the test asset/tenant at the time checked. These checks do not guarantee that no later activity could occur.

### 9.2 Test results

| Test | Result |
|---|---|
| Retrieve current readiness | PASS |
| Retrieve administrative history | PASS |
| Authorise asset management | PASS |
| Revoke asset management | PASS |
| Reauthorise asset management | PASS |
| Authorise execution target | PASS |
| Observe active target and remediation-ready state | PASS |
| Revoke execution target | PASS |
| Replacement button disabled without active target | PASS |
| Replace execution target with different target | PASS |
| Observe replacement audit event | PASS |
| Revoke replacement target | PASS |
| Observe `EXECUTION_TARGET_REVOKED` audit event | PASS |
| Observe `Remediation Ready: NO` after revocation | PASS |
| Observe revoke button disabled after revocation | PASS |
| Verify final management state in PostgreSQL | PASS |

These results are based on the reported Appsmith tests and the supplied final database query output. They are functional tests, not a penetration test or comprehensive production acceptance assessment.

## 10. Final verified state

After the temporary replacement target was revoked, Appsmith displayed:

| Property | Final observed state |
|---|---|
| Asset Management Authorised | YES |
| Execution Target Authorised | NO |
| Active Execution Target | None |
| Remediation Ready | NO |

The following independent SQL query was executed:

```sql
SELECT
    asset_id,
    tenant_code,
    inventory_state,
    lifecycle_status,
    management_authorised_at,
    management_revoked_at
FROM assets
WHERE asset_id = 2
  AND tenant_code = 'READINESS-UI-TEST';
```

The returned row was:

| Column | Verified value |
|---|---|
| `asset_id` | `2` |
| `tenant_code` | `READINESS-UI-TEST` |
| `inventory_state` | `MANAGED` |
| `lifecycle_status` | `ACTIVE` |
| `management_authorised_at` | `2026-10-08 12:25:41.798409+00` |
| `management_revoked_at` | `NULL` |

**Evidence distinction:** This SQL query independently verifies the management-state fields only. The final execution-target and remediation-readiness states were verified through the Appsmith interface, not through this particular SQL query.

## 11. Security and operational considerations

Before production acceptance, separately validate:

1. Server-side enforcement of all administrative preconditions, independent of button states.
2. Tenant isolation and administrator authorisation at the API boundary.
3. Bearer credential protection and rotation.
4. Audit actor attribution and audit-record integrity.
5. Execution-target validation and safe handling of scanner/remediation destinations.
6. Revalidation of readiness and target authorisation at execution time.
7. Transactional behaviour and race handling for simultaneous administrative changes.
8. Error handling, service recovery and operational observability.
9. Appropriate audit retention and access controls.

These are acceptance requirements, not claims that every control has been independently tested.

## 12. Completion statement

The documented Appsmith interface and all five administrative operations were implemented and passed the reported functional tests. The controlled test asset was returned to a state with management authorisation active, no authorised execution target and `Remediation Ready: NO`.

- **UI implementation:** COMPLETE for the documented scope
- **Planned functional validation:** PASSED
- **Production security acceptance:** NOT ESTABLISHED BY THESE TESTS

---

*End of document — Version 1.0*
