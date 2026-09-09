# Frozen architecture

## Controller machine

Runs:
- n8n
- controller API on `127.0.0.1:9000`
- seven controller modules behind that API
- Ansible Runner host endpoint on `127.0.0.1:8081`
  (mapped to container port `8080`)

Communication:

`n8n -> :9000/remediate -> controller -> :8081/run`

## Scanner/orchestrator machine

Runs:
- scanner orchestrators
- verification gateway on port 8090

Communication:

`controller -> scanner:8090/verify -> verification dispatcher -> scanner orchestrator`

## Stage 1

Ansible performs the requested change and its playbook emits `regis_stage1_verification`.
The controller records this in `remediation_verifications` with `stage=1`.

## Stage 2

The controller sends the original scanner identity and finding key to the verification gateway.
The original scanner orchestrator runs in verification mode.
Only `verification_status=PASSED` together with `present=false`
results in `RESOLVED`.

## Safety model

There is no separate safety-rule table.
`remediation_rules` contains:
- `automation_tier`
- `approval_required`
- `required_parameters`
- `enabled`

Rules with `approval_required=true` remain behind the approval/human-intervention
gate. TIER_3 remediation rules must require approval.

## Risk-Aware Remediation Prioritisation

Contextual risk and remediation routing remain separate concerns.

Deterministic remediation routing first selects exactly one applicable
remediation rule and exposes the result through `open_remediation_queue`.

Risk-Aware Remediation Prioritisation then orders those already-routed
findings through `prioritised_remediation_queue`.

```text
finding_risk_assessments
        |
        v
open_remediation_queue
        |
        v
prioritised_remediation_queue
        |
        v
n8n / remediation orchestration
        |
        v
controller / approval
```

The distinction is:

```text
open_remediation_queue
    = which remediation rule applies

prioritised_remediation_queue
    = which already-routed finding should be handled first
```

The prioritisation order is:

```sql
ORDER BY
    has_contextual_risk DESC,
    contextual_risk_score DESC NULLS LAST,
    detected_at ASC,
    finding_id ASC;
```

`remediation_rules.priority` remains routing precedence between matching
rules and is not used as finding priority.

Contextual risk does not alter capability, playbook, remediation action,
automation tier, approval requirements, controller behaviour, or
two-stage verification.
