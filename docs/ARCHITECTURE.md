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
