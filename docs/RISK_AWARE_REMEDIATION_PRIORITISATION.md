# Risk-Aware Remediation Prioritisation

## 1. Purpose

Risk-Aware Remediation Prioritisation orders findings that already have
a deterministic remediation route.

It answers:

> Given the findings that are eligible for remediation, which finding
> should be handled first?

This capability is separate from remediation routing.

Remediation routing determines **which remediation rule applies**.

Risk-aware prioritisation determines **which already-routed finding
should be handled first**.

It uses the current deterministic contextual risk assessment without
changing scanner evidence, finding classification, remediation rule
selection, approval policy, or execution semantics.

---

## 2. Scope of V1

Risk-Aware Remediation Prioritisation V1 provides:

- a read-only `prioritised_remediation_queue` database view;
- prioritisation after deterministic remediation routing;
- use of the current `contextual_risk_score`;
- support for scored `ASSESSED` and `PARTIAL` assessments;
- explicit handling of `UNSCORABLE` findings;
- continued visibility of findings without a current risk assessment;
- deterministic tie-breaking;
- tenant-safe joining of findings and risk assessments;
- regression coverage; and
- release-smoke database invariant coverage.

V1 does not:

- change scanner normalisation;
- change scanner/native severity;
- change `finding_class`;
- change finding identity, recurrence, or lifecycle semantics;
- change remediation-rule selection;
- reinterpret `remediation_rules.priority`;
- change remediation capability, playbook, or action;
- change `automation_tier` or `approval_required`;
- implement SLA policy;
- use `tenant_service_tier` for prioritisation;
- use AI as an authoritative prioritisation input;
- use threat intelligence;
- use recurrence or remediation-attempt counts for ranking;
- persist a separate priority value on the finding;
- automatically dispatch remediation; or
- change controller or verification behaviour.

---

## 3. Architectural Position

```text
Scanner
  |
  v
Scanner Orchestrator
  |
  | normalisation + finding_class
  v
Unified Security Finding
  |
  v
Asset Resolution / Context
  |
  v
Risk Contextualisation
  |
  v
finding_risk_assessments
  |
  v
Deterministic Remediation Routing
  |
  v
open_remediation_queue
  |
  v
Risk-Aware Remediation Prioritisation
  |
  v
prioritised_remediation_queue
  |
  v
Workflow / Remediation Orchestration
  |
  v
Controller / Approval
  |
  v
Ansible
  |
  v
Stage 1 Verification
  |
  v
Stage 2 Verification
```

The two queue contracts have different responsibilities:

```text
open_remediation_queue
    = WHICH remediation rule applies?

prioritised_remediation_queue
    = WHICH already-routed finding should be handled first?
```

## 4. Database Contract

Migration:

```text
database/migrations/011_risk_aware_remediation_prioritisation.sql
```

creates:

```text
prioritised_remediation_queue
```

The view is derived from `open_remediation_queue` and joins the current
risk assessment using both:

```text
finding_id
tenant_code
```

It exposes the routed finding and adds:

```text
assessment_status
contextual_risk_score
contextual_risk_level
assessment_model
assessed_at
has_contextual_risk
```

`open_remediation_queue` remains the authoritative remediation-routing
contract.

## 5. Usable Contextual Risk

`has_contextual_risk` is true when:

```text
assessment_status IN ('ASSESSED', 'PARTIAL')
AND contextual_risk_score IS NOT NULL
```

A scored `PARTIAL` assessment participates in prioritisation according
to its actual contextual risk score.

`PARTIAL` is not automatically ranked below `ASSESSED`.

An `UNSCORABLE` finding remains visible but has:

```text
has_contextual_risk = false
contextual_risk_score = null
```

A routed finding without a current risk assessment also remains visible
with null risk fields and:

```text
has_contextual_risk = false
```

The platform does not fabricate contextual risk for either case.

## 6. Ordering Contract

The database view itself does not guarantee row order.

Consumers must explicitly use:

```sql
ORDER BY
    has_contextual_risk DESC,
    contextual_risk_score DESC NULLS LAST,
    detected_at ASC,
    finding_id ASC;
```

The ordering means:

1. findings with usable contextual risk come first;
2. higher contextual risk comes first;
3. equal scores are ordered by older `detected_at`;
4. `finding_id` is the final deterministic tie-breaker.

## 7. Scanner Severity Is Not a Fallback

The prioritisation layer deliberately does not use:

```sql
COALESCE(contextual_risk_score, severity_score)
```

Scanner severity and contextual risk represent different concepts.

`severity_score` is scanner evidence.

`contextual_risk_score` is the platform-derived assessment of the
finding's significance in organisational context.

An unassessed or unscorable finding must therefore remain recognisably
unscored.

## 8. Remediation Rule Priority Is Separate

`remediation_rules.priority` is routing precedence between matching
remediation rules.

It is not finding priority.

The distinction is:

```text
remediation_rules.priority
    -> which matching remediation rule wins

contextual_risk_score
    -> which already-routed finding is handled first
```

Risk-Aware Remediation Prioritisation must not alter this boundary.

## 9. Approval and Execution

Prioritisation does not grant permission to execute remediation.

Existing authoritative fields such as:

```text
automation_tier
approval_required
```

continue to control execution policy.

A finding may therefore be first in the prioritised queue and still
require approval before execution.

The controller remains authoritative for rule validation, execution
state, approval enforcement, and remediation initiation.

The existing Stage 1 and Stage 2 verification model is unchanged.

## 10. Dynamic Reprioritisation

Priority is derived rather than persisted.

When asset context changes and risk reassessment updates
`finding_risk_assessments`, the next query of
`prioritised_remediation_queue` observes the current risk score.

No second authoritative priority value needs to be synchronised.

---

## 11. Validation

Regression coverage is provided by:

```text
tests/test_risk_aware_remediation_prioritisation.py
```

It verifies:

- higher contextual risk is ordered first;
- scored `PARTIAL` assessments remain prioritised;
- equal scores use deterministic age ordering;
- `UNSCORABLE` findings remain visible;
- findings without risk assessments remain visible; and
- contextual risk is never fabricated.

The release smoke test also verifies that a clean database reconstruction
contains `prioritised_remediation_queue`.

## 12. Consumer Contract

A remediation workflow should consume:

```text
prioritised_remediation_queue
```

and explicitly apply:

```sql
ORDER BY
    has_contextual_risk DESC,
    contextual_risk_score DESC NULLS LAST,
    detected_at ASC,
    finding_id ASC;
```

The consumer must not reinterpret contextual risk as remediation-routing
authority.

n8n implementation, concurrency policy, SLA calculation, automatic
dispatch, and future approval-policy changes are outside the scope of
Risk-Aware Remediation Prioritisation V1.
