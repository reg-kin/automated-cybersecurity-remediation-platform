# Risk Contextualisation

## 1. Purpose

Risk Contextualisation is the platform capability that converts a
scanner's technical severity into a separate, deterministic assessment
of organisational risk.

A vulnerability scanner can establish that a finding is technically
severe, but technical severity alone does not establish how important
that finding is to a particular organisation. The same vulnerability may
exist on an isolated development host and on an Internet-facing
production system supporting a critical business service. The technical
vulnerability may be identical; the organisational risk is not.

Risk Contextualisation V1 therefore combines:

-   scanner/native technical severity;
-   curated asset criticality and security requirements;
-   data classification;
-   asset environment; and
-   network/internet exposure.

The result is a platform-derived `contextual_risk_score` on a
0.00--10.00 scale and a corresponding `LOW`, `MEDIUM`, `HIGH`, or
`CRITICAL` risk level.

The capability is deliberately deterministic and auditable. It does not
ask an AI model to decide authoritative risk, and it does not overwrite
the scanner's severity.

------------------------------------------------------------------------

## 2. Scope of V1

Risk Contextualisation V1 provides:

-   a deterministic risk calculation model;
-   explicit assessment states (`ASSESSED`, `PARTIAL`, and
    `UNSCORABLE`);
-   persistence of one current risk assessment per finding;
-   preservation of the factors and asset-context snapshot used in the
    assessment;
-   model version identification through `CONTEXTUAL_RISK_V1`;
-   integration into normal finding ingestion;
-   reassessment of existing findings when curated asset context
    changes;
-   tenant-scoped database relationships and reassessment;
-   database integrity constraints; and
-   regression and release-smoke coverage.

V1 deliberately does **not**:

-   replace scanner/native severity;
-   change scanner-specific normalisation;
-   change finding classification;
-   change finding identity, recurrence, or lifecycle semantics;
-   add contextual risk to the Unified Security Finding ingress
    contract;
-   use AI as authoritative risk state;
-   use contextual risk to select remediation rules, playbooks, approval
    policy, or execution parameters;
-   keep a historical ledger of every prior risk assessment; or
-   incorporate threat intelligence into the deterministic score.

These boundaries are important. V1 establishes a reliable
risk-assessment foundation before risk is allowed to influence automated
remediation decisions.

------------------------------------------------------------------------

## 3. Architectural Position

Risk Contextualisation is downstream of finding normalisation and asset
resolution.

``` text
Scanner-specific evidence
        |
        v
Scanner Orchestrator
        |
        v
Unified Security Finding
        |
        +----------------------> Asset Resolution
        |                              |
        |                              v
        |                        Asset Inventory
        |                              |
        |                        Curated Asset Context
        |                              |
        +------------------------------+
                       |
                       v
             Risk Contextualisation
                       |
                       v
          Current Risk Assessment
                       |
                       v
          Future Decision-Making
```

The responsibilities remain separated:

**Scanner orchestrators** understand scanner-native data, normalise
findings, and determine `finding_class`.

**Asset Management** establishes canonical asset identity.

**Asset Context Management** stores curated organisational/security
context for assets.

**Risk Contextualisation** combines technical severity with curated
context using a deterministic model.

**AI enrichment** provides advisory narrative context only.

**Remediation routing** remains deterministic and separate from
contextual risk in V1.

------------------------------------------------------------------------

## 4. Technical Severity Versus Contextual Risk

The platform maintains two different concepts.

### 4.1 Scanner/native severity

`severity_score` and `severity_level` are evidence supplied or derived
from the scanner integration.

Examples include:

``` text
severity_score = 8.1
severity_level = HIGH
```

This evidence belongs to the finding and is not overwritten by Risk
Contextualisation.

### 4.2 Contextual risk

`contextual_risk_score` and `contextual_risk_level` are platform-derived
values.

They answer a different question:

> Given the technical severity of this finding and what the platform
> knows about the affected asset, how significant is the finding in this
> organisational context?

For example:

``` text
Scanner severity score:     8.10
Technical component:        4.86
Organisational component:   3.00
Exposure component:         1.00
Contextual risk score:      8.86
Contextual risk level:      HIGH
```

The scanner severity remains 8.10. The platform does not replace it with
8.86.

This separation preserves provenance and makes the calculation
explainable.

------------------------------------------------------------------------

## 5. Assessment Model

The model identifier is:

``` text
CONTEXTUAL_RISK_V1
```

The maximum contextual risk score is 10.00.

The model allocates the score as follows:

  Component                 Maximum contribution   Percentage of total
  ----------------------- ---------------------- ---------------------
  Technical severity                        6.00                   60%
  Organisational impact                     3.00                   30%
  Exposure                                  1.00                   10%
  **Total**                            **10.00**              **100%**

Conceptually:

``` text
contextual_risk_score
    = technical_component
    + organisational_component
    + exposure_component
```

The result is bounded to 0--10 and rounded to two decimal places using
`ROUND_HALF_UP`.

------------------------------------------------------------------------

## 6. Technical Severity Component

### 6.1 Numeric severity score

When `severity_score` is present, it takes precedence over
`severity_level`.

The technical component is:

``` text
technical_component = (severity_score / 10) * 6
```

For a scanner score of 8.1:

``` text
(8.1 / 10) * 6 = 4.86
```

A numeric severity score must be finite and between 0 and 10 inclusive.
Invalid values are rejected.

### 6.2 Severity-level fallback

If the numeric score is absent but a valid severity level exists, the
model uses an internal effective severity:

  Severity level     Effective severity
  ---------------- --------------------
  LOW                               2.5
  MEDIUM                            5.5
  HIGH                              8.0
  CRITICAL                          9.5

For example:

``` text
severity_score = null
severity_level = HIGH

effective severity = 8.0
technical component = (8.0 / 10) * 6 = 4.8
```

The fallback value is used only for calculation. It is **not** written
back as the finding's `base_severity_score`. This prevents the platform
from fabricating scanner evidence.

The assessment records the source:

``` text
technical_severity_source = severity_score
```

or:

``` text
technical_severity_source = severity_level_fallback
```

### 6.3 No usable technical severity

If both `severity_score` and `severity_level` are absent, the finding is
`UNSCORABLE`.

Organisational context alone cannot produce an authoritative risk score
in V1.

------------------------------------------------------------------------

## 7. Organisational Impact Component

Organisational impact contributes up to 3.00 points.

It uses:

-   asset criticality;
-   data classification;
-   confidentiality requirement;
-   integrity requirement; and
-   availability requirement.

### 7.1 Criticality and CIA factors

  Value        Factor
  ---------- --------
  UNKNOWN        0.00
  LOW            0.25
  MEDIUM         0.50
  HIGH           0.75
  CRITICAL       1.00

The same factor scale is used for:

-   `criticality`;
-   `confidentiality_requirement`;
-   `integrity_requirement`; and
-   `availability_requirement`.

### 7.2 Data-classification factors

  Classification     Factor
  ---------------- --------
  UNKNOWN              0.00
  PUBLIC               0.25
  INTERNAL             0.50
  CONFIDENTIAL         0.75
  RESTRICTED           1.00

### 7.3 Impact weighting

The combined impact factor is:

``` text
impact_factor =
    0.40     * criticality_factor
  + 0.20     * data_classification_factor
  + 0.133333 * confidentiality_requirement_factor
  + 0.133333 * integrity_requirement_factor
  + 0.133334 * availability_requirement_factor
```

The organisational component is:

``` text
organisational_component = impact_factor * 3
```

The slightly asymmetric final CIA coefficient (`0.133334`) is
intentional: together, the coefficients sum exactly to 1.00 at the
configured decimal precision.

### 7.4 Maximum-impact example

If all impact inputs have a factor of 1.00:

``` text
impact_factor =
    0.40
  + 0.20
  + 0.133333
  + 0.133333
  + 0.133334
  = 1.00

organisational_component = 1.00 * 3 = 3.00
```

------------------------------------------------------------------------

## 8. Exposure Component

Exposure contributes up to 1.00 point.

It combines:

-   `internet_exposure`; and
-   `environment`.

### 8.1 Internet-exposure factors

  Value                    Factor
  ---------------------- --------
  UNKNOWN                    0.00
  INTERNAL                   0.20
  EXTERNALLY_REACHABLE       0.60
  INTERNET_FACING            1.00

### 8.2 Environment factors

  Value           Factor
  ------------- --------
  UNKNOWN           0.00
  DEVELOPMENT       0.20
  TEST              0.20
  STAGING           0.50
  CORPORATE         0.70
  PRODUCTION        1.00

### 8.3 Exposure weighting

``` text
exposure_factor =
    0.70 * internet_exposure_factor
  + 0.30 * environment_factor

exposure_component = exposure_factor
```

Internet exposure therefore has more influence than environment within
the 10% exposure allocation.

For an internal development asset:

``` text
internet exposure factor = 0.20
environment factor       = 0.20

exposure component =
    (0.70 * 0.20) + (0.30 * 0.20)
  = 0.14 + 0.06
  = 0.20
```

For an Internet-facing production asset:

``` text
(0.70 * 1.00) + (0.30 * 1.00) = 1.00
```

------------------------------------------------------------------------

## 9. Risk Bands

After calculation and two-decimal rounding, the score is mapped to a
level:

  Score         Risk level
  ------------- ------------
  0.00--3.99    LOW
  4.00--6.99    MEDIUM
  7.00--8.99    HIGH
  9.00--10.00   CRITICAL

The boundary behaviour is deterministic:

``` text
3.90 -> LOW
4.00 -> MEDIUM
7.00 -> HIGH
9.00 -> CRITICAL
```

------------------------------------------------------------------------

## 10. Assessment Status

Every persisted risk assessment has one of three states.

### 10.1 ASSESSED

`ASSESSED` means:

-   usable technical severity exists;
-   the finding has a resolved `asset_id`; and
-   a curated asset-context row exists.

An all-`UNKNOWN` context row is still a context row. Therefore a
technically scorable finding with a resolved asset and an existing
all-`UNKNOWN` context row is `ASSESSED`, even though those unknown
values contribute zero.

### 10.2 PARTIAL

A technically scorable finding is `PARTIAL` when either:

-   the asset is unresolved; or
-   no curated asset-context row exists.

The platform still calculates the score using available deterministic
evidence. Missing organisational/exposure context contributes zero.

This means `PARTIAL` does **not** mean "no risk assessment exists." It
means the score was calculated from incomplete contextual evidence.

### 10.3 UNSCORABLE

`UNSCORABLE` means neither a usable numeric severity score nor a valid
severity level is available.

For this state:

``` text
contextual_risk_score = NULL
contextual_risk_level = NULL
```

A context snapshot may still exist if the asset has curated context.
This preserves what was known about the asset while correctly refusing
to invent technical severity.

------------------------------------------------------------------------

## 11. Missing Context Versus UNKNOWN Context

This distinction is fundamental.

### No context row

``` text
asset_context = None
context_snapshot = NULL
```

A scorable finding is `PARTIAL`.

### Existing context row containing UNKNOWN values

For example:

``` json
{
  "environment": "UNKNOWN",
  "criticality": "UNKNOWN",
  "data_classification": "UNKNOWN",
  "internet_exposure": "UNKNOWN",
  "confidentiality_requirement": "UNKNOWN",
  "integrity_requirement": "UNKNOWN",
  "availability_requirement": "UNKNOWN"
}
```

If the asset is resolved, the finding is `ASSESSED`.

Each unknown scoring value contributes zero, but the platform knows that
a curated context record exists.

This distinction prevents absence of organisational knowledge from being
silently represented as explicit curated knowledge.

------------------------------------------------------------------------

## 12. Context Snapshot

Each assessment can retain the curated context used when the calculation
was performed.

The snapshot includes:

``` text
environment
business_service
business_unit
owner
technical_owner
criticality
data_classification
internet_exposure
network_zone
confidentiality_requirement
integrity_requirement
availability_requirement
context_source
```

Not every field contributes numerically to V1.

For example, `business_service`, `business_unit`, `owner`,
`technical_owner`, and `network_zone` are retained for audit context but
do not alter the V1 score.

The snapshot is deep-copied by the contextualiser, and the calculation
does not mutate the supplied context dictionary.

------------------------------------------------------------------------

## 13. Assessment Factors

The calculation returns an `assessment_factors` object containing the
deterministic inputs and intermediate components used to explain the
score.

For a scorable assessment, this includes:

``` text
technical_severity_source
effective_technical_severity
technical_component
criticality_factor
data_classification_factor
confidentiality_requirement_factor
integrity_requirement_factor
availability_requirement_factor
organisational_impact_component
internet_exposure_factor
environment_factor
exposure_component
```

The ingestion and reassessment integration additionally records:

``` text
tenant_service_tier
```

`tenant_service_tier` is **informational and non-scoring** in V1. It is
not part of the context snapshot and does not change the risk score.

For an `UNSCORABLE` assessment, the contextualiser records:

``` text
technical_severity_source = null
effective_technical_severity = null
```

and does not fabricate a numeric score.

------------------------------------------------------------------------

## 14. Database Model

Migration:

``` text
database/migrations/009_risk_contextualisation.sql
```

creates the Risk Contextualisation persistence foundation.

### 14.1 Finding tenant key

The migration adds:

``` text
UNIQUE (finding_id, tenant_code)
```

to `unified_security_findings`.

This enables the risk-assessment relationship to enforce both finding
identity and tenant ownership.

### 14.2 `finding_risk_assessments`

The table represents the **current** deterministic assessment for each
finding.

  -----------------------------------------------------------------------
  Column                              Purpose
  ----------------------------------- -----------------------------------
  `finding_id`                        Finding identifier and primary key

  `tenant_code`                       Tenant boundary

  `asset_id`                          Contextualised asset, nullable

  `assessment_status`                 `ASSESSED`, `PARTIAL`, or
                                      `UNSCORABLE`

  `base_severity_score`               Original numeric scanner severity,
                                      if supplied

  `base_severity_level`               Original/normalised scanner
                                      severity level

  `contextual_risk_score`             Derived 0--10 score

  `contextual_risk_level`             Derived risk band

  `assessment_factors`                Deterministic calculation factors

  `context_snapshot`                  Curated asset context used

  `assessment_model`                  Model/version identifier

  `assessed_at`                       Time current assessment was
                                      calculated/persisted

  `updated_at`                        Current row update time
  -----------------------------------------------------------------------

### 14.3 One current row per finding

`finding_id` is the table's primary key.

Therefore:

``` text
one finding -> zero or one current risk-assessment row
```

Reassessment updates the row rather than appending another row.

V1 is a current-state model, not an assessment-history model.

------------------------------------------------------------------------

## 15. Database Integrity

### 15.1 Finding/tenant foreign key

The composite foreign key:

``` text
(finding_id, tenant_code)
    -> unified_security_findings(finding_id, tenant_code)
```

prevents a risk assessment from associating a finding with the wrong
tenant.

Deleting the finding cascades to its risk assessment.

### 15.2 Asset/tenant foreign key

The composite relationship:

``` text
(asset_id, tenant_code)
    -> assets(asset_id, tenant_code)
```

prevents cross-tenant asset association.

If an asset is deleted, only `asset_id` in the assessment is set to
`NULL`; the risk-assessment row is retained.

### 15.3 Scored-state constraint

The database enforces:

-   `ASSESSED` and `PARTIAL` must have both a contextual score and
    contextual level;
-   `UNSCORABLE` must have neither.

This makes invalid state combinations impossible through ordinary
database writes.

### 15.4 Score ranges

Both base and contextual numeric scores are constrained to 0--10 where
present.

### 15.5 Model identifier

`assessment_model` must contain non-whitespace content.

### 15.6 Indexes

V1 creates indexes supporting:

-   tenant/risk-level/risk-score queries;
-   asset/risk-score queries; and
-   tenant/assessment-status queries.

These support future prioritisation, dashboards, and operational
querying without changing the V1 decision boundary.

------------------------------------------------------------------------

## 16. Pure Contextualisation Engine

Implementation:

``` text
risk_management/contextualiser.py
```

The module is intentionally pure with respect to infrastructure.

It performs:

-   input validation;
-   severity normalisation;
-   severity fallback;
-   deterministic factor lookup;
-   weighted calculation;
-   risk-band mapping;
-   context snapshot construction; and
-   assessment construction.

It does **not** perform:

-   database access;
-   persistence;
-   asset resolution;
-   asset-context lookup;
-   remediation routing;
-   AI analysis; or
-   transaction management.

This separation makes the model independently testable and prevents
hidden side effects.

------------------------------------------------------------------------

## 17. Persistence Layer

Implementation:

``` text
risk_management/persistence.py
```

The public operation is:

``` python
upsert_risk_assessment(
    conn,
    *,
    finding_id,
    tenant_code,
    assessment,
)
```

It inserts the current assessment or updates the existing row on
`finding_id` conflict.

On reassessment, it replaces the current:

-   tenant;
-   asset;
-   assessment status;
-   base severity;
-   contextual score and level;
-   factors;
-   snapshot; and
-   model identifier.

It also refreshes `assessed_at` and `updated_at`.

The function does not commit or roll back the caller's transaction.

------------------------------------------------------------------------

## 18. Finding-Ingestion Workflow

Risk assessment is integrated into `worker/enricher_worker.py`.

The relevant workflow is:

``` text
Receive normalised Unified Security Finding
        |
        v
AI advisory enrichment
        |
        v
Begin caller-owned DB transaction
        |
        v
Resolve canonical asset
        |
        v
UPSERT unified_security_findings
        |
        v
Read persisted asset_id
        |
        +---- asset exists ----> Read curated asset context
        |                              |
        |                              v
        +----------------------> contextualise_risk()
                                       |
                                       v
                         add tenant_service_tier factor
                                       |
                                       v
                         upsert_risk_assessment()
                                       |
                                       v
                         Continue existing refresh logic
                                       |
                                       v
                         Commit caller transaction
```

### 18.1 Why persisted `asset_id` is used

Finding upsert preserves an existing asset binding if a later ingestion
cannot resolve the asset:

``` text
asset_id =
    COALESCE(
        EXCLUDED.asset_id,
        unified_security_findings.asset_id
    )
```

The worker then uses the `asset_id` returned by the database, not merely
the current resolver result.

This matters because weak or temporarily incomplete scanner evidence
must not erase a previously established canonical asset relationship.

Consequently, risk contextualisation follows the persisted asset
relationship.

------------------------------------------------------------------------

## 19. AI Boundary

The worker still performs AI enrichment, but the AI output is separate
from authoritative contextual risk.

The AI system prompt explicitly prevents the model from selecting or
recommending:

-   Ansible roles;
-   playbooks;
-   remediation actions;
-   automation tiers;
-   approval requirements;
-   remediation capabilities; and
-   execution parameters.

Its output is limited to advisory fields such as:

``` text
risk_summary
business_context_impact
confidence_score
```

Risk Contextualisation does not read `ai_analysis` to calculate the
deterministic score.

This creates two distinct layers:

``` text
AI enrichment
    -> explanatory/advisory narrative

Risk Contextualisation
    -> deterministic authoritative platform risk state
```

A model hallucination therefore cannot directly alter the V1 contextual
risk score.

------------------------------------------------------------------------

## 20. Automatic Reassessment

Finding ingestion is not the only event that can change risk.

If the technical finding remains unchanged but an administrator changes
the asset from, for example:

``` text
DEVELOPMENT / LOW / INTERNAL
```

to:

``` text
PRODUCTION / CRITICAL / INTERNET_FACING
```

the organisational risk has changed.

Waiting for the scanner to rediscover the finding would leave stale risk
state.

V1 therefore provides:

``` text
risk_management/reassessment.py
```

### 20.1 `reassess_asset_findings()`

This operation:

1.  validates/reads the current tenant-scoped asset context;
2.  selects findings whose `tenant_code` and `asset_id` match;
3.  recalculates every selected finding;
4.  adds the informational tenant service tier; and
5.  upserts each current assessment.

It returns the number of findings reassessed.

An existing asset with no findings is a valid no-op and returns `0`.

### 20.2 `set_asset_context_and_reassess()`

This higher-level operation:

1.  sets or patches curated asset context through Asset Context
    Management;
2.  immediately reassesses findings bound to the asset; and
3.  returns the updated context and reassessed-finding count.

### 20.3 `clear_asset_context_and_reassess()`

This operation:

1.  clears the curated context row; and
2.  immediately reassesses findings bound to the asset.

A scorable finding normally moves from `ASSESSED` to `PARTIAL`,
retaining its technical contribution but losing the
organisational/exposure contribution.

An unscorable finding remains `UNSCORABLE`.

------------------------------------------------------------------------

## 21. Important Context-Mutation Contract

Automatic reassessment is guaranteed when context changes are made
through the **risk-aware mutation service**:

``` python
set_asset_context_and_reassess(...)
clear_asset_context_and_reassess(...)
```

The lower-level functions in:

``` text
asset_management/context.py
```

remain pure context CRUD operations.

Calling `set_asset_context()` or `clear_asset_context()` directly does
**not**, by itself, invoke risk reassessment.

Therefore future runtime APIs, administrative interfaces, importers, or
workflows that change curated asset context and require current risk
state to remain synchronised should call the risk-aware operations.

This boundary avoids introducing a reverse dependency from Asset
Management into Risk Management while still providing an atomic
higher-level workflow.

------------------------------------------------------------------------

## 22. Transaction Semantics

Risk Contextualisation follows caller-owned transaction semantics.

The persistence and reassessment services do not independently commit
the database connection.

This permits operations such as:

``` text
BEGIN
  update asset context
  reassess all affected findings
COMMIT
```

to succeed or fail as one logical transaction.

If the caller rolls back, both the context mutation and resulting risk
changes are rolled back.

This is particularly important because persisting new context without
its corresponding risk recalculation would create inconsistent derived
state.

------------------------------------------------------------------------

## 23. Tenant Isolation

Tenant isolation is enforced at several layers.

### Application/reassessment layer

Reassessment selects findings using both:

``` text
tenant_code = ?
asset_id = ?
```

Asset-context lookup also validates the tenant/asset relationship.

### Database layer

Composite foreign keys prevent:

-   assigning another tenant's finding to a risk assessment; and
-   assigning another tenant's asset to the assessment.

Tenant isolation therefore does not depend only on application query
discipline.

------------------------------------------------------------------------

## 24. Worked Example A --- Technical Evidence Only

Finding:

``` text
severity_score = 8.1
severity_level = HIGH
asset_id = resolved
asset context row = absent
```

Technical component:

``` text
8.1 / 10 * 6 = 4.86
```

Organisational component:

``` text
0.00
```

Exposure component:

``` text
0.00
```

Result:

``` text
contextual_risk_score = 4.86
contextual_risk_level = MEDIUM
assessment_status = PARTIAL
context_snapshot = NULL
```

The finding is not unscorable: valid technical evidence exists. It is
partial because organisational context is absent.

------------------------------------------------------------------------

## 25. Worked Example B --- Maximum Curated Context

Use the same technical severity:

``` text
severity_score = 8.1
```

Context:

``` text
environment = PRODUCTION
criticality = CRITICAL
data_classification = RESTRICTED
internet_exposure = INTERNET_FACING
confidentiality_requirement = CRITICAL
integrity_requirement = CRITICAL
availability_requirement = CRITICAL
```

Technical:

``` text
4.86
```

Organisational impact:

``` text
impact factor = 1.00
organisational component = 3.00
```

Exposure:

``` text
(0.70 * 1.00) + (0.30 * 1.00) = 1.00
```

Total:

``` text
4.86 + 3.00 + 1.00 = 8.86
```

Result:

``` text
contextual_risk_score = 8.86
contextual_risk_level = HIGH
assessment_status = ASSESSED
```

Notice that maximum organisational context does not automatically make
an 8.1 technical finding `CRITICAL`; the deterministic band threshold
remains 9.00.

------------------------------------------------------------------------

## 26. Worked Example C --- Low Organisational Context

Same technical finding:

``` text
severity_score = 8.1
```

Context:

``` text
environment = DEVELOPMENT
criticality = LOW
data_classification = PUBLIC
internet_exposure = INTERNAL
confidentiality_requirement = LOW
integrity_requirement = LOW
availability_requirement = LOW
```

Every impact input has factor `0.25`.

Impact:

``` text
impact factor =
    (0.40 * 0.25)
  + (0.20 * 0.25)
  + (0.133333 * 0.25)
  + (0.133333 * 0.25)
  + (0.133334 * 0.25)
  = 0.25

organisational component = 0.25 * 3 = 0.75
```

Exposure:

``` text
(0.70 * 0.20) + (0.30 * 0.20)
= 0.20
```

Total:

``` text
4.86 + 0.75 + 0.20 = 5.81
```

Result:

``` text
contextual_risk_score = 5.81
contextual_risk_level = MEDIUM
assessment_status = ASSESSED
```

------------------------------------------------------------------------

## 27. Worked Example D --- Severity-Level Fallback

Finding:

``` text
severity_score = NULL
severity_level = HIGH
asset_id = unresolved
asset_context = absent
```

The HIGH fallback is 8.0.

``` text
technical component =
    8.0 / 10 * 6
  = 4.8
```

Result:

``` text
base_severity_score = NULL
base_severity_level = HIGH
effective_technical_severity = 8.0
technical_severity_source = severity_level_fallback
contextual_risk_score = 4.80
contextual_risk_level = MEDIUM
assessment_status = PARTIAL
```

The important point is that the platform uses 8.0 for calculation but
does not claim that the scanner supplied a numeric score.

------------------------------------------------------------------------

## 28. Worked Example E --- Unscorable Finding

Finding:

``` text
severity_score = NULL
severity_level = NULL
asset_id = resolved
asset context = present
```

Result:

``` text
assessment_status = UNSCORABLE
base_severity_score = NULL
base_severity_level = NULL
contextual_risk_score = NULL
contextual_risk_level = NULL
assessment_model = CONTEXTUAL_RISK_V1
```

The context snapshot can still be retained.

The platform refuses to turn business criticality into a vulnerability
severity substitute.

------------------------------------------------------------------------

## 29. Worked Example F --- Context Removal

Assume an existing finding has:

``` text
severity_score = 8.1
asset_id = resolved
maximum curated context
```

Before removal:

``` text
score = 8.86
level = HIGH
status = ASSESSED
```

When curated context is cleared through
`clear_asset_context_and_reassess()`:

``` text
technical component = 4.86
organisational component = 0
exposure component = 0
```

After removal:

``` text
score = 4.86
level = MEDIUM
status = PARTIAL
context_snapshot = NULL
```

The finding and asset binding remain. Only the unavailable
organisational context ceases to contribute.

------------------------------------------------------------------------

## 30. Current-State Persistence Versus History

V1 deliberately keeps one current assessment per finding.

Reassessment performs an upsert:

``` text
finding_id conflict
    -> update current assessment
```

Therefore changing context from high to low does not produce two
assessment rows. The row is updated to represent current deterministic
risk.

This design provides a simple authoritative current state.

It does **not** provide historical questions such as:

-   What was the score yesterday?
-   Which context change caused a risk downgrade?
-   How many times has the score crossed HIGH?
-   Who changed the context that produced a previous score?

Those capabilities would require a separate history/event model and
should not be inferred from V1.

------------------------------------------------------------------------

## 31. Asset Deletion and Finding Deletion

The database intentionally treats these differently.

### Asset deletion

If the referenced asset is deleted:

``` text
finding_risk_assessments.asset_id -> NULL
```

The assessment row remains.

This preserves the finding's risk record while removing the now-invalid
asset reference.

### Finding deletion

If the finding is deleted:

``` text
finding_risk_assessments row -> deleted by cascade
```

The risk assessment has no independent meaning without its finding.

------------------------------------------------------------------------

## 32. Validation and Error Handling

The contextualiser rejects invalid deterministic inputs rather than
silently interpreting them.

Examples include:

-   severity score below 0;
-   severity score above 10;
-   non-numeric severity score;
-   non-finite numeric severity;
-   unsupported severity level;
-   unsupported scored context value; and
-   non-dictionary `asset_context`.

Severity and context enumeration values are normalised to uppercase
where the contextualiser performs validation.

Invalid inputs therefore fail explicitly instead of quietly producing
misleading risk.

------------------------------------------------------------------------

## 33. Regression Coverage

### `tests/test_risk_contextualisation.py`

The pure calculation regression covers:

-   full-context calculation;
-   numeric severity precedence;
-   severity-level fallback;
-   missing context;
-   unresolved asset behaviour;
-   unscorable findings;
-   audit-field snapshots;
-   non-mutation of supplied context;
-   all-UNKNOWN context;
-   risk-band boundaries;
-   invalid severity score;
-   invalid severity level;
-   invalid scored context values; and
-   asset-context type validation.

### `tests/test_risk_persistence.py`

Persistence regression covers:

-   initial current-assessment persistence; and
-   reassessment replacing the existing current row rather than creating
    a second row.

### `tests/test_risk_reassessment.py`

Reassessment regression covers:

-   technical-only starting risk;
-   context set triggering reassessment;
-   context update replacing current risk;
-   context clear returning to technical-only risk;
-   unscorable behaviour through context changes;
-   tenant scoping;
-   asset-with-no-findings no-op behaviour; and
-   caller-owned transaction rollback.

### Worker integration regression

The worker integration tests establish that:

-   findings receive deterministic risk during ingestion;
-   Wazuh findings can converge on a canonical asset;
-   unresolved re-ingestion preserves an existing asset binding; and
-   contextual risk uses the persisted asset binding.

------------------------------------------------------------------------

## 34. Release Smoke Integration

The release smoke test reconstructs the temporary database from the
canonical schema and migrations, including:

``` text
database/migrations/009_risk_contextualisation.sql
```

The risk regressions run alongside asset-management regressions.

The smoke test also checks database-level risk invariants, including:

-   existence of `finding_risk_assessments`;
-   finding/tenant foreign key;
-   asset/tenant foreign key;
-   primary key;
-   duplicate current-assessment rejection;
-   cross-tenant finding rejection;
-   cross-tenant asset rejection;
-   scored-state constraints;
-   contextual score range;
-   asset-deletion behaviour; and
-   finding-deletion cascade behaviour.

Risk Contextualisation is therefore tested at pure-function,
persistence, integration, reassessment, schema, and release-smoke
levels.

------------------------------------------------------------------------

## 35. Auditability and Explainability

V1 is designed so that a reviewer can distinguish:

1.  what the scanner said;
2.  what asset was associated with the finding;
3.  what curated organisational context was available;
4.  which numerical factors the model used;
5.  which model version performed the calculation; and
6.  what contextual score and level resulted.

The principal audit fields are:

``` text
base_severity_score
base_severity_level
asset_id
assessment_status
assessment_factors
context_snapshot
assessment_model
assessed_at
updated_at
```

This is materially different from persisting only a final opaque risk
number.

------------------------------------------------------------------------

## 36. Why the Model Is Deterministic

Automated remediation requires predictable decision inputs.

For identical inputs, `CONTEXTUAL_RISK_V1` produces the same result. The
calculation uses fixed factor tables, fixed weights, decimal arithmetic,
explicit rounding, and explicit band thresholds.

This provides:

-   reproducibility;
-   testability;
-   change control;
-   explainability;
-   easier incident review; and
-   a stable basis for future policy.

If the scoring model changes later, it should receive a new model
identifier rather than silently changing the meaning of
`CONTEXTUAL_RISK_V1`.

------------------------------------------------------------------------

## 37. Why UNKNOWN Contributes Zero

V1 uses zero contribution for `UNKNOWN` contextual factors.

This does **not** mean that unknown context proves low organisational
importance. It means the model does not award risk points for facts the
platform does not possess.

The `assessment_status` and `context_snapshot` provide the necessary
interpretation:

-   absent context produces `PARTIAL`;
-   an explicit context row with `UNKNOWN` values can produce
    `ASSESSED`, but the unknown factors are visible in the snapshot and
    contribute zero.

Operational consumers should therefore consider both the score and
assessment status/context completeness rather than treating the numeric
score as the only meaningful field.

------------------------------------------------------------------------

## 38. Service Tier

`tenant_service_tier` is attached to `assessment_factors` by the worker
and reassessment service.

It is intentionally not part of the numerical V1 model.

This avoids conflating:

``` text
commercial/service entitlement
```

with:

``` text
security risk
```

A GOLD service customer does not automatically have a more severe
vulnerability than a STANDARD service customer.

Service tier may be useful later for SLA or workflow policy, but that is
a separate decision dimension.

------------------------------------------------------------------------

## 39. Remediation Boundary

Risk Contextualisation V1 does not modify remediation routing.

The authoritative remediation path remains separate and deterministic.

This means a finding becoming `HIGH` contextual risk does not, merely
because of this feature:

-   choose a different remediation capability;
-   bypass approval;
-   select an Ansible role;
-   change verification semantics;
-   cause automatic execution; or
-   alter scanner-specific remediation evidence.

A future feature may use contextual risk as an input to prioritisation
or approval policy, but that must be introduced and tested explicitly.

------------------------------------------------------------------------

## 40. Developer Invariants

Future changes should preserve the following unless a deliberate
architecture revision is approved.

1.  **Never overwrite scanner severity with contextual risk.**
2.  **Do not make AI output authoritative risk input.**
3.  **Do not move risk classification into scanner orchestrators.**
4.  **Do not change finding identity or recurrence semantics merely to
    support risk.**
5.  **Use persisted `asset_id` when calculating risk after finding
    upsert.**
6.  **Treat missing context and an existing UNKNOWN context row as
    different states.**
7.  **Do not fabricate `base_severity_score` when severity-level
    fallback is used.**
8.  **Keep `tenant_service_tier` non-scoring in V1.**
9.  **Maintain tenant scoping in both queries and database
    relationships.**
10. **Keep transaction ownership with the caller.**
11. **Use risk-aware context mutation operations when context changes
    must immediately refresh risk.**
12. **Do not assume direct low-level Asset Context CRUD triggers
    reassessment.**
13. **Maintain one current assessment per finding unless a separate
    history model is deliberately introduced.**
14. **Version any materially different scoring model.**
15. **Do not make remediation routing depend on contextual risk without
    a separately reviewed feature.**

------------------------------------------------------------------------

## 41. Operational Query Examples

The persistence model supports useful current-state queries.

### Highest contextual risk for a tenant

``` sql
SELECT
    finding_id,
    asset_id,
    assessment_status,
    contextual_risk_score,
    contextual_risk_level
FROM finding_risk_assessments
WHERE tenant_code = $1
  AND contextual_risk_score IS NOT NULL
ORDER BY contextual_risk_score DESC;
```

### Partial assessments

``` sql
SELECT
    finding_id,
    asset_id,
    contextual_risk_score,
    contextual_risk_level
FROM finding_risk_assessments
WHERE tenant_code = $1
  AND assessment_status = 'PARTIAL'
ORDER BY contextual_risk_score DESC;
```

### Unscorable findings

``` sql
SELECT
    finding_id,
    asset_id,
    assessed_at
FROM finding_risk_assessments
WHERE tenant_code = $1
  AND assessment_status = 'UNSCORABLE'
ORDER BY assessed_at DESC;
```

### Risk for an asset

``` sql
SELECT
    finding_id,
    contextual_risk_score,
    contextual_risk_level,
    assessment_status
FROM finding_risk_assessments
WHERE tenant_code = $1
  AND asset_id = $2
ORDER BY contextual_risk_score DESC NULLS LAST;
```

These examples query current state only.

------------------------------------------------------------------------

## 42. Suggested Integration Pattern for Future Context APIs

A future API that changes curated context should conceptually use:

``` python
with conn:
    context, reassessed_count = set_asset_context_and_reassess(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
        context=context_patch,
        context_source="API",
    )
```

For deletion:

``` python
with conn:
    reassessed_count = clear_asset_context_and_reassess(
        conn,
        tenant_code=tenant_code,
        asset_id=asset_id,
    )
```

The caller owns the transaction.

Direct use of the lower-level Asset Context CRUD API should be reserved
for cases where risk reassessment is intentionally not part of that
operation or where a higher-level caller explicitly performs
reassessment itself.

------------------------------------------------------------------------

## 43. Future Evolution

The following are logical future capabilities, but they are **not
implemented by Risk Contextualisation V1**.

### 43.1 Risk-aware remediation prioritisation

Contextual risk could become one input to:

-   remediation queue ordering;
-   SLA calculation;
-   approval policy; or
-   escalation.

That should be implemented separately from the scoring foundation.

### 43.2 Threat intelligence

Exploit activity, known exploitation, threat actor relevance, EPSS-like
probability data, or other threat intelligence could form a separate
deterministic threat dimension.

Such inputs should retain provenance and freshness metadata rather than
being mixed opaquely into asset context.

### 43.3 Risk history

A historical assessment/event table could preserve:

-   previous scores;
-   previous snapshots;
-   model versions;
-   reason for reassessment;
-   actor/source of context change; and
-   risk transitions over time.

### 43.4 Context completeness

A future model could expose a distinct context-completeness/confidence
indicator rather than requiring consumers to infer completeness from
`assessment_status` and snapshot values.

### 43.5 Model version migration

If a `CONTEXTUAL_RISK_V2` is introduced, the platform should define how
existing findings are reassessed and how model-version transitions are
audited.

### 43.6 Scan coordination and coverage

Risk can eventually be considered alongside scan coverage so that the
platform distinguishes high contextual risk from gaps in assurance
coverage. That is a separate platform capability.

------------------------------------------------------------------------

## 44. Implementation Reference

  ------------------------------------------------------------------------------------------
  Responsibility                      Implementation
  ----------------------------------- ------------------------------------------------------
  Risk database foundation            `database/migrations/009_risk_contextualisation.sql`

  Pure deterministic model            `risk_management/contextualiser.py`

  Current-state persistence           `risk_management/persistence.py`

  Context-change reassessment         `risk_management/reassessment.py`

  Finding-ingestion integration       `worker/enricher_worker.py`

  Calculation regression              `tests/test_risk_contextualisation.py`

  Persistence regression              `tests/test_risk_persistence.py`

  Reassessment regression             `tests/test_risk_reassessment.py`

  Worker integration regression       `tests/test_enricher_asset_integration.py`

  Release/database invariants         `tests/release_smoke_test.sh`
  ------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 45. End-to-End Summary

The complete V1 flow is:

``` text
1. Scanner discovers security evidence.

2. Scanner-specific orchestrator:
      - parses native evidence;
      - normalises the Unified Security Finding;
      - determines finding_class.

3. Worker receives the normalised finding.

4. AI enrichment creates advisory narrative context only.

5. A database transaction begins.

6. Asset resolver attempts to establish canonical asset identity.

7. The finding is inserted or updated.
      - existing asset binding is preserved if new resolution is absent.

8. The worker reads the persisted asset_id.

9. If an asset is bound, current curated asset context is retrieved.

10. CONTEXTUAL_RISK_V1:
      - validates technical severity;
      - selects numeric score or severity-level fallback;
      - calculates the 60% technical component;
      - calculates the 30% organisational-impact component;
      - calculates the 10% exposure component;
      - rounds the final score;
      - assigns the risk band;
      - assigns ASSESSED, PARTIAL, or UNSCORABLE;
      - records factors and the context snapshot.

11. tenant_service_tier is attached as a non-scoring informational factor.

12. The current finding_risk_assessments row is inserted or updated.

13. The caller commits the transaction.

14. If curated asset context later changes through the risk-aware mutation
    service, every existing finding bound to that tenant/asset is
    reassessed immediately without requiring scanner re-ingestion.
```

The result is a risk layer that is deterministic, tenant-scoped,
auditable, independent of AI authority, and separated from remediation
execution.

------------------------------------------------------------------------

## 46. Design Principle

The central design principle of Risk Contextualisation V1 is:

> **Technical severity describes the security weakness; contextual risk
> describes the significance of that weakness in the organisation.**

The platform preserves both.

That separation allows the system to become progressively more
context-aware without losing scanner provenance, introducing opaque AI
decisions, or prematurely coupling risk calculation to automated
remediation execution.
