# Remediation Workflow Orchestration V1

## Purpose

Remediation Workflow Orchestration V1 defines how the platform selects the next eligible already-routed finding and delivers it into the existing remediation execution lifecycle.

It sits between `prioritised_remediation_queue` and the existing controller / approval / Ansible execution path.

The dispatcher orchestration layer does not perform remediation routing, risk scoring, approval decisions, execution-state management, or verification.

## V1 Implementation

The production V1 orchestration component is a Python remediation dispatcher.

The dispatcher consumes the prioritised remediation queue and delivers one already-routed finding at a time to the existing remediation controller.

n8n is not required for core remediation execution. It is reserved for optional integrations, notifications, report distribution, and other external business workflows.

## Architectural Boundary

`open_remediation_queue` answers which remediation rule applies.

`prioritised_remediation_queue` answers which already-routed finding should be handled first.

Workflow orchestration delivers the next eligible finding to the controller.

The controller and database claim the finding and control the remediation execution lifecycle.

The dispatcher layer must not introduce a second routing engine or execution state machine.

## Next-Item Selection

V1 selects one remediation candidate per workflow invocation.

The dispatcher must query `prioritised_remediation_queue` using:

```sql
SELECT *
FROM prioritised_remediation_queue
ORDER BY
    has_contextual_risk DESC,
    contextual_risk_score DESC NULLS LAST,
    detected_at ASC,
    finding_id ASC
LIMIT 1;
```

This means usable contextual risk first, then higher contextual risk score, then older `detected_at`, then lower `finding_id` as the final deterministic tie-breaker.

The dispatcher must not reproduce or reinterpret this ordering in application-side logic.

`remediation_rules.priority` remains remediation-rule selection precedence and is not remediation work priority.

## Deterministic Route Consumption

The selected queue row already contains the authoritative remediation route produced by deterministic remediation routing.

The dispatcher consumes, rather than recomputes, fields including `rule_id`, `capability`, `playbook_name`, `remediation_action`, `automation_tier`, `approval_required`, `parameter_template`, and `required_parameters`.

The dispatcher must not select another rule, capability, playbook, automation tier, remediation action, or approval policy.

## Controller Payload Construction

The dispatcher constructs the existing controller request from the selected queue row.

The controller payload includes the persisted finding identity and persisted remediation-rule identity required by the controller, including `finding_id`, `rule_id`, `tenant_code`, `target_host`, `engine_source`, `finding_class`, `finding_key`, `finding_title`, `capability`, `playbook_name`, `remediation_action`, `automation_tier`, `approval_required`, `engine_metadata`, and `execution_parameters`.

Risk-prioritisation fields are selection metadata and must not alter the remediation route or execution parameters.

The controller independently validates the request against the persisted finding and remediation rule before any execution is created.

## Parameter Template Rendering

Remediation execution parameters are derived deterministically from persisted `parameter_template` and scanner-produced `engine_metadata`.

V1 supports only exact whole-value placeholders of the form `{{ engine_metadata.key }}`.

The renderer preserves JSON value types, supports nested dictionaries and lists, preserves literal values, validates required parameters, rejects missing referenced metadata, rejects null or blank required string values, and rejects malformed input structures.

Unsupported namespaces, filters, expressions, arbitrary code, and embedded interpolation are rejected.

No Jinja2 execution, Python expression evaluation, shell evaluation, or other general-purpose template execution is permitted.

Missing information must fail closed. The dispatcher must never invent a remediation parameter.

## Queue Consumption Boundary

Reading a row from `prioritised_remediation_queue` does not claim it.

The authoritative queue-consumption boundary is the existing finding lifecycle transition performed by the controller/database layer: `OPEN -> IN_REMEDIATION` through `ensure_claimed()`.

Because `open_remediation_queue` exposes only `OPEN` findings and `prioritised_remediation_queue` is derived from it, a successfully claimed finding naturally leaves both queues.

No additional `DISPATCHED` finding state is introduced in V1.

## Execution Creation

The controller performs `ensure_claimed()` and `create_execution()` inside the existing database transaction boundary.

Normal immediate remediation begins as `QUEUED`. Approval-gated remediation begins as `AWAITING_APPROVAL`.

The dispatcher does not create or manipulate remediation execution states directly.

## Delivery and Duplicate Safety

Dispatcher delivery in V1 follows an at-least-once delivery model.

A selected finding may therefore be submitted again following a timeout, lost response, retry, or concurrent dispatcher delivery.

Duplicate safety is enforced by the authoritative controller/database boundary, not by an n8n lock or dispatcher lease.

PostgreSQL enforces at most one active remediation execution per finding through `uq_one_active_execution_per_finding` for the active statuses `QUEUED`, `AWAITING_APPROVAL`, `RUNNING`, `STAGE1_PASSED`, and `VERIFYING`.

A duplicate delivery reaches `create_execution()`, the database rejects the second active execution, and the helper raises `ActiveRemediationExistsError`.

The failed duplicate attempt does not create a second active execution.

V1 does not introduce a separate dispatcher claim table, lease table, distributed lock, or second execution state machine.

## Approval Boundary

Workflow prioritisation and dispatch do not grant remediation approval.

If the persisted remediation rule requires approval, the controller creates an execution in `AWAITING_APPROVAL` and does not execute the remediation until the existing approval mechanism authorises it.

The dispatcher must never approve an execution, bypass `approval_required`, change an automation tier, or convert an approval-gated rule into an automatically executable rule.

Approval remains an independent controller responsibility.

## Controller Response and Retry Semantics

`200` and `202` represent accepted delivery paths and do not require delivery retry.

`400` represents a permanent request or contract failure and the same unchanged payload must not be retried.

`401` represents an authentication or configuration problem requiring operational correction.

A specific duplicate-active-execution conflict is safe because the database has already prevented a second active execution.

Other `409` responses may represent different state conflicts and must not automatically be treated as benign duplicates.

Network failures, timeouts, connection failures, and `5xx` responses are retryable delivery or infrastructure failures.

Retries must reuse the same authoritative finding and rule identity. They must not select a different remediation route for the same finding.

## Failure and Crash Behaviour

If the dispatcher fails before controller submission, the finding remains `OPEN` and remains eligible for a later orchestration invocation.

If the controller commits but the dispatcher loses the response, a later duplicate submission is prevented from creating another active execution by the database uniqueness constraint.

If the controller transaction fails before commit, the claim and execution creation do not become a successfully committed execution.

Recovery of an execution that has already entered the controller execution lifecycle and later becomes stranded is a controller/runtime recovery concern, not an orchestration claim problem.

## Component Responsibilities

PostgreSQL remains authoritative for persisted findings, deterministic routing results, prioritised queue data, finding lifecycle state, remediation execution state, and exactly-one-active-execution enforcement.

The dispatcher orchestrator is responsible for triggering orchestration, selecting the next queue row, constructing the deterministic controller request, delivering it, and classifying the response. Retryable outcomes are exposed to the invoking scheduler or service for a later invocation.

The controller remains responsible for validating the finding and remediation rule, enforcing approval constraints, claiming the finding, creating the execution, invoking the remediation capability, controlling execution state transitions, and coordinating verification.

Ansible remains responsible for performing the requested remediation change and producing Stage 1 verification evidence.

Scanner orchestrators remain responsible for scanner-native normalisation, `finding_class` determination, and scanner-based Stage 2 verification where supported.


## Proven Regression Guarantees

Current automated regression testing proves deterministic next-item selection, authoritative route consumption, deterministic controller payload construction, safe parameter rendering, duplicate-delivery rejection, exactly one active execution per finding, queue removal after claim, and selection of the next eligible finding.

These regressions are included in the repository release smoke test.

## V1 Exclusions

V1 deliberately does not introduce batch dispatch, parallel dispatch, dispatcher-owned locking, dispatcher claim or lease tables, a `DISPATCHED` lifecycle state, another execution state machine, service-tier scheduling, SLA-driven scheduling, threat-intelligence scheduling, AI-based remediation decisions, AI-based route selection, AI-based approval decisions, dynamic remediation-rule selection in n8n, risk-driven approval policy, or automatic recovery of stranded controller executions.

## V1 Invariant

The dispatcher decides when to deliver the next already-routed finding. It does not decide how that finding is remediated.

The controller and PostgreSQL remain authoritative for whether a remediation execution may exist and proceed.
