from datetime import datetime, timezone

from remediation.shared import db
from remediation.shared.ansible_runner_client import (
    run as run_ansible,
)
from remediation.shared.verification_client import (
    verify as run_stage2,
)
from remediation.shared.config import SKIP_STAGE2


def utcnow():
    return datetime.now(timezone.utc)


def _metadata_false(value):
    """
    Normalise boolean-like scanner metadata.

    Scanner integrations may serialise capability flags as either
    JSON booleans or strings.
    """
    if value is False:
        return True

    if isinstance(value, str):
        return value.strip().lower() in (
            "false",
            "0",
            "no",
        )

    return False


def verification_strategy(p):
    """
    Select the Stage 2 verification strategy declared by scanner
    metadata.

    Deferred verification is deliberately opt-in. Findings retain
    the existing immediate Stage 2 behaviour unless the scanner
    explicitly declares asynchronous state refresh and explicitly
    declares that targeted verification is not supported.
    """
    metadata = p.get("engine_metadata") or {}

    capability = str(
        metadata.get("verification_capability") or ""
    ).strip().lower()

    targeted_supported = metadata.get(
        "targeted_verification_supported"
    )

    if (
        capability == "asynchronous_state_refresh"
        and _metadata_false(targeted_supported)
    ):
        return "DEFERRED"

    return "IMMEDIATE"


class BaseController:
    capability = None

    def validate(self, p, rule, finding):
        """
        Validate a remediation request before the finding is
        claimed and before an execution row is created.

        Three sources are deliberately distinguished:

        - p:
          caller-supplied execution request
        - rule:
          authoritative remediation_rules row
        - finding:
          authoritative unified_security_findings row

        n8n may render execution_parameters, but the controller
        independently verifies that the requested execution agrees
        with the persisted finding and remediation rule.
        """

        required = [
            "finding_id",
            "rule_id",
            "target_host",
            "engine_source",
            "finding_class",
            "finding_key",
            "capability",
            "playbook_name",
            "remediation_action",
            "automation_tier",
        ]

        missing = [
            field
            for field in required
            if p.get(field) in (None, "")
        ]

        if missing:
            raise ValueError(
                "Missing controller fields: "
                + ", ".join(missing)
            )

        if p["capability"] != self.capability:
            raise ValueError(
                f"Controller {self.capability} "
                "cannot handle capability "
                f"{p['capability']}"
            )

        if p["automation_tier"] not in {
            "TIER_1",
            "TIER_2",
            "TIER_3",
        }:
            raise ValueError(
                "Unsupported automation tier: "
                f"{p['automation_tier']}"
            )

        #
        # The persisted finding is authoritative.
        #
        finding_checks = {
            "target_host": finding["target_host"],
            "engine_source": finding["engine_source"],
            "finding_class": finding["finding_class"],
            "finding_key": finding["finding_key"],
        }

        for field, expected in finding_checks.items():
            if p[field] != expected:
                raise ValueError(
                    f"Controller payload {field} does not "
                    f"match finding {p['finding_id']}"
                )

        #
        # The persisted remediation rule is authoritative.
        #
        if not rule["enabled"]:
            raise ValueError(
                f"Remediation rule {rule['rule_id']} "
                "is disabled"
            )

        if (
            rule["finding_class"]
            != finding["finding_class"]
        ):
            raise ValueError(
                f"Remediation rule {rule['rule_id']} "
                "does not apply to finding class "
                f"{finding['finding_class']}"
            )

        rule_checks = {
            "capability": rule["capability"],
            "playbook_name": rule["playbook_name"],
            "remediation_action": (
                rule["remediation_action"]
            ),
            "automation_tier": rule["automation_tier"],
        }

        for field, expected in rule_checks.items():
            if p[field] != expected:
                raise ValueError(
                    f"Controller payload {field} does not "
                    "match remediation rule "
                    f"{rule['rule_id']}"
                )

        if (
            bool(p.get("approval_required"))
            != bool(rule["approval_required"])
        ):
            raise ValueError(
                "Controller payload approval_required "
                "does not match remediation rule "
                f"{rule['rule_id']}"
            )

        #
        # Tier 3 must remain approval gated.
        #
        if (
            rule["automation_tier"] == "TIER_3"
            and not rule["approval_required"]
        ):
            raise ValueError(
                f"Remediation rule {rule['rule_id']} "
                "is invalid: TIER_3 remediation must "
                "require human approval"
            )

        #
        # Initial remediation requests cannot bypass the
        # dedicated approval endpoint.
        #
        if p.get("approved") is True:
            raise ValueError(
                "Initial remediation requests cannot "
                "self-approve; use the execution approval "
                "endpoint"
            )

        #
        # Manual escalation is a workflow outcome, not an
        # executable Ansible remediation action.
        #
        if (
            rule["remediation_action"]
            == "manual_escalation"
        ):
            raise ValueError(
                "manual_escalation is a human remediation "
                "workflow and cannot be executed by the "
                "remediation controller"
            )

        execution_parameters = (
            p.get("execution_parameters")
            or {}
        )

        if not isinstance(
            execution_parameters,
            dict,
        ):
            raise ValueError(
                "execution_parameters must be "
                "a JSON object"
            )

        missing_parameters = []

        for name in rule["required_parameters"]:
            if not isinstance(name, str) or not name:
                raise ValueError(
                    f"Remediation rule {rule['rule_id']} "
                    "contains an invalid required "
                    "parameter name"
                )

            if name not in execution_parameters:
                missing_parameters.append(name)
                continue

            value = execution_parameters[name]

            if value is None:
                missing_parameters.append(name)
                continue

            if (
                isinstance(value, str)
                and not value.strip()
            ):
                missing_parameters.append(name)

        if missing_parameters:
            raise ValueError(
                "Missing required execution parameters "
                f"for rule {rule['rule_id']}: "
                + ", ".join(missing_parameters)
            )

    def execute(self, p):
        """
        Validate and create a remediation execution.

        Validation occurs before the finding is claimed and
        before an execution row is created.

        Approval-gated remediations are created as
        AWAITING_APPROVAL and return without invoking Ansible.

        Immediate remediations continue directly into the
        existing execution pipeline.
        """

        conn = db.connect()
        execution_id = None

        try:
            if p.get("rule_id") in (None, ""):
                raise ValueError(
                    "Missing controller fields: rule_id"
                )

            #
            # Read both authoritative records before making
            # any state transition.
            #
            with conn:
                rule = db.get_remediation_rule(
                    conn,
                    p["rule_id"],
                )

                finding = db.get_finding(
                    conn,
                    p["finding_id"],
                )

            #
            # Critically, this is before ensure_claimed()
            # and create_execution().
            #
            self.validate(
                p,
                rule,
                finding,
            )

            approval_required = bool(
                rule["approval_required"]
            )

            with conn:
                db.ensure_claimed(
                    conn,
                    p["finding_id"],
                )

                create_payload = dict(p)

                create_payload[
                    "initial_status"
                ] = (
                    "AWAITING_APPROVAL"
                    if approval_required
                    else "QUEUED"
                )

                execution_id = (
                    db.create_execution(
                        conn,
                        create_payload,
                    )
                )

            if approval_required:
                return {
                    "success": True,
                    "execution_id": execution_id,
                    "status": (
                        "AWAITING_APPROVAL"
                    ),
                    "approval_required": True,
                    "executed": False,
                }

            return self.execute_existing(
                p,
                execution_id,
            )

        finally:
            conn.close()

    def approve(
        self,
        execution_id,
    ):
        """
        Approve an existing AWAITING_APPROVAL execution.

        The execution is locked and transitioned to RUNNING
        before releasing the transaction so simultaneous
        approval requests cannot launch remediation twice.
        """

        conn = db.connect()

        try:
            with conn:
                execution = (
                    db.get_execution_for_approval(
                        conn,
                        execution_id,
                    )
                )

                if (
                    execution["capability"]
                    != self.capability
                ):
                    raise ValueError(
                        f"Execution {execution_id} "
                        "belongs to capability "
                        f"{execution['capability']}"
                    )

                if (
                    execution["status"]
                    != "AWAITING_APPROVAL"
                ):
                    raise RuntimeError(
                        f"Execution {execution_id} "
                        "is not awaiting approval; "
                        "current status is "
                        f"{execution['status']}"
                    )

                finding = db.get_finding(
                    conn,
                    execution["finding_id"],
                )

                if (
                    finding["lifecycle_status"]
                    != "IN_REMEDIATION"
                ):
                    raise RuntimeError(
                        f"Finding "
                        f"{execution['finding_id']} "
                        "is not in remediation; "
                        "current state is "
                        f"{finding['lifecycle_status']}"
                    )

                db.update_execution_status(
                    conn,
                    execution_id,
                    "RUNNING",
                    started_at=utcnow(),
                )

                execution_payload = {
                    "finding_id": (
                        execution["finding_id"]
                    ),
                    "rule_id": (
                        execution["rule_id"]
                    ),
                    "target_host": (
                        execution["target_host"]
                    ),
                    "engine_source": (
                        finding["engine_source"]
                    ),
                    "finding_class": (
                        finding["finding_class"]
                    ),
                    "finding_key": (
                        finding["finding_key"]
                    ),
                    "capability": (
                        execution["capability"]
                    ),
                    "playbook_name": (
                        execution["playbook_name"]
                    ),
                    "remediation_action": (
                        execution[
                            "remediation_action"
                        ]
                    ),
                    "automation_tier": (
                        execution["automation_tier"]
                    ),
                    "execution_parameters": (
                        execution[
                            "execution_parameters"
                        ]
                        or {}
                    ),
                    "engine_metadata": (
                        finding["engine_metadata"]
                        or {}
                    ),
                    "approval_required": True,
                    "approved": True,
                }

            return self.execute_existing(
                execution_payload,
                execution_id,
                already_running=True,
            )

        finally:
            conn.close()

    def execute_existing(
        self,
        p,
        execution_id,
        already_running=False,
    ):
        """
        Execute remediation against an execution row that
        already exists.

        Used for both immediate remediation and continuation
        of an approved execution.
        """

        conn = db.connect()

        try:
            if not already_running:
                with conn:
                    db.update_execution_status(
                        conn,
                        execution_id,
                        "RUNNING",
                        started_at=utcnow(),
                    )

            extra = {
                **(
                    p.get(
                        "execution_parameters"
                    )
                    or {}
                ),
                "finding_id": p["finding_id"],
                "execution_id": execution_id,
                "remediation_action": (
                    p["remediation_action"]
                ),
            }

            # Stage 1 verification row is created before
            # Ansible execution and completed in place.
            with conn:
                stage1_id = db.begin_verification(
                    conn,
                    p["finding_id"],
                    execution_id,
                    1,
                    "ANSIBLE_LOCAL",
                    "ansible",
                )

            try:
                ansible = run_ansible(
                    p["playbook_name"],
                    p["target_host"],
                    extra,
                )

            except Exception as exc:
                with conn:
                    db.complete_verification(
                        conn,
                        stage1_id,
                        "FAILED",
                        {
                            "passed": False,
                            "error": str(exc),
                        },
                    )

                    db.update_execution_status(
                        conn,
                        execution_id,
                        "FAILED",
                        error_message=(
                            "Ansible execution failed: "
                            f"{exc}"
                        ),
                        completed_at=utcnow(),
                    )

                    db.reopen_failed(
                        conn,
                        p["finding_id"],
                        (
                            "Ansible execution failed: "
                            f"{exc}"
                        ),
                    )

                return {
                    "success": False,
                    "execution_id": execution_id,
                    "stage1": {
                        "status": "FAILED",
                    },
                    "error": str(exc),
                }

            stage1 = (
                ansible.get("verification")
                or {}
            )

            stage1_passed = (
                bool(ansible.get("success"))
                and bool(
                    stage1.get("passed")
                )
            )

            with conn:
                db.complete_verification(
                    conn,
                    stage1_id,
                    (
                        "PASSED"
                        if stage1_passed
                        else "FAILED"
                    ),
                    stage1 or ansible,
                )

                if not stage1_passed:
                    db.update_execution_status(
                        conn,
                        execution_id,
                        "FAILED",
                        ansible_job_id=(
                            ansible.get("job_id")
                        ),
                        result={
                            "ansible": ansible,
                        },
                        error_message=(
                            "Stage 1 verification failed"
                        ),
                        completed_at=utcnow(),
                    )

                    db.reopen_failed(
                        conn,
                        p["finding_id"],
                        (
                            "Stage 1 "
                            "verification failed"
                        ),
                    )

                    return {
                        "success": False,
                        "execution_id": execution_id,
                        "stage1": {
                            "status": "FAILED",
                            "result": stage1,
                        },
                    }

                db.update_execution_status(
                    conn,
                    execution_id,
                    "STAGE1_PASSED",
                    ansible_job_id=(
                        ansible.get("job_id")
                    ),
                    result={
                        "ansible": ansible,
                    },
                )

            #
            # Stage 1 is now durably complete. A deferred
            # scanner refresh must complete strictly after
            # this evidence boundary before it can determine
            # PRESENT or ABSENT.
            #
            evidence_after = utcnow()

            if SKIP_STAGE2:
                return {
                    "success": True,
                    "execution_id": execution_id,
                    "stage1": {
                        "status": "PASSED",
                        "result": stage1,
                    },
                    "stage2": {
                        "status": (
                            "SKIPPED_TEST_MODE"
                        ),
                    },
                }

            #
            # Verification strategy is scanner-declared.
            #
            # Existing scanners remain IMMEDIATE unless their
            # metadata explicitly declares asynchronous state
            # refresh with no targeted verification support.
            #
            strategy = verification_strategy(p)

            scanner_subject_id = None

            if strategy == "DEFERRED":
                metadata = (
                    p.get("engine_metadata")
                    or {}
                )

                scanner_subject_id = (
                    metadata.get("agent_id")
                )

                if scanner_subject_id is None:
                    raise RuntimeError(
                        "Deferred verification requires "
                        "engine_metadata.agent_id"
                    )

                scanner_subject_id = str(
                    scanner_subject_id
                ).strip()

                if not scanner_subject_id:
                    raise RuntimeError(
                        "Deferred verification requires "
                        "non-empty engine_metadata.agent_id"
                    )

            #
            # Stage 2 evidence row exists for both immediate
            # and deferred verification. Deferred verification
            # leaves this row PENDING until the reconciler has
            # fresh authoritative scanner evidence.
            #
            with conn:
                stage2_id = db.begin_verification(
                    conn,
                    p["finding_id"],
                    execution_id,
                    2,
                    "SCANNER_RESCAN",
                    p["engine_source"],
                )

                db.update_execution_status(
                    conn,
                    execution_id,
                    "VERIFYING",
                )

                if strategy == "DEFERRED":
                    deferred_job = (
                        db.create_deferred_verification_job(
                            conn,
                            execution_id=execution_id,
                            finding_id=p["finding_id"],
                            verification_id=stage2_id,
                            engine_source=(
                                p["engine_source"]
                            ),
                            scanner_subject_type=(
                                "wazuh_agent"
                            ),
                            scanner_subject_id=(
                                scanner_subject_id
                            ),
                            evidence_after=(
                                evidence_after
                            ),
                        )
                    )

            #
            # Deferred Stage 2 ends controller processing here.
            #
            # No verification-gateway request is made. The
            # execution remains VERIFYING and the finding
            # remains IN_REMEDIATION until the deferred
            # reconciler obtains fresh post-remediation
            # scanner evidence.
            #
            if strategy == "DEFERRED":
                return {
                    "success": True,
                    "executed": True,
                    "execution_id": execution_id,
                    "status": "VERIFYING",
                    "verification_strategy": (
                        "DEFERRED"
                    ),
                    "stage1": {
                        "status": "PASSED",
                        "result": stage1,
                    },
                    "stage2": {
                        "status": "PENDING",
                        "verification_id": (
                            stage2_id
                        ),
                        "deferred_job_id": (
                            deferred_job[0]
                        ),
                        "scanner_subject_type": (
                            "wazuh_agent"
                        ),
                        "scanner_subject_id": (
                            scanner_subject_id
                        ),
                        "evidence_after": (
                            evidence_after.isoformat()
                        ),
                    },
                }

            #
            # Existing immediate Stage 2 path.
            #
            verification_payload = {
                "finding_id": p["finding_id"],
                "execution_id": execution_id,
                "target_host": p["target_host"],
                "engine_source": (
                    p["engine_source"]
                ),
                "finding_class": (
                    p["finding_class"]
                ),
                "finding_key": p["finding_key"],
                "engine_metadata": (
                    p.get("engine_metadata")
                    or {}
                ),
                "verification_type": (
                    "SCANNER_RESCAN"
                ),
            }

            try:
                scanner = run_stage2(
                    verification_payload
                )

                stage2_passed = (
                    scanner.get(
                        "verification_status"
                    )
                    == "PASSED"
                    and scanner.get("present")
                    is False
                )

                with conn:
                    db.complete_verification(
                        conn,
                        stage2_id,
                        (
                            "PASSED"
                            if stage2_passed
                            else "FAILED"
                        ),
                        scanner,
                    )

                    if stage2_passed:
                        db.update_execution_status(
                            conn,
                            execution_id,
                            "SUCCESS",
                            result={
                                "ansible": ansible,
                                "scanner": scanner,
                            },
                            completed_at=utcnow(),
                        )

                        db.resolve_finding(
                            conn,
                            p["finding_id"],
                        )

                    else:
                        db.update_execution_status(
                            conn,
                            execution_id,
                            "FAILED",
                            result={
                                "ansible": ansible,
                                "scanner": scanner,
                            },
                            error_message=(
                                "Stage 2 scanner "
                                "verification failed"
                            ),
                            completed_at=utcnow(),
                        )

                        db.reopen_failed(
                            conn,
                            p["finding_id"],
                            (
                                "Stage 2 scanner "
                                "verification failed"
                            ),
                        )

                return {
                    "success": stage2_passed,
                    "execution_id": execution_id,
                    "stage1": {
                        "status": "PASSED",
                        "result": stage1,
                    },
                    "stage2": scanner,
                    "error": (
                        None
                        if stage2_passed
                        else (
                            "Stage 2 scanner "
                            "verification failed"
                        )
                    ),
                }

            except Exception as exc:
                fail = {
                    "present": True,
                    "verification_status": (
                        "FAILED"
                    ),
                    "verification_error": (
                        str(exc)
                    ),
                }

                with conn:
                    db.complete_verification(
                        conn,
                        stage2_id,
                        "FAILED",
                        fail,
                    )

                    db.update_execution_status(
                        conn,
                        execution_id,
                        "FAILED",
                        result={
                            "ansible": ansible,
                            "scanner": fail,
                        },
                        error_message=(
                            "Stage 2 infrastructure "
                            f"error: {exc}"
                        ),
                        completed_at=utcnow(),
                    )

                    db.reopen_failed(
                        conn,
                        p["finding_id"],
                        (
                            "Stage 2 infrastructure "
                            f"error: {exc}"
                        ),
                    )

                return {
                    "success": False,
                    "execution_id": execution_id,
                    "stage1": {
                        "status": "PASSED",
                        "result": stage1,
                    },
                    "stage2": fail,
                    "error": str(exc),
                }

        finally:
            conn.close()
