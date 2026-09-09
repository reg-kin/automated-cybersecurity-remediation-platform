-- ============================================================================
-- RISK-AWARE REMEDIATION PRIORITISATION V1
-- ============================================================================
--
-- Purpose:
--   Provide a read-only operational ordering of findings that already have a
--   deterministic remediation route.
--
-- Architectural boundary:
--   - open_remediation_queue remains the authoritative remediation-routing
--     contract.
--   - remediation_rules.priority remains rule-selection priority and is not
--     reinterpreted as finding priority.
--   - contextual risk does not select remediation rules, capabilities,
--     playbooks, actions, automation tiers, or approval requirements.
--   - scanner severity remains separate from contextual risk.
--   - no priority state is persisted on unified_security_findings.
--
-- Ordering:
--   1. Findings with a scored ASSESSED/PARTIAL risk assessment.
--   2. Higher contextual risk score.
--   3. Older finding detection time.
--   4. Lower finding_id as the final deterministic tie-breaker.
--
-- UNSCORABLE findings and findings without a current risk assessment remain
-- visible, but follow findings with usable contextual risk.
-- ============================================================================


CREATE OR REPLACE VIEW prioritised_remediation_queue AS

SELECT
    q.*,

    ra.assessment_status,
    ra.contextual_risk_score,
    ra.contextual_risk_level,
    ra.assessment_model,
    ra.assessed_at,

    CASE
        WHEN ra.assessment_status IN ('ASSESSED', 'PARTIAL')
             AND ra.contextual_risk_score IS NOT NULL
        THEN TRUE
        ELSE FALSE
    END AS has_contextual_risk

FROM
    open_remediation_queue q

LEFT JOIN finding_risk_assessments ra
    ON ra.finding_id = q.finding_id
   AND ra.tenant_code = q.tenant_code;
