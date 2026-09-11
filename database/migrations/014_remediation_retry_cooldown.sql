BEGIN;

-- ============================================================================
-- REMEDIATION RETRY COOLDOWN
--
-- Prevent a failed remediation from being immediately redispatched on every
-- dispatcher timer invocation.
--
-- Semantics:
--   NULL            -> immediately eligible
--   future timestamp -> temporarily withheld from remediation routing
--   due/past timestamp -> eligible again
--
-- This does not introduce a new lifecycle state. Findings remain OPEN while
-- waiting for retry eligibility.
-- ============================================================================

ALTER TABLE unified_security_findings
ADD COLUMN IF NOT EXISTS next_remediation_attempt_at TIMESTAMPTZ NULL;


-- ============================================================================
-- SUCCESSFUL REMEDIATION
--
-- A successfully resolved finding must not retain any retry cooldown.
-- ============================================================================

CREATE OR REPLACE FUNCTION resolve_finding(
    p_finding_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    affected_rows INTEGER;
BEGIN

    UPDATE unified_security_findings
    SET
        lifecycle_status = 'RESOLVED',
        remediated_at = now(),
        last_verified_at = now(),
        last_error = NULL,
        next_remediation_attempt_at = NULL,
        updated_at = now()
    WHERE finding_id = p_finding_id
      AND lifecycle_status = 'IN_REMEDIATION';

    GET DIAGNOSTICS
        affected_rows = ROW_COUNT;

    RETURN affected_rows = 1;

END;
$$;


-- ============================================================================
-- FAILED REMEDIATION
--
-- A failed execution returns the finding to OPEN, but with a deterministic
-- five-minute retry cooldown.
--
-- The dispatcher remains stateless and contains no retry scheduler.
-- ============================================================================

CREATE OR REPLACE FUNCTION reopen_failed_remediation(
    p_finding_id BIGINT,
    p_error TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    affected_rows INTEGER;
BEGIN

    UPDATE unified_security_findings
    SET
        lifecycle_status = 'OPEN',
        last_error = p_error,
        next_remediation_attempt_at = now() + INTERVAL '5 minutes',
        updated_at = now()
    WHERE finding_id = p_finding_id
      AND lifecycle_status = 'IN_REMEDIATION';

    GET DIAGNOSTICS
        affected_rows = ROW_COUNT;

    RETURN affected_rows = 1;

END;
$$;


-- ============================================================================
-- OPEN REMEDIATION QUEUE
--
-- Preserve the existing hardened deterministic routing algorithm exactly.
-- The only new behaviour is retry eligibility filtering.
-- ============================================================================

CREATE OR REPLACE VIEW open_remediation_queue AS
WITH matching_rules AS (
    SELECT
        f.finding_id,
        f.tenant_code,
        f.tenant_service_tier,
        f.target_host,
        f.engine_source,
        f.finding_category,
        f.finding_class,
        f.finding_key,
        f.finding_title,
        f.severity_level,
        f.severity_score,
        f.detected_at,
        f.last_seen_at,
        f.recurrence_count,
        f.last_reopened_at,
        f.engine_metadata,
        f.ai_analysis,

        r.rule_id,
        r.rule_name,
        r.capability,
        r.playbook_name,
        r.remediation_action,
        r.parameter_template,
        r.required_parameters,
        r.automation_tier,
        r.approval_required,
        r.priority,

        CASE
            WHEN r.finding_key_pattern IS NOT NULL THEN 1
            ELSE 0
        END AS key_specificity,

        CASE
            WHEN r.engine_source IS NOT NULL THEN 1
            ELSE 0
        END AS engine_specificity,

        CASE
            WHEN r.target_os_family IS NOT NULL THEN 1
            ELSE 0
        END AS os_specificity

    FROM unified_security_findings f
    JOIN remediation_rules r
      ON r.enabled = true
     AND r.finding_class = f.finding_class

     AND (
            r.engine_source IS NULL
            OR r.engine_source = f.engine_source
         )

     AND (
            r.finding_key_pattern IS NULL
            OR f.finding_key ~ r.finding_key_pattern
         )

     AND (
            r.target_os_family IS NULL
            OR r.target_os_family =
               COALESCE(
                   f.engine_metadata ->> 'os_family',
                   ''
               )
         )

    WHERE f.lifecycle_status = 'OPEN'
      AND (
            f.next_remediation_attempt_at IS NULL
            OR f.next_remediation_attempt_at <= now()
          )
),

ranked_matches AS (
    SELECT
        mr.*,

        DENSE_RANK() OVER (
            PARTITION BY mr.finding_id
            ORDER BY
                mr.key_specificity DESC,
                mr.engine_specificity DESC,
                mr.os_specificity DESC,
                mr.priority DESC
        ) AS routing_rank

    FROM matching_rules mr
),

top_ranked_rules AS (
    SELECT *
    FROM ranked_matches
    WHERE routing_rank = 1
),

top_rank_counts AS (
    SELECT
        finding_id,
        COUNT(*) AS top_rule_count
    FROM top_ranked_rules
    GROUP BY finding_id
)

SELECT
    t.finding_id,
    t.tenant_code,
    t.tenant_service_tier,
    t.target_host,
    t.engine_source,
    t.finding_category,
    t.finding_class,
    t.finding_key,
    t.finding_title,
    t.severity_level,
    t.severity_score,
    t.detected_at,
    t.last_seen_at,
    t.recurrence_count,
    t.last_reopened_at,
    t.engine_metadata,
    t.ai_analysis,

    t.rule_id,
    t.rule_name,
    t.capability,
    t.playbook_name,
    t.remediation_action,
    t.parameter_template,
    t.required_parameters,
    t.automation_tier,
    t.approval_required,
    t.priority

FROM top_ranked_rules t
JOIN top_rank_counts c
  ON c.finding_id = t.finding_id

WHERE c.top_rule_count = 1;


COMMENT ON VIEW open_remediation_queue IS
'OPEN findings currently eligible for remediation and having exactly one highest-ranked matching remediation rule. Failed remediations are withheld until next_remediation_attempt_at is due. Equal-rank rule conflicts are withheld and exposed through ambiguous_remediation_queue.';

COMMIT;
