BEGIN;

-- ============================================================
-- Automated Cybersecurity Remediation Platform
-- Deterministic Remediation Routing Hardening
--
-- Purpose:
--   1. Preserve the existing routing specificity hierarchy.
--   2. Prevent rule_id/insertion order from resolving an
--      equal-rank routing conflict.
--   3. Expose unambiguous findings through
--      open_remediation_queue.
--   4. Expose ambiguous findings through
--      ambiguous_remediation_queue.
--
-- Routing rank, highest first:
--   1. finding_key_pattern specificity
--   2. engine_source specificity
--   3. target_os_family specificity
--   4. priority
--
-- Equal rank across all four dimensions is treated as
-- ambiguous and is NOT routed for remediation.
-- ============================================================


-- ============================================================
-- 1. OPEN REMEDIATION QUEUE
--
-- IMPORTANT:
-- The output column contract is intentionally kept identical
-- to the previous open_remediation_queue view.
-- ============================================================

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
'OPEN findings having exactly one highest-ranked matching remediation rule. Equal-rank rule conflicts are withheld and exposed through ambiguous_remediation_queue.';


-- ============================================================
-- 2. AMBIGUOUS REMEDIATION QUEUE
--
-- One row per affected finding.
--
-- conflicting_rules contains every rule occupying the
-- highest routing rank. Lower-ranked fallback rules are
-- deliberately excluded because they are not responsible
-- for the ambiguity.
-- ============================================================

CREATE OR REPLACE VIEW ambiguous_remediation_queue AS
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
        r.finding_key_pattern AS rule_finding_key_pattern,
        r.engine_source AS rule_engine_source,
        r.target_os_family AS rule_target_os_family,
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

ambiguous_findings AS (
    SELECT
        finding_id
    FROM top_ranked_rules
    GROUP BY finding_id
    HAVING COUNT(*) > 1
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

    COUNT(*)::integer AS conflicting_rule_count,

    t.key_specificity,
    t.engine_specificity,
    t.os_specificity,
    t.priority AS winning_priority,

    JSONB_AGG(
        JSONB_BUILD_OBJECT(
            'rule_id',
            t.rule_id,

            'rule_name',
            t.rule_name,

            'finding_key_pattern',
            t.rule_finding_key_pattern,

            'engine_source',
            t.rule_engine_source,

            'target_os_family',
            t.rule_target_os_family,

            'capability',
            t.capability,

            'playbook_name',
            t.playbook_name,

            'remediation_action',
            t.remediation_action,

            'parameter_template',
            t.parameter_template,

            'required_parameters',
            t.required_parameters,

            'automation_tier',
            t.automation_tier,

            'approval_required',
            t.approval_required,

            'priority',
            t.priority
        )
        ORDER BY t.rule_id
    ) AS conflicting_rules

FROM top_ranked_rules t
JOIN ambiguous_findings a
  ON a.finding_id = t.finding_id

GROUP BY
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
    t.key_specificity,
    t.engine_specificity,
    t.os_specificity,
    t.priority;


COMMENT ON VIEW ambiguous_remediation_queue IS
'OPEN findings for which two or more matching remediation rules occupy the same highest routing rank. These findings are deliberately withheld from open_remediation_queue.';


COMMIT;
