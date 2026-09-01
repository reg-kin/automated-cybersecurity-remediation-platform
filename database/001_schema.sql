CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================================
-- FINDING CLASS CATALOGUE
-- ============================================================================

CREATE TABLE finding_class_catalogue (
    finding_class VARCHAR(100) PRIMARY KEY,

    finding_category VARCHAR(30) NOT NULL
        CHECK (
            finding_category IN (
                'vulnerability',
                'compliance_drift',
                'integrity_drift',
                'rootkit'
            )
        ),

    description TEXT NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ============================================================================
-- UNIFIED SECURITY FINDINGS
-- ============================================================================

CREATE TABLE unified_security_findings (
    finding_id BIGSERIAL PRIMARY KEY,

    -- ------------------------------------------------------------------------
    -- Tenant / asset identity
    -- ------------------------------------------------------------------------

    tenant_code VARCHAR(100) NOT NULL,

    tenant_service_tier VARCHAR(50) NOT NULL,

    target_host VARCHAR(255) NOT NULL,

    engine_source VARCHAR(100) NOT NULL,

    -- ------------------------------------------------------------------------
    -- Finding identity
    -- ------------------------------------------------------------------------

    finding_category VARCHAR(30) NOT NULL
        CHECK (
            finding_category IN (
                'vulnerability',
                'compliance_drift',
                'integrity_drift',
                'rootkit'
            )
        ),

    finding_class VARCHAR(100) NOT NULL
        REFERENCES finding_class_catalogue(
            finding_class
        ),

    finding_key VARCHAR(500) NOT NULL,

    finding_title TEXT NOT NULL,

    -- ------------------------------------------------------------------------
    -- Lifecycle
    -- ------------------------------------------------------------------------

    lifecycle_status VARCHAR(30) NOT NULL
        DEFAULT 'OPEN'
        CHECK (
            lifecycle_status IN (
                'OPEN',
                'IN_REMEDIATION',
                'RESOLVED',
                'FALSE_POSITIVE'
            )
        ),

    -- First time this finding was ever detected.
    detected_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    -- Most recent scanner observation.
    last_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    -- Most recent successful remediation.
    remediated_at TIMESTAMPTZ NULL,

    -- Most recent actual verification event.
    -- This is NOT updated by Ollama enrichment.
    last_verified_at TIMESTAMPTZ NULL,

    -- Most recent time a RESOLVED finding was reopened.
    last_reopened_at TIMESTAMPTZ NULL,

    -- Number of times a RESOLVED finding has genuinely recurred.
    recurrence_count INTEGER NOT NULL
        DEFAULT 0
        CHECK (
            recurrence_count >= 0
        ),

    -- ------------------------------------------------------------------------
    -- Finding evaluation
    -- ------------------------------------------------------------------------

    compliance_result VARCHAR(20) NULL
        CHECK (
            compliance_result IN (
                'PASS',
                'FAIL',
                'NOT_APPLICABLE'
            )
        ),

    severity_level VARCHAR(20) NULL
        CHECK (
            severity_level IN (
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW'
            )
        ),

    severity_score NUMERIC(5,2) NULL
        CHECK (
            severity_score >= 0
            AND severity_score <= 10
        ),

    -- ------------------------------------------------------------------------
    -- Scanner / AI data
    -- ------------------------------------------------------------------------

    engine_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    ai_analysis JSONB NULL,

    -- ------------------------------------------------------------------------
    -- Remediation lifecycle
    -- ------------------------------------------------------------------------

    remediation_attempts INTEGER NOT NULL
        DEFAULT 0
        CHECK (
            remediation_attempts >= 0
        ),

    last_error TEXT NULL,

    -- ------------------------------------------------------------------------
    -- Database bookkeeping
    -- ------------------------------------------------------------------------

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    -- One logical active/history row per scanner identity.
    UNIQUE (
        tenant_code,
        target_host,
        engine_source,
        finding_key
    )
);


-- ============================================================================
-- REMEDIATION RULES
-- ============================================================================

CREATE TABLE remediation_rules (
    rule_id BIGSERIAL PRIMARY KEY,

    rule_name VARCHAR(150) NOT NULL UNIQUE,

    finding_class VARCHAR(100) NOT NULL
        REFERENCES finding_class_catalogue(
            finding_class
        ),

    -- Optional more-specific matching.
    finding_key_pattern TEXT NULL,

    engine_source VARCHAR(100) NULL,

    target_os_family VARCHAR(50) NULL,

    -- ------------------------------------------------------------------------
    -- Deterministic routing
    -- ------------------------------------------------------------------------

    capability VARCHAR(100) NOT NULL
        CHECK (
            capability IN (
                'os_patching',
                'container_image',
                'cis_hardening',
                'service_config',
                'web_application',
                'file_integrity',
                'security_incident'
            )
        ),

    playbook_name VARCHAR(100) NOT NULL,

    remediation_action VARCHAR(100) NOT NULL,

    -- Values are rendered by n8n from engine_metadata/finding context.
    parameter_template JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    required_parameters JSONB NOT NULL
        DEFAULT '[]'::jsonb,

    -- ------------------------------------------------------------------------
    -- Approval / automation policy
    -- ------------------------------------------------------------------------

    automation_tier VARCHAR(10) NOT NULL
        CHECK (
            automation_tier IN (
                'TIER_1',
                'TIER_2',
                'TIER_3'
            )
        ),

    approval_required BOOLEAN NOT NULL
        DEFAULT FALSE,

    priority INTEGER NOT NULL
        DEFAULT 100,

    enabled BOOLEAN NOT NULL
        DEFAULT TRUE,

    description TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now()
);


-- ============================================================================
-- REMEDIATION EXECUTIONS
-- ============================================================================

CREATE TABLE remediation_executions (
    execution_id BIGSERIAL PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES unified_security_findings(
            finding_id
        )
        ON DELETE RESTRICT,

    rule_id BIGINT NOT NULL
        REFERENCES remediation_rules(
            rule_id
        )
        ON DELETE RESTRICT,

    capability VARCHAR(100) NOT NULL,

    target_host TEXT NOT NULL,

    playbook_name TEXT NOT NULL,

    remediation_action TEXT NOT NULL,

    automation_tier TEXT NOT NULL
        CHECK (
            automation_tier IN (
                'TIER_1',
                'TIER_2',
                'TIER_3'
            )
        ),

    status TEXT NOT NULL
        CHECK (
            status IN (
                'QUEUED',
                'AWAITING_APPROVAL',
                'RUNNING',
                'STAGE1_PASSED',
                'VERIFYING',
                'SUCCESS',
                'FAILED',
                'CANCELLED'
            )
        ),

    ansible_job_id TEXT NULL,

    execution_parameters JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    result JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    error_message TEXT NULL,

    started_at TIMESTAMPTZ NULL,

    completed_at TIMESTAMPTZ NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now()
);


-- ============================================================================
-- REMEDIATION VERIFICATIONS
-- ============================================================================

CREATE TABLE remediation_verifications (
    verification_id BIGSERIAL PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES unified_security_findings(
            finding_id
        )
        ON DELETE RESTRICT,

    execution_id BIGINT NOT NULL
        REFERENCES remediation_executions(
            execution_id
        )
        ON DELETE RESTRICT,

    -- 1 = Ansible/local verification
    -- 2 = original scanner verification
    stage SMALLINT NOT NULL
        CHECK (
            stage IN (
                1,
                2
            )
        ),

    verification_type TEXT NOT NULL,

    verification_source TEXT NOT NULL,

    status TEXT NOT NULL
        CHECK (
            status IN (
                'PENDING',
                'PASSED',
                'FAILED',
                'NOT_APPLICABLE'
            )
        ),

    verification_result JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    verified_at TIMESTAMPTZ NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now()
);


-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX idx_findings_lifecycle
    ON unified_security_findings (
        lifecycle_status,
        severity_level,
        finding_id
    );


CREATE INDEX idx_findings_class
    ON unified_security_findings (
        finding_class
    );


CREATE INDEX idx_findings_engine
    ON unified_security_findings (
        engine_source
    );


CREATE INDEX idx_findings_target
    ON unified_security_findings (
        target_host
    );


CREATE INDEX idx_findings_last_seen
    ON unified_security_findings (
        last_seen_at DESC
    );


CREATE INDEX idx_findings_recurrence
    ON unified_security_findings (
        recurrence_count DESC
    )
    WHERE recurrence_count > 0;


CREATE INDEX idx_findings_metadata
    ON unified_security_findings
    USING GIN (
        engine_metadata
    );


CREATE INDEX idx_findings_ai
    ON unified_security_findings
    USING GIN (
        ai_analysis
    );


CREATE INDEX idx_rules_lookup
    ON remediation_rules (
        finding_class,
        enabled,
        priority DESC
    );


CREATE INDEX idx_execution_finding
    ON remediation_executions (
        finding_id,
        created_at DESC
    );


CREATE INDEX idx_execution_status
    ON remediation_executions (
        status,
        created_at DESC
    );


CREATE INDEX idx_verification_finding
    ON remediation_verifications (
        finding_id
    );


CREATE INDEX idx_verification_execution
    ON remediation_verifications (
        execution_id,
        stage
    );


-- ============================================================================
-- PREVENT TWO ACTIVE REMEDIATIONS OF THE SAME FINDING
-- ============================================================================

CREATE UNIQUE INDEX uq_one_active_execution_per_finding

    ON remediation_executions (
        finding_id
    )

    WHERE status IN (
        'QUEUED',
        'AWAITING_APPROVAL',
        'RUNNING',
        'STAGE1_PASSED',
        'VERIFYING'
    );


-- ============================================================================
-- CLAIM FINDING
-- ============================================================================

CREATE OR REPLACE FUNCTION claim_finding(
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
        lifecycle_status =
            'IN_REMEDIATION',

        remediation_attempts =
            remediation_attempts + 1,

        last_error =
            NULL,

        updated_at =
            now()

    WHERE
        finding_id =
            p_finding_id

        AND
        lifecycle_status =
            'OPEN';

    GET DIAGNOSTICS
        affected_rows =
            ROW_COUNT;

    RETURN
        affected_rows = 1;

END;

$$;


-- ============================================================================
-- MARK FINDING RESOLVED
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
        lifecycle_status =
            'RESOLVED',

        remediated_at =
            now(),

        last_verified_at =
            now(),

        last_error =
            NULL,

        updated_at =
            now()

    WHERE
        finding_id =
            p_finding_id

        AND
        lifecycle_status =
            'IN_REMEDIATION';

    GET DIAGNOSTICS
        affected_rows =
            ROW_COUNT;

    RETURN
        affected_rows = 1;

END;

$$;


-- ============================================================================
-- REOPEN FAILED REMEDIATION
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
        lifecycle_status =
            'OPEN',

        last_error =
            p_error,

        updated_at =
            now()

    WHERE
        finding_id =
            p_finding_id

        AND
        lifecycle_status =
            'IN_REMEDIATION';

    GET DIAGNOSTICS
        affected_rows =
            ROW_COUNT;

    RETURN
        affected_rows = 1;

END;

$$;


-- ============================================================================
-- OPEN REMEDIATION QUEUE
-- ============================================================================

CREATE OR REPLACE VIEW open_remediation_queue AS

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

    r.priority

FROM
    unified_security_findings f

JOIN LATERAL (

    SELECT
        rr.*

    FROM
        remediation_rules rr

    WHERE
        rr.enabled = TRUE

        AND
        rr.finding_class =
            f.finding_class

        AND (
            rr.engine_source IS NULL
            OR
            rr.engine_source =
                f.engine_source
        )

        AND (
            rr.finding_key_pattern IS NULL
            OR
            f.finding_key ~
                rr.finding_key_pattern
        )

        AND (
            rr.target_os_family IS NULL
            OR
            rr.target_os_family =
                COALESCE(
                    f.engine_metadata ->> 'os_family',
                    ''
                )
        )

    ORDER BY

        -- Most-specific rule wins.

        CASE
            WHEN rr.finding_key_pattern IS NOT NULL
            THEN 1
            ELSE 0
        END DESC,

        CASE
            WHEN rr.engine_source IS NOT NULL
            THEN 1
            ELSE 0
        END DESC,

        CASE
            WHEN rr.target_os_family IS NOT NULL
            THEN 1
            ELSE 0
        END DESC,

        rr.priority DESC,

        rr.rule_id ASC

    LIMIT 1

) r

ON TRUE

WHERE
    f.lifecycle_status =
        'OPEN';
