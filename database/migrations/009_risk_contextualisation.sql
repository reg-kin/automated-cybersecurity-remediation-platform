BEGIN;

-- ============================================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Deterministic Risk Contextualisation Foundation
--
-- Purpose:
--   1. Persist the current deterministic contextual risk assessment for a
--      security finding.
--   2. Keep scanner/native severity separate from platform-derived risk.
--   3. Preserve the asset context and calculation factors used by the
--      assessment for auditability.
--   4. Version the deterministic assessment model.
--
-- This migration is deliberately additive:
--   - the Unified Security Finding ingress contract is unchanged;
--   - scanner severity remains scanner/native evidence;
--   - ai_analysis remains advisory and is not authoritative risk state;
--   - finding identity, recurrence and lifecycle semantics are unchanged;
--   - unresolved findings may still receive PARTIAL assessments.
-- ============================================================================


ALTER TABLE unified_security_findings
    ADD CONSTRAINT uq_unified_security_findings_id_tenant
        UNIQUE (
            finding_id,
            tenant_code
        );


CREATE TABLE finding_risk_assessments (
    finding_id BIGINT PRIMARY KEY,

    tenant_code VARCHAR(100) NOT NULL,

    asset_id BIGINT NULL,

    assessment_status VARCHAR(20) NOT NULL
        CHECK (
            assessment_status IN (
                'ASSESSED',
                'PARTIAL',
                'UNSCORABLE'
            )
        ),

    base_severity_score NUMERIC(4,2) NULL
        CHECK (
            base_severity_score IS NULL
            OR (
                base_severity_score >= 0
                AND base_severity_score <= 10
            )
        ),

    base_severity_level VARCHAR(20) NULL
        CHECK (
            base_severity_level IS NULL
            OR base_severity_level IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    contextual_risk_score NUMERIC(4,2) NULL
        CHECK (
            contextual_risk_score IS NULL
            OR (
                contextual_risk_score >= 0
                AND contextual_risk_score <= 10
            )
        ),

    contextual_risk_level VARCHAR(20) NULL
        CHECK (
            contextual_risk_level IS NULL
            OR contextual_risk_level IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    assessment_factors JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    context_snapshot JSONB NULL,

    assessment_model VARCHAR(100) NOT NULL,

    assessed_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_risk_assessment_finding_tenant
        FOREIGN KEY (
            finding_id,
            tenant_code
        )
        REFERENCES unified_security_findings (
            finding_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT fk_risk_assessment_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE SET NULL (
            asset_id
        ),

    CONSTRAINT ck_risk_assessment_model
        CHECK (
            length(btrim(assessment_model)) > 0
        ),

    CONSTRAINT ck_risk_assessment_scored_state
        CHECK (
            (
                assessment_status IN (
                    'ASSESSED',
                    'PARTIAL'
                )
                AND contextual_risk_score IS NOT NULL
                AND contextual_risk_level IS NOT NULL
            )
            OR
            (
                assessment_status = 'UNSCORABLE'
                AND contextual_risk_score IS NULL
                AND contextual_risk_level IS NULL
            )
        )
);


CREATE INDEX idx_risk_assessments_tenant_level
    ON finding_risk_assessments (
        tenant_code,
        contextual_risk_level,
        contextual_risk_score DESC
    )
    WHERE contextual_risk_score IS NOT NULL;


CREATE INDEX idx_risk_assessments_asset
    ON finding_risk_assessments (
        asset_id,
        contextual_risk_score DESC
    )
    WHERE asset_id IS NOT NULL;


CREATE INDEX idx_risk_assessments_status
    ON finding_risk_assessments (
        tenant_code,
        assessment_status
    );


COMMIT;
