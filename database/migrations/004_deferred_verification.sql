BEGIN;

-- ============================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Deferred Stage 2 Verification
-- ============================================================


-- ------------------------------------------------------------
-- 1. Scanner refresh watermark
--
-- Records completion of an authoritative scanner state refresh.
-- A deferred Stage 2 verification may only make a security
-- decision when refresh_completed_at is later than the
-- remediation Stage 1 completion boundary.
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scanner_refresh_watermarks (
    watermark_id BIGSERIAL PRIMARY KEY,

    engine_source VARCHAR(64) NOT NULL,

    scanner_subject_type VARCHAR(32) NOT NULL,
    scanner_subject_id TEXT NOT NULL,

    refresh_id TEXT NOT NULL,

    refresh_started_at TIMESTAMPTZ,
    refresh_completed_at TIMESTAMPTZ NOT NULL,

    refresh_status VARCHAR(16) NOT NULL
        CHECK (
            refresh_status IN (
                'SUCCESS',
                'FAILED'
            )
        ),

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (
        engine_source,
        scanner_subject_type,
        scanner_subject_id,
        refresh_id
    )
);


CREATE INDEX IF NOT EXISTS
    idx_scanner_refresh_watermarks_lookup
ON scanner_refresh_watermarks (
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    refresh_completed_at DESC
)
WHERE refresh_status = 'SUCCESS';


-- ------------------------------------------------------------
-- 2. Deferred Stage 2 jobs
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS deferred_verification_jobs (
    deferred_job_id BIGSERIAL PRIMARY KEY,

    execution_id BIGINT NOT NULL
        REFERENCES remediation_executions(execution_id)
        ON DELETE CASCADE,

    finding_id BIGINT NOT NULL
        REFERENCES unified_security_findings(finding_id)
        ON DELETE CASCADE,

    verification_id BIGINT NOT NULL
        REFERENCES remediation_verifications(verification_id)
        ON DELETE CASCADE,

    engine_source VARCHAR(64) NOT NULL,

    scanner_subject_type VARCHAR(32) NOT NULL,
    scanner_subject_id TEXT NOT NULL,

    evidence_after TIMESTAMPTZ NOT NULL,

    status VARCHAR(24) NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'LEASED',
                'COMPLETED',
                'CANCELLED'
            )
        ),

    not_before TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    check_count INTEGER NOT NULL DEFAULT 0,

    lease_owner TEXT,
    lease_until TIMESTAMPTZ,

    last_watermark_id BIGINT
        REFERENCES scanner_refresh_watermarks(watermark_id),

    last_error TEXT,

    completed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (execution_id)
);


CREATE INDEX IF NOT EXISTS
    idx_deferred_verification_jobs_ready
ON deferred_verification_jobs (
    next_check_at,
    deferred_job_id
)
WHERE status = 'PENDING';


CREATE INDEX IF NOT EXISTS
    idx_deferred_verification_jobs_subject
ON deferred_verification_jobs (
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    status
);


COMMIT;
