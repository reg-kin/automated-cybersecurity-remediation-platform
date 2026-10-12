-- Migration 023: Manual Verification
--
-- Introduce explicit inconclusive verification and
-- execution-awaiting-manual-review states.
--
-- This migration must be tested against an isolated database
-- before deployment to production.

BEGIN;

-- Automated Stage 2 can finish inconclusively without
-- asserting that remediation succeeded or failed.
ALTER TABLE remediation_verifications
DROP CONSTRAINT IF EXISTS remediation_verifications_status_check;

ALTER TABLE remediation_verifications
ADD CONSTRAINT remediation_verifications_status_check
CHECK (
    status IN (
        'PENDING',
        'PASSED',
        'FAILED',
        'INCONCLUSIVE',
        'NOT_APPLICABLE'
    )
);

-- An execution can await independent human verification
-- without being incorrectly classified as FAILED.
ALTER TABLE remediation_executions
DROP CONSTRAINT IF EXISTS remediation_executions_status_check;

ALTER TABLE remediation_executions
ADD CONSTRAINT remediation_executions_status_check
CHECK (
    status IN (
        'QUEUED',
        'AWAITING_APPROVAL',
        'RUNNING',
        'STAGE1_PASSED',
        'VERIFYING',
        'AWAITING_MANUAL_VERIFICATION',
        'SUCCESS',
        'FAILED',
        'CANCELLED'
    )
);


-- Each manual review refers to one inconclusive Stage 2 verification.
CREATE TABLE manual_verification_reviews (
    review_id BIGSERIAL PRIMARY KEY,
    tenant_code VARCHAR(100) NOT NULL,
    finding_id BIGINT NOT NULL
        REFERENCES unified_security_findings(finding_id),
    execution_id BIGINT NOT NULL
        REFERENCES remediation_executions(execution_id),
    verification_id BIGINT NOT NULL UNIQUE
        REFERENCES remediation_verifications(verification_id),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'COMPLETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT manual_review_completion_check CHECK (
        (status = 'PENDING' AND completed_at IS NULL)
        OR
        (status = 'COMPLETED' AND completed_at IS NOT NULL)
    )
);

CREATE INDEX idx_manual_verification_reviews_pending
ON manual_verification_reviews (tenant_code, created_at)
WHERE status = 'PENDING';


-- Preserve the identity, evidence and justification for each decision.
-- Decision history is append-only at the application layer;
-- database-level immutability safeguards will be added separately.
CREATE TABLE manual_verification_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES manual_verification_reviews(review_id),
    tenant_code VARCHAR(100) NOT NULL,
    reviewer_id VARCHAR(200) NOT NULL
        CHECK (length(btrim(reviewer_id)) > 0),
    decision VARCHAR(30) NOT NULL
        CHECK (decision IN (
            'REMEDIATED',
            'STILL_PRESENT',
            'INCONCLUSIVE'
        )),
    justification TEXT NOT NULL
        CHECK (length(btrim(justification)) > 0),
    evidence JSONB NOT NULL
        CHECK (jsonb_typeof(evidence) = 'object'),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_manual_verification_decisions_review
ON manual_verification_decisions (review_id, decided_at);


-- Manual verification decisions are immutable audit records.
CREATE FUNCTION prevent_manual_verification_decision_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Manual verification decisions are immutable';
END;
$$;

CREATE TRIGGER trg_manual_verification_decisions_immutable
BEFORE UPDATE OR DELETE ON manual_verification_decisions
FOR EACH ROW
EXECUTE FUNCTION prevent_manual_verification_decision_mutation();


-- Validate tenant and remediation relationships when creating a review.
CREATE FUNCTION validate_manual_verification_review()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM unified_security_findings f
          JOIN remediation_executions e
            ON e.finding_id = f.finding_id
          JOIN remediation_verifications v
            ON v.execution_id = e.execution_id
           AND v.finding_id = f.finding_id
         WHERE f.finding_id = NEW.finding_id
           AND f.tenant_code = NEW.tenant_code
           AND f.lifecycle_status = 'IN_REMEDIATION'
           AND e.execution_id = NEW.execution_id
           AND e.status = 'AWAITING_MANUAL_VERIFICATION'
           AND v.verification_id = NEW.verification_id
           AND v.stage = 2
           AND v.status = 'INCONCLUSIVE'
    ) THEN
        RAISE EXCEPTION
            'Invalid manual verification tenant, finding, execution or Stage 2 context';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_manual_verification_review
BEFORE INSERT ON manual_verification_reviews
FOR EACH ROW
EXECUTE FUNCTION validate_manual_verification_review();


-- A decision must belong to the same tenant as its parent review.
ALTER TABLE manual_verification_reviews
ADD CONSTRAINT uq_manual_verification_review_tenant
UNIQUE (review_id, tenant_code);

ALTER TABLE manual_verification_decisions
ADD CONSTRAINT fk_manual_verification_decision_tenant
FOREIGN KEY (review_id, tenant_code)
REFERENCES manual_verification_reviews (review_id, tenant_code);


-- Individual reviewer credentials with tenant-scoped authorisation.
-- Store SHA-256 hashes of cryptographically random bearer tokens.
-- Never store plaintext tokens.
CREATE TABLE manual_verification_reviewer_credentials (
    credential_id BIGSERIAL PRIMARY KEY,
    reviewer_id VARCHAR(200) NOT NULL
        CHECK (length(btrim(reviewer_id)) > 0),
    tenant_code VARCHAR(100) NOT NULL
        CHECK (length(btrim(tenant_code)) > 0),
    token_hash CHAR(64) NOT NULL UNIQUE
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT manual_reviewer_credential_expiry_check
        CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT manual_reviewer_credential_revocation_check
        CHECK (revoked_at IS NULL OR is_active = FALSE)
);

CREATE INDEX idx_manual_reviewer_credentials_tenant
ON manual_verification_reviewer_credentials (tenant_code, reviewer_id)
WHERE is_active = TRUE;


-- Extend terminal verification outcomes without changing Stage 1 semantics.
-- Completed verification records remain immutable through this function.
CREATE OR REPLACE FUNCTION complete_remediation_verification(
    p_verification_id BIGINT,
    p_status TEXT,
    p_verification_result JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_affected_rows INTEGER;
BEGIN
    IF p_status IS NULL
       OR p_status NOT IN (
           'PASSED', 'FAILED', 'INCONCLUSIVE', 'NOT_APPLICABLE'
       ) THEN
        RAISE EXCEPTION
            'Invalid terminal verification status: %', p_status;
    END IF;

    IF p_status = 'INCONCLUSIVE'
       AND NOT EXISTS (
           SELECT 1
           FROM remediation_verifications
           WHERE verification_id = p_verification_id
             AND stage = 2
       ) THEN
        RAISE EXCEPTION
            'INCONCLUSIVE is permitted only for Stage 2 verification';
    END IF;

    UPDATE remediation_verifications
    SET
        status = p_status,
        verification_result = COALESCE(p_verification_result, '{}'::jsonb),
        verified_at = now()
    WHERE verification_id = p_verification_id
      AND status = 'PENDING';

    GET DIAGNOSTICS v_affected_rows = ROW_COUNT;

    RETURN v_affected_rows = 1;
END;
$$;

COMMIT;
