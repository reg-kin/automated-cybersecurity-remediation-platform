-- Migration 022
-- Restore database functions required by remediation verification.
--
-- Both functions operate within the caller's transaction.
-- Existing terminal verification results cannot be overwritten.

BEGIN;

CREATE OR REPLACE FUNCTION begin_remediation_verification(
    p_finding_id BIGINT,
    p_execution_id BIGINT,
    p_stage SMALLINT,
    p_verification_type TEXT,
    p_verification_source TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_verification_id BIGINT;
BEGIN
    IF p_stage IS NULL OR p_stage NOT IN (1, 2) THEN
        RAISE EXCEPTION 'Invalid verification stage: %', p_stage;
    END IF;

    IF NULLIF(BTRIM(p_verification_type), '') IS NULL
       OR NULLIF(BTRIM(p_verification_source), '') IS NULL THEN
        RAISE EXCEPTION 'Verification type and source are required';
    END IF;

    -- The verification must belong to the specified execution
    -- and finding. Lock the execution to serialize initiation.
    PERFORM 1
    FROM remediation_executions
    WHERE execution_id = p_execution_id
      AND finding_id = p_finding_id
      AND status IN ('RUNNING', 'STAGE1_PASSED', 'VERIFYING')
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Execution % is not eligible for verification of finding %',
            p_execution_id, p_finding_id;
    END IF;

    -- Prevent duplicate verification records for the same stage.
    IF EXISTS (
        SELECT 1
        FROM remediation_verifications
        WHERE execution_id = p_execution_id
          AND stage = p_stage
    ) THEN
        RAISE EXCEPTION
            'Verification stage % already exists for execution %',
            p_stage, p_execution_id;
    END IF;

    INSERT INTO remediation_verifications (
        finding_id,
        execution_id,
        stage,
        verification_type,
        verification_source,
        status
    )
    VALUES (
        p_finding_id,
        p_execution_id,
        p_stage,
        p_verification_type,
        p_verification_source,
        'PENDING'
    )
    RETURNING verification_id INTO v_verification_id;

    RETURN v_verification_id;
END;
$$;

CREATE OR REPLACE FUNCTION complete_remediation_verification(
    p_verification_id BIGINT,
    p_status TEXT,
    p_result JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_affected_rows INTEGER;
BEGIN
    IF p_status IS NULL
       OR p_status NOT IN ('PASSED', 'FAILED', 'NOT_APPLICABLE') THEN
        RAISE EXCEPTION 'Invalid terminal verification status: %', p_status;
    END IF;

    UPDATE remediation_verifications
    SET
        status = p_status,
        verification_result = COALESCE(p_result, '{}'::jsonb),
        verified_at = now()
    WHERE verification_id = p_verification_id
      AND status = 'PENDING';

    GET DIAGNOSTICS v_affected_rows = ROW_COUNT;

    RETURN v_affected_rows = 1;
END;
$$;

COMMIT;
