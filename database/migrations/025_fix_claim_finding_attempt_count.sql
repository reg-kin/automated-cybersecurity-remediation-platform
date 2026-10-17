-- Migration 025
-- Prevent remediation attempts from being counted when a finding
-- is claimed but remediation has not yet started.
--
-- The count_remediation_attempt() trigger remains responsible
-- for incrementing remediation_attempts when an execution
-- transitions to RUNNING.
--
-- This migration does not reset historical attempt counters.

BEGIN;

CREATE OR REPLACE FUNCTION public.claim_finding(
    p_finding_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $function$
DECLARE
    affected_rows INTEGER;
BEGIN
    UPDATE unified_security_findings
    SET
        lifecycle_status = 'IN_REMEDIATION',
        last_error = NULL,
        updated_at = now()
    WHERE
        finding_id = p_finding_id
        AND lifecycle_status = 'OPEN';

    GET DIAGNOSTICS affected_rows = ROW_COUNT;

    RETURN affected_rows = 1;
END;
$function$;

COMMIT;
