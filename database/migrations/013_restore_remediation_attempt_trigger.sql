BEGIN;

ALTER TABLE remediation_executions
ADD COLUMN IF NOT EXISTS attempt_counted BOOLEAN NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION public.count_remediation_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  IF NEW.status = 'RUNNING'
     AND NEW.attempt_counted = FALSE THEN

    UPDATE unified_security_findings
       SET remediation_attempts = remediation_attempts + 1,
           lifecycle_status = CASE
               WHEN lifecycle_status = 'OPEN'
               THEN 'IN_REMEDIATION'
               ELSE lifecycle_status
           END,
           last_error = NULL,
           updated_at = now()
     WHERE finding_id = NEW.finding_id;

    NEW.attempt_counted = TRUE;
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_count_remediation_attempt
ON remediation_executions;

CREATE TRIGGER trg_count_remediation_attempt
BEFORE INSERT OR UPDATE OF status
ON remediation_executions
FOR EACH ROW
EXECUTE FUNCTION count_remediation_attempt();

COMMIT;
