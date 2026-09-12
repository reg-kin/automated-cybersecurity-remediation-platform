BEGIN;

-- ============================================================================
-- Scan Execution Context V1
--
-- Scanner orchestrators require a service tier as part of their normal scan
-- contract. Scan Coordination therefore stores service_tier on the policy and
-- snapshots it into each execution.
--
-- Canonical values are intentionally identical to
-- scanner_orchestrators/common/runtime.py:
--
--     GOLD
--     STANDARD
--     BRONZE
--
-- Existing pre-migration policies/executions did not carry this context, so
-- they are conservatively backfilled to the historical runtime default
-- STANDARD. New coordination code must explicitly preserve the policy value
-- when creating an execution.
-- ============================================================================


ALTER TABLE scan_policies
    ADD COLUMN service_tier VARCHAR(20);


UPDATE scan_policies
SET service_tier = 'STANDARD'
WHERE service_tier IS NULL;


ALTER TABLE scan_policies
    ALTER COLUMN service_tier SET NOT NULL;


ALTER TABLE scan_policies
    ADD CONSTRAINT ck_scan_policy_service_tier
        CHECK (
            service_tier IN (
                'GOLD',
                'STANDARD',
                'BRONZE'
            )
        );


ALTER TABLE scan_executions
    ADD COLUMN service_tier VARCHAR(20);


-- Existing executions pre-date service-tier snapshotting. Their parent
-- policies have just been backfilled to STANDARD above.
UPDATE scan_executions e
SET service_tier = p.service_tier
FROM scan_policies p
WHERE p.scan_policy_id = e.scan_policy_id
  AND e.service_tier IS NULL;


ALTER TABLE scan_executions
    ALTER COLUMN service_tier SET NOT NULL;


ALTER TABLE scan_executions
    ADD CONSTRAINT ck_scan_execution_service_tier
        CHECK (
            service_tier IN (
                'GOLD',
                'STANDARD',
                'BRONZE'
            )
        );


COMMENT ON COLUMN scan_policies.service_tier IS
    'Authoritative scanner service tier: GOLD, STANDARD or BRONZE.';


COMMENT ON COLUMN scan_executions.service_tier IS
    'Immutable snapshot of scan_policies.service_tier when the execution is created.';


COMMIT;
