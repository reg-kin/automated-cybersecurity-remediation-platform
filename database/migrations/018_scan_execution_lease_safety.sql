BEGIN;

-- ---------------------------------------------------------------------------
-- Scan Execution Lease Safety V1
--
-- A scan_execution represents one auditable execution attempt.
--
-- Remote execution agents receive a cryptographically random opaque lease
-- token when a PENDING execution is leased. The plaintext token is returned
-- only to the agent; PostgreSQL stores only its SHA-256 hexadecimal digest.
--
-- Lease expiry is terminal for that execution attempt:
--
--     PENDING -> LEASED -> RUNNING -> SUCCEEDED / FAILED
--                       \-> EXPIRED
--
-- A retry is represented by a new scan_executions row. Expired execution
-- rows are never recycled to PENDING. This preserves execution-node and
-- historical attempt evidence.
-- ---------------------------------------------------------------------------

ALTER TABLE scan_executions
    ADD COLUMN lease_token_hash VARCHAR(64);

ALTER TABLE scan_executions
    ADD CONSTRAINT ck_scan_executions_lease_token_hash_format
    CHECK (
        lease_token_hash IS NULL
        OR lease_token_hash ~ '^[0-9a-f]{64}$'
    );

ALTER TABLE scan_executions
    ADD CONSTRAINT ck_scan_executions_lease_security_state
    CHECK (
        (
            status = 'PENDING'
            AND lease_token_hash IS NULL
        )
        OR
        (
            status IN ('LEASED', 'RUNNING')
            AND execution_node_id IS NOT NULL
            AND lease_token_hash IS NOT NULL
            AND leased_at IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at > leased_at
        )
        OR
        (
            status IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'EXPIRED')
            AND lease_token_hash IS NULL
        )
    );

COMMENT ON COLUMN scan_executions.lease_token_hash IS
    'SHA-256 hexadecimal digest of the current opaque lease bearer token. '
    'The plaintext lease token must never be persisted. It is present only '
    'while an execution is LEASED or RUNNING and is cleared on terminal transition.';

COMMENT ON CONSTRAINT ck_scan_executions_lease_security_state
    ON scan_executions IS
    'Active leases require a node, token hash and valid lease interval. '
    'Pending and terminal executions must not retain a lease token hash.';

COMMIT;
