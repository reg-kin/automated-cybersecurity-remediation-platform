BEGIN;

-- ============================================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Scan Execution Node Authentication V1
--
-- Purpose:
--   1. Provide centrally managed authentication credentials for scanner
--      execution nodes.
--   2. Allow the future Scan Coordination Agent API to derive node identity
--      from authenticated credentials rather than trusting caller-supplied
--      node_code values.
--   3. Store only SHA-256 digests of opaque agent credentials.
--   4. Support credential rotation and explicit revocation.
--
-- Security invariants:
--   - Plaintext agent credentials are never persisted.
--   - Credential hashes are lowercase 64-character SHA-256 hexadecimal values.
--   - Revoked credentials cannot authenticate.
--   - Disabled execution nodes cannot authenticate even when a credential
--     itself remains active.
--   - Multiple active credentials for one node are deliberately permitted so
--     controlled credential rotation can occur without an availability gap.
--   - Per-node credentials authenticate the execution node only. They do not
--     replace per-execution lease credentials.
-- ============================================================================


CREATE TABLE scan_execution_node_credentials (
    credential_id BIGSERIAL PRIMARY KEY,

    execution_node_id BIGINT NOT NULL,

    credential_hash VARCHAR(64) NOT NULL,

    is_active BOOLEAN NOT NULL
        DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    revoked_at TIMESTAMPTZ NULL,

    last_used_at TIMESTAMPTZ NULL,

    CONSTRAINT fk_scan_execution_node_credential_node
        FOREIGN KEY (
            execution_node_id
        )
        REFERENCES scan_execution_nodes (
            execution_node_id
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_execution_node_credential_hash
        UNIQUE (
            credential_hash
        ),

    CONSTRAINT ck_scan_execution_node_credential_hash
        CHECK (
            credential_hash ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT ck_scan_execution_node_credential_revocation
        CHECK (
            (
                is_active = TRUE
                AND revoked_at IS NULL
            )
            OR
            (
                is_active = FALSE
                AND revoked_at IS NOT NULL
            )
        ),

    CONSTRAINT ck_scan_execution_node_credential_last_used
        CHECK (
            last_used_at IS NULL
            OR last_used_at >= created_at
        )
);


CREATE INDEX idx_scan_execution_node_credentials_node
    ON scan_execution_node_credentials (
        execution_node_id,
        is_active,
        credential_id
    );


CREATE INDEX idx_scan_execution_node_credentials_active_hash
    ON scan_execution_node_credentials (
        credential_hash
    )
    WHERE is_active = TRUE;


COMMENT ON TABLE scan_execution_node_credentials IS
    'Authentication credentials for distributed scanner execution nodes. '
    'Only SHA-256 digests are stored; plaintext agent credentials must never '
    'be persisted. Multiple active credentials per node are allowed during '
    'controlled credential rotation.';


COMMENT ON COLUMN scan_execution_node_credentials.credential_hash IS
    'Lowercase SHA-256 hexadecimal digest of the opaque execution-node '
    'credential. The plaintext credential is returned only when issued.';


COMMENT ON COLUMN scan_execution_node_credentials.last_used_at IS
    'Timestamp of the most recent successful authentication using this '
    'credential. Failed authentication attempts do not update this value.';


COMMIT;
