-- Administrative audit history for scan-policy management.
-- Historical records remain independent of operational scan policies.

CREATE TABLE scan_policy_admin_audit (
    audit_id BIGSERIAL PRIMARY KEY,

    scan_policy_id BIGINT NOT NULL,
    tenant_code VARCHAR(100) NOT NULL,

    action VARCHAR(40) NOT NULL
        CHECK (
            action IN (
                'CREATE',
                'UPDATE_CONFIGURATION',
                'ENABLE',
                'DISABLE'
            )
        ),

    performed_by VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,

    before_state JSONB,
    after_state JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT scan_policy_admin_audit_tenant_nonblank
        CHECK (length(btrim(tenant_code)) > 0),

    CONSTRAINT scan_policy_admin_audit_actor_nonblank
        CHECK (length(btrim(performed_by)) > 0),

    CONSTRAINT scan_policy_admin_audit_reason_nonblank
        CHECK (length(btrim(reason)) > 0),

    CONSTRAINT scan_policy_admin_audit_policy_id_positive
        CHECK (scan_policy_id > 0)
);

CREATE INDEX idx_scan_policy_admin_audit_history
    ON scan_policy_admin_audit (
        tenant_code,
        scan_policy_id,
        audit_id
    );
