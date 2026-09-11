BEGIN;

-- ============================================================================
-- REMEDIATION EXECUTION TARGETS
-- ============================================================================
--
-- Scanner-native target_host remains evidence from the finding.
--
-- Automated remediation execution requires a separate, explicitly provisioned
-- management-plane target belonging to an ACTIVE, MANAGED canonical asset.
--
-- Merely discovering an identifier or endpoint never authorises remediation.
-- ============================================================================

CREATE TABLE asset_execution_targets (
    execution_target_id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    execution_target TEXT NOT NULL,

    is_active BOOLEAN NOT NULL
        DEFAULT TRUE,

    source VARCHAR(100) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_execution_targets_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT ck_asset_execution_targets_value
        CHECK (
            length(btrim(execution_target)) > 0
        ),

    CONSTRAINT uq_asset_execution_target_per_asset
        UNIQUE (
            asset_id,
            execution_target
        )
);


-- At most one active authorised execution destination may exist for an asset.
CREATE UNIQUE INDEX uq_asset_execution_targets_one_active
    ON asset_execution_targets (
        asset_id
    )
    WHERE is_active = TRUE;


CREATE INDEX idx_asset_execution_targets_tenant
    ON asset_execution_targets (
        tenant_code,
        asset_id
    )
    WHERE is_active = TRUE;


-- ============================================================================
-- EXECUTION-ELIGIBLE REMEDIATION QUEUE
-- ============================================================================
--
-- This view does not perform remediation routing or risk prioritisation.
--
-- It applies the management-plane safety gate to findings that have already
-- been routed and prioritised.
--
-- Eligibility requires:
--   1. a canonical asset binding;
--   2. ACTIVE asset lifecycle;
--   3. MANAGED inventory state;
--   4. exactly one active authorised execution target.
--
-- The partial unique index above guarantees that an asset cannot have more
-- than one active execution target.
-- ============================================================================

CREATE VIEW eligible_remediation_queue AS
SELECT
    q.*,
    f.asset_id,
    aet.execution_target
FROM prioritised_remediation_queue q
JOIN unified_security_findings f
  ON f.finding_id = q.finding_id
 AND f.tenant_code = q.tenant_code
JOIN assets a
  ON a.asset_id = f.asset_id
 AND a.tenant_code = f.tenant_code
JOIN asset_execution_targets aet
  ON aet.asset_id = a.asset_id
 AND aet.tenant_code = a.tenant_code
 AND aet.is_active = TRUE
WHERE a.inventory_state = 'MANAGED'
  AND a.lifecycle_status = 'ACTIVE';


COMMIT;
