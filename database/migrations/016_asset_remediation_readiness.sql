BEGIN;

-- ============================================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Asset Remediation Readiness V1
--
-- Purpose:
--   1. Make remediation authorisation explicit and auditable.
--   2. Separate asset discovery from permission to remediate.
--   3. Separate scanner-native target evidence from authorised execution
--      destinations.
--   4. Ensure remediation eligibility requires explicit asset and execution-
--      target authorisation.
--   5. Preserve historical readiness decisions in an append-only audit log.
--
-- Safety invariants:
--   - Asset discovery/resolution MUST NOT authorise remediation.
--   - PROVISIONAL assets are not remediation-ready.
--   - MANAGED status requires explicit management authorisation for all new
--     or changed readiness state.
--   - An active execution target requires explicit target authorisation for
--     all new or changed readiness state.
--   - Legacy MANAGED assets or active execution targets are NOT silently
--     treated as authorised by this migration.
--   - eligible_remediation_queue remains downstream of deterministic routing
--     and risk-aware prioritisation.
--   - Scanner-native target_host remains evidence and is never converted into
--     an execution target by this migration.
-- ============================================================================


-- ============================================================================
-- 1. ASSET MANAGEMENT AUTHORISATION
-- ============================================================================

ALTER TABLE assets
    ADD COLUMN management_authorised_at TIMESTAMPTZ,
    ADD COLUMN management_authorised_by VARCHAR(255),
    ADD COLUMN management_authorisation_reason TEXT,
    ADD COLUMN management_revoked_at TIMESTAMPTZ,
    ADD COLUMN management_revoked_by VARCHAR(255),
    ADD COLUMN management_revocation_reason TEXT;


ALTER TABLE assets
    ADD CONSTRAINT ck_assets_management_authorised_by_nonblank
        CHECK (
            management_authorised_by IS NULL
            OR length(btrim(management_authorised_by)) > 0
        ),

    ADD CONSTRAINT ck_assets_management_authorisation_reason_nonblank
        CHECK (
            management_authorisation_reason IS NULL
            OR length(btrim(management_authorisation_reason)) > 0
        ),

    ADD CONSTRAINT ck_assets_management_revoked_by_nonblank
        CHECK (
            management_revoked_by IS NULL
            OR length(btrim(management_revoked_by)) > 0
        ),

    ADD CONSTRAINT ck_assets_management_revocation_reason_nonblank
        CHECK (
            management_revocation_reason IS NULL
            OR length(btrim(management_revocation_reason)) > 0
        ),

    ADD CONSTRAINT ck_assets_management_authorisation_triplet
        CHECK (
            (
                management_authorised_at IS NULL
                AND management_authorised_by IS NULL
                AND management_authorisation_reason IS NULL
            )
            OR
            (
                management_authorised_at IS NOT NULL
                AND management_authorised_by IS NOT NULL
                AND management_authorisation_reason IS NOT NULL
            )
        ),

    ADD CONSTRAINT ck_assets_management_revocation_triplet
        CHECK (
            (
                management_revoked_at IS NULL
                AND management_revoked_by IS NULL
                AND management_revocation_reason IS NULL
            )
            OR
            (
                management_revoked_at IS NOT NULL
                AND management_revoked_by IS NOT NULL
                AND management_revocation_reason IS NOT NULL
            )
        ),

    ADD CONSTRAINT ck_assets_management_revocation_order
        CHECK (
            management_revoked_at IS NULL
            OR (
                management_authorised_at IS NOT NULL
                AND management_revoked_at >= management_authorised_at
            )
        );


-- Existing legacy rows are deliberately not back-filled with synthetic
-- authorisation metadata. Doing so would incorrectly turn historical state
-- into evidence of an explicit administrative authorisation.
--
-- State-dependent enforcement is therefore implemented with a trigger.
-- Existing legacy rows remain readable, but any new/changed readiness state
-- must satisfy the V1 authorisation contract.

CREATE OR REPLACE FUNCTION enforce_asset_management_authorisation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.inventory_state = 'MANAGED' THEN

        IF NEW.management_authorised_at IS NULL
           OR NEW.management_authorised_by IS NULL
           OR length(btrim(NEW.management_authorised_by)) = 0
           OR NEW.management_authorisation_reason IS NULL
           OR length(btrim(NEW.management_authorisation_reason)) = 0 THEN

            RAISE EXCEPTION
                'MANAGED asset % requires explicit management authorisation',
                NEW.asset_id;
        END IF;

        IF NEW.management_revoked_at IS NOT NULL
           OR NEW.management_revoked_by IS NOT NULL
           OR NEW.management_revocation_reason IS NOT NULL THEN

            RAISE EXCEPTION
                'MANAGED asset % cannot have revoked management authorisation',
                NEW.asset_id;
        END IF;

    ELSE

        -- If an asset has previously been authorised but is no longer
        -- MANAGED, that authorisation must be explicitly revoked.
        IF NEW.management_authorised_at IS NOT NULL
           AND (
               NEW.management_revoked_at IS NULL
               OR NEW.management_revoked_by IS NULL
               OR length(btrim(NEW.management_revoked_by)) = 0
               OR NEW.management_revocation_reason IS NULL
               OR length(btrim(NEW.management_revocation_reason)) = 0
           ) THEN

            RAISE EXCEPTION
                'Asset % leaving MANAGED state requires explicit management revocation',
                NEW.asset_id;
        END IF;

    END IF;

    RETURN NEW;
END;
$function$;


CREATE TRIGGER trg_enforce_asset_management_authorisation
BEFORE INSERT OR UPDATE OF
    inventory_state,
    management_authorised_at,
    management_authorised_by,
    management_authorisation_reason,
    management_revoked_at,
    management_revoked_by,
    management_revocation_reason
ON assets
FOR EACH ROW
EXECUTE FUNCTION enforce_asset_management_authorisation();


-- ============================================================================
-- 2. EXECUTION-TARGET AUTHORISATION
-- ============================================================================

ALTER TABLE asset_execution_targets
    ADD COLUMN authorised_at TIMESTAMPTZ,
    ADD COLUMN authorised_by VARCHAR(255),
    ADD COLUMN authorisation_reason TEXT,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD COLUMN revoked_by VARCHAR(255),
    ADD COLUMN revocation_reason TEXT;


ALTER TABLE asset_execution_targets
    ADD CONSTRAINT ck_execution_targets_authorised_by_nonblank
        CHECK (
            authorised_by IS NULL
            OR length(btrim(authorised_by)) > 0
        ),

    ADD CONSTRAINT ck_execution_targets_authorisation_reason_nonblank
        CHECK (
            authorisation_reason IS NULL
            OR length(btrim(authorisation_reason)) > 0
        ),

    ADD CONSTRAINT ck_execution_targets_revoked_by_nonblank
        CHECK (
            revoked_by IS NULL
            OR length(btrim(revoked_by)) > 0
        ),

    ADD CONSTRAINT ck_execution_targets_revocation_reason_nonblank
        CHECK (
            revocation_reason IS NULL
            OR length(btrim(revocation_reason)) > 0
        ),

    ADD CONSTRAINT ck_execution_targets_authorisation_triplet
        CHECK (
            (
                authorised_at IS NULL
                AND authorised_by IS NULL
                AND authorisation_reason IS NULL
            )
            OR
            (
                authorised_at IS NOT NULL
                AND authorised_by IS NOT NULL
                AND authorisation_reason IS NOT NULL
            )
        ),

    ADD CONSTRAINT ck_execution_targets_revocation_triplet
        CHECK (
            (
                revoked_at IS NULL
                AND revoked_by IS NULL
                AND revocation_reason IS NULL
            )
            OR
            (
                revoked_at IS NOT NULL
                AND revoked_by IS NOT NULL
                AND revocation_reason IS NOT NULL
            )
        ),

    ADD CONSTRAINT ck_execution_targets_revocation_order
        CHECK (
            revoked_at IS NULL
            OR (
                authorised_at IS NOT NULL
                AND revoked_at >= authorised_at
            )
        );


CREATE OR REPLACE FUNCTION enforce_execution_target_authorisation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.is_active = TRUE THEN

        IF NOT EXISTS (
            SELECT 1
            FROM assets a
            WHERE a.asset_id = NEW.asset_id
              AND a.tenant_code = NEW.tenant_code
              AND a.inventory_state = 'MANAGED'
              AND a.management_authorised_at IS NOT NULL
              AND a.management_authorised_by IS NOT NULL
              AND length(btrim(a.management_authorised_by)) > 0
              AND a.management_revoked_at IS NULL
        ) THEN

            RAISE EXCEPTION
                'Active execution target for asset % requires a currently authorised MANAGED asset',
                NEW.asset_id;
        END IF;

        IF NEW.authorised_at IS NULL
           OR NEW.authorised_by IS NULL
           OR length(btrim(NEW.authorised_by)) = 0
           OR NEW.authorisation_reason IS NULL
           OR length(btrim(NEW.authorisation_reason)) = 0 THEN

            RAISE EXCEPTION
                'Active execution target for asset % requires explicit authorisation',
                NEW.asset_id;
        END IF;

        IF NEW.revoked_at IS NOT NULL
           OR NEW.revoked_by IS NOT NULL
           OR NEW.revocation_reason IS NOT NULL THEN

            RAISE EXCEPTION
                'Active execution target for asset % cannot be revoked',
                NEW.asset_id;
        END IF;

    ELSE

        -- An execution target that was previously authorised must carry
        -- explicit revocation metadata when it becomes inactive.
        IF NEW.authorised_at IS NOT NULL
           AND (
               NEW.revoked_at IS NULL
               OR NEW.revoked_by IS NULL
               OR length(btrim(NEW.revoked_by)) = 0
               OR NEW.revocation_reason IS NULL
               OR length(btrim(NEW.revocation_reason)) = 0
           ) THEN

            RAISE EXCEPTION
                'Authorised execution target for asset % requires explicit revocation when deactivated',
                NEW.asset_id;
        END IF;

    END IF;

    RETURN NEW;
END;
$function$;


CREATE TRIGGER trg_enforce_execution_target_authorisation
BEFORE INSERT OR UPDATE OF
    is_active,
    authorised_at,
    authorised_by,
    authorisation_reason,
    revoked_at,
    revoked_by,
    revocation_reason
ON asset_execution_targets
FOR EACH ROW
EXECUTE FUNCTION enforce_execution_target_authorisation();


-- ============================================================================
-- 3. APPEND-ONLY REMEDIATION-READINESS AUDIT
-- ============================================================================
--
-- This table records administrative decisions affecting remediation
-- readiness. It is intentionally independent of mutable current-state fields.
--
-- asset_id and execution_target_id are retained as historical identifiers.
-- Foreign keys are deliberately not used here so audit history is not
-- destroyed if operational asset records are ever removed.
-- ============================================================================

CREATE TABLE asset_remediation_audit (
    audit_id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    execution_target_id BIGINT,

    event_type VARCHAR(60) NOT NULL
        CHECK (
            event_type IN (
                'ASSET_MANAGED',
                'ASSET_MANAGEMENT_REVOKED',
                'EXECUTION_TARGET_AUTHORISED',
                'EXECUTION_TARGET_REVOKED',
                'EXECUTION_TARGET_REPLACED',
                'ASSET_DEACTIVATED',
                'ASSET_RETIRED'
            )
        ),

    performed_by VARCHAR(255) NOT NULL,

    reason TEXT NOT NULL,

    event_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT ck_asset_remediation_audit_actor
        CHECK (
            length(btrim(performed_by)) > 0
        ),

    CONSTRAINT ck_asset_remediation_audit_reason
        CHECK (
            length(btrim(reason)) > 0
        ),

    CONSTRAINT ck_asset_remediation_audit_metadata_object
        CHECK (
            jsonb_typeof(event_metadata) = 'object'
        )
);


CREATE INDEX idx_asset_remediation_audit_asset
    ON asset_remediation_audit (
        tenant_code,
        asset_id,
        created_at DESC
    );


CREATE INDEX idx_asset_remediation_audit_target
    ON asset_remediation_audit (
        execution_target_id,
        created_at DESC
    )
    WHERE execution_target_id IS NOT NULL;


CREATE INDEX idx_asset_remediation_audit_event
    ON asset_remediation_audit (
        tenant_code,
        event_type,
        created_at DESC
    );


-- Prevent application code from rewriting historical readiness decisions.
CREATE OR REPLACE FUNCTION prevent_asset_remediation_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION
        'asset_remediation_audit is append-only';
END;
$function$;


CREATE TRIGGER trg_prevent_asset_remediation_audit_update
BEFORE UPDATE
ON asset_remediation_audit
FOR EACH ROW
EXECUTE FUNCTION prevent_asset_remediation_audit_mutation();


CREATE TRIGGER trg_prevent_asset_remediation_audit_delete
BEFORE DELETE
ON asset_remediation_audit
FOR EACH ROW
EXECUTE FUNCTION prevent_asset_remediation_audit_mutation();


-- ============================================================================
-- 4. EXECUTION-ELIGIBLE REMEDIATION QUEUE
-- ============================================================================
--
-- Routing and risk prioritisation have already happened upstream.
--
-- This view applies only the remediation-readiness safety gate.
--
-- Eligibility now requires:
--   1. finding bound to a canonical asset;
--   2. asset inventory_state = MANAGED;
--   3. asset lifecycle_status = ACTIVE;
--   4. explicit current asset-management authorisation;
--   5. exactly one active execution target;
--   6. explicit current execution-target authorisation.
--
-- Legacy MANAGED state or legacy is_active target state without V1
-- authorisation metadata is deliberately insufficient for execution.
-- ============================================================================

CREATE OR REPLACE VIEW eligible_remediation_queue AS
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
 AND aet.authorised_at IS NOT NULL
 AND aet.authorised_by IS NOT NULL
 AND length(btrim(aet.authorised_by)) > 0
 AND aet.revoked_at IS NULL
WHERE a.inventory_state = 'MANAGED'
  AND a.lifecycle_status = 'ACTIVE'
  AND a.management_authorised_at IS NOT NULL
  AND a.management_authorised_by IS NOT NULL
  AND length(btrim(a.management_authorised_by)) > 0
  AND a.management_revoked_at IS NULL;


COMMIT;
