BEGIN;

-- ============================================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Asset Management Foundation
--
-- Purpose:
--   1. Introduce canonical tenant-scoped technical assets.
--   2. Preserve scanner-native target_host evidence.
--   3. Allow security findings to bind to canonical assets.
--   4. Separate asset identity, endpoints, organisational context,
--      observations and relationships.
--   5. Provide the data foundation for deterministic risk contextualisation.
--
-- This migration is deliberately additive:
--   - the Unified Security Finding ingress contract is unchanged;
--   - target_host remains authoritative scanner/remediation evidence;
--   - existing finding uniqueness and lifecycle semantics are unchanged;
--   - existing findings may initially have asset_id = NULL.
-- ============================================================================


-- ============================================================================
-- 1. CANONICAL ASSETS
-- ============================================================================

CREATE TABLE assets (
    asset_id BIGSERIAL PRIMARY KEY,

    tenant_code VARCHAR(100) NOT NULL,

    asset_type VARCHAR(40) NOT NULL
        CHECK (
            asset_type IN (
                'HOST',
                'VIRTUAL_MACHINE',
                'NETWORK_DEVICE',
                'APPLICATION',
                'CONTAINER',
                'CONTAINER_IMAGE',
                'CLOUD_RESOURCE',
                'OTHER'
            )
        ),

    canonical_name VARCHAR(255) NOT NULL,

    inventory_state VARCHAR(20) NOT NULL
        DEFAULT 'PROVISIONAL'
        CHECK (
            inventory_state IN (
                'PROVISIONAL',
                'MANAGED',
                'UNMANAGED'
            )
        ),

    lifecycle_status VARCHAR(20) NOT NULL
        DEFAULT 'ACTIVE'
        CHECK (
            lifecycle_status IN (
                'ACTIVE',
                'INACTIVE',
                'RETIRED'
            )
        ),

    first_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    last_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT uq_assets_asset_tenant
        UNIQUE (
            asset_id,
            tenant_code
        ),

    CONSTRAINT ck_assets_seen_order
        CHECK (
            last_seen_at >= first_seen_at
        )
);


CREATE INDEX idx_assets_tenant
    ON assets (
        tenant_code,
        lifecycle_status,
        asset_type
    );


CREATE INDEX idx_assets_canonical_name
    ON assets (
        tenant_code,
        canonical_name
    );


CREATE INDEX idx_assets_last_seen
    ON assets (
        tenant_code,
        last_seen_at DESC
    );


-- ============================================================================
-- 2. ASSET IDENTIFIERS
--
-- An identifier is evidence that may help resolve scanner observations to a
-- canonical asset.
--
-- Not every identifier is permanently unique:
--
--   Strong:
--     WAZUH_AGENT_ID
--     MACHINE_ID
--     CLOUD_INSTANCE_ID
--     CONTAINER_ID
--     CONTAINER_IMAGE_DIGEST
--
--   Potentially reusable / ambiguous:
--     HOSTNAME
--     FQDN
--     IP_ADDRESS
--     MAC_ADDRESS
--     CONTAINER_IMAGE_REFERENCE
--     APPLICATION_ID
--     URL
--
-- Strong active identifiers are protected by a tenant-scoped partial unique
-- index below. Weak identifiers are indexed for lookup but deliberately do not
-- force two assets to merge.
-- ============================================================================

CREATE TABLE asset_identifiers (
    asset_identifier_id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    identifier_type VARCHAR(40) NOT NULL
        CHECK (
            identifier_type IN (
                'HOSTNAME',
                'FQDN',
                'IP_ADDRESS',
                'MAC_ADDRESS',
                'WAZUH_AGENT_ID',
                'MACHINE_ID',
                'CLOUD_INSTANCE_ID',
                'CONTAINER_ID',
                'CONTAINER_IMAGE_DIGEST',
                'CONTAINER_IMAGE_REFERENCE',
                'APPLICATION_ID',
                'URL'
            )
        ),

    identifier_value TEXT NOT NULL,

    normalized_value TEXT NOT NULL,

    source VARCHAR(100) NOT NULL,

    confidence VARCHAR(20) NOT NULL
        CHECK (
            confidence IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'VERY_HIGH'
            )
        ),

    is_authoritative BOOLEAN NOT NULL
        DEFAULT FALSE,

    is_active BOOLEAN NOT NULL
        DEFAULT TRUE,

    first_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    last_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_identifiers_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_asset_identifier_per_asset
        UNIQUE (
            asset_id,
            identifier_type,
            normalized_value
        ),

    CONSTRAINT ck_asset_identifiers_value
        CHECK (
            length(btrim(identifier_value)) > 0
            AND
            length(btrim(normalized_value)) > 0
        ),

    CONSTRAINT ck_asset_identifiers_seen_order
        CHECK (
            last_seen_at >= first_seen_at
        )
);


CREATE INDEX idx_asset_identifiers_lookup
    ON asset_identifiers (
        tenant_code,
        identifier_type,
        normalized_value
    )
    WHERE is_active = TRUE;


CREATE INDEX idx_asset_identifiers_asset
    ON asset_identifiers (
        asset_id,
        is_active
    );


CREATE UNIQUE INDEX uq_asset_identifiers_strong_active
    ON asset_identifiers (
        tenant_code,
        identifier_type,
        normalized_value
    )
    WHERE
        is_active = TRUE
        AND identifier_type IN (
            'WAZUH_AGENT_ID',
            'MACHINE_ID',
            'CLOUD_INSTANCE_ID',
            'CONTAINER_ID',
            'CONTAINER_IMAGE_DIGEST'
        );


-- ============================================================================
-- 3. ASSET ENDPOINTS
--
-- Endpoints describe exposed/listening/addressable interfaces of an asset.
-- They are not themselves assumed to be globally unique asset identities.
-- ============================================================================

CREATE TABLE asset_endpoints (
    endpoint_id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    endpoint_type VARCHAR(20) NOT NULL
        CHECK (
            endpoint_type IN (
                'TCP',
                'UDP',
                'HTTP',
                'HTTPS',
                'URL'
            )
        ),

    scheme VARCHAR(20) NULL,

    host VARCHAR(255) NOT NULL,

    port INTEGER NULL
        CHECK (
            port IS NULL
            OR (
                port >= 1
                AND port <= 65535
            )
        ),

    path TEXT NULL,

    normalized_endpoint TEXT NOT NULL,

    is_external BOOLEAN NULL,

    is_active BOOLEAN NOT NULL
        DEFAULT TRUE,

    source VARCHAR(100) NOT NULL,

    first_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    last_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_endpoints_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_asset_endpoint_per_asset
        UNIQUE (
            asset_id,
            normalized_endpoint
        ),

    CONSTRAINT ck_asset_endpoints_host
        CHECK (
            length(btrim(host)) > 0
        ),

    CONSTRAINT ck_asset_endpoints_normalized
        CHECK (
            length(btrim(normalized_endpoint)) > 0
        ),

    CONSTRAINT ck_asset_endpoints_seen_order
        CHECK (
            last_seen_at >= first_seen_at
        )
);


CREATE INDEX idx_asset_endpoints_lookup
    ON asset_endpoints (
        tenant_code,
        normalized_endpoint
    )
    WHERE is_active = TRUE;


CREATE INDEX idx_asset_endpoints_asset
    ON asset_endpoints (
        asset_id,
        is_active
    );


-- ============================================================================
-- 4. ORGANISATIONAL / BUSINESS ASSET CONTEXT
--
-- Scanner observations must not silently overwrite this curated context.
-- These values become deterministic inputs to the later risk-contextualisation
-- layer.
-- ============================================================================

CREATE TABLE asset_context (
    asset_id BIGINT PRIMARY KEY,

    tenant_code VARCHAR(100) NOT NULL,

    environment VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            environment IN (
                'DEVELOPMENT',
                'TEST',
                'STAGING',
                'PRODUCTION',
                'CORPORATE',
                'UNKNOWN'
            )
        ),

    business_service TEXT NULL,

    business_unit TEXT NULL,

    owner TEXT NULL,

    technical_owner TEXT NULL,

    criticality VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            criticality IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL',
                'UNKNOWN'
            )
        ),

    data_classification VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            data_classification IN (
                'PUBLIC',
                'INTERNAL',
                'CONFIDENTIAL',
                'RESTRICTED',
                'UNKNOWN'
            )
        ),

    internet_exposure VARCHAR(30) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            internet_exposure IN (
                'INTERNAL',
                'EXTERNALLY_REACHABLE',
                'INTERNET_FACING',
                'UNKNOWN'
            )
        ),

    network_zone TEXT NULL,

    confidentiality_requirement VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            confidentiality_requirement IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL',
                'UNKNOWN'
            )
        ),

    integrity_requirement VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            integrity_requirement IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL',
                'UNKNOWN'
            )
        ),

    availability_requirement VARCHAR(20) NOT NULL
        DEFAULT 'UNKNOWN'
        CHECK (
            availability_requirement IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL',
                'UNKNOWN'
            )
        ),

    context_source VARCHAR(100) NOT NULL
        DEFAULT 'MANUAL',

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_context_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE
);


CREATE INDEX idx_asset_context_risk
    ON asset_context (
        tenant_code,
        criticality,
        environment,
        internet_exposure
    );


-- ============================================================================
-- 5. ASSET OBSERVATIONS
--
-- Scanner/discovery facts are retained separately from curated organisational
-- context so that provenance and confidence remain explicit.
-- ============================================================================

CREATE TABLE asset_observations (
    observation_id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    source_type VARCHAR(30) NOT NULL
        CHECK (
            source_type IN (
                'SCANNER',
                'AGENT',
                'API',
                'IMPORT',
                'MANUAL',
                'OTHER'
            )
        ),

    source_name VARCHAR(100) NOT NULL,

    attribute_name VARCHAR(100) NOT NULL,

    observed_value JSONB NOT NULL,

    confidence VARCHAR(20) NOT NULL
        CHECK (
            confidence IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'VERY_HIGH'
            )
        ),

    observed_at TIMESTAMPTZ NOT NULL,

    expires_at TIMESTAMPTZ NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_observations_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT ck_asset_observations_attribute
        CHECK (
            length(btrim(attribute_name)) > 0
        ),

    CONSTRAINT ck_asset_observations_expiry
        CHECK (
            expires_at IS NULL
            OR expires_at >= observed_at
        )
);


CREATE INDEX idx_asset_observations_asset
    ON asset_observations (
        asset_id,
        observed_at DESC
    );


CREATE INDEX idx_asset_observations_lookup
    ON asset_observations (
        tenant_code,
        source_name,
        attribute_name,
        observed_at DESC
    );


-- ============================================================================
-- 6. ASSET RELATIONSHIPS
--
-- The schema is introduced now so later container/application/service
-- modelling does not require another foundational identity migration.
-- Advanced relationship discovery is intentionally deferred.
-- ============================================================================

CREATE TABLE asset_relationships (
    relationship_id BIGSERIAL PRIMARY KEY,

    tenant_code VARCHAR(100) NOT NULL,

    source_asset_id BIGINT NOT NULL,

    target_asset_id BIGINT NOT NULL,

    relationship_type VARCHAR(40) NOT NULL
        CHECK (
            relationship_type IN (
                'HOSTS',
                'RUNS',
                'DEPENDS_ON',
                'CONNECTS_TO',
                'MEMBER_OF',
                'BACKS',
                'CONTAINS',
                'BUILT_FROM',
                'EXPOSES'
            )
        ),

    source VARCHAR(100) NOT NULL,

    confidence VARCHAR(20) NOT NULL
        CHECK (
            confidence IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'VERY_HIGH'
            )
        ),

    first_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    last_seen_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_asset_relationships_source
        FOREIGN KEY (
            source_asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT fk_asset_relationships_target
        FOREIGN KEY (
            target_asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_asset_relationship
        UNIQUE (
            source_asset_id,
            target_asset_id,
            relationship_type
        ),

    CONSTRAINT ck_asset_relationship_no_self
        CHECK (
            source_asset_id <> target_asset_id
        ),

    CONSTRAINT ck_asset_relationship_seen_order
        CHECK (
            last_seen_at >= first_seen_at
        )
);


CREATE INDEX idx_asset_relationships_source
    ON asset_relationships (
        source_asset_id,
        relationship_type
    );


CREATE INDEX idx_asset_relationships_target
    ON asset_relationships (
        target_asset_id,
        relationship_type
    );


-- ============================================================================
-- 7. BIND SECURITY FINDINGS TO CANONICAL ASSETS
--
-- Nullable by design:
--   - historical findings remain valid;
--   - asset resolution can be introduced incrementally;
--   - unresolved/ambiguous identity never blocks scanner ingestion.
--
-- target_host is deliberately retained and the existing finding uniqueness
-- constraint is deliberately unchanged.
-- ============================================================================

ALTER TABLE unified_security_findings
    ADD COLUMN asset_id BIGINT NULL;


ALTER TABLE unified_security_findings
    ADD CONSTRAINT fk_unified_security_findings_asset
        FOREIGN KEY (
            asset_id
        )
        REFERENCES assets (
            asset_id
        )
        ON DELETE SET NULL;


CREATE INDEX idx_findings_asset
    ON unified_security_findings (
        asset_id
    )
    WHERE asset_id IS NOT NULL;


COMMIT;
