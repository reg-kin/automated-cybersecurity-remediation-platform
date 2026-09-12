BEGIN;

-- ============================================================================
-- AUTOMATED CYBERSECURITY REMEDIATION PLATFORM
-- Scan Coordination Foundation V1
--
-- Purpose:
--   1. Introduce centrally managed scanner execution nodes.
--   2. Record scanner capabilities available on each execution node.
--   3. Bind LOCAL_ASSET execution nodes to the canonical assets they represent.
--   4. Define tenant-scoped scan policies independently of execution location.
--   5. Record every scheduled scan execution and its resolved scanner subject.
--   6. Preserve scanner-specific orchestrators as the owners of scanner
--      invocation/evidence parsing, finding_class determination and Unified
--      Security Finding construction.
--
-- Architectural invariants:
--   - Scan coordination does NOT construct security findings.
--   - Scan coordination does NOT determine finding_class.
--   - Scan coordination does NOT perform risk contextualisation.
--   - Scan coordination does NOT authorise remediation.
--   - Scan policies do not permanently bind to an execution node.
--   - Execution nodes are selected according to scanner capability.
--   - Scanner subjects are resolved at execution time and persisted on the
--     execution record for auditability.
--   - Canonical asset identity remains tenant-scoped.
--   - Scanner-native evidence remains separate from canonical asset identity.
--   - Existing scanner_refresh_* infrastructure remains independent and is not
--     repurposed as the general scan-coordination system.
-- ============================================================================


-- ============================================================================
-- 1. SCANNER EXECUTION NODES
--
-- An execution node is any machine/environment capable of running scanner
-- orchestration workloads.
--
-- Examples:
--   - VPS-local node with Wazuh Indexer access;
--   - dedicated network scanner VM;
--   - customer-side scanner appliance;
--   - host-local scanner agent;
--   - development workstation.
--
-- The schema deliberately does not encode physical machine type such as
-- "laptop" or "server".
-- ============================================================================

CREATE TABLE scan_execution_nodes (
    execution_node_id BIGSERIAL PRIMARY KEY,

    node_code VARCHAR(100) NOT NULL,

    display_name VARCHAR(255) NOT NULL,

    transport_mode VARCHAR(20) NOT NULL
        CHECK (
            transport_mode IN (
                'LOCAL',
                'PULL'
            )
        ),

    is_enabled BOOLEAN NOT NULL
        DEFAULT TRUE,

    last_seen_at TIMESTAMPTZ NULL,

    node_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT uq_scan_execution_nodes_code
        UNIQUE (node_code),

    CONSTRAINT ck_scan_execution_nodes_code
        CHECK (
            length(btrim(node_code)) > 0
        ),

    CONSTRAINT ck_scan_execution_nodes_display_name
        CHECK (
            length(btrim(display_name)) > 0
        ),

    CONSTRAINT ck_scan_execution_nodes_metadata_object
        CHECK (
            jsonb_typeof(node_metadata) = 'object'
        )
);


CREATE INDEX idx_scan_execution_nodes_enabled
    ON scan_execution_nodes (
        is_enabled,
        node_code
    );


-- ============================================================================
-- 2. EXECUTION NODE SCANNER CAPABILITIES
--
-- A node may support multiple scanner orchestrators.
--
-- execution_model describes how that scanner relates to the object being
-- scanned:
--
--   REMOTE_TARGET
--       Scanner actively reaches a remote host/application.
--       Examples: Nmap, Nuclei.
--
--   LOCAL_ASSET
--       Scanner examines the machine on which it executes.
--       Example: Lynis.
--
--   CONTROL_PLANE
--       Scanner/orchestrator talks to an authoritative scanner/security
--       control plane rather than directly probing the canonical asset.
--       Examples: Wazuh Vulnerability, Wazuh SCA, OpenVAS/GVMD.
--
--   RESOURCE_TARGET
--       Scanner operates on a resource reference such as a container image
--       or filesystem path.
--       Example: Trivy.
-- ============================================================================

CREATE TABLE scan_execution_node_capabilities (
    capability_id BIGSERIAL PRIMARY KEY,

    execution_node_id BIGINT NOT NULL,

    scanner_type VARCHAR(50) NOT NULL
        CHECK (
            scanner_type IN (
                'openvas',
                'nuclei',
                'nmap_nse',
                'lynis',
                'trivy',
                'wazuh_vulnerability',
                'wazuh_sca'
            )
        ),

    execution_model VARCHAR(30) NOT NULL
        CHECK (
            execution_model IN (
                'REMOTE_TARGET',
                'LOCAL_ASSET',
                'CONTROL_PLANE',
                'RESOURCE_TARGET'
            )
        ),

    priority INTEGER NOT NULL
        DEFAULT 100
        CHECK (
            priority >= 0
        ),

    is_enabled BOOLEAN NOT NULL
        DEFAULT TRUE,

    capability_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_scan_node_capability_node
        FOREIGN KEY (
            execution_node_id
        )
        REFERENCES scan_execution_nodes (
            execution_node_id
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_node_capability
        UNIQUE (
            execution_node_id,
            scanner_type
        ),

    CONSTRAINT ck_scan_node_capability_metadata_object
        CHECK (
            jsonb_typeof(capability_metadata) = 'object'
        )
);


CREATE INDEX idx_scan_node_capabilities_lookup
    ON scan_execution_node_capabilities (
        scanner_type,
        is_enabled,
        priority,
        execution_node_id
    );


-- ============================================================================
-- 3. EXECUTION NODE ↔ CANONICAL ASSET BINDINGS
--
-- Required for LOCAL_ASSET scanners.
--
-- Example:
--
--   node A
--       capability: lynis / LOCAL_ASSET
--       binding: Customer1 asset_id 25
--
-- means that Lynis executing on node A is permitted to represent a scan of
-- canonical asset 25.
--
-- A generic network scanner does not need such a binding merely to scan a
-- remote target.
-- ============================================================================

CREATE TABLE scan_execution_node_assets (
    node_asset_binding_id BIGSERIAL PRIMARY KEY,

    execution_node_id BIGINT NOT NULL,

    asset_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    is_active BOOLEAN NOT NULL
        DEFAULT TRUE,

    binding_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_scan_node_asset_node
        FOREIGN KEY (
            execution_node_id
        )
        REFERENCES scan_execution_nodes (
            execution_node_id
        )
        ON DELETE CASCADE,

    CONSTRAINT fk_scan_node_asset_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_node_asset_binding
        UNIQUE (
            execution_node_id,
            asset_id,
            tenant_code
        ),

    CONSTRAINT ck_scan_node_asset_metadata_object
        CHECK (
            jsonb_typeof(binding_metadata) = 'object'
        )
);


CREATE INDEX idx_scan_node_assets_asset
    ON scan_execution_node_assets (
        tenant_code,
        asset_id,
        is_active
    );


CREATE INDEX idx_scan_node_assets_node
    ON scan_execution_node_assets (
        execution_node_id,
        is_active
    );


-- ============================================================================
-- 4. SCAN POLICIES
--
-- A policy answers:
--
--   WHAT canonical asset should be scanned?
--   WITH WHICH scanner?
--   USING WHICH scanner-specific profile/configuration?
--   WHEN should the scan run?
--
-- It deliberately does NOT answer:
--
--   WHICH execution node will run the scan?
--
-- Node selection is a coordination decision made when an execution is
-- created. This prevents scan policy from being coupled to temporary scanner
-- infrastructure.
-- ============================================================================

CREATE TABLE scan_policies (
    scan_policy_id BIGSERIAL PRIMARY KEY,

    tenant_code VARCHAR(100) NOT NULL,

    asset_id BIGINT NOT NULL,

    scanner_type VARCHAR(50) NOT NULL
        CHECK (
            scanner_type IN (
                'openvas',
                'nuclei',
                'nmap_nse',
                'lynis',
                'trivy',
                'wazuh_vulnerability',
                'wazuh_sca'
            )
        ),

    profile_name VARCHAR(100) NOT NULL
        DEFAULT 'default',

    scanner_parameters JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    schedule_type VARCHAR(20) NOT NULL
        DEFAULT 'CRON'
        CHECK (
            schedule_type IN (
                'CRON',
                'MANUAL'
            )
        ),

    schedule_expression TEXT NULL,

    schedule_timezone VARCHAR(100) NOT NULL
        DEFAULT 'UTC',

    next_run_at TIMESTAMPTZ NULL,

    is_enabled BOOLEAN NOT NULL
        DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_scan_policy_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE CASCADE,

    CONSTRAINT uq_scan_policy_identity
        UNIQUE (
            tenant_code,
            asset_id,
            scanner_type,
            profile_name
        ),

    CONSTRAINT ck_scan_policy_profile
        CHECK (
            length(btrim(profile_name)) > 0
        ),

    CONSTRAINT ck_scan_policy_timezone
        CHECK (
            length(btrim(schedule_timezone)) > 0
        ),

    CONSTRAINT ck_scan_policy_parameters_object
        CHECK (
            jsonb_typeof(scanner_parameters) = 'object'
        ),

    CONSTRAINT ck_scan_policy_schedule
        CHECK (
            (
                schedule_type = 'CRON'
                AND schedule_expression IS NOT NULL
                AND length(btrim(schedule_expression)) > 0
            )
            OR
            (
                schedule_type = 'MANUAL'
                AND schedule_expression IS NULL
            )
        )
);


CREATE INDEX idx_scan_policies_due
    ON scan_policies (
        next_run_at,
        scan_policy_id
    )
    WHERE
        is_enabled = TRUE
        AND schedule_type = 'CRON';


CREATE INDEX idx_scan_policies_asset
    ON scan_policies (
        tenant_code,
        asset_id,
        scanner_type
    );


-- ============================================================================
-- 5. SCAN EXECUTIONS
--
-- An execution is the auditable record of one concrete scan attempt.
--
-- Unlike scan_policy, it records:
--
--   - the selected execution node;
--   - the scanner execution model;
--   - the resolved scanner subject type/value;
--   - the exact scanner parameters used;
--   - execution lifecycle timestamps and outcome.
--
-- scanner_subject_type deliberately makes scanner semantics explicit instead
-- of overloading one ambiguous "target" field.
-- ============================================================================

CREATE TABLE scan_executions (
    scan_execution_id BIGSERIAL PRIMARY KEY,

    scan_policy_id BIGINT NOT NULL,

    tenant_code VARCHAR(100) NOT NULL,

    asset_id BIGINT NOT NULL,

    scanner_type VARCHAR(50) NOT NULL
        CHECK (
            scanner_type IN (
                'openvas',
                'nuclei',
                'nmap_nse',
                'lynis',
                'trivy',
                'wazuh_vulnerability',
                'wazuh_sca'
            )
        ),

    execution_node_id BIGINT NOT NULL,

    execution_model VARCHAR(30) NOT NULL
        CHECK (
            execution_model IN (
                'REMOTE_TARGET',
                'LOCAL_ASSET',
                'CONTROL_PLANE',
                'RESOURCE_TARGET'
            )
        ),

    scanner_subject_type VARCHAR(40) NOT NULL
        CHECK (
            scanner_subject_type IN (
                'IP_ADDRESS',
                'HOSTNAME',
                'FQDN',
                'URL',
                'WAZUH_AGENT_ID',
                'OPENVAS_TASK',
                'LOCAL_ASSET',
                'CONTAINER_IMAGE',
                'FILESYSTEM'
            )
        ),

    scanner_subject_value TEXT NOT NULL,

    scanner_parameters JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    status VARCHAR(20) NOT NULL
        DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'LEASED',
                'RUNNING',
                'SUCCEEDED',
                'FAILED',
                'CANCELLED',
                'EXPIRED'
            )
        ),

    scheduled_for TIMESTAMPTZ NOT NULL,

    leased_at TIMESTAMPTZ NULL,

    lease_expires_at TIMESTAMPTZ NULL,

    started_at TIMESTAMPTZ NULL,

    completed_at TIMESTAMPTZ NULL,

    exit_code INTEGER NULL,

    failure_reason TEXT NULL,

    execution_metadata JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT fk_scan_execution_policy
        FOREIGN KEY (
            scan_policy_id
        )
        REFERENCES scan_policies (
            scan_policy_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT fk_scan_execution_asset_tenant
        FOREIGN KEY (
            asset_id,
            tenant_code
        )
        REFERENCES assets (
            asset_id,
            tenant_code
        )
        ON DELETE RESTRICT,

    CONSTRAINT fk_scan_execution_node
        FOREIGN KEY (
            execution_node_id
        )
        REFERENCES scan_execution_nodes (
            execution_node_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT ck_scan_execution_subject
        CHECK (
            length(btrim(scanner_subject_value)) > 0
        ),

    CONSTRAINT ck_scan_execution_parameters_object
        CHECK (
            jsonb_typeof(scanner_parameters) = 'object'
        ),

    CONSTRAINT ck_scan_execution_metadata_object
        CHECK (
            jsonb_typeof(execution_metadata) = 'object'
        ),

    CONSTRAINT ck_scan_execution_lease_order
        CHECK (
            lease_expires_at IS NULL
            OR leased_at IS NOT NULL
        ),

    CONSTRAINT ck_scan_execution_lease_expiry
        CHECK (
            lease_expires_at IS NULL
            OR lease_expires_at >= leased_at
        ),

    CONSTRAINT ck_scan_execution_start_order
        CHECK (
            started_at IS NULL
            OR started_at >= scheduled_for
        ),

    CONSTRAINT ck_scan_execution_completion_order
        CHECK (
            completed_at IS NULL
            OR (
                started_at IS NOT NULL
                AND completed_at >= started_at
            )
        )
);


CREATE INDEX idx_scan_executions_dispatch
    ON scan_executions (
        execution_node_id,
        status,
        scheduled_for,
        scan_execution_id
    );


CREATE INDEX idx_scan_executions_asset_history
    ON scan_executions (
        tenant_code,
        asset_id,
        scheduled_for DESC
    );


CREATE INDEX idx_scan_executions_policy_history
    ON scan_executions (
        scan_policy_id,
        scheduled_for DESC
    );


-- Prevent concurrent overlapping executions of the same policy.
--
-- A completed/failed/cancelled/expired execution does not block the next one.

CREATE UNIQUE INDEX uq_scan_policy_active_execution
    ON scan_executions (
        scan_policy_id
    )
    WHERE status IN (
        'PENDING',
        'LEASED',
        'RUNNING'
    );


-- ============================================================================
-- 6. UPDATED_AT SUPPORT
-- ============================================================================

CREATE OR REPLACE FUNCTION set_scan_coordination_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_scan_execution_nodes_updated_at
BEFORE UPDATE ON scan_execution_nodes
FOR EACH ROW
EXECUTE FUNCTION set_scan_coordination_updated_at();


CREATE TRIGGER trg_scan_execution_node_capabilities_updated_at
BEFORE UPDATE ON scan_execution_node_capabilities
FOR EACH ROW
EXECUTE FUNCTION set_scan_coordination_updated_at();


CREATE TRIGGER trg_scan_execution_node_assets_updated_at
BEFORE UPDATE ON scan_execution_node_assets
FOR EACH ROW
EXECUTE FUNCTION set_scan_coordination_updated_at();


CREATE TRIGGER trg_scan_policies_updated_at
BEFORE UPDATE ON scan_policies
FOR EACH ROW
EXECUTE FUNCTION set_scan_coordination_updated_at();


CREATE TRIGGER trg_scan_executions_updated_at
BEFORE UPDATE ON scan_executions
FOR EACH ROW
EXECUTE FUNCTION set_scan_coordination_updated_at();


COMMIT;
