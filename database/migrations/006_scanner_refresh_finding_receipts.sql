BEGIN;

CREATE TABLE IF NOT EXISTS scanner_refresh_finding_receipts (
    receipt_id BIGSERIAL PRIMARY KEY,

    engine_source VARCHAR(64) NOT NULL,
    scanner_subject_type VARCHAR(32) NOT NULL,
    scanner_subject_id TEXT NOT NULL,

    refresh_id TEXT NOT NULL,

    tenant_code TEXT,

    finding_key TEXT NOT NULL,
    finding_id BIGINT,

    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT scanner_refresh_finding_receipts_unique
        UNIQUE (
            engine_source,
            scanner_subject_type,
            scanner_subject_id,
            refresh_id,
            finding_key
        ),

    CONSTRAINT scanner_refresh_finding_receipts_finding_fk
        FOREIGN KEY (finding_id)
        REFERENCES unified_security_findings(finding_id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scanner_refresh_finding_receipts_count
ON scanner_refresh_finding_receipts (
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    refresh_id
);

CREATE INDEX IF NOT EXISTS idx_scanner_refresh_finding_receipts_tenant
ON scanner_refresh_finding_receipts (
    tenant_code,
    engine_source,
    refresh_id
);

COMMIT;
