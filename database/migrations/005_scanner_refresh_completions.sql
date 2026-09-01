BEGIN;
CREATE TABLE IF NOT EXISTS scanner_refresh_completions (
 completion_id BIGSERIAL PRIMARY KEY,
 engine_source VARCHAR NOT NULL,
 scanner_subject_type VARCHAR NOT NULL,
 scanner_subject_id TEXT NOT NULL,
 refresh_id TEXT NOT NULL,
 refresh_started_at TIMESTAMPTZ NOT NULL,
 refresh_completed_at TIMESTAMPTZ NOT NULL,
 refresh_status VARCHAR NOT NULL CHECK (refresh_status IN ('SUCCESS','FAILED')),
 expected_findings INTEGER NOT NULL CHECK (expected_findings >= 0),
 tenant_code TEXT,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 promoted_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(engine_source,scanner_subject_type,scanner_subject_id,refresh_id)
);
CREATE INDEX IF NOT EXISTS idx_scanner_refresh_completions_pending
ON scanner_refresh_completions(engine_source,scanner_subject_type,scanner_subject_id,refresh_completed_at)
WHERE promoted_at IS NULL;
COMMIT;
