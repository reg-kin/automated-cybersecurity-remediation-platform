-- ============================================================================
-- Automated Cybersecurity Remediation Platform
-- Migration 021: Scan Policy Scheduling V1
--
-- Purpose:
--   Strengthen the persistence invariants required by deterministic,
--   idempotent scan-policy scheduling.
--
-- This migration does not implement cron calculation or scanner-subject
-- resolution. Those remain application-layer responsibilities.
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. MANUAL policies must never carry automatic scheduling state.
--
-- CRON policies may temporarily have next_run_at = NULL while their schedule
-- is being initialised, disabled, or otherwise awaiting scheduling-service
-- processing.
-- ============================================================================

ALTER TABLE scan_policies
    ADD CONSTRAINT ck_scan_policy_manual_next_run
    CHECK (
        schedule_type <> 'MANUAL'
        OR next_run_at IS NULL
    );

-- ============================================================================
-- 2. One policy occurrence may create at most one execution.
--
-- uq_scan_policy_active_execution prevents overlapping active executions.
-- It does not prevent a terminal execution from being recreated for the same
-- scheduled occurrence.
--
-- This constraint makes the scheduled occurrence itself idempotent:
--
--     (scan_policy_id, scheduled_for)
--
-- identifies exactly one auditable execution attempt.
-- ============================================================================

ALTER TABLE scan_executions
    ADD CONSTRAINT uq_scan_execution_policy_occurrence
    UNIQUE (
        scan_policy_id,
        scheduled_for
    );

COMMIT;
