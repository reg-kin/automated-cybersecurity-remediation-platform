#!/usr/bin/env bash
set -Eeuo pipefail

# Automated Cybersecurity Remediation Platform
# Release smoke test
#
# Validates that a repository checkout is internally consistent and that the
# database can be reconstructed cleanly from the published SQL assets.
#
# Usage:
#   ./tests/release_smoke_test.sh
#
# Optional environment variables:
#   REGIS_PG_CONTAINER   PostgreSQL container name
#   REGIS_PG_USER        PostgreSQL user
#   REGIS_TEST_DB        Temporary test database name
#
# Defaults reflect the current tested development environment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PG_CONTAINER="${REGIS_PG_CONTAINER:-portal-datastore}"
PG_USER="${REGIS_PG_USER:-telemetry_admin}"
TEST_DB="${REGIS_TEST_DB:-regis_release_smoke_test}"

EXPECTED_FINDING_CLASSES=43
EXPECTED_GENERIC_RULES=43
EXPECTED_TOTAL_RULES=44

SPECIALISED_RULE_NAME="wazuh_sca_cis_ubuntu24_04_35594_crontab_permissions"

SQL_FILES=(
    "database/001_schema.sql"
    "database/002_seed_finding_classes.sql"
    "database/003_seed_remediation_rules.sql"
    "database/migrations/004_deferred_verification.sql"
    "database/migrations/005_scanner_refresh_completions.sql"
    "database/migrations/006_scanner_refresh_finding_receipts.sql"
    "database/010_harden_remediation_routing.sql"
)

cleanup() {
    if docker ps --format '{{.Names}}' | grep -Fxq "${PG_CONTAINER}"; then
        docker exec -i "${PG_CONTAINER}" \
            psql \
            -U "${PG_USER}" \
            -d postgres \
            -v ON_ERROR_STOP=1 \
            -c "DROP DATABASE IF EXISTS ${TEST_DB};" \
            >/dev/null 2>&1 || true
    fi
}

fail() {
    echo
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

trap cleanup EXIT

cd "${ROOT_DIR}"

echo "============================================================"
echo "Automated Cybersecurity Remediation Platform"
echo "Release Smoke Test"
echo "============================================================"
echo

# ---------------------------------------------------------------------------
# 1. Repository structure
# ---------------------------------------------------------------------------

echo "[1/8] Checking required repository files..."

REQUIRED_FILES=(
    "README.md"
    "LICENSE"
    "SECURITY.md"
    "CONTRIBUTING.md"
    "schema/unified_security_finding.schema.json"
    "scanner_orchestrators/finding_class_mapping.json"
    "tests/check_catalogue.py"
)

for file in "${REQUIRED_FILES[@]}" "${SQL_FILES[@]}"; do
    [[ -f "${file}" ]] || fail "Required file missing: ${file}"
done

pass "Required repository files are present."

# ---------------------------------------------------------------------------
# 2. Python catalogue consistency
# ---------------------------------------------------------------------------

echo
echo "[2/8] Running catalogue consistency check..."

python3 tests/check_catalogue.py

pass "Catalogue consistency check passed."

# ---------------------------------------------------------------------------
# 3. Git whitespace check
# ---------------------------------------------------------------------------

echo
echo "[3/8] Checking Git whitespace integrity..."

git diff --check

pass "No Git whitespace errors detected."

# ---------------------------------------------------------------------------
# 4. Secret-literal check
# ---------------------------------------------------------------------------

echo
echo "[4/8] Checking tracked files for obvious literal credentials..."

if git grep -nEI \
    '([Pp]assword|[Pp]asswd|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey)[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{4,}["'\'']'
then
    fail "Possible literal credential detected in tracked files."
fi

pass "No obvious tracked literal credentials detected."

# ---------------------------------------------------------------------------
# 5. PostgreSQL availability
# ---------------------------------------------------------------------------

echo
echo "[5/8] Checking PostgreSQL test environment..."

command -v docker >/dev/null 2>&1 \
    || fail "docker command is not available."

docker ps --format '{{.Names}}' | grep -Fxq "${PG_CONTAINER}" \
    || fail "PostgreSQL container is not running: ${PG_CONTAINER}"

docker exec -i "${PG_CONTAINER}" \
    psql \
    -U "${PG_USER}" \
    -d postgres \
    -v ON_ERROR_STOP=1 \
    -c "SELECT 1;" \
    >/dev/null

pass "PostgreSQL container is reachable."

# ---------------------------------------------------------------------------
# 6. Clean database reconstruction
# ---------------------------------------------------------------------------

echo
echo "[6/8] Reconstructing temporary database..."

docker exec -i "${PG_CONTAINER}" \
    psql \
    -U "${PG_USER}" \
    -d postgres \
    -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS ${TEST_DB};" \
    >/dev/null

docker exec -i "${PG_CONTAINER}" \
    psql \
    -U "${PG_USER}" \
    -d postgres \
    -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE ${TEST_DB};" \
    >/dev/null

for file in "${SQL_FILES[@]}"; do
    echo "  Applying ${file}"

    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -v ON_ERROR_STOP=1 \
        < "${file}" \
        >/dev/null
done

pass "Database reconstruction completed successfully."

# ---------------------------------------------------------------------------
# 7. Database invariant checks
# ---------------------------------------------------------------------------

echo
echo "[7/8] Checking reconstructed database invariants..."

finding_class_count="$(
    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM finding_class_catalogue;"
)"

rule_count="$(
    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM remediation_rules;"
)"

generic_rule_count="$(
    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM remediation_rules WHERE rule_name LIKE '%\_generic' ESCAPE '\';"
)"

orphan_rule_count="$(
    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM remediation_rules r
        LEFT JOIN finding_class_catalogue c
          ON c.finding_class = r.finding_class
        WHERE c.finding_class IS NULL;
        "
)"

specialised_rule_count="$(
    docker exec -i "${PG_CONTAINER}" \
        psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM remediation_rules
        WHERE rule_name = '${SPECIALISED_RULE_NAME}'
          AND finding_class = 'access_control_configuration'
          AND finding_key_pattern = '^cis_ubuntu24-04:35594$'
          AND engine_source = 'wazuh_sca'
          AND capability = 'cis_hardening'
          AND playbook_name = 'cis_hardening.yml'
          AND remediation_action = 'apply_control'
          AND automation_tier = 'TIER_2'
          AND approval_required IS TRUE
          AND priority = 200
          AND enabled IS TRUE;
        "
)"

[[ "${finding_class_count}" == "${EXPECTED_FINDING_CLASSES}" ]] \
    || fail "Expected ${EXPECTED_FINDING_CLASSES} finding classes, found ${finding_class_count}."

[[ "${generic_rule_count}" == "${EXPECTED_GENERIC_RULES}" ]] \
    || fail "Expected ${EXPECTED_GENERIC_RULES} generic rules, found ${generic_rule_count}."

[[ "${rule_count}" == "${EXPECTED_TOTAL_RULES}" ]] \
    || fail "Expected ${EXPECTED_TOTAL_RULES} total remediation rules, found ${rule_count}."

[[ "${orphan_rule_count}" == "0" ]] \
    || fail "Found ${orphan_rule_count} remediation rule(s) referencing unknown finding classes."

[[ "${specialised_rule_count}" == "1" ]] \
    || fail "Specialised Wazuh SCA remediation rule is missing or incorrect."

echo "  finding_classes: ${finding_class_count}"
echo "  generic_rules:   ${generic_rule_count}"
echo "  total_rules:     ${rule_count}"
echo "  orphan_rules:    ${orphan_rule_count}"

pass "Database invariants are correct."

# ---------------------------------------------------------------------------
# 8. Git release/tag information
# ---------------------------------------------------------------------------

echo
echo "[8/8] Checking Git release information..."

commit="$(git rev-parse --short HEAD)"
echo "  commit: ${commit}"

if tag="$(git describe --tags --exact-match 2>/dev/null)"; then
    echo "  exact_tag: ${tag}"
else
    echo "  exact_tag: none"
    echo "  NOTE: this checkout is not currently positioned exactly on a Git tag."
fi

echo
echo "============================================================"
echo "PASS: release smoke test completed successfully."
echo "============================================================"
