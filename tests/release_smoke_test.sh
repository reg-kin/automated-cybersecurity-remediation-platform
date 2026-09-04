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
#   PG_CONTAINER   PostgreSQL container name
#   PG_USER        PostgreSQL user
#   TEST_DB        Temporary test database name
#
# Defaults reflect the current tested development environment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PG_CONTAINER="${PG_CONTAINER:-portal-datastore}"
PG_USER="${PG_USER:-telemetry_admin}"
TEST_DB="${TEST_DB:-regis_release_smoke_test}"

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

echo "[1/10] Checking required repository files..."

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
echo "[2/10] Running catalogue consistency check..."

python3 tests/check_catalogue.py

pass "Catalogue consistency check passed."

# ---------------------------------------------------------------------------
# 3. Git whitespace check
# ---------------------------------------------------------------------------

echo
echo "[3/10] Checking Git whitespace integrity..."

git diff --check

pass "No Git whitespace errors detected."

# ---------------------------------------------------------------------------
# 4. Secret-literal check
# ---------------------------------------------------------------------------

echo
echo "[4/10] Checking tracked files for obvious literal credentials..."

if git grep -nEI \
    '([Pp]assword|[Pp]asswd|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey)[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{4,}["'\'']'
then
    fail "Possible literal credential detected in tracked files."
fi

pass "No obvious tracked literal credentials detected."

# ---------------------------------------------------------------------------
# 5. Release-critical regression tests
# ---------------------------------------------------------------------------

echo
echo "[5/10] Running release-critical regression tests..."

REGRESSION_TESTS=(
    "tests/test_remediation_controller_runtime.py"
    "tests/test_deferred_verification_runtime.py"
    "tests/test_ansible_runner_allowlist.py"
    "tests/test_verification_gateway_security.py"
    "tests/test_api_authentication.py"
    "tests/test_unified_finding_schema.py"
    "tests/test_nuclei_normalization.py"
    "tests/test_trivy_normalization.py"
    "tests/test_nmap_normalization.py"
    "tests/test_lynis_normalization.py"
    "tests/test_wazuh_sca_normalization.py"
    "tests/test_wazuh_vulnerability_normalization.py"
    "tests/test_openvas_normalization.py"
)

for test_file in "${REGRESSION_TESTS[@]}"; do
    [[ -f "${test_file}" ]] \
        || fail "Required regression test missing: ${test_file}"

    echo "  Running ${test_file}"
    python3 "${test_file}"
done

pass "Release-critical regression tests passed."

# ---------------------------------------------------------------------------
# 6. Deployment contract checks
# ---------------------------------------------------------------------------

echo
echo "[6/10] Checking deployment contracts..."

CONTROLLER_API="remediation/controller_api.py"
DISPATCHER="verification/verification_dispatcher.py"
COMPOSE="deployment/docker/n8n-ansible/docker-compose.yml"
ENRICHER_SERVICE="deployment/systemd/ollama-wazuh-enricher.service"
ENRICHER_OVERRIDE="deployment/systemd/ollama-wazuh-enricher.service.d/override.conf"
CONTROLLER_ENV="deployment/systemd/env/remediation-controller.env.example"

for file in \
    "${CONTROLLER_API}" \
    "${DISPATCHER}" \
    "${COMPOSE}" \
    "${ENRICHER_SERVICE}" \
    "${CONTROLLER_ENV}"
do
    [[ -f "${file}" ]] || fail "Required deployment contract file missing: ${file}"
done

# Controller bind configuration must remain externally configurable while
# retaining the documented loopback deployment default.
grep -Fq '"CONTROLLER_HOST"' "${CONTROLLER_API}" \
    || fail "Controller no longer consumes CONTROLLER_HOST."

grep -Fq '"CONTROLLER_PORT"' "${CONTROLLER_API}" \
    || fail "Controller no longer consumes CONTROLLER_PORT."

grep -Fxq 'CONTROLLER_HOST=127.0.0.1' "${CONTROLLER_ENV}" \
    || fail "Controller environment example must default to loopback."

grep -Fxq 'CONTROLLER_PORT=9000' "${CONTROLLER_ENV}" \
    || fail "Controller environment example has the wrong controller port."

# The reference Compose deployment exposes host port 8081 while the
# Ansible Runner container listens on port 8080.
grep -Fq '"127.0.0.1:8081:8080"' "${COMPOSE}" \
    || fail "Ansible Runner host/container port mapping is incorrect."

EXPECTED_PLAYBOOKS="os_patching.yml,container_image.yml,cis_hardening.yml,service_config.yml,web_application.yml,file_integrity.yml,security_incident.yml"

grep -Fq "ALLOWED_PLAYBOOKS=${EXPECTED_PLAYBOOKS}" "${COMPOSE}" \
    || fail "Production Ansible playbook allowlist is missing or incorrect."

if grep -Eq 'ALLOWED_PLAYBOOKS=.*controller_.*\.yml' "${COMPOSE}"; then
    fail "Controller test playbook appears in the production Ansible allowlist."
fi

# The repository root is the Python package import root for RQ workers.
grep -Fq \
    'ExecStart=/usr/bin/rq worker ai-enrichment --path /opt/automated-remediation' \
    "${ENRICHER_SERVICE}" \
    || fail "AI enrichment worker uses the wrong RQ import path."

[[ ! -e "${ENRICHER_OVERRIDE}" ]] \
    || fail "Obsolete AI enrichment systemd override has been restored."

# Stage-2 dispatcher support is intentionally limited to the seven
# implemented scanner orchestrators.
declare -A EXPECTED_ORCHESTRATORS=(
    [openvas]="/opt/automated-remediation/scanner_orchestrators/openvas_orchestrator.py"
    [nmap_nse]="/opt/automated-remediation/scanner_orchestrators/nmap_orchestrator.py"
    [wazuh_vulnerability]="/opt/automated-remediation/scanner_orchestrators/wazuh_vuln_orchestrator.py"
    [wazuh_sca]="/opt/automated-remediation/scanner_orchestrators/wazuh_sca_orchestrator.py"
    [lynis]="/opt/automated-remediation/scanner_orchestrators/lynis_orchestrator.py"
    [nuclei]="/opt/automated-remediation/scanner_orchestrators/nuclei_orchestrator.py"
    [trivy]="/opt/automated-remediation/scanner_orchestrators/trivy_orchestrator.py"
)

for engine in "${!EXPECTED_ORCHESTRATORS[@]}"; do
    orchestrator="${EXPECTED_ORCHESTRATORS[$engine]}"

    grep -Fq "'${engine}':os.getenv(" "${DISPATCHER}" \
        || fail "Verification dispatcher is missing engine: ${engine}"

    grep -F "'${engine}':os.getenv(" "${DISPATCHER}" \
        | grep -Fq "'${orchestrator}'" \
        || fail "Verification dispatcher has the wrong orchestrator path for ${engine}"
done

pass "Deployment contracts are consistent."

# ---------------------------------------------------------------------------
# 7. PostgreSQL availability
# ---------------------------------------------------------------------------

echo
echo "[7/10] Checking PostgreSQL test environment..."

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
# 8. Clean database reconstruction
# ---------------------------------------------------------------------------

echo
echo "[8/10] Reconstructing temporary database..."

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
# 9. Database invariant checks
# ---------------------------------------------------------------------------

echo
echo "[9/10] Checking reconstructed database invariants..."

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
# 10. Git release/tag information
# ---------------------------------------------------------------------------

echo
echo "[10/10] Checking Git release information..."

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
