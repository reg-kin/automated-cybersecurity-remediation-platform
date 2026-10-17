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
#   SMOKE_PG_MODE docker (default) or native (psql using PGHOST/PGPORT/PGPASSFILE)
#   PG_CONTAINER   PostgreSQL container name
#   PG_USER        PostgreSQL user
#   TEST_DB        Temporary test database name
#
# Defaults reflect the current tested development environment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHON="${ROOT_DIR}/.venv/bin/python"
if [[ ! -x "${PYTHON}" ]]; then
    echo "ERROR: Project Python virtual environment is missing." >&2
    echo "Create it with: python3 -m venv .venv" >&2
    echo "Install dependencies with: .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

PG_CONTAINER="${PG_CONTAINER:-portal-datastore}"
PG_USER="${PG_USER:-telemetry_admin}"
SMOKE_PG_MODE="${SMOKE_PG_MODE:-docker}"
# Never accept libpq connection strings, service overrides or multiple endpoints.
[[ -z "${PGSERVICE:-}${PGSERVICEFILE:-}${PGHOSTADDR:-}${PGOPTIONS:-}${PGREQUIRESSL:-}${PGREQUIREPEER:-}${PGGSSENCMODE:-}${PGKRBSRVNAME:-}${PGGSSLIB:-}${PGREALM:-}${PGREQUIREAUTH:-}${PGLOADBALANCEHOSTS:-}${PGTARGETSESSIONATTRS:-}${PGSSLNEGOTIATION:-}" ]] || {
    echo "ERROR: libpq endpoint, session or authentication overrides are not supported." >&2; exit 1;
}
export PGHOST="${PGHOST:-127.0.0.1}"
export PGPORT="${PGPORT:-5432}"
[[ "${PGHOST}" =~ ^[a-zA-Z0-9_.:-]+$ && "${PGPORT}" =~ ^[0-9]{1,5}$ ]] &&
    (( 10#${PGPORT} > 0 && 10#${PGPORT} <= 65535 )) || {
    echo "ERROR: Invalid PostgreSQL host or port." >&2; exit 1;
}
[[ "${PG_USER}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ && ${#PG_USER} -le 63 ]] || exit 1
case "${SMOKE_PG_MODE}" in
    docker|native) ;;
    *) echo "ERROR: SMOKE_PG_MODE must be docker or native." >&2; exit 1 ;;
esac
export PGCONNECT_TIMEOUT=5
INVOCATION_ID="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(10))')"
TEST_DB="${TEST_DB:-automated_remediation_release_smoke_test}_${INVOCATION_ID}"
[[ "${TEST_DB}" =~ ^automated_remediation_release_smoke_test_[a-z0-9_]+$ && ${#TEST_DB} -le 63 ]] || {
    echo "ERROR: Invalid TEST_DB prefix (maximum 42 ASCII bytes before the 21-byte random suffix)." >&2; exit 1;
}
DB_CREATED=false
ROLE_CREATED=false
DB_OID=
ROLE_OID=
CREATION_ATTEMPTED=false
DB_CREATION_ATTEMPTED=false
DB_REMOVED=false

smoke_psql() {
    if [[ "${SMOKE_PG_MODE}" == native ]]; then
        SMOKE_DB_PASSWORD="${SMOKE_DB_PASSWORD}" psql -X -w -h "${PGHOST}" -p "${PGPORT}" "$@"
    else
        docker exec -i -e PGCONNECT_TIMEOUT=5 -e SMOKE_DB_PASSWORD="${SMOKE_DB_PASSWORD}" \
            "${PG_CONTAINER}" env -u PGSERVICE -u PGSERVICEFILE -u PGHOSTADDR -u PGOPTIONS -u PGREQUIRESSL -u PGREQUIREPEER -u PGGSSENCMODE -u PGKRBSRVNAME -u PGGSSLIB -u PGREALM -u PGREQUIREAUTH -u PGLOADBALANCEHOSTS -u PGTARGETSESSIONATTRS -u PGSSLNEGOTIATION psql -X -w -h 127.0.0.1 -p 5432 "$@"
    fi
}

SMOKE_DB_USER="remediation_smoke_${INVOCATION_ID}"
SMOKE_DB_PASSWORD="$("${PYTHON}" -c 'import secrets; print(secrets.token_urlsafe(32))')"

EXPECTED_FINDING_CLASSES=43
EXPECTED_GENERIC_RULES=43
EXPECTED_TOTAL_RULES=44

SPECIALISED_RULE_NAME="wazuh_sca_cis_ubuntu24_04_35594_crontab_permissions"

# Read the installer's validated, ordered manifest; never glob migrations.
SQL_MANIFEST="$(
    "${PYTHON}" - "${ROOT_DIR}" <<'PYTHON'
import sys
sys.path.insert(0, sys.argv[1] + "/install")
from database import ROOT_DIR, validate_manifest
for path in validate_manifest():
    print(path.relative_to(ROOT_DIR))
PYTHON
)" || { echo "ERROR: Database installation manifest is invalid." >&2; exit 1; }
mapfile -t SQL_FILES <<< "${SQL_MANIFEST}"

cleanup() {
    local status=$? cleanup_failed=false
    if [[ "${CREATION_ATTEMPTED:-false}" == true && ( "${DB_CREATED}" != true || "${ROLE_CREATED}" != true ) ]]; then
        cleanup_failed=true
        echo "Manual review: database=${TEST_DB} role=${SMOKE_DB_USER}; creation or ownership was not fully acknowledged." >&2
    fi
    local kind name oid actual drop_response
    for kind in DATABASE ROLE; do
        if [[ "${kind}" == DATABASE ]]; then
            [[ "${DB_CREATED}" == true ]] || continue
            name="${TEST_DB}"; oid="${DB_OID}"
            actual="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 \
                -c "SELECT oid FROM pg_database WHERE datname='${name}' AND datdba=${ROLE_OID} AND shobj_description(oid, 'pg_database')='${INVOCATION_ID}';")" || actual=
        else
            [[ "${ROLE_CREATED}" == true ]] || continue
            if [[ "${DB_CREATION_ATTEMPTED:-false}" == true && "${DB_REMOVED:-false}" != true ]]; then
                echo "ERROR: Retaining role ${SMOKE_DB_USER}: database ${TEST_DB} has not been safely removed." >&2
                cleanup_failed=true
                continue
            fi
            name="${SMOKE_DB_USER}"; oid="${ROLE_OID}"
            actual="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 \
                -c "SELECT oid FROM pg_roles WHERE rolname='${name}' AND shobj_description(oid, 'pg_authid')='${INVOCATION_ID}';")" || actual=
        fi
        if [[ ! "${oid}" =~ ^[0-9]+$ || "${actual}" != "${oid}" ]]; then
            echo "ERROR: Cannot establish ownership of ${kind} ${name}; leaving it untouched." >&2
            cleanup_failed=true
            continue
        fi
        local suffix=""
        [[ "${kind}" != DATABASE ]] || suffix=" WITH (FORCE)"
        if ! drop_response="$(smoke_psql -U "${PG_USER}" -d postgres -At -v ON_ERROR_STOP=1 \
            -c "DROP ${kind} ${name}${suffix};")" || [[ "${drop_response}" != "DROP ${kind}" ]]; then
            echo "ERROR: Cleanup failed for ${kind} ${name}." >&2
            cleanup_failed=true
        elif [[ "${kind}" == DATABASE ]]; then
            DB_REMOVED=true
        fi
    done
    if [[ "${cleanup_failed}" == true ]]; then
        echo "Recovery: mode=${SMOKE_PG_MODE:-unknown} host=${PGHOST:-unknown} port=${PGPORT:-unknown} container=${PG_CONTAINER:-none} database=${TEST_DB} database_oid=${DB_OID:-unknown} role=${SMOKE_DB_USER} role_oid=${ROLE_OID:-unknown} marker=${INVOCATION_ID}; inspect owner, OIDs and comments on this endpoint before manual removal; remove the database before its role." >&2
        [[ ${status} -ne 0 ]] || status=1
    fi
    exit "${status}"
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

echo "[1/11] Checking required repository files..."

REQUIRED_FILES=(
    "README.md"
    "LICENSE"
    "SECURITY.md"
    "CONTRIBUTING.md"
    "docs/ARCHITECTURE.md"
    "docs/PROJECT_STATUS.md"
    "docs/REMEDIATION_WORKFLOW_ORCHESTRATION.md"
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
echo "[2/11] Running catalogue consistency check..."

"${PYTHON}" tests/check_catalogue.py

pass "Catalogue consistency check passed."

# ---------------------------------------------------------------------------
# 3. Git whitespace check
# ---------------------------------------------------------------------------

echo
echo "[3/11] Checking Git whitespace integrity..."

git diff --check

pass "No Git whitespace errors detected."

# ---------------------------------------------------------------------------
# 4. Secret-literal check
# ---------------------------------------------------------------------------

echo
echo "[4/11] Checking tracked files for obvious literal credentials..."

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
echo "[5/11] Running release-critical regression tests..."

REGRESSION_TESTS=(
    "tests/test_remediation_controller_runtime.py"
    "tests/test_deferred_verification_runtime.py"
    "tests/test_ansible_runner_allowlist.py"
    "tests/test_ansible_runner_target_validation.py"
    "tests/test_ansible_runner_identity.py"
    "tests/test_systemd_service_identity.py"
    "tests/test_verification_gateway_security.py"
    "tests/test_verification_command_safety.py"
    "tests/test_verification_stdin_transport.py"
    "tests/test_api_authentication.py"
    "tests/test_unified_finding_schema.py"
    "tests/test_nuclei_normalization.py"
    "tests/test_trivy_normalization.py"
    "tests/test_nmap_normalization.py"
    "tests/test_lynis_normalization.py"
    "tests/test_wazuh_sca_normalization.py"
    "tests/test_wazuh_sca_api_configuration.py"
    "tests/test_wazuh_vulnerability_normalization.py"
    "tests/test_wazuh_indexer_tls_configuration.py"
    "tests/test_wazuh_integration_redis_configuration.py"
    "tests/test_openvas_normalization.py"
    "tests/test_scan_policy_scheduling.py"
)

for test_file in "${REGRESSION_TESTS[@]}"; do
    [[ -f "${test_file}" ]] \
        || fail "Required regression test missing: ${test_file}"

    echo "  Running ${test_file}"
    "${PYTHON}" "${test_file}"
done

pass "Release-critical regression tests passed."

# ---------------------------------------------------------------------------
# 6. Deployment contract checks
# ---------------------------------------------------------------------------

echo
echo "[6/11] Checking deployment contracts..."

CONTROLLER_API="remediation/controller_api.py"
DISPATCHER="verification/verification_dispatcher.py"
COMPOSE="deployment/docker/n8n-ansible/docker-compose.yml"
ANSIBLE_RUNNER_REQUIREMENTS="ansible-runner/requirements.txt"
ANSIBLE_RUNNER_DOCKERFILE="ansible-runner/Dockerfile"
ENRICHER_SERVICE="deployment/systemd/ollama-wazuh-enricher.service"
ENRICHER_OVERRIDE="deployment/systemd/ollama-wazuh-enricher.service.d/override.conf"
CONTROLLER_ENV="deployment/systemd/env/remediation-controller.env.example"
REMEDIATION_DISPATCHER_SERVICE="deployment/systemd/remediation-dispatcher.service"
REMEDIATION_DISPATCHER_TIMER="deployment/systemd/remediation-dispatcher.timer"
REMEDIATION_DISPATCHER_ENV="deployment/systemd/env/remediation-dispatcher.env.example"
SCANNER_ENV="deployment/systemd/env/verification-scanner.env.example"
WAZUH_INDEXER_ENV="deployment/systemd/env/wazuh-indexer.env.example"

for file in \
    "${CONTROLLER_API}" \
    "${DISPATCHER}" \
    "${COMPOSE}" \
    "${ANSIBLE_RUNNER_REQUIREMENTS}" \
    "${ANSIBLE_RUNNER_DOCKERFILE}" \
    "${ENRICHER_SERVICE}" \
    "${CONTROLLER_ENV}" \
    "${REMEDIATION_DISPATCHER_SERVICE}" \
    "${REMEDIATION_DISPATCHER_TIMER}" \
    "${REMEDIATION_DISPATCHER_ENV}" \
    "${SCANNER_ENV}" \
    "${WAZUH_INDEXER_ENV}"
do
    [[ -f "${file}" ]] || fail "Required deployment contract file missing: ${file}"
done

# Public scanner configuration names must remain neutral. This deliberately
# checks production scanner sources and deployment examples only; obsolete
# names retained by negative security tests and non-environment integration
# identifiers are outside this contract.
DEPRECATED_SCANNER_ENV_PATTERN='REGIS_(NMAP|LYNIS|COMPLIANCE|LOG_DIR|WAZUH|SCA|NUCLEI|OPENVAS|GVMD|SCANNER|TRIVY)_[A-Z0-9_]+'

if grep -REn     "${DEPRECATED_SCANNER_ENV_PATTERN}"     scanner_orchestrators     deployment/systemd/env
then
    fail "Deprecated REGIS_* scanner configuration name detected."
fi

for expected in     'NUCLEI_BINARY=/usr/bin/nuclei'     'TRIVY_BINARY=/usr/bin/trivy'     'NMAP_BINARY=/usr/bin/nmap'
do
    grep -Fxq "${expected}" "${SCANNER_ENV}"         || fail "Scanner verification environment example is missing: ${expected}"
done

grep -Fxq 'WAZUH_INDEXER_USER=CHANGE_ME' "${WAZUH_INDEXER_ENV}"     || fail "Wazuh Indexer environment example is missing WAZUH_INDEXER_USER."

grep -Fxq 'WAZUH_INDEXER_PASSWORD=CHANGE_ME' "${WAZUH_INDEXER_ENV}"     || fail "Wazuh Indexer environment example is missing WAZUH_INDEXER_PASSWORD."

grep -Fxq 'WAZUH_API_URL=https://wazuh-manager.example.test:55000' "${SCANNER_ENV}" \
    || fail "Scanner verification environment example is missing HTTPS WAZUH_API_URL."

grep -Fxq '# WAZUH_API_CA_BUNDLE=/etc/ssl/certs/wazuh-api-ca.pem' "${SCANNER_ENV}" \
    || fail "Scanner verification environment example is missing WAZUH_API_CA_BUNDLE documentation."

grep -Fxq 'WAZUH_INDEXER_URL=https://127.0.0.1:9200' "${WAZUH_INDEXER_ENV}" \
    || fail "Wazuh Indexer environment example is missing HTTPS WAZUH_INDEXER_URL."

grep -Fxq '# WAZUH_INDEXER_CA_BUNDLE=/etc/ssl/certs/wazuh-indexer-ca.pem' "${WAZUH_INDEXER_ENV}" \
    || fail "Wazuh Indexer environment example is missing WAZUH_INDEXER_CA_BUNDLE documentation."

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


# The remediation dispatcher is a timer-driven one-shot service.
grep -Fxq 'Type=oneshot' "${REMEDIATION_DISPATCHER_SERVICE}" \
    || fail "Remediation dispatcher must remain a one-shot service."

grep -Fxq \
    'ExecStart=/opt/automated-remediation/venv/bin/python -m remediation.dispatcher' \
    "${REMEDIATION_DISPATCHER_SERVICE}" \
    || fail "Remediation dispatcher uses the wrong production entry point."

grep -Fxq \
    'EnvironmentFile=/etc/remediation-dispatcher.env' \
    "${REMEDIATION_DISPATCHER_SERVICE}" \
    || fail "Remediation dispatcher uses the wrong environment file."

grep -Fxq \
    'Wants=network-online.target remediation-controller.service' \
    "${REMEDIATION_DISPATCHER_SERVICE}" \
    || fail "Remediation dispatcher must request the controller dependency."

grep -Fxq 'TimeoutStartSec=3000' "${REMEDIATION_DISPATCHER_SERVICE}" \
    || fail "Remediation dispatcher systemd timeout is incorrect."

grep -Fxq 'OnBootSec=30s' "${REMEDIATION_DISPATCHER_TIMER}" \
    || fail "Remediation dispatcher timer has the wrong initial delay."

grep -Fxq 'OnUnitInactiveSec=30s' "${REMEDIATION_DISPATCHER_TIMER}" \
    || fail "Remediation dispatcher timer has the wrong invocation cadence."

grep -Fxq \
    'Unit=remediation-dispatcher.service' \
    "${REMEDIATION_DISPATCHER_TIMER}" \
    || fail "Remediation dispatcher timer targets the wrong service."

grep -Fxq 'Persistent=true' "${REMEDIATION_DISPATCHER_TIMER}" \
    || fail "Remediation dispatcher timer must remain persistent."

grep -Fxq 'CONTROLLER_TOKEN=CHANGE_ME' "${REMEDIATION_DISPATCHER_ENV}" \
    || fail "Remediation dispatcher environment example is missing CONTROLLER_TOKEN."

grep -Fxq \
    'CONTROLLER_REMEDIATE_URL=http://127.0.0.1:9000/remediate' \
    "${REMEDIATION_DISPATCHER_ENV}" \
    || fail "Remediation dispatcher environment example has the wrong controller URL."

grep -Fxq \
    'CONTROLLER_REQUEST_TIMEOUT=2700' \
    "${REMEDIATION_DISPATCHER_ENV}" \
    || fail "Remediation dispatcher controller timeout is incorrect."

# Ansible Runner Python dependencies must remain pinned to the tested versions.
grep -Fxq 'ansible==12.3.0' "${ANSIBLE_RUNNER_REQUIREMENTS}" \
    || fail "Ansible Runner must pin ansible to tested version 12.3.0."

grep -Fxq 'psycopg2-binary==2.9.12' "${ANSIBLE_RUNNER_REQUIREMENTS}" \
    || fail "Ansible Runner must pin psycopg2-binary to tested version 2.9.12."

if grep -Eq '^ansible[[:space:]]*(>=|>|~=|==)?[[:space:]]*9\.0\.0$|^ansible>=9\.0\.0$' "${ANSIBLE_RUNNER_REQUIREMENTS}"; then
    fail "Ansible Runner must not use the previous floating ansible requirement."
fi

if grep -Eq '^psycopg2-binary[[:space:]]*$' "${ANSIBLE_RUNNER_REQUIREMENTS}"; then
    fail "Ansible Runner must not use an unpinned psycopg2-binary requirement."
fi

if grep -Eq '^[[:space:]]*ansible[[:space:]]*\\$' "${ANSIBLE_RUNNER_DOCKERFILE}"; then
    fail "Ansible Runner Dockerfile must not install the redundant Debian ansible package."
fi

EXPECTED_ANSIBLE_RUNNER_BASE_IMAGE="python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534"

grep -Fqx \
    "FROM ${EXPECTED_ANSIBLE_RUNNER_BASE_IMAGE}" \
    "${ANSIBLE_RUNNER_DOCKERFILE}" \
    || fail "Ansible Runner base image must be pinned to the tested digest."

if grep -Eq '^FROM[[:space:]]+python:3\.11-slim([[:space:]]|$)' "${ANSIBLE_RUNNER_DOCKERFILE}"; then
    fail "Ansible Runner Dockerfile must not use the floating python:3.11-slim tag."
fi

# n8n must use the tested release version rather than a floating tag.
grep -Fq "image: docker.n8n.io/n8nio/n8n:2.31.7" "${COMPOSE}" \
    || fail "Compose deployment must pin n8n to tested version 2.31.7."

if grep -Eq 'image:[[:space:]]+docker\.n8n\.io/n8nio/n8n:latest([[:space:]]|$)' "${COMPOSE}"; then
    fail "Compose deployment must not use the floating n8n:latest tag."
fi

# The Ansible Runner container must not receive unnecessary host-level
# network administration privileges.
if grep -Eq '^[[:space:]]*-[[:space:]]*NET_ADMIN([[:space:]]|$)' "${COMPOSE}"; then
    fail "Ansible Runner Compose deployment must not grant NET_ADMIN."
fi

if grep -Eq '^[[:space:]]*privileged:[[:space:]]*true([[:space:]]|$)' "${COMPOSE}"; then
    fail "Compose deployment must not enable privileged container execution."
fi

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
    'ExecStart=/opt/automated-remediation/venv/bin/rq worker ai-enrichment --path /opt/automated-remediation' \
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

"${PYTHON}" - <<'PY_CHECK'
from pathlib import Path
import ast

dispatcher_path = Path(
    "verification/verification_dispatcher.py"
)

tree = ast.parse(
    dispatcher_path.read_text()
)

expected = {
    "openvas":
        "/opt/automated-remediation/scanner_orchestrators/openvas_orchestrator.py",
    "nmap_nse":
        "/opt/automated-remediation/scanner_orchestrators/nmap_orchestrator.py",
    "wazuh_vulnerability":
        "/opt/automated-remediation/scanner_orchestrators/wazuh_vuln_orchestrator.py",
    "wazuh_sca":
        "/opt/automated-remediation/scanner_orchestrators/wazuh_sca_orchestrator.py",
    "lynis":
        "/opt/automated-remediation/scanner_orchestrators/lynis_orchestrator.py",
    "nuclei":
        "/opt/automated-remediation/scanner_orchestrators/nuclei_orchestrator.py",
    "trivy":
        "/opt/automated-remediation/scanner_orchestrators/trivy_orchestrator.py",
}

mapping = None

for node in tree.body:
    if not isinstance(node, ast.Assign):
        continue

    if not any(
        isinstance(target, ast.Name)
        and target.id == "ORCHESTRATORS"
        for target in node.targets
    ):
        continue

    if not isinstance(node.value, ast.Dict):
        raise SystemExit(
            "ORCHESTRATORS is not a dictionary"
        )

    mapping = {}

    for key_node, value_node in zip(
        node.value.keys,
        node.value.values,
    ):
        if not (
            isinstance(key_node, ast.Constant)
            and isinstance(key_node.value, str)
        ):
            raise SystemExit(
                "ORCHESTRATORS contains a non-string key"
            )

        if not (
            isinstance(value_node, ast.Call)
            and isinstance(value_node.func, ast.Attribute)
            and isinstance(value_node.func.value, ast.Name)
            and value_node.func.value.id == "os"
            and value_node.func.attr == "getenv"
            and len(value_node.args) >= 2
            and isinstance(value_node.args[1], ast.Constant)
            and isinstance(value_node.args[1].value, str)
        ):
            raise SystemExit(
                "Unexpected ORCHESTRATORS value for "
                f"{key_node.value}"
            )

        mapping[key_node.value] = (
            value_node.args[1].value
        )

    break

if mapping is None:
    raise SystemExit(
        "ORCHESTRATORS mapping not found"
    )

missing = sorted(
    set(expected) - set(mapping)
)

unexpected = sorted(
    set(mapping) - set(expected)
)

wrong_paths = {
    engine: {
        "expected": expected[engine],
        "actual": mapping.get(engine),
    }
    for engine in expected
    if mapping.get(engine) != expected[engine]
}

if missing:
    raise SystemExit(
        "Verification dispatcher is missing engines: "
        + ", ".join(missing)
    )

if unexpected:
    raise SystemExit(
        "Verification dispatcher has unexpected engines: "
        + ", ".join(unexpected)
    )

if wrong_paths:
    details = "; ".join(
        f"{engine}: expected "
        f"{values['expected']!r}, got "
        f"{values['actual']!r}"
        for engine, values in wrong_paths.items()
    )

    raise SystemExit(
        "Verification dispatcher has incorrect "
        f"orchestrator paths: {details}"
    )

print(
    "PASS: Verification dispatcher engine mapping is correct."
)
PY_CHECK

pass "Deployment contracts are consistent."

# ---------------------------------------------------------------------------
# 7. PostgreSQL availability
# ---------------------------------------------------------------------------

echo
echo "[7/11] Checking PostgreSQL test environment..."

if [[ "${SMOKE_PG_MODE}" == docker ]]; then
    command -v docker >/dev/null 2>&1 || fail "docker command is not available."
    docker ps --format '{{.Names}}' | grep -Fxq "${PG_CONTAINER}" \
        || fail "PostgreSQL container is not running: ${PG_CONTAINER}"
else
    command -v psql >/dev/null 2>&1 || fail "psql command is not available."
fi

smoke_psql \
    -U "${PG_USER}" \
    -d postgres \
    -v ON_ERROR_STOP=1 \
    -c "SELECT 1;" \
    >/dev/null

pass "PostgreSQL test server is reachable."

# ---------------------------------------------------------------------------
# 8. Clean database reconstruction
# ---------------------------------------------------------------------------

echo
echo "[8/11] Reconstructing temporary database..."

existing_db="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT 1 FROM pg_database WHERE datname = '${TEST_DB}';")"
[[ -z "${existing_db}" ]] || fail "Test database already exists; refusing to overwrite: ${TEST_DB}"

existing_role="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT 1 FROM pg_roles WHERE rolname = '${SMOKE_DB_USER}';")"
[[ -z "${existing_role}" ]] || fail "Smoke role already exists: ${SMOKE_DB_USER}"
CREATION_ATTEMPTED=true
# Failed CREATE may have committed: never infer ownership from an attempt.
if ! smoke_psql \
    -U "${PG_USER}" \
    -d postgres \
    -v ON_ERROR_STOP=1 <<SQL
\\getenv smoke_db_password SMOKE_DB_PASSWORD

BEGIN;
CREATE ROLE ${SMOKE_DB_USER}
    LOGIN
    PASSWORD :'smoke_db_password';
COMMENT ON ROLE ${SMOKE_DB_USER} IS '${INVOCATION_ID}';
COMMIT;
SQL
then
    fail "Ambiguous role creation; manual review required: ${SMOKE_DB_USER}"
fi
ROLE_OID="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 -c "SELECT oid FROM pg_roles WHERE rolname='${SMOKE_DB_USER}';")"
[[ "${ROLE_OID}" =~ ^[0-9]+$ ]] || fail "Ambiguous role OID; manual review required."
ROLE_CREATED=true

DB_CREATION_ATTEMPTED=true
if ! create_response="$(smoke_psql -U "${PG_USER}" -d postgres -At -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE ${TEST_DB} OWNER ${SMOKE_DB_USER};")" || [[ "${create_response}" != "CREATE DATABASE" ]]; then
    # The role may own a database after an ambiguous CREATE. Retain both.
    ROLE_CREATED=false
    fail "Ambiguous database creation; manual review required: ${TEST_DB} ${SMOKE_DB_USER}"
fi
if ! comment_response="$(smoke_psql -U "${PG_USER}" -d postgres -At -v ON_ERROR_STOP=1 \
    -c "COMMENT ON DATABASE ${TEST_DB} IS '${INVOCATION_ID}';")" || [[ "${comment_response}" != COMMENT ]]; then
    fail "Ambiguous database comment; manual review required: ${TEST_DB} ${SMOKE_DB_USER}"
fi
DB_OID="$(smoke_psql -U "${PG_USER}" -d postgres -qAt -v ON_ERROR_STOP=1 -c "SELECT oid FROM pg_database WHERE datname='${TEST_DB}';")"
[[ "${DB_OID}" =~ ^[0-9]+$ ]] || fail "Ambiguous database OID; manual review required."
SMOKE_EXPECTED_ENDPOINT="$(smoke_psql -U "${PG_USER}" -d "${TEST_DB}" -qAt -v ON_ERROR_STOP=1 \
    -c "SELECT inet_server_addr()::text || ':' || inet_server_port() || ':' || oid || ':' || shobj_description(oid, 'pg_database') FROM pg_database WHERE datname=current_database();")"
[[ "${SMOKE_EXPECTED_ENDPOINT}" =~ ^[a-zA-Z0-9_.:-]+:[0-9]+:${DB_OID}:${INVOCATION_ID}$ ]] || fail "Ambiguous server identity response; manual review required."
DB_CREATED=true
export SMOKE_PG_MODE
export SMOKE_EXPECTED_ENDPOINT
export SMOKE_DISPOSABLE_DATABASE="${TEST_DB}"
export PG_DBNAME="${TEST_DB}" PG_HOST="${PGHOST}" PG_PORT="${PGPORT}"
export PG_PASSWORD="${SMOKE_DB_PASSWORD}"
PG_USER="${SMOKE_DB_USER}" "${PYTHON}" -c 'from sys import path; path.insert(0, "tests"); from smoke_database_guard import connect; connect().close()'


for file in "${SQL_FILES[@]}"; do
    echo "  Applying ${file}"

    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -v ON_ERROR_STOP=1 \
        < "${file}" \
        >/dev/null
done

smoke_psql \
    -U "${PG_USER}" \
    -d "${TEST_DB}" \
    -v ON_ERROR_STOP=1 <<SQL
GRANT CONNECT ON DATABASE ${TEST_DB}
    TO ${SMOKE_DB_USER};

GRANT USAGE ON SCHEMA public
    TO ${SMOKE_DB_USER};

GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public
    TO ${SMOKE_DB_USER};

GRANT USAGE, SELECT, UPDATE
    ON ALL SEQUENCES IN SCHEMA public
    TO ${SMOKE_DB_USER};
SQL

pass "Database reconstruction completed successfully."

# ---------------------------------------------------------------------------
# 9. Deterministic Wazuh asset resolution
# ---------------------------------------------------------------------------

echo
echo "[9/11] Checking deterministic asset resolution..."

PG_PASSWORD="${SMOKE_DB_PASSWORD}"

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_asset_resolver.py \
    || fail "Deterministic asset resolver regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_enricher_asset_integration.py \
    || fail "Enricher asset integration regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_asset_context.py \
    || fail "Asset context management regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_risk_persistence.py \
    || fail "Risk persistence regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_risk_reassessment.py \
    || fail "Risk reassessment regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_risk_aware_remediation_prioritisation.py \
    || fail "Risk-aware remediation prioritisation regression failed."

"${PYTHON}" tests/test_controller_api_error_codes.py || fail "Controller API error-code regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_remediation_target_safety.py \
    || fail "Remediation target-safety regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_asset_remediation_readiness.py \
    || fail "Asset remediation readiness regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_administrative_readiness_management.py \
    || fail "Administrative readiness management regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_readiness_admin_api.py \
    || fail "Readiness administrative API regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_coordination_foundation.py \
    || fail "Scan coordination foundation regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_execution_lease_safety.py \
    || fail "Scan execution lease-safety regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_coordination_service.py \
    || fail "Scan coordination service regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_subject_resolution.py \
    || fail "Scan subject resolution regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_policy_scheduler.py \
    || fail "Scan policy scheduler regression failed."

"${PYTHON}" tests/test_scan_policy_scheduling.py \
    || fail "Scan policy scheduling calculation regression failed."

"${PYTHON}" tests/test_scan_policy_scheduler_runtime.py \
    || fail "Scan policy scheduler runtime regression failed."

"${PYTHON}" tests/test_systemd_service_identity.py \
    || fail "Systemd service identity regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_execution_node_authentication.py \
    || fail "Scan execution-node authentication regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_scan_coordination_agent_api.py \
    || fail "Scan Coordination Agent API regression failed."

"${PYTHON}" tests/test_scan_execution_scanner_adapters.py \
    || fail "Scan execution scanner-adapter regression failed."

"${PYTHON}" tests/test_scan_execution_agent.py \
    || fail "Scan execution agent regression failed."


"${PYTHON}" tests/test_remediation_dispatcher.py \
    || fail "Remediation dispatcher regression failed."

PG_HOST="${PGHOST:-127.0.0.1}" \
PG_PORT="${PGPORT:-5432}" \
PG_DBNAME="${TEST_DB}" \
PG_USER="${SMOKE_DB_USER}" \
PG_PASSWORD="${PG_PASSWORD}" \
"${PYTHON}" tests/test_remediation_workflow_orchestration.py \
    || fail "Remediation workflow orchestration regression failed."

"${PYTHON}" tests/test_risk_contextualisation.py \
    || fail "Risk contextualisation regression failed."

unset PG_PASSWORD

pass "Deterministic asset and risk contextualisation checks are correct."

# ---------------------------------------------------------------------------
# 10. Database invariant checks
# ---------------------------------------------------------------------------

echo
echo "[10/11] Checking reconstructed database invariants..."

finding_class_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM finding_class_catalogue;"
)"

rule_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM remediation_rules;"
)"

generic_rule_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "SELECT COUNT(*) FROM remediation_rules WHERE rule_name LIKE '%\_generic' ESCAPE '\';"
)"

orphan_rule_count="$(
    smoke_psql \
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
    smoke_psql \
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

asset_table_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
              'assets',
              'asset_identifiers',
              'asset_endpoints',
              'asset_context',
              'asset_observations',
              'asset_relationships'
          );
        "
)"

finding_asset_column_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'unified_security_findings'
          AND column_name = 'asset_id'
          AND data_type = 'bigint'
          AND is_nullable = 'YES';
        "
)"

finding_asset_fk_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_constraint
        WHERE conname = 'fk_unified_security_findings_asset'
          AND contype = 'f';
        "
)"

strong_identifier_index_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'asset_identifiers'
          AND indexname = 'uq_asset_identifiers_strong_active';
        "
)"

application_identifier_index_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'asset_identifiers'
          AND indexname = 'uq_asset_identifiers_application_active';
        "
)"

prioritised_queue_view_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.views
        WHERE table_schema = 'public'
          AND table_name = 'prioritised_remediation_queue';
        "
)"

risk_assessment_table_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'finding_risk_assessments';
        "
)"

risk_assessment_finding_fk_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_constraint
        WHERE conname = 'fk_risk_assessment_finding_tenant'
          AND contype = 'f';
        "
)"

risk_assessment_asset_fk_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_constraint
        WHERE conname = 'fk_risk_assessment_asset_tenant'
          AND contype = 'f';
        "
)"

risk_assessment_pk_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_constraint
        WHERE conrelid = 'finding_risk_assessments'::regclass
          AND contype = 'p';
        "
)"

scan_coordination_table_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
              'scan_execution_nodes',
              'scan_execution_node_capabilities',
              'scan_execution_node_assets',
              'scan_policies',
              'scan_executions'
          );
        "
)"

scan_node_credential_table_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'scan_execution_node_credentials';
        "
)"

scan_service_tier_column_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name = 'service_tier'
          AND table_name IN (
              'scan_policies',
              'scan_executions'
          );
        "
)"

scan_service_tier_not_null_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name = 'service_tier'
          AND table_name IN (
              'scan_policies',
              'scan_executions'
          )
          AND is_nullable = 'NO';
        "
)"

scan_policy_execution_node_column_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'scan_policies'
          AND column_name = 'execution_node_id';
        "
)"

scan_tenant_asset_fk_table_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(DISTINCT child.relname)
        FROM pg_constraint c
        JOIN pg_class child
          ON child.oid = c.conrelid
        JOIN pg_namespace child_ns
          ON child_ns.oid = child.relnamespace
        JOIN pg_class parent
          ON parent.oid = c.confrelid
        WHERE child_ns.nspname = 'public'
          AND c.contype = 'f'
          AND child.relname IN (
              'scan_execution_node_assets',
              'scan_policies',
              'scan_executions'
          )
          AND parent.relname = 'assets'
          AND pg_get_constraintdef(c.oid) LIKE
              'FOREIGN KEY (asset_id, tenant_code) REFERENCES assets(asset_id, tenant_code)%';
        "
)"

scan_active_execution_index_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -At \
        -c "
        SELECT COUNT(*)
        FROM pg_class index_relation
        JOIN pg_index index_metadata
          ON index_metadata.indexrelid = index_relation.oid
        JOIN pg_class table_relation
          ON table_relation.oid = index_metadata.indrelid
        JOIN pg_namespace table_namespace
          ON table_namespace.oid = table_relation.relnamespace
        WHERE table_namespace.nspname = 'public'
          AND table_relation.relname = 'scan_executions'
          AND index_relation.relname = 'uq_scan_policy_active_execution'
          AND index_metadata.indisunique IS TRUE
          AND index_metadata.indpred IS NOT NULL;
        "
)"

[[ "${scan_coordination_table_count}" == "5" ]] \
    || fail "Expected 5 scan-coordination tables, found ${scan_coordination_table_count}."

[[ "${scan_node_credential_table_count}" == "1" ]] \
    || fail "Expected exactly one scan execution-node credential table, found ${scan_node_credential_table_count}."

[[ "${scan_service_tier_column_count}" == "2" ]] \
    || fail "Expected service_tier on scan_policies and scan_executions."

[[ "${scan_service_tier_not_null_count}" == "2" ]] \
    || fail "scan_policies.service_tier and scan_executions.service_tier must both be NOT NULL."

[[ "${scan_policy_execution_node_column_count}" == "0" ]] \
    || fail "scan_policies must not contain execution_node_id."

[[ "${scan_tenant_asset_fk_table_count}" == "3" ]] \
    || fail "Expected tenant-scoped asset foreign keys on all 3 scan-coordination asset tables, found ${scan_tenant_asset_fk_table_count}."

[[ "${scan_active_execution_index_count}" == "1" ]] \
    || fail "Partial unique active-execution index is missing or incorrect."

echo "  scan_tables:      ${scan_coordination_table_count}"
echo "  scan_node_creds:  ${scan_node_credential_table_count}"
echo "  scan_policy_node: ${scan_policy_execution_node_column_count}"
echo "  scan_asset_fks:   ${scan_tenant_asset_fk_table_count}"
echo "  scan_active_idx:  ${scan_active_execution_index_count}"

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

asset_identity_constraint_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -qAt \
        -v ON_ERROR_STOP=1 \
        -c "
        BEGIN;

        INSERT INTO assets (
            tenant_code,
            asset_type,
            canonical_name
        )
        VALUES
            ('ASSET-TEST', 'HOST', 'host-a'),
            ('ASSET-TEST', 'HOST', 'host-b');

        INSERT INTO asset_identifiers (
            asset_id,
            tenant_code,
            identifier_type,
            identifier_value,
            normalized_value,
            source,
            confidence
        )
        SELECT
            MIN(asset_id),
            'ASSET-TEST',
            'WAZUH_AGENT_ID',
            '007',
            '007',
            'wazuh_sca',
            'VERY_HIGH'
        FROM assets
        WHERE tenant_code = 'ASSET-TEST';

        DO \$\$
        DECLARE
            other_asset_id BIGINT;
        BEGIN
            SELECT MAX(asset_id)
            INTO other_asset_id
            FROM assets
            WHERE tenant_code = 'ASSET-TEST';

            BEGIN
                INSERT INTO asset_identifiers (
                    asset_id,
                    tenant_code,
                    identifier_type,
                    identifier_value,
                    normalized_value,
                    source,
                    confidence
                )
                VALUES (
                    other_asset_id,
                    'ASSET-TEST',
                    'WAZUH_AGENT_ID',
                    '007',
                    '007',
                    'wazuh_vulnerability',
                    'VERY_HIGH'
                );

                RAISE EXCEPTION
                    'duplicate strong identifier unexpectedly accepted';
            EXCEPTION
                WHEN unique_violation THEN
                    NULL;
            END;
        END
        \$\$;

        ROLLBACK;

        SELECT 1;
        "
)"

application_identity_constraint_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -qAt \
        -v ON_ERROR_STOP=1 \
        -c "
        BEGIN;

        INSERT INTO assets (
            tenant_code,
            asset_type,
            canonical_name
        )
        VALUES
            (
                'APPLICATION-ASSET-TEST',
                'APPLICATION',
                'https://example.test'
            ),
            (
                'APPLICATION-ASSET-TEST',
                'APPLICATION',
                'duplicate-application'
            );

        INSERT INTO asset_identifiers (
            asset_id,
            tenant_code,
            identifier_type,
            identifier_value,
            normalized_value,
            source,
            confidence
        )
        SELECT
            MIN(asset_id),
            'APPLICATION-ASSET-TEST',
            'APPLICATION_ID',
            'https://example.test',
            'https://example.test',
            'nuclei',
            'HIGH'
        FROM assets
        WHERE tenant_code = 'APPLICATION-ASSET-TEST';

        DO \$\$
        DECLARE
            other_asset_id BIGINT;
        BEGIN
            SELECT MAX(asset_id)
            INTO other_asset_id
            FROM assets
            WHERE tenant_code = 'APPLICATION-ASSET-TEST';

            BEGIN
                INSERT INTO asset_identifiers (
                    asset_id,
                    tenant_code,
                    identifier_type,
                    identifier_value,
                    normalized_value,
                    source,
                    confidence
                )
                VALUES (
                    other_asset_id,
                    'APPLICATION-ASSET-TEST',
                    'APPLICATION_ID',
                    'https://example.test',
                    'https://example.test',
                    'nuclei',
                    'HIGH'
                );

                RAISE EXCEPTION
                    'duplicate application identifier unexpectedly accepted';
            EXCEPTION
                WHEN unique_violation THEN
                    NULL;
            END;
        END
        \$\$;

        ROLLBACK;

        SELECT 1;
        "
)"

asset_tenant_constraint_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -qAt \
        -v ON_ERROR_STOP=1 \
        -c "
        BEGIN;

        INSERT INTO assets (
            tenant_code,
            asset_type,
            canonical_name
        )
        VALUES (
            'TENANT-A',
            'HOST',
            'tenant-a-host'
        );

        DO \$\$
        DECLARE
            test_asset_id BIGINT;
        BEGIN
            SELECT asset_id
            INTO test_asset_id
            FROM assets
            WHERE tenant_code = 'TENANT-A'
              AND canonical_name = 'tenant-a-host'
            ORDER BY asset_id DESC
            LIMIT 1;

            BEGIN
                INSERT INTO asset_identifiers (
                    asset_id,
                    tenant_code,
                    identifier_type,
                    identifier_value,
                    normalized_value,
                    source,
                    confidence
                )
                VALUES (
                    test_asset_id,
                    'TENANT-B',
                    'HOSTNAME',
                    'tenant-a-host',
                    'tenant-a-host',
                    'test',
                    'MEDIUM'
                );

                RAISE EXCEPTION
                    'cross-tenant asset identifier unexpectedly accepted';
            EXCEPTION
                WHEN foreign_key_violation THEN
                    NULL;
            END;
        END
        \$\$;

        ROLLBACK;

        SELECT 1;
        "
)"

risk_assessment_constraint_count="$(
    smoke_psql \
        -U "${PG_USER}" \
        -d "${TEST_DB}" \
        -qAt \
        -v ON_ERROR_STOP=1 \
        -c "
        BEGIN;

        DO \$\$
        DECLARE
            asset_a BIGINT;
            finding_a BIGINT;
            finding_b BIGINT;
            retained_count INTEGER;
            cascade_count INTEGER;
        BEGIN
            INSERT INTO assets (
                tenant_code,
                asset_type,
                canonical_name
            )
            VALUES (
                'RISK-TENANT-A',
                'HOST',
                'risk-host-a'
            )
            RETURNING asset_id INTO asset_a;

            INSERT INTO unified_security_findings (
                tenant_code,
                tenant_service_tier,
                target_host,
                engine_source,
                finding_category,
                finding_class,
                finding_key,
                finding_title,
                severity_level,
                severity_score
            )
            VALUES (
                'RISK-TENANT-A',
                'STANDARD',
                'risk-host-a',
                'openvas',
                'vulnerability',
                'cve',
                'risk-test-a',
                'Risk foundation test A',
                'HIGH',
                8.0
            )
            RETURNING finding_id INTO finding_a;

            INSERT INTO unified_security_findings (
                tenant_code,
                tenant_service_tier,
                target_host,
                engine_source,
                finding_category,
                finding_class,
                finding_key,
                finding_title,
                severity_level,
                severity_score
            )
            VALUES (
                'RISK-TENANT-B',
                'STANDARD',
                'risk-host-b',
                'openvas',
                'vulnerability',
                'cve',
                'risk-test-b',
                'Risk foundation test B',
                'MEDIUM',
                5.0
            )
            RETURNING finding_id INTO finding_b;

            INSERT INTO finding_risk_assessments (
                finding_id,
                tenant_code,
                asset_id,
                assessment_status,
                base_severity_score,
                base_severity_level,
                contextual_risk_score,
                contextual_risk_level,
                assessment_factors,
                context_snapshot,
                assessment_model
            )
            VALUES (
                finding_a,
                'RISK-TENANT-A',
                asset_a,
                'ASSESSED',
                8.0,
                'HIGH',
                8.25,
                'HIGH',
                '{}'::jsonb,
                '{}'::jsonb,
                'CONTEXTUAL_RISK_V1'
            );

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    assessment_status,
                    contextual_risk_score,
                    contextual_risk_level,
                    assessment_model
                )
                VALUES (
                    finding_a,
                    'RISK-TENANT-A',
                    'PARTIAL',
                    8.0,
                    'HIGH',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'duplicate risk assessment unexpectedly accepted';
            EXCEPTION
                WHEN unique_violation THEN
                    NULL;
            END;

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    assessment_status,
                    contextual_risk_score,
                    contextual_risk_level,
                    assessment_model
                )
                VALUES (
                    finding_b,
                    'RISK-TENANT-A',
                    'PARTIAL',
                    5.0,
                    'MEDIUM',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'cross-tenant finding risk assessment unexpectedly accepted';
            EXCEPTION
                WHEN foreign_key_violation THEN
                    NULL;
            END;

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    asset_id,
                    assessment_status,
                    contextual_risk_score,
                    contextual_risk_level,
                    assessment_model
                )
                VALUES (
                    finding_b,
                    'RISK-TENANT-B',
                    asset_a,
                    'PARTIAL',
                    5.0,
                    'MEDIUM',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'cross-tenant risk asset unexpectedly accepted';
            EXCEPTION
                WHEN foreign_key_violation THEN
                    NULL;
            END;

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    assessment_status,
                    assessment_model
                )
                VALUES (
                    finding_b,
                    'RISK-TENANT-B',
                    'ASSESSED',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'scored assessment without score unexpectedly accepted';
            EXCEPTION
                WHEN check_violation THEN
                    NULL;
            END;

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    assessment_status,
                    contextual_risk_score,
                    contextual_risk_level,
                    assessment_model
                )
                VALUES (
                    finding_b,
                    'RISK-TENANT-B',
                    'UNSCORABLE',
                    5.0,
                    'MEDIUM',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'UNSCORABLE assessment with score unexpectedly accepted';
            EXCEPTION
                WHEN check_violation THEN
                    NULL;
            END;

            BEGIN
                INSERT INTO finding_risk_assessments (
                    finding_id,
                    tenant_code,
                    assessment_status,
                    contextual_risk_score,
                    contextual_risk_level,
                    assessment_model
                )
                VALUES (
                    finding_b,
                    'RISK-TENANT-B',
                    'PARTIAL',
                    10.01,
                    'CRITICAL',
                    'CONTEXTUAL_RISK_V1'
                );

                RAISE EXCEPTION
                    'out-of-range contextual risk score unexpectedly accepted';
            EXCEPTION
                WHEN check_violation THEN
                    NULL;
            END;

            DELETE FROM assets
            WHERE asset_id = asset_a;

            SELECT COUNT(*)
            INTO retained_count
            FROM finding_risk_assessments
            WHERE finding_id = finding_a
              AND tenant_code = 'RISK-TENANT-A'
              AND asset_id IS NULL;

            IF retained_count <> 1 THEN
                RAISE EXCEPTION
                    'asset deletion did not preserve risk assessment';
            END IF;

            DELETE FROM unified_security_findings
            WHERE finding_id = finding_a;

            SELECT COUNT(*)
            INTO cascade_count
            FROM finding_risk_assessments
            WHERE finding_id = finding_a;

            IF cascade_count <> 0 THEN
                RAISE EXCEPTION
                    'finding deletion did not cascade to risk assessment';
            END IF;
        END
        \$\$;

        ROLLBACK;

        SELECT 1;
        "
)"

[[ "${prioritised_queue_view_count}" == "1" ]] \
    || fail "prioritised_remediation_queue view is missing."

[[ "${risk_assessment_table_count}" == "1" ]] \
    || fail "finding_risk_assessments table is missing."

[[ "${risk_assessment_finding_fk_count}" == "1" ]] \
    || fail "Risk-assessment finding tenant foreign key is missing."

[[ "${risk_assessment_asset_fk_count}" == "1" ]] \
    || fail "Risk-assessment asset tenant foreign key is missing."

[[ "${risk_assessment_pk_count}" == "1" ]] \
    || fail "Risk-assessment primary key is missing."

[[ "${risk_assessment_constraint_count}" == "1" ]] \
    || fail "Risk-assessment database integrity behaviour is incorrect."

[[ "${asset_table_count}" == "6" ]] \
    || fail "Expected 6 asset-management tables, found ${asset_table_count}."

[[ "${finding_asset_column_count}" == "1" ]] \
    || fail "unified_security_findings.asset_id is missing, incorrectly typed, or not nullable."

[[ "${finding_asset_fk_count}" == "1" ]] \
    || fail "Finding-to-asset foreign key is missing."

[[ "${strong_identifier_index_count}" == "1" ]] \
    || fail "Strong active asset-identifier uniqueness index is missing."

[[ "${application_identifier_index_count}" == "1" ]] \
    || fail "Active application-identifier uniqueness index is missing."

[[ "${asset_identity_constraint_count}" == "1" ]] \
    || fail "Strong asset identifier uniqueness behaviour is incorrect."

[[ "${application_identity_constraint_count}" == "1" ]] \
    || fail "Application identifier uniqueness behaviour is incorrect."

[[ "${asset_tenant_constraint_count}" == "1" ]] \
    || fail "Asset tenant-isolation behaviour is incorrect."

echo "  finding_classes: ${finding_class_count}"
echo "  generic_rules:   ${generic_rule_count}"
echo "  total_rules:     ${rule_count}"
echo "  priority_view:   ${prioritised_queue_view_count}"
echo "  risk_table:      ${risk_assessment_table_count}"
echo "  risk_finding_fk: ${risk_assessment_finding_fk_count}"
echo "  risk_asset_fk:   ${risk_assessment_asset_fk_count}"
echo "  risk_pk:         ${risk_assessment_pk_count}"
echo "  risk_guard:      ${risk_assessment_constraint_count}"
echo "  asset_tables:    ${asset_table_count}"
echo "  finding_asset:   ${finding_asset_column_count}"
echo "  asset_fk:        ${finding_asset_fk_count}"
echo "  strong_id_index: ${strong_identifier_index_count}"
echo "  strong_id_guard: ${asset_identity_constraint_count}"
echo "  app_id_index:    ${application_identifier_index_count}"
echo "  app_id_guard:    ${application_identity_constraint_count}"
echo "  tenant_guard:    ${asset_tenant_constraint_count}"
echo "  orphan_rules:    ${orphan_rule_count}"

pass "Database invariants are correct."

# ---------------------------------------------------------------------------
# 11. Git release/tag information
# ---------------------------------------------------------------------------

echo
echo "[11/11] Checking Git release information..."

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
