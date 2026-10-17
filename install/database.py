#!/usr/bin/env python3
"""Database installation utility for fresh deployments."""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

SQL_FILES = [
    "database/001_schema.sql",
    "database/002_seed_finding_classes.sql",
    "database/003_seed_remediation_rules.sql",
    *(
        f"database/migrations/{number:03d}_{name}.sql"
        for number, name in [
            (4, "deferred_verification"),
            (5, "scanner_refresh_completions"),
            (6, "scanner_refresh_finding_receipts"),
            (7, "asset_management"),
            (8, "application_asset_identity"),
            (9, "risk_contextualisation"),
        ]
    ),
    "database/010_harden_remediation_routing.sql",
    "database/migrations/011_risk_aware_remediation_prioritisation.sql",
    "database/migrations/012_fix_package_vulnerability_rule.sql",
    "database/migrations/013_restore_remediation_attempt_trigger.sql",
    "database/migrations/014_remediation_retry_cooldown.sql",
    "database/migrations/015_remediation_execution_targets.sql",
    "database/migrations/016_asset_remediation_readiness.sql",
    "database/migrations/017_scan_coordination.sql",
    "database/migrations/018_scan_execution_lease_safety.sql",
    "database/migrations/019_scan_execution_node_authentication.sql",
    "database/migrations/020_scan_execution_context.sql",
    "database/migrations/021_scan_policy_scheduling.sql",
    "database/migrations/022_remediation_verification_functions.sql",
    "database/migrations/023_manual_verification.sql",
    "database/migrations/024_scan_policy_admin_audit.sql",
    "database/migrations/025_fix_claim_finding_attempt_count.sql",
]


def validate_manifest():
    """Ensure every required SQL file exists before installation."""
    missing = [
        filename
        for filename in SQL_FILES
        if not (ROOT_DIR / filename).is_file()
    ]

    if missing:
        raise RuntimeError(
            "Missing database installation files:\n"
            + "\n".join(missing)
        )

    return [ROOT_DIR / filename for filename in SQL_FILES]




PROTECTED_DATABASES = frozenset({
    "postgres",
    "template0",
    "template1",
    "security_portal",
})


def validate_database_target(database_name: str) -> str:
    """Reject missing or protected database targets."""
    if not database_name or not database_name.strip():
        raise ValueError("An explicit target database name is required.")

    database_name = database_name.strip()

    if database_name.lower() in PROTECTED_DATABASES:
        raise ValueError(
            f"Database '{database_name}' is protected from installation."
        )

    return database_name



def assert_database_empty(connection) -> None:
    """Require a fresh database without existing application objects.

    PostgreSQL extension-owned objects are excluded from the object check.
    Non-default extensions are rejected separately.
    """
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM pg_extension
                WHERE extname <> 'plpgsql'
            )
            OR EXISTS (
                SELECT 1
                FROM pg_namespace
                WHERE nspname NOT IN (
                    'public', 'pg_catalog', 'information_schema'
                )
                  AND nspname NOT LIKE 'pg_toast%'
                  AND nspname NOT LIKE 'pg_temp_%'
            )
            OR EXISTS (
                SELECT 1
                FROM pg_depend AS d
                JOIN pg_extension AS e
                  ON e.oid = d.refobjid
                WHERE d.deptype = 'e'
                  AND e.extname <> 'plpgsql'
            )
            OR EXISTS (
                SELECT 1
                FROM pg_class AS c
                JOIN pg_namespace AS n
                  ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
                  AND NOT EXISTS (
                      SELECT 1
                      FROM pg_depend AS d
                      WHERE d.classid = 'pg_class'::regclass
                        AND d.objid = c.oid
                        AND d.deptype = 'e'
                  )
            )
            OR EXISTS (
                SELECT 1
                FROM pg_proc AS p
                JOIN pg_namespace AS n
                  ON n.oid = p.pronamespace
                WHERE n.nspname = 'public'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM pg_depend AS d
                      WHERE d.classid = 'pg_proc'::regclass
                        AND d.objid = p.oid
                        AND d.deptype = 'e'
                  )
            )
            OR EXISTS (
                SELECT 1
                FROM pg_type AS t
                JOIN pg_namespace AS n
                  ON n.oid = t.typnamespace
                WHERE n.nspname = 'public'
                  AND t.typtype IN ('e', 'd', 'r', 'm')
                  AND NOT EXISTS (
                      SELECT 1
                      FROM pg_depend AS d
                      WHERE d.classid = 'pg_type'::regclass
                        AND d.objid = t.oid
                        AND d.deptype = 'e'
                  )
            )
        """)
        contains_objects = cursor.fetchone()[0]

    if contains_objects:
        raise RuntimeError(
            "Installation refused: target database is not empty."
        )


def prepare_migration_sql(path: Path) -> str:
    """Remove supported outer transaction wrappers without altering function bodies."""
    import re

    sql = path.read_text(encoding="utf-8")
    lines = sql.splitlines(keepends=True)

    begin_pattern = re.compile(r"^\s*BEGIN\s*;\s*(?:--[^\r\n]*)?$", re.I)
    commit_pattern = re.compile(r"^\s*COMMIT\s*;\s*(?:--[^\r\n]*)?$", re.I)

    begin_indices = [
        index for index, line in enumerate(lines)
        if begin_pattern.fullmatch(line.rstrip("\r\n"))
    ]
    commit_indices = [
        index for index, line in enumerate(lines)
        if commit_pattern.fullmatch(line.rstrip("\r\n"))
    ]

    if not begin_indices and not commit_indices:
        return sql

    if len(begin_indices) != 1 or len(commit_indices) != 1:
        raise RuntimeError(f"Unsupported transaction structure: {path}")

    begin_index = begin_indices[0]
    commit_index = commit_indices[0]

    if begin_index >= commit_index:
        raise RuntimeError(f"Invalid transaction boundaries: {path}")

    # Fail closed if substantive SQL appears outside the transaction.
    before = "".join(lines[:begin_index])
    after = "".join(lines[commit_index + 1:])

    def only_comments_and_whitespace(text: str) -> bool:
        return all(
            not line.strip() or line.lstrip().startswith("--")
            for line in text.splitlines()
        )

    if not only_comments_and_whitespace(before):
        raise RuntimeError(f"SQL before transaction boundary: {path}")

    if not only_comments_and_whitespace(after):
        raise RuntimeError(f"SQL after transaction boundary: {path}")

    return "".join(
        line
        for index, line in enumerate(lines)
        if index not in (begin_index, commit_index)
    )


def execute_migrations(connection) -> list[str]:
    """Apply the installation manifest in one caller-controlled transaction.

    The caller must explicitly commit after successful verification.
    Any exception triggers a rollback.
    """
    if connection.autocommit:
        raise RuntimeError("Installation requires autocommit=False.")

    from psycopg2 import extensions

    if connection.get_transaction_status() != extensions.TRANSACTION_STATUS_IDLE:
        raise RuntimeError(
            "Installation requires a connection with no active transaction."
        )

    try:
        files = validate_manifest()

        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            database_name = cursor.fetchone()[0]

        validate_database_target(database_name)

        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '10s'")
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                (20261012, 1),
            )

        assert_database_empty(connection)

        applied = []

        with connection.cursor() as cursor:
            for path in files:
                sql = prepare_migration_sql(path)
                cursor.execute(sql)
                applied.append(str(path.relative_to(ROOT_DIR)))

        return applied

    except Exception:
        connection.rollback()
        raise


if __name__ == "__main__":
    files = validate_manifest()
    print(f"Database installation manifest validated: {len(files)} files")
    for path in files:
        print(path.relative_to(ROOT_DIR))
