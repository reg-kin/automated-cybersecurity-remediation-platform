"""Execute smoke lifecycle fragments with fake SQL only; never use PostgreSQL."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from smoke_database_guard import connect

SCRIPT = (Path(__file__).parent / 'release_smoke_test.sh').read_text()
CLEANUP = SCRIPT[SCRIPT.index('cleanup() {'):SCRIPT.index('\nfail() {')]
CREATE = SCRIPT[SCRIPT.index('existing_db='):SCRIPT.index('for file in "${SQL_FILES[@]}";', SCRIPT.index('existing_db='))]


class SmokeSafetyTests(unittest.TestCase):
    def lifecycle(self, scenario, status=0):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'calls'
            command = '''set -Eeuo pipefail
DB_CREATED=false ROLE_CREATED=false
DB_OID= ROLE_OID=
TEST_DB=automated_remediation_release_smoke_test_abc
SMOKE_DB_USER=remediation_smoke_abc
INVOCATION_ID=abc
PG_USER=admin
smoke_psql() {
    local sql="$*"
    if [[ "$sql" != *"-c "* ]]; then sql="$(cat)"; fi
    printf '%s\\n' "$sql" >> "$LOG"
    if [[ "$sql" == *"SELECT 1"* ]]; then
        [[ "$SCENARIO" != collision ]] || echo 1
    elif [[ "$sql" == *"CREATE ROLE"* && "$SCENARIO" == role_failure ]]; then return 9
    elif [[ "$sql" == *"CREATE DATABASE"* && "$SCENARIO" == db_failure ]]; then return 9
    elif [[ "$sql" == *"COMMENT ON DATABASE"* && "$SCENARIO" == marker_failure ]]; then return 9
    elif [[ "$sql" == *"SELECT inet_server_addr"* ]]; then
        [[ "$SCENARIO" != endpoint_failure ]] || return 9
        [[ "$SCENARIO" != ambiguous_endpoint ]] || return 0
        echo '127.0.0.1:5432:42:abc'
    elif [[ "$sql" == *"SELECT oid"* ]]; then
        if [[ "$sql" == *pg_database* && "$SCENARIO" == db_oid_failure ]]; then return 9; fi
        if [[ "$sql" == *pg_database* && "$SCENARIO" == ambiguous_db_oid ]]; then printf '42\\n43\\n'; return; fi
        if [[ "$SCENARIO" == oid_failure ]]; then return 9; fi
        if [[ "$SCENARIO" == ambiguous_oid ]]; then printf '42\\n43\\n'; return; fi
        if [[ "$SCENARIO" == lookup_failure && "$sql" == *description* ]]; then return 9; fi
        if [[ "$SCENARIO" == ownership_mismatch && "$sql" == *description* ]]; then echo 99; else echo 42; fi
    elif [[ "$sql" == *"DROP "* && "$SCENARIO" == cleanup_failure ]]; then return 8
    elif [[ "$sql" == *"DROP DATABASE"* ]]; then
        [[ "$SCENARIO" != ambiguous_drop ]] || return 0
        echo 'DROP DATABASE'
    elif [[ "$sql" == *"DROP ROLE"* ]]; then
        [[ "$SCENARIO" != role_cleanup_failure ]] || return 8
        echo 'DROP ROLE'
    elif [[ "$sql" == *"CREATE DATABASE"* ]]; then
        [[ "$SCENARIO" != ambiguous_create ]] || return 0
        echo 'CREATE DATABASE'
    elif [[ "$sql" == *"COMMENT ON DATABASE"* ]]; then
        [[ "$SCENARIO" != ambiguous_comment ]] || return 0
        echo COMMENT
    fi
    return 0
}
fail() { echo "$*" >&2; exit 1; }
''' + CLEANUP + '\ntrap cleanup EXIT\n' + CREATE.split('export SMOKE_PG_MODE')[0] + f'\nexit {status}\n'
            result = subprocess.run(['bash', '-c', command], env={**os.environ, 'LOG': str(log), 'SCENARIO': scenario}, capture_output=True, text=True)
            return result, log.read_text()

    def test_collision_never_drops(self):
        result, calls = self.lifecycle('collision')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('CREATE ', calls)
        self.assertNotIn('DROP ', calls)

    def test_failed_or_ambiguous_creation_never_drops_uncertain_objects(self):
        for scenario in ('role_failure', 'db_failure', 'ambiguous_create'):
            with self.subTest(scenario=scenario):
                result, calls = self.lifecycle(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('manual review', result.stderr)
                self.assertNotIn('DROP ', calls)

    def test_cleanup_requires_ownership(self):
        result, calls = self.lifecycle('ownership_mismatch')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('DROP ', calls)

    def test_success_cleanup_and_failure_status(self):
        result, calls = self.lifecycle('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('DROP DATABASE', calls)
        self.assertIn('DROP ROLE', calls)
        for status in (0, 7):
            result, calls = self.lifecycle('cleanup_failure', status)
            self.assertEqual(result.returncode, status or 1)
            self.assertIn('Recovery:', result.stderr)
            self.assertNotIn('DROP ROLE', calls)

    def test_role_cleanup_failure_reports_recovery(self):
        result, calls = self.lifecycle('role_cleanup_failure')
        self.assertEqual(result.returncode, 1)
        self.assertIn('DROP DATABASE', calls)
        self.assertIn('DROP ROLE', calls)
        self.assertIn('Recovery:', result.stderr)

    def test_endpoint_and_disposable_guard(self):
        database = 'automated_remediation_release_smoke_test_abc'
        fake = MagicMock()
        fake.cursor.return_value.__enter__.return_value.fetchall.return_value = [('other:5432:42:' + 'a' * 20,)]
        driver = Mock(connect=Mock(return_value=fake))
        with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'disposable'):
                connect(dbname='production')
            driver.connect.assert_not_called()
            os.environ.update(SMOKE_DISPOSABLE_DATABASE=database, SMOKE_EXPECTED_ENDPOINT='server:5432:42:' + 'a' * 20, PG_HOST='server', PG_PORT='5432')
            with self.assertRaisesRegex(RuntimeError, 'endpoint mismatch'):
                connect(dbname=database)
            fake.close.assert_called_once()
            self.assertEqual(driver.connect.call_args.kwargs['connect_timeout'], 5)

    def test_guard_accepts_verified_endpoint(self):
        database = 'automated_remediation_release_smoke_test_abc'
        fake = MagicMock()
        fake.cursor.return_value.__enter__.return_value.fetchall.return_value = [('server:5432:42:' + 'a' * 20,)]
        driver = Mock(connect=Mock(return_value=fake))
        with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, {
                'SMOKE_DISPOSABLE_DATABASE': database, 'PG_HOST': 'server', 'PG_PORT': '5432',
                'SMOKE_EXPECTED_ENDPOINT': 'server:5432:42:' + 'a' * 20}, clear=True):
            self.assertIs(connect(dbname=database), fake)
            fake.rollback.assert_called_once()
            fake.close.assert_not_called()

    def guard_fixture(self):
        database = 'automated_remediation_release_smoke_test_' + 'a' * 20
        marker = 'a' * 20
        fake = MagicMock()
        fake.cursor.return_value.__enter__.return_value.fetchall.return_value = [
            ('172.18.0.2:5432:42:' + marker,)]
        driver = Mock(connect=Mock(return_value=fake))
        env = dict(PG_HOST='localhost', PG_PORT='15432', PG_USER='smoke',
                   PG_DBNAME=database, SMOKE_DISPOSABLE_DATABASE=database,
                   SMOKE_EXPECTED_ENDPOINT='127.0.0.1:5432:42:' + marker)
        return database, fake, driver, env

    def test_effective_arguments_rejected_before_connect(self):
        database, fake, driver, env = self.guard_fixture()
        overrides = (
            {'database': 'production'}, {'database': 'production', 'dbname': database},
            {'dbname': 'postgresql://other/production'}, {'dsn': 'dbname=production'},
            {'host': 'elsewhere'}, {'host': 'localhost,other'}, {'hostaddr': '192.0.2.1'},
            {'port': 5432}, {'port': '15432 dbname=production'}, {'service': 'other'},
            {'options': '-c role=other'}, {'password': 'different'},
        )
        env['PG_PASSWORD'] = 'generated'
        with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, env, clear=True):
            for kwargs in overrides:
                with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                    connect(**kwargs)
                driver.connect.assert_not_called()

    def test_invalid_effective_endpoint_and_inherited_configuration(self):
        database, fake, driver, env = self.guard_fixture()
        overrides = ({'PG_HOST': ''}, {'PG_HOST': '/tmp'}, {'PG_PORT': '0'},
                     {'PG_PORT': '65536'}, {'PG_PORT': '1,2'},
                     {'PG_DBNAME': database + 'x'}, {'PGHOST': 'other'},
                     {'PGPORT': '5432'})
        from smoke_database_guard import UNSAFE_ENV
        overrides += tuple({key: 'override'} for key in UNSAFE_ENV)
        for override in overrides:
            with self.subTest(override=override), patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, {**env, **override}, clear=True):
                with self.assertRaises(RuntimeError):
                    connect()
                driver.connect.assert_not_called()

    def test_docker_identity_allows_nat_but_rejects_other_database(self):
        database, fake, driver, env = self.guard_fixture()
        with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'endpoint mismatch'):
                connect()
            os.environ['SMOKE_PG_MODE'] = 'docker'
            self.assertIs(connect(database=database, port=15432), fake)
            for rows in ([], [(None,)], [('127.0.0.1:5432:99:' + 'a' * 20,)],
                         [('127.0.0.1:5432:42:' + 'b' * 20,)],
                         [('127.0.0.1:5432:42:' + 'a' * 20,)] * 2):
                fake.cursor.return_value.__enter__.return_value.fetchall.return_value = rows
                with self.subTest(rows=rows), self.assertRaisesRegex(RuntimeError, 'endpoint mismatch'):
                    connect()

    def test_password_file_and_scram_settings_remain_supported(self):
        database, fake, driver, env = self.guard_fixture()
        env.update(SMOKE_PG_MODE='docker', PGPASSFILE='/private/pgpass',
                   PGSSLMODE='verify-full', PGCHANNELBINDING='require')
        with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, env, clear=True):
            self.assertIs(connect(), fake)
            self.assertNotIn('password', driver.connect.call_args.kwargs)

    def test_identifier_byte_limits(self):
        database, fake, driver, env = self.guard_fixture()
        for length in (63, 64):
            name = 'automated_remediation_release_smoke_test_'.ljust(length, 'a')
            with patch.dict(sys.modules, {'psycopg2': driver}), patch.dict(os.environ, {
                    **env, 'PG_DBNAME': name, 'SMOKE_DISPOSABLE_DATABASE': name,
                    'SMOKE_PG_MODE': 'docker'}, clear=True):
                if length == 63:
                    self.assertIs(connect(), fake)
                else:
                    driver.connect.reset_mock()
                    with self.assertRaises(RuntimeError):
                        connect()
                    driver.connect.assert_not_called()

    def test_all_smoke_database_connections_use_guard(self):
        import re
        for name in set(re.findall(r'"\$\{PYTHON\}" (tests/test_\w+\.py)', SCRIPT)):
            text = (Path(__file__).resolve().parents[1] / name).read_text()
            self.assertNotIn('psycopg2.connect(', text, name)

    def test_metadata_failures_leave_unproven_objects(self):
        for scenario in ('marker_failure', 'oid_failure', 'lookup_failure', 'ambiguous_oid', 'ambiguous_drop',
                         'db_oid_failure', 'ambiguous_db_oid', 'endpoint_failure', 'ambiguous_endpoint',
                         'ambiguous_comment'):
            result, calls = self.lifecycle(scenario)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('DROP ROLE', calls)
            self.assertIn('Recovery:', result.stderr)
            if scenario != 'ambiguous_drop':
                self.assertNotIn('DROP DATABASE', calls)

    def test_invalid_endpoints_stop_before_sql(self):
        fragment = SCRIPT[SCRIPT.index('PG_CONTAINER='):SCRIPT.index('export PGCONNECT_TIMEOUT=')]
        for overrides in ({'PGHOST': 'host dbname=production'}, {'PGHOST': 'a,b'},
                          {'PGPORT': '0'}, {'PGPORT': '65536'}, {'PGSERVICE': 'other'},
                          {'PGHOSTADDR': '192.0.2.1'}, {'PGPORT': 'abc'},
                          {'PGOPTIONS': '-c role=other'}, {'PGREQUIREAUTH': 'none'},
                          {'PG_USER': 'a' * 64}):
            with self.subTest(overrides=overrides):
                result = subprocess.run(['bash', '-c', 'set -e\n' + fragment],
                                        env={**os.environ, **overrides}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_shell_identifier_prefix_limits(self):
        fragment = SCRIPT[SCRIPT.index('INVOCATION_ID='):SCRIPT.index('DB_CREATED=false')]
        for length in (42, 43):
            prefix = ('automated_remediation_release_smoke_test_'
                      .ljust(length, 'a'))
            result = subprocess.run(['bash', '-c', 'set -e\n' + fragment],
                                    env={**os.environ, 'PYTHON': sys.executable,
                                         'TEST_DB': prefix}, capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, length == 42, result.stderr)

    def test_transport_and_random_identifiers(self):
        fragment = SCRIPT[SCRIPT.index('smoke_psql() {'):SCRIPT.index('\nSMOKE_DB_USER=')]
        for mode in ('native', 'docker'):
            result = subprocess.run(['bash', '-c', 'psql() { echo psql "$@"; }; docker() { echo docker "$@"; };\n' + fragment + '\nsmoke_psql -d postgres'], env={**os.environ, 'SMOKE_PG_MODE': mode, 'SMOKE_DB_PASSWORD': '', 'PGHOST': 'db.example', 'PGPORT': '5433', 'PG_CONTAINER': 'test'}, capture_output=True, text=True, check=True)
            self.assertIn('-X -w -h', result.stdout)
            if mode == 'docker':
                self.assertIn('env -u PGSERVICE', result.stdout)
                self.assertIn('-u PGOPTIONS', result.stdout)
                self.assertNotIn('-u PGPASSFILE', result.stdout)
            self.assertIn('5433' if mode == 'native' else '5432', result.stdout)
        self.assertIn('secrets.token_hex(10)', SCRIPT)
        self.assertIn('TEST_DB:-automated_remediation_release_smoke_test}_${INVOCATION_ID}', SCRIPT)


if __name__ == '__main__':
    unittest.main()
