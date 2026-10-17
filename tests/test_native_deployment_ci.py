"""Native deployment checks use disposable files and fake process calls only."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'install'))
from install_application import environment_templates
from service_provisioning import inspect_service_provisioning
from provision_staged_application import provision_staged_application
from provision_python import provision_python_environment
from verify_deployment_configuration import MANDATORY, NATIVE_MANDATORY, verify_deployment_configuration


class NativeDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'app'
        self.app.mkdir(mode=0o700)
        shutil.copytree(ROOT / 'deployment', self.app / 'deployment')
        shutil.copyfile(ROOT / 'requirements.txt', self.app / 'requirements.txt')
        self.units = self.root / 'units'
        self.units.mkdir(mode=0o700)
        self.mapping = {key: self.root / Path(key).name
                        for key in environment_templates(native=True)}

    def test_legacy_and_native_inventory(self):
        self.assertEqual(len(environment_templates()), 6)
        self.assertEqual(len(inspect_service_provisioning(ROOT)['unit_names']), 9)
        result = inspect_service_provisioning(ROOT, native=True)
        self.assertEqual(len(result['unit_names']), 11)
        self.assertEqual(len(result['environment_files']), 8)
        self.assertEqual(result['actions_performed'], 0)

    def test_native_transaction_and_exact_content_verification(self):
        from verify_complete_provisioning import verify_complete_provisioning
        journal = self.root / 'journal'
        with patch('provisioning_middle_stages.provision_python_environment') as provision, \
             patch('provisioning_middle_stages.verify_python_environment', return_value=True), \
             patch('verify_complete_provisioning.verify_python_environment', return_value=True):
            result = provision_staged_application(journal, self.app, self.units, self.mapping,
                                                 uid=os.geteuid(), gid=os.getegid(), native=True)
            self.assertEqual(result['state'], 'COMPLETE')
            self.assertTrue(provision.call_args.kwargs['native'])
            self.assertEqual(len(list(self.units.iterdir())), 11)
            self.assertEqual(len(self.mapping), 8)
            (self.units / 'ansible-runner.service').write_text('changed')
            with self.assertRaisesRegex(RuntimeError, 'content mismatch'):
                verify_complete_provisioning(journal, self.app, self.units, self.mapping,
                                             uid=os.geteuid(), gid=os.getegid(), native=True)

    def test_native_post_configuration_readiness(self):
        from assess_offline_readiness import assess_offline_readiness
        with patch('provisioning_middle_stages.provision_python_environment'), \
             patch('provisioning_middle_stages.verify_python_environment', return_value=True), \
             patch('verify_complete_provisioning.verify_python_environment', return_value=True):
            provision_staged_application(self.root / 'journal', self.app, self.units, self.mapping,
                                         uid=os.geteuid(), gid=os.getegid(), native=True)
        self.configured()
        self.runtime_files()
        (self.app / 'venv/bin').mkdir(parents=True, exist_ok=True)
        (self.app / 'venv/pyvenv.cfg').write_text('test fixture')
        shutil.copyfile('/bin/true', self.app / 'venv/bin/python')
        (self.app / 'venv/bin/python').chmod(0o700)
        with patch('verify_python_ownership.verify_python_environment', return_value=True):
            result = assess_offline_readiness(self.root / 'journal', self.app, self.units, self.mapping,
                                              uid=os.geteuid(), gid=os.getegid(), native=True)
        self.assertEqual(result['configured_files'], 8)
        self.assertEqual(result['offline_readiness'], 'PASSED')
        self.assertFalse(result['activation_authorized'])

    def runtime_files(self):
        for directory in ('ansible', 'ansible-runner', 'verification', 'remediation',
                          'readiness_management', 'scan_policy_administration', 'scan_coordination', 'worker'):
            shutil.copytree(ROOT / directory, self.app / directory, dirs_exist_ok=True)
        (self.app / 'venv/bin').mkdir(parents=True, exist_ok=True)
        (self.app / 'venv/pyvenv.cfg').write_text('fixture')
        for name in ('python', 'gunicorn', 'ansible', 'ansible-playbook', 'rq'):
            path = self.app / 'venv/bin' / name
            path.write_text('fixture')
            path.chmod(0o700)

    def test_native_runtime_negative_access(self):
        from verify_service_identity_access import verify_service_identity_access
        self.configured()
        self.runtime_files()
        check = lambda: verify_service_identity_access(
            self.app, self.mapping, uid=os.geteuid(), gid=os.getegid(), native=True)
        check()
        with self.assertRaisesRegex(RuntimeError, 'traverse'):
            verify_service_identity_access(self.app, self.mapping,
                uid=os.geteuid() + 10000, gid=os.getegid() + 10000, native=True)
        for name in ('ansible-runner/server.py', 'verification/verification_gateway.py',
                     'ansible/playbooks/os_patching.yml', 'ansible/roles/os_patching/tasks/main.yml',
                     'venv/bin/gunicorn', 'venv/bin/ansible-playbook'):
            path = self.app / name
            mode = path.stat().st_mode
            path.chmod(0)
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                check()
            path.chmod(mode)
            saved = path.read_bytes()
            path.unlink()
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                check()
            path.write_bytes(saved)
            path.chmod(mode)
        executable = self.app / 'venv/bin/gunicorn'
        executable.unlink()
        target_dir = self.root / 'inaccessible-target'
        target_dir.mkdir()
        target = target_dir / 'gunicorn'
        target.write_text('fixture')
        target.chmod(0o700)
        executable.symlink_to(target)
        target_dir.chmod(0o600)
        with self.assertRaises((RuntimeError, PermissionError)):
            check()
        target_dir.chmod(0o700)
        (self.app / 'worker').chmod(0o600)
        with self.assertRaises(RuntimeError):
            check()

    def test_journal_profile_binding(self):
        from provisioning_journal import begin_provisioning, advance_provisioning, assert_not_deployable, STAGES
        from provisioning_middle_stages import execute_middle_stages
        from provisioning_final_stages import execute_final_provisioning_stages
        import json
        for native in (False, True):
            journal = self.root / f'journal-{native}'
            begin_provisioning(journal, application=self.app, native=native)
            with self.assertRaisesRegex(RuntimeError, 'profile'):
                advance_provisioning(journal, 'preflight', evidence_confirmed=True, native=not native)
            advance_provisioning(journal, 'preflight', evidence_confirmed=True, native=native)
            with self.assertRaisesRegex(RuntimeError, 'profile'):
                execute_middle_stages(journal, self.app, uid=os.geteuid(), gid=os.getegid(), native=not native)
            with self.assertRaisesRegex(RuntimeError, 'profile'):
                execute_final_provisioning_stages(journal, self.app, self.units, self.mapping,
                                                  uid=os.geteuid(), gid=os.getegid(), native=not native)
            for stage in STAGES[1:]:
                advance_provisioning(journal, stage, evidence_confirmed=True, native=native)
            with self.assertRaisesRegex(RuntimeError, 'profile'):
                assert_not_deployable(journal, native=not native)
            from verify_complete_provisioning import verify_complete_provisioning
            from assess_offline_readiness import assess_offline_readiness
            for verify in (verify_complete_provisioning, assess_offline_readiness):
                with self.assertRaisesRegex(RuntimeError, 'profile'):
                    verify(journal, self.app, self.units, self.mapping,
                           uid=os.geteuid(), gid=os.getegid(), native=not native)
            if not native:
                record = json.loads(journal.read_text())
                del record['profile']
                journal.write_text(json.dumps(record))
                self.assertEqual(assert_not_deployable(journal)['state'], 'COMPLETE')
                with self.assertRaisesRegex(RuntimeError, 'profile'):
                    assert_not_deployable(journal, native=True)

    def test_controller_legacy_defaults(self):
        lines = (ROOT / 'deployment/systemd/remediation-controller.service').read_text().splitlines()
        values = dict(line.removeprefix('Environment=').split('=', 1)
                      for line in lines if line.startswith('Environment=') and '=' in line)
        self.assertEqual(values['CONTROLLER_HOST'], '127.0.0.1')
        self.assertEqual(values['CONTROLLER_PORT'], '9000')
        self.assertLess(lines.index('Environment=CONTROLLER_PORT=9000'),
                        lines.index('EnvironmentFile=/etc/remediation-controller.env'))

    def test_production_roles_resolve_without_execution(self):
        import yaml
        unit = (ROOT / 'deployment/systemd/native/ansible-runner.service').read_text()
        self.assertIn('Environment=ANSIBLE_ROLES_PATH=/opt/automated-remediation/ansible/roles', unit)
        count = 0
        for playbook in (ROOT / 'ansible/playbooks').glob('*.yml'):
            for play in yaml.safe_load(playbook.read_text()):
                for role in play.get('roles', []):
                    name = role['role'] if isinstance(role, dict) else role
                    self.assertTrue((ROOT / 'ansible/roles' / name / 'tasks/main.yml').is_file(), name)
                    count += 1
        self.assertGreaterEqual(count, 7)

    def test_smoke_cleanup_failure_preserves_status_and_recovery(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        cleanup = script[script.index('cleanup() {'):script.index('\nfail() {')]
        for status in (0, 7):
            command = f'''DB_CREATED=true
ROLE_CREATED=true
TEST_DB=automated_remediation_release_smoke_test
SMOKE_DB_USER=remediation_smoke_test
PG_USER=test
smoke_psql() {{ echo "$*" >&2; return 1; }}
{cleanup}
trap cleanup EXIT
exit {status}
'''
            result = subprocess.run(['bash', '-c', command], capture_output=True, text=True)
            self.assertEqual(result.returncode, status or 1)
            self.assertIn('WITH (FORCE)', result.stderr)
            self.assertIn('Recovery: database=', result.stderr)
            self.assertIn('role=remediation_smoke_test', result.stderr)
        self.assertLess(script.index('ROLE_CREATED=true'), script.index('CREATE ROLE'))
        self.assertLess(script.index('DB_CREATED=true'), script.index('CREATE DATABASE'))

    def test_smoke_server_creation_then_client_failure(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        cleanup = script[script.index('cleanup() {'):script.index('\nfail() {')]
        creation = script[script.index('existing_db='):script.index('for file in "${SQL_FILES[@]}";', script.index('existing_db='))]
        for failure in ('ROLE', 'DATABASE'):
            marker = self.root / 'transport-calls'
            marker.unlink(missing_ok=True)
            command = f'''set -Eeuo pipefail
DB_CREATED=false
ROLE_CREATED=false
TEST_DB=automated_remediation_release_smoke_test
SMOKE_DB_USER=remediation_smoke_test
PG_USER=test
smoke_psql() {{
    local sql="$*"
    if [[ "$sql" != *"-c "* ]]; then sql="$(cat)"; fi
    echo "$sql" >> '{marker}'
    if [[ "$sql" == *"CREATE {failure}"* ]]; then return 9; fi
}}
fail() {{ exit 1; }}
{cleanup}
trap cleanup EXIT
{creation}
'''
            result = subprocess.run(['bash', '-c', command], capture_output=True, text=True)
            self.assertEqual(result.returncode, 9)
            calls = marker.read_text()
            self.assertIn('DROP ROLE IF EXISTS remediation_smoke_test', calls)
            if failure == 'DATABASE':
                self.assertIn('DROP DATABASE IF EXISTS automated_remediation_release_smoke_test WITH (FORCE)', calls)
            else:
                self.assertNotIn('DROP DATABASE', calls)

    def test_native_dependency_command(self):
        with patch('provision_python.subprocess.run') as run:
            provision_python_environment(self.app, native=True, installer=['/bin/true'])
        self.assertEqual(run.call_args.args[0][-4:], [
            '--requirement', str(self.app / 'requirements.txt'),
            '--requirement', str(self.app / 'deployment/requirements-native.txt')])

    def configured(self):
        for key, template in environment_templates(native=True).items():
            text = (ROOT / template).read_text().replace('CHANGE_ME', 'TEST_ONLY')
            for setting in {**MANDATORY, **NATIVE_MANDATORY}[key]:
                text = text.replace(setting + '=\n', setting + '=TEST_ONLY\n')
            self.mapping[key].write_text(text)
            self.mapping[key].chmod(0o640)

    def check(self):
        return verify_deployment_configuration(self.mapping, uid=os.geteuid(), gid=os.getegid(), native=True)

    def test_native_configuration_matches(self):
        self.configured()
        self.assertEqual(self.check()['configured_files'], 8)

    def test_native_authentication_and_endpoint_mismatches(self):
        for old, new, message in [('ANSIBLE_RUNNER_TOKEN=TEST_ONLY', 'ANSIBLE_RUNNER_TOKEN=different', 'authentication'),
                                  ('ANSIBLE_RUNNER_PORT=8081', 'ANSIBLE_RUNNER_PORT=1234', 'endpoint'),
                                  ('ANSIBLE_RUNNER_PORT=8081', 'ANSIBLE_RUNNER_PORT=invalid', 'endpoint')]:
            with self.subTest(new=new):
                self.configured()
                path = self.mapping['/etc/ansible-runner.env']
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaisesRegex(RuntimeError, message):
                    self.check()

    def test_native_requires_complete_mapping(self):
        self.configured()
        del self.mapping['/etc/verification-gateway.env']
        with self.assertRaisesRegex(RuntimeError, 'inventory'):
            self.check()

    def test_native_cli_preflight_is_read_only(self):
        import contextlib
        import io
        import json
        from provision_offline_cli import main
        mapping = self.root / 'mapping.json'
        mapping.write_text(json.dumps({k: str(v) for k, v in self.mapping.items()}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(['--native', '--application', str(self.app),
                           '--unit-destination', str(self.units),
                           '--environment-map', str(mapping), '--journal', str(self.root / 'journal'),
                           '--uid', str(os.geteuid()), '--gid', str(os.getegid())])
        self.assertEqual(result, 0)
        self.assertIn('"units": 11', output.getvalue())
        self.assertIn('"environment_files": 8', output.getvalue())
        self.assertFalse((self.root / 'journal').exists())
        self.assertEqual(list(self.units.iterdir()), [])

    def test_missing_native_requirement_blocks_before_journal(self):
        (self.app / 'deployment/requirements-native.txt').unlink()
        with self.assertRaises(FileNotFoundError):
            provision_staged_application(self.root / 'journal', self.app, self.units, self.mapping,
                                         uid=os.geteuid(), gid=os.getegid(), native=True)
        self.assertFalse((self.root / 'journal').exists())

    def test_smoke_cleanup_only_removes_created_objects(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        cleanup = script[script.index('cleanup() {'):script.index('\nfail() {')]
        for created in ('false', 'true'):
            marker = self.root / 'calls'
            marker.unlink(missing_ok=True)
            command = f'''DB_CREATED={created}
ROLE_CREATED={created}
TEST_DB=automated_remediation_release_smoke_test
SMOKE_DB_USER=remediation_smoke_test
smoke_psql() {{ printf '%s\\n' "$*" >> '{marker}'; }}
{cleanup}
cleanup
'''
            subprocess.run(['bash', '-c', command], check=True)
            self.assertEqual(marker.exists(), created == 'true')
            if created == 'true':
                self.assertIn('DROP DATABASE IF EXISTS automated_remediation_release_smoke_test', marker.read_text())
                self.assertIn('DROP ROLE IF EXISTS remediation_smoke_test', marker.read_text())

    def test_smoke_transport_modes_without_database(self):
        script = (ROOT / 'tests/release_smoke_test.sh').read_text()
        function = script[script.index('smoke_psql() {'):script.index('\nSMOKE_DB_USER=')]
        for mode, expected in [('native', 'psql -X'), ('docker', 'docker exec -i')]:
            command = f'''SMOKE_PG_MODE={mode}
SMOKE_DB_PASSWORD=TEST_ONLY
PG_CONTAINER=test-container
psql() {{ printf 'psql %s\\n' "$*"; }}
docker() {{ printf 'docker %s\\n' "$*"; }}
{function}
smoke_psql -U test-user -d test-db
'''
            result = subprocess.run(['bash', '-c', command], capture_output=True, text=True, check=True)
            self.assertIn(expected, result.stdout)
            self.assertIn('-U test-user -d test-db', result.stdout)


if __name__ == '__main__':
    unittest.main()
