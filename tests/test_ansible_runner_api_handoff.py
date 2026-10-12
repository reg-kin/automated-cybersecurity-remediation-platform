#!/usr/bin/env python3
"""Isolated runner API tests: authentication and exact Ansible variable handoff.

No Ansible process is started: subprocess.run is mocked.
"""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "ansible-runner/server.py"

with patch.dict(os.environ, {
    "ANSIBLE_RUNNER_TOKEN": "isolated-test-token",
    "ALLOWED_PLAYBOOKS": "service_config.yml",
    "ANSIBLE_PLAYBOOK_DIR": str(ROOT / "ansible/playbooks"),
}):
    spec = importlib.util.spec_from_file_location("regis_runner_api_test", SERVER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

client = runner.app.test_client()
body = {
    "playbook": "service_config.yml",
    "target_host": "192.0.2.20",
    "extra_vars": {
        "finding_id": 101,
        "execution_id": 301,
        "remediation_action": "disable_vsftpd_anonymous",
        "validated_ftp_port": 2121,
    },
}

with patch.object(runner.subprocess, "run") as process:
    response = client.post("/run", json=body)
    assert response.status_code == 401, response.get_json()
    process.assert_not_called()
print("PASS: unauthenticated runner request rejected without subprocess")

with patch.object(runner.subprocess, "run") as process:
    response = client.post(
        "/run", json=body,
        headers={"Authorization": "Bearer incorrect-token"},
    )
    assert response.status_code == 401, response.get_json()
    process.assert_not_called()
print("PASS: incorrect runner token rejected without subprocess")

with patch.object(runner.subprocess, "run") as process:
    response = client.post(
        "/run",
        json={**body, "playbook": "../service_config.yml"},
        headers={"Authorization": "Bearer isolated-test-token"},
    )
    assert response.status_code == 400, response.get_json()
    process.assert_not_called()
print("PASS: unapproved playbook rejected without subprocess")

with patch.object(runner.subprocess, "run") as process:
    response = client.post(
        "/run",
        json={**body, "extra_vars": ["invalid"]},
        headers={"Authorization": "Bearer isolated-test-token"},
    )
    assert response.status_code == 400, response.get_json()
    process.assert_not_called()
print("PASS: non-object extra_vars rejected without subprocess")

with patch.object(
    runner.subprocess, "run",
    return_value=Mock(returncode=0, stdout="ok", stderr=""),
) as process:
    response = client.post(
        "/run", json=body,
        headers={"Authorization": "Bearer isolated-test-token"},
    )
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["success"] is True
    process.assert_called_once()
    command = process.call_args.args[0]
    assert command[0] == "ansible-playbook", command
    assert command[command.index("-i") + 1] == "192.0.2.20,"
    forwarded = json.loads(command[command.index("--extra-vars") + 1])
    assert forwarded == body["extra_vars"], forwarded
    assert forwarded["validated_ftp_port"] == 2121
print("PASS: authenticated runner forwards exact controller variables to Ansible")
