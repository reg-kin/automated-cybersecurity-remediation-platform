#!/usr/bin/env python3

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["CONTROLLER_TOKEN"] = "controller-api-error-test-token"

import remediation.controller_api as controller_api
from remediation.shared.db import ActiveRemediationExistsError


TOKEN = "controller-api-error-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


class DuplicateController:
    def execute(self, payload):
        raise ActiveRemediationExistsError(123)


class ConflictController:
    def execute(self, payload):
        raise RuntimeError("finding is not remediable")

app = controller_api.app
app.testing = True
client = app.test_client()

original = controller_api.CONTROLLERS["os_patching"]

try:
    controller_api.CONTROLLERS["os_patching"] = DuplicateController()

    response = client.post(
        "/remediate",
        json={"capability": "os_patching"},
        headers=HEADERS,
    )

    assert response.status_code == 409
    body = response.get_json()
    assert body["success"] is False
    assert body["code"] == "ACTIVE_REMEDIATION_EXISTS"
    assert "Finding 123 already has" in body["error"]
finally:
    controller_api.CONTROLLERS["os_patching"] = original

try:
    controller_api.CONTROLLERS["os_patching"] = ConflictController()

    response = client.post(
        "/remediate",
        json={"capability": "os_patching"},
        headers=HEADERS,
    )

    assert response.status_code == 409
    body = response.get_json()
    assert body["success"] is False
    assert body["code"] == "REMEDIATION_STATE_CONFLICT"
    assert body["error"] == "finding is not remediable"
finally:
    controller_api.CONTROLLERS["os_patching"] = original

print("PASS: controller API exposes distinct 409 error codes")
