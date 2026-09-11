#!/usr/bin/env python3

"""Regression tests for the remediation-readiness administrative API."""

import os
import subprocess
import sys
from pathlib import Path

import psycopg2


ROOT = Path(__file__).resolve().parents[1]

READINESS_SERVICE_FILE = (
    ROOT
    / "deployment"
    / "systemd"
    / "readiness-admin-api.service"
)

READINESS_ENV_EXAMPLE = (
    ROOT
    / "deployment"
    / "systemd"
    / "env"
    / "readiness-admin-api.env.example"
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TOKEN = "readiness-admin-api-test-token"
PRINCIPAL = "readiness_admin_api_test"
TENANT = "READINESS-ADMIN-API-TEST"
OTHER_TENANT = "READINESS-ADMIN-API-OTHER-TENANT"

FIRST_TARGET = "192.0.2.250"
REPLACEMENT_TARGET = "192.0.2.251"

PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.getenv("PG_USER", "telemetry_admin"),
    "password": os.getenv("PG_PASSWORD", ""),
}


# The module deliberately fails closed at import time, so configure the
# administrative credential before importing it in this test process.
os.environ["READINESS_ADMIN_TOKEN"] = TOKEN
os.environ["READINESS_ADMIN_PRINCIPAL"] = PRINCIPAL

import readiness_management.api as readiness_api


HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
}

WRONG_HEADERS = {
    "Authorization": "Bearer wrong-readiness-admin-token",
}


def run_python(code, env):
    return subprocess.run(
        [
            sys.executable,
            "-c",
            code,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def readiness_api_env(
    *,
    token=None,
    principal=None,
):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)

    env.pop(
        "READINESS_ADMIN_TOKEN",
        None,
    )
    env.pop(
        "READINESS_ADMIN_PRINCIPAL",
        None,
    )

    if token is not None:
        env["READINESS_ADMIN_TOKEN"] = token

    if principal is not None:
        env["READINESS_ADMIN_PRINCIPAL"] = principal

    return env


def clean_database(conn):
    """Remove only this regression test's operational assets."""

    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )


def create_provisional_asset(conn):
    """Create an ordinary discovered asset with no remediation authority."""

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (
                tenant_code,
                asset_type,
                canonical_name,
                inventory_state,
                lifecycle_status
            )
            VALUES (
                %s,
                'HOST',
                'readiness-admin-api-test-host',
                'PROVISIONAL',
                'ACTIVE'
            )
            RETURNING asset_id
            """,
            (TENANT,),
        )

        return cur.fetchone()[0]


def assert_error(
    response,
    *,
    status_code,
    code,
):
    assert response.status_code == status_code

    body = response.get_json()

    assert body["success"] is False
    assert body["code"] == code
    assert str(body["error"]).strip()

    return body


def main():
    #
    # ------------------------------------------------------------------
    # 0. Deployment contract must preserve the administrative boundary.
    # ------------------------------------------------------------------
    #
    service_text = READINESS_SERVICE_FILE.read_text(
        encoding="utf-8"
    )

    env_text = READINESS_ENV_EXAMPLE.read_text(
        encoding="utf-8"
    )

    assert (
        "User=automated-remediation"
        in service_text
    )

    assert (
        "Group=automated-remediation"
        in service_text
    )

    assert (
        "EnvironmentFile=/etc/readiness-admin-api.env"
        in service_text
    )

    assert (
        "--bind 127.0.0.1:9100"
        in service_text
    )

    assert (
        "readiness_management.api:app"
        in service_text
    )

    assert (
        "remediation.controller_api:app"
        not in service_text
    )

    assert (
        "CONTROLLER_TOKEN"
        not in service_text
    )

    assert (
        "READINESS_ADMIN_TOKEN=CHANGE_ME"
        in env_text
    )

    assert (
        "READINESS_ADMIN_PRINCIPAL=CHANGE_ME"
        in env_text
    )

    assert (
        "READINESS_ADMIN_HOST=127.0.0.1"
        in env_text
    )

    assert (
        "READINESS_ADMIN_PORT=9100"
        in env_text
    )

    assert (
        "CONTROLLER_TOKEN"
        not in env_text
    )

    print(
        "PASS: readiness admin API deployment preserves the separate "
        "loopback-only administrative security boundary"
    )

    #
    # ------------------------------------------------------------------
    # 1. Startup configuration must fail closed.
    # ------------------------------------------------------------------
    #
    result = run_python(
        "import readiness_management.api",
        readiness_api_env(),
    )

    assert result.returncode != 0
    assert (
        "READINESS_ADMIN_TOKEN must be configured with a non-empty value"
        in result.stderr
    ), result.stderr

    result = run_python(
        "import readiness_management.api",
        readiness_api_env(
            token="   ",
            principal=PRINCIPAL,
        ),
    )

    assert result.returncode != 0
    assert (
        "READINESS_ADMIN_TOKEN must be configured with a non-empty value"
        in result.stderr
    ), result.stderr

    result = run_python(
        "import readiness_management.api",
        readiness_api_env(
            token=TOKEN,
        ),
    )

    assert result.returncode != 0
    assert (
        "READINESS_ADMIN_PRINCIPAL must be configured with a non-empty value"
        in result.stderr
    ), result.stderr

    result = run_python(
        "import readiness_management.api",
        readiness_api_env(
            token=TOKEN,
            principal="   ",
        ),
    )

    assert result.returncode != 0
    assert (
        "READINESS_ADMIN_PRINCIPAL must be configured with a non-empty value"
        in result.stderr
    ), result.stderr

    print(
        "PASS: readiness admin API fails closed without mandatory "
        "administrative configuration"
    )

    #
    # ------------------------------------------------------------------
    # 2. Authentication helper must accept only the configured token.
    # ------------------------------------------------------------------
    #
    app = readiness_api.app
    app.testing = True

    with app.test_request_context(
        "/admin/assets/1/readiness"
    ):
        assert readiness_api.authorised() is False

    with app.test_request_context(
        "/admin/assets/1/readiness",
        headers=WRONG_HEADERS,
    ):
        assert readiness_api.authorised() is False

    with app.test_request_context(
        "/admin/assets/1/readiness",
        headers=HEADERS,
    ):
        assert readiness_api.authorised() is True

    print(
        "PASS: readiness admin API authentication accepts only the "
        "configured Bearer token"
    )

    #
    # Point API database connections at the same PostgreSQL test database
    # used to create the fixture. The real readiness service remains in use.
    #
    original_connect = readiness_api.db.connect

    def test_connect():
        return psycopg2.connect(
            **PG
        )

    readiness_api.db.connect = test_connect

    setup_conn = psycopg2.connect(
        **PG
    )

    try:
        with setup_conn:
            clean_database(
                setup_conn
            )

            asset_id = create_provisional_asset(
                setup_conn
            )

        client = app.test_client()

        #
        # --------------------------------------------------------------
        # 3. Health remains available without administrative credentials.
        # --------------------------------------------------------------
        #
        response = client.get(
            "/health"
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body == {
            "status": "ok",
            "service": "readiness-admin-api",
        }

        print(
            "PASS: readiness admin API health endpoint is available"
        )

        #
        # --------------------------------------------------------------
        # 4. Administrative endpoints reject missing/wrong credentials.
        # --------------------------------------------------------------
        #
        readiness_path = (
            f"/admin/assets/{asset_id}/readiness"
            f"?tenant_code={TENANT}"
        )

        response = client.get(
            readiness_path
        )

        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"] == "unauthorised"

        response = client.get(
            readiness_path,
            headers=WRONG_HEADERS,
        )

        assert response.status_code == 401
        body = response.get_json()
        assert body["success"] is False
        assert body["error"] == "unauthorised"

        print(
            "PASS: readiness administrative endpoints reject "
            "unauthenticated callers"
        )

        #
        # --------------------------------------------------------------
        # 5. HTTP validation maps to 400.
        # --------------------------------------------------------------
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/authorise",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": "   ",
            },
        )

        assert_error(
            response,
            status_code=400,
            code="READINESS_VALIDATION_ERROR",
        )

        response = client.post(
            f"/admin/assets/{asset_id}/management/authorise",
            headers=HEADERS,
            json=[
                TENANT,
                "not-an-object",
            ],
        )

        assert_error(
            response,
            status_code=400,
            code="READINESS_VALIDATION_ERROR",
        )

        print(
            "PASS: readiness validation failures map to HTTP 400"
        )

        #
        # --------------------------------------------------------------
        # 6. Caller-controlled performed_by must be rejected.
        # --------------------------------------------------------------
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/authorise",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Attempt to forge administrative audit identity"
                ),
                "performed_by": "forged-admin",
            },
        )

        assert_error(
            response,
            status_code=400,
            code="READINESS_VALIDATION_ERROR",
        )

        response = client.get(
            readiness_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True
        assert body["readiness"][
            "asset"
        ]["inventory_state"] == "PROVISIONAL"
        assert body["readiness"][
            "asset_management_authorised"
        ] is False

        print(
            "PASS: callers cannot forge administrative audit identity"
        )

        #
        # --------------------------------------------------------------
        # 7. Tenant-scoped asset absence maps to 404.
        # --------------------------------------------------------------
        #
        response = client.get(
            (
                f"/admin/assets/{asset_id}/readiness"
                f"?tenant_code={OTHER_TENANT}"
            ),
            headers=HEADERS,
        )

        assert_error(
            response,
            status_code=404,
            code="ASSET_NOT_FOUND",
        )

        print(
            "PASS: tenant-scoped asset absence maps to HTTP 404"
        )

        #
        # --------------------------------------------------------------
        # 8. Invalid readiness transitions map to 409.
        #
        # A PROVISIONAL asset cannot receive an execution target before
        # management authorisation.
        # --------------------------------------------------------------
        #
        response = client.post(
            (
                f"/admin/assets/{asset_id}"
                "/execution-target/authorise"
            ),
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "execution_target": FIRST_TARGET,
                "reason": (
                    "Conflict mapping regression test"
                ),
            },
        )

        assert_error(
            response,
            status_code=409,
            code="READINESS_CONFLICT",
        )

        print(
            "PASS: readiness state conflicts map to HTTP 409"
        )

        #
        # --------------------------------------------------------------
        # 9. Explicitly authorise asset management.
        # --------------------------------------------------------------
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/authorise",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Asset ownership and remediation authority verified"
                ),
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        asset_result = body["asset"]

        assert asset_result["asset_id"] == asset_id
        assert asset_result["tenant_code"] == TENANT
        assert asset_result["inventory_state"] == "MANAGED"
        assert asset_result[
            "management_authorised_by"
        ] == PRINCIPAL
        assert asset_result[
            "management_authorised_at"
        ] is not None
        assert asset_result["audit_id"] is not None

        print(
            "PASS: API explicitly authorises asset management using "
            "the configured administrative principal"
        )

        #
        # Duplicate management authorisation is a state conflict.
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/authorise",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Duplicate management authorisation test"
                ),
            },
        )

        assert_error(
            response,
            status_code=409,
            code="READINESS_CONFLICT",
        )

        #
        # --------------------------------------------------------------
        # 10. Explicitly authorise the first execution target.
        # --------------------------------------------------------------
        #
        response = client.post(
            (
                f"/admin/assets/{asset_id}"
                "/execution-target/authorise"
            ),
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "execution_target": FIRST_TARGET,
                "reason": (
                    "Approved administrative remediation endpoint"
                ),
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        target_result = body[
            "execution_target"
        ]

        first_target_id = target_result[
            "execution_target_id"
        ]

        assert first_target_id is not None
        assert target_result[
            "execution_target"
        ] == FIRST_TARGET
        assert target_result[
            "is_active"
        ] is True
        assert target_result[
            "authorised_by"
        ] == PRINCIPAL
        assert target_result[
            "authorised_at"
        ] is not None

        print(
            "PASS: API explicitly authorises an execution target "
            "using the configured administrative principal"
        )

        #
        # --------------------------------------------------------------
        # 11. Readiness endpoint exposes the derived ready state.
        # --------------------------------------------------------------
        #
        response = client.get(
            readiness_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        readiness = body["readiness"]

        assert readiness[
            "asset_management_authorised"
        ] is True
        assert readiness[
            "execution_target_authorised"
        ] is True
        assert readiness[
            "remediation_ready"
        ] is True

        active_target = readiness[
            "active_execution_target"
        ]

        assert active_target is not None
        assert active_target[
            "execution_target_id"
        ] == first_target_id
        assert active_target[
            "execution_target"
        ] == FIRST_TARGET

        assert len(
            [
                target
                for target in readiness["execution_targets"]
                if target["is_active"]
            ]
        ) == 1

        print(
            "PASS: readiness API exposes the derived remediation-ready "
            "state with exactly one active execution target"
        )

        #
        # --------------------------------------------------------------
        # 12. Audit history uses the configured principal.
        # --------------------------------------------------------------
        #
        history_path = (
            f"/admin/assets/{asset_id}/readiness/history"
            f"?tenant_code={TENANT}"
        )

        response = client.get(
            history_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        history = body["history"]

        assert [
            event["event_type"]
            for event in history
        ] == [
            "ASSET_MANAGED",
            "EXECUTION_TARGET_AUTHORISED",
        ]

        assert all(
            event["performed_by"] == PRINCIPAL
            for event in history
        )

        print(
            "PASS: readiness audit history attributes administrative "
            "actions to the configured principal"
        )

        #
        # --------------------------------------------------------------
        # 13. Atomically replace the authorised execution target.
        # --------------------------------------------------------------
        #
        response = client.post(
            (
                f"/admin/assets/{asset_id}"
                "/execution-target/replace"
            ),
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "execution_target": REPLACEMENT_TARGET,
                "reason": (
                    "Approved execution-target replacement"
                ),
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        replacement = body[
            "execution_target"
        ]

        replacement_target_id = replacement[
            "execution_target_id"
        ]

        assert replacement_target_id is not None
        assert replacement_target_id != first_target_id
        assert replacement[
            "previous_execution_target_id"
        ] == first_target_id
        assert replacement[
            "previous_execution_target"
        ] == FIRST_TARGET
        assert replacement[
            "execution_target"
        ] == REPLACEMENT_TARGET
        assert replacement[
            "is_active"
        ] is True
        assert replacement[
            "authorised_by"
        ] == PRINCIPAL

        response = client.get(
            readiness_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        readiness = response.get_json()[
            "readiness"
        ]

        active_targets = [
            target
            for target in readiness["execution_targets"]
            if target["is_active"]
        ]

        assert len(active_targets) == 1
        assert active_targets[0][
            "execution_target_id"
        ] == replacement_target_id
        assert active_targets[0][
            "execution_target"
        ] == REPLACEMENT_TARGET

        old_target = next(
            target
            for target in readiness["execution_targets"]
            if target[
                "execution_target_id"
            ] == first_target_id
        )

        assert old_target["is_active"] is False
        assert old_target["revoked_at"] is not None
        assert old_target["revoked_by"] == PRINCIPAL

        print(
            "PASS: API atomically replaces the execution target and "
            "preserves exactly one active target"
        )

        #
        # --------------------------------------------------------------
        # 14. Management cannot be revoked while target remains active.
        # --------------------------------------------------------------
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/revoke",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Unsafe management revocation regression test"
                ),
            },
        )

        assert_error(
            response,
            status_code=409,
            code="READINESS_CONFLICT",
        )

        print(
            "PASS: API blocks management revocation while an "
            "execution target remains active"
        )

        #
        # --------------------------------------------------------------
        # 15. Revoke the active execution target.
        # --------------------------------------------------------------
        #
        response = client.post(
            (
                f"/admin/assets/{asset_id}"
                "/execution-target/revoke"
            ),
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Administrative target revocation"
                ),
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        revoked_target = body[
            "execution_target"
        ]

        assert revoked_target[
            "execution_target_id"
        ] == replacement_target_id
        assert revoked_target[
            "execution_target"
        ] == REPLACEMENT_TARGET
        assert revoked_target[
            "is_active"
        ] is False
        assert revoked_target[
            "revoked_by"
        ] == PRINCIPAL
        assert revoked_target[
            "revoked_at"
        ] is not None

        response = client.get(
            readiness_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        readiness = response.get_json()[
            "readiness"
        ]

        assert readiness[
            "asset_management_authorised"
        ] is True
        assert readiness[
            "execution_target_authorised"
        ] is False
        assert readiness[
            "remediation_ready"
        ] is False
        assert readiness[
            "active_execution_target"
        ] is None

        print(
            "PASS: target revocation immediately removes remediation "
            "readiness"
        )

        #
        # --------------------------------------------------------------
        # 16. Revoke asset management.
        # --------------------------------------------------------------
        #
        response = client.post(
            f"/admin/assets/{asset_id}/management/revoke",
            headers=HEADERS,
            json={
                "tenant_code": TENANT,
                "reason": (
                    "Administrative management revocation"
                ),
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        revoked_asset = body["asset"]

        assert revoked_asset["asset_id"] == asset_id
        assert revoked_asset["tenant_code"] == TENANT
        assert revoked_asset[
            "inventory_state"
        ] == "UNMANAGED"
        assert revoked_asset[
            "management_revoked_by"
        ] == PRINCIPAL
        assert revoked_asset[
            "management_revoked_at"
        ] is not None

        response = client.get(
            readiness_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        readiness = response.get_json()[
            "readiness"
        ]

        assert readiness[
            "asset"
        ]["inventory_state"] == "UNMANAGED"
        assert readiness[
            "asset_management_authorised"
        ] is False
        assert readiness[
            "execution_target_authorised"
        ] is False
        assert readiness[
            "remediation_ready"
        ] is False

        print(
            "PASS: API explicitly revokes asset management and keeps "
            "the asset remediation-ineligible"
        )

        #
        # --------------------------------------------------------------
        # 17. Verify the final append-only API-driven audit sequence.
        # --------------------------------------------------------------
        #
        response = client.get(
            history_path,
            headers=HEADERS,
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        history = body["history"]

        assert [
            event["event_type"]
            for event in history
        ] == [
            "ASSET_MANAGED",
            "EXECUTION_TARGET_AUTHORISED",
            "EXECUTION_TARGET_REPLACED",
            "EXECUTION_TARGET_REVOKED",
            "ASSET_MANAGEMENT_REVOKED",
        ]

        assert all(
            event["asset_id"] == asset_id
            for event in history
        )

        assert all(
            event["tenant_code"] == TENANT
            for event in history
        )

        assert all(
            event["performed_by"] == PRINCIPAL
            for event in history
        )

        assert all(
            str(event["reason"]).strip()
            for event in history
        )

        #
        # Verify identity attribution at the persistence boundary as well,
        # rather than relying only on the HTTP representation.
        #
        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT performed_by
                    FROM asset_remediation_audit
                    WHERE asset_id = %s
                      AND tenant_code = %s
                    """,
                    (
                        asset_id,
                        TENANT,
                    ),
                )

                persisted_actors = [
                    row[0]
                    for row in cur.fetchall()
                ]

        assert persisted_actors == [
            PRINCIPAL
        ]

        print(
            "PASS: complete API-driven readiness history is append-only "
            "and attributed to the configured administrative principal"
        )

        print(
            "PASS: remediation-readiness administrative API regression "
            "completed successfully"
        )

    finally:
        readiness_api.db.connect = original_connect

        try:
            with setup_conn:
                clean_database(
                    setup_conn
                )
        finally:
            setup_conn.close()


if __name__ == "__main__":
    main()
