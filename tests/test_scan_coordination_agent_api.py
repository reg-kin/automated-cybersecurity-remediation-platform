#!/usr/bin/env python3

"""Regression tests for the authenticated Scan Coordination Agent API."""

import hashlib
import os
import sys
from pathlib import Path

import psycopg2


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination.node_auth import (
    issue_node_credential,
)

import scan_coordination.api as agent_api


TENANT = "SCAN-AGENT-API-TEST"
NODE_A = "scan-agent-api-node-a"
NODE_B = "scan-agent-api-node-b"

TARGET = "192.0.2.44"


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


def passed(message):
    print(f"PASS: {message}")


def clean_database(conn):
    """Remove only this regression test's Scan Coordination state."""

    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM scan_executions
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM scan_policies
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM scan_execution_nodes
            WHERE node_code IN (%s, %s)
            """,
            (
                NODE_A,
                NODE_B,
            ),
        )

        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )


def create_fixture(conn):
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
                'scan-agent-api-test-host',
                'PROVISIONAL',
                'ACTIVE'
            )
            RETURNING asset_id
            """,
            (TENANT,),
        )

        asset_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO scan_execution_nodes (
                node_code,
                display_name,
                transport_mode,
                is_enabled
            )
            VALUES (
                %s,
                'Agent API Node A',
                'PULL',
                TRUE
            )
            RETURNING execution_node_id
            """,
            (NODE_A,),
        )

        node_a_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO scan_execution_nodes (
                node_code,
                display_name,
                transport_mode,
                is_enabled
            )
            VALUES (
                %s,
                'Agent API Node B',
                'PULL',
                TRUE
            )
            RETURNING execution_node_id
            """,
            (NODE_B,),
        )

        node_b_id = cur.fetchone()[0]

        for node_id in (
            node_a_id,
            node_b_id,
        ):
            cur.execute(
                """
                INSERT INTO scan_execution_node_capabilities (
                    execution_node_id,
                    scanner_type,
                    execution_model,
                    priority,
                    is_enabled
                )
                VALUES (
                    %s,
                    'nmap_nse',
                    'REMOTE_TARGET',
                    10,
                    TRUE
                )
                """,
                (node_id,),
            )

        cur.execute(
            """
            INSERT INTO scan_policies (
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                profile_name,
                scanner_parameters,
                schedule_type,
                schedule_expression,
                schedule_timezone,
                next_run_at,
                is_enabled
            )
            VALUES (
                %s,
                %s,
                'nmap_nse',
                'GOLD',
                'agent-api-test',
                '{"scan_mode":"safe"}'::jsonb,
                'MANUAL',
                NULL,
                'UTC',
                NULL,
                TRUE
            )
            RETURNING scan_policy_id
            """,
            (
                TENANT,
                asset_id,
            ),
        )

        policy_id = cur.fetchone()[0]

    return {
        "asset_id": asset_id,
        "node_a_id": node_a_id,
        "node_b_id": node_b_id,
        "policy_id": policy_id,
    }


def create_pending_execution(
    conn,
    *,
    fixture,
    subject_value=TARGET,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_executions (
                scan_policy_id,
                tenant_code,
                asset_id,
                scanner_type,
                service_tier,
                execution_node_id,
                execution_model,
                scanner_subject_type,
                scanner_subject_value,
                scanner_parameters,
                status,
                scheduled_for
            )
            VALUES (
                %s,
                %s,
                %s,
                'nmap_nse',
                'GOLD',
                %s,
                'REMOTE_TARGET',
                'IP_ADDRESS',
                %s,
                '{"scan_mode":"safe"}'::jsonb,
                'PENDING',
                now() - interval '1 second'
            )
            RETURNING scan_execution_id
            """,
            (
                fixture["policy_id"],
                TENANT,
                fixture["asset_id"],
                fixture["node_a_id"],
                subject_value,
            ),
        )

        return cur.fetchone()[0]


def auth_headers(token):
    return {
        "Authorization": f"Bearer {token}",
    }


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
    setup_conn = psycopg2.connect(
        **PG
    )

    original_connect = agent_api.db.connect

    def test_connect():
        return psycopg2.connect(
            **PG
        )

    agent_api.db.connect = test_connect

    try:
        with setup_conn:
            clean_database(
                setup_conn
            )

            fixture = create_fixture(
                setup_conn
            )

            node_a_credential = issue_node_credential(
                setup_conn,
                execution_node_id=fixture[
                    "node_a_id"
                ],
            )

            node_b_credential = issue_node_credential(
                setup_conn,
                execution_node_id=fixture[
                    "node_b_id"
                ],
            )

            first_execution_id = create_pending_execution(
                setup_conn,
                fixture=fixture,
            )

        node_a_token = node_a_credential[
            "credential"
        ]
        node_b_token = node_b_credential[
            "credential"
        ]

        node_a_headers = auth_headers(
            node_a_token
        )
        node_b_headers = auth_headers(
            node_b_token
        )

        app = agent_api.app
        app.testing = True

        client = app.test_client()

        # --------------------------------------------------------------
        # Health is loopback-service health, not an authenticated
        #    execution operation.
        # --------------------------------------------------------------
        response = client.get(
            "/health"
        )

        assert response.status_code == 200

        assert response.get_json() == {
            "status": "ok",
            "service": "scan-coordination-agent-api",
        }

        passed(
            "Scan Coordination Agent API health endpoint is available"
        )

        # --------------------------------------------------------------
        # Protected endpoints authenticate before payload validation.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            json=[
                "invalid",
                "payload",
            ],
        )

        assert_error(
            response,
            status_code=401,
            code="SCAN_NODE_AUTHENTICATION_ERROR",
        )

        response = client.post(
            "/agent/jobs/lease",
            headers={
                "Authorization": (
                    "Bearer invalid-node-credential"
                ),
            },
            json=[
                "invalid",
                "payload",
            ],
        )

        assert_error(
            response,
            status_code=401,
            code="SCAN_NODE_AUTHENTICATION_ERROR",
        )

        passed(
            "Agent API authenticates execution nodes before "
            "request-body validation"
        )

        # --------------------------------------------------------------
        # Authenticated malformed JSON shape maps to validation error.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json=[
                "not",
                "an",
                "object",
            ],
        )

        assert_error(
            response,
            status_code=400,
            code="SCAN_COORDINATION_VALIDATION_ERROR",
        )

        passed(
            "authenticated malformed Agent API payload maps to HTTP 400"
        )

        # --------------------------------------------------------------
        # Caller-controlled node identity is forbidden.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json={
                "node_code": NODE_B,
            },
        )

        body = assert_error(
            response,
            status_code=400,
            code="SCAN_COORDINATION_VALIDATION_ERROR",
        )

        assert "node_code" in body[
            "error"
        ]

        passed(
            "Agent API rejects caller-controlled execution-node identity"
        )

        # --------------------------------------------------------------
        # Node B cannot see Node A's pending execution.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            headers=node_b_headers,
            json={},
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body == {
            "success": True,
            "job": None,
        }

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                assert cur.fetchone()[0] == "PENDING"

        passed(
            "authenticated node identity scopes lease retrieval "
            "to that node's assigned work"
        )

        # --------------------------------------------------------------
        # Correct node leases its assigned execution.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json={
                "lease_seconds": 300,
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True

        job = body["job"]

        assert job is not None
        assert (
            job["scan_execution_id"]
            == first_execution_id
        )
        assert (
            job["scan_policy_id"]
            == fixture["policy_id"]
        )
        assert job["tenant_code"] == TENANT
        assert (
            job["asset_id"]
            == fixture["asset_id"]
        )
        assert job["scanner_type"] == "nmap_nse"
        assert (
            job["execution_node_id"]
            == fixture["node_a_id"]
        )
        assert job["node_code"] == NODE_A
        assert (
            job["execution_model"]
            == "REMOTE_TARGET"
        )
        assert (
            job["scanner_subject_type"]
            == "IP_ADDRESS"
        )
        assert (
            job["scanner_subject_value"]
            == TARGET
        )
        assert job["scanner_parameters"] == {
            "scan_mode": "safe",
        }
        assert job["service_tier"] == "GOLD"
        assert job["status"] == "LEASED"
        assert job["lease_token"]

        lease_token = job[
            "lease_token"
        ]

        lease_digest = hashlib.sha256(
            lease_token.encode(
                "utf-8"
            )
        ).hexdigest()

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        lease_token_hash,
                        leased_at IS NOT NULL,
                        lease_expires_at IS NOT NULL
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                persisted = cur.fetchone()

        assert persisted == (
            "LEASED",
            lease_digest,
            True,
            True,
        )

        assert persisted[1] != lease_token

        passed(
            "lease endpoint returns scanner assignment and plaintext "
            "execution credential while PostgreSQL stores only its digest"
        )

        # --------------------------------------------------------------
        # Active execution cannot be leased a second time.
        # --------------------------------------------------------------
        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json={},
        )

        assert response.status_code == 200
        assert response.get_json() == {
            "success": True,
            "job": None,
        }

        passed(
            "leased execution is not returned by subsequent pull requests"
        )

        # --------------------------------------------------------------
        # Another authenticated node cannot start the execution.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/start"
            ),
            headers=node_b_headers,
            json={
                "lease_token": lease_token,
            },
        )

        assert_error(
            response,
            status_code=403,
            code="SCAN_LEASE_AUTHENTICATION_ERROR",
        )

        passed(
            "node credential and lease ownership must both match "
            "before execution can start"
        )

        # --------------------------------------------------------------
        # Correct node with wrong lease token is rejected.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/start"
            ),
            headers=node_a_headers,
            json={
                "lease_token": "wrong-lease-token",
            },
        )

        assert_error(
            response,
            status_code=403,
            code="SCAN_LEASE_AUTHENTICATION_ERROR",
        )

        passed(
            "per-execution lease credential is independently enforced"
        )

        # --------------------------------------------------------------
        # Correct node + correct lease transitions to RUNNING.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/start"
            ),
            headers=node_a_headers,
            json={
                "lease_token": lease_token,
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True
        assert (
            body["execution"][
                "scan_execution_id"
            ]
            == first_execution_id
        )
        assert (
            body["execution"]["status"]
            == "RUNNING"
        )
        assert (
            body["execution"]["started_at"]
            is not None
        )

        passed(
            "valid authenticated lease transitions LEASED execution "
            "to RUNNING"
        )

        # --------------------------------------------------------------
        # RUNNING lease can be renewed by its authenticated owner.
        # --------------------------------------------------------------
        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        lease_expires_at,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                before_renewal = cur.fetchone()

        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": lease_token,
                "lease_seconds": 600,
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True
        assert (
            body["execution"]["scan_execution_id"]
            == first_execution_id
        )
        assert (
            body["execution"]["status"]
            == "RUNNING"
        )

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        lease_expires_at,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                after_renewal = cur.fetchone()

        assert after_renewal[0] == "RUNNING"
        assert (
            after_renewal[1]
            > before_renewal[0]
        )
        assert (
            after_renewal[2]
            == before_renewal[1]
        )

        passed(
            "authenticated RUNNING lease renewal extends expiry "
            "without rotating the execution credential"
        )

        # --------------------------------------------------------------
        # Renewal rejects caller-controlled node identity.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": lease_token,
                "lease_seconds": 600,
                "node_code": NODE_B,
            },
        )

        body = assert_error(
            response,
            status_code=400,
            code="SCAN_COORDINATION_VALIDATION_ERROR",
        )

        assert "node_code" in body["error"]

        passed(
            "renewal rejects caller-controlled execution-node identity"
        )

        # --------------------------------------------------------------
        # Another authenticated node cannot renew the lease.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/renew"
            ),
            headers=node_b_headers,
            json={
                "lease_token": lease_token,
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=403,
            code="SCAN_LEASE_AUTHENTICATION_ERROR",
        )

        passed(
            "renewal requires the authenticated node "
            "that owns the execution lease"
        )

        # --------------------------------------------------------------
        # Correct node with wrong lease token cannot renew.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": "wrong-lease-token",
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=403,
            code="SCAN_LEASE_AUTHENTICATION_ERROR",
        )

        passed(
            "renewal independently enforces the "
            "per-execution lease credential"
        )

        # --------------------------------------------------------------
        # Complete endpoint cannot carry finding/risk/remediation data.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/complete"
            ),
            headers=node_a_headers,
            json={
                "status": "SUCCEEDED",
                "lease_token": lease_token,
                "finding_class": (
                    "generic_package_vulnerability"
                ),
            },
        )

        body = assert_error(
            response,
            status_code=400,
            code="SCAN_COORDINATION_VALIDATION_ERROR",
        )

        assert "finding_class" in body[
            "error"
        ]

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                assert cur.fetchone()[0] == "RUNNING"

        passed(
            "Agent API rejects finding construction and downstream "
            "security-decision fields"
        )

        # --------------------------------------------------------------
        # Completion status is deliberately narrow.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/complete"
            ),
            headers=node_a_headers,
            json={
                "status": "CANCELLED",
                "lease_token": lease_token,
            },
        )

        assert_error(
            response,
            status_code=400,
            code="SCAN_COORDINATION_VALIDATION_ERROR",
        )

        passed(
            "Agent completion accepts only SUCCEEDED or FAILED"
        )

        # --------------------------------------------------------------
        # Successful completion clears the execution lease credential.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/complete"
            ),
            headers=node_a_headers,
            json={
                "status": "SUCCEEDED",
                "lease_token": lease_token,
                "execution_metadata": {
                    "scanner_exit": "clean",
                    "adapter": "nmap-test",
                },
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True
        assert (
            body["execution"]["status"]
            == "SUCCEEDED"
        )
        assert (
            body["execution"][
                "scan_execution_id"
            ]
            == first_execution_id
        )

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        exit_code,
                        failure_reason,
                        execution_metadata,
                        lease_token_hash,
                        completed_at IS NOT NULL
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (first_execution_id,),
                )

                completed = cur.fetchone()

        assert completed == (
            "SUCCEEDED",
            0,
            None,
            {
                "scanner_exit": "clean",
                "adapter": "nmap-test",
            },
            None,
            True,
        )

        passed(
            "successful Agent API completion persists terminal state "
            "and clears the lease credential"
        )

        # --------------------------------------------------------------
        # Terminal execution cannot renew its former lease.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": lease_token,
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=409,
            code="SCAN_COORDINATION_CONFLICT",
        )

        passed(
            "terminal execution rejects stale lease renewal"
        )

        # --------------------------------------------------------------
        # Stale duplicate completion cannot overwrite terminal state.
        # --------------------------------------------------------------
        response = client.post(
            (
                f"/agent/jobs/{first_execution_id}"
                "/complete"
            ),
            headers=node_a_headers,
            json={
                "status": "FAILED",
                "lease_token": lease_token,
                "failure_reason": (
                    "stale duplicate report"
                ),
                "exit_code": 99,
            },
        )

        assert_error(
            response,
            status_code=409,
            code="SCAN_COORDINATION_CONFLICT",
        )

        passed(
            "stale duplicate completion cannot overwrite "
            "authoritative terminal state"
        )

        # --------------------------------------------------------------
        # FAILED completion path preserves failure diagnostics.
        # --------------------------------------------------------------
        with setup_conn:
            second_execution_id = create_pending_execution(
                setup_conn,
                fixture=fixture,
                subject_value="192.0.2.45",
            )

        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json={},
        )

        assert response.status_code == 200

        second_job = response.get_json()[
            "job"
        ]

        assert (
            second_job["scan_execution_id"]
            == second_execution_id
        )

        second_lease_token = second_job[
            "lease_token"
        ]

        response = client.post(
            (
                f"/agent/jobs/{second_execution_id}"
                "/start"
            ),
            headers=node_a_headers,
            json={
                "lease_token": second_lease_token,
            },
        )

        assert response.status_code == 200

        response = client.post(
            (
                f"/agent/jobs/{second_execution_id}"
                "/complete"
            ),
            headers=node_a_headers,
            json={
                "status": "FAILED",
                "lease_token": second_lease_token,
                "failure_reason": (
                    "scanner process exited unsuccessfully"
                ),
                "exit_code": 7,
                "execution_metadata": {
                    "stderr_summary": "test failure",
                },
            },
        )

        assert response.status_code == 200

        body = response.get_json()

        assert body["success"] is True
        assert (
            body["execution"]["status"]
            == "FAILED"
        )

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        exit_code,
                        failure_reason,
                        execution_metadata,
                        lease_token_hash,
                        completed_at IS NOT NULL
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (second_execution_id,),
                )

                failed = cur.fetchone()

        assert failed == (
            "FAILED",
            7,
            "scanner process exited unsuccessfully",
            {
                "stderr_summary": "test failure",
            },
            None,
            True,
        )

        passed(
            "failed Agent API completion preserves scanner "
            "execution diagnostics and clears the lease credential"
        )

        # --------------------------------------------------------------
        # Non-existent execution maps to 404.
        # --------------------------------------------------------------
        response = client.post(
            (
                "/agent/jobs/9223372036854775807"
                "/start"
            ),
            headers=node_a_headers,
            json={
                "lease_token": "unused-token",
            },
        )

        assert_error(
            response,
            status_code=404,
            code="SCAN_EXECUTION_NOT_FOUND",
        )

        passed(
            "missing scan execution maps to HTTP 404"
        )

        response = client.post(
            (
                "/agent/jobs/9223372036854775807"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": "unused-token",
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=404,
            code="SCAN_EXECUTION_NOT_FOUND",
        )

        passed(
            "missing scan execution renewal maps to HTTP 404"
        )

        # --------------------------------------------------------------
        # Expired lease maps distinctly to 409.
        # --------------------------------------------------------------
        with setup_conn:
            third_execution_id = create_pending_execution(
                setup_conn,
                fixture=fixture,
                subject_value="192.0.2.46",
            )

        response = client.post(
            "/agent/jobs/lease",
            headers=node_a_headers,
            json={},
        )

        assert response.status_code == 200

        third_job = response.get_json()[
            "job"
        ]

        assert (
            third_job["scan_execution_id"]
            == third_execution_id
        )

        third_lease_token = third_job[
            "lease_token"
        ]

        response = client.post(
            (
                f"/agent/jobs/{third_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": third_lease_token,
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=409,
            code="SCAN_COORDINATION_CONFLICT",
        )

        passed(
            "LEASED execution cannot renew before entering RUNNING"
        )

        response = client.post(
            (
                f"/agent/jobs/{third_execution_id}"
                "/start"
            ),
            headers=node_a_headers,
            json={
                "lease_token": third_lease_token,
            },
        )

        assert response.status_code == 200
        assert (
            response.get_json()["execution"]["status"]
            == "RUNNING"
        )

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_executions
                    SET
                        leased_at =
                            now() - interval '10 minutes',
                        lease_expires_at =
                            now() - interval '5 minutes'
                    WHERE scan_execution_id = %s
                    """,
                    (third_execution_id,),
                )

        response = client.post(
            (
                f"/agent/jobs/{third_execution_id}"
                "/renew"
            ),
            headers=node_a_headers,
            json={
                "lease_token": third_lease_token,
                "lease_seconds": 600,
            },
        )

        assert_error(
            response,
            status_code=409,
            code="SCAN_LEASE_EXPIRED",
        )

        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        status,
                        lease_token_hash
                    FROM scan_executions
                    WHERE scan_execution_id = %s
                    """,
                    (third_execution_id,),
                )

                expired_running = cur.fetchone()

        assert expired_running[0] == "RUNNING"
        assert expired_running[1] is not None

        passed(
            "expired RUNNING lease renewal maps distinctly to HTTP 409 "
            "without resurrecting or mutating execution state"
        )

        # --------------------------------------------------------------
        # Bearer credential establishes node activity in PostgreSQL.
        # --------------------------------------------------------------
        with setup_conn:
            with setup_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        c.last_used_at IS NOT NULL,
                        n.last_seen_at IS NOT NULL
                    FROM scan_execution_node_credentials c
                    JOIN scan_execution_nodes n
                      ON n.execution_node_id =
                         c.execution_node_id
                    WHERE c.credential_id = %s
                    """,
                    (
                        node_a_credential[
                            "credential_id"
                        ],
                    ),
                )

                activity = cur.fetchone()

        assert activity == (
            True,
            True,
        )

        passed(
            "Agent API authentication records credential use "
            "and execution-node presence"
        )

        passed(
            "Scan Coordination Agent API regression tests"
        )

    finally:
        agent_api.db.connect = original_connect

        try:
            with setup_conn:
                clean_database(
                    setup_conn
                )
        finally:
            setup_conn.close()


if __name__ == "__main__":
    main()
