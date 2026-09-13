#!/usr/bin/env python3

"""Regression tests for deterministic scanner-subject resolution."""

import os
import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import Json


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from scan_coordination.subject_resolver import (
    ScanSubjectAmbiguousError,
    ScanSubjectNotResolvableError,
    resolve_scanner_subject,
)


PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "automated_remediation_release_smoke_test",
    ),
    "user": os.getenv(
        "PG_USER",
        "telemetry_admin",
    ),
    "password": os.getenv(
        "PG_PASSWORD",
        "",
    ),
}


TENANT = "SCAN-SUBJECT-RESOLUTION-TEST"


def clean_database(conn):
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
            DELETE FROM scan_execution_node_assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )

        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code = %s
            """,
            (TENANT,),
        )


def create_asset(
    conn,
    *,
    asset_type,
    canonical_name,
    lifecycle_status="ACTIVE",
):
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
                %s,
                %s,
                'PROVISIONAL',
                %s
            )
            RETURNING asset_id
            """,
            (
                TENANT,
                asset_type,
                canonical_name,
                lifecycle_status,
            ),
        )

        return cur.fetchone()[0]


def add_identifier(
    conn,
    *,
    asset_id,
    identifier_type,
    identifier_value,
    normalized_value=None,
    confidence="HIGH",
    is_authoritative=False,
):
    if normalized_value is None:
        normalized_value = identifier_value

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO asset_identifiers (
                asset_id,
                tenant_code,
                identifier_type,
                identifier_value,
                normalized_value,
                source,
                confidence,
                is_authoritative,
                is_active
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                'scan_subject_resolution_test',
                %s,
                %s,
                TRUE
            )
            """,
            (
                asset_id,
                TENANT,
                identifier_type,
                identifier_value,
                normalized_value,
                confidence,
                is_authoritative,
            ),
        )


def create_policy(
    conn,
    *,
    asset_id,
    scanner_type,
    profile_name,
    scanner_parameters=None,
    enabled=True,
):
    if scanner_parameters is None:
        scanner_parameters = {}

    with conn.cursor() as cur:
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
                %s,
                'GOLD',
                %s,
                %s,
                'MANUAL',
                NULL,
                'UTC',
                NULL,
                %s
            )
            RETURNING scan_policy_id
            """,
            (
                TENANT,
                asset_id,
                scanner_type,
                profile_name,
                Json(scanner_parameters),
                enabled,
            ),
        )

        return cur.fetchone()[0]


def expect_not_resolvable(
    conn,
    *,
    policy_id,
    expected_text,
):
    try:
        resolve_scanner_subject(
            conn,
            scan_policy_id=policy_id,
        )
    except ScanSubjectNotResolvableError as exc:
        assert expected_text in str(exc), (
            f"Expected {expected_text!r} in {str(exc)!r}"
        )
        return

    raise AssertionError(
        "Expected ScanSubjectNotResolvableError"
    )


def main():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            clean_database(conn)

        # --------------------------------------------------------------
        # Wazuh Vulnerability
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="wazuh-vulnerability-host",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="WAZUH_AGENT_ID",
                identifier_value="001",
                confidence="VERY_HIGH",
                is_authoritative=True,
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="wazuh_vulnerability",
                profile_name="wazuh-vulnerability",
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "WAZUH_AGENT_ID",
            "scanner_subject_value": "001",
        }

        print(
            "PASS: Wazuh Vulnerability resolves "
            "authoritative WAZUH_AGENT_ID"
        )

        # --------------------------------------------------------------
        # Wazuh SCA
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="wazuh-sca-host",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="WAZUH_AGENT_ID",
                identifier_value="002",
                confidence="VERY_HIGH",
                is_authoritative=True,
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="wazuh_sca",
                profile_name="wazuh-sca",
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "WAZUH_AGENT_ID",
            "scanner_subject_value": "002",
        }

        print(
            "PASS: Wazuh SCA resolves "
            "authoritative WAZUH_AGENT_ID"
        )

        # --------------------------------------------------------------
        # Nmap NSE
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="nmap-host",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="IP_ADDRESS",
                identifier_value="192.0.2.55",
                confidence="MEDIUM",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                profile_name="nmap",
                scanner_parameters={
                    "task_name": "nmap-baseline",
                },
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "IP_ADDRESS",
            "scanner_subject_value": "192.0.2.55",
        }

        print(
            "PASS: Nmap NSE resolves one active IP_ADDRESS"
        )

        # --------------------------------------------------------------
        # Nmap ambiguity fails closed.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="nmap-ambiguous-host",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="IP_ADDRESS",
                identifier_value="192.0.2.60",
                confidence="MEDIUM",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="IP_ADDRESS",
                identifier_value="192.0.2.61",
                confidence="MEDIUM",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                profile_name="nmap-ambiguous",
                scanner_parameters={
                    "task_name": "nmap-ambiguous",
                },
            )

            ambiguous_blocked = False

            try:
                resolve_scanner_subject(
                    conn,
                    scan_policy_id=policy_id,
                )
            except ScanSubjectAmbiguousError:
                ambiguous_blocked = True

        assert ambiguous_blocked is True

        print(
            "PASS: Nmap NSE fails closed on multiple "
            "active IP_ADDRESS identifiers"
        )

        # --------------------------------------------------------------
        # Nuclei
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="APPLICATION",
                canonical_name="https://app.example.test",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="APPLICATION_ID",
                identifier_value="https://app.example.test",
                normalized_value="https://app.example.test",
                confidence="HIGH",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nuclei",
                profile_name="nuclei",
                scanner_parameters={
                    "task_name": "nuclei-baseline",
                },
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "URL",
            "scanner_subject_value": (
                "https://app.example.test"
            ),
        }

        print(
            "PASS: Nuclei maps APPLICATION_ID to URL subject"
        )

        # --------------------------------------------------------------
        # Lynis
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="lynis-local-host",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="lynis",
                profile_name="lynis",
                scanner_parameters={
                    "target_host": "lynis-local-host",
                },
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "LOCAL_ASSET",
            "scanner_subject_value": str(asset_id),
        }

        print(
            "PASS: Lynis resolves canonical asset "
            "to LOCAL_ASSET subject"
        )

        # --------------------------------------------------------------
        # Trivy image
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="CONTAINER_IMAGE",
                canonical_name="example/app:1.0",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="CONTAINER_IMAGE_REFERENCE",
                identifier_value="example/app:1.0",
                confidence="HIGH",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="trivy",
                profile_name="trivy-image",
                scanner_parameters={
                    "scan_type": "image",
                },
            )

            subject = resolve_scanner_subject(
                conn,
                scan_policy_id=policy_id,
            )

        assert subject == {
            "scanner_subject_type": "CONTAINER_IMAGE",
            "scanner_subject_value": "example/app:1.0",
        }

        print(
            "PASS: Trivy image resolves "
            "CONTAINER_IMAGE_REFERENCE"
        )

        # --------------------------------------------------------------
        # Trivy filesystem is intentionally unresolved in V1.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="trivy-filesystem-host",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="trivy",
                profile_name="trivy-folder",
                scanner_parameters={
                    "scan_type": "folder",
                },
            )

            expect_not_resolvable(
                conn,
                policy_id=policy_id,
                expected_text=(
                    "filesystem scan subject is not "
                    "represented"
                ),
            )

        print(
            "PASS: Trivy filesystem fails closed when "
            "no canonical filesystem subject exists"
        )

        # --------------------------------------------------------------
        # OpenVAS is intentionally unresolved in V1.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="openvas-host",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="openvas",
                profile_name="openvas",
            )

            expect_not_resolvable(
                conn,
                policy_id=policy_id,
                expected_text=(
                    "OpenVAS task subject is not represented"
                ),
            )

        print(
            "PASS: OpenVAS fails closed when no canonical "
            "OPENVAS_TASK binding exists"
        )

        # --------------------------------------------------------------
        # Missing required identifier fails closed.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="wazuh-no-agent-id",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="wazuh_sca",
                profile_name="wazuh-no-agent-id",
            )

            expect_not_resolvable(
                conn,
                policy_id=policy_id,
                expected_text=(
                    "has no active WAZUH_AGENT_ID identifier"
                ),
            )

        print(
            "PASS: missing required canonical identifier "
            "fails closed"
        )

        # --------------------------------------------------------------
        # Disabled policy fails closed.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="disabled-policy-host",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="IP_ADDRESS",
                identifier_value="192.0.2.70",
                confidence="MEDIUM",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                profile_name="disabled-policy",
                scanner_parameters={
                    "task_name": "disabled-test",
                },
                enabled=False,
            )

            expect_not_resolvable(
                conn,
                policy_id=policy_id,
                expected_text="is disabled",
            )

        print(
            "PASS: disabled scan policy cannot resolve "
            "an execution subject"
        )

        # --------------------------------------------------------------
        # Inactive asset fails closed.
        # --------------------------------------------------------------
        with conn:
            asset_id = create_asset(
                conn,
                asset_type="HOST",
                canonical_name="inactive-asset-host",
                lifecycle_status="INACTIVE",
            )

            add_identifier(
                conn,
                asset_id=asset_id,
                identifier_type="IP_ADDRESS",
                identifier_value="192.0.2.80",
                confidence="MEDIUM",
            )

            policy_id = create_policy(
                conn,
                asset_id=asset_id,
                scanner_type="nmap_nse",
                profile_name="inactive-asset",
                scanner_parameters={
                    "task_name": "inactive-test",
                },
            )

            expect_not_resolvable(
                conn,
                policy_id=policy_id,
                expected_text="is not ACTIVE",
            )

        print(
            "PASS: inactive canonical asset cannot resolve "
            "an execution subject"
        )

        print(
            "OK: scan subject resolution regression tests passed."
        )

    finally:
        try:
            with conn:
                clean_database(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
