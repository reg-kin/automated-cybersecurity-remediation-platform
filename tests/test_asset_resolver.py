#!/usr/bin/env python3

"""Regression tests for deterministic HOST asset resolution."""

import os
import sys

import psycopg2


REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from asset_management.resolver import resolve_asset

PG_HOST = os.getenv("PG_HOST", "127.0.0.1")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DATABASE = os.getenv(
    "PG_DBNAME",
    "regis_release_smoke_test",
)
PG_USER = os.getenv(
    "PG_USER",
    "telemetry_admin",
)
PG_PASSWORD = os.getenv("PG_PASSWORD", "")

def connect():
    kwargs = {
        "host": PG_HOST,
        "port": PG_PORT,
        "dbname": PG_DATABASE,
        "user": PG_USER,
    }

    if PG_PASSWORD:
        kwargs["password"] = PG_PASSWORD

    return psycopg2.connect(**kwargs)


def clean_test_assets(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM assets
            WHERE tenant_code LIKE 'ASSET-RESOLVER-%'
            """
        )

    conn.commit()


def test_wazuh_sca_creates_host(conn):
    asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-A",
        target_host="192.0.2.40",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "007",
            "agent_name": "ubuntu24-test",
            "agent_ip": "192.0.2.40",
        },
    )

    assert asset_id is not None

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                asset_type,
                canonical_name,
                inventory_state
            FROM assets
            WHERE asset_id = %s
            """,
            (asset_id,),
        )

        assert cur.fetchone() == (
            "HOST",
            "ubuntu24-test",
            "PROVISIONAL",
        )

        cur.execute(
            """
            SELECT
                identifier_type,
                normalized_value,
                confidence,
                is_authoritative
            FROM asset_identifiers
            WHERE asset_id = %s
            ORDER BY identifier_type
            """,
            (asset_id,),
        )

        rows = cur.fetchall()

    assert (
        "WAZUH_AGENT_ID",
        "007",
        "VERY_HIGH",
        True,
    ) in rows

    assert (
        "HOSTNAME",
        "ubuntu24-test",
        "HIGH",
        False,
    ) in rows

    assert (
        "IP_ADDRESS",
        "192.0.2.40",
        "MEDIUM",
        False,
    ) in rows


def test_wazuh_engines_converge(conn):
    sca_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-B",
        target_host="192.0.2.40",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "007",
            "agent_name": "ubuntu24-test",
            "agent_ip": "192.0.2.40",
        },
    )

    vulnerability_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-B",
        target_host="192.0.2.40",
        engine_source="wazuh_vulnerability",
        engine_metadata={
            "agent_id": "007",
        },
    )

    assert vulnerability_asset_id == sca_asset_id

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM assets
            WHERE tenant_code = 'ASSET-RESOLVER-B'
            """
        )

        assert cur.fetchone()[0] == 1


def test_same_agent_id_is_tenant_scoped(conn):
    first = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-C1",
        target_host="192.0.2.40",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "007",
        },
    )

    second = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-C2",
        target_host="192.0.2.40",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "007",
        },
    )

    assert first != second


def test_weak_identity_does_not_create_asset(conn):
    asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-D",
        target_host="192.0.2.41",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_name": "weak-only-host",
            "agent_ip": "192.0.2.41",
        },
    )

    assert asset_id is None

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM assets
            WHERE tenant_code = 'ASSET-RESOLVER-D'
            """
        )

        assert cur.fetchone()[0] == 0

def test_nmap_binds_existing_wazuh_host_by_ip(conn):
    wazuh_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-E",
        target_host="192.0.2.60",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "060",
            "agent_name": "nmap-target",
            "agent_ip": "192.0.2.60",
        },
    )

    nmap_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-E",
        target_host="192.0.2.60",
        engine_source="nmap_nse",
        engine_metadata={},
    )

    assert nmap_asset_id == wazuh_asset_id


def test_openvas_binds_existing_wazuh_host_by_ip(conn):
    wazuh_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-F",
        target_host="192.0.2.61",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "061",
            "agent_name": "openvas-target",
            "agent_ip": "192.0.2.61",
        },
    )

    openvas_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-F",
        target_host="192.0.2.61",
        engine_source="openvas",
        engine_metadata={},
    )

    assert openvas_asset_id == wazuh_asset_id


def test_lynis_binds_existing_wazuh_host_by_ip(conn):
    wazuh_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-G",
        target_host="192.0.2.62",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "062",
            "agent_name": "lynis-target",
            "agent_ip": "192.0.2.62",
        },
    )

    lynis_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-G",
        target_host="192.0.2.62",
        engine_source="lynis",
        engine_metadata={},
    )

    assert lynis_asset_id == wazuh_asset_id


def test_weak_scanner_does_not_create_host(conn):
    asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-H",
        target_host="192.0.2.70",
        engine_source="nmap_nse",
        engine_metadata={},
    )

    assert asset_id is None

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM assets
            WHERE tenant_code = 'ASSET-RESOLVER-H'
            """
        )

        assert cur.fetchone()[0] == 0


def test_ambiguous_ip_remains_unresolved(conn):
    first_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-I",
        target_host="192.0.2.80",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "080-A",
            "agent_name": "host-a",
            "agent_ip": "192.0.2.80",
        },
    )

    second_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-I",
        target_host="192.0.2.80",
        engine_source="wazuh_sca",
        engine_metadata={
            "agent_id": "080-B",
            "agent_name": "host-b",
            "agent_ip": "192.0.2.80",
        },
    )

    assert first_asset_id != second_asset_id

    resolved_asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-I",
        target_host="192.0.2.80",
        engine_source="nmap_nse",
        engine_metadata={},
    )

    assert resolved_asset_id is None

def test_unsupported_engine_remains_unresolved(conn):
    asset_id = resolve_asset(
        conn,
        tenant_code="ASSET-RESOLVER-E",
        target_host="192.0.2.50",
        engine_source="openvas",
        engine_metadata={},
    )

    assert asset_id is None


def main():
    conn = connect()

    try:
        clean_test_assets(conn)

        tests = [
            test_wazuh_sca_creates_host,
            test_wazuh_engines_converge,
            test_same_agent_id_is_tenant_scoped,
            test_weak_identity_does_not_create_asset,
            test_nmap_binds_existing_wazuh_host_by_ip,
            test_openvas_binds_existing_wazuh_host_by_ip,
            test_lynis_binds_existing_wazuh_host_by_ip,
            test_weak_scanner_does_not_create_host,
            test_ambiguous_ip_remains_unresolved,
            test_unsupported_engine_remains_unresolved,
        ]

        for test in tests:
            test(conn)
            conn.rollback()
            print(f"PASS: {test.__name__}")

    finally:
        try:
            clean_test_assets(conn)
        finally:
            conn.close()

    print(
        "PASS: deterministic HOST asset resolver "
        "regression tests"
    )


if __name__ == "__main__":
    main()
