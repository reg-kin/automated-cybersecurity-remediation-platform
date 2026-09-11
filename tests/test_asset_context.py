#!/usr/bin/env python3

"""Regression tests for curated asset context management."""

import os
import sys

import psycopg2


REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from asset_management.context import (
    clear_asset_context,
    get_asset_context,
    set_asset_context,
)


PG_HOST = os.getenv("PG_HOST", "127.0.0.1")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DATABASE = os.getenv(
    "PG_DBNAME",
    "automated_remediation_release_smoke_test",
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
            WHERE tenant_code LIKE 'ASSET-CONTEXT-%'
            """
        )

    conn.commit()


def create_asset(
    conn,
    *,
    tenant_code,
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
                lifecycle_status,
                management_authorised_at,
                management_authorised_by,
                management_authorisation_reason
            )
            VALUES (
                %s,
                'HOST',
                %s,
                'MANAGED',
                %s,
                now(),
                'asset_context_test',
                'Authorised for asset context regression testing'
            )
            RETURNING asset_id
            """,
            (
                tenant_code,
                canonical_name,
                lifecycle_status,
            ),
        )

        return cur.fetchone()[0]

def test_create_context_for_existing_asset(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-A",
        canonical_name="host-a",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-A",
        asset_id=asset_id,
        context={
            "environment": "PRODUCTION",
            "business_service": "Customer Portal",
            "criticality": "CRITICAL",
            "data_classification": "CONFIDENTIAL",
            "internet_exposure": "INTERNET_FACING",
            "confidentiality_requirement": "HIGH",
            "integrity_requirement": "CRITICAL",
            "availability_requirement": "HIGH",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-A",
        asset_id=asset_id,
    )

    assert context is not None
    assert context["asset_id"] == asset_id
    assert context["tenant_code"] == "ASSET-CONTEXT-A"
    assert context["environment"] == "PRODUCTION"
    assert context["business_service"] == "Customer Portal"
    assert context["criticality"] == "CRITICAL"
    assert context["data_classification"] == "CONFIDENTIAL"
    assert context["internet_exposure"] == "INTERNET_FACING"


def test_missing_context_returns_none(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-B",
        canonical_name="host-b",
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-B",
        asset_id=asset_id,
    )

    assert context is None


def test_partial_update_preserves_existing_fields(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-C",
        canonical_name="host-c",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-C",
        asset_id=asset_id,
        context={
            "environment": "PRODUCTION",
            "business_service": "Payments",
            "business_unit": "Finance",
            "criticality": "HIGH",
        },
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-C",
        asset_id=asset_id,
        context={
            "criticality": "CRITICAL",
            "internet_exposure": "INTERNET_FACING",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-C",
        asset_id=asset_id,
    )

    assert context["environment"] == "PRODUCTION"
    assert context["business_service"] == "Payments"
    assert context["business_unit"] == "Finance"
    assert context["criticality"] == "CRITICAL"
    assert context["internet_exposure"] == "INTERNET_FACING"


def test_enum_values_are_normalised(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-D",
        canonical_name="host-d",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-D",
        asset_id=asset_id,
        context={
            "environment": "production",
            "criticality": "Critical",
            "data_classification": "confidential",
            "internet_exposure": "internet_facing",
            "confidentiality_requirement": "high",
            "integrity_requirement": "medium",
            "availability_requirement": "critical",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-D",
        asset_id=asset_id,
    )

    assert context["environment"] == "PRODUCTION"
    assert context["criticality"] == "CRITICAL"
    assert context["data_classification"] == "CONFIDENTIAL"
    assert context["internet_exposure"] == "INTERNET_FACING"
    assert context["confidentiality_requirement"] == "HIGH"
    assert context["integrity_requirement"] == "MEDIUM"
    assert context["availability_requirement"] == "CRITICAL"


def test_invalid_enum_is_rejected(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-E",
        canonical_name="host-e",
    )

    try:
        set_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-E",
            asset_id=asset_id,
            context={
                "criticality": "EXTREME",
            },
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid criticality must raise ValueError"
        )


def test_empty_nullable_text_becomes_null(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-F",
        canonical_name="host-f",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-F",
        asset_id=asset_id,
        context={
            "business_service": "   ",
            "business_unit": "",
            "owner": " ",
            "technical_owner": "",
            "network_zone": "   ",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-F",
        asset_id=asset_id,
    )

    assert context["business_service"] is None
    assert context["business_unit"] is None
    assert context["owner"] is None
    assert context["technical_owner"] is None
    assert context["network_zone"] is None


def test_context_is_tenant_scoped(conn):
    first = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-G1",
        canonical_name="host-g1",
    )

    second = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-G2",
        canonical_name="host-g2",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-G1",
        asset_id=first,
        context={
            "criticality": "CRITICAL",
        },
    )

    assert (
        get_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-G1",
            asset_id=first,
        )["criticality"]
        == "CRITICAL"
    )

    assert (
        get_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-G2",
            asset_id=second,
        )
        is None
    )


def test_wrong_tenant_cannot_update_asset(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-H1",
        canonical_name="host-h",
    )

    try:
        set_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-H2",
            asset_id=asset_id,
            context={
                "criticality": "CRITICAL",
            },
        )
    except LookupError:
        pass
    else:
        raise AssertionError(
            "Wrong tenant must not update asset context"
        )


def test_nonexistent_asset_cannot_receive_context(conn):
    try:
        set_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-I",
            asset_id=999999999,
            context={
                "criticality": "HIGH",
            },
        )
    except LookupError:
        pass
    else:
        raise AssertionError(
            "Nonexistent asset must raise LookupError"
        )


def test_context_source_is_recorded(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-J",
        canonical_name="host-j",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-J",
        asset_id=asset_id,
        context={
            "criticality": "HIGH",
        },
        context_source="CMDB",
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-J",
        asset_id=asset_id,
    )

    assert context["context_source"] == "CMDB"


def test_clear_context_preserves_asset(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-K",
        canonical_name="host-k",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-K",
        asset_id=asset_id,
        context={
            "criticality": "HIGH",
        },
    )

    clear_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-K",
        asset_id=asset_id,
    )

    assert (
        get_asset_context(
            conn,
            tenant_code="ASSET-CONTEXT-K",
            asset_id=asset_id,
        )
        is None
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM assets
            WHERE asset_id = %s
              AND tenant_code = %s
            """,
            (
                asset_id,
                "ASSET-CONTEXT-K",
            ),
        )

        assert cur.fetchone()[0] == 1


def test_retired_asset_can_retain_context(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-L",
        canonical_name="host-l",
        lifecycle_status="RETIRED",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-L",
        asset_id=asset_id,
        context={
            "criticality": "HIGH",
            "environment": "PRODUCTION",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-L",
        asset_id=asset_id,
    )

    assert context is not None
    assert context["criticality"] == "HIGH"
    assert context["environment"] == "PRODUCTION"


def test_new_context_uses_unknown_defaults(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-M",
        canonical_name="host-m",
    )

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-M",
        asset_id=asset_id,
        context={
            "business_service": "Identity",
        },
    )

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-M",
        asset_id=asset_id,
    )

    assert context["environment"] == "UNKNOWN"
    assert context["criticality"] == "UNKNOWN"
    assert context["data_classification"] == "UNKNOWN"
    assert context["internet_exposure"] == "UNKNOWN"
    assert context["confidentiality_requirement"] == "UNKNOWN"
    assert context["integrity_requirement"] == "UNKNOWN"
    assert context["availability_requirement"] == "UNKNOWN"


def test_context_manager_does_not_commit(conn):
    asset_id = create_asset(
        conn,
        tenant_code="ASSET-CONTEXT-N",
        canonical_name="host-n",
    )

    conn.commit()

    set_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-N",
        asset_id=asset_id,
        context={
            "criticality": "HIGH",
        },
    )

    conn.rollback()

    context = get_asset_context(
        conn,
        tenant_code="ASSET-CONTEXT-N",
        asset_id=asset_id,
    )

    assert context is None


def main():
    conn = connect()

    try:
        clean_test_assets(conn)

        tests = [
            test_create_context_for_existing_asset,
            test_missing_context_returns_none,
            test_partial_update_preserves_existing_fields,
            test_enum_values_are_normalised,
            test_invalid_enum_is_rejected,
            test_empty_nullable_text_becomes_null,
            test_context_is_tenant_scoped,
            test_wrong_tenant_cannot_update_asset,
            test_nonexistent_asset_cannot_receive_context,
            test_context_source_is_recorded,
            test_clear_context_preserves_asset,
            test_retired_asset_can_retain_context,
            test_new_context_uses_unknown_defaults,
            test_context_manager_does_not_commit,
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
        "PASS: asset context management "
        "regression tests"
    )


if __name__ == "__main__":
    main()
