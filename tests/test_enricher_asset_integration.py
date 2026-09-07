#!/usr/bin/env python3

import importlib.util
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from unittest.mock import patch

import psycopg2


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = REPO_ROOT / "worker" / "enricher_worker.py"
ORCHESTRATOR_DIR = REPO_ROOT / "scanner_orchestrators"

SCA_ORCHESTRATOR_PATH = (
    ORCHESTRATOR_DIR
    / "wazuh_sca_orchestrator.py"
)

VULN_ORCHESTRATOR_PATH = (
    ORCHESTRATOR_DIR
    / "wazuh_vuln_orchestrator.py"
)

SCA_FIXTURE_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "wazuh_sca"
    / "cis_crontab_permissions.json"
)

VULN_FIXTURE_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "wazuh_vulnerability"
    / "package_vulnerability.json"
)

PG = {
    "host": os.getenv("PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("PG_PORT", "5432")),
    "dbname": os.getenv(
        "PG_DBNAME",
        "regis_release_smoke_test",
    ),
    "user": os.getenv("PG_USER", "telemetry_admin"),
    "password": os.getenv("PG_PASSWORD", ""),
}

TENANT = "ASSET-WORKER-INTEGRATION"


def load_module(name, path):

    if path.parent == ORCHESTRATOR_DIR:
        orchestrator_path = str(ORCHESTRATOR_DIR)

        if orchestrator_path not in sys.path:
            sys.path.insert(0, orchestrator_path)

    spec = importlib.util.spec_from_file_location(
        name,
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load module: {path}"
        )

    module = importlib.util.module_from_spec(spec)

    with (
        patch("os.makedirs"),
        patch.object(
            logging.handlers,
            "RotatingFileHandler",
            return_value=logging.NullHandler(),
        ),
    ):
        spec.loader.exec_module(module)

    return module


def build_sca_finding():
    orchestrator = load_module(
        "asset_test_wazuh_sca",
        SCA_ORCHESTRATOR_PATH,
    )

    with SCA_FIXTURE_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        fixture = json.load(handle)

    return orchestrator.build_finding(
        tenant=TENANT,
        tier="STANDARD",
        agent_id="007",
        agent_identity=fixture["agent_identity"],
        policy=fixture["policy"],
        item=fixture["check"],
        refresh_id=None,
        refresh_started_at=None,
    )


def build_vulnerability_finding():
    orchestrator = load_module(
        "asset_test_wazuh_vulnerability",
        VULN_ORCHESTRATOR_PATH,
    )

    with VULN_FIXTURE_PATH.open(
        "r",
        encoding="utf-8",
    ) as handle:
        hit = json.load(handle)

    return orchestrator.normalize_hit(
        hit=hit,
        tenant_code=TENANT,
        service_tier="STANDARD",
        agent_id="007",
        refresh_id=None,
        refresh_started_at=None,
    )


def clean_database():
    conn = psycopg2.connect(**PG)

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM unified_security_findings
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
    finally:
        conn.close()


def fetch_finding_asset(engine_source):
    conn = psycopg2.connect(**PG)

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_id
                FROM unified_security_findings
                WHERE tenant_code = %s
                  AND engine_source = %s
                """,
                (
                    TENANT,
                    engine_source,
                ),
            )

            row = cur.fetchone()

            if row is None:
                raise AssertionError(
                    f"No finding stored for {engine_source}"
                )

            return row[0]
    finally:
        conn.close()


def fetch_asset_count():
    conn = psycopg2.connect(**PG)

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM assets
                WHERE tenant_code = %s
                """,
                (TENANT,),
            )

            return cur.fetchone()[0]
    finally:
        conn.close()


def main():
    worker = load_module(
        "asset_test_enricher_worker",
        WORKER_PATH,
    )

    clean_database()

    try:
        sca_finding = build_sca_finding()
        vulnerability_finding = (
            build_vulnerability_finding()
        )

        fake_ai = {
            "risk_summary": "Test risk summary.",
            "business_context_impact": (
                "Test business context impact."
            ),
            "confidence_score": 1.0,
        }

        test_config = worker.DEFAULT.copy()
        test_config.update(
            {
                "pg_host": PG["host"],
                "pg_port": PG["port"],
                "pg_dbname": PG["dbname"],
                "pg_user": PG["user"],
                "pg_password": PG["password"],
                "pg_minconn": 1,
                "pg_maxconn": 2,
            }
        )

        with (
            patch.object(
                worker,
                "config",
                return_value=test_config,
            ),
            patch.object(
                worker,
                "setup",
            ),
            patch.object(
                worker,
                "enrich",
                return_value=fake_ai,
            ),
        ):

            worker.process_ai_enrichment(
                sca_finding
            )

            sca_asset_id = fetch_finding_asset(
                "wazuh_sca"
            )

            assert sca_asset_id is not None

            print(
                "PASS: Wazuh SCA finding is persisted "
                "with a canonical asset_id"
            )

            worker.process_ai_enrichment(
                vulnerability_finding
            )

            vulnerability_asset_id = (
                fetch_finding_asset(
                    "wazuh_vulnerability"
                )
            )

            assert vulnerability_asset_id is not None

            assert (
                vulnerability_asset_id
                == sca_asset_id
            )

            assert fetch_asset_count() == 1

            print(
                "PASS: Wazuh SCA and Wazuh Vulnerability "
                "findings converge on one canonical asset"
            )

            with patch.object(
                worker,
                "resolve_asset",
                return_value=None,
            ):
                worker.process_ai_enrichment(
                    sca_finding
                )

            preserved_asset_id = (
                fetch_finding_asset(
                    "wazuh_sca"
                )
            )

            assert preserved_asset_id == sca_asset_id

            print(
                "PASS: unresolved re-ingestion preserves "
                "the existing finding asset_id"
            )

    finally:
        if worker.pool is not None:
            worker.pool.closeall()
            worker.pool = None

        clean_database()

    print(
        "PASS: enricher worker persists deterministic "
        "Wazuh asset resolution"
    )


if __name__ == "__main__":
    main()
