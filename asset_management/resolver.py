"""Deterministic canonical asset resolution.

Scanner orchestrators remain responsible for converting scanner-native
evidence into the Unified Security Finding contract. Asset resolution is a
separate downstream concern.

Transaction ownership belongs to the caller. This module must not commit or
roll back the supplied PostgreSQL connection.
"""

import ipaddress

from psycopg2 import errors

SUPPORTED_ENGINES = {
    "wazuh_sca",
    "wazuh_vulnerability",
    "nmap_nse",
    "openvas",
    "lynis",
}

WEAK_HOST_ENGINES = {
    "nmap_nse",
    "openvas",
    "lynis",
}

STRONG_IDENTIFIER_INDEX = "uq_asset_identifiers_strong_active"

def _normalise_text(value):
    if value is None:
        return None

    value = str(value).strip()
    return value or None


def _normalise_ip(value):
    value = _normalise_text(value)

    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _extract_wazuh_evidence(
    target_host,
    engine_metadata,
):
    metadata = engine_metadata or {}

    agent_id = _normalise_text(
        metadata.get("agent_id")
    )
    agent_name = _normalise_text(
        metadata.get("agent_name")
    )
    agent_ip = _normalise_ip(
        metadata.get("agent_ip")
    )
    target_ip = _normalise_ip(target_host)

    identifiers = []

    if agent_id:
        identifiers.append(
            {
                "identifier_type": "WAZUH_AGENT_ID",
                "identifier_value": agent_id,
                "normalized_value": agent_id,
                "confidence": "VERY_HIGH",
                "is_authoritative": True,
            }
        )

    if agent_name:
        identifiers.append(
            {
                "identifier_type": "HOSTNAME",
                "identifier_value": agent_name,
                "normalized_value": agent_name.lower(),
                "confidence": "HIGH",
                "is_authoritative": False,
            }
        )

    observed_ip = agent_ip or target_ip

    if observed_ip:
        identifiers.append(
            {
                "identifier_type": "IP_ADDRESS",
                "identifier_value": observed_ip,
                "normalized_value": observed_ip,
                "confidence": "MEDIUM",
                "is_authoritative": False,
            }
        )

    canonical_name = (
        agent_name
        or agent_ip
        or _normalise_text(target_host)
        or agent_id
    )

    return {
        "asset_type": "HOST",
        "canonical_name": canonical_name,
        "identifiers": identifiers,
    }

def _extract_weak_host_evidence(
    target_host,
):
    target_ip = _normalise_ip(target_host)

    if target_ip is None:
        return {
            "asset_type": "HOST",
            "canonical_name": None,
            "identifiers": [],
        }

    return {
        "asset_type": "HOST",
        "canonical_name": target_ip,
        "identifiers": [
            {
                "identifier_type": "IP_ADDRESS",
                "identifier_value": target_ip,
                "normalized_value": target_ip,
                "confidence": "MEDIUM",
                "is_authoritative": False,
            }
        ],
    }

def _extract_evidence(
    target_host,
    engine_source,
    engine_metadata,
):
    if engine_source not in SUPPORTED_ENGINES:
        return None

    if engine_source in WEAK_HOST_ENGINES:
        return _extract_weak_host_evidence(
            target_host,
        )

    return _extract_wazuh_evidence(
        target_host,
        engine_metadata,
    )

def _find_strong_asset(
    cur,
    tenant_code,
    identifiers,
):
    strong = [
        identifier
        for identifier in identifiers
        if identifier["identifier_type"]
        == "WAZUH_AGENT_ID"
    ]

    if not strong:
        return None

    identifier = strong[0]

    cur.execute(
        """
        SELECT asset_id
        FROM asset_identifiers
        WHERE tenant_code = %s
          AND identifier_type = %s
          AND normalized_value = %s
          AND is_active IS TRUE
        """,
        (
            tenant_code,
            identifier["identifier_type"],
            identifier["normalized_value"],
        ),
    )

    rows = cur.fetchall()

    if len(rows) > 1:
        raise RuntimeError(
            "Strong asset identifier resolved to "
            "multiple active assets"
        )

    if rows:
        return rows[0][0]

    return None

def _find_weak_host_asset(
    cur,
    tenant_code,
    identifiers,
):
    weak_ips = [
        identifier
        for identifier in identifiers
        if identifier["identifier_type"]
        == "IP_ADDRESS"
    ]

    if not weak_ips:
        return None

    identifier = weak_ips[0]

    cur.execute(
        """
        SELECT DISTINCT ai.asset_id
        FROM asset_identifiers AS ai
        JOIN assets AS a
          ON a.asset_id = ai.asset_id
         AND a.tenant_code = ai.tenant_code
        WHERE ai.tenant_code = %s
          AND ai.identifier_type = 'IP_ADDRESS'
          AND ai.normalized_value = %s
          AND ai.is_active IS TRUE
          AND a.asset_type = 'HOST'
          AND a.lifecycle_status = 'ACTIVE'
          AND EXISTS (
              SELECT 1
              FROM asset_identifiers AS strong_ai
              WHERE strong_ai.asset_id = ai.asset_id
                AND strong_ai.tenant_code = ai.tenant_code
                AND strong_ai.is_active IS TRUE
                AND strong_ai.identifier_type IN (
                    'WAZUH_AGENT_ID',
                    'MACHINE_ID',
                    'CLOUD_INSTANCE_ID'
                )
          )
        """,
        (
            tenant_code,
            identifier["normalized_value"],
        ),
    )

    rows = cur.fetchall()

    if len(rows) != 1:
        return None

    return rows[0][0]

def _create_asset(
    cur,
    tenant_code,
    asset_type,
    canonical_name,
):
    if not canonical_name:
        raise ValueError(
            "Cannot create an asset without a canonical name"
        )

    cur.execute(
        """
        INSERT INTO assets (
            tenant_code,
            asset_type,
            canonical_name,
            inventory_state
        )
        VALUES (%s, %s, %s, 'PROVISIONAL')
        RETURNING asset_id
        """,
        (
            tenant_code,
            asset_type,
            canonical_name,
        ),
    )

    return cur.fetchone()[0]


def _record_identifier(
    cur,
    asset_id,
    tenant_code,
    source,
    identifier,
):
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
            %s,
            %s,
            %s,
            TRUE
        )
        ON CONFLICT (
            asset_id,
            identifier_type,
            normalized_value
        )
        DO UPDATE SET
            identifier_value = EXCLUDED.identifier_value,
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            is_authoritative = (
                asset_identifiers.is_authoritative
                OR EXCLUDED.is_authoritative
            ),
            is_active = TRUE,
            last_seen_at = NOW()
        """,
        (
            asset_id,
            tenant_code,
            identifier["identifier_type"],
            identifier["identifier_value"],
            identifier["normalized_value"],
            source,
            identifier["confidence"],
            identifier["is_authoritative"],
        ),
    )


def _touch_asset(
    cur,
    asset_id,
):
    cur.execute(
        """
        UPDATE assets
        SET
            last_seen_at = NOW(),
            updated_at = NOW()
        WHERE asset_id = %s
        """,
        (asset_id,),
    )

    if cur.rowcount != 1:
        raise RuntimeError(
            f"Resolved asset {asset_id} no longer exists"
        )


def _persist_resolution(
    cur,
    *,
    tenant_code,
    engine_source,
    evidence,
):
    asset_id = _find_strong_asset(
        cur,
        tenant_code,
        evidence["identifiers"],
    )

    if asset_id is None:
        asset_id = _create_asset(
            cur,
            tenant_code,
            evidence["asset_type"],
            evidence["canonical_name"],
        )
    else:
        _touch_asset(
            cur,
            asset_id,
        )

    for identifier in evidence["identifiers"]:
        _record_identifier(
            cur,
            asset_id,
            tenant_code,
            engine_source,
            identifier,
        )

    return asset_id


def resolve_asset(
    conn,
    *,
    tenant_code,
    target_host,
    engine_source,
    engine_metadata,
):

    """Resolve scanner evidence to a canonical asset.

    WAZUH_AGENT_ID is the authoritative Wazuh convergence key. Wazuh
    hostname and IP evidence is recorded on the resolved asset but is not
    used to merge existing assets.

    Nmap, OpenVAS and Lynis may bind by IP address only when exactly one
    existing active HOST asset matches and that asset is anchored by an
    active strong host identifier. Weak scanner evidence never creates or
    merges assets.

    Unsupported scanners and unresolved identities return None.

    The caller owns the surrounding transaction.
    """

    tenant_code = _normalise_text(tenant_code)
    engine_source = _normalise_text(engine_source)

    if not tenant_code:
        raise ValueError(
            "tenant_code is required for asset resolution"
        )

    evidence = _extract_evidence(
        target_host,
        engine_source,
        engine_metadata,
    )

    if evidence is None:
        return None

    if engine_source in WEAK_HOST_ENGINES:
        with conn.cursor() as cur:
            asset_id = _find_weak_host_asset(
                cur,
                tenant_code,
                evidence["identifiers"],
            )

            if asset_id is None:
                return None

            _touch_asset(
                cur,
                asset_id,
            )

        return asset_id

    has_strong_identity = any(
        identifier["identifier_type"]
        == "WAZUH_AGENT_ID"
        for identifier in evidence["identifiers"]
    )

    if not has_strong_identity:
        return None

    with conn.cursor() as cur:
        # The savepoint lets the caller's larger transaction survive a
        # concurrent first-discovery race on the strong-identifier index.
        cur.execute(
            "SAVEPOINT asset_resolution"
        )

        try:
            asset_id = _persist_resolution(
                cur,
                tenant_code=tenant_code,
                engine_source=engine_source,
                evidence=evidence,
            )

        except errors.UniqueViolation as exc:
            constraint_name = getattr(
                exc.diag,
                "constraint_name",
                None,
            )

            cur.execute(
                "ROLLBACK TO SAVEPOINT asset_resolution"
            )

            if constraint_name != STRONG_IDENTIFIER_INDEX:
                raise

            # Another transaction may have established the authoritative
            # identity first. Resolve it rather than creating a duplicate.
            asset_id = _find_strong_asset(
                cur,
                tenant_code,
                evidence["identifiers"],
            )

            if asset_id is None:
                raise

            _touch_asset(
                cur,
                asset_id,
            )

            for identifier in evidence["identifiers"]:
                _record_identifier(
                    cur,
                    asset_id,
                    tenant_code,
                    engine_source,
                    identifier,
                )

        finally:
            cur.execute(
                "RELEASE SAVEPOINT asset_resolution"
            )

    return asset_id
