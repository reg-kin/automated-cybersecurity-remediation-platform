"""Deterministic scanner-subject resolution.

This module resolves a canonical scan policy to the scanner-native subject
required by scan execution.

It deliberately does not:
- invoke scanners;
- parse scanner-native evidence;
- determine finding_class;
- construct Unified Security Findings;
- perform risk contextualisation;
- select execution nodes;
- create scan executions;
- modify canonical asset identity.

Resolution is read-only. The caller owns transaction boundaries.
"""


class ScanSubjectResolutionError(RuntimeError):
    """Base error for deterministic scanner-subject resolution."""


class ScanSubjectNotResolvableError(ScanSubjectResolutionError):
    """Raised when no deterministic scanner subject can be resolved."""


class ScanSubjectAmbiguousError(ScanSubjectResolutionError):
    """Raised when more than one valid scanner subject is available."""


def _load_policy(conn, *, scan_policy_id: int) -> dict:
    if (
        isinstance(scan_policy_id, bool)
        or not isinstance(scan_policy_id, int)
        or scan_policy_id <= 0
    ):
        raise ValueError(
            "scan_policy_id must be a positive integer"
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                p.scan_policy_id,
                p.tenant_code,
                p.asset_id,
                p.scanner_type,
                p.scanner_parameters,
                p.is_enabled,
                a.asset_type,
                a.lifecycle_status
            FROM scan_policies AS p
            JOIN assets AS a
              ON a.asset_id = p.asset_id
             AND a.tenant_code = p.tenant_code
            WHERE p.scan_policy_id = %s
            """,
            (scan_policy_id,),
        )

        row = cur.fetchone()

    if row is None:
        raise ScanSubjectNotResolvableError(
            f"Scan policy {scan_policy_id} does not exist"
        )

    return {
        "scan_policy_id": row[0],
        "tenant_code": row[1],
        "asset_id": row[2],
        "scanner_type": row[3],
        "scanner_parameters": row[4],
        "is_enabled": row[5],
        "asset_type": row[6],
        "asset_lifecycle_status": row[7],
    }


def _load_identifiers(
    conn,
    *,
    tenant_code: str,
    asset_id: int,
    identifier_type: str,
) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT identifier_value
            FROM asset_identifiers
            WHERE tenant_code = %s
              AND asset_id = %s
              AND identifier_type = %s
              AND is_active IS TRUE
            ORDER BY
                is_authoritative DESC,
                CASE confidence
                    WHEN 'VERY_HIGH' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END DESC,
                asset_identifier_id ASC
            """,
            (
                tenant_code,
                asset_id,
                identifier_type,
            ),
        )

        return [
            row[0]
            for row in cur.fetchall()
        ]


def _require_single_identifier(
    conn,
    *,
    policy: dict,
    identifier_type: str,
    subject_type: str,
) -> dict:
    values = _load_identifiers(
        conn,
        tenant_code=policy["tenant_code"],
        asset_id=policy["asset_id"],
        identifier_type=identifier_type,
    )

    if not values:
        raise ScanSubjectNotResolvableError(
            f"Asset {policy['asset_id']} has no active "
            f"{identifier_type} identifier"
        )

    distinct_values = list(
        dict.fromkeys(values)
    )

    if len(distinct_values) != 1:
        raise ScanSubjectAmbiguousError(
            f"Asset {policy['asset_id']} has multiple active "
            f"{identifier_type} identifiers"
        )

    return {
        "scanner_subject_type": subject_type,
        "scanner_subject_value": distinct_values[0],
    }


def resolve_scanner_subject(
    conn,
    *,
    scan_policy_id: int,
) -> dict:
    """Resolve one scan policy to one deterministic scanner subject."""

    policy = _load_policy(
        conn,
        scan_policy_id=scan_policy_id,
    )

    if not policy["is_enabled"]:
        raise ScanSubjectNotResolvableError(
            f"Scan policy {scan_policy_id} is disabled"
        )

    if policy["asset_lifecycle_status"] != "ACTIVE":
        raise ScanSubjectNotResolvableError(
            f"Asset {policy['asset_id']} is not ACTIVE"
        )

    scanner_type = policy["scanner_type"]

    if scanner_type in {
        "wazuh_vulnerability",
        "wazuh_sca",
    }:
        return _require_single_identifier(
            conn,
            policy=policy,
            identifier_type="WAZUH_AGENT_ID",
            subject_type="WAZUH_AGENT_ID",
        )

    if scanner_type == "nmap_nse":
        return _require_single_identifier(
            conn,
            policy=policy,
            identifier_type="IP_ADDRESS",
            subject_type="IP_ADDRESS",
        )

    if scanner_type == "nuclei":
        return _require_single_identifier(
            conn,
            policy=policy,
            identifier_type="APPLICATION_ID",
            subject_type="URL",
        )

    if scanner_type == "lynis":
        return {
            "scanner_subject_type": "LOCAL_ASSET",
            "scanner_subject_value": str(
                policy["asset_id"]
            ),
        }

    if scanner_type == "trivy":
        parameters = (
            policy["scanner_parameters"]
            or {}
        )

        scan_type = parameters.get(
            "scan_type"
        )

        if scan_type == "image":
            return _require_single_identifier(
                conn,
                policy=policy,
                identifier_type=(
                    "CONTAINER_IMAGE_REFERENCE"
                ),
                subject_type="CONTAINER_IMAGE",
            )

        if scan_type == "folder":
            raise ScanSubjectNotResolvableError(
                "Trivy filesystem scan subject is not "
                "represented by the current canonical "
                "asset identity model"
            )

        raise ScanSubjectNotResolvableError(
            "Trivy scan policy requires scanner_parameters."
            "scan_type of 'image' or 'folder'"
        )

    if scanner_type == "openvas":
        raise ScanSubjectNotResolvableError(
            "OpenVAS task subject is not represented by "
            "the current canonical asset identity model"
        )

    raise ScanSubjectNotResolvableError(
        f"Unsupported scanner type: {scanner_type}"
    )
