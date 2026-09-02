#!/usr/bin/env python3
"""
Regis Security Consulting
Wazuh Vulnerability Detection Orchestrator

PURPOSE
=======

This orchestrator queries the local Wazuh Indexer for the current
vulnerability state of a specified Wazuh agent.

Responsibilities:

1. Query Wazuh Vulnerability Detection findings for an agent.
2. Determine the canonical finding_class deterministically.
3. Normalise each finding to the current UnifiedSecurityFinding schema.
4. Add scanner-specific metadata required by later remediation.
5. Deduplicate findings.
6. Optionally filter by severity.
7. Write findings line-by-line to the local Wazuh-monitored scanner log.

The normal ingestion pipeline is:

    Wazuh Vulnerability Detection
        ->
    wazuh_vuln_orchestrator.py
        ->
    /var/log/scanners_raw.log
        ->
    Wazuh Agent / rule / integration
        ->
    Redis
        ->
    Ollama enrichment worker
        ->
    PostgreSQL

IMPORTANT: STAGE 2 VERIFICATION
===============================

This orchestrator currently supports SCAN MODE ONLY.

Wazuh Vulnerability Detection does not provide this orchestrator with a
reliable mechanism to initiate an immediate, targeted vulnerability scan
for one specific CVE on one particular agent.

Therefore this orchestrator must NOT pretend that querying the current
Indexer state is equivalent to launching a fresh Stage 2 verification scan.

Stage 2 verification for Wazuh Vulnerability Detection will be implemented
separately using an asynchronous/current-state confirmation mechanism once
the Wazuh vulnerability inventory has refreshed after remediation.

Canonical Wazuh Vulnerability finding classes
=============================================

This orchestrator uses exactly these finding classes:

    cve
    package_vulnerability
    kernel_vulnerability
    unsupported_software
    missing_security_update

No new finding classes are created here.

Ollama is NOT responsible for finding_class determination.

Examples
========

Preferred explicit invocation:

    python3 wazuh_vuln_orchestrator.py \
        --mode scan \
        --tenant-code CUSTOMER_A \
        --service-tier GOLD \
        --agent-id 007 \
        --severities high,critical

Without severity filtering:

    python3 wazuh_vuln_orchestrator.py \
        --mode scan \
        --tenant-code CUSTOMER_A \
        --service-tier GOLD \
        --agent-id 007

Legacy invocation remains supported:

    python3 wazuh_vuln_orchestrator.py \
        CUSTOMER_A \
        GOLD \
        007 \
        high,critical
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import uuid

from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Set, Tuple

from common.runtime import utc_now

import requests
import urllib3


# ============================================================================
# CONFIGURATION
# ============================================================================

INDEXER_URL = os.getenv(
    "REGIS_WAZUH_INDEXER_URL",
    "https://127.0.0.1:9200",
)

INDEX_PATTERN = os.getenv(
    "REGIS_WAZUH_VULN_INDEX",
    "wazuh-states-vulnerabilities-*",
)

CREDENTIALS_FILE = os.getenv(
    "REGIS_WAZUH_CREDENTIALS_FILE",
    "/opt/regis-security/scanner_orchestrators/api_keys.json",
)

DATA_LOG_PATH = os.getenv(
    "REGIS_SCANNER_RAW_LOG",
    "/var/log/scanners_raw.log",
)

LOG_DIR = os.getenv(
    "REGIS_LOG_DIR",
    "/var/log/regis-security",
)

ERROR_LOG_PATH = os.path.join(
    LOG_DIR,
    "wazuh_vuln_orchestrator.error.log",
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "REGIS_WAZUH_INDEXER_TIMEOUT",
        "30",
    )
)

PAGE_SIZE = int(
    os.getenv(
        "REGIS_WAZUH_VULN_PAGE_SIZE",
        os.getenv(
            "REGIS_WAZUH_VULN_MAX_RESULTS",
            "5000",
        ),
    )
)

SCROLL_TTL = os.getenv(
    "REGIS_WAZUH_VULN_SCROLL_TTL",
    "2m",
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_SERVICE_TIERS = {
    "GOLD",
    "STANDARD",
    "BRONZE",
}

VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
}

VALID_WAZUH_VULN_CLASSES = {
    "cve",
    "package_vulnerability",
    "kernel_vulnerability",
    "unsupported_software",
    "missing_security_update",
}

VALID_FINDING_CATEGORIES = {
    "vulnerability",
    "compliance_drift",
    "integrity_drift",
    "rootkit",
}

VALID_LIFECYCLE_STATUSES = {
    "OPEN",
    "IN_REMEDIATION",
    "RESOLVED",
    "FALSE_POSITIVE",
}


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging() -> logging.Logger:
    """
    Configure application logging.

    Operational logs are written to stderr so stdout can remain suitable
    for optional machine-readable scan summaries.
    """

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "wazuh_vuln_orchestrator"
    )

    logger.setLevel(
        logging.INFO
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    error_handler = RotatingFileHandler(
        ERROR_LOG_PATH,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )

    error_handler.setFormatter(
        formatter
    )

    error_handler.setLevel(
        logging.WARNING
    )

    stream_handler = logging.StreamHandler(
        sys.stderr
    )

    stream_handler.setFormatter(
        formatter
    )

    stream_handler.setLevel(
        logging.INFO
    )

    logger.handlers.clear()

    logger.addHandler(
        error_handler
    )

    logger.addHandler(
        stream_handler
    )

    logger.propagate = False

    return logger


logger = setup_logging()


# Wazuh Indexer is currently queried locally with TLS verification disabled.
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================================
# GENERAL HELPERS
# ============================================================================

def get_session() -> requests.Session:
    """
    Create the HTTP session used for Wazuh Indexer queries.
    """

    session = requests.Session()

    session.verify = False

    return session


# ============================================================================
# EXISTING WORKING CREDENTIAL HANDLING
# ============================================================================

def load_credentials():
    """
    Load Wazuh Indexer credentials.

    Credential precedence:

    1. REGIS_WAZUH_INDEXER_USER and REGIS_WAZUH_INDEXER_PASSWORD
    2. Optional local credentials file defined by CREDENTIALS_FILE

    No hard-coded production credentials or usable default password are
    permitted.
    """

    env_user = os.getenv("REGIS_WAZUH_INDEXER_USER", "").strip()
    env_password = os.getenv("REGIS_WAZUH_INDEXER_PASSWORD", "").strip()

    if env_user and env_password:
        return env_user, env_password

    try:
        with open(
            CREDENTIALS_FILE,
            "r",
            encoding="utf-8",
        ) as f:
            creds = json.load(f)

        indexer_block = creds.get("indexer", {})

        user = (
            indexer_block.get("user")
            or indexer_block.get("username")
            or ""
        ).strip()

        password = (
            indexer_block.get("pass")
            or indexer_block.get("password")
            or ""
        ).strip()

        if user and password:
            return user, password

    except FileNotFoundError:
        logger.debug(
            "Wazuh Indexer credentials file not found: %s",
            CREDENTIALS_FILE,
        )

    except Exception as e:
        logger.warning(
            "Failed to load Wazuh Indexer credentials from %s: %s",
            CREDENTIALS_FILE,
            e,
        )

    raise RuntimeError(
        "Wazuh Indexer credentials are not configured. "
        "Set REGIS_WAZUH_INDEXER_USER and "
        "REGIS_WAZUH_INDEXER_PASSWORD, or provide a valid "
        "local credentials file."
    )


def normalize_service_tier(
    value: str,
) -> str:

    tier = str(
        value or "STANDARD"
    ).strip().upper()

    if tier not in VALID_SERVICE_TIERS:

        logger.warning(
            "Unknown service tier %r; using STANDARD.",
            value,
        )

        return "STANDARD"

    return tier


def normalize_severity_level(
    raw_severity: Any,
) -> str:
    """
    Convert Wazuh/vendor severity strings into the canonical severity enum.
    """

    if raw_severity is None:
        return "MEDIUM"

    severity = str(
        raw_severity
    ).strip().upper()

    aliases = {
        "CRIT": "CRITICAL",
        "MODERATE": "MEDIUM",
        "IMPORTANT": "HIGH",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "NEGLIGIBLE": "LOW",
        "UNKNOWN": "MEDIUM",
    }

    severity = aliases.get(
        severity,
        severity,
    )

    if severity in VALID_SEVERITIES:
        return severity

    return "MEDIUM"


def clamp_cvss(
    value: Any,
) -> Optional[float]:

    if value is None:
        return None

    try:

        score = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None

    return max(
        0.0,
        min(
            10.0,
            score,
        ),
    )


def first_non_empty(
    *values: Any,
) -> Any:

    for value in values:

        if value not in (
            None,
            "",
            [],
            {},
        ):

            return value

    return None


# ============================================================================
# WAZUH FIELD EXTRACTION
# ============================================================================

def extract_vulnerability_block(
    source: Dict[str, Any],
) -> Dict[str, Any]:

    block = source.get(
        "vulnerability"
    )

    if isinstance(
        block,
        dict,
    ):

        return block

    return {}


def extract_package_block(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
) -> Dict[str, Any]:

    possible = first_non_empty(
        vulnerability.get(
            "package"
        ),
        source.get(
            "package"
        ),
    )

    if isinstance(
        possible,
        dict,
    ):

        return possible

    return {}


def extract_agent_block(
    source: Dict[str, Any],
) -> Dict[str, Any]:

    block = source.get(
        "agent"
    )

    if isinstance(
        block,
        dict,
    ):

        return block

    return {}


def extract_cve(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
) -> str:

    value = first_non_empty(
        vulnerability.get(
            "id"
        ),
        vulnerability.get(
            "cve"
        ),
        source.get(
            "cve"
        ),
        source.get(
            "vulnerability_id"
        ),
    )

    if value:

        return str(
            value
        ).strip()

    return "UNKNOWN-VULNERABILITY"


def extract_package_name(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package: Dict[str, Any],
) -> Optional[str]:

    value = first_non_empty(
        package.get(
            "name"
        ),
        vulnerability.get(
            "package_name"
        ),
        source.get(
            "package_name"
        ),
        source.get(
            "name"
        ),
    )

    if value is None:
        return None

    value = str(
        value
    ).strip()

    return value or None


def extract_installed_version(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package: Dict[str, Any],
) -> Optional[str]:

    value = first_non_empty(
        package.get(
            "version"
        ),
        vulnerability.get(
            "installed_version"
        ),
        source.get(
            "installed_version"
        ),
        source.get(
            "version"
        ),
    )

    if value is None:
        return None

    return (
        str(
            value
        ).strip()
        or None
    )


def extract_fixed_version(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package: Dict[str, Any],
) -> Optional[str]:
    """
    Extract an explicitly reported fixed/remediated version when Wazuh
    provides one.

    A fixed version is never invented.
    """

    value = first_non_empty(
        package.get(
            "fixed_version"
        ),
        vulnerability.get(
            "fixed_version"
        ),
        vulnerability.get(
            "version_fixed"
        ),
        source.get(
            "fixed_version"
        ),
        source.get(
            "version_fixed"
        ),
    )

    if value is None:
        return None

    return (
        str(
            value
        ).strip()
        or None
    )


def extract_architecture(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package: Dict[str, Any],
) -> Optional[str]:

    value = first_non_empty(
        package.get(
            "architecture"
        ),
        package.get(
            "arch"
        ),
        vulnerability.get(
            "architecture"
        ),
        source.get(
            "architecture"
        ),
    )

    if value is None:
        return None

    return (
        str(
            value
        ).strip()
        or None
    )


def extract_package_source(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package: Dict[str, Any],
) -> Optional[str]:

    value = first_non_empty(
        package.get(
            "source"
        ),
        vulnerability.get(
            "package_source"
        ),
        source.get(
            "package_source"
        ),
    )

    if value is None:
        return None

    return (
        str(
            value
        ).strip()
        or None
    )


def extract_target_host(
    source: Dict[str, Any],
) -> str:
    """
    Extract the remediation target.

    We deliberately do NOT fall back to 127.0.0.1.
    """

    agent = extract_agent_block(
        source
    )

    host_block = source.get(
        "host"
    )

    host_ip = None

    if isinstance(
        host_block,
        dict,
    ):

        host_ip = first_non_empty(
            host_block.get(
                "ip"
            ),
            host_block.get(
                "name"
            ),
        )

    target = first_non_empty(
        agent.get(
            "ip"
        ),
        host_ip,
        agent.get(
            "name"
        ),
    )

    if target is None:

        raise ValueError(
            "Unable to determine target host from Wazuh finding."
        )

    target = str(
        target
    ).strip()

    if not target:

        raise ValueError(
            "Wazuh target host is empty."
        )

    return target


def extract_title(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    finding_key: str,
) -> str:

    title = first_non_empty(
        vulnerability.get(
            "title"
        ),
        vulnerability.get(
            "description"
        ),
        source.get(
            "title"
        ),
        source.get(
            "description"
        ),
    )

    if title is None:

        title = (
            f"Vulnerability detected: {finding_key}"
        )

    return str(
        title
    ).strip()


def extract_severity_score(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    raw_severity: Any,
) -> float:

    cvss = vulnerability.get(
        "cvss"
    )

    possible_scores: List[Any] = [
        vulnerability.get(
            "cvss3"
        ),
        vulnerability.get(
            "cvss2"
        ),
        vulnerability.get(
            "score"
        ),
        source.get(
            "cvss3"
        ),
        source.get(
            "cvss2"
        ),
        source.get(
            "score"
        ),
    ]

    if isinstance(
        cvss,
        dict,
    ):

        possible_scores.extend(
            [
                cvss.get(
                    "score"
                ),
                cvss.get(
                    "base_score"
                ),
            ]
        )

        cvss3 = cvss.get(
            "cvss3"
        )

        if isinstance(
            cvss3,
            dict,
        ):

            possible_scores.extend(
                [
                    cvss3.get(
                        "base_score"
                    ),
                    cvss3.get(
                        "score"
                    ),
                ]
            )

        cvss2 = cvss.get(
            "cvss2"
        )

        if isinstance(
            cvss2,
            dict,
        ):

            possible_scores.extend(
                [
                    cvss2.get(
                        "base_score"
                    ),
                    cvss2.get(
                        "score"
                    ),
                ]
            )

    for candidate in possible_scores:

        score = clamp_cvss(
            candidate
        )

        if score is not None:
            return score

    fallback = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 3.0,
    }

    return fallback[
        normalize_severity_level(
            raw_severity
        )
    ]


# ============================================================================
# FINDING CLASSIFICATION
# ============================================================================

def is_kernel_package(
    package_name: Optional[str],
) -> bool:

    if not package_name:
        return False

    package = package_name.lower()

    kernel_patterns = (
        r"^kernel(?:-|$)",
        r"^linux-image",
        r"^linux-headers",
        r"^linux-modules",
        r"^linux-generic",
        r"^linux-kernel",
    )

    return any(
        re.search(
            pattern,
            package,
        )
        for pattern in kernel_patterns
    )


def build_searchable_text(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
) -> str:

    fields = [
        vulnerability.get(
            "title"
        ),
        vulnerability.get(
            "description"
        ),
        vulnerability.get(
            "status"
        ),
        vulnerability.get(
            "condition"
        ),
        source.get(
            "title"
        ),
        source.get(
            "description"
        ),
        source.get(
            "status"
        ),
        source.get(
            "condition"
        ),
    ]

    return " ".join(
        str(item)
        for item in fields
        if item is not None
    ).lower()


def determine_finding_class(
    source: Dict[str, Any],
    vulnerability: Dict[str, Any],
    package_name: Optional[str],
    finding_key: str,
) -> str:
    """
    Deterministically classify Wazuh Vulnerability Detection findings.

    Precedence:

        kernel_vulnerability
        unsupported_software
        missing_security_update
        package_vulnerability
        cve
    """

    # ------------------------------------------------------------------
    # 1. Kernel vulnerability
    # ------------------------------------------------------------------

    if is_kernel_package(
        package_name
    ):

        return "kernel_vulnerability"

    searchable = build_searchable_text(
        source,
        vulnerability,
    )

    # ------------------------------------------------------------------
    # 2. Unsupported/EOL software
    # ------------------------------------------------------------------

    unsupported_indicators = (
        "end of life",
        "end-of-life",
        "eol",
        "unsupported software",
        "unsupported version",
        "no longer supported",
    )

    if any(
        indicator in searchable
        for indicator in unsupported_indicators
    ):

        return "unsupported_software"

    # ------------------------------------------------------------------
    # 3. Explicit missing security update
    # ------------------------------------------------------------------

    missing_update_indicators = (
        "missing security update",
        "missing security patch",
        "security update is available",
        "security update available",
        "security patch available",
    )

    if any(
        indicator in searchable
        for indicator in missing_update_indicators
    ):

        return "missing_security_update"

    # ------------------------------------------------------------------
    # 4. Installed vulnerable package
    # ------------------------------------------------------------------

    if package_name:

        return "package_vulnerability"

    # ------------------------------------------------------------------
    # 5. Generic CVE
    # ------------------------------------------------------------------

    if re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        finding_key,
        re.IGNORECASE,
    ):

        return "cve"

    # No new class is invented.
    return "cve"


# ============================================================================
# SCHEMA VALIDATION
# ============================================================================

def validate_unified_finding(
    payload: Dict[str, Any],
) -> None:
    """
    Validate the portions of UnifiedSecurityFinding owned by this
    orchestrator.

    The enrichment worker and PostgreSQL provide additional validation.
    """

    required = (
        "tenant_code",
        "tenant_service_tier",
        "target_host",
        "engine_source",
        "finding_category",
        "finding_class",
        "finding_key",
        "finding_title",
        "lifecycle_status",
    )

    for field in required:

        if payload.get(
            field
        ) in (
            None,
            "",
        ):

            raise ValueError(
                "Unified finding is missing "
                f"required field: {field}"
            )

    if (
        payload["finding_category"]
        not in VALID_FINDING_CATEGORIES
    ):

        raise ValueError(
            "Invalid finding_category: "
            f"{payload['finding_category']}"
        )

    if (
        payload["finding_class"]
        not in VALID_WAZUH_VULN_CLASSES
    ):

        raise ValueError(
            "Invalid Wazuh Vulnerability finding_class: "
            f"{payload['finding_class']}"
        )

    if (
        payload["lifecycle_status"]
        not in VALID_LIFECYCLE_STATUSES
    ):

        raise ValueError(
            "Invalid lifecycle_status: "
            f"{payload['lifecycle_status']}"
        )

    severity = payload.get(
        "severity_level"
    )

    if (
        severity is not None
        and severity not in VALID_SEVERITIES
    ):

        raise ValueError(
            "Invalid severity_level: "
            f"{severity}"
        )

    score = payload.get(
        "severity_score"
    )

    if score is not None:

        numeric_score = float(
            score
        )

        if not (
            0.0
            <= numeric_score
            <= 10.0
        ):

            raise ValueError(
                "severity_score must be between 0 and 10"
            )


# ============================================================================
# WAZUH INDEXER QUERY
# ============================================================================

def query_indexer(
    query: Dict[str, Any],
    page_size: int = PAGE_SIZE,
) -> List[Dict[str, Any]]:
    """
    Retrieve the complete matching Wazuh Indexer result set.

    A deferred Stage 2 refresh cannot be authoritative if the orchestrator
    silently truncates the current vulnerability inventory.  The previous
    implementation requested a single page only.  This implementation uses
    the Indexer scroll API and fails closed if the number of retrieved
    documents does not match the total reported by the Indexer.
    """

    if page_size <= 0:
        raise ValueError(
            "REGIS_WAZUH_VULN_PAGE_SIZE must be greater than zero"
        )

    user, password = load_credentials()

    if not user or not password:
        raise RuntimeError(
            "Unable to obtain Wazuh Indexer credentials."
        )

    session = get_session()

    search_url = (
        f"{INDEXER_URL}/"
        f"{INDEX_PATTERN}/_search"
    )

    request_body = {
        "size": page_size,
        "track_total_hits": True,
        "sort": [
            "_doc"
        ],
        "query": query,
    }

    response = session.post(
        search_url,
        params={
            "scroll": SCROLL_TTL,
        },
        auth=(
            user,
            password,
        ),
        headers={
            "Content-Type":
                "application/json",
        },
        json=request_body,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    body = response.json()

    scroll_id = body.get(
        "_scroll_id"
    )

    hits_block = body.get(
        "hits",
        {},
    )

    total_block = hits_block.get(
        "total",
        0,
    )

    if isinstance(
        total_block,
        dict,
    ):
        total_hits = int(
            total_block.get(
                "value",
                0,
            )
        )
    else:
        total_hits = int(
            total_block or 0
        )

    all_hits: List[
        Dict[str, Any]
    ] = list(
        hits_block.get(
            "hits",
            [],
        )
    )

    try:
        while scroll_id:
            current_page = (
                body
                .get(
                    "hits",
                    {},
                )
                .get(
                    "hits",
                    [],
                )
            )

            if not current_page:
                break

            scroll_response = session.post(
                f"{INDEXER_URL}/_search/scroll",
                auth=(
                    user,
                    password,
                ),
                headers={
                    "Content-Type":
                        "application/json",
                },
                json={
                    "scroll": SCROLL_TTL,
                    "scroll_id": scroll_id,
                },
                timeout=REQUEST_TIMEOUT,
            )

            scroll_response.raise_for_status()

            body = scroll_response.json()

            scroll_id = body.get(
                "_scroll_id",
                scroll_id,
            )

            next_page = (
                body
                .get(
                    "hits",
                    {},
                )
                .get(
                    "hits",
                    [],
                )
            )

            if not next_page:
                break

            all_hits.extend(
                next_page
            )

    finally:
        if scroll_id:
            try:
                session.delete(
                    f"{INDEXER_URL}/_search/scroll",
                    auth=(
                        user,
                        password,
                    ),
                    headers={
                        "Content-Type":
                            "application/json",
                    },
                    json={
                        "scroll_id": [
                            scroll_id
                        ]
                    },
                    timeout=REQUEST_TIMEOUT,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to clear Wazuh Indexer scroll context: %s",
                    exc,
                )

    if len(
        all_hits
    ) != total_hits:
        raise RuntimeError(
            "Incomplete Wazuh vulnerability inventory: "
            f"Indexer reported {total_hits} document(s), "
            f"but {len(all_hits)} were retrieved."
        )

    return all_hits


def query_agent_vulnerabilities(
    agent_id: str,
) -> List[Dict[str, Any]]:
    """
    Query current Wazuh Vulnerability Detection state for one agent.
    """

    return query_indexer(
        {
            "bool": {
                "filter": [
                    {
                        "term": {
                            "agent.id":
                                agent_id
                        }
                    }
                ]
            }
        }
    )


# ============================================================================
# FINDING NORMALISATION
# ============================================================================

def normalize_hit(
    hit: Dict[str, Any],
    tenant_code: str,
    service_tier: str,
    agent_id: str,
    refresh_id: str,
    refresh_started_at: str,
) -> Dict[str, Any]:

    source = hit.get(
        "_source",
        {},
    )

    vulnerability = extract_vulnerability_block(
        source
    )

    package = extract_package_block(
        source,
        vulnerability,
    )

    finding_key = extract_cve(
        source,
        vulnerability,
    )

    package_name = extract_package_name(
        source,
        vulnerability,
        package,
    )

    installed_version = extract_installed_version(
        source,
        vulnerability,
        package,
    )

    fixed_version = extract_fixed_version(
        source,
        vulnerability,
        package,
    )

    architecture = extract_architecture(
        source,
        vulnerability,
        package,
    )

    package_source = extract_package_source(
        source,
        vulnerability,
        package,
    )

    target_host = extract_target_host(
        source
    )

    title = extract_title(
        source,
        vulnerability,
        finding_key,
    )

    raw_severity = first_non_empty(
        vulnerability.get(
            "severity"
        ),
        source.get(
            "severity"
        ),
        "medium",
    )

    severity_level = normalize_severity_level(
        raw_severity
    )

    severity_score = extract_severity_score(
        source,
        vulnerability,
        raw_severity,
    )

    finding_class = determine_finding_class(
        source,
        vulnerability,
        package_name,
        finding_key,
    )

    # ------------------------------------------------------------------
    # Engine metadata
    #
    # Store information useful to deterministic remediation and later
    # verification decisions.
    # ------------------------------------------------------------------

    metadata: Dict[str, Any] = {
        "task_name":
            "Wazuh Vulnerability Scan",

        "agent_id":
            agent_id,

        "refresh_id":
            refresh_id,

        "refresh_started_at":
            refresh_started_at,

        "package_name":
            package_name,

        "installed_version":
            installed_version,

        "fixed_version":
            fixed_version,

        "package_architecture":
            architecture,

        "package_source":
            package_source,

        "cve":
            finding_key,

        "finding_ref":
            vulnerability.get(
                "reference"
            ),

        "raw_severity":
            raw_severity,

        "vulnerability_status":
            vulnerability.get(
                "status"
            ),

        "vulnerability_condition":
            vulnerability.get(
                "condition"
            ),

        "index_name":
            hit.get(
                "_index"
            ),

        "index_document_id":
            hit.get(
                "_id"
            ),

        # Important for verification routing.
        #
        # Wazuh Vulnerability Detection currently cannot perform a
        # synchronous targeted Stage 2 scan.
        "verification_capability":
            "asynchronous_state_refresh",

        "targeted_verification_supported":
            False,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value is not None
    }

    if (
        title.lower()
        .startswith(
            finding_key.lower()
        )
    ):

        finding_title = (
            title[:220]
        )

    else:

        finding_title = (
            f"{finding_key} - "
            f"{title[:160]}"
        )

    payload = {
        "tenant_code":
            tenant_code,

        "tenant_service_tier":
            service_tier,

        "target_host":
            target_host,

        # Canonical scanner identity.
        "engine_source":
            "wazuh_vulnerability",

        "finding_category":
            "vulnerability",

        "finding_class":
            finding_class,

        "finding_key":
            finding_key,

        "finding_title":
            finding_title,

        "lifecycle_status":
            "OPEN",

        "detected_at":
            utc_now(),

        "remediated_at":
            None,

        "last_verified_at":
            None,

        "compliance_result":
            None,

        "severity_level":
            severity_level,

        "severity_score":
            severity_score,

        "engine_metadata":
            metadata,

        # Ollama enrichment occurs AFTER scanner ingestion.
        "ai_analysis":
            None,
    }

    validate_unified_finding(
        payload
    )

    return payload


# ============================================================================
# REFRESH CONTROL EVENTS
# ============================================================================

def build_refresh_complete_event(
    *,
    tenant_code: str,
    service_tier: str,
    agent_id: str,
    refresh_id: str,
    refresh_started_at: str,
    refresh_completed_at: str,
    refresh_status: str,
    expected_findings: int,
    indexer_documents: int,
    malformed_documents: int,
    severity_filter: Optional[Set[str]],
) -> Dict[str, Any]:
    """
    Build the control event consumed by the ingestion side.

    This event is deliberately not a UnifiedSecurityFinding.  It marks the
    end of one complete scanner-state refresh and supplies the count needed
    by the ingestion side before that refresh can be promoted to a trusted
    PostgreSQL scanner_refresh_watermark.
    """

    if refresh_status not in {
        "SUCCESS",
        "FAILED",
    }:
        raise ValueError(
            "refresh_status must be SUCCESS or FAILED"
        )

    return {
        "event_type":
            "scanner_refresh_complete",

        "engine_source":
            "wazuh_vulnerability",

        "scanner_subject_type":
            "wazuh_agent",

        "scanner_subject_id":
            agent_id,

        "tenant_code":
            tenant_code,

        "tenant_service_tier":
            service_tier,

        "refresh_id":
            refresh_id,

        "refresh_started_at":
            refresh_started_at,

        "refresh_completed_at":
            refresh_completed_at,

        "refresh_status":
            refresh_status,

        # Number of finding messages carrying this refresh_id that the
        # ingestion side must observe before SUCCESS can become authoritative.
        "expected_findings":
            expected_findings,

        # Raw inventory evidence for operational auditing.
        "indexer_documents":
            indexer_documents,

        "malformed_documents":
            malformed_documents,

        "severity_filter": (
            sorted(
                severity_filter
            )
            if severity_filter
            else []
        ),
    }


# ============================================================================
# SCAN MODE
# ============================================================================

def run_scan_mode(
    tenant_code: str,
    service_tier: str,
    agent_id: str,
    severities: Optional[str],
) -> int:

    tenant_code = str(
        tenant_code
    ).strip()

    if not tenant_code:

        raise ValueError(
            "tenant_code cannot be empty"
        )

    service_tier = normalize_service_tier(
        service_tier
    )

    agent_id = str(
        agent_id
    ).strip()

    if not agent_id:

        raise ValueError(
            "agent_id cannot be empty"
        )

    # ------------------------------------------------------------------
    # Optional severity filtering
    # ------------------------------------------------------------------

    allowed_severities: Optional[
        Set[str]
    ] = None

    if severities:

        allowed_severities = {
            normalize_severity_level(
                item
            )
            for item
            in severities.split(",")
            if item.strip()
        }

    refresh_id = str(
        uuid.uuid4()
    )

    refresh_started_at = utc_now()

    logger.info(
        "SCAN mode: querying Wazuh vulnerability inventory "
        "agent_id=%s tenant=%s tier=%s severities=%s refresh_id=%s",
        agent_id,
        tenant_code,
        service_tier,
        (
            sorted(
                allowed_severities
            )
            if allowed_severities
            else "ALL"
        ),
        refresh_id,
    )

    # query_agent_vulnerabilities() now guarantees that every document
    # reported by the Indexer has been retrieved before returning.
    hits = query_agent_vulnerabilities(
        agent_id
    )

    if not hits:
        logger.info(
            "No vulnerabilities found for agent_id=%s; "
            "the empty inventory will still emit a refresh completion event.",
            agent_id,
        )

    findings: List[
        Dict[str, Any]
    ] = []

    seen: Set[
        Tuple[
            str,
            str,
            str,
            str,
        ]
    ] = set()

    malformed_documents = 0

    for hit in hits:

        try:

            payload = normalize_hit(
                hit=hit,
                tenant_code=tenant_code,
                service_tier=service_tier,
                agent_id=agent_id,
                refresh_id=refresh_id,
                refresh_started_at=refresh_started_at,
            )

        except Exception as exc:

            malformed_documents += 1

            logger.warning(
                "Skipping malformed vulnerability "
                "document %s: %s",
                hit.get(
                    "_id"
                ),
                exc,
            )

            continue

        # --------------------------------------------------------------
        # Severity filtering
        # --------------------------------------------------------------

        if (
            allowed_severities
            and payload[
                "severity_level"
            ]
            not in allowed_severities
        ):

            continue

        # --------------------------------------------------------------
        # Deduplication
        # --------------------------------------------------------------

        dedup_key = (
            payload[
                "target_host"
            ],
            payload[
                "engine_source"
            ],
            payload[
                "finding_class"
            ],
            payload[
                "finding_key"
            ],
        )

        if dedup_key in seen:
            continue

        seen.add(
            dedup_key
        )

        findings.append(
            payload
        )

    # A malformed source document means this refresh cannot be used as
    # authoritative absence evidence.  We still emit valid findings and a
    # FAILED completion marker for auditability, but the ingestion side must
    # never promote that marker to a successful verification watermark.
    refresh_status = (
        "SUCCESS"
        if malformed_documents == 0
        else "FAILED"
    )

    refresh_completed_at = utc_now()

    refresh_event = build_refresh_complete_event(
        tenant_code=tenant_code,
        service_tier=service_tier,
        agent_id=agent_id,
        refresh_id=refresh_id,
        refresh_started_at=refresh_started_at,
        refresh_completed_at=refresh_completed_at,
        refresh_status=refresh_status,
        expected_findings=len(
            findings
        ),
        indexer_documents=len(
            hits
        ),
        malformed_documents=malformed_documents,
        severity_filter=allowed_severities,
    )

    # ------------------------------------------------------------------
    # Write findings and then the completion control event to the same
    # Wazuh-monitored log.  The completion event is always last.
    # ------------------------------------------------------------------

    log_directory = os.path.dirname(
        DATA_LOG_PATH
    )

    if log_directory:

        os.makedirs(
            log_directory,
            exist_ok=True,
        )

    with open(
        DATA_LOG_PATH,
        "a",
        encoding="utf-8",
    ) as handle:

        for payload in findings:

            handle.write(
                json.dumps(
                    payload,
                    separators=(
                        ",",
                        ":",
                    ),
                    ensure_ascii=False,
                )
                + "\n"
            )

        handle.write(
            json.dumps(
                refresh_event,
                separators=(
                    ",",
                    ":",
                ),
                ensure_ascii=False,
            )
            + "\n"
        )

        handle.flush()

    logger.info(
        "SCAN mode complete. refresh_id=%s status=%s "
        "indexer_documents=%d findings_written=%d malformed=%d output=%s",
        refresh_id,
        refresh_status,
        len(
            hits
        ),
        len(
            findings
        ),
        malformed_documents,
        DATA_LOG_PATH,
    )

    return len(
        findings
    )


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Regis Security Wazuh Vulnerability "
            "Detection scanner orchestrator"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "scan",
        ],
        default=None,
        help=(
            "Operating mode. Wazuh Vulnerability Detection "
            "currently supports scan mode only."
        ),
    )

    parser.add_argument(
        "--tenant-code"
    )

    parser.add_argument(
        "--service-tier"
    )

    parser.add_argument(
        "--agent-id"
    )

    parser.add_argument(
        "--severities",
        help=(
            "Optional comma-separated severity filter, "
            "for example high,critical"
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print a machine-readable summary of the scan execution."
        ),
    )

    return parser


def parse_arguments() -> argparse.Namespace:
    """
    Support the previous positional invocation while providing the new
    explicit --mode scan interface.

    Legacy:

        script.py TENANT TIER AGENT [severities]

    Preferred:

        script.py \
            --mode scan \
            --tenant-code TENANT \
            --service-tier GOLD \
            --agent-id 007
    """

    if (
        len(
            sys.argv
        )
        >= 4
        and not sys.argv[
            1
        ].startswith(
            "-"
        )
    ):

        legacy = argparse.Namespace()

        legacy.mode = "scan"

        legacy.tenant_code = (
            sys.argv[1]
        )

        legacy.service_tier = (
            sys.argv[2]
        )

        legacy.agent_id = (
            sys.argv[3]
        )

        legacy.severities = (
            sys.argv[4]
            if len(
                sys.argv
            )
            >= 5
            else None
        )

        legacy.json = False

        return legacy

    parser = build_parser()

    args = parser.parse_args()

    if not args.mode:

        parser.error(
            "--mode scan is required "
            "when using the new command-line interface."
        )

    return args


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    args = parse_arguments()

    try:

        missing = [
            name
            for name, value
            in (
                (
                    "--tenant-code",
                    args.tenant_code,
                ),
                (
                    "--service-tier",
                    args.service_tier,
                ),
                (
                    "--agent-id",
                    args.agent_id,
                ),
            )
            if not value
        ]

        if missing:

            raise ValueError(
                "SCAN mode requires: "
                + ", ".join(
                    missing
                )
            )

        count = run_scan_mode(
            tenant_code=args.tenant_code,
            service_tier=args.service_tier,
            agent_id=args.agent_id,
            severities=args.severities,
        )

        if args.json:

            print(
                json.dumps(
                    {
                        "mode":
                            "scan",

                        "scanner":
                            "wazuh_vulnerability",

                        "findings_written":
                            count,

                        "output":
                            DATA_LOG_PATH,

                        "targeted_verification_supported":
                            False,
                    },
                    separators=(
                        ",",
                        ":",
                    ),
                )
            )

        else:

            print(
                "Wazuh vulnerability scan complete. "
                f"Payloads written: {count}."
            )

        return 0

    except Exception as exc:

        logger.exception(
            "Wazuh vulnerability orchestrator failed: %s",
            exc,
        )

        return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
