#!/usr/bin/env python3
"""
Automated Cybersecurity Remediation Platform
Nuclei Security Scan Orchestrator

PURPOSE
=======

This orchestrator operates in two modes.

1. SCAN MODE
   - Executes Nuclei locally.
   - Supports normal tag/severity-based scanning.
   - Supports scanning one specific Nuclei template.
   - Determines the canonical finding_class.
   - Normalises findings to UnifiedSecurityFinding.
   - Writes findings to /var/log/scanners_raw.log for Wazuh collection.

2. VERIFY MODE
   - Called by verification_gateway.py after remediation.
   - Re-runs the exact Nuclei template that originally produced the finding.
   - Prefers engine_metadata.template_path when the exact local template path is available.
   - Falls back to template_id selection for installed Nuclei templates.
   - Prefers engine_metadata.verification_target, then matched_at, then target_host.
   - Does NOT write a new OPEN finding.
   - Prints exactly one JSON object to stdout.
   - Returns present=true if the original security condition is still detected.
   - Returns present=false only when the targeted Nuclei check no longer matches.

CANONICAL NUCLEI FINDING CLASSES
================================

The following existing finding classes are used by this orchestrator:

    web_application_vulnerability
    web_misconfiguration
    exposed_sensitive_information
    exposed_service
    security_header_missing
    tls_configuration
    injection_vulnerability
    xss_vulnerability
    ssrf_vulnerability
    path_traversal
    file_exposure
    misconfigured_cloud_service

No additional finding classes are introduced.

ENGINE SOURCE
=============

    nuclei

SCAN EXAMPLES
=============

Normal scan:

    python3 nuclei_orchestrator.py \
        --mode scan \
        --tenant-code Customer5 \
        --service-tier GOLD \
        --task-name "Nuclei Web Scan" \
        --target-host https://example.test \
        --severities critical,high,medium \
        --tags cve,exposed,tech

Run without tag filtering:

    python3 nuclei_orchestrator.py \
        --mode scan \
        --tenant-code Customer5 \
        --service-tier GOLD \
        --task-name "Nuclei Full Scan" \
        --target-host https://example.test \
        --severities critical,high \
        --tags no-filters

Specific-template scan:

    python3 nuclei_orchestrator.py \
        --mode scan \
        --tenant-code Customer5 \
        --service-tier GOLD \
        --task-name "Specific Nuclei Check" \
        --target-host https://example.test \
        --scan-mode specific \
        --template-id CVE-2021-44228

VERIFY EXAMPLE
==============

    python3 nuclei_orchestrator.py \
        --mode verify \
        --target-host https://example.test \
        --finding-key '...' \
        --finding-class web_application_vulnerability \
        --engine-metadata-json \
        '{"template_id":"CVE-2021-44228","template_path":"/root/.local/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml","verification_target":"https://example.test","matched_at":"https://example.test/"}' \
        --json

LEGACY COMPATIBILITY
====================

The previous positional scan invocation remains supported:

    nuclei_orchestrator.py \
        TENANT \
        SERVICE_TIER \
        TASK_NAME \
        TARGET_HOST \
        SEVERITIES \
        [TAGS] \
        [--verbose]
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import sys

from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from common.finding import build_unified_finding
from common.runtime import normalize_service_tier, utc_now
from common.validation import REQUIRED_UNIFIED_FINDING_FIELDS

# ============================================================================
# CONFIGURATION
# ============================================================================

NUCLEI_BINARY = os.getenv(
    "NUCLEI_BINARY",
    "nuclei",
)

LOCAL_LOG_PATH = os.getenv(
    "NUCLEI_RAW_LOG",
    "/var/log/scanners_raw.log",
)

LOG_DIR = os.getenv(
    "LOG_DIR",
    "/var/log/automated-remediation",
)

ERROR_LOG_PATH = os.path.join(
    LOG_DIR,
    "nuclei_orchestrator.error.log",
)

NUCLEI_TIMEOUT = int(
    os.getenv(
        "NUCLEI_TIMEOUT",
        "1800",
    )
)

DEFAULT_TAGS = os.getenv(
    "NUCLEI_DEFAULT_TAGS",
    "cve,exposed,tech",
)

DEFAULT_SEVERITIES = os.getenv(
    "NUCLEI_DEFAULT_SEVERITIES",
    "critical,high,medium,low",
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_NUCLEI_CLASSES = {
    "web_application_vulnerability",
    "web_misconfiguration",
    "exposed_sensitive_information",
    "exposed_service",
    "security_header_missing",
    "tls_configuration",
    "injection_vulnerability",
    "xss_vulnerability",
    "ssrf_vulnerability",
    "path_traversal",
    "file_exposure",
    "misconfigured_cloud_service",
}

VALID_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
}

NO_FILTER_VALUES = {
    "no-filters",
    "nofilters",
    "no-tags",
    "notags",
    "none",
    "all",
}

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(
    verbose: bool = False,
) -> logging.Logger:
    """
    Log operational messages to stderr.

    Verification mode reserves stdout exclusively for its machine-readable
    JSON result because verification_dispatcher.py parses stdout.
    """

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "nuclei_orchestrator"
    )

    logger.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    error_handler = RotatingFileHandler(
        ERROR_LOG_PATH,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )

    error_handler.setLevel(
        logging.WARNING
    )

    error_handler.setFormatter(
        formatter
    )

    stream_handler = logging.StreamHandler(
        sys.stderr
    )

    stream_handler.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    stream_handler.setFormatter(
        formatter
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


# ============================================================================
# GENERAL HELPERS
# ============================================================================

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


def clean_string(
    value: Any,
) -> str:

    if value is None:
        return ""

    return (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def normalise_list(
    value: Any,
) -> List[str]:
    """
    Convert Nuclei metadata that may be a string, list, tuple or scalar
    into a clean list of strings.
    """

    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):

        # Some fields may contain comma-separated strings.
        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):

        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return [
        str(value).strip()
    ]


def compact_json(
    value: Any,
) -> str:

    return json.dumps(
        value,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def parse_json_object(
    raw: Optional[str],
) -> Dict[str, Any]:

    if not raw:
        return {}

    value = json.loads(
        raw
    )

    if not isinstance(
        value,
        dict,
    ):

        raise ValueError(
            "--engine-metadata-json must contain a JSON object"
        )

    return value


def extract_cves_from_text(
    text: Any,
) -> List[str]:

    return sorted(
        {
            item.upper()
            for item in CVE_PATTERN.findall(
                str(text or "")
            )
        }
    )


# ============================================================================
# NUCLEI RESULT ACCESSORS
# ============================================================================

def get_template_id(
    finding: Dict[str, Any],
) -> str:
    """
    Support common Nuclei JSONL key variants.
    """

    value = first_non_empty(
        finding.get("template-id"),
        finding.get("template_id"),
        finding.get("templateID"),
    )

    if value is None:

        return "unknown-template"

    return clean_string(
        value
    )


def get_info(
    finding: Dict[str, Any],
) -> Dict[str, Any]:

    info = finding.get(
        "info",
        {},
    )

    if isinstance(
        info,
        dict,
    ):

        return info

    return {}


def get_classification(
    info: Dict[str, Any],
) -> Dict[str, Any]:

    classification = info.get(
        "classification",
        {},
    )

    if isinstance(
        classification,
        dict,
    ):

        return classification

    return {}


def get_matched_at(
    finding: Dict[str, Any],
    fallback_target: str,
) -> str:

    value = first_non_empty(
        finding.get("matched-at"),
        finding.get("matched_at"),
        finding.get("matched"),
        finding.get("url"),
        finding.get("host"),
        fallback_target,
    )

    return clean_string(
        value
    )


def get_matcher_name(
    finding: Dict[str, Any],
) -> Optional[str]:

    value = first_non_empty(
        finding.get("matcher-name"),
        finding.get("matcher_name"),
        finding.get("matcher"),
    )

    if value is None:
        return None

    return clean_string(
        value
    ) or None


def get_extracted_results(
    finding: Dict[str, Any],
) -> List[str]:

    value = first_non_empty(
        finding.get("extracted-results"),
        finding.get("extracted_results"),
    )

    return normalise_list(
        value
    )


def get_cves(
    finding: Dict[str, Any],
) -> List[str]:
    """
    Extract CVE references from Nuclei classification, tags, template ID,
    name and description.
    """

    info = get_info(
        finding
    )

    classification = get_classification(
        info
    )

    values: Set[str] = set()

    for field in (
        "cve-id",
        "cve_id",
        "cve",
    ):

        for item in normalise_list(
            classification.get(
                field
            )
        ):

            values.update(
                extract_cves_from_text(
                    item
                )
            )

    for candidate in (
        get_template_id(
            finding
        ),
        info.get("name"),
        info.get("description"),
        info.get("tags"),
    ):

        values.update(
            extract_cves_from_text(
                candidate
            )
        )

    return sorted(
        values
    )


# ============================================================================
# SEVERITY
# ============================================================================

def normalize_severity_level(
    raw: Any,
) -> str:

    value = str(
        raw or "medium"
    ).strip().lower()

    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "LOW",
        "informational": "LOW",
        "unknown": "MEDIUM",
    }

    return mapping.get(
        value,
        "MEDIUM",
    )


def clamp_cvss(
    value: Any,
) -> Optional[float]:

    if value is None:
        return None

    try:

        result = float(
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
            result,
        ),
    )


def get_severity_score(
    finding: Dict[str, Any],
) -> float:

    info = get_info(
        finding
    )

    classification = get_classification(
        info
    )

    score = first_non_empty(
        classification.get("cvss-score"),
        classification.get("cvss_score"),
        classification.get("cvss"),
    )

    numeric = clamp_cvss(
        score
    )

    if numeric is not None:
        return numeric

    level = normalize_severity_level(
        info.get(
            "severity"
        )
    )

    fallback = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
    }

    return fallback[
        level
    ]


# ============================================================================
# FINDING-CLASS CLASSIFICATION
# ============================================================================

def classification_blob(
    finding: Dict[str, Any],
) -> str:

    info = get_info(
        finding
    )

    classification = get_classification(
        info
    )

    values: List[str] = [
        get_template_id(
            finding
        ),
        str(
            info.get(
                "name",
                "",
            )
        ),
        str(
            info.get(
                "description",
                "",
            )
        ),
        " ".join(
            normalise_list(
                info.get(
                    "tags"
                )
            )
        ),
        str(
            get_matcher_name(
                finding
            )
            or ""
        ),
        compact_json(
            classification
        ),
    ]

    return " ".join(
        values
    ).lower()


def contains_any(
    text: str,
    markers: Iterable[str],
) -> bool:

    return any(
        marker in text
        for marker in markers
    )


def determine_finding_class(
    finding: Dict[str, Any],
) -> str:
    """
    Deterministically map Nuclei output to the canonical catalogue.

    Specific classes are evaluated before generic classes.
    """

    text = classification_blob(
        finding
    )

    tags = {
        tag.lower()
        for tag in normalise_list(
            get_info(
                finding
            ).get(
                "tags"
            )
        )
    }

    template_id = get_template_id(
        finding
    ).lower()

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------

    if (
        "xss" in tags
        or "xss" in template_id
        or contains_any(
            text,
            (
                "cross-site scripting",
                "cross site scripting",
                "reflected xss",
                "stored xss",
                "dom xss",
            ),
        )
    ):

        return "xss_vulnerability"

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------

    if (
        "ssrf" in tags
        or "ssrf" in template_id
        or contains_any(
            text,
            (
                "server-side request forgery",
                "server side request forgery",
            ),
        )
    ):

        return "ssrf_vulnerability"

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    injection_markers = (
        "sql injection",
        "sqli",
        "command injection",
        "code injection",
        "template injection",
        "ssti",
        "ldap injection",
        "xpath injection",
        "nosql injection",
        "xml injection",
    )

    injection_tags = {
        "sqli",
        "injection",
        "ssti",
    }

    if (
        tags.intersection(
            injection_tags
        )
        or contains_any(
            text,
            injection_markers,
        )
    ):

        return "injection_vulnerability"

    # ------------------------------------------------------------------
    # Path traversal
    # ------------------------------------------------------------------

    if (
        tags.intersection(
            {
                "lfi",
                "traversal",
            }
        )
        or contains_any(
            text,
            (
                "path traversal",
                "directory traversal",
                "local file inclusion",
                "lfi vulnerability",
            ),
        )
    ):

        return "path_traversal"

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    if contains_any(
        text,
        (
            "missing security header",
            "security header missing",
            "missing header",
            "content-security-policy missing",
            "strict-transport-security missing",
            "x-frame-options missing",
            "x-content-type-options missing",
        ),
    ):

        return "security_header_missing"

    # ------------------------------------------------------------------
    # TLS / SSL configuration
    # ------------------------------------------------------------------

    if (
        tags.intersection(
            {
                "ssl",
                "tls",
            }
        )
        and contains_any(
            text,
            (
                "tls",
                "ssl",
                "cipher",
                "certificate",
                "protocol",
            ),
        )
    ):

        return "tls_configuration"

    if contains_any(
        text,
        (
            "weak tls",
            "weak ssl",
            "deprecated tls",
            "deprecated ssl",
            "tls configuration",
            "ssl configuration",
            "insecure cipher",
        ),
    ):

        return "tls_configuration"

    # ------------------------------------------------------------------
    # Cloud misconfiguration
    # ------------------------------------------------------------------

    cloud_markers = (
        "aws",
        "amazon s3",
        "azure",
        "gcp",
        "google cloud",
        "cloudfront",
        "cloud storage",
        "s3 bucket",
        "blob storage",
    )

    if (
        contains_any(
            text,
            cloud_markers,
        )
        and contains_any(
            text,
            (
                "misconfiguration",
                "public access",
                "publicly accessible",
                "exposed",
                "anonymous access",
            ),
        )
    ):

        return "misconfigured_cloud_service"

    # ------------------------------------------------------------------
    # Sensitive information exposure
    # ------------------------------------------------------------------

    if contains_any(
        text,
        (
            "sensitive information",
            "information disclosure",
            "credentials exposed",
            "credential exposure",
            "password exposure",
            "password disclosed",
            "api key",
            "access token",
            "secret key",
            "private key exposed",
            "environment variables exposed",
        ),
    ):

        return "exposed_sensitive_information"

    if tags.intersection(
        {
            "token",
            "secrets",
            "secret",
            "exposure",
        }
    ) and contains_any(
        text,
        (
            "credential",
            "password",
            "token",
            "secret",
            "sensitive",
        ),
    ):

        return "exposed_sensitive_information"

    # ------------------------------------------------------------------
    # File exposure
    # ------------------------------------------------------------------

    if contains_any(
        text,
        (
            ".git/config",
            ".git exposure",
            ".env exposure",
            "environment file exposed",
            "backup file exposed",
            "configuration file exposed",
            "database dump exposed",
            "source code exposed",
            "sensitive file exposed",
        ),
    ):

        return "file_exposure"

    if (
        "exposure" in tags
        and contains_any(
            text,
            (
                "file",
                ".git",
                ".env",
                "backup",
                "config",
                "dump",
            ),
        )
    ):

        return "file_exposure"

    # ------------------------------------------------------------------
    # Exposed service/panel
    # ------------------------------------------------------------------

    if contains_any(
        text,
        (
            "panel exposed",
            "dashboard exposed",
            "admin panel",
            "administrative interface",
            "management interface exposed",
            "debug interface exposed",
            "service exposed",
            "unauthenticated interface",
        ),
    ):

        return "exposed_service"

    # ------------------------------------------------------------------
    # General web misconfiguration
    # ------------------------------------------------------------------

    if (
        "misconfig" in tags
        or "misconfiguration" in text
        or contains_any(
            text,
            (
                "directory listing",
                "http trace enabled",
                "unsafe http method",
                "cors misconfiguration",
                "host header misconfiguration",
            ),
        )
    ):

        return "web_misconfiguration"

    # ------------------------------------------------------------------
    # Everything else from the web-focused Nuclei scanner belongs to the
    # general web application vulnerability class.
    # ------------------------------------------------------------------

    return "web_application_vulnerability"


# ============================================================================
# FINDING IDENTITY
# ============================================================================

def normalise_matched_at_for_identity(
    matched_at: str,
) -> str:
    """
    Normalise enough of matched-at to make the key deterministic while
    retaining the actual matched-at value separately in engine_metadata.
    """

    return (
        matched_at
        .strip()
        .rstrip("/")
        .lower()
    )


def matched_at_fingerprint(
    matched_at: str,
) -> str:

    normalised = normalise_matched_at_for_identity(
        matched_at
    )

    return hashlib.sha256(
        normalised.encode(
            "utf-8"
        )
    ).hexdigest()[:16]


def build_finding_key(
    finding: Dict[str, Any],
    target_host: str,
) -> str:
    """
    Produce a stable identity that distinguishes the same template matching
    multiple locations on one host.

    If the template has a CVE, the CVE remains visible at the beginning of
    the finding key for specific remediation-rule matching.
    """

    template_id = get_template_id(
        finding
    )

    matched_at = get_matched_at(
        finding,
        target_host,
    )

    fingerprint = matched_at_fingerprint(
        matched_at
    )

    cves = get_cves(
        finding
    )

    if cves:

        return (
            f"{cves[0]}|NUCLEI:"
            f"{template_id}:"
            f"{fingerprint}"
        )

    return (
        f"NUCLEI:"
        f"{template_id}:"
        f"{fingerprint}"
    )


# ============================================================================
# PORT EXTRACTION
# ============================================================================

def determine_port(
    matched_at: str,
) -> Tuple[
    Optional[int],
    Optional[str],
]:
    """
    Extract useful port/protocol context from the matched URL.

    Do not assume port 80 when parsing fails.
    """

    try:

        parsed = urlparse(
            matched_at
        )

        scheme = (
            parsed.scheme.lower()
            if parsed.scheme
            else None
        )

        if parsed.port:

            return (
                parsed.port,
                "tcp",
            )

        if scheme == "https":

            return (
                443,
                "tcp",
            )

        if scheme == "http":

            return (
                80,
                "tcp",
            )

    except Exception:

        pass

    return (
        None,
        None,
    )


def derive_verification_target(
    matched_at: str,
    target_host: str,
    result_host: Optional[str] = None,
) -> str:
    """
    Derive the narrowest stable Nuclei rescan target that does not duplicate
    template paths.

    Precedence:
    1. A scanner-provided result host when present.
    2. For HTTP(S) matched URLs, scheme://authority (BaseURL).
    3. The original matched_at value for non-HTTP targets.
    4. The canonical target_host.

    The explicit engine_metadata.verification_target stored by scan mode can be
    overridden later by a caller when a scanner/template requires something
    more specific.
    """

    result_host_value = clean_string(
        result_host
    )

    if result_host_value:
        parsed_host = urlparse(
            result_host_value
        )

        if (
            parsed_host.scheme.lower()
            in {"http", "https"}
            and parsed_host.netloc
        ):
            return (
                f"{parsed_host.scheme.lower()}://"
                f"{parsed_host.netloc}"
            )

        return result_host_value

    matched_value = clean_string(
        matched_at
    )

    if matched_value:
        parsed = urlparse(
            matched_value
        )

        if (
            parsed.scheme.lower()
            in {"http", "https"}
            and parsed.netloc
        ):
            return (
                f"{parsed.scheme.lower()}://"
                f"{parsed.netloc}"
            )

        return matched_value

    return clean_string(
        target_host
    )


# ============================================================================
# SCHEMA VALIDATION
# ============================================================================

def validate_unified_finding(
    payload: Dict[str, Any],
) -> None:

    for field in REQUIRED_UNIFIED_FINDING_FIELDS:

        if payload.get(
            field
        ) in (
            None,
            "",
        ):

            raise ValueError(
                f"Unified finding is missing {field}"
            )

    if payload[
        "finding_class"
    ] not in VALID_NUCLEI_CLASSES:

        raise ValueError(
            "Invalid Nuclei finding_class: "
            f"{payload['finding_class']}"
        )

    score = payload.get(
        "severity_score"
    )

    if score is not None:

        score = float(
            score
        )

        if not 0 <= score <= 10:

            raise ValueError(
                "severity_score must be between 0 and 10"
            )


# ============================================================================
# NORMALISATION
# ============================================================================

def normalize_finding(
    finding: Dict[str, Any],
    tenant_code: str,
    service_tier: str,
    task_name: str,
    target_host: str,
    scan_mode: str,
) -> Dict[str, Any]:

    info = get_info(
        finding
    )

    classification = get_classification(
        info
    )

    template_id = get_template_id(
        finding
    )

    matched_at = get_matched_at(
        finding,
        target_host,
    )

    matcher_name = get_matcher_name(
        finding
    )

    tags = normalise_list(
        info.get(
            "tags"
        )
    )

    cves = get_cves(
        finding
    )

    finding_class = determine_finding_class(
        finding
    )

    finding_key = build_finding_key(
        finding,
        target_host,
    )

    severity_level = normalize_severity_level(
        info.get(
            "severity"
        )
    )

    severity_score = get_severity_score(
        finding
    )

    port, protocol = determine_port(
        matched_at
    )

    verification_target = derive_verification_target(
        matched_at=matched_at,
        target_host=target_host,
        result_host=finding.get(
            "host"
        ),
    )

    title = clean_string(
        first_non_empty(
            info.get("name"),
            template_id,
            "Unknown Nuclei Finding",
        )
    )

    description = clean_string(
        first_non_empty(
            info.get("description"),
            "No description provided.",
        )
    )

    metadata: Dict[str, Any] = {
        "task_name":
            task_name,

        "scan_mode":
            scan_mode,

        # Critical for Stage 2 verification.
        "template_id":
            template_id,

        "matched_at":
            matched_at,

        # Preferred Stage 2 rescan target. For HTTP(S) findings this is
        # normally the BaseURL rather than the full matched path.
        "verification_target":
            verification_target,

        "matcher_name":
            matcher_name,

        "port":
            port,

        "protocol":
            protocol,

        "scanned_port":
            (
                f"{port}/{protocol}"
                if port and protocol
                else None
            ),

        "tags":
            tags,

        "cves":
            cves,

        "description":
            description[:4000],

        "extracted_results":
            get_extracted_results(
                finding
            ),

        "classification":
            classification,

        "template_path":
            first_non_empty(
                finding.get(
                    "template-path"
                ),
                finding.get(
                    "template_path"
                ),
            ),

        "type":
            finding.get(
                "type"
            ),

        "host":
            finding.get(
                "host"
            ),

        "ip":
            finding.get(
                "ip"
            ),

        "timestamp":
            finding.get(
                "timestamp"
            ),
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value not in (
            None,
            "",
            [],
            {},
        )
    }

    payload = build_unified_finding(
        tenant_code=tenant_code,
        tenant_service_tier=service_tier,
        target_host=target_host,
        engine_source="nuclei",
        finding_category="vulnerability",
        finding_class=finding_class,
        finding_key=finding_key,
        finding_title=title,
        detected_at=utc_now(),
        compliance_result=None,
        severity_level=severity_level,
        severity_score=severity_score,
        engine_metadata=metadata,
    )

    validate_unified_finding(
        payload
    )

    return payload


# ============================================================================
# CLI VALIDATION
# ============================================================================

def validate_template_id(
    template_id: str,
) -> str:
    """
    Nuclei template IDs are identifiers, not arbitrary command strings.

    Permit typical ProjectDiscovery template IDs while preventing command-line
    control characters from being passed through.
    """

    value = clean_string(
        template_id
    )

    if not value:

        raise ValueError(
            "template_id cannot be empty"
        )

    if not re.fullmatch(
        r"[A-Za-z0-9_.:+\-*]+",
        value,
    ):

        raise ValueError(
            f"Invalid Nuclei template ID: {value}"
        )

    return value


def normalize_severity_filter(
    value: Optional[str],
) -> str:

    if not value:

        return DEFAULT_SEVERITIES

    requested = [
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    ]

    invalid = [
        item
        for item in requested
        if item not in VALID_SEVERITIES
    ]

    if invalid:

        raise ValueError(
            "Invalid Nuclei severities: "
            + ", ".join(
                invalid
            )
        )

    return ",".join(
        requested
    )


# ============================================================================
# NUCLEI COMMAND CONSTRUCTION
# ============================================================================

def build_scan_command(
    target_host: str,
    severities: Optional[str],
    tags: Optional[str],
    scan_mode: str,
    template_id: Optional[str],
) -> List[str]:

    command = [
        NUCLEI_BINARY,
        "-target",
        target_host,
        "-jsonl",
        "-silent",
    ]

    if scan_mode == "specific":

        if not template_id:

            raise ValueError(
                "--scan-mode specific requires --template-id"
            )

        command.extend(
            [
                "-id",
                validate_template_id(
                    template_id
                ),
            ]
        )

        # Do not apply tag filters in specific-template mode.
        #
        # The caller has explicitly selected the template.

    elif scan_mode == "default":

        severity_filter = normalize_severity_filter(
            severities
        )

        command.extend(
            [
                "-severity",
                severity_filter,
            ]
        )

        tags_value = (
            tags
            if tags is not None
            else DEFAULT_TAGS
        )

        if (
            tags_value
            and tags_value.lower()
            not in NO_FILTER_VALUES
        ):

            command.extend(
                [
                    "-tags",
                    tags_value,
                ]
            )

    else:

        raise ValueError(
            f"Unsupported scan mode: {scan_mode}"
        )

    return command


def build_verify_command(
    verification_target: str,
    template_id: str,
    template_path: Optional[str] = None,
) -> List[str]:
    """
    Build a targeted Nuclei Stage 2 verification command.

    Selection precedence:
    1. If a concrete template_path is supplied, execute that exact template
       with -t. This supports local/custom templates and makes verification
       deterministic when scan mode recorded the original path.
    2. Otherwise select the installed template by template_id with -id.

    No shell is used; every argument is passed as a distinct list element.
    """

    target = clean_string(
        verification_target
    )

    if not target:
        raise ValueError(
            "verification_target cannot be empty"
        )

    if len(target) > 2048:
        raise ValueError(
            "Nuclei verification_target exceeds maximum length of 2048"
        )

    if target.startswith("-"):
        raise ValueError(
            "Nuclei verification_target must not begin with '-'"
        )

    if any(
        char in target
        for char in ("\x00", "\r", "\n")
    ):
        raise ValueError(
            "Nuclei verification_target contains prohibited "
            "control characters"
        )

    command = [
        NUCLEI_BINARY,
        "-target",
        target,
    ]

    path_value = clean_string(
        template_path
    )

    if path_value:
        resolved_path = os.path.abspath(
            path_value
        )

        if not os.path.isfile(
            resolved_path
        ):
            raise RuntimeError(
                "Nuclei verification template_path does not exist: "
                f"{resolved_path}"
            )

        command.extend(
            [
                "-t",
                resolved_path,
            ]
        )

    else:
        command.extend(
            [
                "-id",
                validate_template_id(
                    template_id
                ),
            ]
        )

    command.extend(
        [
            "-jsonl",
            "-silent",
        ]
    )

    return command


# ============================================================================
# PROCESS EXECUTION
# ============================================================================

def execute_nuclei(
    command: List[str],
) -> Tuple[
    int,
    List[Dict[str, Any]],
    str,
]:
    """
    Execute Nuclei and parse JSONL results.

    A successfully completed scan with zero JSON lines is not an error.
    It simply means no template matched.
    """

    logger.debug(
        "Executing Nuclei command: %s",
        command,
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    results: List[
        Dict[str, Any]
    ] = []

    stderr_text = ""

    try:

        stdout_text, stderr_text = process.communicate(
            timeout=NUCLEI_TIMEOUT
        )

    except subprocess.TimeoutExpired:

        process.kill()

        stdout_text, stderr_text = process.communicate()

        raise RuntimeError(
            f"Nuclei execution exceeded {NUCLEI_TIMEOUT} seconds"
        )

    for line in stdout_text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:

            value = json.loads(
                line
            )

        except json.JSONDecodeError as exc:

            logger.warning(
                "Ignoring malformed Nuclei JSONL output: %s",
                exc,
            )

            continue

        if isinstance(
            value,
            dict,
        ):

            results.append(
                value
            )

    return (
        process.returncode,
        results,
        stderr_text,
    )


# ============================================================================
# SCAN MODE
# ============================================================================

def run_scan_mode(
    tenant_code: str,
    service_tier: str,
    task_name: str,
    target_host: str,
    severities: Optional[str],
    tags: Optional[str],
    scan_mode: str,
    template_id: Optional[str],
) -> int:

    tenant_code = clean_string(
        tenant_code
    )

    if not tenant_code:

        raise ValueError(
            "tenant_code cannot be empty"
        )

    service_tier = normalize_service_tier(
        service_tier,
        logger,
    )

    task_name = clean_string(
        task_name
    )

    target_host = clean_string(
        target_host
    )

    if not target_host:

        raise ValueError(
            "target_host cannot be empty"
        )

    logger.info(
        "SCAN mode: target=%s mode=%s template=%s severities=%s tags=%s",
        target_host,
        scan_mode,
        template_id or "FILTERED-TEMPLATES",
        severities or DEFAULT_SEVERITIES,
        tags if tags is not None else DEFAULT_TAGS,
    )

    command = build_scan_command(
        target_host=target_host,
        severities=severities,
        tags=tags,
        scan_mode=scan_mode,
        template_id=template_id,
    )

    return_code, results, stderr_text = execute_nuclei(
        command
    )

    if return_code != 0:

        raise RuntimeError(
            f"Nuclei exited with return code {return_code}: "
            f"{stderr_text[:2000]}"
        )

    findings: List[
        Dict[str, Any]
    ] = []

    seen: Set[
        Tuple[str, str, str]
    ] = set()

    for raw_finding in results:

        try:

            payload = normalize_finding(
                finding=raw_finding,
                tenant_code=tenant_code,
                service_tier=service_tier,
                task_name=task_name,
                target_host=target_host,
                scan_mode=scan_mode,
            )

        except Exception as exc:

            logger.warning(
                "Unable to normalise Nuclei result: %s",
                exc,
            )

            continue

        dedup_key = (
            payload[
                "target_host"
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

    os.makedirs(
        os.path.dirname(
            LOCAL_LOG_PATH
        ),
        exist_ok=True,
    )

    with open(
        LOCAL_LOG_PATH,
        "a",
        encoding="utf-8",
    ) as handle:

        for payload in findings:

            handle.write(
                compact_json(
                    payload
                )
                + "\n"
            )

    logger.info(
        "SCAN mode complete. Logged %d finding(s) to %s.",
        len(findings),
        LOCAL_LOG_PATH,
    )

    return len(
        findings
    )


# ============================================================================
# VERIFY MODE
# ============================================================================

def result_corresponds_to_original(
    result: Dict[str, Any],
    original_template_id: str,
    original_matcher_name: Optional[str],
) -> bool:
    """
    Determine whether a result represents the original security condition.

    Since verification runs only the original template against the original
    matched target, any positive result from that template is conservatively
    treated as the finding still being present.

    If the original matcher name is available, prefer the same matcher, but
    do not generate a false PASS solely because Nuclei omitted matcher-name
    from a later result.
    """

    current_template = get_template_id(
        result
    )

    if (
        current_template.lower()
        != original_template_id.lower()
    ):

        return False

    if not original_matcher_name:

        return True

    current_matcher = get_matcher_name(
        result
    )

    if not current_matcher:

        # Fail conservatively.
        return True

    return (
        current_matcher.lower()
        == original_matcher_name.lower()
    )


def run_verify_mode(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Stage 2 Nuclei verification.

    Required metadata:
        template_id

    Preferred metadata:
        template_path
        verification_target
        matched_at
        matcher_name

    Template selection precedence:
        exact engine_metadata.template_path
        installed template selected by template_id

    Verification target precedence:
        engine_metadata.verification_target
        original matched_at
        original target_host

    The scanner is run fail-closed: any inability to execute the targeted
    check raises an exception, which main() serialises as present=true plus a
    verification_error so infrastructure failure can never become a false PASS.
    """

    if finding_class not in VALID_NUCLEI_CLASSES:

        raise ValueError(
            f"Unsupported Nuclei finding_class: {finding_class}"
        )

    template_id = clean_string(
        engine_metadata.get(
            "template_id"
        )
    )

    if not template_id:

        raise ValueError(
            "Nuclei Stage 2 verification requires "
            "engine_metadata.template_id"
        )

    template_path = clean_string(
        engine_metadata.get(
            "template_path"
        )
    ) or None

    matcher_name = clean_string(
        engine_metadata.get(
            "matcher_name"
        )
    ) or None

    matched_at = clean_string(
        engine_metadata.get(
            "matched_at"
        )
    )

    explicit_verification_target = clean_string(
        engine_metadata.get(
            "verification_target"
        )
    )

    verification_target = (
        explicit_verification_target
        or matched_at
        or clean_string(
            target_host
        )
    )

    if not verification_target:
        raise ValueError(
            "Nuclei Stage 2 verification could not determine "
            "a verification target"
        )

    logger.info(
        "VERIFY mode: target=%s key=%s class=%s "
        "template_id=%s template_path=%s matcher=%s",
        verification_target,
        finding_key,
        finding_class,
        template_id,
        template_path or "INSTALLED_TEMPLATE",
        matcher_name or "ANY",
    )

    command = build_verify_command(
        verification_target=verification_target,
        template_id=template_id,
        template_path=template_path,
    )

    logger.debug(
        "VERIFY mode Nuclei command: %s",
        command,
    )

    return_code, results, stderr_text = execute_nuclei(
        command
    )

    if return_code != 0:

        raise RuntimeError(
            f"Nuclei verification exited with return code "
            f"{return_code}: {stderr_text[:2000]}"
        )

    matching_results: List[
        Dict[str, Any]
    ] = []

    for result in results:

        if not result_corresponds_to_original(
            result=result,
            original_template_id=template_id,
            original_matcher_name=matcher_name,
        ):

            continue

        matching_results.append(
            {
                "template_id":
                    get_template_id(
                        result
                    ),

                "matched_at":
                    get_matched_at(
                        result,
                        verification_target,
                    ),

                "matcher_name":
                    get_matcher_name(
                        result
                    ),

                "finding_class":
                    determine_finding_class(
                        result
                    ),

                "cves":
                    get_cves(
                        result
                    ),

                "extracted_results":
                    get_extracted_results(
                        result
                    ),
            }
        )

    present = bool(
        matching_results
    )

    logger.info(
        "VERIFY mode complete: key=%s template=%s present=%s matches=%d",
        finding_key,
        template_id,
        present,
        len(
            matching_results
        ),
    )

    return {
        "present":
            present,

        "finding_key":
            finding_key,

        "finding_class":
            finding_class,

        "scanner":
            "nuclei",

        # Return the original canonical target_host, not the scanner rescan
        # target, because verification_dispatcher checks target consistency.
        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence": {
            "template_id":
                template_id,

            "template_path":
                template_path,

            "template_selection":
                (
                    "template_path"
                    if template_path
                    else "template_id"
                ),

            "verification_target":
                verification_target,

            "original_matched_at":
                matched_at or None,

            "original_matcher_name":
                matcher_name,

            "match_count":
                len(
                    matching_results
                ),

            "matches":
                matching_results,
        },
    }


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Nuclei scanner orchestrator"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "scan",
            "verify",
        ],
        required=True,
    )

    # ------------------------------------------------------------------
    # Common
    # ------------------------------------------------------------------

    parser.add_argument(
        "--target-host",
        required=True,
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Machine-readable output. Required by verification gateway."
        ),
    )

    # ------------------------------------------------------------------
    # Scan mode
    # ------------------------------------------------------------------

    parser.add_argument(
        "--tenant-code"
    )

    parser.add_argument(
        "--service-tier"
    )

    parser.add_argument(
        "--task-name"
    )

    parser.add_argument(
        "--severities",
        default=DEFAULT_SEVERITIES,
    )

    parser.add_argument(
        "--tags",
        default=DEFAULT_TAGS,
    )

    parser.add_argument(
        "--scan-mode",
        choices=[
            "default",
            "specific",
        ],
        default="default",
    )

    parser.add_argument(
        "--template-id",
        help=(
            "Run one specific Nuclei template using Nuclei's "
            "-id / -template-id filter."
        ),
    )

    # ------------------------------------------------------------------
    # Verify mode
    # ------------------------------------------------------------------

    parser.add_argument(
        "--finding-key"
    )

    parser.add_argument(
        "--finding-class"
    )

    parser.add_argument(
        "--engine-metadata-json"
    )

    return parser


# ============================================================================
# LEGACY POSITIONAL ARGUMENT SUPPORT
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Preserve the original invocation:

        script TENANT TIER TASK TARGET SEVERITIES [TAGS] [--verbose]

    New deployments should use the explicit --mode interface.
    """

    if (
        len(
            sys.argv
        )
        >= 6
        and not sys.argv[1].startswith("-")
    ):

        args = argparse.Namespace()

        args.mode = "scan"

        args.tenant_code = (
            sys.argv[1]
        )

        args.service_tier = (
            sys.argv[2]
        )

        args.task_name = (
            sys.argv[3]
        )

        args.target_host = (
            sys.argv[4]
        )

        args.severities = (
            sys.argv[5]
        )

        args.tags = DEFAULT_TAGS

        args.scan_mode = "default"

        args.template_id = None

        args.finding_key = None
        args.finding_class = None
        args.engine_metadata_json = None
        args.json = False

        args.verbose = False

        if len(
            sys.argv
        ) >= 7:

            arg6 = (
                sys.argv[6]
                .strip()
            )

            if arg6.lower() in (
                "--verbose",
                "verbose",
                "-v",
            ):

                args.verbose = True

            else:

                args.tags = arg6

        if len(
            sys.argv
        ) >= 8:

            if (
                sys.argv[7]
                .strip()
                .lower()
                in (
                    "--verbose",
                    "verbose",
                    "-v",
                )
            ):

                args.verbose = True

        return args

    return build_parser().parse_args()


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    global logger

    args = parse_arguments()

    logger = setup_logging(
        args.verbose
    )

    try:

        # ==============================================================
        # SCAN
        # ==============================================================

        if args.mode == "scan":

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
                        "--task-name",
                        args.task_name,
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

            if (
                args.scan_mode
                == "specific"
                and not args.template_id
            ):

                raise ValueError(
                    "--scan-mode specific requires --template-id"
                )

            count = run_scan_mode(
                tenant_code=args.tenant_code,
                service_tier=args.service_tier,
                task_name=args.task_name,
                target_host=args.target_host,
                severities=args.severities,
                tags=args.tags,
                scan_mode=args.scan_mode,
                template_id=args.template_id,
            )

            if args.json:

                print(
                    compact_json(
                        {
                            "mode":
                                "scan",

                            "scanner":
                                "nuclei",

                            "findings_written":
                                count,

                            "output":
                                LOCAL_LOG_PATH,
                        }
                    )
                )

            else:

                print(
                    "[SUCCESS] Nuclei scan finished. "
                    f"Logged {count} finding(s) "
                    f"to {LOCAL_LOG_PATH}"
                )

            return 0

        # ==============================================================
        # VERIFY
        # ==============================================================

        if not args.finding_key:

            raise ValueError(
                "VERIFY mode requires --finding-key"
            )

        if not args.finding_class:

            raise ValueError(
                "VERIFY mode requires --finding-class"
            )

        metadata = parse_json_object(
            args.engine_metadata_json
        )

        result = run_verify_mode(
            target_host=args.target_host,
            finding_key=args.finding_key,
            finding_class=args.finding_class,
            engine_metadata=metadata,
        )

        # verification_dispatcher.py expects exactly one JSON object.
        print(
            compact_json(
                result
            )
        )

        return 0

    except Exception as exc:

        logger.exception(
            "Nuclei orchestrator failed: %s",
            exc,
        )

        if args.mode == "verify":

            # Fail closed.
            #
            # An inability to run the scanner must never be interpreted as
            # proof that a vulnerability disappeared.
            print(
                compact_json(
                    {
                        "present":
                            True,

                        "finding_key":
                            getattr(
                                args,
                                "finding_key",
                                None,
                            ),

                        "finding_class":
                            getattr(
                                args,
                                "finding_class",
                                None,
                            ),

                        "scanner":
                            "nuclei",

                        "target_host":
                            getattr(
                                args,
                                "target_host",
                                None,
                            ),

                        "verified_at":
                            utc_now(),

                        "verification_error":
                            str(
                                exc
                            ),

                        "evidence":
                            {},
                    }
                )
            )

        return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
