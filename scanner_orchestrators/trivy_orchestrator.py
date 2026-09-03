#!/usr/bin/env python3
"""
Regis Security Consulting
Trivy Scanner Orchestrator

ARCHITECTURE
============

This orchestrator participates in two separate stages of the Regis
security-assurance platform.

1. SCAN MODE

   - Executes Trivy.
   - Supports Trivy scanners:

         vuln
         misconfig
         secret
         license

   - Supports target types:

         image
         folder

   - Deterministically determines finding_class.
   - Normalises findings into UnifiedSecurityFinding.
   - Writes findings line-by-line to:

         /var/log/scanners_raw.log

   - The Wazuh Agent subsequently transports those findings through:

         Wazuh
           -> Redis
           -> Ollama enrichment
           -> PostgreSQL

   Ollama does NOT determine finding_class.

2. VERIFY MODE

   - Called by verification_gateway.py.
   - verification_dispatcher.py launches this script.
   - Receives the original finding's engine_metadata.
   - Re-runs only the relevant Trivy scanner.
   - Reuses the original scan_type and scan_target.
   - Searches specifically for the original finding.
   - Does NOT write anything to scanners_raw.log.
   - Prints exactly one JSON object to stdout.

CANONICAL VERIFICATION INTERFACE
================================

verification_dispatcher.py calls:

    trivy_orchestrator.py \
        --mode verify \
        --target-host <original target> \
        --finding-key <finding key> \
        --finding-class <finding class> \
        --engine-metadata-json '<original engine_metadata>' \
        --json

Example:

    trivy_orchestrator.py \
        --mode verify \
        --target-host nginx:1.25 \
        --finding-key CVE-2024-1234:libssl3 \
        --finding-class container_image_vulnerability \
        --engine-metadata-json \
        '{"scanner":"vuln","scan_type":"image","scan_target":"nginx:1.25","package_name":"libssl3","cve_id":"CVE-2024-1234"}' \
        --json

The verification result is:

    {
        "present": false,
        "finding_key": "...",
        "finding_class": "...",
        "scanner": "trivy",
        "target_host": "...",
        "verified_at": "...",
        "evidence": {}
    }

Meaning:

    present = false
        The original finding is no longer detected.
        Stage 2 PASSES.

    present = true
        The original finding is still detected.
        Stage 2 FAILS.

If Trivy fails, times out, produces malformed data, or verification cannot
be completed reliably, the orchestrator fails CLOSED. It must never
interpret scanner failure as remediation success.

CANONICAL TRIVY FINDING CLASSES
===============================

    container_image_vulnerability
    container_dependency_vulnerability
    container_misconfiguration
    container_secret_exposure
    container_license_issue
    dockerfile_misconfiguration
    iac_misconfiguration

No additional Trivy finding classes are introduced by this file.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import subprocess
import sys

from logging.handlers import RotatingFileHandler
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)

from common.runtime import normalize_service_tier, utc_now
from common.validation import REQUIRED_UNIFIED_FINDING_FIELDS

# ============================================================================
# CONFIGURATION
# ============================================================================

TRIVY_BINARY = os.getenv(
    "REGIS_TRIVY_BINARY",
    "trivy",
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
    "trivy_orchestrator.error.log",
)

TRIVY_TIMEOUT = int(
    os.getenv(
        "REGIS_TRIVY_TIMEOUT",
        "1800",
    )
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_SCANNERS = {
    "vuln",
    "misconfig",
    "secret",
    "license",
}

VALID_SCAN_TYPES = {
    "image",
    "folder",
}

VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
}

VALID_TRIVY_FINDING_CLASSES = {
    "container_image_vulnerability",
    "container_dependency_vulnerability",
    "container_misconfiguration",
    "container_secret_exposure",
    "container_license_issue",
    "dockerfile_misconfiguration",
    "iac_misconfiguration",
}

VALID_FINDING_CATEGORIES = {
    "vulnerability",
    "compliance_drift",
    "integrity_drift",
    "rootkit",
}


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging() -> logging.Logger:
    """
    Operational logging deliberately goes to stderr.

    In VERIFY mode, verification_dispatcher.py expects stdout to contain
    exactly one JSON document.
    """

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "trivy_orchestrator"
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


# ============================================================================
# GENERAL HELPERS
# ============================================================================

def normalize_severity_level(
    raw_severity: Any,
) -> str:
    """
    Normalise Trivy severity into UnifiedSecurityFinding severity_level.
    """

    if raw_severity is None:
        return "MEDIUM"

    severity = str(
        raw_severity
    ).strip().upper()

    aliases = {
        "UNKNOWN": "MEDIUM",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
    }

    severity = aliases.get(
        severity,
        severity,
    )

    if severity in VALID_SEVERITIES:
        return severity

    return "MEDIUM"


def clamp_score(
    raw_value: Any,
) -> Optional[float]:
    """
    Convert a value to CVSS-compatible 0-10 range.
    """

    if raw_value is None:
        return None

    try:

        value = float(
            raw_value
        )

    except (
        ValueError,
        TypeError,
    ):

        return None

    return max(
        0.0,
        min(
            value,
            10.0,
        ),
    )


def severity_score_fallback(
    severity: str,
) -> float:
    """
    Deterministic numeric fallback when Trivy does not provide CVSS.
    """

    mapping = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 3.0,
    }

    return mapping.get(
        severity,
        5.0,
    )


def get_vulnerability_score(
    vulnerability: Dict[str, Any],
    severity: str,
) -> float:
    """
    Extract the best available CVSS score from Trivy.
    """

    cvss_data = vulnerability.get(
        "CVSS",
        {},
    )

    if isinstance(
        cvss_data,
        dict,
    ):

        preferred_vendors = (
            "nvd",
            "redhat",
            "ghsa",
            "ubuntu",
            "debian",
        )

        for vendor in preferred_vendors:

            vendor_data = cvss_data.get(
                vendor
            )

            if not isinstance(
                vendor_data,
                dict,
            ):

                continue

            score = (
                vendor_data.get("V4Score")
                or vendor_data.get("V3Score")
                or vendor_data.get("V2Score")
            )

            score = clamp_score(
                score
            )

            if score is not None:
                return score

        # Search all remaining CVSS providers.
        for vendor_data in cvss_data.values():

            if not isinstance(
                vendor_data,
                dict,
            ):

                continue

            score = (
                vendor_data.get("V4Score")
                or vendor_data.get("V3Score")
                or vendor_data.get("V2Score")
            )

            score = clamp_score(
                score
            )

            if score is not None:
                return score

    return severity_score_fallback(
        severity
    )


def stable_hash(
    value: str,
    length: int = 16,
) -> str:
    """
    Create deterministic IDs for findings without native stable IDs.
    """

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:length]


def clean_string(
    value: Any,
) -> Optional[str]:
    """
    Convert optional value to clean string.
    """

    if value is None:
        return None

    value = str(
        value
    ).strip()

    return value or None


def trim_title(
    value: str,
    maximum: int = 220,
) -> str:
    """
    Keep finding_title reasonably small.
    """

    value = str(
        value
    ).strip()

    if len(value) <= maximum:
        return value

    return (
        value[:maximum - 3]
        + "..."
    )


def parse_json_object(
    raw_value: Optional[str],
    argument_name: str,
) -> Dict[str, Any]:
    """
    Parse command-line JSON object safely.
    """

    if not raw_value:
        return {}

    try:

        value = json.loads(
            raw_value
        )

    except json.JSONDecodeError as exc:

        raise ValueError(
            f"{argument_name} must contain valid JSON: {exc}"
        ) from exc

    if not isinstance(
        value,
        dict,
    ):

        raise ValueError(
            f"{argument_name} must contain a JSON object"
        )

    return value


# ============================================================================
# TRIVY EXECUTION
# ============================================================================

def determine_trivy_subcommand(
    scan_type: str,
) -> str:
    """
    Convert platform scan type into Trivy subcommand.
    """

    if scan_type == "image":
        return "image"

    if scan_type == "folder":
        return "fs"

    raise ValueError(
        f"Unsupported scan_type: {scan_type}"
    )


def build_trivy_command(
    scan_type: str,
    target: str,
    scanners: Iterable[str],
    severity: Optional[str] = None,
    ignore_unfixed: bool = False,
    license_full: bool = False,
) -> List[str]:
    """
    Construct Trivy command without a shell.
    """

    scanner_list = list(
        dict.fromkeys(
            scanners
        )
    )

    invalid = (
        set(scanner_list)
        - VALID_SCANNERS
    )

    if invalid:

        raise ValueError(
            "Unsupported Trivy scanners: "
            + ", ".join(
                sorted(
                    invalid
                )
            )
        )

    if not scanner_list:

        raise ValueError(
            "At least one Trivy scanner must be selected."
        )

    if scan_type not in VALID_SCAN_TYPES:

        raise ValueError(
            f"Unsupported scan_type: {scan_type}"
        )

    if not target:

        raise ValueError(
            "Trivy target cannot be empty"
        )

    command = [
        TRIVY_BINARY,
        determine_trivy_subcommand(
            scan_type
        ),
        "--format",
        "json",
        "--scanners",
        ",".join(
            scanner_list
        ),
    ]

    if severity:

        command.extend(
            [
                "--severity",
                severity,
            ]
        )

    # --ignore-unfixed is relevant only to vulnerabilities.
    if (
        ignore_unfixed
        and "vuln" in scanner_list
    ):

        command.append(
            "--ignore-unfixed"
        )

    if (
        license_full
        and "license" in scanner_list
    ):

        command.append(
            "--license-full"
        )

    command.append(
        target
    )

    return command


def execute_trivy(
    scan_type: str,
    target: str,
    scanners: Iterable[str],
    severity: Optional[str] = None,
    ignore_unfixed: bool = False,
    license_full: bool = False,
) -> Dict[str, Any]:
    """
    Execute Trivy and return parsed JSON report.
    """

    command = build_trivy_command(
        scan_type=scan_type,
        target=target,
        scanners=scanners,
        severity=severity,
        ignore_unfixed=ignore_unfixed,
        license_full=license_full,
    )

    logger.info(
        "Executing Trivy: %s",
        " ".join(
            command
        ),
    )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=TRIVY_TIMEOUT,
        )

    except subprocess.TimeoutExpired as exc:

        raise RuntimeError(
            f"Trivy execution exceeded "
            f"{TRIVY_TIMEOUT} seconds"
        ) from exc

    if result.returncode != 0:

        raise RuntimeError(
            "Trivy failed with exit code "
            f"{result.returncode}: "
            f"{result.stderr.strip()}"
        )

    if not result.stdout.strip():

        raise RuntimeError(
            "Trivy returned empty stdout"
        )

    try:

        report = json.loads(
            result.stdout
        )

    except json.JSONDecodeError as exc:

        raise RuntimeError(
            f"Unable to parse Trivy JSON output: {exc}"
        ) from exc

    if not isinstance(
        report,
        dict,
    ):

        raise RuntimeError(
            "Trivy JSON output is not a JSON object"
        )

    return report


# ============================================================================
# FINDING CLASSIFICATION
# ============================================================================

def is_os_package_result(
    result: Dict[str, Any],
) -> bool:
    """
    Determine whether Trivy vulnerability results belong to OS packages.

    Common Result.Class values:

        os-pkgs
        lang-pkgs
    """

    result_class = str(
        result.get(
            "Class",
            "",
        )
    ).lower()

    result_type = str(
        result.get(
            "Type",
            "",
        )
    ).lower()

    if result_class == "os-pkgs":
        return True

    os_types = {
        "alpine",
        "debian",
        "ubuntu",
        "redhat",
        "centos",
        "rocky",
        "alma",
        "amazon",
        "oracle",
        "fedora",
        "suse",
        "photon",
    }

    return result_type in os_types


def determine_vulnerability_class(
    scan_type: str,
    result: Dict[str, Any],
) -> str:
    """
    Determine whether vulnerability belongs to container image OS or an
    application dependency.
    """

    if (
        scan_type == "image"
        and is_os_package_result(
            result
        )
    ):

        return "container_image_vulnerability"

    return "container_dependency_vulnerability"


def determine_misconfiguration_class(
    result: Dict[str, Any],
    misconfiguration: Dict[str, Any],
) -> str:
    """
    Classify Trivy configuration findings.
    """

    result_target = str(
        result.get(
            "Target",
            "",
        )
    ).lower()

    result_type = str(
        result.get(
            "Type",
            "",
        )
    ).lower()

    cause_metadata = misconfiguration.get(
        "CauseMetadata"
    )

    metadata_text = ""

    if isinstance(
        cause_metadata,
        dict,
    ):

        try:

            metadata_text = json.dumps(
                cause_metadata
            ).lower()

        except Exception:

            metadata_text = str(
                cause_metadata
            ).lower()

    combined = " ".join(
        [
            result_target,
            result_type,
            metadata_text,
            str(
                misconfiguration.get(
                    "Type",
                    "",
                )
            ).lower(),
        ]
    )

    docker_indicators = (
        "dockerfile",
        "containerfile",
    )

    if any(
        indicator in combined
        for indicator in docker_indicators
    ):

        return "dockerfile_misconfiguration"

    iac_indicators = (
        "terraform",
        "cloudformation",
        "kubernetes",
        "helm",
        "azure-arm",
        "arm template",
        "terraformplan",
        ".tf",
        ".yaml",
        ".yml",
    )

    if any(
        indicator in combined
        for indicator in iac_indicators
    ):

        return "iac_misconfiguration"

    return "container_misconfiguration"


def scanner_for_finding_class(
    finding_class: str,
) -> str:
    """
    Map canonical finding_class back to the appropriate Trivy scanner.

    This is used only for Stage 2 re-verification.
    """

    mapping = {
        "container_image_vulnerability":
            "vuln",

        "container_dependency_vulnerability":
            "vuln",

        "container_misconfiguration":
            "misconfig",

        "dockerfile_misconfiguration":
            "misconfig",

        "iac_misconfiguration":
            "misconfig",

        "container_secret_exposure":
            "secret",

        "container_license_issue":
            "license",
    }

    try:

        return mapping[
            finding_class
        ]

    except KeyError as exc:

        raise ValueError(
            "Unsupported Trivy finding_class: "
            f"{finding_class}"
        ) from exc


# ============================================================================
# COMMON PAYLOAD BUILDER
# ============================================================================

def build_base_payload(
    tenant_code: str,
    service_tier: str,
    original_target: str,
    finding_category: str,
    finding_class: str,
    finding_key: str,
    finding_title: str,
    severity_level: Optional[str],
    severity_score: Optional[float],
    metadata: Dict[str, Any],
    detected_at: str,
) -> Dict[str, Any]:
    """
    Build UnifiedSecurityFinding.

    target_host contains the ORIGINAL Trivy target.

    Examples:

        nginx:1.25

        /opt/application

    For Trivy the field is semantically a scan target rather than
    necessarily an IP address. The current unified schema permits any
    non-empty string.
    """

    payload = {
        "tenant_code":
            tenant_code,

        "tenant_service_tier":
            service_tier,

        "target_host":
            original_target,

        "engine_source":
            "trivy",

        "finding_category":
            finding_category,

        "finding_class":
            finding_class,

        "finding_key":
            finding_key,

        "finding_title":
            finding_title,

        "lifecycle_status":
            "OPEN",

        "detected_at":
            detected_at,

        "remediated_at":
            None,

        "last_verified_at":
            None,

        "compliance_result":
            (
                "FAIL"
                if finding_category == "compliance_drift"
                else None
            ),

        "severity_level":
            severity_level,

        "severity_score":
            severity_score,

        "engine_metadata":
            metadata,

        # Scanner executes before Ollama.
        "ai_analysis":
            None,
    }

    validate_unified_finding(
        payload
    )

    return payload


# ============================================================================
# VULNERABILITY NORMALISATION
# ============================================================================

def normalize_vulnerability(
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    original_target: str,
    result: Dict[str, Any],
    vulnerability: Dict[str, Any],
    detected_at: str,
) -> Dict[str, Any]:

    vulnerability_id = clean_string(
        vulnerability.get(
            "VulnerabilityID"
        )
    ) or "UNKNOWN-VULNERABILITY"

    package_name = clean_string(
        vulnerability.get(
            "PkgName"
        )
    ) or "unknown_package"

    installed_version = clean_string(
        vulnerability.get(
            "InstalledVersion"
        )
    )

    fixed_version = clean_string(
        vulnerability.get(
            "FixedVersion"
        )
    )

    finding_class = determine_vulnerability_class(
        scan_type,
        result,
    )

    raw_severity = vulnerability.get(
        "Severity",
        "MEDIUM",
    )

    severity_level = normalize_severity_level(
        raw_severity
    )

    severity_score = get_vulnerability_score(
        vulnerability,
        severity_level,
    )

    # CVE alone is insufficient because one CVE may affect multiple
    # packages in the same target.
    finding_key = (
        f"{vulnerability_id}:{package_name}"
    )

    title = (
        vulnerability.get(
            "Title"
        )
        or vulnerability.get(
            "Description"
        )
        or (
            f"{vulnerability_id} "
            f"in {package_name}"
        )
    )

    finding_title = trim_title(
        f"{vulnerability_id} - "
        f"{package_name}: {title}"
    )

    metadata = {
        # Scanner subtype needed for precise Stage 2 execution.
        "scanner":
            "vuln",

        # Authoritative source for verification target type.
        "scan_type":
            scan_type,

        # Authoritative original target used to rerun Trivy.
        "scan_target":
            original_target,

        "result_target":
            result.get(
                "Target"
            ),

        "result_class":
            result.get(
                "Class"
            ),

        "result_type":
            result.get(
                "Type"
            ),

        "cve_id":
            vulnerability_id,

        "package_name":
            package_name,

        "installed_version":
            installed_version,

        "fixed_version":
            fixed_version,

        "primary_url":
            vulnerability.get(
                "PrimaryURL"
            ),

        "references":
            vulnerability.get(
                "References",
                [],
            ),

        "raw_severity":
            raw_severity,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value is not None
    }

    return build_base_payload(
        tenant_code=tenant_code,
        service_tier=service_tier,
        original_target=original_target,
        finding_category="vulnerability",
        finding_class=finding_class,
        finding_key=finding_key,
        finding_title=finding_title,
        severity_level=severity_level,
        severity_score=severity_score,
        metadata=metadata,
        detected_at=detected_at,
    )


# ============================================================================
# MISCONFIGURATION NORMALISATION
# ============================================================================

def normalize_misconfiguration(
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    original_target: str,
    result: Dict[str, Any],
    item: Dict[str, Any],
    detected_at: str,
) -> Dict[str, Any]:

    finding_class = determine_misconfiguration_class(
        result,
        item,
    )

    check_id = clean_string(
        item.get(
            "ID"
        )
    )

    if not check_id:

        check_id = clean_string(
            item.get(
                "AVDID"
            )
        )

    if not check_id:

        basis = json.dumps(
            item,
            sort_keys=True,
            default=str,
        )

        check_id = (
            "TRIVY-MISCONFIG-"
            + stable_hash(
                basis
            )
        )

    title = (
        item.get(
            "Title"
        )
        or item.get(
            "Description"
        )
        or (
            f"Trivy misconfiguration "
            f"{check_id}"
        )
    )

    raw_severity = item.get(
        "Severity",
        "MEDIUM",
    )

    severity_level = normalize_severity_level(
        raw_severity
    )

    severity_score = severity_score_fallback(
        severity_level
    )

    finding_key = str(
        check_id
    )

    metadata = {
        "scanner":
            "misconfig",

        "scan_type":
            scan_type,

        "scan_target":
            original_target,

        "result_target":
            result.get(
                "Target"
            ),

        "result_class":
            result.get(
                "Class"
            ),

        "result_type":
            result.get(
                "Type"
            ),

        "check_id":
            check_id,

        "description":
            item.get(
                "Description"
            ),

        "message":
            item.get(
                "Message"
            ),

        "resolution":
            item.get(
                "Resolution"
            ),

        "primary_url":
            item.get(
                "PrimaryURL"
            ),

        "references":
            item.get(
                "References",
                [],
            ),

        "cause_metadata":
            item.get(
                "CauseMetadata"
            ),

        "raw_severity":
            raw_severity,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value is not None
    }

    return build_base_payload(
        tenant_code=tenant_code,
        service_tier=service_tier,
        original_target=original_target,
        finding_category="compliance_drift",
        finding_class=finding_class,
        finding_key=finding_key,
        finding_title=trim_title(
            f"{check_id} - {title}"
        ),
        severity_level=severity_level,
        severity_score=severity_score,
        metadata=metadata,
        detected_at=detected_at,
    )


# ============================================================================
# SECRET NORMALISATION
# ============================================================================

def normalize_secret(
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    original_target: str,
    result: Dict[str, Any],
    item: Dict[str, Any],
    detected_at: str,
) -> Dict[str, Any]:

    rule_id = clean_string(
        item.get(
            "RuleID"
        )
    ) or clean_string(
        item.get(
            "Category"
        )
    ) or "secret"

    title = (
        item.get(
            "Title"
        )
        or (
            f"Secret detected "
            f"by {rule_id}"
        )
    )

    start_line = (
        item.get(
            "StartLine"
        )
        or item.get(
            "Line"
        )
    )

    end_line = (
        item.get(
            "EndLine"
        )
        or start_line
    )

    result_target = clean_string(
        result.get(
            "Target"
        )
    ) or original_target

    # Do not include the actual secret in the identity.
    finding_key = (
        "TRIVY-SECRET:"
        + stable_hash(
            "|".join(
                [
                    str(
                        rule_id
                    ),
                    str(
                        result_target
                    ),
                    str(
                        start_line
                        or ""
                    ),
                ]
            )
        )
    )

    raw_severity = item.get(
        "Severity",
        "HIGH",
    )

    severity_level = normalize_severity_level(
        raw_severity
    )

    metadata = {
        "scanner":
            "secret",

        "scan_type":
            scan_type,

        "scan_target":
            original_target,

        "result_target":
            result_target,

        "rule_id":
            rule_id,

        "category":
            item.get(
                "Category"
            ),

        "start_line":
            start_line,

        "end_line":
            end_line,

        # Trivy may already return a masked Match. We preserve the scanner
        # value but deliberately do not manufacture raw secret material.
        "match":
            item.get(
                "Match"
            ),

        "raw_severity":
            raw_severity,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value is not None
    }

    return build_base_payload(
        tenant_code=tenant_code,
        service_tier=service_tier,
        original_target=original_target,
        finding_category="vulnerability",
        finding_class="container_secret_exposure",
        finding_key=finding_key,
        finding_title=trim_title(
            f"{rule_id} - {title}"
        ),
        severity_level=severity_level,
        severity_score=severity_score_fallback(
            severity_level
        ),
        metadata=metadata,
        detected_at=detected_at,
    )


# ============================================================================
# LICENCE NORMALISATION
# ============================================================================

def iter_licenses(
    result: Dict[str, Any],
) -> Iterable[
    Tuple[
        Optional[str],
        Dict[str, Any],
    ]
]:
    """
    Trivy has exposed licence information in different structures across
    versions and scan targets.

    Yield:

        package_name,
        licence_object
    """

    licenses = result.get(
        "Licenses"
    )

    if isinstance(
        licenses,
        list,
    ):

        for item in licenses:

            if isinstance(
                item,
                dict,
            ):

                yield (
                    clean_string(
                        item.get(
                            "PkgName"
                        )
                    ),
                    item,
                )

    packages = result.get(
        "Packages"
    )

    if isinstance(
        packages,
        list,
    ):

        for package in packages:

            if not isinstance(
                package,
                dict,
            ):

                continue

            package_name = clean_string(
                package.get(
                    "Name"
                )
                or package.get(
                    "PkgName"
                )
            )

            package_licenses = package.get(
                "Licenses"
            )

            if not isinstance(
                package_licenses,
                list,
            ):

                continue

            for licence_item in package_licenses:

                if isinstance(
                    licence_item,
                    dict,
                ):

                    yield (
                        package_name,
                        licence_item,
                    )

                else:

                    yield (
                        package_name,
                        {
                            "Name":
                                str(
                                    licence_item
                                )
                        },
                    )


def license_name(
    item: Dict[str, Any],
) -> str:
    """
    Obtain licence identifier across Trivy versions.
    """

    return str(
        item.get(
            "Name"
        )
        or item.get(
            "License"
        )
        or item.get(
            "SPDX"
        )
        or "UNKNOWN"
    )


def normalize_license(
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    original_target: str,
    result: Dict[str, Any],
    package_name: Optional[str],
    item: Dict[str, Any],
    detected_at: str,
) -> Dict[str, Any]:

    name = license_name(
        item
    )

    classification = str(
        item.get(
            "Category"
        )
        or item.get(
            "Classification"
        )
        or "UNKNOWN"
    ).upper()

    raw_severity = str(
        item.get(
            "Severity"
        )
        or "MEDIUM"
    )

    severity_level = normalize_severity_level(
        raw_severity
    )

    result_target = clean_string(
        result.get(
            "Target"
        )
    ) or original_target

    finding_key = (
        "TRIVY-LICENSE:"
        + stable_hash(
            "|".join(
                [
                    name,
                    package_name
                    or "",
                    result_target,
                ]
            )
        )
    )

    title = (
        f"Licence issue: {name}"
    )

    if package_name:

        title += (
            f" in {package_name}"
        )

    metadata = {
        "scanner":
            "license",

        "scan_type":
            scan_type,

        "scan_target":
            original_target,

        "result_target":
            result_target,

        "package_name":
            package_name,

        "license_name":
            name,

        "license_classification":
            classification,

        "raw_severity":
            raw_severity,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value is not None
    }

    return build_base_payload(
        tenant_code=tenant_code,
        service_tier=service_tier,
        original_target=original_target,
        finding_category="vulnerability",
        finding_class="container_license_issue",
        finding_key=finding_key,
        finding_title=trim_title(
            title
        ),
        severity_level=severity_level,
        severity_score=severity_score_fallback(
            severity_level
        ),
        metadata=metadata,
        detected_at=detected_at,
    )


# ============================================================================
# REPORT NORMALISATION
# ============================================================================

def add_if_unique(
    payload: Dict[str, Any],
    findings: List[Dict[str, Any]],
    seen: set,
) -> None:
    """
    Deduplicate normalised Trivy findings.
    """

    key = (
        payload["target_host"],
        payload["engine_source"],
        payload["finding_class"],
        payload["finding_key"],
        payload[
            "engine_metadata"
        ].get(
            "result_target"
        ),
    )

    if key in seen:
        return

    seen.add(
        key
    )

    findings.append(
        payload
    )


def normalize_report(
    report: Dict[str, Any],
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    original_target: str,
    enabled_scanners: Set[str],
) -> List[Dict[str, Any]]:
    """
    Convert Trivy JSON report into zero or more Unified Security Findings.
    """

    findings: List[
        Dict[str, Any]
    ] = []

    seen = set()

    detected_at = utc_now()

    results = (
        report.get(
            "Results"
        )
        or []
    )

    if not isinstance(
        results,
        list,
    ):

        raise ValueError(
            "Trivy Results field must be an array"
        )

    for result in results:

        if not isinstance(
            result,
            dict,
        ):

            continue

        # ------------------------------------------------------------------
        # Vulnerabilities
        # ------------------------------------------------------------------

        if "vuln" in enabled_scanners:

            vulnerabilities = (
                result.get(
                    "Vulnerabilities"
                )
                or []
            )

            if isinstance(
                vulnerabilities,
                list,
            ):

                for item in vulnerabilities:

                    if not isinstance(
                        item,
                        dict,
                    ):

                        continue

                    payload = normalize_vulnerability(
                        tenant_code,
                        service_tier,
                        scan_type,
                        original_target,
                        result,
                        item,
                        detected_at,
                    )

                    add_if_unique(
                        payload,
                        findings,
                        seen,
                    )

        # ------------------------------------------------------------------
        # Misconfigurations
        # ------------------------------------------------------------------

        if "misconfig" in enabled_scanners:

            misconfigurations = (
                result.get(
                    "Misconfigurations"
                )
                or []
            )

            if isinstance(
                misconfigurations,
                list,
            ):

                for item in misconfigurations:

                    if not isinstance(
                        item,
                        dict,
                    ):

                        continue

                    payload = normalize_misconfiguration(
                        tenant_code,
                        service_tier,
                        scan_type,
                        original_target,
                        result,
                        item,
                        detected_at,
                    )

                    add_if_unique(
                        payload,
                        findings,
                        seen,
                    )

        # ------------------------------------------------------------------
        # Secrets
        # ------------------------------------------------------------------

        if "secret" in enabled_scanners:

            secrets = (
                result.get(
                    "Secrets"
                )
                or []
            )

            if isinstance(
                secrets,
                list,
            ):

                for item in secrets:

                    if not isinstance(
                        item,
                        dict,
                    ):

                        continue

                    payload = normalize_secret(
                        tenant_code,
                        service_tier,
                        scan_type,
                        original_target,
                        result,
                        item,
                        detected_at,
                    )

                    add_if_unique(
                        payload,
                        findings,
                        seen,
                    )

        # ------------------------------------------------------------------
        # Licences
        # ------------------------------------------------------------------

        if "license" in enabled_scanners:

            for (
                package_name,
                item,
            ) in iter_licenses(
                result
            ):

                payload = normalize_license(
                    tenant_code,
                    service_tier,
                    scan_type,
                    original_target,
                    result,
                    package_name,
                    item,
                    detected_at,
                )

                add_if_unique(
                    payload,
                    findings,
                    seen,
                )

    return findings


# ============================================================================
# UNIFIED SECURITY FINDING VALIDATION
# ============================================================================

def validate_unified_finding(
    payload: Dict[str, Any],
) -> None:
    """
    Validate fields controlled directly by this scanner orchestrator.

    The enrichment worker and PostgreSQL provide another validation layer.
    """

    for field in REQUIRED_UNIFIED_FINDING_FIELDS:

        if payload.get(
            field
        ) in (
            None,
            "",
        ):

            raise ValueError(
                "Unified finding missing "
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
        not in VALID_TRIVY_FINDING_CLASSES
    ):

        raise ValueError(
            "Invalid Trivy finding_class: "
            f"{payload['finding_class']}"
        )

    if (
        payload["engine_source"]
        != "trivy"
    ):

        raise ValueError(
            "Trivy findings must use "
            "engine_source='trivy'"
        )

    if payload[
        "lifecycle_status"
    ] not in {
        "OPEN",
        "IN_REMEDIATION",
        "RESOLVED",
        "FALSE_POSITIVE",
    }:

        raise ValueError(
            "Invalid lifecycle_status"
        )

    severity_score = payload.get(
        "severity_score"
    )

    if severity_score is not None:

        score = float(
            severity_score
        )

        if not 0 <= score <= 10:

            raise ValueError(
                "severity_score must be "
                "between 0 and 10"
            )


# ============================================================================
# SCAN MODE
# ============================================================================

def write_findings(
    findings: List[Dict[str, Any]],
) -> None:
    """
    Write normal scan findings to the Wazuh-monitored JSONL log.
    """

    directory = os.path.dirname(
        DATA_LOG_PATH
    )

    if directory:

        os.makedirs(
            directory,
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
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )


def run_scan_mode(
    tenant_code: str,
    service_tier: str,
    scan_type: str,
    target: str,
    scanners: Set[str],
    severity: Optional[str],
    ignore_unfixed: bool,
    license_full: bool,
) -> int:
    """
    Execute normal ingestion scan.
    """

    tenant_code = str(
        tenant_code
    ).strip()

    if not tenant_code:

        raise ValueError(
            "tenant_code cannot be empty"
        )

    service_tier = normalize_service_tier(
        service_tier,
        logger,
    )

    target = str(
        target
    ).strip()

    if not target:

        raise ValueError(
            "target cannot be empty"
        )

    if scan_type not in VALID_SCAN_TYPES:

        raise ValueError(
            f"Unsupported scan_type: "
            f"{scan_type}"
        )

    invalid_scanners = (
        scanners
        - VALID_SCANNERS
    )

    if invalid_scanners:

        raise ValueError(
            "Unsupported Trivy scanners: "
            + ", ".join(
                sorted(
                    invalid_scanners
                )
            )
        )

    logger.info(
        "SCAN mode: "
        "type=%s target=%s scanners=%s",
        scan_type,
        target,
        ",".join(
            sorted(
                scanners
            )
        ),
    )

    report = execute_trivy(
        scan_type=scan_type,
        target=target,
        scanners=scanners,
        severity=severity,
        ignore_unfixed=ignore_unfixed,
        license_full=license_full,
    )

    findings = normalize_report(
        report=report,
        tenant_code=tenant_code,
        service_tier=service_tier,
        scan_type=scan_type,
        original_target=target,
        enabled_scanners=scanners,
    )

    write_findings(
        findings
    )

    logger.info(
        "SCAN mode complete. "
        "Wrote %d findings to %s.",
        len(
            findings
        ),
        DATA_LOG_PATH,
    )

    return len(
        findings
    )


# ============================================================================
# VERIFICATION HELPERS
# ============================================================================

def determine_verification_scan_type(
    target_host: str,
    engine_metadata: Dict[str, Any],
    cli_scan_type: Optional[str] = None,
) -> str:
    """
    Determine the ORIGINAL scan type.

    Precedence:

        1. engine_metadata.scan_type
        2. explicit --scan-type
        3. conservative legacy inference

    New findings should always contain engine_metadata.scan_type.
    """

    metadata_scan_type = clean_string(
        engine_metadata.get(
            "scan_type"
        )
    )

    if metadata_scan_type:

        metadata_scan_type = (
            metadata_scan_type.lower()
        )

        if metadata_scan_type not in VALID_SCAN_TYPES:

            raise ValueError(
                "Invalid engine_metadata.scan_type: "
                f"{metadata_scan_type}"
            )

        return metadata_scan_type

    if cli_scan_type:

        if cli_scan_type not in VALID_SCAN_TYPES:

            raise ValueError(
                f"Invalid --scan-type: "
                f"{cli_scan_type}"
            )

        return cli_scan_type

    # Legacy compatibility only.
    #
    # New records must carry scan_type in engine_metadata.
    if os.path.exists(
        target_host
    ):

        logger.warning(
            "Verification finding does not contain "
            "engine_metadata.scan_type; inferred folder "
            "because target exists locally."
        )

        return "folder"

    logger.warning(
        "Verification finding does not contain "
        "engine_metadata.scan_type; inferred image."
    )

    return "image"


def determine_verification_target(
    target_host: str,
    engine_metadata: Dict[str, Any],
) -> str:
    """
    Use the original scanner target stored in engine_metadata whenever
    available.

    target_host remains the fallback because it is also populated with the
    original Trivy target in scan mode.
    """

    scan_target = clean_string(
        engine_metadata.get(
            "scan_target"
        )
    )

    if scan_target:

        return scan_target

    return str(
        target_host
    ).strip()


def finding_identity_matches(
    finding: Dict[str, Any],
    original_finding_key: str,
    original_finding_class: str,
) -> bool:
    """
    Match the exact canonical identity used when the finding was ingested.
    """

    return (
        str(
            finding.get(
                "finding_key",
                "",
            )
        )
        == str(
            original_finding_key
        )
        and
        str(
            finding.get(
                "finding_class",
                "",
            )
        )
        == str(
            original_finding_class
        )
    )


def validate_verification_metadata(
    finding_class: str,
    scanner: str,
    engine_metadata: Dict[str, Any],
) -> None:
    """
    Cross-check original metadata against the deterministic class -> scanner
    mapping.

    This catches corrupted/mismatched verification requests without changing
    the finding's routing logic.
    """

    original_scanner = clean_string(
        engine_metadata.get(
            "scanner"
        )
    )

    if (
        original_scanner
        and original_scanner != scanner
    ):

        raise ValueError(
            "Verification metadata scanner mismatch: "
            f"finding_class={finding_class} "
            f"requires scanner={scanner}, "
            f"but engine_metadata.scanner="
            f"{original_scanner}"
        )


# ============================================================================
# VERIFICATION MODE
# ============================================================================

def run_verify_mode(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Dict[str, Any],
    scan_type_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform Stage 2 scanner-backed verification.

    The question is strictly:

        "Does Trivy still report the ORIGINAL finding?"

    This function deliberately does NOT:
        - write to scanners_raw.log;
        - create an OPEN finding;
        - use Ollama;
        - update PostgreSQL;
        - decide remediation actions.
    """

    target_host = str(
        target_host
    ).strip()

    finding_key = str(
        finding_key
    ).strip()

    finding_class = str(
        finding_class
    ).strip()

    if not target_host:

        raise ValueError(
            "target_host is required"
        )

    if not finding_key:

        raise ValueError(
            "finding_key is required"
        )

    if (
        finding_class
        not in VALID_TRIVY_FINDING_CLASSES
    ):

        raise ValueError(
            "Unsupported Trivy "
            f"finding_class: {finding_class}"
        )

    if not isinstance(
        engine_metadata,
        dict,
    ):

        raise ValueError(
            "engine_metadata must be "
            "a JSON object"
        )

    scanner = scanner_for_finding_class(
        finding_class
    )

    validate_verification_metadata(
        finding_class=finding_class,
        scanner=scanner,
        engine_metadata=engine_metadata,
    )

    scan_type = determine_verification_scan_type(
        target_host=target_host,
        engine_metadata=engine_metadata,
        cli_scan_type=scan_type_override,
    )

    verification_target = determine_verification_target(
        target_host=target_host,
        engine_metadata=engine_metadata,
    )

    logger.info(
        "VERIFY mode: "
        "target=%s type=%s scanner=%s "
        "key=%s class=%s",
        verification_target,
        scan_type,
        scanner,
        finding_key,
        finding_class,
    )

    # IMPORTANT:
    #
    # Do not apply severity filters here.
    #
    # Do not use --ignore-unfixed here.
    #
    # We are not creating a new report. We are answering whether the
    # original security condition still exists.
    report = execute_trivy(
        scan_type=scan_type,
        target=verification_target,
        scanners={
            scanner
        },
        severity=None,
        ignore_unfixed=False,
        license_full=(
            scanner
            == "license"
        ),
    )

    # Reuse the same normalisation logic that produced the original
    # finding identity.
    #
    # Dummy tenant values are never written anywhere.
    findings = normalize_report(
        report=report,
        tenant_code="VERIFICATION",
        service_tier="STANDARD",
        scan_type=scan_type,
        original_target=verification_target,
        enabled_scanners={
            scanner
        },
    )

    matches = []

    for finding in findings:

        if not finding_identity_matches(
            finding,
            finding_key,
            finding_class,
        ):

            continue

        matches.append(
            {
                "finding_key":
                    finding[
                        "finding_key"
                    ],

                "finding_class":
                    finding[
                        "finding_class"
                    ],

                "finding_title":
                    finding[
                        "finding_title"
                    ],

                "result_target":
                    finding[
                        "engine_metadata"
                    ].get(
                        "result_target"
                    ),

                "package_name":
                    finding[
                        "engine_metadata"
                    ].get(
                        "package_name"
                    ),

                "cve_id":
                    finding[
                        "engine_metadata"
                    ].get(
                        "cve_id"
                    ),

                "check_id":
                    finding[
                        "engine_metadata"
                    ].get(
                        "check_id"
                    ),

                "rule_id":
                    finding[
                        "engine_metadata"
                    ].get(
                        "rule_id"
                    ),

                "license_name":
                    finding[
                        "engine_metadata"
                    ].get(
                        "license_name"
                    ),
            }
        )

    present = bool(
        matches
    )

    verification_result = {
        "present":
            present,

        "finding_key":
            finding_key,

        "finding_class":
            finding_class,

        "scanner":
            "trivy",

        # Return the controller-provided target identity rather than
        # replacing it with a Trivy Results[].Target.
        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence": {
            "trivy_scanner":
                scanner,

            "scan_type":
                scan_type,

            "scan_target":
                verification_target,

            "original_result_target":
                engine_metadata.get(
                    "result_target"
                ),

            "match_count":
                len(
                    matches
                ),

            "matches":
                matches,
        },
    }

    logger.info(
        "VERIFY mode complete: "
        "target=%s key=%s present=%s",
        verification_target,
        finding_key,
        present,
    )

    return verification_result


# ============================================================================
# COMMAND-LINE HELPERS
# ============================================================================

def comma_list(
    raw: str,
) -> Set[str]:
    """
    Parse --scanners vuln,misconfig,...
    """

    result = {
        item.strip().lower()
        for item
        in str(
            raw
        ).split(",")
        if item.strip()
    }

    invalid = (
        result
        - VALID_SCANNERS
    )

    if invalid:

        raise argparse.ArgumentTypeError(
            "Invalid scanner(s): "
            + ", ".join(
                sorted(
                    invalid
                )
            )
        )

    return result


def build_parser() -> argparse.ArgumentParser:
    """
    Build explicit dual-mode command-line interface.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Trivy orchestrator for Regis "
            "Unified Security Findings"
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

    # ----------------------------------------------------------------------
    # SCAN MODE
    # ----------------------------------------------------------------------

    parser.add_argument(
        "--tenant-code"
    )

    parser.add_argument(
        "--service-tier"
    )

    parser.add_argument(
        "--scan-type",
        choices=[
            "image",
            "folder",
        ],
    )

    parser.add_argument(
        "--target"
    )

    parser.add_argument(
        "--scanners",
        type=comma_list,
        default=None,
        help=(
            "Comma-separated scanners: "
            "vuln,misconfig,secret,license"
        ),
    )

    parser.add_argument(
        "--scanner",
        choices=[
            "vuln",
            "misconfig",
            "secret",
            "license",
        ],
    )

    parser.add_argument(
        "--severity"
    )

    parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
    )

    parser.add_argument(
        "--license-full",
        action="store_true",
    )

    # ----------------------------------------------------------------------
    # VERIFICATION MODE
    # ----------------------------------------------------------------------

    parser.add_argument(
        "--target-host"
    )

    parser.add_argument(
        "--finding-key"
    )

    parser.add_argument(
        "--finding-class"
    )

    # NEW canonical architecture argument.
    parser.add_argument(
        "--engine-metadata-json",
        help=(
            "Original UnifiedSecurityFinding "
            "engine_metadata serialised as JSON. "
            "Passed by verification_dispatcher.py."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print machine-readable JSON. "
            "Verification mode always emits "
            "machine-readable JSON."
        ),
    )

    return parser


# ============================================================================
# LEGACY ARGUMENT COMPATIBILITY
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Preserve the old Trivy invocation during migration.

    OLD:

        trivy_orchestrator.py \
            Customer5 Gold image nginx:latest \
            --severity HIGH,CRITICAL \
            --ignore-unfixed

    Internally translated to:

        --mode scan
        --scanner vuln

    New deployments should use the explicit --mode syntax.
    """

    if (
        len(
            sys.argv
        )
        >= 5
        and not sys.argv[1].startswith(
            "-"
        )
    ):

        translated = [
            sys.argv[0],

            "--mode",
            "scan",

            "--tenant-code",
            sys.argv[1],

            "--service-tier",
            sys.argv[2],

            "--scan-type",
            sys.argv[3],

            "--target",
            sys.argv[4],

            "--scanner",
            "vuln",
        ]

        translated.extend(
            sys.argv[5:]
        )

        original = sys.argv

        try:

            sys.argv = translated

            return (
                build_parser()
                .parse_args()
            )

        finally:

            sys.argv = original

    return (
        build_parser()
        .parse_args()
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    args = parse_arguments()

    try:

        # ==================================================================
        # SCAN MODE
        # ==================================================================

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
                        "--scan-type",
                        args.scan_type,
                    ),
                    (
                        "--target",
                        args.target,
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
                args.scanner
                and args.scanners
            ):

                raise ValueError(
                    "Use either --scanner "
                    "or --scanners, not both."
                )

            if args.scanner:

                scanners = {
                    args.scanner
                }

            elif args.scanners:

                scanners = (
                    args.scanners
                )

            else:

                # Preserve predictable legacy default.
                scanners = {
                    "vuln"
                }

            count = run_scan_mode(
                tenant_code=
                    args.tenant_code,

                service_tier=
                    args.service_tier,

                scan_type=
                    args.scan_type,

                target=
                    args.target,

                scanners=
                    scanners,

                severity=
                    args.severity,

                ignore_unfixed=
                    args.ignore_unfixed,

                license_full=
                    args.license_full,
            )

            if args.json:

                print(
                    json.dumps(
                        {
                            "mode":
                                "scan",

                            "scanner":
                                "trivy",

                            "scan_type":
                                args.scan_type,

                            "trivy_scanners":
                                sorted(
                                    scanners
                                ),

                            "target":
                                args.target,

                            "findings_written":
                                count,

                            "output":
                                DATA_LOG_PATH,
                        },
                        separators=(
                            ",",
                            ":",
                        ),
                    )
                )

            else:

                print(
                    "Trivy scan complete. "
                    f"Payloads written: "
                    f"{count}."
                )

            return 0

        # ==================================================================
        # VERIFY MODE
        # ==================================================================

        missing = [
            name
            for name, value
            in (
                (
                    "--target-host",
                    args.target_host,
                ),
                (
                    "--finding-key",
                    args.finding_key,
                ),
                (
                    "--finding-class",
                    args.finding_class,
                ),
            )
            if not value
        ]

        if missing:

            raise ValueError(
                "VERIFY mode requires: "
                + ", ".join(
                    missing
                )
            )

        engine_metadata = parse_json_object(
            args.engine_metadata_json,
            "--engine-metadata-json",
        )

        verification = run_verify_mode(
            target_host=
                args.target_host,

            finding_key=
                args.finding_key,

            finding_class=
                args.finding_class,

            engine_metadata=
                engine_metadata,

            # --scan-type is retained only as a compatibility fallback.
            # engine_metadata.scan_type is authoritative for new findings.
            scan_type_override=
                args.scan_type,
        )

        # verification_dispatcher.py requires exactly one JSON object
        # on stdout.
        print(
            json.dumps(
                verification,
                separators=(
                    ",",
                    ":",
                ),
                ensure_ascii=False,
            )
        )

        return 0

    except Exception as exc:

        logger.exception(
            "Trivy orchestrator failed: %s",
            exc,
        )

        if (
            getattr(
                args,
                "mode",
                None,
            )
            == "verify"
        ):

            # --------------------------------------------------------------
            # FAIL CLOSED
            # --------------------------------------------------------------
            #
            # Failure to scan cannot mean that a finding disappeared.
            #
            # verification_dispatcher.py additionally treats our non-zero
            # exit status as Stage 2 failure.
            # --------------------------------------------------------------

            print(
                json.dumps(
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
                            "trivy",

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
                    },
                    separators=(
                        ",",
                        ":",
                    ),
                )
            )

        return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
