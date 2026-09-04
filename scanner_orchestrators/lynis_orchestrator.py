#!/usr/bin/env python3
"""
Automated Cybersecurity Remediation Platform
Lynis Compliance / Hardening Orchestrator

OPERATING MODES
===============

1. SCAN MODE

   - Runs a local Lynis audit.
   - Parses /var/log/lynis-report.dat.
   - Determines a canonical finding_class.
   - Normalises findings to UnifiedSecurityFinding.
   - Writes findings to /var/log/compliance_raw.log.
   - Does not perform remediation.

2. VERIFY MODE

   - Called by verification_gateway.py after remediation.
   - Runs a fresh Lynis audit.
   - Checks whether the ORIGINAL finding_key is still present.
   - Does NOT write findings to compliance_raw.log.
   - Does NOT create a new OPEN finding.
   - Prints exactly one JSON object to stdout.

CANONICAL VERIFICATION CONTRACT
===============================

verification_dispatcher.py invokes scanner orchestrators using:

    --mode verify
    --target-host <target>
    --finding-key <key>
    --finding-class <class>
    --engine-metadata-json '<json>'
    --json

Lynis accepts engine_metadata for interface compatibility, although
the current Lynis verification algorithm does not need scanner metadata
to rerun a test. The original finding_key (Lynis test ID) is sufficient.

CANONICAL LYNIS FINDING CLASSES
===============================

    lynis_hardening
    security_configuration
    service_configuration
    authentication_configuration
    access_control_configuration
    logging_configuration
    filesystem_configuration
    network_configuration

SCAN EXAMPLES
=============

Preferred:

    sudo python3 lynis_orchestrator.py \
        --mode scan \
        --tenant-code CUSTOMER_A \
        --service-tier STANDARD \
        --target-host 10.20.30.15

With warning filter:

    sudo python3 lynis_orchestrator.py \
        --mode scan \
        --tenant-code CUSTOMER_A \
        --service-tier STANDARD \
        --target-host 10.20.30.15 \
        --filter-mode warnings_only

Optional task metadata override:

    sudo python3 lynis_orchestrator.py \
        --mode scan \
        --tenant-code CUSTOMER_A \
        --service-tier STANDARD \
        --target-host 10.20.30.15 \
        --task-name "Monthly Host Compliance Audit"

Legacy-compatible positional scan:

    sudo python3 lynis_orchestrator.py \
        CUSTOMER_A STANDARD 10.20.30.15

Legacy positional scan with filter:

    sudo python3 lynis_orchestrator.py \
        CUSTOMER_A STANDARD 10.20.30.15 warnings_only

VERIFY EXAMPLE
==============

    sudo python3 lynis_orchestrator.py \
        --mode verify \
        --target-host 10.20.30.15 \
        --finding-key AUTH-9282 \
        --finding-class authentication_configuration \
        --engine-metadata-json \
        '{"lynis_test_id":"AUTH-9282"}' \
        --json
"""

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional

from common.finding import build_unified_finding as build_common_unified_finding
from common.runtime import normalize_service_tier, utc_now
from common.validation import REQUIRED_UNIFIED_FINDING_FIELDS
from common.verification import read_verification_request

# ============================================================================
# CONFIGURATION
# ============================================================================

LYNIS_REPORT_PATH = os.getenv(
    "LYNIS_REPORT_PATH",
    "/var/log/lynis-report.dat",
)

LOCAL_COMPLIANCE_LOG = os.getenv(
    "COMPLIANCE_RAW_LOG",
    "/var/log/compliance_raw.log",
)

LOG_DIR = os.getenv(
    "LOG_DIR",
    "/var/log/automated-remediation",
)

ERROR_LOG_PATH = os.path.join(
    LOG_DIR,
    "lynis_orchestrator.error.log",
)

LYNIS_BINARY = os.getenv(
    "LYNIS_BINARY",
    "lynis",
)

LYNIS_TIMEOUT = int(
    os.getenv(
        "LYNIS_TIMEOUT",
        "900",
    )
)

DEFAULT_TASK_NAME = os.getenv(
    "LYNIS_TASK_NAME",
    "Lynis System Audit",
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_LYNIS_CLASSES = {
    "lynis_hardening",
    "security_configuration",
    "service_configuration",
    "authentication_configuration",
    "access_control_configuration",
    "logging_configuration",
    "filesystem_configuration",
    "network_configuration",
}

VALID_LIFECYCLE_STATES = {
    "OPEN",
    "IN_REMEDIATION",
    "RESOLVED",
    "FALSE_POSITIVE",
}

ENGINE_SOURCE = "lynis"

FINDING_CATEGORY = "compliance_drift"


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(
    verbose: bool = False,
) -> logging.Logger:
    """
    Operational logs go to stderr.

    This is essential because verification_gateway.py expects stdout from:

        --mode verify --json

    to contain exactly one JSON document.
    """

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "lynis_orchestrator"
    )

    logger.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler = RotatingFileHandler(
        ERROR_LOG_PATH,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )

    file_handler.setFormatter(
        formatter
    )

    file_handler.setLevel(
        logging.WARNING
    )

    stream_handler = logging.StreamHandler(
        sys.stderr
    )

    stream_handler.setFormatter(
        formatter
    )

    stream_handler.setLevel(
        logging.DEBUG
        if verbose
        else logging.INFO
    )

    logger.handlers.clear()

    logger.addHandler(
        file_handler
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

def normalize_filter_mode(
    value: Optional[str],
) -> str:
    """
    Supported scan filters:

        warnings_only
        all
    """

    mode = str(
        value or "warnings_only"
    ).strip().lower()

    aliases = {
        "warning": "warnings_only",
        "warnings": "warnings_only",
        "warnings_only": "warnings_only",

        "all": "all",
        "everything": "all",
        "warnings_and_suggestions": "all",
    }

    mode = aliases.get(
        mode,
        mode,
    )

    if mode not in {
        "warnings_only",
        "all",
    }:

        raise ValueError(
            "filter_mode must be 'warnings_only' or 'all'"
        )

    return mode


def normalize_task_name(
    value: Optional[str],
) -> str:
    """
    task_name is metadata only.
    """

    if value is None:

        return DEFAULT_TASK_NAME

    value = str(
        value
    ).strip()

    if not value:

        return DEFAULT_TASK_NAME

    return value


def parse_json_object(
    value: Optional[str],
) -> Dict[str, Any]:
    """
    Parse --engine-metadata-json.

    The canonical verification dispatcher supplies this argument to every
    scanner orchestrator.

    Lynis currently does not require metadata for verification, but it
    accepts and validates the argument to maintain a common interface.
    """

    if not value:

        return {}

    try:

        data = json.loads(
            value
        )

    except json.JSONDecodeError as exc:

        raise ValueError(
            "--engine-metadata-json is not valid JSON"
        ) from exc

    if not isinstance(
        data,
        dict,
    ):

        raise ValueError(
            "--engine-metadata-json must contain a JSON object"
        )

    return data


# ============================================================================
# LYNIS EXECUTION
# ============================================================================

def run_lynis_scan() -> None:
    """
    Run a fresh local Lynis system audit.

    Existing working Lynis execution is preserved:

        lynis audit system --quick --cronjob
    """

    logger.info(
        "Launching local Lynis system audit."
    )

    command = [
        LYNIS_BINARY,
        "audit",
        "system",
        "--quick",
        "--cronjob",
    ]

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=LYNIS_TIMEOUT,
        )

    except subprocess.TimeoutExpired as exc:

        raise RuntimeError(
            f"Lynis scan exceeded {LYNIS_TIMEOUT} seconds."
        ) from exc

    except FileNotFoundError as exc:

        raise RuntimeError(
            f"Lynis executable not found: {LYNIS_BINARY}"
        ) from exc

    except Exception as exc:

        raise RuntimeError(
            f"Unable to execute Lynis: {exc}"
        ) from exc

    logger.info(
        "Lynis audit completed with exit code %s.",
        result.returncode,
    )

    # Lynis can return a non-zero status for audit conditions while still
    # producing a valid report. The report itself is therefore authoritative
    # for this orchestrator.

    if not os.path.exists(
        LYNIS_REPORT_PATH
    ):

        raise RuntimeError(
            f"Lynis report was not generated at "
            f"{LYNIS_REPORT_PATH}"
        )


# ============================================================================
# REPORT PARSING
# ============================================================================

def parse_report_line(
    line: str,
) -> Optional[Dict[str, Any]]:
    """
    Parse Lynis records such as:

        warning[]=AUTH-9282|Description

        suggestion[]=SSH-7408|Description
    """

    line = line.strip()

    if not line:

        return None

    if line.startswith("#"):

        return None

    is_warning = line.startswith(
        "warning[]="
    )

    is_suggestion = line.startswith(
        "suggestion[]="
    )

    if not (
        is_warning
        or is_suggestion
    ):

        return None

    finding_type = (
        "warning"
        if is_warning
        else "suggestion"
    )

    raw_payload = line.split(
        "=",
        1,
    )[1]

    parts = raw_payload.split(
        "|"
    )

    finding_id = (
        parts[0].strip()
        if parts
        else "UNKNOWN"
    )

    if not finding_id:

        finding_id = "UNKNOWN"

    description = (
        parts[1].strip()
        if len(parts) >= 2
        else raw_payload.strip()
    )

    additional_fields = [
        item.strip()
        for item in parts[2:]
        if item.strip()
    ]

    return {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "description": description,
        "additional_fields": additional_fields,
        "raw_record": raw_payload,
    }


def load_report_findings() -> List[Dict[str, Any]]:
    """
    Load warnings and suggestions from the latest Lynis report.
    """

    if not os.path.exists(
        LYNIS_REPORT_PATH
    ):

        raise RuntimeError(
            f"Lynis report not found at "
            f"{LYNIS_REPORT_PATH}"
        )

    findings: List[
        Dict[str, Any]
    ] = []

    with open(
        LYNIS_REPORT_PATH,
        "r",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line in handle:

            parsed = parse_report_line(
                line
            )

            if parsed:

                findings.append(
                    parsed
                )

    return findings


# ============================================================================
# FINDING-CLASS CLASSIFICATION
# ============================================================================

def classification_text(
    finding_id: str,
    description: str,
) -> str:

    return (
        f"{finding_id} {description}"
    ).lower()


def determine_finding_class(
    finding_id: str,
    description: str,
) -> str:
    """
    Deterministically classify a Lynis finding.

    No Ollama involvement.

    More specific classes are evaluated before the generic
    lynis_hardening fallback.
    """

    text = classification_text(
        finding_id,
        description,
    )

    # ------------------------------------------------------------------
    # Authentication configuration
    # ------------------------------------------------------------------

    authentication_patterns = (
        "authentication",
        "password",
        "password policy",
        "password aging",
        "password expiry",
        "pam",
        "login",
        "logon",
        "permitrootlogin",
        "root login",
        "passwordauthentication",
        "publickeyauthentication",
        "authenticationmethods",
        "account lock",
        "account locking",
        "lockout",
        "faillock",
        "login.defs",
    )

    if any(
        pattern in text
        for pattern in authentication_patterns
    ):

        return "authentication_configuration"

    # ------------------------------------------------------------------
    # Logging configuration
    # ------------------------------------------------------------------

    logging_patterns = (
        "logging",
        "logger",
        "syslog",
        "rsyslog",
        "journald",
        "auditd",
        "audit log",
        "audit logging",
        "log file",
        "log rotation",
        "logrotate",
        "remote logging",
    )

    if any(
        pattern in text
        for pattern in logging_patterns
    ):

        return "logging_configuration"

    # ------------------------------------------------------------------
    # Filesystem configuration
    # ------------------------------------------------------------------

    filesystem_patterns = (
        "filesystem",
        "file system",
        "mount",
        "mountpoint",
        "partition",
        "/tmp",
        "/var/tmp",
        "/home",
        "/dev/shm",
        "nodev",
        "nosuid",
        "noexec",
        "fstab",
        "file permission",
        "permissions",
        "world writable",
        "world-writable",
        "sticky bit",
        "umask",
    )

    if any(
        pattern in text
        for pattern in filesystem_patterns
    ):

        return "filesystem_configuration"

    # ------------------------------------------------------------------
    # Access control configuration
    # ------------------------------------------------------------------

    access_control_patterns = (
        "access control",
        "authorization",
        "authorisation",
        "acl",
        "ownership",
        "owner",
        "group permission",
        "sudoers",
        "sudo ",
        "su ",
        "privilege",
        "privileged",
        "user rights",
        "user permission",
        "file access",
    )

    if any(
        pattern in text
        for pattern in access_control_patterns
    ):

        return "access_control_configuration"

    # ------------------------------------------------------------------
    # Network configuration
    # ------------------------------------------------------------------

    network_patterns = (
        "network",
        "ipv4",
        "ipv6",
        "sysctl",
        "icmp",
        "redirect",
        "source routing",
        "forwarding",
        "tcp syncookies",
        "tcp syn",
        "rp_filter",
        "firewall",
        "iptables",
        "nftables",
        "ufw",
        "packet filtering",
        "network interface",
    )

    if any(
        pattern in text
        for pattern in network_patterns
    ):

        return "network_configuration"

    # ------------------------------------------------------------------
    # Service configuration
    # ------------------------------------------------------------------

    service_patterns = (
        "service",
        "daemon",
        "sshd",
        "ssh ",
        "openssh",
        "apache",
        "nginx",
        "mysql",
        "mariadb",
        "postgresql",
        "postfix",
        "dns",
        "bind",
        "named",
        "ntp",
        "chrony",
        "snmp",
        "ftp",
        "telnet",
        "rpc",
        "cups",
        "samba",
    )

    if any(
        pattern in text
        for pattern in service_patterns
    ):

        return "service_configuration"

    # ------------------------------------------------------------------
    # General security configuration
    # ------------------------------------------------------------------

    security_configuration_patterns = (
        "security configuration",
        "hardening setting",
        "kernel parameter",
        "kernel hardening",
        "core dump",
        "coredump",
        "secure boot",
        "selinux",
        "apparmor",
        "security framework",
        "malware scanner",
        "integrity checker",
        "compiler",
        "usb storage",
        "modprobe",
        "kernel module",
    )

    if any(
        pattern in text
        for pattern in security_configuration_patterns
    ):

        return "security_configuration"

    # ------------------------------------------------------------------
    # Generic Lynis hardening recommendation
    # ------------------------------------------------------------------

    return "lynis_hardening"


# ============================================================================
# UNIFIED SECURITY FINDING
# ============================================================================

def validate_unified_finding(
    payload: Dict[str, Any],
) -> None:
    """
    Validate the part of UnifiedSecurityFinding owned by Lynis.
    """

    for field in REQUIRED_UNIFIED_FINDING_FIELDS:

        if payload.get(field) in (
            None,
            "",
        ):

            raise ValueError(
                f"Unified finding is missing required field: "
                f"{field}"
            )

    if (
        payload["engine_source"]
        != ENGINE_SOURCE
    ):

        raise ValueError(
            f"Lynis findings must use "
            f"engine_source={ENGINE_SOURCE}"
        )

    if (
        payload["finding_category"]
        != FINDING_CATEGORY
    ):

        raise ValueError(
            f"Lynis findings must use "
            f"finding_category={FINDING_CATEGORY}"
        )

    if (
        payload["finding_class"]
        not in VALID_LYNIS_CLASSES
    ):

        raise ValueError(
            f"Invalid Lynis finding_class: "
            f"{payload['finding_class']}"
        )

    if (
        payload["lifecycle_status"]
        not in VALID_LIFECYCLE_STATES
    ):

        raise ValueError(
            f"Invalid lifecycle_status: "
            f"{payload['lifecycle_status']}"
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
                "severity_score must be between 0 and 10"
            )


def build_unified_finding(
    parsed: Dict[str, Any],
    tenant_code: str,
    service_tier: str,
    target_host: str,
    task_name: str = DEFAULT_TASK_NAME,
) -> Dict[str, Any]:
    """
    Convert one parsed Lynis finding into UnifiedSecurityFinding.
    """

    finding_id = parsed[
        "finding_id"
    ]

    finding_type = parsed[
        "finding_type"
    ]

    description = parsed[
        "description"
    ]

    finding_class = determine_finding_class(
        finding_id,
        description,
    )

    metadata = {
        "task_name":
            task_name,

        # This is the scanner-native stable identifier and is useful
        # both for remediation rules and Stage 2 evidence.
        "lynis_test_id":
            finding_id,

        "finding_type":
            finding_type,

        "description":
            description,

        "additional_fields":
            parsed.get(
                "additional_fields",
                [],
            ),

        "raw_record":
            parsed.get(
                "raw_record",
                "",
            ),
    }

    payload = build_common_unified_finding(
        tenant_code=tenant_code,
        tenant_service_tier=service_tier,
        target_host=target_host,
        engine_source=ENGINE_SOURCE,
        finding_category=FINDING_CATEGORY,
        finding_class=finding_class,
        finding_key=finding_id,
        finding_title=(
            f"Lynis "
            f"{finding_type.capitalize()} "
            f"({finding_id})"
        ),
        detected_at=utc_now(),
        compliance_result="FAIL",
        severity_level=None,
        severity_score=None,
        engine_metadata=metadata,
    )

    validate_unified_finding(
        payload
    )

    return payload


# ============================================================================
# SCAN MODE
# ============================================================================

def run_scan_mode(
    tenant_code: str,
    service_tier: str,
    target_host: str,
    filter_mode: str = "warnings_only",
    task_name: Optional[str] = None,
) -> int:
    """
    Run Lynis and write normalised findings to the Wazuh-monitored log.
    """

    tenant_code = str(
        tenant_code
    ).strip()

    target_host = str(
        target_host
    ).strip()

    if not tenant_code:

        raise ValueError(
            "tenant_code cannot be empty"
        )

    if not target_host:

        raise ValueError(
            "target_host cannot be empty"
        )

    service_tier = normalize_service_tier(
        service_tier,
        logger,
    )

    filter_mode = normalize_filter_mode(
        filter_mode
    )

    task_name = normalize_task_name(
        task_name
    )

    logger.info(
        "SCAN mode: "
        "tenant=%s tier=%s target=%s "
        "task=%s filter=%s",
        tenant_code,
        service_tier,
        target_host,
        task_name,
        filter_mode,
    )

    run_lynis_scan()

    parsed_findings = load_report_findings()

    output_findings: List[
        Dict[str, Any]
    ] = []

    seen = set()

    for parsed in parsed_findings:

        if (
            filter_mode == "warnings_only"
            and parsed["finding_type"]
            == "suggestion"
        ):

            continue

        payload = build_unified_finding(
            parsed=parsed,
            tenant_code=tenant_code,
            service_tier=service_tier,
            target_host=target_host,
            task_name=task_name,
        )

        dedup_key = (
            payload["target_host"],
            payload["engine_source"],
            payload["finding_class"],
            payload["finding_key"],
        )

        if dedup_key in seen:

            continue

        seen.add(
            dedup_key
        )

        output_findings.append(
            payload
        )

    log_directory = os.path.dirname(
        LOCAL_COMPLIANCE_LOG
    )

    if log_directory:

        os.makedirs(
            log_directory,
            exist_ok=True,
        )

    with open(
        LOCAL_COMPLIANCE_LOG,
        "a",
        encoding="utf-8",
    ) as log_file:

        for payload in output_findings:

            log_file.write(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )

    logger.info(
        "SCAN mode complete. "
        "Wrote %d Lynis findings to %s.",
        len(output_findings),
        LOCAL_COMPLIANCE_LOG,
    )

    return len(
        output_findings
    )


# ============================================================================
# VERIFY MODE
# ============================================================================

def run_verify_mode(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Perform Stage 2 verification.

    Lynis verification strategy
    ---------------------------

    1. Run a fresh Lynis audit.
    2. Read the newly generated Lynis report.
    3. Search for the original finding_key / Lynis test ID.
    4. If the original key still exists:
           present=True
           Stage 2 FAILS.
    5. If it no longer exists:
           present=False
           Stage 2 PASSES.

    engine_metadata is accepted as part of the common scanner verification
    interface. The current Lynis verification algorithm does not require
    scanner metadata because finding_key is the stable Lynis test ID.
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

    engine_metadata = (
        engine_metadata
        if isinstance(
            engine_metadata,
            dict,
        )
        else {}
    )

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
        not in VALID_LYNIS_CLASSES
    ):

        raise ValueError(
            f"Unsupported Lynis finding_class: "
            f"{finding_class}"
        )

    # If metadata contains the original Lynis test ID, verify that it agrees
    # with finding_key. A mismatch is safer to reject than to verify the wrong
    # condition.
    metadata_test_id = engine_metadata.get(
        "lynis_test_id"
    )

    if (
        metadata_test_id
        and str(metadata_test_id).strip().lower()
        != finding_key.lower()
    ):

        raise ValueError(
            "engine_metadata.lynis_test_id does not match "
            "the requested finding_key"
        )

    logger.info(
        "VERIFY mode: "
        "target=%s key=%s class=%s",
        target_host,
        finding_key,
        finding_class,
    )

    # Stage 2 must always use a fresh scanner result.
    run_lynis_scan()

    parsed_findings = load_report_findings()

    matches: List[
        Dict[str, Any]
    ] = []

    for parsed in parsed_findings:

        current_key = str(
            parsed["finding_id"]
        ).strip()

        if (
            current_key.lower()
            != finding_key.lower()
        ):

            continue

        current_class = determine_finding_class(
            current_key,
            parsed["description"],
        )

        matches.append(
            {
                "finding_key":
                    current_key,

                "current_finding_class":
                    current_class,

                "requested_finding_class":
                    finding_class,

                "finding_type":
                    parsed["finding_type"],

                "description":
                    parsed["description"],

                "additional_fields":
                    parsed.get(
                        "additional_fields",
                        [],
                    ),
            }
        )

    # The finding key is the authoritative identity.
    #
    # If classification has changed slightly after a new Lynis version or
    # wording change, but the same test ID is still present, we must NOT
    # incorrectly treat the issue as resolved.
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
            ENGINE_SOURCE,

        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence": {
            "lynis_test_id":
                finding_key,

            "match_count":
                len(matches),

            "matching_findings":
                matches,

            "report_path":
                LYNIS_REPORT_PATH,
        },
    }

    logger.info(
        "VERIFY mode complete: "
        "target=%s key=%s present=%s",
        target_host,
        finding_key,
        present,
    )

    return verification_result


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """
    Canonical scanner orchestrator CLI.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Lynis compliance/hardening orchestrator"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "scan",
            "verify",
        ],
        default=None,
    )

    # ------------------------------------------------------------------
    # Scan-mode arguments
    # ------------------------------------------------------------------

    parser.add_argument(
        "--tenant-code"
    )

    parser.add_argument(
        "--service-tier"
    )

    # target_host is used by both modes.
    parser.add_argument(
        "--target-host"
    )

    parser.add_argument(
        "--filter-mode",
        default="warnings_only",
    )

    parser.add_argument(
        "--task-name",
        default=None,
        help=(
            "Optional metadata label. "
            f"Defaults to '{DEFAULT_TASK_NAME}'."
        ),
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
    )

    # ------------------------------------------------------------------
    # Verification-mode arguments
    # ------------------------------------------------------------------

    parser.add_argument(
        "--finding-key"
    )

    parser.add_argument(
        "--finding-class"
    )

    # This argument is now part of the common Stage 2 scanner contract.
    parser.add_argument(
        "--engine-metadata-json",
        default=None,
        help=(
            "Original finding engine_metadata serialised as JSON. "
            "Accepted for compatibility with verification_dispatcher.py."
        ),
    )

    parser.add_argument(
        "--verification-request-stdin",
        action="store_true",
        help=(
            "Read the canonical Stage-2 verification request "
            "as one JSON object from stdin."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Return machine-readable JSON. "
            "Used by verification_gateway.py."
        ),
    )

    return parser


# ============================================================================
# LEGACY COMPATIBILITY
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Support both the current explicit interface and the previous positional
    scan invocation.

    New scan:

        script.py \
          --mode scan \
          --tenant-code CUSTOMER \
          --service-tier STANDARD \
          --target-host 10.0.0.1

    New verification:

        script.py \
          --mode verify \
          --target-host 10.0.0.1 \
          --finding-key AUTH-9282 \
          --finding-class authentication_configuration \
          --engine-metadata-json '{"lynis_test_id":"AUTH-9282"}' \
          --json

    Legacy scan:

        script.py CUSTOMER STANDARD 10.0.0.1

    Optional fourth positional argument:

        warnings_only
    """

    if (
        len(sys.argv) >= 4
        and not sys.argv[1].startswith("-")
    ):

        args = argparse.Namespace()

        args.mode = "scan"

        args.tenant_code = sys.argv[1]

        args.service_tier = sys.argv[2]

        args.target_host = sys.argv[3]

        args.filter_mode = "warnings_only"

        args.task_name = None

        args.verbose = False

        args.finding_key = None

        args.finding_class = None

        args.engine_metadata_json = None

        args.json = False

        if len(sys.argv) >= 5:

            argument = (
                sys.argv[4]
                .strip()
                .lower()
            )

            if argument in {
                "--verbose",
                "verbose",
                "-v",
            }:

                args.verbose = True

            else:

                args.filter_mode = argument

        if len(sys.argv) >= 6:

            argument = (
                sys.argv[5]
                .strip()
                .lower()
            )

            if argument in {
                "--verbose",
                "verbose",
                "-v",
            }:

                args.verbose = True

        return args

    parser = build_parser()

    args = parser.parse_args()

    if not args.mode:

        parser.error(
            "--mode is required when using "
            "the new command-line interface."
        )

    return args


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    global logger

    args = parse_arguments()

    if (
        getattr(
            args,
            "verification_request_stdin",
            False,
        )
    ):
        if (
            getattr(
                args,
                "mode",
                None,
            )
            != "verify"
        ):
            raise ValueError(
                "--verification-request-stdin is valid only "
                "with --mode verify"
            )

        verification_request = (
            read_verification_request()
        )

        args.target_host = (
            verification_request[
                "target_host"
            ]
        )

        args.finding_key = (
            verification_request[
                "finding_key"
            ]
        )

        args.finding_class = (
            verification_request[
                "finding_class"
            ]
        )

        args.engine_metadata_json = (
            verification_request[
                "engine_metadata_json"
            ]
        )

    logger = setup_logging(
        getattr(
            args,
            "verbose",
            False,
        )
    )

    if os.geteuid() != 0:

        logger.error(
            "Lynis orchestrator must run as root."
        )

        if (
            getattr(
                args,
                "mode",
                None,
            )
            == "verify"
        ):

            # Verification failures always fail closed.
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
                            ENGINE_SOURCE,

                        "target_host":
                            getattr(
                                args,
                                "target_host",
                                None,
                            ),

                        "verified_at":
                            utc_now(),

                        "verification_error":
                            (
                                "Lynis orchestrator "
                                "must run as root"
                            ),

                        "evidence":
                            {},
                    },
                    separators=(",", ":"),
                )
            )

        return 1

    try:

        # ==============================================================
        # SCAN MODE
        # ==============================================================

        if args.mode == "scan":

            missing = [
                name
                for name, value in (
                    (
                        "--tenant-code",
                        args.tenant_code,
                    ),
                    (
                        "--service-tier",
                        args.service_tier,
                    ),
                    (
                        "--target-host",
                        args.target_host,
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

            total = run_scan_mode(
                tenant_code=(
                    args.tenant_code
                ),

                service_tier=(
                    args.service_tier
                ),

                target_host=(
                    args.target_host
                ),

                filter_mode=(
                    args.filter_mode
                ),

                task_name=(
                    args.task_name
                ),
            )

            if args.json:

                print(
                    json.dumps(
                        {
                            "mode":
                                "scan",

                            "scanner":
                                ENGINE_SOURCE,

                            "findings_written":
                                total,

                            "output":
                                LOCAL_COMPLIANCE_LOG,
                        },
                        separators=(",", ":"),
                    )
                )

            else:

                print(
                    "[SUCCESS] Lynis scan completed. "
                    f"Logged {total} finding(s)."
                )

            return 0

        # ==============================================================
        # VERIFY MODE
        # ==============================================================

        missing = [
            name
            for name, value in (
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

        # This is supplied by verification_dispatcher.py.
        engine_metadata = parse_json_object(
            args.engine_metadata_json
        )

        result = run_verify_mode(
            target_host=(
                args.target_host
            ),

            finding_key=(
                args.finding_key
            ),

            finding_class=(
                args.finding_class
            ),

            engine_metadata=(
                engine_metadata
            ),
        )

        # verification_gateway.py expects stdout to contain exactly
        # one JSON object.
        print(
            json.dumps(
                result,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )

        return 0

    except Exception as exc:

        logger.exception(
            "Lynis orchestrator failed: %s",
            exc,
        )

        # ==============================================================
        # FAIL-CLOSED VERIFICATION
        # ==============================================================

        if (
            getattr(
                args,
                "mode",
                None,
            )
            == "verify"
        ):

            # Failure to perform verification must NEVER be interpreted as:
            #
            #     finding absent
            #     Stage 2 passed
            #
            # Therefore present remains True.
            error_result = {
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
                    ENGINE_SOURCE,

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

            print(
                json.dumps(
                    error_result,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )

        return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
