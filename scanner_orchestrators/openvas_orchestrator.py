#!/usr/bin/env python3
"""
Regis Security Consulting
OpenVAS / Greenbone Scan Orchestrator and Webhook Listener

===========================================================================
ARCHITECTURE
===========================================================================

This component supports three invocation patterns.

1. WEBHOOK / NORMAL SCAN INGESTION
----------------------------------

OpenVAS/GVMD calls:

    http://127.0.0.1:8080/?task=BANKER-LTD__GOLD__Daily_External_Scan

The listener:

    - receives ONLY the task name;
    - derives tenant information from the task name;
    - finds the task in GVMD;
    - obtains its latest report;
    - normalises findings to UnifiedSecurityFinding;
    - determines finding_class;
    - writes findings to /var/log/scanners_raw.log.

Tenant information MUST NOT be supplied independently through query parameters.

Canonical task-name format:

    <TENANT_CODE>__<SERVICE_TIER>__<SCAN_NAME>

Example:

    BANKER-LTD__GOLD__Daily_External_Scan

becomes:

    tenant_code         = BANKER-LTD
    tenant_service_tier = GOLD
    scan_name           = Daily_External_Scan


2. MANUAL SCAN/REPORT PROCESSING
--------------------------------

The latest completed report for an existing task can also be processed manually:

    python3 openvas_orchestrator.py \
        --mode scan \
        --task-name BANKER-LTD__GOLD__Daily_External_Scan


3. STAGE 2 VERIFICATION
-----------------------

verification_dispatcher.py calls:

    python3 openvas_orchestrator.py \
        --mode verify \
        --target-host 10.20.30.15 \
        --finding-key 'CVE-2023-1234' \
        --finding-class network_service_vulnerability \
        --engine-metadata-json '{...}' \
        --json

Verification mode:

    - locates the ORIGINAL OpenVAS task using engine_metadata.task_name;
    - starts a fresh run of that task;
    - waits for completion;
    - retrieves the fresh report;
    - searches specifically for the original finding;
    - DOES NOT write findings to scanners_raw.log;
    - returns exactly one JSON object to stdout.

The result contract is:

    {
        "present": false,
        "finding_key": "...",
        "finding_class": "...",
        "scanner": "openvas",
        "target_host": "...",
        "verified_at": "...",
        "evidence": {}
    }

present=false
    Stage 2 PASSED. The original finding was not rediscovered.

present=true
    Stage 2 FAILED. The original finding still exists.

Verification fails closed. Scanner/GVMD errors never produce present=false.


===========================================================================
OPENVAS FINDING CLASSES
===========================================================================

This orchestrator uses only these established canonical finding classes:

    cve
    network_service_vulnerability
    network_service_exposure
    weak_cryptography
    insecure_protocol
    service_misconfiguration
    default_credentials
    authentication_weakness
    certificate_issue
    unsupported_software

No new finding classes are introduced here.
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Set, Tuple

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp


# ============================================================================
# CONFIGURATION
# ============================================================================

PORT = int(
    os.getenv(
        "REGIS_OPENVAS_WEBHOOK_PORT",
        "8080",
    )
)

LISTEN_HOST = os.getenv(
    "REGIS_OPENVAS_WEBHOOK_HOST",
    "127.0.0.1",
)

LOCAL_LOG_PATH = os.getenv(
    "REGIS_SCANNER_RAW_LOG",
    "/var/log/scanners_raw.log",
)

GVMD_SOCKET_PATH = os.getenv(
    "REGIS_GVMD_SOCKET",
    "/var/run/gvmd/gvmd.sock",
)

# Preserve the currently working GVMD authentication arrangement.
OPENVAS_USER = os.getenv(
    "REGIS_OPENVAS_USER",
)

OPENVAS_PASS = os.getenv(
    "REGIS_OPENVAS_PASSWORD",
)

if not OPENVAS_USER or not OPENVAS_PASS:
    raise RuntimeError(
        "OpenVAS credentials are required. "
        "Set REGIS_OPENVAS_USER and REGIS_OPENVAS_PASSWORD."
    )

LOG_DIR = os.getenv(
    "REGIS_LOG_DIR",
    "/var/log/regis-security",
)

LOG_PATH = os.path.join(
    LOG_DIR,
    "openvas_orchestrator.log",
)

ERROR_LOG_PATH = os.path.join(
    LOG_DIR,
    "openvas_orchestrator.error.log",
)

VERIFY_POLL_INTERVAL = int(
    os.getenv(
        "REGIS_OPENVAS_VERIFY_POLL_INTERVAL",
        "15",
    )
)

VERIFY_TIMEOUT = int(
    os.getenv(
        "REGIS_OPENVAS_VERIFY_TIMEOUT",
        "3600",
    )
)

# A verification run may itself trigger the configured GVMD webhook.
#
# We remember such task names for this period so the callback is ignored
# rather than being ingested as a brand-new scan.
VERIFY_CALLBACK_SUPPRESSION_SECONDS = int(
    os.getenv(
        "REGIS_OPENVAS_VERIFY_SUPPRESSION_SECONDS",
        "7200",
    )
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_SERVICE_TIERS = {
    "GOLD",
    "STANDARD",
    "BRONZE",
}

VALID_OPENVAS_FINDING_CLASSES = {
    "cve",
    "network_service_vulnerability",
    "network_service_exposure",
    "weak_cryptography",
    "insecure_protocol",
    "service_misconfiguration",
    "default_credentials",
    "authentication_weakness",
    "certificate_issue",
    "unsupported_software",
}

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)


# ============================================================================
# VERIFICATION CALLBACK SUPPRESSION
# ============================================================================

_verification_tasks: Dict[str, float] = {}
_verification_tasks_lock = threading.Lock()


def suppress_ingestion_for_verification_task(
    task_name: str,
) -> None:
    """
    Mark an OpenVAS task as temporarily belonging to Stage 2 verification.

    If GVMD subsequently calls the normal webhook for this task, the webhook
    acknowledges it but does not write the verification report into the
    normal finding-ingestion pipeline.
    """

    expires_at = (
        time.time()
        + VERIFY_CALLBACK_SUPPRESSION_SECONDS
    )

    with _verification_tasks_lock:
        _verification_tasks[task_name] = expires_at


def is_verification_task_suppressed(
    task_name: str,
) -> bool:

    now = time.time()

    with _verification_tasks_lock:

        expired = [
            name
            for name, expiry
            in _verification_tasks.items()
            if expiry <= now
        ]

        for name in expired:
            _verification_tasks.pop(
                name,
                None,
            )

        expiry = _verification_tasks.get(
            task_name
        )

        return bool(
            expiry
            and expiry > now
        )


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging() -> logging.Logger:

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "openvas_orchestrator"
    )

    logger.setLevel(
        logging.INFO
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    app_handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )

    app_handler.setFormatter(
        formatter
    )

    app_handler.setLevel(
        logging.INFO
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

    # Logging goes to STDERR.
    #
    # Verification mode reserves STDOUT for exactly one JSON object.
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
        app_handler
    )

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

def utc_now() -> str:

    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()


def clean_text(
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


def get_node_text(
    node: ET.Element,
    path: str,
    default: str = "",
) -> str:

    target = node.find(
        path
    )

    if (
        target is not None
        and target.text is not None
    ):

        return target.text.strip()

    return default


def parse_engine_metadata(
    value: Optional[str],
) -> Dict[str, Any]:

    if not value:
        return {}

    data = json.loads(
        value
    )

    if not isinstance(
        data,
        dict,
    ):

        raise ValueError(
            "engine_metadata must be a JSON object"
        )

    return data


# ============================================================================
# TASK NAME -> TENANT IDENTITY
# ============================================================================

def parse_task_identity(
    task_name: str,
) -> Tuple[str, str, str]:
    """
    Task naming convention:

        TENANT_CODE__SERVICE_TIER__SCAN_NAME

    Example:

        BANKER-LTD__GOLD__Daily_External_Scan

    becomes:

        BANKER-LTD
        GOLD
        Daily_External_Scan

    Tenant data is never accepted independently from the webhook query.
    """

    task_name = str(
        task_name or ""
    ).strip()

    if not task_name:

        raise ValueError(
            "OpenVAS task name is empty"
        )

    parts = task_name.split(
        "__",
        2,
    )

    if len(parts) != 3:

        raise ValueError(
            "Invalid OpenVAS task name. Expected "
            "TENANT_CODE__SERVICE_TIER__SCAN_NAME; "
            f"received: {task_name}"
        )

    tenant_code = parts[0].strip()

    service_tier = parts[1].strip().upper()

    scan_name = parts[2].strip()

    if not tenant_code:

        raise ValueError(
            f"Task {task_name!r} contains an empty tenant code"
        )

    if service_tier not in VALID_SERVICE_TIERS:

        raise ValueError(
            f"Task {task_name!r} contains unsupported "
            f"service tier {service_tier!r}"
        )

    if not scan_name:

        raise ValueError(
            f"Task {task_name!r} contains an empty scan name"
        )

    return (
        tenant_code,
        service_tier,
        scan_name,
    )


# ============================================================================
# SEVERITY
# ============================================================================

def normalise_severity(
    cvss_value: Any,
) -> Tuple[str, float]:

    try:

        score = float(
            cvss_value
        )

    except (
        ValueError,
        TypeError,
    ):

        score = 0.0

    score = max(
        0.0,
        min(
            10.0,
            score,
        ),
    )

    if score >= 9.0:
        return "CRITICAL", score

    if score >= 7.0:
        return "HIGH", score

    if score >= 4.0:
        return "MEDIUM", score

    return "LOW", score


# ============================================================================
# NVT / CVE EXTRACTION
# ============================================================================

def extract_nvt_oid(
    result: ET.Element,
) -> Optional[str]:

    nvt = result.find(
        "./nvt"
    )

    if nvt is None:
        return None

    oid = nvt.get(
        "oid"
    )

    if not oid:
        return None

    return oid.strip()


def extract_cves(
    result: ET.Element,
) -> List[str]:
    """
    Greenbone versions/report formats can expose CVEs differently.

    We therefore inspect:
      - NVT CVE text fields
      - refs/ref attributes/text
      - name/description text

    and normalise everything through the CVE regex.
    """

    values: Set[str] = set()

    nvt = result.find(
        "./nvt"
    )

    text_parts: List[str] = []

    if nvt is not None:

        for possible_path in (
            "./cve",
            "./name",
            "./tags",
        ):

            value = get_node_text(
                nvt,
                possible_path,
                "",
            )

            if value:
                text_parts.append(
                    value
                )

        for ref in nvt.findall(
            ".//ref"
        ):

            ref_type = (
                ref.get("type")
                or ""
            ).lower()

            ref_id = (
                ref.get("id")
                or ""
            )

            ref_text = (
                ref.text
                or ""
            )

            if (
                ref_type == "cve"
                or "cve-" in ref_id.lower()
                or "cve-" in ref_text.lower()
            ):

                text_parts.extend(
                    [
                        ref_id,
                        ref_text,
                    ]
                )

    text_parts.extend(
        [
            get_node_text(
                result,
                "./name",
                "",
            ),
            get_node_text(
                result,
                "./description",
                "",
            ),
        ]
    )

    combined = " ".join(
        text_parts
    )

    for match in CVE_PATTERN.findall(
        combined
    ):

        values.add(
            match.upper()
        )

    return sorted(
        values
    )


# ============================================================================
# FINDING CLASSIFICATION
# ============================================================================

def determine_finding_class(
    vuln_name: str,
    description: str,
    scanned_port: str,
    cves: List[str],
) -> str:
    """
    Deterministically map an OpenVAS NVT result to one of the existing
    canonical OpenVAS finding classes.

    Precedence matters: highly specific problem types are chosen before
    the generic network_service_vulnerability/cve classes.
    """

    text = (
        f"{vuln_name} "
        f"{description} "
        f"{scanned_port}"
    ).lower()

    # ------------------------------------------------------------------
    # Default/factory credentials
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "default credential",
            "default credentials",
            "default password",
            "default username",
            "factory password",
            "factory credential",
            "known default password",
        )
    ):

        return "default_credentials"

    # ------------------------------------------------------------------
    # Authentication weakness
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "authentication bypass",
            "authentication weakness",
            "weak authentication",
            "anonymous login",
            "anonymous access",
            "authentication disabled",
            "no authentication",
        )
    ):

        return "authentication_weakness"

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "certificate expired",
            "expired certificate",
            "self-signed certificate",
            "self signed certificate",
            "certificate hostname mismatch",
            "certificate name mismatch",
            "untrusted certificate",
            "invalid certificate",
            "certificate issue",
        )
    ):

        return "certificate_issue"

    # ------------------------------------------------------------------
    # Weak cryptography
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "weak cipher",
            "weak ciphers",
            "weak encryption",
            "weak cryptograph",
            "rc4",
            "3des",
            "triple des",
            "des cipher",
            "weak dh",
            "weak diffie",
            "weak key exchange",
        )
    ):

        return "weak_cryptography"

    # ------------------------------------------------------------------
    # Insecure/deprecated protocol
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "sslv2",
            "ssl v2",
            "sslv3",
            "ssl v3",
            "tls 1.0",
            "tlsv1.0",
            "tls 1.1",
            "tlsv1.1",
            "telnet",
            "cleartext protocol",
            "clear-text protocol",
            "unencrypted protocol",
            "insecure protocol",
            "obsolete protocol",
        )
    ):

        return "insecure_protocol"

    # ------------------------------------------------------------------
    # Unsupported / EOL software
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "end of life",
            "end-of-life",
            "eol",
            "unsupported version",
            "unsupported software",
            "no longer supported",
            "obsolete software",
        )
    ):

        return "unsupported_software"

    # ------------------------------------------------------------------
    # Service exposure
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "service exposed",
            "exposed service",
            "administration interface exposed",
            "administrative interface exposed",
            "management interface exposed",
            "database exposed",
            "unrestricted access",
        )
    ):

        return "network_service_exposure"

    # ------------------------------------------------------------------
    # Service misconfiguration
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "misconfiguration",
            "misconfigured",
            "insecure configuration",
            "configuration weakness",
            "directory listing",
            "http trace enabled",
            "unsafe method",
            "unrestricted relay",
        )
    ):

        return "service_misconfiguration"

    # ------------------------------------------------------------------
    # Generic OpenVAS vulnerability
    # ------------------------------------------------------------------

    # OpenVAS is predominantly evaluating a remotely reachable service.
    # A port-bearing vulnerability is therefore classified as a network
    # service vulnerability rather than losing that useful context.
    if (
        scanned_port
        and scanned_port.lower()
        not in (
            "",
            "general",
            "0",
        )
    ):

        return "network_service_vulnerability"

    if cves:
        return "cve"

    return "network_service_vulnerability"


# ============================================================================
# STABLE FINDING KEY
# ============================================================================

def build_finding_key(
    cves: List[str],
    nvt_oid: Optional[str],
    scanned_port: str,
    vuln_name: str,
) -> str:
    """
    OpenVAS result UUIDs are scan-instance IDs and are not suitable as the
    persistent security finding identity.

    Prefer:

        CVE

    otherwise:

        OPENVAS-NVT:<OID>@<PORT>

    and finally a deterministic name/port fallback.

    CVEs remain directly usable by specific remediation-rule patterns.
    """

    if cves:
        return cves[0]

    if nvt_oid:

        return (
            f"OPENVAS-NVT:{nvt_oid}"
            f"@{scanned_port or 'general'}"
        )

    clean_name = re.sub(
        r"[^A-Za-z0-9_.:-]+",
        "_",
        vuln_name,
    ).strip("_")

    return (
        f"OPENVAS:{clean_name}"
        f"@{scanned_port or 'general'}"
    )


# ============================================================================
# GMP HELPERS
# ============================================================================

def open_gmp() -> Tuple[
    UnixSocketConnection,
    Gmp,
]:
    """
    Retained as a helper primarily for documentation.

    Callers use the normal context-manager pattern directly because Gmp
    owns the connection lifecycle.
    """

    connection = UnixSocketConnection(
        path=GVMD_SOCKET_PATH
    )

    return (
        connection,
        Gmp(
            connection=connection
        ),
    )


def find_task_by_name(
    gmp: Gmp,
    task_name: str,
) -> ET.Element:
    """
    Preserve the existing, known-working task lookup behaviour.
    """

    tasks_xml = gmp.get_tasks()

    root = ET.fromstring(
        tasks_xml
    )

    for task in root.findall(
        ".//task"
    ):

        name_node = task.find(
            "./name"
        )

        if (
            name_node is not None
            and name_node.text
            and name_node.text.strip()
            == task_name
        ):

            return task

    raise RuntimeError(
        f"OpenVAS task named {task_name!r} "
        "was not found through GMP"
    )


def get_task_id(
    task: ET.Element,
) -> str:

    task_id = task.get(
        "id"
    )

    if not task_id:

        raise RuntimeError(
            "OpenVAS task does not contain an ID"
        )

    return task_id


def get_latest_report_id_from_task(
    task: ET.Element,
) -> str:

    report = task.find(
        "./last_report/report"
    )

    if report is None:

        raise RuntimeError(
            "OpenVAS task does not yet have a last report"
        )

    report_id = report.get(
        "id"
    )

    if not report_id:

        raise RuntimeError(
            "OpenVAS last_report element has no report ID"
        )

    return report_id


def fetch_report(
    gmp: Gmp,
    report_id: str,
) -> ET.Element:

    report_xml = gmp.get_report(
        report_id=report_id
    )

    return ET.fromstring(
        report_xml
    )


def get_current_task_status(
    gmp: Gmp,
    task_id: str,
) -> Tuple[str, ET.Element]:

    task_xml = gmp.get_task(
        task_id=task_id
    )

    root = ET.fromstring(
        task_xml
    )

    task = root.find(
        ".//task"
    )

    if task is None:

        raise RuntimeError(
            f"Unable to read task {task_id} from GVMD"
        )

    status = get_node_text(
        task,
        "./status",
        "",
    )

    return (
        status,
        task,
    )


def start_task_and_wait(
    gmp: Gmp,
    task_id: str,
    task_name: str,
) -> str:
    """
    Run the existing OpenVAS task and wait synchronously for completion.

    Used only for Stage 2 verification.
    """

    suppress_ingestion_for_verification_task(
        task_name
    )

    logger.info(
        "Starting OpenVAS Stage 2 verification task: "
        "%s (%s)",
        task_name,
        task_id,
    )

    gmp.start_task(
        task_id=task_id
    )

    deadline = (
        time.time()
        + VERIFY_TIMEOUT
    )

    last_status = None

    while time.time() < deadline:

        status, task = get_current_task_status(
            gmp,
            task_id,
        )

        if status != last_status:

            logger.info(
                "Verification task %s status: %s",
                task_name,
                status,
            )

            last_status = status

        normalised_status = (
            status or ""
        ).strip().lower()

        if normalised_status == "done":

            return get_latest_report_id_from_task(
                task
            )

        if normalised_status in {
            "stopped",
            "interrupted",
            "delete requested",
        }:

            raise RuntimeError(
                f"Verification task {task_name!r} "
                f"terminated with status {status!r}"
            )

        time.sleep(
            VERIFY_POLL_INTERVAL
        )

    raise TimeoutError(
        f"OpenVAS verification task {task_name!r} "
        f"did not finish within {VERIFY_TIMEOUT} seconds"
    )


# ============================================================================
# RESULT NORMALISATION
# ============================================================================

def normalise_result(
    result: ET.Element,
    tenant_code: str,
    service_tier: str,
    scan_name: str,
    task_name: str,
    task_id: str,
    report_id: str,
) -> Dict[str, Any]:

    target_host = get_node_text(
        result,
        "./host",
        "",
    )

    if not target_host:

        raise ValueError(
            "OpenVAS result does not contain a target host"
        )

    scanned_port = get_node_text(
        result,
        "./port",
        "general",
    )

    vuln_name = get_node_text(
        result,
        "./name",
        "Generic OpenVAS Finding",
    )

    raw_cvss = get_node_text(
        result,
        "./nvt/cvss_base",
        "0.0",
    )

    description = get_node_text(
        result,
        "./description",
        "No details provided.",
    )

    nvt_oid = extract_nvt_oid(
        result
    )

    cves = extract_cves(
        result
    )

    severity_level, severity_score = (
        normalise_severity(
            raw_cvss
        )
    )

    finding_class = determine_finding_class(
        vuln_name=vuln_name,
        description=description,
        scanned_port=scanned_port,
        cves=cves,
    )

    finding_key = build_finding_key(
        cves=cves,
        nvt_oid=nvt_oid,
        scanned_port=scanned_port,
        vuln_name=vuln_name,
    )

    metadata: Dict[str, Any] = {
        "task_name":
            task_name,

        "scan_name":
            scan_name,

        "openvas_task_id":
            task_id,

        "openvas_report_id":
            report_id,

        "openvas_result_id":
            result.get("id"),

        # Essential for precise Stage 2 matching.
        "nvt_oid":
            nvt_oid,

        "scanned_port":
            scanned_port,

        "cves":
            cves,

        "primary_cve":
            cves[0]
            if cves
            else None,

        "description":
            description[:8000],

        "requires_gmp_fetch":
            False,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value not in (
            None,
            "",
            [],
        )
    }

    payload = {
        "tenant_code":
            tenant_code,

        "tenant_service_tier":
            service_tier,

        "target_host":
            target_host,

        "engine_source":
            "openvas",

        "finding_category":
            "vulnerability",

        "finding_class":
            finding_class,

        "finding_key":
            finding_key,

        "finding_title":
            vuln_name,

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

        # Ollama enrichment has not yet occurred.
        "ai_analysis":
            None,
    }

    return payload


# ============================================================================
# REPORT INGESTION
# ============================================================================

def process_completed_task(
    task_name: str,
) -> int:
    """
    Parse the most recent report for a completed task and write normalised
    findings into scanners_raw.log.
    """

    tenant_code, service_tier, scan_name = (
        parse_task_identity(
            task_name
        )
    )

    logger.info(
        "Processing OpenVAS task %s "
        "(tenant=%s tier=%s scan=%s)",
        task_name,
        tenant_code,
        service_tier,
        scan_name,
    )

    connection = UnixSocketConnection(
        path=GVMD_SOCKET_PATH
    )

    with Gmp(
        connection=connection
    ) as gmp:

        gmp.authenticate(
            username=OPENVAS_USER,
            password=OPENVAS_PASS,
        )

        task = find_task_by_name(
            gmp,
            task_name,
        )

        task_id = get_task_id(
            task
        )

        report_id = (
            get_latest_report_id_from_task(
                task
            )
        )

        logger.info(
            "Latest report for %s: %s",
            task_name,
            report_id,
        )

        report_root = fetch_report(
            gmp,
            report_id,
        )

    results = report_root.findall(
        ".//result"
    )

    logger.info(
        "Parsing %d OpenVAS result records.",
        len(results),
    )

    normalised: List[
        Dict[str, Any]
    ] = []

    seen: Set[
        Tuple[str, str, str]
    ] = set()

    for result in results:

        try:

            finding = normalise_result(
                result=result,
                tenant_code=tenant_code,
                service_tier=service_tier,
                scan_name=scan_name,
                task_name=task_name,
                task_id=task_id,
                report_id=report_id,
            )

        except Exception as exc:

            logger.warning(
                "Skipping malformed OpenVAS result %s: %s",
                result.get("id"),
                exc,
            )

            continue

        dedup_key = (
            finding["target_host"],
            finding["finding_class"],
            finding["finding_key"],
        )

        if dedup_key in seen:
            continue

        seen.add(
            dedup_key
        )

        normalised.append(
            finding
        )

    if not normalised:

        logger.info(
            "No OpenVAS findings were written for task %s.",
            task_name,
        )

        return 0

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

        for record in normalised:

            handle.write(
                json.dumps(
                    record,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )

    logger.info(
        "Successfully wrote %d OpenVAS findings to %s.",
        len(normalised),
        LOCAL_LOG_PATH,
    )

    return len(
        normalised
    )


# ============================================================================
# STAGE 2 FINDING MATCHING
# ============================================================================

def result_matches_original_finding(
    result: ET.Element,
    target_host: str,
    finding_key: str,
    original_nvt_oid: Optional[str],
    original_port: Optional[str],
) -> bool:
    """
    Determine whether an OpenVAS result represents the ORIGINAL finding.

    Matching precedence:

      target host MUST match.

      Then prefer original NVT OID because that is the OpenVAS/NVT identity.

      If a CVE is present in finding_key, match the CVE as well.

      If the original port is known, require the same port.

    This is deliberately stricter than searching only by title.
    """

    current_host = get_node_text(
        result,
        "./host",
        "",
    )

    if current_host != target_host:
        return False

    current_port = get_node_text(
        result,
        "./port",
        "general",
    )

    if (
        original_port
        and current_port != original_port
    ):

        return False

    current_oid = extract_nvt_oid(
        result
    )

    current_cves = extract_cves(
        result
    )

    finding_key_upper = (
        finding_key.upper()
    )

    requested_cves = CVE_PATTERN.findall(
        finding_key_upper
    )

    # Strongest identity: same NVT.
    if original_nvt_oid:

        if current_oid != original_nvt_oid:
            return False

        # If the original finding also carried a CVE, require it too.
        if requested_cves:

            return any(
                cve.upper()
                in {
                    item.upper()
                    for item
                    in current_cves
                }
                for cve
                in requested_cves
            )

        return True

    # No OID available: use CVE.
    if requested_cves:

        current_set = {
            item.upper()
            for item in current_cves
        }

        return any(
            cve.upper()
            in current_set
            for cve in requested_cves
        )

    # Last fallback: reconstruct the same stable key.
    vuln_name = get_node_text(
        result,
        "./name",
        "Generic OpenVAS Finding",
    )

    current_key = build_finding_key(
        cves=current_cves,
        nvt_oid=current_oid,
        scanned_port=current_port,
        vuln_name=vuln_name,
    )

    return (
        current_key.lower()
        == finding_key.lower()
    )


# ============================================================================
# STAGE 2 VERIFICATION
# ============================================================================

def run_verification(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Dict[str, Any],
) -> Dict[str, Any]:

    if (
        finding_class
        not in VALID_OPENVAS_FINDING_CLASSES
    ):

        raise ValueError(
            "Unsupported OpenVAS finding_class: "
            f"{finding_class}"
        )

    task_name = engine_metadata.get(
        "task_name"
    )

    if not task_name:

        raise ValueError(
            "OpenVAS Stage 2 verification requires "
            "engine_metadata.task_name"
        )

    # Also validates tenant/tier naming format.
    parse_task_identity(
        task_name
    )

    original_nvt_oid = engine_metadata.get(
        "nvt_oid"
    )

    original_port = engine_metadata.get(
        "scanned_port"
    )

    logger.info(
        "Starting OpenVAS Stage 2 verification: "
        "target=%s key=%s class=%s task=%s oid=%s port=%s",
        target_host,
        finding_key,
        finding_class,
        task_name,
        original_nvt_oid,
        original_port,
    )

    connection = UnixSocketConnection(
        path=GVMD_SOCKET_PATH
    )

    with Gmp(
        connection=connection
    ) as gmp:

        gmp.authenticate(
            username=OPENVAS_USER,
            password=OPENVAS_PASS,
        )

        task = find_task_by_name(
            gmp,
            task_name,
        )

        task_id = get_task_id(
            task
        )

        # A fresh OpenVAS scan is intentionally performed here.
        report_id = start_task_and_wait(
            gmp=gmp,
            task_id=task_id,
            task_name=task_name,
        )

        logger.info(
            "Verification report completed: %s",
            report_id,
        )

        report_root = fetch_report(
            gmp,
            report_id,
        )

    matches: List[
        Dict[str, Any]
    ] = []

    for result in report_root.findall(
        ".//result"
    ):

        if not result_matches_original_finding(
            result=result,
            target_host=target_host,
            finding_key=finding_key,
            original_nvt_oid=original_nvt_oid,
            original_port=original_port,
        ):

            continue

        matches.append(
            {
                "openvas_result_id":
                    result.get("id"),

                "nvt_oid":
                    extract_nvt_oid(
                        result
                    ),

                "port":
                    get_node_text(
                        result,
                        "./port",
                        "general",
                    ),

                "name":
                    get_node_text(
                        result,
                        "./name",
                        "",
                    ),

                "cves":
                    extract_cves(
                        result
                    ),

                "severity":
                    get_node_text(
                        result,
                        "./nvt/cvss_base",
                        "0.0",
                    ),
            }
        )

    present = bool(
        matches
    )

    result = {
        "present":
            present,

        "finding_key":
            finding_key,

        "finding_class":
            finding_class,

        "scanner":
            "openvas",

        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence": {
            "task_name":
                task_name,

            "openvas_task_id":
                task_id,

            "openvas_report_id":
                report_id,

            "nvt_oid":
                original_nvt_oid,

            "scanned_port":
                original_port,

            "match_count":
                len(matches),

            "matches":
                matches,
        },
    }

    logger.info(
        "OpenVAS Stage 2 complete: "
        "target=%s key=%s present=%s matches=%d",
        target_host,
        finding_key,
        present,
        len(matches),
    )

    return result


# ============================================================================
# WEBHOOK BACKGROUND WORKER
# ============================================================================

def webhook_worker(
    task_name: str,
) -> None:

    try:

        count = process_completed_task(
            task_name
        )

        logger.info(
            "Webhook processing complete for %s: "
            "%d findings written.",
            task_name,
            count,
        )

    except Exception as exc:

        logger.exception(
            "OpenVAS webhook processing failed "
            "for task %s: %s",
            task_name,
            exc,
        )


# ============================================================================
# HTTP WEBHOOK
# ============================================================================

class OpenVASUnifiedHandler(
    BaseHTTPRequestHandler
):

    def send_json(
        self,
        status_code: int,
        payload: Dict[str, Any],
    ) -> None:

        body = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode(
            "utf-8"
        )

        self.send_response(
            status_code
        )

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(
                len(body)
            ),
        )

        self.end_headers()

        self.wfile.write(
            body
        )

    def do_GET(
        self,
    ) -> None:

        parsed_url = urllib.parse.urlparse(
            self.path
        )

        # --------------------------------------------------------------
        # Health endpoint
        # --------------------------------------------------------------

        if parsed_url.path == "/health":

            self.send_json(
                200,
                {
                    "status":
                        "ok",

                    "service":
                        "regis-openvas-orchestrator",

                    "mode":
                        "webhook",

                    "log":
                        LOCAL_LOG_PATH,

                    "task_name_format":
                        "TENANT__TIER__SCAN_NAME",
                },
            )

            return

        # --------------------------------------------------------------
        # Existing webhook endpoint
        # --------------------------------------------------------------

        params = urllib.parse.parse_qs(
            parsed_url.query
        )

        if "task" not in params:

            self.send_json(
                400,
                {
                    "status":
                        "rejected",

                    "error":
                        "Missing task parameter",
                },
            )

            return

        # Tenant/service-tier overrides are deliberately not supported.
        forbidden = {
            "tenant_code",
            "tenant_id",
            "service_tier",
            "tenant_service_tier",
        }

        supplied_forbidden = (
            forbidden.intersection(
                params.keys()
            )
        )

        if supplied_forbidden:

            self.send_json(
                400,
                {
                    "status":
                        "rejected",

                    "error":
                        (
                            "Tenant information must be derived "
                            "from the OpenVAS task name"
                        ),

                    "forbidden_parameters":
                        sorted(
                            supplied_forbidden
                        ),
                },
            )

            return

        task_name = params[
            "task"
        ][0].strip()

        try:

            tenant_code, service_tier, scan_name = (
                parse_task_identity(
                    task_name
                )
            )

        except Exception as exc:

            self.send_json(
                400,
                {
                    "status":
                        "rejected",

                    "error":
                        str(
                            exc
                        ),
                },
            )

            return

        # --------------------------------------------------------------
        # Verification callback suppression
        # --------------------------------------------------------------

        if is_verification_task_suppressed(
            task_name
        ):

            logger.info(
                "Ignoring normal-ingestion webhook for "
                "Stage 2 verification task: %s",
                task_name,
            )

            self.send_json(
                200,
                {
                    "status":
                        "accepted",

                    "action":
                        "verification_callback_suppressed",

                    "task":
                        task_name,

                    "tenant_code":
                        tenant_code,

                    "tenant_service_tier":
                        service_tier,

                    "scan_name":
                        scan_name,
                },
            )

            return

        # Respond before deep report processing.
        self.send_json(
            202,
            {
                "status":
                    "accepted",

                "task":
                    task_name,

                "tenant_code":
                    tenant_code,

                "tenant_service_tier":
                    service_tier,

                "scan_name":
                    scan_name,
            },
        )

        worker = threading.Thread(
            target=webhook_worker,
            args=(
                task_name,
            ),
            daemon=True,
        )

        worker.start()

    def log_message(
        self,
        format: str,
        *args: Any,
    ) -> None:

        return


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Regis Security OpenVAS scanner orchestrator"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "scan",
            "verify",
        ],
    )

    # Manual scan processing
    parser.add_argument(
        "--task-name",
    )

    # Canonical verification-dispatcher arguments
    parser.add_argument(
        "--target-host",
    )

    parser.add_argument(
        "--finding-key",
    )

    parser.add_argument(
        "--finding-class",
    )

    parser.add_argument(
        "--engine-metadata-json",
    )

    parser.add_argument(
        "--json",
        action="store_true",
    )

    return parser


# ============================================================================
# CLI EXECUTION
# ============================================================================

def run_cli(
    args: argparse.Namespace,
) -> int:

    # ------------------------------------------------------------------
    # MANUAL SCAN/REPORT PROCESSING
    # ------------------------------------------------------------------

    if args.mode == "scan":

        if not args.task_name:

            raise ValueError(
                "--mode scan requires --task-name"
            )

        count = process_completed_task(
            args.task_name
        )

        if args.json:

            print(
                json.dumps(
                    {
                        "mode":
                            "scan",

                        "scanner":
                            "openvas",

                        "task_name":
                            args.task_name,

                        "findings_written":
                            count,

                        "output":
                            LOCAL_LOG_PATH,
                    },
                    separators=(",", ":"),
                )
            )

        else:

            print(
                f"OpenVAS report processing complete. "
                f"Findings written: {count}"
            )

        return 0

    # ------------------------------------------------------------------
    # VERIFICATION
    # ------------------------------------------------------------------

    if args.mode == "verify":

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
                (
                    "--engine-metadata-json",
                    args.engine_metadata_json,
                ),
            )
            if not value
        ]

        if missing:

            raise ValueError(
                "Verification mode requires: "
                + ", ".join(
                    missing
                )
            )

        metadata = parse_engine_metadata(
            args.engine_metadata_json
        )

        result = run_verification(
            target_host=args.target_host,
            finding_key=args.finding_key,
            finding_class=args.finding_class,
            engine_metadata=metadata,
        )

        # verification_dispatcher.py expects exactly one JSON object.
        print(
            json.dumps(
                result,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )

        return 0

    raise ValueError(
        "Unsupported CLI mode"
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    parser = build_parser()

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # No --mode:
    # run the long-lived webhook listener exactly as before.
    # ------------------------------------------------------------------

    if args.mode is None:

        logger.info(
            "Starting OpenVAS webhook listener "
            "on %s:%s",
            LISTEN_HOST,
            PORT,
        )

        logger.info(
            "Task naming convention: "
            "TENANT_CODE__SERVICE_TIER__SCAN_NAME"
        )

        logger.info(
            "Normalised output: %s",
            LOCAL_LOG_PATH,
        )

        server = ThreadingHTTPServer(
            (
                LISTEN_HOST,
                PORT,
            ),
            OpenVASUnifiedHandler,
        )

        try:

            server.serve_forever()

        except KeyboardInterrupt:

            logger.info(
                "OpenVAS listener stopped."
            )

            return 0

    # ------------------------------------------------------------------
    # CLI scan / verify
    # ------------------------------------------------------------------

    try:

        return run_cli(
            args
        )

    except Exception as exc:

        logger.exception(
            "OpenVAS orchestrator failed: %s",
            exc,
        )

        # Verification must fail closed.
        if args.mode == "verify":

            print(
                json.dumps(
                    {
                        "present":
                            True,

                        "finding_key":
                            args.finding_key,

                        "finding_class":
                            args.finding_class,

                        "scanner":
                            "openvas",

                        "target_host":
                            args.target_host,

                        "verified_at":
                            utc_now(),

                        "verification_error":
                            str(
                                exc
                            ),

                        "evidence":
                            {},
                    },
                    separators=(",", ":"),
                )
            )

        return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
