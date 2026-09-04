#!/usr/bin/env python3
"""
Automated Cybersecurity Remediation Platform
Nmap NSE Security Scan Orchestrator

Architecture
============

The orchestrator supports two modes:

1. SCAN MODE
   - Executes Nmap/NSE locally.
   - Supports:
       * vuln_only
       * all_vuln
       * specific
   - Determines finding_class deterministically.
   - Normalises findings to UnifiedSecurityFinding.
   - Writes findings to the local Wazuh-monitored scanner log.

2. VERIFY MODE
   - Called by verification_gateway.py after remediation.
   - Re-runs the NSE script that originally detected the finding.
   - Optionally restricts verification to the original port.
   - Looks specifically for the original finding_key.
   - Does NOT write findings to the normal scanner log.
   - Prints exactly one JSON result to stdout.

Canonical Nmap NSE finding classes
==================================

Nmap NSE may produce:

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

The orchestrator chooses the class. Ollama does not.

Examples
========

Broad vulnerability scan:

    python3 nmap_nse_orchestrator.py \
      --mode scan \
      --tenant-code Customer5 \
      --service-tier GOLD \
      --task-name "Nmap Vulnerability Scan" \
      --target-host 172.16.95.130 \
      --scan-mode vuln_only

All NSE vulnerability scripts:

    python3 nmap_nse_orchestrator.py \
      --mode scan \
      --tenant-code Customer5 \
      --service-tier GOLD \
      --task-name "Nmap Vulnerability Scan" \
      --target-host 172.16.95.130 \
      --scan-mode all_vuln

Specific vulnerability/NSE script:

    python3 nmap_nse_orchestrator.py \
      --mode scan \
      --tenant-code Customer5 \
      --service-tier GOLD \
      --task-name "Heartbleed targeted scan" \
      --target-host 172.16.95.130 \
      --scan-mode specific \
      --nse-script ssl-heartbleed \
      --finding-key CVE-2014-0160 \
      --ports 443

Verification:

    python3 nmap_nse_orchestrator.py \
      --mode verify \
      --target-host 172.16.95.130 \
      --finding-key CVE-2014-0160 \
      --finding-class network_service_vulnerability \
      --engine-metadata-json '{"script_id":"ssl-heartbleed","port":"443","protocol":"tcp"}' \
      --json
"""

import argparse
import datetime
import json
import logging
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Set, Tuple

from common.finding import build_unified_finding
from common.runtime import normalize_service_tier, utc_now

# ============================================================================
# CONFIGURATION
# ============================================================================

# Keep the existing log path by default so the current Wazuh logcollector
# configuration is not broken.
LOCAL_LOG_PATH = os.getenv(
    "REGIS_NMAP_RAW_LOG",
    "/var/log/compliance_raw.log",
)

LOG_DIR = os.getenv(
    "REGIS_LOG_DIR",
    "/var/log/automated-remediation",
)

ERROR_LOG_PATH = os.path.join(
    LOG_DIR,
    "nmap_nse_orchestrator.error.log",
)

NMAP_BINARY = os.getenv(
    "REGIS_NMAP_BINARY",
    "nmap",
)

NMAP_TIMEOUT = int(
    os.getenv(
        "REGIS_NMAP_TIMEOUT",
        "1800",
    )
)


# ============================================================================
# CANONICAL VALUES
# ============================================================================

VALID_FINDING_CLASSES = {
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

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Operational output goes to stderr.

    Verification mode reserves stdout for exactly one JSON object.
    """

    os.makedirs(
        LOG_DIR,
        exist_ok=True,
    )

    logger = logging.getLogger(
        "nmap_nse_orchestrator"
    )

    logger.setLevel(
        logging.DEBUG if verbose else logging.INFO
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
        logging.DEBUG if verbose else logging.INFO
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


logger = setup_logging(False)


# ============================================================================
# GENERAL HELPERS
# ============================================================================

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


def extract_cves(
    text: str,
) -> List[str]:

    values = {
        match.upper()
        for match in CVE_PATTERN.findall(
            text or ""
        )
    }

    return sorted(
        values
    )


def parse_json_object(
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
            "engine metadata must be a JSON object"
        )

    return data


def severity_from_output(
    output: str,
) -> Tuple[str, float]:

    upper = (
        output or ""
    ).upper()

    if "CRITICAL" in upper:
        return (
            "CRITICAL",
            9.0,
        )

    if "HIGH" in upper:
        return (
            "HIGH",
            7.5,
        )

    if "MEDIUM" in upper:
        return (
            "MEDIUM",
            5.0,
        )

    if "LOW" in upper:
        return (
            "LOW",
            3.0,
        )

    # An NSE vulnerability script declaring VULNERABLE without a CVSS
    # value is treated as HIGH rather than inventing an exact CVSS score.
    return (
        "HIGH",
        7.0,
    )


# ============================================================================
# FINDING DETECTION
# ============================================================================

def output_indicates_positive_finding(
    script_id: str,
    output: str,
) -> bool:
    """
    Determine whether the NSE output actually reports a security condition.

    For broad vuln scans we are deliberately conservative.

    The mere execution of an NSE script is not a finding.
    """

    combined = (
        f"{script_id} {output}"
    ).lower()

    positive_markers = (
        "vulnerable",
        "likely vulnerable",
        "state: vuln",
        "state: vulnerable",
        "authentication bypass",
        "anonymous login allowed",
        "default credential",
        "weak cipher",
        "weak encryption",
        "expired certificate",
        "self-signed certificate",
        "hostname mismatch",
        "directory traversal",
        "path traversal",
        "cross site scripting",
        "cross-site scripting",
        "sql injection",
        "command injection",
        "ssrf",
        "server-side request forgery",
        "sensitive information",
        "exposed",
    )

    if any(
        marker in combined
        for marker in positive_markers
    ):
        return True

    # Many vulnerability NSE scripts include the actual CVE in their
    # positive result.
    if extract_cves(
        output
    ):
        return True

    return False


# ============================================================================
# FINDING CLASSIFICATION
# ============================================================================

def determine_finding_class(
    script_id: str,
    output: str,
    service_name: Optional[str],
    port: Optional[str],
) -> str:
    """
    Determine the semantic problem class.

    The order is important: specific security conditions take precedence
    over generic web/network vulnerability classes.
    """

    script = (
        script_id or ""
    ).lower()

    text = (
        f"{script_id} {output} "
        f"{service_name or ''}"
    ).lower()

    # ------------------------------------------------------------------
    # Web vulnerability classes
    # ------------------------------------------------------------------

    if (
        "xss" in script
        or "cross-site scripting" in text
        or "cross site scripting" in text
    ):
        return "xss_vulnerability"

    if (
        "ssrf" in script
        or "server-side request forgery" in text
        or "server side request forgery" in text
    ):
        return "ssrf_vulnerability"

    if any(
        marker in text
        for marker in (
            "sql injection",
            "command injection",
            "template injection",
            "ldap injection",
            "xpath injection",
            "injection vulnerability",
        )
    ):
        return "injection_vulnerability"

    if (
        "sql-injection" in script
        or "sql-inject" in script
    ):
        return "injection_vulnerability"

    if any(
        marker in text
        for marker in (
            "path traversal",
            "directory traversal",
            "../",
        )
    ):
        return "path_traversal"

    if any(
        marker in text
        for marker in (
            ".env",
            ".git/config",
            "backup file",
            "configuration file exposed",
            "sensitive file",
            "file exposure",
        )
    ):
        return "file_exposure"

    if any(
        marker in text
        for marker in (
            "missing security header",
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
        )
    ):
        return "security_header_missing"

    if any(
        marker in text
        for marker in (
            "sensitive information",
            "information disclosure",
            "credentials exposed",
            "password exposed",
            "api key exposed",
            "secret exposed",
        )
    ):
        return "exposed_sensitive_information"

    if (
        "cloud" in script
        and any(
            marker in text
            for marker in (
                "misconfig",
                "public",
                "exposed",
            )
        )
    ):
        return "misconfigured_cloud_service"

    # ------------------------------------------------------------------
    # Authentication/service classes
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "default credential",
            "default password",
            "factory credential",
        )
    ):
        return "default_credentials"

    if (
        "brute" in script
        or "authentication bypass" in text
        or "weak authentication" in text
    ):
        return "authentication_weakness"

    if any(
        marker in text
        for marker in (
            "unsupported version",
            "end of life",
            "end-of-life",
            "no longer supported",
        )
    ):
        return "unsupported_software"

    # ------------------------------------------------------------------
    # Certificate/TLS/crypto
    # ------------------------------------------------------------------

    if (
        "ssl-cert" in script
        or "certificate" in script
    ):
        if any(
            marker in text
            for marker in (
                "expired",
                "self-signed",
                "self signed",
                "hostname mismatch",
                "not valid",
            )
        ):
            return "certificate_issue"

    if any(
        marker in text
        for marker in (
            "weak cipher",
            "rc4",
            "3des",
            "des cipher",
            "weak dh",
            "weak diffie",
            "weak mac",
        )
    ):
        return "weak_cryptography"

    if (
        "ssl-enum-ciphers" in script
        or "ssl-dh-params" in script
    ):
        return "weak_cryptography"

    if any(
        marker in text
        for marker in (
            "sslv2",
            "ssl v2",
            "sslv3",
            "ssl v3",
            "tlsv1.0",
            "tls 1.0",
            "telnet",
            "cleartext protocol",
            "clear-text protocol",
        )
    ):
        return "insecure_protocol"

    if (
        "ssl" in script
        or "tls" in script
    ):
        if any(
            marker in text
            for marker in (
                "protocol",
                "cipher",
                "tls",
                "ssl",
            )
        ):
            return "tls_configuration"

    # ------------------------------------------------------------------
    # Exposure / configuration
    # ------------------------------------------------------------------

    if any(
        marker in text
        for marker in (
            "administrative interface exposed",
            "debug interface exposed",
            "management interface exposed",
            "service exposed",
        )
    ):
        return "exposed_service"

    if any(
        marker in text
        for marker in (
            "anonymous login allowed",
            "http trace enabled",
            "directory listing",
            "unsafe method",
        )
    ):
        if (
            service_name
            and service_name.lower() in (
                "http",
                "https",
                "http-proxy",
            )
        ):
            return "web_misconfiguration"

        return "service_misconfiguration"

    # ------------------------------------------------------------------
    # Generic vulnerability handling
    # ------------------------------------------------------------------

    is_web = (
        service_name
        and service_name.lower() in (
            "http",
            "https",
            "http-proxy",
            "ssl/http",
        )
    )

    if script.startswith(
        "http-"
    ):
        return "web_application_vulnerability"

    # A CVE discovered against a remotely reachable network daemon is
    # generally more useful as network_service_vulnerability than generic
    # cve because remediation needs service/package context.
    if port:
        return "network_service_vulnerability"

    if extract_cves(
        output
    ):
        return "cve"

    if is_web:
        return "web_application_vulnerability"

    return "network_service_vulnerability"


# ============================================================================
# FINDING KEY
# ============================================================================

def build_finding_keys(
    script_id: str,
    output: str,
    port: Optional[str],
    protocol: Optional[str],
) -> List[str]:
    """
    Prefer CVE identifiers because they are stable across rescans.

    If no CVE exists, use deterministic script+port identity.
    """

    cves = extract_cves(
        output
    )

    if cves:
        return cves

    port_part = (
        f"{port}/{protocol}"
        if port
        else "host"
    )

    return [
        f"NMAP-NSE:{script_id}:{port_part}"
    ]


# ============================================================================
# NMAP EXECUTION
# ============================================================================

def validate_nse_script_name(
    script_name: str,
) -> str:
    """
    Prevent arbitrary command-like values while still allowing common
    NSE script names and categories.
    """

    value = str(
        script_name
    ).strip()

    if not re.fullmatch(
        r"[A-Za-z0-9_.+\-]+",
        value,
    ):
        raise ValueError(
            f"Invalid NSE script name: {value}"
        )

    return value


def validate_ports(
    ports: Optional[str],
) -> Optional[str]:

    if not ports:
        return None

    value = str(
        ports
    ).strip()

    if not re.fullmatch(
        r"[0-9,\-]+",
        value,
    ):
        raise ValueError(
            "ports must contain only numbers, commas and hyphens"
        )

    return value


def determine_script_argument(
    scan_mode: str,
    nse_script: Optional[str],
) -> str:

    if scan_mode == "vuln_only":

        return (
            "vuln and not "
            "(broadcast or safe or default)"
        )

    if scan_mode == "all_vuln":

        return "vuln"

    if scan_mode == "specific":

        if not nse_script:

            raise ValueError(
                "--nse-script is required when "
                "--scan-mode specific is used"
            )

        return validate_nse_script_name(
            nse_script
        )

    raise ValueError(
        f"Unsupported scan_mode: {scan_mode}"
    )


def run_nmap(
    target_host: str,
    scan_mode: str,
    nse_script: Optional[str] = None,
    ports: Optional[str] = None,
    verbose: bool = False,
) -> str:

    script_argument = determine_script_argument(
        scan_mode,
        nse_script,
    )

    ports = validate_ports(
        ports
    )

    command = [
        NMAP_BINARY,
        "-sV",
        "-T4",
        "-Pn",
        f"--script={script_argument}",
    ]

    if ports:

        command.extend(
            [
                "-p",
                ports,
            ]
        )

    command.extend(
        [
            "-oX",
            "-",
            target_host,
        ]
    )

    if verbose:

        logger.debug(
            "Executing Nmap command: %s",
            command,
        )

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=NMAP_TIMEOUT,
        check=False,
    )

    if result.returncode != 0:

        raise RuntimeError(
            f"Nmap returned {result.returncode}: "
            f"{result.stderr.strip()}"
        )

    return result.stdout


# ============================================================================
# XML EXTRACTION
# ============================================================================

def service_details(
    port_element: ET.Element,
) -> Dict[str, Optional[str]]:

    service = port_element.find(
        "service"
    )

    if service is None:

        return {
            "service_name": None,
            "product": None,
            "version": None,
            "extrainfo": None,
        }

    return {
        "service_name": service.get(
            "name"
        ),
        "product": service.get(
            "product"
        ),
        "version": service.get(
            "version"
        ),
        "extrainfo": service.get(
            "extrainfo"
        ),
    }


def collect_script_results(
    xml_text: str,
) -> List[Dict[str, Any]]:

    root = ET.fromstring(
        xml_text
    )

    results: List[
        Dict[str, Any]
    ] = []

    for host in root.findall(
        ".//host"
    ):

        addresses = [
            address.get("addr")
            for address in host.findall(
                "address"
            )
            if address.get("addr")
        ]

        discovered_host = (
            addresses[0]
            if addresses
            else None
        )

        # --------------------------------------------------------------
        # Port scripts
        # --------------------------------------------------------------

        for port_element in host.findall(
            ".//ports/port"
        ):

            state_element = port_element.find(
                "state"
            )

            if (
                state_element is not None
                and state_element.get("state")
                not in (
                    "open",
                    "open|filtered",
                )
            ):
                continue

            port = port_element.get(
                "portid"
            )

            protocol = port_element.get(
                "protocol"
            )

            svc = service_details(
                port_element
            )

            for script in port_element.findall(
                "script"
            ):

                results.append(
                    {
                        "host": discovered_host,
                        "port": port,
                        "protocol": protocol,
                        "script_id": clean_text(
                            script.get("id")
                        ),
                        "output": (
                            script.get("output")
                            or ""
                        ),
                        **svc,
                    }
                )

        # --------------------------------------------------------------
        # Host scripts
        # --------------------------------------------------------------

        for script in host.findall(
            "./hostscript/script"
        ):

            results.append(
                {
                    "host": discovered_host,
                    "port": None,
                    "protocol": None,
                    "script_id": clean_text(
                        script.get("id")
                    ),
                    "output": (
                        script.get("output")
                        or ""
                    ),
                    "service_name": None,
                    "product": None,
                    "version": None,
                    "extrainfo": None,
                }
            )

    return results


# ============================================================================
# NORMALISATION
# ============================================================================

def normalize_results(
    script_results: List[Dict[str, Any]],
    tenant_code: str,
    service_tier: str,
    task_name: str,
    requested_target: str,
    scan_mode: str,
    requested_script: Optional[str],
    requested_finding_key: Optional[str],
) -> List[Dict[str, Any]]:

    findings: List[
        Dict[str, Any]
    ] = []

    seen: Set[
        Tuple[str, str, str]
    ] = set()

    requested_key_upper = (
        requested_finding_key.upper()
        if requested_finding_key
        else None
    )

    for result in script_results:

        script_id = result[
            "script_id"
        ]

        output = result[
            "output"
        ]

        if not output_indicates_positive_finding(
            script_id,
            output,
        ):
            continue

        finding_class = determine_finding_class(
            script_id=script_id,
            output=output,
            service_name=result.get(
                "service_name"
            ),
            port=result.get(
                "port"
            ),
        )

        finding_keys = build_finding_keys(
            script_id=script_id,
            output=output,
            port=result.get("port"),
            protocol=result.get(
                "protocol"
            ),
        )

        for finding_key in finding_keys:

            if (
                requested_key_upper
                and finding_key.upper()
                != requested_key_upper
            ):
                continue

            target_host = (
                result.get("host")
                or requested_target
            )

            dedup_key = (
                target_host,
                finding_class,
                finding_key,
            )

            if dedup_key in seen:
                continue

            seen.add(
                dedup_key
            )

            severity_level, severity_score = (
                severity_from_output(
                    output
                )
            )

            port = result.get(
                "port"
            )

            protocol = result.get(
                "protocol"
            )

            scanned_port = (
                f"{port}/{protocol}"
                if port
                else None
            )

            metadata = {
                "task_name": task_name,
                "scan_mode": scan_mode,

                # This field is critical for Stage 2.
                "script_id": script_id,

                "requested_script":
                    requested_script,

                "port": port,
                "protocol": protocol,
                "scanned_port":
                    scanned_port,

                "service_name":
                    result.get(
                        "service_name"
                    ),

                "product":
                    result.get(
                        "product"
                    ),

                "version":
                    result.get(
                        "version"
                    ),

                "service_extrainfo":
                    result.get(
                        "extrainfo"
                    ),

                "cves":
                    extract_cves(
                        output
                    ),

                "description":
                    output[:4000],
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

            finding_title = (
                f"Nmap NSE: {script_id}"
            )

            if (
                finding_key.upper()
                .startswith("CVE-")
            ):

                finding_title = (
                    f"{finding_key} - "
                    f"Nmap NSE {script_id}"
                )

            payload = build_unified_finding(
                tenant_code=tenant_code,
                tenant_service_tier=service_tier,
                target_host=target_host,
                engine_source="nmap_nse",
                finding_category="vulnerability",
                finding_class=finding_class,
                finding_key=finding_key,
                finding_title=finding_title,
                detected_at=utc_now(),
                compliance_result=None,
                severity_level=severity_level,
                severity_score=severity_score,
                engine_metadata=metadata,
            )

            findings.append(
                payload
            )

    return findings


# ============================================================================
# SCAN MODE
# ============================================================================

def run_scan_mode(
    tenant_code: str,
    service_tier: str,
    task_name: str,
    target_host: str,
    scan_mode: str,
    nse_script: Optional[str],
    finding_key: Optional[str],
    ports: Optional[str],
    verbose: bool,
) -> int:

    service_tier = normalize_service_tier(
        service_tier,
        logger,
    )

    logger.info(
        "SCAN mode: target=%s mode=%s script=%s finding_key=%s ports=%s",
        target_host,
        scan_mode,
        nse_script or "category:vuln",
        finding_key or "ALL",
        ports or "default",
    )

    xml_text = run_nmap(
        target_host=target_host,
        scan_mode=scan_mode,
        nse_script=nse_script,
        ports=ports,
        verbose=verbose,
    )

    script_results = collect_script_results(
        xml_text
    )

    findings = normalize_results(
        script_results=script_results,
        tenant_code=tenant_code,
        service_tier=service_tier,
        task_name=task_name,
        requested_target=target_host,
        scan_mode=scan_mode,
        requested_script=nse_script,
        requested_finding_key=finding_key,
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

        for finding in findings:

            handle.write(
                json.dumps(
                    finding,
                    separators=(",", ":"),
                    ensure_ascii=False,
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
# VERIFICATION MODE
# ============================================================================

def verification_result_contains_key(
    script_results: List[Dict[str, Any]],
    finding_key: str,
    finding_class: str,
) -> Tuple[
    bool,
    List[Dict[str, Any]],
]:
    """
    Determine whether the original finding remains present.
    """

    matches: List[
        Dict[str, Any]
    ] = []

    key_upper = finding_key.upper()

    for result in script_results:

        script_id = result[
            "script_id"
        ]

        output = result[
            "output"
        ]

        if not output_indicates_positive_finding(
            script_id,
            output,
        ):
            continue

        keys = build_finding_keys(
            script_id=script_id,
            output=output,
            port=result.get("port"),
            protocol=result.get(
                "protocol"
            ),
        )

        if not any(
            candidate.upper()
            == key_upper
            for candidate in keys
        ):
            continue

        current_class = determine_finding_class(
            script_id=script_id,
            output=output,
            service_name=result.get(
                "service_name"
            ),
            port=result.get(
                "port"
            ),
        )

        # finding_key is the primary identity.
        #
        # We retain the calculated class as evidence rather than turning
        # a classification drift into a false PASS.
        matches.append(
            {
                "script_id":
                    script_id,

                "port":
                    result.get(
                        "port"
                    ),

                "protocol":
                    result.get(
                        "protocol"
                    ),

                "service_name":
                    result.get(
                        "service_name"
                    ),

                "finding_key":
                    finding_key,

                "requested_finding_class":
                    finding_class,

                "current_finding_class":
                    current_class,

                "output":
                    output[:4000],
            }
        )

    return (
        bool(matches),
        matches,
    )


def run_verify_mode(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Dict[str, Any],
    verbose: bool,
) -> Dict[str, Any]:
    """
    Stage 2 verification.

    The original script ID stored in engine_metadata is required.

    This prevents verification from falling back to a broad NSE scan and
    potentially making an incorrect resolution decision.
    """

    script_id = (
        engine_metadata.get(
            "script_id"
        )
        or engine_metadata.get(
            "requested_script"
        )
    )

    if not script_id:

        raise ValueError(
            "Stage 2 Nmap verification requires "
            "engine_metadata.script_id"
        )

    validate_nse_script_name(
        script_id
    )

    port = engine_metadata.get(
        "port"
    )

    ports = (
        str(port)
        if port is not None
        else None
    )

    logger.info(
        "VERIFY mode: target=%s key=%s class=%s script=%s port=%s",
        target_host,
        finding_key,
        finding_class,
        script_id,
        ports or "default",
    )

    xml_text = run_nmap(
        target_host=target_host,
        scan_mode="specific",
        nse_script=script_id,
        ports=ports,
        verbose=verbose,
    )

    script_results = collect_script_results(
        xml_text
    )

    present, matches = (
        verification_result_contains_key(
            script_results=script_results,
            finding_key=finding_key,
            finding_class=finding_class,
        )
    )

    return {
        "present":
            present,

        "finding_key":
            finding_key,

        "finding_class":
            finding_class,

        "scanner":
            "nmap_nse",

        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence": {
            "script_id":
                script_id,

            "port":
                port,

            "match_count":
                len(matches),

            "matches":
                matches,
        },
    }


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Nmap NSE scanner orchestrator"
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
        "--scan-mode",
        choices=[
            "vuln_only",
            "all_vuln",
            "specific",
        ],
        default="vuln_only",
    )

    parser.add_argument(
        "--nse-script",
        help=(
            "Specific NSE script, for example ssl-heartbleed. "
            "Required with --scan-mode specific."
        ),
    )

    parser.add_argument(
        "--ports",
        help=(
            "Optional Nmap port expression, e.g. 443 or 80,443."
        ),
    )

    # ------------------------------------------------------------------
    # Both modes
    # ------------------------------------------------------------------

    parser.add_argument(
        "--target-host",
        required=True,
    )

    parser.add_argument(
        "--finding-key",
        help=(
            "Optional specific finding identity such as a CVE in "
            "scan mode; required in verify mode."
        ),
    )

    parser.add_argument(
        "--finding-class"
    )

    # ------------------------------------------------------------------
    # Verification gateway metadata
    # ------------------------------------------------------------------

    parser.add_argument(
        "--engine-metadata-json",
        help=(
            "Original finding engine_metadata serialised as JSON. "
            "Used by Stage 2 verification."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
    )

    return parser


# ============================================================================
# LEGACY COMPATIBILITY
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Preserve your existing positional scan invocation while moving new
    deployments to the explicit --mode interface.

    Existing:
        script.py TENANT TIER TASK TARGET SCAN_MODE [--verbose]

    New:
        script.py --mode scan ...
        script.py --mode verify ...
    """

    if (
        len(sys.argv) >= 6
        and not sys.argv[1].startswith("-")
    ):

        args = argparse.Namespace()

        args.mode = "scan"
        args.tenant_code = sys.argv[1]
        args.service_tier = sys.argv[2]
        args.task_name = sys.argv[3]
        args.target_host = sys.argv[4]
        args.scan_mode = sys.argv[5].lower()

        args.nse_script = None
        args.ports = None
        args.finding_key = None
        args.finding_class = None
        args.engine_metadata_json = None

        args.verbose = any(
            value.lower()
            in (
                "--verbose",
                "verbose",
                "-v",
            )
            for value in sys.argv[6:]
        )

        args.json = False

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
        # SCAN MODE
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
                    "SCAN mode requires "
                    + ", ".join(
                        missing
                    )
                )

            if (
                args.scan_mode
                == "specific"
                and not args.nse_script
            ):

                raise ValueError(
                    "--scan-mode specific requires --nse-script"
                )

            count = run_scan_mode(
                tenant_code=args.tenant_code,
                service_tier=args.service_tier,
                task_name=args.task_name,
                target_host=args.target_host,
                scan_mode=args.scan_mode,
                nse_script=args.nse_script,
                finding_key=args.finding_key,
                ports=args.ports,
                verbose=args.verbose,
            )

            if args.json:

                print(
                    json.dumps(
                        {
                            "mode":
                                "scan",

                            "scanner":
                                "nmap_nse",

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
                    "[SUCCESS] Nmap NSE scan complete. "
                    f"Logged {count} finding(s) "
                    f"to {LOCAL_LOG_PATH}"
                )

            return 0

        # ==============================================================
        # VERIFY MODE
        # ==============================================================

        if not args.finding_key:

            raise ValueError(
                "VERIFY mode requires --finding-key"
            )

        if not args.finding_class:

            raise ValueError(
                "VERIFY mode requires --finding-class"
            )

        if (
            args.finding_class
            not in VALID_FINDING_CLASSES
        ):

            raise ValueError(
                "Unsupported Nmap NSE finding_class: "
                f"{args.finding_class}"
            )

        engine_metadata = parse_json_object(
            args.engine_metadata_json
        )

        result = run_verify_mode(
            target_host=args.target_host,
            finding_key=args.finding_key,
            finding_class=args.finding_class,
            engine_metadata=engine_metadata,
            verbose=args.verbose,
        )

        # verification_gateway.py expects exactly one JSON object.
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
            "Nmap NSE orchestrator failed: %s",
            exc,
        )

        if args.mode == "verify":

            # Fail closed. Failure to run Nmap can never mean that the
            # vulnerability disappeared.
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
                            "nmap_nse",

                        "target_host":
                            args.target_host,

                        "verified_at":
                            utc_now(),

                        "verification_error":
                            str(exc),

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
