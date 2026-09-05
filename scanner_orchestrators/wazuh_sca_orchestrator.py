#!/usr/bin/env python3
"""
Automated Cybersecurity Remediation Platform
Wazuh Security Configuration Assessment Orchestrator

Responsibilities
================

SCAN MODE
---------
- Authenticates to the existing Wazuh server API.
- Requests the SCA data already maintained by Wazuh.
- Retrieves policies and their checks for the requested Wazuh agent.
- Processes FAILED checks only.
- Deterministically assigns one of the approved Wazuh SCA finding classes.
- Normalises findings to UnifiedSecurityFinding.
- Writes findings line-by-line to /var/log/compliance_raw.log.

VERIFY MODE
-----------
- Called by verification_gateway.py during Stage 2 verification.
- Accepts the standard verification contract:

      --mode verify
      --target-host
      --finding-key
      --finding-class
      --engine-metadata-json
      --json

- Uses engine_metadata to identify:

      agent_id
      policy_id
      check_id

- Queries Wazuh for the current state of that exact SCA check.
- Does NOT write anything to the normal scanner ingestion log.
- Returns exactly one JSON object on stdout.

Stage 2 semantics
=================

If the Wazuh SCA check currently reports:

    failed
        -> present = true
        -> security finding still exists
        -> Stage 2 FAILED

    passed
        -> present = false
        -> security finding no longer exists
        -> Stage 2 PASSED

    not applicable
        -> present = false
        -> security finding no longer applies
        -> Stage 2 PASSED

API/query failures or unknown states fail closed and MUST NOT result in
the finding being considered resolved.

IMPORTANT
=========

Wazuh SCA results are maintained by Wazuh according to the agent's SCA
evaluation schedule. This orchestrator reads the latest Wazuh SCA state;
it does not itself force an immediate SCA scan.

For production remediation completion, freshness of the SCA result must
therefore be considered before a finding is marked RESOLVED.

Canonical Wazuh SCA finding classes
===================================

cis_control
security_configuration
service_configuration
authentication_configuration
access_control_configuration
logging_configuration
filesystem_configuration
network_configuration

Examples
========

Normal scan:

    python3 wazuh_sca_orchestrator.py \
        --mode scan \
        --tenant-code Customer5 \
        --service-tier GOLD \
        --agent-id 007

Stage 2 verification:

    python3 wazuh_sca_orchestrator.py \
        --mode verify \
        --target-host 172.16.95.131 \
        --finding-key unix_audit:3016 \
        --finding-class authentication_configuration \
        --engine-metadata-json \
        '{"agent_id":"007","policy_id":"unix_audit","check_id":"3016"}' \
        --json

Legacy scan invocation remains supported:

    python3 wazuh_sca_orchestrator.py Customer5 GOLD 007
"""

import argparse
import datetime
import json
import logging
import os
import sys
import uuid

from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from common.finding import build_unified_finding
from common.runtime import normalize_service_tier, utc_now
from common.validation import REQUIRED_UNIFIED_FINDING_FIELDS
from common.verification import read_verification_request

# ============================================================================
# CONFIGURATION
# ============================================================================

WAZUH_URL = os.getenv(
    "WAZUH_API_URL",
    "",
).strip()

CREDENTIALS_FILE = os.getenv(
    "WAZUH_CREDENTIALS_FILE",
    "/opt/automated-remediation/scanner_orchestrators/api_keys.json",
)

DATA_LOG_PATH = os.getenv(
    "SCA_RAW_LOG",
    "/var/log/compliance_raw.log",
)

LOG_PATH = os.getenv(
    "SCA_LOG",
    "/var/log/sca_orchestrator.log",
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "WAZUH_API_TIMEOUT",
        "15",
    )
)

def require_wazuh_api_url() -> str:
    """
    Return the explicitly configured Wazuh API URL.

    Wazuh SCA execution must not silently fall back to an
    environment-specific API endpoint.
    """

    if not WAZUH_URL:

        raise RuntimeError(
            "WAZUH_API_URL must be configured with a non-empty value."
        )

    if not WAZUH_URL.startswith(
        (
            "http://",
            "https://",
        )
    ):

        raise RuntimeError(
            "WAZUH_API_URL must start with http:// or https://."
        )

    return WAZUH_URL

# ============================================================================
# CANONICAL VALUES
# ============================================================================

WAZUH_SCA_FINDING_CLASSES = {
    "cis_control",
    "security_configuration",
    "service_configuration",
    "authentication_configuration",
    "access_control_configuration",
    "logging_configuration",
    "filesystem_configuration",
    "network_configuration",
}

VALID_SCA_RESULTS = {
    "passed",
    "failed",
    "not applicable",
    "not_applicable",
}


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging() -> logging.Logger:

    os.makedirs(
        os.path.dirname(LOG_PATH),
        exist_ok=True,
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=2,
    )

    handler.setFormatter(
        formatter
    )

    stream_handler = logging.StreamHandler(
        sys.stderr
    )

    stream_handler.setFormatter(
        formatter
    )

    logger_instance = logging.getLogger(
        "SCA_Orchestrator"
    )

    logger_instance.setLevel(
        logging.INFO
    )

    logger_instance.handlers.clear()

    logger_instance.addHandler(
        handler
    )

    logger_instance.addHandler(
        stream_handler
    )

    logger_instance.propagate = False

    return logger_instance


logger = setup_logging()


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================================
# GENERAL HELPERS
# ============================================================================


def normalize_status(
    raw_status: Any,
) -> Optional[str]:
    """
    Convert Wazuh SCA status to UnifiedSecurityFinding
    compliance_result.
    """

    if (
        not raw_status
        or not isinstance(
            raw_status,
            str,
        )
    ):

        return None

    mapping = {
        "passed": "PASS",
        "failed": "FAIL",
        "not applicable": "NOT_APPLICABLE",
        "not_applicable": "NOT_APPLICABLE",
    }

    return mapping.get(
        raw_status.strip().lower()
    )


def get_session() -> requests.Session:
    """
    Preserve the existing working Wazuh API behaviour.
    """

    session = requests.Session()

    session.verify = False

    return session


def parse_engine_metadata(
    raw_json: Optional[str],
) -> Dict[str, Any]:
    """
    Parse engine_metadata passed by verification_dispatcher.py.
    """

    if not raw_json:
        return {}

    try:

        metadata = json.loads(
            raw_json
        )

    except json.JSONDecodeError as exc:

        raise ValueError(
            "--engine-metadata-json is not valid JSON"
        ) from exc

    if not isinstance(
        metadata,
        dict,
    ):

        raise ValueError(
            "--engine-metadata-json must contain a JSON object"
        )

    return metadata


# ============================================================================
# WAZUH AUTHENTICATION
# ============================================================================

def get_auth_headers(
    session: requests.Session,
) -> Optional[Dict[str, str]]:
    """
    Preserve the authentication logic from the working orchestrator.
    """

    try:

        with open(
            CREDENTIALS_FILE,
            "r",
            encoding="utf-8",
        ) as handle:

            creds = json.load(
                handle
            )

        response = session.post(
            f"{WAZUH_URL}/security/user/authenticate?raw=true",
            auth=(
                creds["wazuh"]["user"],
                creds["wazuh"]["pass"],
            ),
            timeout=10,
        )

        response.raise_for_status()

        token = response.text.strip()

        if not token:

            raise RuntimeError(
                "Wazuh authentication returned an empty token."
            )

        return {
            "Authorization": f"Bearer {token}"
        }

    except Exception as exc:

        logger.error(
            "Authentication failed: %s",
            exc,
        )

        return None


# ============================================================================
# AGENT INFORMATION
# ============================================================================

def get_agent_identity(
    agent_id: str,
    session: requests.Session,
    headers: Dict[str, str],
) -> Dict[str, str]:

    endpoints = [
        f"{WAZUH_URL}/agents?agents_list={agent_id}",
        f"{WAZUH_URL}/agents/{agent_id}",
    ]

    for url in endpoints:

        try:

            response = session.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

            if not response.ok:
                continue

            affected_items = (
                response.json()
                .get("data", {})
                .get("affected_items", [])
            )

            if not affected_items:
                continue

            agent = affected_items[0]

            agent_ip = agent.get(
                "ip"
            )

            agent_name = agent.get(
                "name"
            )

            target_host = (
                agent_ip
                or agent_name
            )

            if target_host:

                return {
                    "target_host": str(
                        target_host
                    ),
                    "agent_name": str(
                        agent_name or ""
                    ),
                    "agent_ip": str(
                        agent_ip or ""
                    ),
                }

        except Exception as exc:

            logger.warning(
                "Could not retrieve agent identity through %s: %s",
                url,
                exc,
            )

    return {
        "target_host": f"Agent-{agent_id}",
        "agent_name": f"Agent-{agent_id}",
        "agent_ip": "",
    }


# ============================================================================
# FINDING CLASSIFICATION
# ============================================================================

def text_blob(
    policy: Dict[str, Any],
    item: Dict[str, Any],
) -> str:

    values: List[Any] = [
        policy.get("name"),
        policy.get("description"),
        policy.get("policy_id"),
        item.get("title"),
        item.get("description"),
        item.get("rationale"),
        item.get("remediation"),
        item.get("command"),
        item.get("file"),
        item.get("directory"),
        item.get("process"),
        item.get("registry"),
    ]

    compliance = item.get(
        "compliance",
        [],
    )

    if isinstance(
        compliance,
        list,
    ):

        for entry in compliance:

            if isinstance(
                entry,
                dict,
            ):

                values.extend(
                    [
                        entry.get("key"),
                        entry.get("value"),
                    ]
                )

    return " ".join(
        str(value)
        for value in values
        if value not in (
            None,
            "",
        )
    ).lower()


def determine_finding_class(
    policy: Dict[str, Any],
    item: Dict[str, Any],
) -> str:

    text = text_blob(
        policy,
        item,
    )

    # ------------------------------------------------------------------
    # Logging / auditing
    # ------------------------------------------------------------------

    logging_terms = (
        "auditd",
        "audit log",
        "auditing",
        "audit rule",
        "audit rules",
        "audit configuration",
        "logging",
        "log file",
        "journald",
        "rsyslog",
        "syslog",
        "logrotate",
    )

    if any(
        term in text
        for term in logging_terms
    ):

        return "logging_configuration"

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    authentication_terms = (
        "authentication",
        "password",
        "passwd",
        "pam",
        "login",
        "login.defs",
        "password policy",
        "password expiration",
        "password ageing",
        "password aging",
        "password reuse",
        "password complexity",
        "permitrootlogin",
        "root login",
        "empty password",
        "lockout",
        "faillock",
        "pam_tally",
        "remember=",
        "sudo authentication",
    )

    if any(
        term in text
        for term in authentication_terms
    ):

        return "authentication_configuration"

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------

    access_terms = (
        "access control",
        "permissions",
        "permission",
        "ownership",
        "owner",
        "group ownership",
        "sudoers",
        "sudo ",
        "su ",
        "acl",
        "authorized_keys",
        "allowusers",
        "allowgroups",
        "denyusers",
        "denygroups",
        "world writable",
        "world-writable",
    )

    if any(
        term in text
        for term in access_terms
    ):

        return "access_control_configuration"

    # ------------------------------------------------------------------
    # Filesystem
    # ------------------------------------------------------------------

    filesystem_terms = (
        "filesystem",
        "file system",
        "mount",
        "partition",
        "/tmp",
        "/var/tmp",
        "/home",
        "/dev/shm",
        "nodev",
        "nosuid",
        "noexec",
        "fstab",
        "filesystem module",
    )

    if any(
        term in text
        for term in filesystem_terms
    ):

        return "filesystem_configuration"

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    network_terms = (
        "network",
        "ipv4",
        "ipv6",
        "sysctl",
        "packet forwarding",
        "ip forwarding",
        "source routed",
        "source-routed",
        "icmp",
        "tcp syncookies",
        "firewall",
        "iptables",
        "ip6tables",
        "nftables",
        "ufw",
        "wireless",
        "network interface",
    )

    if any(
        term in text
        for term in network_terms
    ):

        return "network_configuration"

    # ------------------------------------------------------------------
    # Service configuration
    # ------------------------------------------------------------------

    service_terms = (
        "service",
        "daemon",
        "systemctl",
        "sshd",
        "ssh server",
        "apache",
        "nginx",
        "cron",
        "crond",
        "avahi",
        "cups",
        "rpcbind",
        "xinetd",
        "telnet",
        "ftp",
        "snmp",
    )

    if any(
        term in text
        for term in service_terms
    ):

        return "service_configuration"

    # ------------------------------------------------------------------
    # CIS
    # ------------------------------------------------------------------

    cis_terms = (
        "cis",
        "center for internet security",
    )

    if any(
        term in text
        for term in cis_terms
    ):

        return "cis_control"

    return "security_configuration"


# ============================================================================
# COMPLIANCE METADATA
# ============================================================================

def normalize_compliance(
    raw_compliance: Any,
) -> Dict[str, Any]:

    if not isinstance(
        raw_compliance,
        list,
    ):

        return {}

    result: Dict[str, Any] = {}

    for entry in raw_compliance:

        if not isinstance(
            entry,
            dict,
        ):

            continue

        key = entry.get(
            "key"
        )

        value = entry.get(
            "value"
        )

        if key is not None:

            result[
                str(key)
            ] = value

    return result


# ============================================================================
# SCHEMA VALIDATION
# ============================================================================

def validate_payload(
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
                f"Missing required unified finding field: {field}"
            )

    if (
        payload[
            "finding_category"
        ]
        != "compliance_drift"
    ):

        raise ValueError(
            "Wazuh SCA findings must use "
            "finding_category=compliance_drift."
        )

    if (
        payload[
            "finding_class"
        ]
        not in WAZUH_SCA_FINDING_CLASSES
    ):

        raise ValueError(
            f"Invalid Wazuh SCA finding_class: "
            f"{payload['finding_class']}"
        )

    if (
        payload.get(
            "compliance_result"
        )
        not in (
            "PASS",
            "FAIL",
            "NOT_APPLICABLE",
            None,
        )
    ):

        raise ValueError(
            "Invalid compliance_result."
        )


# ============================================================================
# WAZUH SCA API
# ============================================================================

def get_policies(
    agent_id: str,
    session: requests.Session,
    headers: Dict[str, str],
) -> List[Dict[str, Any]]:

    url = (
        f"{WAZUH_URL}/sca/"
        f"{agent_id}"
    )

    response = session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return (
        response.json()
        .get(
            "data",
            {},
        )
        .get(
            "affected_items",
            [],
        )
    )


def get_policy_checks(
    agent_id: str,
    policy_id: str,
    session: requests.Session,
    headers: Dict[str, str],
) -> List[Dict[str, Any]]:

    url = (
        f"{WAZUH_URL}/sca/"
        f"{agent_id}/checks/"
        f"{policy_id}"
    )

    response = session.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    return (
        response.json()
        .get(
            "data",
            {},
        )
        .get(
            "affected_items",
            [],
        )
    )


# ============================================================================
# TARGETED SCA VERIFICATION
# ============================================================================

def parse_finding_key(
    finding_key: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse:

        unix_audit:3016

    into:

        policy_id = unix_audit
        check_id  = 3016
    """

    value = str(
        finding_key or ""
    ).strip()

    if ":" not in value:

        return (
            None,
            None,
        )

    policy_id, check_id = value.rsplit(
        ":",
        1,
    )

    policy_id = policy_id.strip()
    check_id = check_id.strip()

    return (
        policy_id or None,
        check_id or None,
    )


def resolve_verification_identity(
    finding_key: str,
    engine_metadata: Dict[str, Any],
) -> Tuple[str, str, str]:
    """
    Determine agent_id, policy_id and check_id.

    engine_metadata is authoritative.

    finding_key is used as a safe fallback for policy/check identity.
    """

    metadata_agent_id = engine_metadata.get(
        "agent_id"
    )

    metadata_policy_id = engine_metadata.get(
        "policy_id"
    )

    metadata_check_id = engine_metadata.get(
        "check_id"
    )

    key_policy_id, key_check_id = parse_finding_key(
        finding_key
    )

    agent_id = (
        str(
            metadata_agent_id
        ).strip()
        if metadata_agent_id is not None
        else ""
    )

    policy_id = (
        str(
            metadata_policy_id
        ).strip()
        if metadata_policy_id is not None
        else ""
    )

    check_id = (
        str(
            metadata_check_id
        ).strip()
        if metadata_check_id is not None
        else ""
    )

    if not policy_id:

        policy_id = (
            key_policy_id
            or ""
        )

    if not check_id:

        check_id = (
            key_check_id
            or ""
        )

    if not agent_id:

        raise ValueError(
            "Wazuh SCA verification requires engine_metadata.agent_id"
        )

    if not policy_id:

        raise ValueError(
            "Unable to determine Wazuh SCA policy_id."
        )

    if not check_id:

        raise ValueError(
            "Unable to determine Wazuh SCA check_id."
        )

    return (
        agent_id,
        policy_id,
        check_id,
    )


def find_exact_sca_check(
    agent_id: str,
    policy_id: str,
    check_id: str,
    session: requests.Session,
    headers: Dict[str, str],
) -> Dict[str, Any]:
    """
    Retrieve the checks for one policy and locate the exact original
    check by check ID.
    """

    checks = get_policy_checks(
        agent_id,
        policy_id,
        session,
        headers,
    )

    for item in checks:

        current_id = item.get(
            "id"
        )

        if current_id is None:
            continue

        if (
            str(
                current_id
            ).strip()
            == str(
                check_id
            ).strip()
        ):

            return item

    raise RuntimeError(
        "Original Wazuh SCA check was not found in the current "
        f"SCA policy state: agent={agent_id}, "
        f"policy={policy_id}, check={check_id}"
    )


def extract_sca_timestamp(
    item: Dict[str, Any],
) -> Optional[Any]:
    """
    Preserve any freshness/time field Wazuh happens to provide.

    Different Wazuh versions/payloads may expose different names.
    We do not invent a timestamp.
    """

    candidates = (
        "last_scan",
        "last_scan_time",
        "updated_at",
        "timestamp",
        "last_update",
    )

    for key in candidates:

        value = item.get(
            key
        )

        if value not in (
            None,
            "",
        ):

            return value

    return None


def run_verify_mode(
    target_host: str,
    finding_key: str,
    finding_class: str,
    engine_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Perform targeted Stage 2 verification against the current Wazuh
    SCA state.
    """

    if (
        finding_class
        not in WAZUH_SCA_FINDING_CLASSES
    ):

        raise ValueError(
            f"Unsupported Wazuh SCA finding_class: {finding_class}"
        )

    agent_id, policy_id, check_id = (
        resolve_verification_identity(
            finding_key,
            engine_metadata,
        )
    )

    logger.info(
        "VERIFY mode: "
        "target=%s agent=%s policy=%s check=%s "
        "key=%s class=%s",
        target_host,
        agent_id,
        policy_id,
        check_id,
        finding_key,
        finding_class,
    )

    session = get_session()

    headers = get_auth_headers(
        session
    )

    if not headers:

        raise RuntimeError(
            "Unable to authenticate to Wazuh API."
        )

    current_check = find_exact_sca_check(
        agent_id,
        policy_id,
        check_id,
        session,
        headers,
    )

    raw_result = current_check.get(
        "result"
    )

    if raw_result is None:

        raise RuntimeError(
            "Wazuh SCA check does not contain a result field."
        )

    normalized_result = str(
        raw_result
    ).strip().lower()

    if (
        normalized_result
        not in VALID_SCA_RESULTS
    ):

        raise RuntimeError(
            f"Unsupported/unknown Wazuh SCA result: "
            f"{raw_result!r}"
        )

    # --------------------------------------------------------------
    # Stage 2 meaning
    # --------------------------------------------------------------
    #
    # FAILED SCA check:
    #     drift still exists
    #     present = True
    #
    # PASSED / NOT APPLICABLE:
    #     original drift no longer exists
    #     present = False
    # --------------------------------------------------------------

    present = (
        normalized_result
        == "failed"
    )

    current_finding_key = (
        f"{policy_id}:{check_id}"
    )

    evidence = {
        "agent_id":
            agent_id,

        "policy_id":
            policy_id,

        "check_id":
            check_id,

        "current_finding_key":
            current_finding_key,

        "raw_result":
            raw_result,

        "compliance_result":
            normalize_status(
                raw_result
            ),

        "title":
            current_check.get(
                "title"
            ),

        "description":
            current_check.get(
                "description"
            ),

        "rationale":
            current_check.get(
                "rationale"
            ),

        "remediation":
            current_check.get(
                "remediation"
            ),

        "file":
            current_check.get(
                "file"
            ),

        "command":
            current_check.get(
                "command"
            ),

        "sca_result_timestamp":
            extract_sca_timestamp(
                current_check
            ),

        # Important operational qualification.
        "freshness_guaranteed":
            False,

        "freshness_note": (
            "Verification used the latest SCA state currently stored "
            "by Wazuh. This orchestrator did not force an immediate "
            "new Wazuh SCA evaluation."
        ),
    }

    evidence = {
        key: value
        for key, value
        in evidence.items()
        if value not in (
            None,
            "",
        )
    }

    result = {
        "present":
            present,

        "finding_key":
            finding_key,

        "finding_class":
            finding_class,

        "scanner":
            "wazuh_sca",

        "target_host":
            target_host,

        "verified_at":
            utc_now(),

        "evidence":
            evidence,
    }

    logger.info(
        "VERIFY mode complete: "
        "agent=%s policy=%s check=%s result=%s present=%s",
        agent_id,
        policy_id,
        check_id,
        normalized_result,
        present,
    )

    return result


# ============================================================================
# FINDING CREATION
# ============================================================================

def build_finding(
    tenant: str,
    tier: str,
    agent_id: str,
    agent_identity: Dict[str, str],
    policy: Dict[str, Any],
    item: Dict[str, Any],
    refresh_id: Optional[str] = None,
    refresh_started_at: Optional[str] = None,
) -> Dict[str, Any]:

    policy_id = str(
        policy.get(
            "policy_id",
            "UNKNOWN-POLICY",
        )
    )

    check_id = item.get(
        "id"
    )

    if check_id is None:

        finding_key = policy_id

    else:

        finding_key = (
            f"{policy_id}:{check_id}"
        )

    finding_class = determine_finding_class(
        policy,
        item,
    )

    raw_status = item.get(
        "result"
    )

    compliance_result = normalize_status(
        raw_status
    )

    normalized_compliance = normalize_compliance(
        item.get(
            "compliance",
            [],
        )
    )

    title = str(
        item.get(
            "title",
            "",
        )
    ).strip()

    if not title:

        title = (
            f"Wazuh SCA check {finding_key}"
        )

    metadata = {
        "task_name":
            "Wazuh SCA Assessment",

        "agent_id":
            agent_id,

        "agent_name":
            agent_identity.get(
                "agent_name"
            ),

        "agent_ip":
            agent_identity.get(
                "agent_ip"
            ),

        "policy_id":
            policy_id,

        "policy_name":
            policy.get(
                "name"
            ),

        "policy_description":
            policy.get(
                "description"
            ),

        "check_id":
            check_id,

        "description":
            item.get(
                "description",
                "",
            ),

        "rationale":
            item.get(
                "rationale",
                "",
            ),

        "remediation":
            item.get(
                "remediation",
                "",
            ),

        "reason":
            item.get(
                "reason"
            ),

        "command":
            item.get(
                "command"
            ),

        "file":
            item.get(
                "file"
            ),

        "directory":
            item.get(
                "directory"
            ),

        "process":
            item.get(
                "process"
            ),

        "registry":
            item.get(
                "registry"
            ),

        "compliance":
            normalized_compliance,

        "raw_result":
            raw_status,

        "verification_capability":
            "asynchronous_state_refresh",

        "targeted_verification_supported":
            False,

        "refresh_id":
            refresh_id,

        "refresh_started_at":
            refresh_started_at,
    }

    metadata = {
        key: value
        for key, value
        in metadata.items()
        if value not in (
            None,
            "",
            {},
            [],
        )
    }

    payload = build_unified_finding(
        tenant_code=tenant,
        tenant_service_tier=tier,
        target_host=agent_identity["target_host"],
        engine_source="wazuh_sca",
        finding_category="compliance_drift",
        finding_class=finding_class,
        finding_key=finding_key,
        finding_title=title,
        detected_at=utc_now(),
        compliance_result=compliance_result,
        severity_level=None,
        severity_score=None,
        engine_metadata=metadata,
    )

    validate_payload(
        payload
    )

    return payload


# ============================================================================
# SCAN MODE
# ============================================================================

def build_refresh_completion_event(
    tenant: str,
    tier: str,
    agent_id: str,
    refresh_id: str,
    refresh_started_at: str,
    refresh_completed_at: str,
    refresh_status: str,
    expected_findings: int,
    policies_discovered: int,
    policies_completed: int,
    checks_inspected: int,
    malformed_documents: int,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build the separate scanner-refresh control event.

    This is deliberately NOT a UnifiedSecurityFinding.  The enrichment
    worker detects event_type before Unified Finding validation/Ollama.
    """

    event: Dict[str, Any] = {
        "event_type": "scanner_refresh_complete",
        "engine_source": "wazuh_sca",
        "scanner_subject_type": "wazuh_agent",
        "scanner_subject_id": str(agent_id),
        "tenant_code": tenant,
        "tenant_service_tier": tier,
        "refresh_id": refresh_id,
        "refresh_started_at": refresh_started_at,
        "refresh_completed_at": refresh_completed_at,
        "refresh_status": refresh_status,
        "expected_findings": int(expected_findings),
        "policies_discovered": int(policies_discovered),
        "policies_completed": int(policies_completed),
        "checks_inspected": int(checks_inspected),
        "malformed_documents": int(malformed_documents),
    }

    if errors:
        event["errors"] = errors

    return event


def process_agent(
    tenant: str,
    tier: str,
    agent_id: str,
    session: requests.Session,
    headers: Dict[str, str],
) -> int:

    tier = normalize_service_tier(
        tier,
        logger,
    )

    refresh_id = str(uuid.uuid4())
    refresh_started_at = utc_now()

    agent_identity = get_agent_identity(
        agent_id,
        session,
        headers,
    )

    logger.info(
        "SCAN mode: tenant=%s tier=%s agent=%s target=%s refresh_id=%s",
        tenant,
        tier,
        agent_id,
        agent_identity["target_host"],
        refresh_id,
    )

    # A failure to enumerate policies means that we do not possess a complete
    # authoritative SCA snapshot.  Let the exception propagate; main() will
    # fail the scan rather than emitting a misleading SUCCESS refresh.
    policies = get_policies(
        agent_id,
        session,
        headers,
    )

    findings: List[Dict[str, Any]] = []
    seen = set()
    errors: List[str] = []
    malformed_documents = 0
    policies_completed = 0
    checks_inspected = 0

    for policy in policies:

        policy_id = policy.get(
            "policy_id"
        )

        if not policy_id:
            malformed_documents += 1
            errors.append("SCA policy missing policy_id")
            logger.error(
                "Malformed SCA policy without policy_id; refresh cannot be authoritative."
            )
            continue

        try:
            checks = get_policy_checks(
                agent_id,
                str(policy_id),
                session,
                headers,
            )
        except Exception as exc:
            errors.append(
                f"Failed to retrieve checks for policy {policy_id}: {exc}"
            )
            logger.error(
                "Failed to retrieve SCA checks agent=%s policy=%s: %s",
                agent_id,
                policy_id,
                exc,
            )
            continue

        policies_completed += 1

        for item in checks:
            checks_inspected += 1

            raw_status = str(
                item.get(
                    "result",
                    "",
                )
            ).strip().lower()

            # Scan mode persists failed checks only.  PASS and NOT APPLICABLE
            # are represented by absence from the complete failed-check set.
            if raw_status != "failed":
                continue

            try:
                payload = build_finding(
                    tenant=tenant,
                    tier=tier,
                    agent_id=agent_id,
                    agent_identity=agent_identity,
                    policy=policy,
                    item=item,
                    refresh_id=refresh_id,
                    refresh_started_at=refresh_started_at,
                )
            except Exception as exc:
                malformed_documents += 1
                errors.append(
                    f"Malformed failed check policy={policy_id} check={item.get('id')}: {exc}"
                )
                logger.error(
                    "Malformed failed SCA check means refresh is not authoritative "
                    "agent=%s policy=%s check=%s: %s",
                    agent_id,
                    policy_id,
                    item.get("id"),
                    exc,
                )
                continue

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

            findings.append(
                payload
            )

    # Any incomplete policy retrieval, missing policy identity, or malformed
    # failed check makes absence unsafe to interpret.  Findings collected from
    # the partial refresh may still be emitted, but the completion event MUST
    # be FAILED so it can never become successful Stage-2 evidence.
    refresh_status = "SUCCESS"

    if (
        errors
        or malformed_documents > 0
        or policies_completed != len(policies)
    ):
        refresh_status = "FAILED"

    os.makedirs(
        os.path.dirname(
            DATA_LOG_PATH
        ),
        exist_ok=True,
    )

    with open(
        DATA_LOG_PATH,
        "a",
        encoding="utf-8",
    ) as handle:

        # Findings are deliberately written before the completion marker.
        # Downstream processing is asynchronous, so Step 4B stages a SUCCESS
        # completion until all expected findings have committed.
        for payload in findings:
            handle.write(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            )

        refresh_completed_at = utc_now()

        completion_event = build_refresh_completion_event(
            tenant=tenant,
            tier=tier,
            agent_id=agent_id,
            refresh_id=refresh_id,
            refresh_started_at=refresh_started_at,
            refresh_completed_at=refresh_completed_at,
            refresh_status=refresh_status,
            expected_findings=len(findings),
            policies_discovered=len(policies),
            policies_completed=policies_completed,
            checks_inspected=checks_inspected,
            malformed_documents=malformed_documents,
            errors=errors,
        )

        # Control event is always emitted LAST.
        handle.write(
            json.dumps(
                completion_event,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )

    logger.info(
        "SCAN mode complete: findings=%d refresh_status=%s "
        "policies=%d/%d checks=%d malformed=%d refresh_id=%s output=%s",
        len(findings),
        refresh_status,
        policies_completed,
        len(policies),
        checks_inspected,
        malformed_documents,
        refresh_id,
        DATA_LOG_PATH,
    )

    if refresh_status != "SUCCESS":
        logger.error(
            "SCA refresh %s is FAILED and MUST NOT be used as authoritative "
            "Stage-2 evidence. errors=%s",
            refresh_id,
            errors,
        )

    return len(findings)


# ============================================================================
# COMMAND LINE
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "Wazuh SCA orchestrator"
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
        "--target-host"
    )

    parser.add_argument(
        "--finding-key"
    )

    parser.add_argument(
        "--finding-class"
    )

    # NEW:
    # canonical Stage 2 metadata contract.
    parser.add_argument(
        "--engine-metadata-json",
        help=(
            "Original finding engine_metadata serialised as JSON. "
            "Used by Stage 2 verification."
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
    )

    return parser


def parse_arguments() -> argparse.Namespace:

    # Preserve original positional scan invocation.
    if (
        len(sys.argv) == 4
        and not sys.argv[1].startswith("-")
    ):

        args = argparse.Namespace()

        args.mode = "scan"
        args.tenant_code = sys.argv[1]
        args.service_tier = sys.argv[2]
        args.agent_id = sys.argv[3]

        args.target_host = None
        args.finding_key = None
        args.finding_class = None
        args.engine_metadata_json = None
        args.json = False

        return args

    parser = build_parser()

    args = parser.parse_args()

    if not args.mode:

        parser.error(
            "--mode is required."
        )

    return args


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

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

    # ======================================================================
    # VERIFY MODE
    # ======================================================================

    if args.mode == "verify":

        try:

            if not args.target_host:

                raise ValueError(
                    "VERIFY mode requires --target-host."
                )

            if not args.finding_key:

                raise ValueError(
                    "VERIFY mode requires --finding-key."
                )

            if not args.finding_class:

                raise ValueError(
                    "VERIFY mode requires --finding-class."
                )

            metadata = parse_engine_metadata(
                args.engine_metadata_json
            )

            require_wazuh_api_url()

            result = run_verify_mode(
                target_host=args.target_host,
                finding_key=args.finding_key,
                finding_class=args.finding_class,
                engine_metadata=metadata,
            )

            # stdout contains exactly one JSON document.
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
                "Wazuh SCA verification failed: %s",
                exc,
            )

            # Fail closed.
            #
            # An infrastructure/query problem must never become
            # present=False / PASSED.
            error_result = {
                "present":
                    True,

                "finding_key":
                    args.finding_key,

                "finding_class":
                    args.finding_class,

                "scanner":
                    "wazuh_sca",

                "target_host":
                    args.target_host,

                "verified_at":
                    utc_now(),

                "verification_error":
                    str(exc),

                "evidence":
                    {},
            }

            print(
                json.dumps(
                    error_result,
                    separators=(",", ":"),
                )
            )

            return 1

    # ======================================================================
    # SCAN MODE
    # ======================================================================

    if not args.tenant_code:

        raise SystemExit(
            "SCAN mode requires --tenant-code."
        )

    if not args.service_tier:

        raise SystemExit(
            "SCAN mode requires --service-tier."
        )

    if not args.agent_id:

        raise SystemExit(
            "SCAN mode requires --agent-id."
        )

    try:

        require_wazuh_api_url()

    except RuntimeError as exc:

        logger.error(
            "Wazuh SCA configuration error: %s",
            exc,
        )

        return 1

    session = get_session()

    headers = get_auth_headers(
        session
    )

    if not headers:

        return 1

    try:

        count = process_agent(
            args.tenant_code.strip(),
            args.service_tier.strip(),
            args.agent_id.strip(),
            session,
            headers,
        )

    except Exception as exc:

        logger.exception(
            "Wazuh SCA scan failed: %s",
            exc,
        )

        return 1

    if args.json:

        print(
            json.dumps(
                {
                    "mode":
                        "scan",

                    "scanner":
                        "wazuh_sca",

                    "findings_written":
                        count,

                    "output":
                        DATA_LOG_PATH,
                },
                separators=(",", ":"),
            )
        )

    else:

        print(
            f"[*] Wazuh SCA collection complete. "
            f"Findings written: {count}. "
            f"Check {DATA_LOG_PATH}."
        )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
