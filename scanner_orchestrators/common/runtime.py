"""
Shared runtime utilities for scanner orchestrators.

This module contains only behaviour that is genuinely common across
scanner implementations. Scanner-specific execution, classification,
identity, transport and verification logic must remain within the
individual orchestrators.
"""

import datetime
import logging
from typing import Any, FrozenSet


VALID_SERVICE_TIERS: FrozenSet[str] = frozenset({
    "GOLD",
    "STANDARD",
    "BRONZE",
})

DEFAULT_SERVICE_TIER = "STANDARD"


def utc_now() -> str:
    """
    Return the current UTC timestamp as an ISO-8601 string.
    """

    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()


def normalize_service_tier(
    value: Any,
    logger: logging.Logger,
) -> str:
    """
    Normalise a service tier to a canonical value.

    Missing or unsupported values fall back to STANDARD. The caller's
    logger is used so operational warnings remain associated with the
    scanner orchestrator that supplied the value.
    """

    tier = str(
        value or DEFAULT_SERVICE_TIER
    ).strip().upper()

    if tier not in VALID_SERVICE_TIERS:

        logger.warning(
            "Unknown service tier %r; using STANDARD.",
            value,
        )

        return DEFAULT_SERVICE_TIER

    return tier
