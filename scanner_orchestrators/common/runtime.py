"""
Shared runtime utilities for scanner orchestrators.

This module contains only behaviour that is genuinely common across
scanner implementations. Scanner-specific execution, classification,
identity, transport and verification logic must remain within the
individual orchestrators.
"""

import datetime


def utc_now() -> str:
    """
    Return the current UTC timestamp as an ISO-8601 string.
    """

    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
