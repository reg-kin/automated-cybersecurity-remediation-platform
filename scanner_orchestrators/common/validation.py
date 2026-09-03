"""
Shared validation constants for scanner orchestrators.

This module contains only validation definitions that are genuinely
common across scanner implementations. Scanner-specific validation
rules must remain within the individual orchestrators.
"""

from typing import Tuple


REQUIRED_UNIFIED_FINDING_FIELDS: Tuple[str, ...] = (
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
