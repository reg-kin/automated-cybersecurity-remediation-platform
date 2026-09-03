"""
Shared Unified Security Finding construction scaffolding.

This module owns only canonical envelope construction and invariant default
fields. Scanner-specific classification, identity, parsing, severity,
target derivation, metadata and verification semantics remain in the
individual scanner orchestrators.
"""

from typing import Any, Dict, Optional


def build_unified_finding(
    *,
    tenant_code: str,
    tenant_service_tier: str,
    target_host: str,
    engine_source: str,
    finding_category: str,
    finding_class: str,
    finding_key: str,
    finding_title: str,
    detected_at: str,
    compliance_result: Optional[str],
    severity_level: Optional[str],
    severity_score: Optional[float],
    engine_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Construct the canonical Unified Security Finding envelope.

    All scanner-derived values are supplied by the caller. In particular,
    this function does not generate timestamps, classify findings, derive
    targets, calculate severity or interpret scanner metadata.
    """

    return {
        "tenant_code": tenant_code,
        "tenant_service_tier": tenant_service_tier,
        "target_host": target_host,
        "engine_source": engine_source,
        "finding_category": finding_category,
        "finding_class": finding_class,
        "finding_key": finding_key,
        "finding_title": finding_title,
        "lifecycle_status": "OPEN",
        "detected_at": detected_at,
        "remediated_at": None,
        "last_verified_at": None,
        "compliance_result": compliance_result,
        "severity_level": severity_level,
        "severity_score": severity_score,
        "engine_metadata": engine_metadata,
        "ai_analysis": None,
    }
