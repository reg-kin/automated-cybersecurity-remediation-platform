"""Deterministic contextual risk assessment.

This module calculates organisationally contextualised risk from
scanner/native severity and curated asset context.

It does not perform database access, persistence, remediation routing,
or AI analysis.
"""

from copy import deepcopy
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Optional


ASSESSMENT_MODEL = "CONTEXTUAL_RISK_V1"


SEVERITY_LEVEL_SCORES = {
    "LOW": Decimal("2.5"),
    "MEDIUM": Decimal("5.5"),
    "HIGH": Decimal("8.0"),
    "CRITICAL": Decimal("9.5"),
}


IMPACT_FACTORS = {
    "UNKNOWN": Decimal("0"),
    "LOW": Decimal("0.25"),
    "MEDIUM": Decimal("0.50"),
    "HIGH": Decimal("0.75"),
    "CRITICAL": Decimal("1.00"),
}


DATA_CLASSIFICATION_FACTORS = {
    "UNKNOWN": Decimal("0"),
    "PUBLIC": Decimal("0.25"),
    "INTERNAL": Decimal("0.50"),
    "CONFIDENTIAL": Decimal("0.75"),
    "RESTRICTED": Decimal("1.00"),
}


INTERNET_EXPOSURE_FACTORS = {
    "UNKNOWN": Decimal("0"),
    "INTERNAL": Decimal("0.20"),
    "EXTERNALLY_REACHABLE": Decimal("0.60"),
    "INTERNET_FACING": Decimal("1.00"),
}


ENVIRONMENT_FACTORS = {
    "UNKNOWN": Decimal("0"),
    "DEVELOPMENT": Decimal("0.20"),
    "TEST": Decimal("0.20"),
    "STAGING": Decimal("0.50"),
    "CORPORATE": Decimal("0.70"),
    "PRODUCTION": Decimal("1.00"),
}


CONTEXT_SNAPSHOT_FIELDS = (
    "environment",
    "business_service",
    "business_unit",
    "owner",
    "technical_owner",
    "criticality",
    "data_classification",
    "internet_exposure",
    "network_zone",
    "confidentiality_requirement",
    "integrity_requirement",
    "availability_requirement",
    "context_source",
)


def _normalise_level(
    value: Any,
) -> Optional[str]:
    if value is None:
        return None

    normalised = str(value).strip().upper()

    if not normalised:
        return None

    if normalised not in SEVERITY_LEVEL_SCORES:
        raise ValueError(
            f"Invalid severity_level: {value!r}"
        )

    return normalised


def _normalise_score(
    value: Any,
) -> Optional[Decimal]:
    if value is None:
        return None

    try:
        score = Decimal(str(value))
    except Exception as exc:
        raise ValueError(
            f"Invalid severity_score: {value!r}"
        ) from exc

    if not score.is_finite():
        raise ValueError(
            f"Invalid severity_score: {value!r}"
        )

    if score < 0 or score > 10:
        raise ValueError(
            "severity_score must be between 0 and 10"
        )

    return score


def _context_value(
    context: Dict[str, Any],
    field_name: str,
    factors: Dict[str, Decimal],
) -> Decimal:
    value = context.get(field_name, "UNKNOWN")

    if value is None:
        value = "UNKNOWN"

    normalised = str(value).strip().upper()

    if not normalised:
        normalised = "UNKNOWN"

    if normalised not in factors:
        raise ValueError(
            f"Invalid asset context {field_name}: {value!r}"
        )

    return factors[normalised]


def _context_snapshot(
    context: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if context is None:
        return None

    if not isinstance(context, dict):
        raise TypeError(
            "asset_context must be a dictionary or None"
        )

    return {
        field_name: deepcopy(context.get(field_name))
        for field_name in CONTEXT_SNAPSHOT_FIELDS
    }


def _risk_level(
    score: Decimal,
) -> str:
    if score >= Decimal("9.0"):
        return "CRITICAL"

    if score >= Decimal("7.0"):
        return "HIGH"

    if score >= Decimal("4.0"):
        return "MEDIUM"

    return "LOW"


def contextualise_risk(
    *,
    severity_score: Any,
    severity_level: Any,
    asset_id: Optional[int],
    asset_context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return a deterministic CONTEXTUAL_RISK_V1 assessment.

    asset_context must be None when no curated context row exists.
    A non-None value is expected to be canonical context returned by
    Asset Context Management.
    """

    base_score = _normalise_score(severity_score)
    base_level = _normalise_level(severity_level)

    snapshot = _context_snapshot(asset_context)

    if base_score is None and base_level is None:
        return {
            "asset_id": asset_id,
            "assessment_status": "UNSCORABLE",
            "base_severity_score": None,
            "base_severity_level": None,
            "contextual_risk_score": None,
            "contextual_risk_level": None,
            "assessment_factors": {
                "technical_severity_source": None,
                "effective_technical_severity": None,
            },
            "context_snapshot": snapshot,
            "assessment_model": ASSESSMENT_MODEL,
        }

    if base_score is not None:
        effective_severity = base_score
        severity_source = "severity_score"
    else:
        effective_severity = SEVERITY_LEVEL_SCORES[
            base_level
        ]
        severity_source = "severity_level_fallback"

    technical_component = (
        effective_severity
        / Decimal("10")
        * Decimal("6")
    )

    if asset_context is None:
        criticality_factor = Decimal("0")
        data_factor = Decimal("0")
        confidentiality_factor = Decimal("0")
        integrity_factor = Decimal("0")
        availability_factor = Decimal("0")
        internet_factor = Decimal("0")
        environment_factor = Decimal("0")
    else:
        criticality_factor = _context_value(
            asset_context,
            "criticality",
            IMPACT_FACTORS,
        )
        data_factor = _context_value(
            asset_context,
            "data_classification",
            DATA_CLASSIFICATION_FACTORS,
        )
        confidentiality_factor = _context_value(
            asset_context,
            "confidentiality_requirement",
            IMPACT_FACTORS,
        )
        integrity_factor = _context_value(
            asset_context,
            "integrity_requirement",
            IMPACT_FACTORS,
        )
        availability_factor = _context_value(
            asset_context,
            "availability_requirement",
            IMPACT_FACTORS,
        )
        internet_factor = _context_value(
            asset_context,
            "internet_exposure",
            INTERNET_EXPOSURE_FACTORS,
        )
        environment_factor = _context_value(
            asset_context,
            "environment",
            ENVIRONMENT_FACTORS,
        )

    impact_factor = (
        Decimal("0.40") * criticality_factor
        + Decimal("0.20") * data_factor
        + Decimal("0.133333") * confidentiality_factor
        + Decimal("0.133333") * integrity_factor
        + Decimal("0.133334") * availability_factor
    )

    organisational_component = (
        impact_factor * Decimal("3")
    )

    exposure_factor = (
        Decimal("0.70") * internet_factor
        + Decimal("0.30") * environment_factor
    )

    exposure_component = exposure_factor

    raw_score = (
        technical_component
        + organisational_component
        + exposure_component
    )

    bounded_score = min(
        Decimal("10"),
        max(Decimal("0"), raw_score),
    )

    final_score = bounded_score.quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )

    assessment_status = (
        "ASSESSED"
        if asset_id is not None
        and asset_context is not None
        else "PARTIAL"
    )

    return {
        "asset_id": asset_id,
        "assessment_status": assessment_status,
        "base_severity_score": (
            float(base_score)
            if base_score is not None
            else None
        ),
        "base_severity_level": base_level,
        "contextual_risk_score": float(final_score),
        "contextual_risk_level": _risk_level(
            final_score
        ),
        "assessment_factors": {
            "technical_severity_source": severity_source,
            "effective_technical_severity": float(
                effective_severity
            ),
            "technical_component": float(
                technical_component.quantize(
                    Decimal("0.000001"),
                    rounding=ROUND_HALF_UP,
                )
            ),
            "criticality_factor": float(
                criticality_factor
            ),
            "data_classification_factor": float(
                data_factor
            ),
            "confidentiality_requirement_factor": float(
                confidentiality_factor
            ),
            "integrity_requirement_factor": float(
                integrity_factor
            ),
            "availability_requirement_factor": float(
                availability_factor
            ),
            "organisational_impact_component": float(
                organisational_component.quantize(
                    Decimal("0.000001"),
                    rounding=ROUND_HALF_UP,
                )
            ),
            "internet_exposure_factor": float(
                internet_factor
            ),
            "environment_factor": float(
                environment_factor
            ),
            "exposure_component": float(
                exposure_component.quantize(
                    Decimal("0.000001"),
                    rounding=ROUND_HALF_UP,
                )
            ),
        },
        "context_snapshot": snapshot,
        "assessment_model": ASSESSMENT_MODEL,
    }
