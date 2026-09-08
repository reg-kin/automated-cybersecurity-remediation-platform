#!/usr/bin/env python3

"""Regression tests for deterministic contextual risk assessment."""

import os
import sys


REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


from risk_management.contextualiser import (
    ASSESSMENT_MODEL,
    contextualise_risk,
)


FULL_CONTEXT = {
    "environment": "PRODUCTION",
    "business_service": "Customer Portal",
    "business_unit": "Digital",
    "owner": "Business Owner",
    "technical_owner": "Platform Team",
    "criticality": "CRITICAL",
    "data_classification": "RESTRICTED",
    "internet_exposure": "INTERNET_FACING",
    "network_zone": "DMZ",
    "confidentiality_requirement": "CRITICAL",
    "integrity_requirement": "CRITICAL",
    "availability_requirement": "CRITICAL",
    "context_source": "MANUAL",
}


def test_full_context_calculation():
    assessment = contextualise_risk(
        severity_score=8.0,
        severity_level="HIGH",
        asset_id=101,
        asset_context=FULL_CONTEXT,
    )

    assert assessment["assessment_status"] == "ASSESSED"
    assert assessment["base_severity_score"] == 8.0
    assert assessment["base_severity_level"] == "HIGH"
    assert assessment["contextual_risk_score"] == 8.8
    assert assessment["contextual_risk_level"] == "HIGH"
    assert assessment["assessment_model"] == ASSESSMENT_MODEL

    factors = assessment["assessment_factors"]

    assert factors["technical_severity_source"] == "severity_score"
    assert factors["effective_technical_severity"] == 8.0
    assert factors["technical_component"] == 4.8
    assert factors["organisational_impact_component"] == 3.0
    assert factors["exposure_component"] == 1.0


def test_numeric_score_takes_precedence_over_level():
    assessment = contextualise_risk(
        severity_score=4.0,
        severity_level="CRITICAL",
        asset_id=None,
        asset_context=None,
    )

    assert assessment["assessment_status"] == "PARTIAL"
    assert assessment["base_severity_score"] == 4.0
    assert assessment["base_severity_level"] == "CRITICAL"
    assert assessment["contextual_risk_score"] == 2.4
    assert assessment["contextual_risk_level"] == "LOW"

    factors = assessment["assessment_factors"]

    assert factors["technical_severity_source"] == "severity_score"
    assert factors["effective_technical_severity"] == 4.0


def test_severity_level_fallback_does_not_fabricate_base_score():
    assessment = contextualise_risk(
        severity_score=None,
        severity_level="HIGH",
        asset_id=None,
        asset_context=None,
    )

    assert assessment["assessment_status"] == "PARTIAL"
    assert assessment["base_severity_score"] is None
    assert assessment["base_severity_level"] == "HIGH"
    assert assessment["contextual_risk_score"] == 4.8
    assert assessment["contextual_risk_level"] == "MEDIUM"

    factors = assessment["assessment_factors"]

    assert (
        factors["technical_severity_source"]
        == "severity_level_fallback"
    )
    assert factors["effective_technical_severity"] == 8.0


def test_missing_asset_context_is_partial():
    assessment = contextualise_risk(
        severity_score=9.5,
        severity_level="CRITICAL",
        asset_id=201,
        asset_context=None,
    )

    assert assessment["assessment_status"] == "PARTIAL"
    assert assessment["context_snapshot"] is None
    assert assessment["contextual_risk_score"] == 5.7
    assert assessment["contextual_risk_level"] == "MEDIUM"


def test_unresolved_asset_with_context_is_partial():
    assessment = contextualise_risk(
        severity_score=8.0,
        severity_level="HIGH",
        asset_id=None,
        asset_context=FULL_CONTEXT,
    )

    assert assessment["assessment_status"] == "PARTIAL"
    assert assessment["contextual_risk_score"] == 8.8


def test_no_technical_severity_is_unscorable():
    assessment = contextualise_risk(
        severity_score=None,
        severity_level=None,
        asset_id=301,
        asset_context=FULL_CONTEXT,
    )

    assert assessment["assessment_status"] == "UNSCORABLE"
    assert assessment["base_severity_score"] is None
    assert assessment["base_severity_level"] is None
    assert assessment["contextual_risk_score"] is None
    assert assessment["contextual_risk_level"] is None
    assert assessment["assessment_model"] == ASSESSMENT_MODEL


def test_context_snapshot_preserves_audit_fields():
    assessment = contextualise_risk(
        severity_score=8.0,
        severity_level="HIGH",
        asset_id=401,
        asset_context=FULL_CONTEXT,
    )

    snapshot = assessment["context_snapshot"]

    assert snapshot["environment"] == "PRODUCTION"
    assert snapshot["business_service"] == "Customer Portal"
    assert snapshot["business_unit"] == "Digital"
    assert snapshot["owner"] == "Business Owner"
    assert snapshot["technical_owner"] == "Platform Team"
    assert snapshot["network_zone"] == "DMZ"
    assert snapshot["context_source"] == "MANUAL"

def test_contextualisation_does_not_mutate_context():
    context = dict(FULL_CONTEXT)
    original = dict(context)

    contextualise_risk(
        severity_score=8.0,
        severity_level="HIGH",
        asset_id=450,
        asset_context=context,
    )

    assert context == original

def test_contextualisation_does_not_mutate_context():
    context = dict(FULL_CONTEXT)
    original = dict(context)

    contextualise_risk(
        severity_score=8.0,
        severity_level="HIGH",
        asset_id=450,
        asset_context=context,
    )

    assert context == original

def test_unknown_context_contributes_zero():
    context = {
        "environment": "UNKNOWN",
        "criticality": "UNKNOWN",
        "data_classification": "UNKNOWN",
        "internet_exposure": "UNKNOWN",
        "confidentiality_requirement": "UNKNOWN",
        "integrity_requirement": "UNKNOWN",
        "availability_requirement": "UNKNOWN",
    }

    assessment = contextualise_risk(
        severity_score=10.0,
        severity_level="CRITICAL",
        asset_id=501,
        asset_context=context,
    )

    assert assessment["assessment_status"] == "ASSESSED"
    assert assessment["contextual_risk_score"] == 6.0
    assert assessment["contextual_risk_level"] == "MEDIUM"


def test_contextual_risk_band_boundaries():
    low = contextualise_risk(
        severity_score=6.5,
        severity_level=None,
        asset_id=None,
        asset_context=None,
    )

    medium = contextualise_risk(
        severity_score=6.6666667,
        severity_level=None,
        asset_id=None,
        asset_context=None,
    )

    high = contextualise_risk(
        severity_score=10.0,
        severity_level=None,
        asset_id=601,
        asset_context={
            "criticality": "HIGH",
            "data_classification": "CONFIDENTIAL",
            "confidentiality_requirement": "HIGH",
            "integrity_requirement": "HIGH",
            "availability_requirement": "HIGH",
            "internet_exposure": "INTERNAL",
            "environment": "UNKNOWN",
        },
    )

    critical = contextualise_risk(
        severity_score=10.0,
        severity_level=None,
        asset_id=602,
        asset_context={
            "criticality": "CRITICAL",
            "data_classification": "RESTRICTED",
            "confidentiality_requirement": "CRITICAL",
            "integrity_requirement": "CRITICAL",
            "availability_requirement": "CRITICAL",
            "internet_exposure": "UNKNOWN",
            "environment": "UNKNOWN",
        },
    )

    assert low["contextual_risk_score"] == 3.9
    assert low["contextual_risk_level"] == "LOW"

    assert medium["contextual_risk_score"] == 4.0
    assert medium["contextual_risk_level"] == "MEDIUM"

    assert high["contextual_risk_level"] == "HIGH"

    assert critical["contextual_risk_score"] == 9.0
    assert critical["contextual_risk_level"] == "CRITICAL"


def test_invalid_severity_score_is_rejected():
    for invalid in (-0.01, 10.01, "invalid", float("inf")):
        try:
            contextualise_risk(
                severity_score=invalid,
                severity_level="HIGH",
                asset_id=None,
                asset_context=None,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"Invalid severity score accepted: {invalid!r}"
            )


def test_invalid_severity_level_is_rejected():
    try:
        contextualise_risk(
            severity_score=None,
            severity_level="EXTREME",
            asset_id=None,
            asset_context=None,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid severity level must raise ValueError"
        )


def test_invalid_scored_context_value_is_rejected():
    context = dict(FULL_CONTEXT)
    context["criticality"] = "EXTREME"

    try:
        contextualise_risk(
            severity_score=8.0,
            severity_level="HIGH",
            asset_id=701,
            asset_context=context,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid criticality must raise ValueError"
        )


def test_asset_context_must_be_dictionary():
    try:
        contextualise_risk(
            severity_score=8.0,
            severity_level="HIGH",
            asset_id=801,
            asset_context="PRODUCTION",
        )
    except TypeError:
        pass
    else:
        raise AssertionError(
            "Non-dictionary asset context must raise TypeError"
        )


def run_test(name, function):
    function()
    print(f"PASS: {name}")


def main():
    tests = (
        test_full_context_calculation,
        test_numeric_score_takes_precedence_over_level,
        test_severity_level_fallback_does_not_fabricate_base_score,
        test_missing_asset_context_is_partial,
        test_unresolved_asset_with_context_is_partial,
        test_no_technical_severity_is_unscorable,
        test_context_snapshot_preserves_audit_fields,
        test_contextualisation_does_not_mutate_context,
        test_unknown_context_contributes_zero,
        test_contextual_risk_band_boundaries,
        test_invalid_severity_score_is_rejected,
        test_invalid_severity_level_is_rejected,
        test_invalid_scored_context_value_is_rejected,
        test_asset_context_must_be_dictionary,
    )

    for test in tests:
        run_test(
            test.__name__,
            test,
        )

    print(
        "PASS: deterministic risk contextualisation regression tests"
    )


if __name__ == "__main__":
    main()
