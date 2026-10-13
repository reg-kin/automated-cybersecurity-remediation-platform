#!/usr/bin/env python3

"""Administrative API for scan-policy management.

This API exposes scan-policy administration over HTTP while preserving the
separation between:

- administrative scan-policy configuration and lifecycle management;
- the scan scheduler; and
- the execution-node Agent API.

Administrative audit attribution is derived from the configured
SCAN_POLICY_ADMIN_PRINCIPAL. Callers cannot supply performed_by directly.

PostgreSQL and scan_policy_administration.service remain the final enforcement
boundaries for scan-policy state transitions.
"""

import hmac
import os

from flask import Flask, jsonify, request

from remediation.shared import db
from scan_policy_administration.service import (
    ScanPolicyAdministrationConflictError,
    ScanPolicyAdministrationValidationError,
    ScanPolicyAssetNotFoundError,
    ScanPolicyNotFoundError,
    create_scan_policy,
    disable_scan_policy,
    enable_scan_policy,
    get_scan_policy,
    get_scan_policy_history,
    list_scan_policies,
    update_scan_policy_configuration,
)


SCAN_POLICY_ADMIN_TOKEN = os.getenv(
    "SCAN_POLICY_ADMIN_TOKEN",
    "",
)

SCAN_POLICY_ADMIN_PRINCIPAL = os.getenv(
    "SCAN_POLICY_ADMIN_PRINCIPAL",
    "",
)

SCAN_POLICY_ADMIN_HOST = os.getenv(
    "SCAN_POLICY_ADMIN_HOST",
    "127.0.0.1",
)

SCAN_POLICY_ADMIN_PORT = int(
    os.getenv(
        "SCAN_POLICY_ADMIN_PORT",
        "9102",
    )
)


if not SCAN_POLICY_ADMIN_TOKEN.strip():
    raise RuntimeError(
        "SCAN_POLICY_ADMIN_TOKEN must be configured with a non-empty value"
    )


if not SCAN_POLICY_ADMIN_PRINCIPAL.strip():
    raise RuntimeError(
        "SCAN_POLICY_ADMIN_PRINCIPAL must be configured with a non-empty value"
    )


app = Flask(__name__)


def authorised():
    """Return True only for the configured administrative Bearer token."""

    auth_header = request.headers.get(
        "Authorization",
        "",
    )

    expected = (
        f"Bearer {SCAN_POLICY_ADMIN_TOKEN}"
    )

    return hmac.compare_digest(
        auth_header,
        expected,
    )


def unauthorised_response():
    return jsonify(
        {
            "success": False,
            "error": "unauthorised",
        }
    ), 401


def require_json_object():
    """Return the request JSON object or raise a validation error."""

    payload = request.get_json(
        silent=True,
    )

    if payload is None:
        return {}

    if not isinstance(payload, dict):
        raise ScanPolicyAdministrationValidationError(
            "request body must be a JSON object"
        )

    return payload


def require_field(payload, field_name):
    """Return a required non-blank request field."""

    value = payload.get(
        field_name
    )

    if value is None or not str(value).strip():
        raise ScanPolicyAdministrationValidationError(
            f"{field_name} must be non-blank"
        )

    return value


def require_tenant_query_parameter():
    tenant_code = request.args.get(
        "tenant_code",
        "",
    ).strip()

    if not tenant_code:
        raise ScanPolicyAdministrationValidationError(
            "tenant_code must be non-blank"
        )

    return tenant_code


def reject_performed_by(payload):
    """Prevent caller-controlled administrative audit attribution."""

    if "performed_by" in payload:
        raise ScanPolicyAdministrationValidationError(
            "performed_by must not be supplied by the caller"
        )


def error_response(exc):
    """Map scan-policy administration domain errors to HTTP responses."""

    if isinstance(
        exc,
        ScanPolicyAdministrationValidationError,
    ):
        status = 400
        code = "SCAN_POLICY_VALIDATION_ERROR"

    elif isinstance(
        exc,
        ScanPolicyAssetNotFoundError,
    ):
        status = 404
        code = "SCAN_POLICY_ASSET_NOT_FOUND"

    elif isinstance(
        exc,
        ScanPolicyNotFoundError,
    ):
        status = 404
        code = "SCAN_POLICY_NOT_FOUND"

    elif isinstance(
        exc,
        ScanPolicyAdministrationConflictError,
    ):
        status = 409
        code = "SCAN_POLICY_CONFLICT"

    else:
        raise TypeError(
            f"Unsupported scan-policy administration error: "
            f"{type(exc).__name__}"
        )

    return jsonify(
        {
            "success": False,
            "error": str(exc),
            "code": code,
        }
    ), status


DOMAIN_ERRORS = (
    ScanPolicyAdministrationValidationError,
    ScanPolicyAssetNotFoundError,
    ScanPolicyNotFoundError,
    ScanPolicyAdministrationConflictError,
)


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "scan-policy-admin-api",
        }
    )


@app.get("/admin/scan-policies")
def scan_policy_list():
    if not authorised():
        return unauthorised_response()

    conn = None

    try:
        tenant_code = require_tenant_query_parameter()

        conn = db.connect()

        with conn:
            policies = list_scan_policies(
                conn,
                tenant_code=tenant_code,
            )

        return jsonify(
            {
                "success": True,
                "scan_policies": policies,
            }
        ), 200

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy listing failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()


@app.get("/admin/scan-policies/<int:scan_policy_id>")
def scan_policy_detail(scan_policy_id):
    if not authorised():
        return unauthorised_response()

    conn = None

    try:
        tenant_code = require_tenant_query_parameter()

        conn = db.connect()

        with conn:
            policy = get_scan_policy(
                conn,
                scan_policy_id=scan_policy_id,
                tenant_code=tenant_code,
            )

        return jsonify(
            {
                "success": True,
                "scan_policy": policy,
            }
        ), 200

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy lookup failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()


@app.get("/admin/scan-policies/<int:scan_policy_id>/history")
def scan_policy_history(scan_policy_id):
    if not authorised():
        return unauthorised_response()

    conn = None

    try:
        tenant_code = require_tenant_query_parameter()

        conn = db.connect()

        with conn:
            history = get_scan_policy_history(
                conn,
                scan_policy_id=scan_policy_id,
                tenant_code=tenant_code,
            )

        return jsonify(
            {
                "success": True,
                "history": history,
            }
        ), 200

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy history lookup failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()


@app.post("/admin/scan-policies")
def create_policy():
    if not authorised():
        return unauthorised_response()

    conn = None

    try:
        payload = require_json_object()
        reject_performed_by(payload)

        tenant_code = require_field(
            payload,
            "tenant_code",
        )

        asset_id = require_field(
            payload,
            "asset_id",
        )

        scanner_type = require_field(
            payload,
            "scanner_type",
        )

        service_tier = require_field(
            payload,
            "service_tier",
        )

        reason = require_field(
            payload,
            "reason",
        )

        kwargs = {
            "tenant_code": tenant_code,
            "asset_id": asset_id,
            "scanner_type": scanner_type,
            "service_tier": service_tier,
            "performed_by": SCAN_POLICY_ADMIN_PRINCIPAL,
            "reason": reason,
        }

        for field_name in (
            "profile_name",
            "scanner_parameters",
            "schedule_type",
            "schedule_expression",
            "schedule_timezone",
            "is_enabled",
        ):
            if field_name in payload:
                kwargs[field_name] = payload[field_name]

        conn = db.connect()

        with conn:
            policy = create_scan_policy(
                conn,
                **kwargs,
            )

        return jsonify(
            {
                "success": True,
                "scan_policy": policy,
            }
        ), 201

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy creation failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()


@app.patch("/admin/scan-policies/<int:scan_policy_id>")
def update_policy(scan_policy_id):
    if not authorised():
        return unauthorised_response()

    conn = None

    try:
        payload = require_json_object()
        reject_performed_by(payload)

        tenant_code = require_field(
            payload,
            "tenant_code",
        )

        reason = require_field(
            payload,
            "reason",
        )

        allowed_fields = {
            "tenant_code",
            "reason",
            "scanner_parameters",
            "service_tier",
            "schedule_type",
            "schedule_expression",
            "schedule_timezone",
        }

        unexpected_fields = (
            set(payload)
            - allowed_fields
        )

        if unexpected_fields:
            raise ScanPolicyAdministrationValidationError(
                "unsupported scan policy update field(s): "
                + ", ".join(
                    sorted(unexpected_fields)
                )
            )

        kwargs = {
            "scan_policy_id": scan_policy_id,
            "tenant_code": tenant_code,
            "performed_by": SCAN_POLICY_ADMIN_PRINCIPAL,
            "reason": reason,
        }

        for field_name in (
            "scanner_parameters",
            "service_tier",
            "schedule_type",
            "schedule_expression",
            "schedule_timezone",
        ):
            if field_name in payload:
                kwargs[field_name] = payload[field_name]

        conn = db.connect()

        with conn:
            policy = update_scan_policy_configuration(
                conn,
                **kwargs,
            )

        return jsonify(
            {
                "success": True,
                "scan_policy": policy,
            }
        ), 200

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy configuration update failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500

    finally:
        if conn is not None:
            conn.close()


def lifecycle_request(
    scan_policy_id,
    operation,
    operation_name,
):
    payload = require_json_object()
    reject_performed_by(payload)

    allowed_fields = {
        "tenant_code",
        "reason",
    }

    unexpected_fields = (
        set(payload)
        - allowed_fields
    )

    if unexpected_fields:
        raise ScanPolicyAdministrationValidationError(
            f"unsupported scan policy {operation_name} field(s): "
            + ", ".join(
                sorted(unexpected_fields)
            )
        )

    tenant_code = require_field(
        payload,
        "tenant_code",
    )

    reason = require_field(
        payload,
        "reason",
    )

    conn = None

    try:
        conn = db.connect()

        with conn:
            policy = operation(
                conn,
                scan_policy_id=scan_policy_id,
                tenant_code=tenant_code,
                performed_by=SCAN_POLICY_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "scan_policy": policy,
            }
        ), 200

    finally:
        if conn is not None:
            conn.close()


@app.post("/admin/scan-policies/<int:scan_policy_id>/enable")
def enable_policy(scan_policy_id):
    if not authorised():
        return unauthorised_response()

    try:
        return lifecycle_request(
            scan_policy_id,
            enable_scan_policy,
            "enable",
        )

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy enable failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500


@app.post("/admin/scan-policies/<int:scan_policy_id>/disable")
def disable_policy(scan_policy_id):
    if not authorised():
        return unauthorised_response()

    try:
        return lifecycle_request(
            scan_policy_id,
            disable_scan_policy,
            "disable",
        )

    except DOMAIN_ERRORS as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan policy disable failed"
        )

        return jsonify(
            {
                "success": False,
                "error": "Internal server error",
            }
        ), 500


if __name__ == "__main__":
    app.run(
        host=SCAN_POLICY_ADMIN_HOST,
        port=SCAN_POLICY_ADMIN_PORT,
    )
