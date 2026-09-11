#!/usr/bin/env python3

"""Administrative API for remediation-readiness management.

This API exposes the administrative remediation-readiness service over
HTTP while preserving the separation between:

- the remediation runtime controller; and
- administrative authorisation of remediation readiness.

Administrative audit attribution is derived from the configured
READINESS_ADMIN_PRINCIPAL. Callers cannot supply performed_by directly.

PostgreSQL and readiness_management.service remain the final enforcement
boundaries for remediation-readiness state transitions.
"""

import hmac
import os

from flask import Flask, jsonify, request

from remediation.shared import db
from readiness_management.service import (
    AssetNotFoundError,
    ReadinessConflictError,
    ReadinessValidationError,
    authorise_asset_management,
    authorise_execution_target,
    get_asset_readiness,
    get_asset_readiness_history,
    replace_execution_target,
    revoke_asset_management,
    revoke_execution_target,
)


READINESS_ADMIN_TOKEN = os.getenv(
    "READINESS_ADMIN_TOKEN",
    "",
)

READINESS_ADMIN_PRINCIPAL = os.getenv(
    "READINESS_ADMIN_PRINCIPAL",
    "",
)

READINESS_ADMIN_HOST = os.getenv(
    "READINESS_ADMIN_HOST",
    "127.0.0.1",
)

READINESS_ADMIN_PORT = int(
    os.getenv(
        "READINESS_ADMIN_PORT",
        "9100",
    )
)


if not READINESS_ADMIN_TOKEN.strip():
    raise RuntimeError(
        "READINESS_ADMIN_TOKEN must be configured with a non-empty value"
    )


if not READINESS_ADMIN_PRINCIPAL.strip():
    raise RuntimeError(
        "READINESS_ADMIN_PRINCIPAL must be configured with a non-empty value"
    )


app = Flask(__name__)


def authorised():
    """Return True only for the configured administrative Bearer token."""

    auth_header = request.headers.get(
        "Authorization",
        "",
    )

    expected = (
        f"Bearer {READINESS_ADMIN_TOKEN}"
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
        raise ReadinessValidationError(
            "request body must be a JSON object"
        )

    return payload


def require_field(payload, field_name):
    """Return a required non-blank request field."""

    value = payload.get(
        field_name
    )

    if value is None or not str(value).strip():
        raise ReadinessValidationError(
            f"{field_name} must be non-blank"
        )

    return str(value).strip()


def reject_performed_by(payload):
    """Prevent caller-controlled administrative audit attribution."""

    if "performed_by" in payload:
        raise ReadinessValidationError(
            "performed_by must not be supplied by the caller"
        )


def error_response(exc):
    """Map readiness-management domain errors to HTTP responses."""

    if isinstance(
        exc,
        ReadinessValidationError,
    ):
        status = 400
        code = "READINESS_VALIDATION_ERROR"

    elif isinstance(
        exc,
        AssetNotFoundError,
    ):
        status = 404
        code = "ASSET_NOT_FOUND"

    elif isinstance(
        exc,
        ReadinessConflictError,
    ):
        status = 409
        code = "READINESS_CONFLICT"

    else:
        raise TypeError(
            f"Unsupported readiness error: {type(exc).__name__}"
        )

    return jsonify(
        {
            "success": False,
            "error": str(exc),
            "code": code,
        }
    ), status


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "readiness-admin-api",
        }
    )


@app.get(
    "/admin/assets/<int:asset_id>/readiness"
)
def asset_readiness(asset_id):
    if not authorised():
        return unauthorised_response()

    tenant_code = request.args.get(
        "tenant_code",
        "",
    ).strip()

    if not tenant_code:
        return jsonify(
            {
                "success": False,
                "error": "tenant_code must be non-blank",
                "code": "READINESS_VALIDATION_ERROR",
            }
        ), 400

    conn = None

    try:
        conn = db.connect()

        with conn:
            result = get_asset_readiness(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
            )

        return jsonify(
            {
                "success": True,
                "readiness": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Readiness lookup failed"
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


@app.get(
    "/admin/assets/<int:asset_id>/readiness/history"
)
def asset_readiness_history(asset_id):
    if not authorised():
        return unauthorised_response()

    tenant_code = request.args.get(
        "tenant_code",
        "",
    ).strip()

    if not tenant_code:
        return jsonify(
            {
                "success": False,
                "error": "tenant_code must be non-blank",
                "code": "READINESS_VALIDATION_ERROR",
            }
        ), 400

    conn = None

    try:
        conn = db.connect()

        with conn:
            result = get_asset_readiness_history(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
            )

        return jsonify(
            {
                "success": True,
                "history": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Readiness history lookup failed"
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


@app.post(
    "/admin/assets/<int:asset_id>/management/authorise"
)
def authorise_management(asset_id):
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

        conn = db.connect()

        with conn:
            result = authorise_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
                performed_by=READINESS_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "asset": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Asset management authorisation failed"
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


@app.post(
    "/admin/assets/<int:asset_id>/management/revoke"
)
def revoke_management(asset_id):
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

        conn = db.connect()

        with conn:
            result = revoke_asset_management(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
                performed_by=READINESS_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "asset": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Asset management revocation failed"
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


@app.post(
    "/admin/assets/<int:asset_id>/execution-target/authorise"
)
def authorise_target(asset_id):
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

        execution_target = require_field(
            payload,
            "execution_target",
        )

        reason = require_field(
            payload,
            "reason",
        )

        conn = db.connect()

        with conn:
            result = authorise_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
                execution_target=execution_target,
                performed_by=READINESS_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "execution_target": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Execution-target authorisation failed"
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


@app.post(
    "/admin/assets/<int:asset_id>/execution-target/revoke"
)
def revoke_target(asset_id):
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

        conn = db.connect()

        with conn:
            result = revoke_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
                performed_by=READINESS_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "execution_target": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Execution-target revocation failed"
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


@app.post(
    "/admin/assets/<int:asset_id>/execution-target/replace"
)
def replace_target(asset_id):
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

        execution_target = require_field(
            payload,
            "execution_target",
        )

        reason = require_field(
            payload,
            "reason",
        )

        conn = db.connect()

        with conn:
            result = replace_execution_target(
                conn,
                asset_id=asset_id,
                tenant_code=tenant_code,
                execution_target=execution_target,
                performed_by=READINESS_ADMIN_PRINCIPAL,
                reason=reason,
            )

        return jsonify(
            {
                "success": True,
                "execution_target": result,
            }
        ), 200

    except (
        ReadinessValidationError,
        AssetNotFoundError,
        ReadinessConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Execution-target replacement failed"
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


if __name__ == "__main__":
    app.run(
        host=READINESS_ADMIN_HOST,
        port=READINESS_ADMIN_PORT,
    )
