#!/usr/bin/env python3

"""Authenticated pull API for Scan Coordination execution nodes.

This API exposes only the execution-node pull plane:

    POST /agent/jobs/lease
    POST /agent/jobs/<scan_execution_id>/start
    POST /agent/jobs/<scan_execution_id>/renew
    POST /agent/jobs/<scan_execution_id>/complete

Execution-node identity is derived exclusively from the authenticated
per-node Bearer credential. Callers cannot select or override node_code.

Two independent credentials protect the protocol:

1. node credential
   Authenticates the execution node to this API.

2. execution lease token
   Authorises lifecycle transitions for one specific leased execution.

This API deliberately does not:
- create or modify scan policies;
- create canonical assets;
- accept caller-controlled node identity;
- invoke scanners itself;
- parse scanner-native evidence;
- determine finding_class;
- construct Unified Security Findings;
- accept findings, severity, risk or remediation decisions.

PostgreSQL and the scan_coordination domain services remain the final
enforcement boundaries.

The API owns transaction boundaries for HTTP requests.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

from remediation.shared import db

from scan_coordination.node_auth import (
    ScanNodeAuthenticationError,
    ScanNodeAuthValidationError,
    authenticate_node_credential,
)

from scan_coordination.service import (
    DEFAULT_LEASE_SECONDS,
    ScanCoordinationConflictError,
    ScanCoordinationNotFoundError,
    ScanCoordinationValidationError,
    ScanLeaseAuthenticationError,
    ScanLeaseExpiredError,
    lease_next_execution,
    mark_execution_failed,
    mark_execution_started,
    mark_execution_succeeded,
    renew_execution_lease,
)


SCAN_COORDINATION_AGENT_HOST = os.getenv(
    "SCAN_COORDINATION_AGENT_HOST",
    "127.0.0.1",
)

SCAN_COORDINATION_AGENT_PORT = int(
    os.getenv(
        "SCAN_COORDINATION_AGENT_PORT",
        "9201",
    )
)


app = Flask(__name__)


LEASE_FIELDS = {
    "lease_seconds",
}

START_FIELDS = {
    "lease_token",
}

RENEW_FIELDS = {
    "lease_token",
    "lease_seconds",
}

COMPLETE_FIELDS = {
    "status",
    "lease_token",
    "exit_code",
    "failure_reason",
    "execution_metadata",
}


def require_json_object():
    """Return a JSON object or raise a coordination validation error."""

    payload = request.get_json(
        silent=True,
    )

    if payload is None:
        return {}

    if not isinstance(payload, dict):
        raise ScanCoordinationValidationError(
            "request body must be a JSON object"
        )

    return payload


def require_field(
    payload,
    field_name,
):
    """Return one required non-blank request field."""

    value = payload.get(
        field_name
    )

    if value is None or not str(value).strip():
        raise ScanCoordinationValidationError(
            f"{field_name} must be non-blank"
        )

    return str(value).strip()


def reject_unknown_fields(
    payload,
    allowed_fields,
):
    """Reject fields outside the narrow execution-agent contract."""

    unknown = sorted(
        set(payload) - set(allowed_fields)
    )

    if unknown:
        raise ScanCoordinationValidationError(
            "unsupported request field(s): "
            + ", ".join(unknown)
        )


def get_bearer_credential():
    """Extract the execution-node Bearer credential.

    The API does not accept node_code from any caller-controlled field.
    """

    auth_header = request.headers.get(
        "Authorization",
        "",
    )

    prefix = "Bearer "

    if not auth_header.startswith(prefix):
        raise ScanNodeAuthenticationError(
            "Invalid execution-node credential"
        )

    credential = auth_header[
        len(prefix):
    ].strip()

    if not credential:
        raise ScanNodeAuthenticationError(
            "Invalid execution-node credential"
        )

    return credential


def authenticate_request_node(conn):
    """Authenticate the caller and derive its authoritative node identity."""

    credential = get_bearer_credential()

    return authenticate_node_credential(
        conn,
        credential=credential,
    )


def unauthorised_response():
    return jsonify(
        {
            "success": False,
            "error": "unauthorised",
            "code": "SCAN_NODE_AUTHENTICATION_ERROR",
        }
    ), 401


def error_response(exc):
    """Map Scan Coordination domain failures to HTTP responses."""

    if isinstance(
        exc,
        (
            ScanCoordinationValidationError,
            ScanNodeAuthValidationError,
        ),
    ):
        status = 400
        code = "SCAN_COORDINATION_VALIDATION_ERROR"

    elif isinstance(
        exc,
        ScanCoordinationNotFoundError,
    ):
        status = 404
        code = "SCAN_EXECUTION_NOT_FOUND"

    elif isinstance(
        exc,
        ScanLeaseAuthenticationError,
    ):
        status = 403
        code = "SCAN_LEASE_AUTHENTICATION_ERROR"

    elif isinstance(
        exc,
        ScanLeaseExpiredError,
    ):
        status = 409
        code = "SCAN_LEASE_EXPIRED"

    elif isinstance(
        exc,
        ScanCoordinationConflictError,
    ):
        status = 409
        code = "SCAN_COORDINATION_CONFLICT"

    else:
        raise TypeError(
            f"Unsupported Scan Coordination error: "
            f"{type(exc).__name__}"
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
            "service": "scan-coordination-agent-api",
        }
    )


@app.post("/agent/jobs/lease")
def lease_job():
    conn = None

    try:
        conn = db.connect()

        with conn:
            authenticated_node = authenticate_request_node(
                conn
            )

            payload = require_json_object()

            reject_unknown_fields(
                payload,
                LEASE_FIELDS,
            )

            lease_seconds = payload.get(
                "lease_seconds",
                DEFAULT_LEASE_SECONDS,
            )

            result = lease_next_execution(
                conn,
                node_code=authenticated_node[
                    "node_code"
                ],
                lease_seconds=lease_seconds,
            )

        if result is None:
            return jsonify(
                {
                    "success": True,
                    "job": None,
                }
            ), 200

        return jsonify(
            {
                "success": True,
                "job": result,
            }
        ), 200

    except ScanNodeAuthenticationError:
        return unauthorised_response()

    except (
        ScanCoordinationValidationError,
        ScanNodeAuthValidationError,
        ScanCoordinationNotFoundError,
        ScanLeaseAuthenticationError,
        ScanLeaseExpiredError,
        ScanCoordinationConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan execution lease request failed"
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
    "/agent/jobs/<int:scan_execution_id>/start"
)
def start_job(scan_execution_id):
    conn = None

    try:
        conn = db.connect()

        with conn:
            authenticated_node = authenticate_request_node(
                conn
            )

            payload = require_json_object()

            reject_unknown_fields(
                payload,
                START_FIELDS,
            )

            lease_token = require_field(
                payload,
                "lease_token",
            )

            result = mark_execution_started(
                conn,
                scan_execution_id=scan_execution_id,
                node_code=authenticated_node[
                    "node_code"
                ],
                lease_token=lease_token,
            )

        return jsonify(
            {
                "success": True,
                "execution": result,
            }
        ), 200

    except ScanNodeAuthenticationError:
        return unauthorised_response()

    except (
        ScanCoordinationValidationError,
        ScanNodeAuthValidationError,
        ScanCoordinationNotFoundError,
        ScanLeaseAuthenticationError,
        ScanLeaseExpiredError,
        ScanCoordinationConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan execution start request failed"
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
    "/agent/jobs/<int:scan_execution_id>/renew"
)
def renew_job(scan_execution_id):
    conn = None

    try:
        conn = db.connect()

        with conn:
            authenticated_node = authenticate_request_node(
                conn
            )

            payload = require_json_object()

            reject_unknown_fields(
                payload,
                RENEW_FIELDS,
            )

            lease_token = require_field(
                payload,
                "lease_token",
            )

            lease_seconds = payload.get(
                "lease_seconds",
                DEFAULT_LEASE_SECONDS,
            )

            result = renew_execution_lease(
                conn,
                scan_execution_id=scan_execution_id,
                node_code=authenticated_node[
                    "node_code"
                ],
                lease_token=lease_token,
                lease_seconds=lease_seconds,
            )

        return jsonify(
            {
                "success": True,
                "execution": result,
            }
        ), 200

    except ScanNodeAuthenticationError:
        return unauthorised_response()

    except (
        ScanCoordinationValidationError,
        ScanNodeAuthValidationError,
        ScanCoordinationNotFoundError,
        ScanLeaseAuthenticationError,
        ScanLeaseExpiredError,
        ScanCoordinationConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan execution lease renewal request failed"
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
    "/agent/jobs/<int:scan_execution_id>/complete"
)
def complete_job(scan_execution_id):
    conn = None

    try:
        conn = db.connect()

        with conn:
            authenticated_node = authenticate_request_node(
                conn
            )

            payload = require_json_object()

            reject_unknown_fields(
                payload,
                COMPLETE_FIELDS,
            )

            status = require_field(
                payload,
                "status",
            ).upper()

            lease_token = require_field(
                payload,
                "lease_token",
            )

            execution_metadata = payload.get(
                "execution_metadata",
                {},
            )

            node_code = authenticated_node[
                "node_code"
            ]

            if status == "SUCCEEDED":
                if "failure_reason" in payload:
                    raise ScanCoordinationValidationError(
                        "failure_reason must not be supplied "
                        "for SUCCEEDED completion"
                    )

                if "exit_code" in payload:
                    raise ScanCoordinationValidationError(
                        "exit_code must not be supplied "
                        "for SUCCEEDED completion"
                    )

                result = mark_execution_succeeded(
                    conn,
                    scan_execution_id=scan_execution_id,
                    node_code=node_code,
                    lease_token=lease_token,
                    execution_metadata=execution_metadata,
                )

            elif status == "FAILED":
                failure_reason = require_field(
                    payload,
                    "failure_reason",
                )

                result = mark_execution_failed(
                    conn,
                    scan_execution_id=scan_execution_id,
                    node_code=node_code,
                    lease_token=lease_token,
                    failure_reason=failure_reason,
                    exit_code=payload.get(
                        "exit_code"
                    ),
                    execution_metadata=execution_metadata,
                )

            else:
                raise ScanCoordinationValidationError(
                    "status must be SUCCEEDED or FAILED"
                )

        return jsonify(
            {
                "success": True,
                "execution": result,
            }
        ), 200

    except ScanNodeAuthenticationError:
        return unauthorised_response()

    except (
        ScanCoordinationValidationError,
        ScanNodeAuthValidationError,
        ScanCoordinationNotFoundError,
        ScanLeaseAuthenticationError,
        ScanLeaseExpiredError,
        ScanCoordinationConflictError,
    ) as exc:
        return error_response(exc)

    except Exception:
        app.logger.exception(
            "Scan execution completion request failed"
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
        host=SCAN_COORDINATION_AGENT_HOST,
        port=SCAN_COORDINATION_AGENT_PORT,
    )
