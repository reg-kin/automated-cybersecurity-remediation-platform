#!/usr/bin/env python3

import hmac
import os

from flask import Flask, jsonify, request

from verification_dispatcher import dispatch


TOKEN = os.getenv("VERIFICATION_TOKEN", "").strip()

if not TOKEN:
    raise RuntimeError(
        "VERIFICATION_TOKEN must be configured and non-empty"
    )

HOST = (
    os.getenv("VERIFICATION_HOST", "127.0.0.1").strip()
    or "127.0.0.1"
)

PORT = int(
    os.getenv("VERIFICATION_PORT", "8090")
)

app = Flask(__name__)


def authorised() -> bool:
    """
    Require an exact Bearer token match.

    The verification gateway must never treat a missing or empty
    configured token as authenticated.
    """

    supplied = request.headers.get(
        "Authorization",
        "",
    )

    expected = f"Bearer {TOKEN}"

    return hmac.compare_digest(
        supplied,
        expected,
    )


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "verification-gateway",
        }
    )


@app.post("/verify")
def verify():

    if not authorised():
        return jsonify(
            {"error": "unauthorised"}
        ), 401

    try:

        payload = request.get_json(
            force=True
        ) or {}

        return jsonify(
            dispatch(payload)
        ), 200

    except Exception as exc:

        app.logger.exception(
            "Verification failed closed"
        )

        return jsonify(
            {
                "verification_status": "FAILED",
                "present": True,
                "verification_error": str(exc),
            }
        ), 500


if __name__ == "__main__":

    app.run(
        host=HOST,
        port=PORT,
    )
