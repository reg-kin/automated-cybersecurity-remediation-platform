"""Authenticated, tenant-scoped Manual Verification decision API."""

import os

from flask import Flask, jsonify, request

from manual_verification.auth import (
    ReviewerAuthenticationError,
    authenticate_reviewer_credential,
)
from manual_verification.service import record_decision
from remediation.shared import db


app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/manual-verification/reviews/<int:review_id>/decisions")
def submit_decision(review_id):
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        return jsonify({"error": "Authentication required"}), 401

    credential = authorization[len("Bearer "):].strip()

    if not credential:
        return jsonify({"error": "Authentication required"}), 401

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object required"}), 400

    allowed_fields = {"decision", "justification", "evidence"}

    if set(payload) - allowed_fields:
        return jsonify({"error": "Unsupported request fields"}), 400

    conn = None

    try:
        conn = db.connect()

        with conn:
            reviewer = authenticate_reviewer_credential(
                conn,
                credential=credential,
            )

            result = record_decision(
                conn,
                review_id=review_id,
                tenant_code=reviewer["tenant_code"],
                reviewer_id=reviewer["reviewer_id"],
                decision=payload.get("decision"),
                justification=payload.get("justification"),
                evidence=payload.get("evidence"),
            )

        return jsonify(result), 200

    except ReviewerAuthenticationError:
        return jsonify({"error": "Invalid reviewer credential"}), 401

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    except Exception:
        app.logger.exception("Manual Verification decision failed")
        return jsonify({"error": "Manual Verification request failed"}), 500

    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(
        "Run this API through an explicitly configured WSGI server; "
        "the Flask development server is disabled."
    )
