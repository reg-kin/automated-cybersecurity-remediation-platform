#!/usr/bin/env python3

import logging

import requests
from psycopg2.extras import RealDictCursor

from remediation.shared import db
from remediation.shared.config import (
    CONTROLLER_REMEDIATE_URL,
    CONTROLLER_REQUEST_TIMEOUT,
    CONTROLLER_TOKEN,
)
from remediation.shared.workflow_payload import (
    build_controller_payload,
)


logger = logging.getLogger("automated_remediation.dispatcher")


NEXT_REMEDIATION_SQL = """
SELECT *
FROM eligible_remediation_queue
ORDER BY
    has_contextual_risk DESC,
    contextual_risk_score DESC NULLS LAST,
    detected_at ASC,
    finding_id ASC
LIMIT 1
"""


def select_next(conn):
    """Return the next authoritative remediation candidate or None."""

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(NEXT_REMEDIATION_SQL)
        row = cur.fetchone()

    if row is None:
        return None

    return dict(row)


def response_body(response):
    try:
        body = response.json()
    except ValueError:
        body = {}

    return body if isinstance(body, dict) else {}


def classify_response(response):
    """Classify the existing controller API response deterministically."""

    body = response_body(response)
    status = response.status_code

    if status == 200:
        return "ACCEPTED"

    if status == 202:
        return "AWAITING_APPROVAL"

    if (
        status == 409
        and body.get("code") == "ACTIVE_REMEDIATION_EXISTS"
    ):
        return "DUPLICATE_ACTIVE_EXECUTION"

    if status == 400:
        return "PERMANENT_REQUEST_FAILURE"

    if status == 401:
        return "AUTHENTICATION_FAILURE"

    if status == 409:
        return "STATE_CONFLICT"

    if 500 <= status <= 599:
        return "RETRYABLE_FAILURE"

    return "UNEXPECTED_RESPONSE"


def submit(payload):
    """Submit one already-routed remediation to the controller."""

    if not CONTROLLER_TOKEN or not CONTROLLER_TOKEN.strip():
        raise RuntimeError(
            "CONTROLLER_TOKEN must be configured with a non-empty value"
        )

    return requests.post(
        CONTROLLER_REMEDIATE_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {CONTROLLER_TOKEN}",
        },
        timeout=CONTROLLER_REQUEST_TIMEOUT,
    )


def dispatch_once():
    """Select and deliver at most one remediation candidate."""

    conn = db.connect()

    try:
        queue_row = select_next(conn)
    finally:
        conn.close()

    if queue_row is None:
        return {
            "outcome": "NO_ELIGIBLE_FINDING",
            "finding_id": None,
        }

    payload = build_controller_payload(queue_row)

    try:
        response = submit(payload)
    except requests.RequestException as exc:
        logger.warning(
            "Controller delivery failed for finding_id=%s: %s",
            payload["finding_id"],
            exc,
        )

        return {
            "outcome": "RETRYABLE_FAILURE",
            "finding_id": payload["finding_id"],
            "error": str(exc),
        }

    return {
        "outcome": classify_response(response),
        "finding_id": payload["finding_id"],
        "http_status": response.status_code,
        "response": response_body(response),
    }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    result = dispatch_once()
    logger.info("Dispatcher outcome: %s", result)

    successful_outcomes = {
        "NO_ELIGIBLE_FINDING",
        "ACCEPTED",
        "AWAITING_APPROVAL",
        "DUPLICATE_ACTIVE_EXECUTION",
    }

    if result["outcome"] in successful_outcomes:
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
