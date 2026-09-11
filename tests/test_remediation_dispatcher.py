#!/usr/bin/env python3

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import requests

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import remediation.dispatcher as dispatcher


def fake_response(status, body=None):
    response = Mock()
    response.status_code = status
    response.json.return_value = body if body is not None else {}
    return response


assert dispatcher.classify_response(fake_response(200)) == "ACCEPTED"
assert dispatcher.classify_response(fake_response(202)) == "AWAITING_APPROVAL"
assert dispatcher.classify_response(
    fake_response(409, {"code": "ACTIVE_REMEDIATION_EXISTS"})
) == "DUPLICATE_ACTIVE_EXECUTION"
assert dispatcher.classify_response(fake_response(400)) == "PERMANENT_REQUEST_FAILURE"
assert dispatcher.classify_response(fake_response(401)) == "AUTHENTICATION_FAILURE"
assert dispatcher.classify_response(
    fake_response(409, {"code": "REMEDIATION_STATE_CONFLICT"})
) == "STATE_CONFLICT"
assert dispatcher.classify_response(fake_response(500)) == "RETRYABLE_FAILURE"
assert dispatcher.classify_response(fake_response(503)) == "RETRYABLE_FAILURE"
assert dispatcher.classify_response(fake_response(418)) == "UNEXPECTED_RESPONSE"

print("PASS: dispatcher response classification")


sql = " ".join(dispatcher.NEXT_REMEDIATION_SQL.split())
assert "FROM eligible_remediation_queue" in sql
assert "has_contextual_risk DESC" in sql
assert "contextual_risk_score DESC NULLS LAST" in sql
assert "detected_at ASC" in sql
assert "finding_id ASC" in sql
assert sql.endswith("LIMIT 1")

print("PASS: dispatcher authoritative queue ordering")


connection = Mock()

with patch.object(dispatcher.db, "connect", return_value=connection), patch.object(
    dispatcher,
    "select_next",
    return_value=None,
):
    result = dispatcher.dispatch_once()

assert result == {
    "outcome": "NO_ELIGIBLE_FINDING",
    "finding_id": None,
}
connection.close.assert_called_once_with()

print("PASS: dispatcher empty queue handling")


connection = Mock()
queue_row = {"finding_id": 123}
payload = {"finding_id": 123, "capability": "os_patching"}
response = fake_response(200, {"success": True})

with patch.object(dispatcher.db, "connect", return_value=connection), patch.object(
    dispatcher,
    "select_next",
    return_value=queue_row,
), patch.object(
    dispatcher,
    "build_controller_payload",
    return_value=payload,
) as builder, patch.object(
    dispatcher,
    "submit",
    return_value=response,
) as submit:
    result = dispatcher.dispatch_once()

builder.assert_called_once_with(queue_row)
submit.assert_called_once_with(payload)
assert result["outcome"] == "ACCEPTED"
assert result["finding_id"] == 123
assert result["http_status"] == 200
connection.close.assert_called_once_with()

print("PASS: dispatcher payload construction and delivery")


for response, expected in (
    (fake_response(202, {"status": "AWAITING_APPROVAL"}), "AWAITING_APPROVAL"),
    (
        fake_response(409, {"code": "ACTIVE_REMEDIATION_EXISTS"}),
        "DUPLICATE_ACTIVE_EXECUTION",
    ),
):
    connection = Mock()

    with patch.object(dispatcher.db, "connect", return_value=connection), patch.object(
        dispatcher,
        "select_next",
        return_value={"finding_id": 321},
    ), patch.object(
        dispatcher,
        "build_controller_payload",
        return_value={"finding_id": 321},
    ), patch.object(
        dispatcher,
        "submit",
        return_value=response,
    ):
        result = dispatcher.dispatch_once()

    assert result["outcome"] == expected

print("PASS: dispatcher approval and duplicate handling")


connection = Mock()

with patch.object(dispatcher.db, "connect", return_value=connection), patch.object(
    dispatcher,
    "select_next",
    return_value={"finding_id": 456},
), patch.object(
    dispatcher,
    "build_controller_payload",
    return_value={"finding_id": 456},
), patch.object(
    dispatcher,
    "submit",
    side_effect=requests.ConnectionError("controller unavailable"),
):
    result = dispatcher.dispatch_once()

assert result["outcome"] == "RETRYABLE_FAILURE"
assert result["finding_id"] == 456
assert "controller unavailable" in result["error"]

print("PASS: dispatcher network failure handling")


with patch.object(dispatcher, "CONTROLLER_TOKEN", ""):
    try:
        dispatcher.submit({"finding_id": 1})
    except RuntimeError as exc:
        assert "CONTROLLER_TOKEN must be configured" in str(exc)
    else:
        raise AssertionError("blank controller token was accepted")

print("PASS: dispatcher controller token fails closed")

for outcome, expected_exit_code in (
    ("NO_ELIGIBLE_FINDING", 0),
    ("ACCEPTED", 0),
    ("AWAITING_APPROVAL", 0),
    ("DUPLICATE_ACTIVE_EXECUTION", 0),
    ("PERMANENT_REQUEST_FAILURE", 1),
    ("AUTHENTICATION_FAILURE", 1),
    ("STATE_CONFLICT", 1),
    ("RETRYABLE_FAILURE", 1),
    ("UNEXPECTED_RESPONSE", 1),
):
    with patch.object(
        dispatcher,
        "dispatch_once",
        return_value={"outcome": outcome},
    ):
        exit_code = dispatcher.main()

    assert exit_code == expected_exit_code

print("PASS: dispatcher process exit-code contract")
