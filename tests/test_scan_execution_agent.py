#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from scan_coordination.execution_agent import (
    ScanExecutionAgent,
    ScanExecutionAgentAPIError,
    ScanExecutionAgentConfigurationError,
    ScanExecutionAgentJobError,
    ScanExecutionAgentProtocolError,
)


class FakeProcess:
    def __init__(
        self,
        poll_results,
    ):
        self.poll_results = list(
            poll_results
        )
        self.last_result = None
        self.terminate_called = False
        self.kill_called = False
        self.wait_calls = []

    def poll(self):
        if self.poll_results:
            self.last_result = (
                self.poll_results.pop(0)
            )

        return self.last_result

    def terminate(self):
        self.terminate_called = True

    def kill(self):
        self.kill_called = True

    def wait(
        self,
        timeout=None,
    ):
        self.wait_calls.append(timeout)

        if self.last_result is None:
            self.last_result = -15

        return self.last_result


class UnresponsiveProcess(FakeProcess):
    def wait(
        self,
        timeout=None,
    ):
        self.wait_calls.append(timeout)

        if timeout is not None:
            raise subprocess.TimeoutExpired(
                cmd="scanner",
                timeout=timeout,
            )

        self.last_result = -9
        return self.last_result


def make_job(
    *,
    scanner_type="nmap_nse",
    scanner_parameters=None,
):
    if scanner_parameters is None:
        scanner_parameters = {
            "task_name": "test-nmap",
            "scan_mode": "vuln_only",
        }

    return {
        "scan_execution_id": 101,
        "scan_policy_id": 41,
        "tenant_code": "TEST-TENANT",
        "asset_id": 51,
        "scanner_type": scanner_type,
        "service_tier": "STANDARD",
        "execution_node_id": 11,
        "node_code": "scanner-node-1",
        "execution_model": (
            "REMOTE_TARGET"
            if scanner_type == "nmap_nse"
            else "CONTROL_PLANE"
        ),
        "scanner_subject_type": (
            "IP_ADDRESS"
            if scanner_type == "nmap_nse"
            else "WAZUH_AGENT_ID"
        ),
        "scanner_subject_value": (
            "192.0.2.10"
            if scanner_type == "nmap_nse"
            else "001"
        ),
        "scanner_parameters": (
            scanner_parameters
        ),
        "status": "LEASED",
        "scheduled_for": (
            "2026-09-12T15:00:00+00:00"
        ),
        "leased_at": (
            "2026-09-12T15:00:01+00:00"
        ),
        "lease_expires_at": (
            "2026-09-12T15:05:01+00:00"
        ),
        "lease_token": "lease-secret-token",
    }


def make_response(
    *,
    status_code=200,
    body=None,
):
    response = Mock()
    response.status_code = status_code
    response.ok = (
        200 <= status_code < 300
    )
    response.json.return_value = (
        {} if body is None else body
    )
    return response


def make_agent(
    *,
    session=None,
    supported_scanners=None,
):
    if session is None:
        session = Mock()

    if supported_scanners is None:
        supported_scanners = {
            "nmap_nse",
            "wazuh_vulnerability",
        }

    return ScanExecutionAgent(
        api_url="http://127.0.0.1:19201",
        node_credential="node-secret",
        supported_scanners=(
            supported_scanners
        ),
        repository_root=ROOT,
        python_executable=sys.executable,
        http_timeout_seconds=5,
        lease_seconds=120,
        session=session,
    )


def test_configuration():
    try:
        ScanExecutionAgent(
            api_url="http://127.0.0.1:19201",
            node_credential="",
            supported_scanners={
                "nmap_nse"
            },
            repository_root=ROOT,
        )
    except ScanExecutionAgentConfigurationError:
        pass
    else:
        raise AssertionError(
            "blank node credential "
            "must be rejected"
        )

    try:
        ScanExecutionAgent(
            api_url="http://127.0.0.1:19201",
            node_credential="credential",
            supported_scanners={
                "not-a-scanner"
            },
            repository_root=ROOT,
        )
    except ScanExecutionAgentConfigurationError:
        pass
    else:
        raise AssertionError(
            "unknown local scanner "
            "must be rejected"
        )

    print(
        "PASS: execution-agent "
        "configuration validation"
    )


def test_empty_lease():
    session = Mock()

    session.post.return_value = (
        make_response(
            body={
                "success": True,
                "job": None,
            }
        )
    )

    agent = make_agent(
        session=session
    )

    assert agent.run_once() is None

    call = session.post.call_args

    assert call.args[0] == (
        "http://127.0.0.1:19201/"
        "agent/jobs/lease"
    )

    assert call.kwargs["json"] == {
        "lease_seconds": 120,
    }

    assert (
        call.kwargs["headers"][
            "Authorization"
        ]
        == "Bearer node-secret"
    )

    print(
        "PASS: empty lease handled "
        "without scanner execution"
    )


def test_successful_execution():
    session = Mock()

    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "SUCCEEDED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    process = FakeProcess(
        [0]
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
        return_value=process,
    ) as popen_mock:
        result = agent.run_once()

    assert result["status"] == "SUCCEEDED"
    assert result["exit_code"] == 0

    assert session.post.call_count == 3

    start_call = (
        session.post.call_args_list[1]
    )

    assert start_call.args[0].endswith(
        "/agent/jobs/101/start"
    )

    assert start_call.kwargs["json"] == {
        "lease_token": (
            "lease-secret-token"
        ),
    }

    complete_call = (
        session.post.call_args_list[2]
    )

    completion_payload = (
        complete_call.kwargs["json"]
    )

    assert (
        completion_payload["status"]
        == "SUCCEEDED"
    )
    assert (
        completion_payload["lease_token"]
        == "lease-secret-token"
    )
    assert (
        "exit_code"
        not in completion_payload
    )
    assert (
        "failure_reason"
        not in completion_payload
    )
    assert (
        completion_payload[
            "execution_metadata"
        ]["scanner_type"]
        == "nmap_nse"
    )

    popen_mock.assert_called_once()

    command = popen_mock.call_args.args[0]

    assert isinstance(command, list)
    assert "--mode" in command
    assert "scan" in command
    assert "--tenant-code" in command
    assert "TEST-TENANT" in command
    assert "--service-tier" in command
    assert "STANDARD" in command
    assert "--target-host" in command
    assert "192.0.2.10" in command

    assert (
        popen_mock.call_args.kwargs[
            "shell"
        ]
        is False
    )

    print(
        "PASS: successful scanner "
        "execution lifecycle"
    )


def test_long_running_execution_renews_lease():
    session = Mock()
    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                    "lease_expires_at": (
                        "2026-09-12T15:07:00+00:00"
                    ),
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "SUCCEEDED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    assert (
        agent._renewal_interval_seconds()
        == 40.0
    )

    process = FakeProcess(
        [
            None,
            0,
        ]
    )

    with (
        patch(
            "scan_coordination.execution_agent."
            "subprocess.Popen",
            return_value=process,
        ),
        patch.object(
            agent,
            "_renewal_interval_seconds",
            return_value=0.0,
        ),
        patch(
            "scan_coordination.execution_agent."
            "time.monotonic",
            return_value=0.0,
        ),
    ):
        result = agent.run_once()

    assert result["status"] == "SUCCEEDED"
    assert session.post.call_count == 4

    renewal_call = (
        session.post.call_args_list[2]
    )

    assert renewal_call.args[0].endswith(
        "/agent/jobs/101/renew"
    )

    assert renewal_call.kwargs["json"] == {
        "lease_token": "lease-secret-token",
        "lease_seconds": 120,
    }

    completion_call = (
        session.post.call_args_list[3]
    )

    assert completion_call.args[0].endswith(
        "/agent/jobs/101/complete"
    )

    assert (
        completion_call.kwargs["json"]["status"]
        == "SUCCEEDED"
    )

    assert process.terminate_called is False
    assert process.kill_called is False

    print(
        "PASS: long-running scanner renews "
        "its execution lease before completion"
    )


def test_nonzero_scanner_exit():
    session = Mock()

    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "FAILED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    process = FakeProcess(
        [7]
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
        return_value=process,
    ):
        result = agent.run_once()

    assert result["status"] == "FAILED"
    assert result["exit_code"] == 7

    payload = (
        session.post.call_args_list[2]
        .kwargs["json"]
    )

    assert payload["status"] == "FAILED"
    assert payload["exit_code"] == 7

    assert (
        "non-zero status 7"
        in payload["failure_reason"]
    )

    print(
        "PASS: non-zero scanner "
        "exit reported FAILED"
    )


def test_local_capability_rejection():
    session = Mock()

    job = make_job(
        scanner_type=(
            "wazuh_vulnerability"
        ),
        scanner_parameters={
            "severities": "high"
        },
    )

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "FAILED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session,
        supported_scanners={
            "nmap_nse"
        },
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
    ) as popen_mock:
        result = agent.run_once()

    assert result["status"] == "FAILED"
    popen_mock.assert_not_called()

    payload = (
        session.post.call_args_list[2]
        .kwargs["json"]
    )

    assert payload["status"] == "FAILED"

    assert (
        "not enabled on this "
        "execution node"
        in payload["failure_reason"]
    )

    print(
        "PASS: local scanner capability "
        "enforced before subprocess"
    )


def test_adapter_validation_failure():
    session = Mock()

    job = make_job(
        scanner_parameters={
            "task_name": "test-nmap",
            "scan_mode": "safe",
        }
    )

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "FAILED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
    ) as popen_mock:
        result = agent.run_once()

    assert result["status"] == "FAILED"
    popen_mock.assert_not_called()

    payload = (
        session.post.call_args_list[2]
        .kwargs["json"]
    )

    assert payload["status"] == "FAILED"

    assert (
        "Nmap scan_mode"
        in payload["failure_reason"]
    )

    print(
        "PASS: scanner-specific "
        "adapter validation remains "
        "at node boundary"
    )


def test_subprocess_exception():
    session = Mock()

    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "FAILED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
        side_effect=OSError(
            "scanner executable unavailable"
        ),
    ):
        result = agent.run_once()

    assert result["status"] == "FAILED"
    assert result["exit_code"] is None

    payload = (
        session.post.call_args_list[2]
        .kwargs["json"]
    )

    assert (
        "scanner executable unavailable"
        in payload["failure_reason"]
    )

    assert "exit_code" not in payload

    print(
        "PASS: local execution exception "
        "reported FAILED"
    )


def test_start_failure_prevents_scanner():
    session = Mock()

    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            status_code=409,
            body={
                "success": False,
                "error": "Lease expired",
                "code": (
                    "SCAN_LEASE_EXPIRED"
                ),
            },
        ),
    ]

    agent = make_agent(
        session=session
    )

    with patch(
        "scan_coordination.execution_agent."
        "subprocess.Popen",
    ) as popen_mock:
        try:
            agent.run_once()
        except ScanExecutionAgentAPIError as exc:
            assert exc.status_code == 409
            assert (
                exc.error_code
                == "SCAN_LEASE_EXPIRED"
            )
        else:
            raise AssertionError(
                "start failure must "
                "raise API error"
            )

    popen_mock.assert_not_called()

    assert session.post.call_count == 2

    print(
        "PASS: failed STARTED transition "
        "prevents scanner execution"
    )


def test_renewal_failure_terminates_scanner():
    session = Mock()
    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            status_code=409,
            body={
                "success": False,
                "error": "Lease expired",
                "code": "SCAN_LEASE_EXPIRED",
            },
        ),
    ]

    agent = make_agent(
        session=session
    )

    process = FakeProcess(
        [
            None,
            None,
        ]
    )

    with (
        patch(
            "scan_coordination.execution_agent."
            "subprocess.Popen",
            return_value=process,
        ),
        patch.object(
            agent,
            "_renewal_interval_seconds",
            return_value=0.0,
        ),
        patch(
            "scan_coordination.execution_agent."
            "time.monotonic",
            return_value=0.0,
        ),
    ):
        try:
            agent.run_once()
        except ScanExecutionAgentAPIError as exc:
            assert exc.status_code == 409
            assert (
                exc.error_code
                == "SCAN_LEASE_EXPIRED"
            )
        else:
            raise AssertionError(
                "renewal failure must propagate "
                "the control-plane API error"
            )

    assert process.terminate_called is True
    assert process.kill_called is False

    assert session.post.call_count == 3

    assert session.post.call_args_list[
        2
    ].args[0].endswith(
        "/agent/jobs/101/renew"
    )

    assert not any(
        call.args[0].endswith(
            "/agent/jobs/101/complete"
        )
        for call in session.post.call_args_list
    )

    print(
        "PASS: lease-renewal failure terminates "
        "scanner and suppresses terminal completion"
    )


def test_renewal_failure_force_kills_unresponsive_scanner():
    session = Mock()
    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            status_code=409,
            body={
                "success": False,
                "error": "Lease expired",
                "code": "SCAN_LEASE_EXPIRED",
            },
        ),
    ]

    agent = make_agent(
        session=session
    )

    process = UnresponsiveProcess(
        [
            None,
            None,
        ]
    )

    with (
        patch(
            "scan_coordination.execution_agent."
            "subprocess.Popen",
            return_value=process,
        ),
        patch.object(
            agent,
            "_renewal_interval_seconds",
            return_value=0.0,
        ),
        patch(
            "scan_coordination.execution_agent."
            "time.monotonic",
            return_value=0.0,
        ),
    ):
        try:
            agent.run_once()
        except ScanExecutionAgentAPIError as exc:
            assert exc.status_code == 409
            assert (
                exc.error_code
                == "SCAN_LEASE_EXPIRED"
            )
        else:
            raise AssertionError(
                "renewal failure must propagate "
                "the control-plane API error"
            )

    assert process.terminate_called is True
    assert process.kill_called is True

    assert process.wait_calls == [
        10.0,
        None,
    ]

    assert session.post.call_count == 3

    assert not any(
        call.args[0].endswith(
            "/agent/jobs/101/complete"
        )
        for call in session.post.call_args_list
    )

    print(
        "PASS: unresponsive scanner is force-killed "
        "after lease-renewal failure"
    )


def test_renewal_protocol_failure_terminates_scanner():
    session = Mock()
    job = make_job()

    session.post.side_effect = [
        make_response(
            body={
                "success": True,
                "job": job,
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "RUNNING",
                },
            }
        ),
        make_response(
            body={
                "success": True,
                "execution": {
                    "status": "SUCCEEDED",
                },
            }
        ),
    ]

    agent = make_agent(
        session=session
    )

    process = FakeProcess(
        [
            None,
            None,
        ]
    )

    with (
        patch(
            "scan_coordination.execution_agent."
            "subprocess.Popen",
            return_value=process,
        ),
        patch.object(
            agent,
            "_renewal_interval_seconds",
            return_value=0.0,
        ),
        patch(
            "scan_coordination.execution_agent."
            "time.monotonic",
            return_value=0.0,
        ),
    ):
        try:
            agent.run_once()
        except ScanExecutionAgentProtocolError as exc:
            assert (
                "status must be RUNNING"
                in str(exc)
            )
        else:
            raise AssertionError(
                "malformed renewal response must "
                "raise protocol error"
            )

    assert process.terminate_called is True
    assert process.kill_called is False

    assert session.post.call_count == 3

    assert session.post.call_args_list[
        2
    ].args[0].endswith(
        "/agent/jobs/101/renew"
    )

    assert not any(
        call.args[0].endswith(
            "/agent/jobs/101/complete"
        )
        for call in session.post.call_args_list
    )

    print(
        "PASS: malformed renewal response "
        "terminates scanner and suppresses completion"
    )


def test_protocol_validation():
    session = Mock()

    bad_job = make_job()
    del bad_job["lease_token"]

    session.post.return_value = (
        make_response(
            body={
                "success": True,
                "job": bad_job,
            }
        )
    )

    agent = make_agent(
        session=session
    )

    try:
        agent.lease_job()
    except ScanExecutionAgentProtocolError:
        pass
    else:
        raise AssertionError(
            "lease without lease_token "
            "must be rejected"
        )

    print(
        "PASS: malformed leased job "
        "rejected"
    )


def test_node_credential_not_in_payload():
    session = Mock()

    session.post.return_value = (
        make_response(
            body={
                "success": True,
                "job": None,
            }
        )
    )

    agent = make_agent(
        session=session
    )

    agent.lease_job()

    payload = (
        session.post.call_args.kwargs[
            "json"
        ]
    )

    assert "node_code" not in payload
    assert (
        "node_credential"
        not in payload
    )
    assert (
        "node-secret"
        not in str(payload)
    )

    assert (
        session.post.call_args.kwargs[
            "headers"
        ]["Authorization"]
        == "Bearer node-secret"
    )

    print(
        "PASS: node identity remains "
        "Bearer-authenticated only"
    )


def main():
    test_configuration()
    test_empty_lease()
    test_successful_execution()
    test_long_running_execution_renews_lease()
    test_nonzero_scanner_exit()
    test_local_capability_rejection()
    test_adapter_validation_failure()
    test_subprocess_exception()
    test_start_failure_prevents_scanner()
    test_renewal_failure_terminates_scanner()
    test_renewal_failure_force_kills_unresponsive_scanner()
    test_renewal_protocol_failure_terminates_scanner()
    test_protocol_validation()
    test_node_credential_not_in_payload()

    print(
        "OK: scan execution agent "
        "regression tests passed."
    )


if __name__ == "__main__":
    main()
