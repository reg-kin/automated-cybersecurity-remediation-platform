#!/usr/bin/env python3

"""Node-local execution agent for centrally coordinated scanner jobs.

The execution agent is deliberately narrow.

It:
- authenticates to the Scan Coordination Agent API with a node credential;
- leases only work assigned by the central control plane;
- reports the leased execution as STARTED;
- translates the leased execution through scanner_adapters;
- invokes the existing scanner-specific orchestrator as an argv list;
- reports SUCCEEDED or FAILED execution status.

It does not:
- connect directly to PostgreSQL or Redis;
- create or modify scan policies;
- resolve canonical assets;
- parse scanner-native evidence;
- determine finding_class;
- construct Unified Security Findings;
- perform risk contextualisation;
- make remediation decisions.

Scanner-specific orchestrators remain responsible for scanner execution/evidence
semantics and Unified Security Finding construction.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Set
from urllib.parse import urljoin

import requests

from scan_coordination.scanner_adapters import (
    ORCHESTRATOR_FILES,
    ScannerAdapterError,
    ScannerAdapterValidationError,
    build_scanner_command,
)


DEFAULT_API_URL = "http://127.0.0.1:19201"
DEFAULT_HTTP_TIMEOUT_SECONDS = 15.0
DEFAULT_LEASE_SECONDS = 300
DEFAULT_POLL_INTERVAL_SECONDS = 10.0

SUCCESS_EXIT_CODE = 0


class ScanExecutionAgentError(RuntimeError):
    """Base error for execution-agent failures."""


class ScanExecutionAgentConfigurationError(
    ScanExecutionAgentError
):
    """Raised when local execution-agent configuration is invalid."""


class ScanExecutionAgentProtocolError(
    ScanExecutionAgentError
):
    """Raised when the control-plane API violates the expected contract."""


class ScanExecutionAgentAPIError(
    ScanExecutionAgentError
):
    """Raised when a control-plane API request fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class ScanExecutionAgentJobError(
    ScanExecutionAgentError
):
    """Raised when a leased job cannot be safely executed."""


def _require_nonblank(
    value: Any,
    *,
    field_name: str,
) -> str:
    if not isinstance(value, str):
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} cannot be empty"
        )

    return cleaned


def _require_positive_int(
    value: Any,
    *,
    field_name: str,
) -> int:
    if isinstance(value, bool):
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive integer"
        )

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive integer"
        ) from exc

    if parsed <= 0:
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive integer"
        )

    return parsed


def _require_positive_float(
    value: Any,
    *,
    field_name: str,
) -> float:
    if isinstance(value, bool):
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive number"
        )

    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive number"
        ) from exc

    if parsed <= 0:
        raise ScanExecutionAgentConfigurationError(
            f"{field_name} must be a positive number"
        )

    return parsed


def _normalise_api_url(value: Any) -> str:
    api_url = _require_nonblank(
        value,
        field_name="api_url",
    )

    if not (
        api_url.startswith("http://")
        or api_url.startswith("https://")
    ):
        raise ScanExecutionAgentConfigurationError(
            "api_url must begin with http:// or https://"
        )

    return api_url.rstrip("/") + "/"


def _parse_supported_scanners(
    value: Any,
) -> Set[str]:
    raw = _require_nonblank(
        value,
        field_name="supported_scanners",
    )

    scanners = {
        item.strip()
        for item in raw.split(",")
        if item.strip()
    }

    if not scanners:
        raise ScanExecutionAgentConfigurationError(
            "supported_scanners cannot be empty"
        )

    unsupported = scanners - set(
        ORCHESTRATOR_FILES
    )

    if unsupported:
        raise ScanExecutionAgentConfigurationError(
            "Unsupported local scanner type(s): "
            + ", ".join(sorted(unsupported))
        )

    return scanners


def _require_job_field(
    job: Mapping[str, Any],
    field_name: str,
) -> Any:
    if field_name not in job:
        raise ScanExecutionAgentProtocolError(
            f"Leased job is missing {field_name}"
        )

    return job[field_name]


def _require_job_nonblank(
    job: Mapping[str, Any],
    field_name: str,
) -> str:
    value = _require_job_field(
        job,
        field_name,
    )

    if not isinstance(value, str):
        raise ScanExecutionAgentProtocolError(
            f"Leased job field {field_name} "
            "must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ScanExecutionAgentProtocolError(
            f"Leased job field {field_name} "
            "cannot be empty"
        )

    return cleaned


def _require_job_positive_int(
    job: Mapping[str, Any],
    field_name: str,
) -> int:
    value = _require_job_field(
        job,
        field_name,
    )

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
    ):
        raise ScanExecutionAgentProtocolError(
            f"Leased job field {field_name} "
            "must be a positive integer"
        )

    return value


def _validate_leased_job(
    job: Any,
) -> Dict[str, Any]:
    if not isinstance(job, Mapping):
        raise ScanExecutionAgentProtocolError(
            "Leased job must be an object"
        )

    validated = dict(job)

    _require_job_positive_int(
        validated,
        "scan_execution_id",
    )

    _require_job_nonblank(
        validated,
        "scanner_type",
    )
    _require_job_nonblank(
        validated,
        "tenant_code",
    )
    _require_job_nonblank(
        validated,
        "service_tier",
    )
    _require_job_nonblank(
        validated,
        "execution_model",
    )
    _require_job_nonblank(
        validated,
        "scanner_subject_type",
    )
    _require_job_nonblank(
        validated,
        "scanner_subject_value",
    )
    _require_job_nonblank(
        validated,
        "lease_token",
    )

    status = _require_job_nonblank(
        validated,
        "status",
    )

    if status != "LEASED":
        raise ScanExecutionAgentProtocolError(
            "Leased job status must be LEASED"
        )

    scanner_parameters = _require_job_field(
        validated,
        "scanner_parameters",
    )

    if not isinstance(
        scanner_parameters,
        Mapping,
    ):
        raise ScanExecutionAgentProtocolError(
            "Leased job scanner_parameters "
            "must be an object"
        )

    validated["scanner_parameters"] = dict(
        scanner_parameters
    )

    return validated


def _failure_reason(
    exc: BaseException,
) -> str:
    message = str(exc).strip()

    if not message:
        message = type(exc).__name__

    return (
        f"{type(exc).__name__}: {message}"
    )[:2000]


class ScanExecutionAgent:
    """Authenticated node-local client for the scan execution pull plane."""

    def __init__(
        self,
        *,
        api_url: str,
        node_credential: str,
        supported_scanners: Sequence[str] | Set[str] | str,
        repository_root: Optional[Path] = None,
        python_executable: Optional[str] = None,
        http_timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_url = _normalise_api_url(
            api_url
        )

        self.node_credential = _require_nonblank(
            node_credential,
            field_name="node_credential",
        )

        if isinstance(
            supported_scanners,
            str,
        ):
            self.supported_scanners = (
                _parse_supported_scanners(
                    supported_scanners
                )
            )
        else:
            normalised = {
                _require_nonblank(
                    value,
                    field_name=(
                        "supported_scanners item"
                    ),
                )
                for value in supported_scanners
            }

            if not normalised:
                raise (
                    ScanExecutionAgentConfigurationError(
                        "supported_scanners "
                        "cannot be empty"
                    )
                )

            unsupported = normalised - set(
                ORCHESTRATOR_FILES
            )

            if unsupported:
                raise (
                    ScanExecutionAgentConfigurationError(
                        "Unsupported local "
                        "scanner type(s): "
                        + ", ".join(
                            sorted(unsupported)
                        )
                    )
                )

            self.supported_scanners = (
                normalised
            )

        self.http_timeout_seconds = (
            _require_positive_float(
                http_timeout_seconds,
                field_name=(
                    "http_timeout_seconds"
                ),
            )
        )

        self.lease_seconds = (
            _require_positive_int(
                lease_seconds,
                field_name="lease_seconds",
            )
        )

        if repository_root is None:
            repository_root = (
                Path(__file__)
                .resolve()
                .parents[1]
            )

        self.repository_root = Path(
            repository_root
        ).resolve()

        if python_executable is None:
            python_executable = sys.executable

        self.python_executable = (
            _require_nonblank(
                python_executable,
                field_name="python_executable",
            )
        )

        self.session = (
            session
            if session is not None
            else requests.Session()
        )

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": (
                f"Bearer "
                f"{self.node_credential}"
            ),
            "Content-Type": (
                "application/json"
            ),
            "Accept": "application/json",
        }

    def _endpoint(
        self,
        path: str,
    ) -> str:
        return urljoin(
            self.api_url,
            path.lstrip("/"),
        )

    def _post(
        self,
        path: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        try:
            response = self.session.post(
                self._endpoint(path),
                json=dict(payload),
                headers=self.headers,
                timeout=(
                    self.http_timeout_seconds
                ),
            )
        except requests.RequestException as exc:
            raise ScanExecutionAgentAPIError(
                "Scan Coordination Agent API "
                f"request failed: {exc}"
            ) from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise ScanExecutionAgentProtocolError(
                "Scan Coordination Agent API "
                "returned non-JSON response"
            ) from exc

        if not isinstance(body, dict):
            raise ScanExecutionAgentProtocolError(
                "Scan Coordination Agent API "
                "response must be a JSON object"
            )

        if not response.ok:
            error_code = body.get("code")
            error_message = body.get(
                "error",
                "Scan Coordination Agent API "
                "request failed",
            )

            raise ScanExecutionAgentAPIError(
                str(error_message),
                status_code=response.status_code,
                error_code=(
                    str(error_code)
                    if error_code is not None
                    else None
                ),
            )

        if body.get("success") is not True:
            raise ScanExecutionAgentProtocolError(
                "Successful API response must "
                "contain success=true"
            )

        return body

    def lease_job(
        self,
    ) -> Optional[Dict[str, Any]]:
        body = self._post(
            "/agent/jobs/lease",
            {
                "lease_seconds": (
                    self.lease_seconds
                ),
            },
        )

        if "job" not in body:
            raise ScanExecutionAgentProtocolError(
                "Lease response is missing job"
            )

        job = body["job"]

        if job is None:
            return None

        return _validate_leased_job(
            job
        )

    def mark_started(
        self,
        *,
        scan_execution_id: int,
        lease_token: str,
    ) -> Dict[str, Any]:
        body = self._post(
            (
                f"/agent/jobs/"
                f"{scan_execution_id}/start"
            ),
            {
                "lease_token": lease_token,
            },
        )

        execution = body.get(
            "execution"
        )

        if not isinstance(
            execution,
            Mapping,
        ):
            raise ScanExecutionAgentProtocolError(
                "Start response is missing "
                "execution object"
            )

        return dict(execution)

    def renew_lease(
        self,
        *,
        scan_execution_id: int,
        lease_token: str,
    ) -> Dict[str, Any]:
        body = self._post(
            (
                f"/agent/jobs/"
                f"{scan_execution_id}/renew"
            ),
            {
                "lease_token": lease_token,
                "lease_seconds": (
                    self.lease_seconds
                ),
            },
        )

        execution = body.get(
            "execution"
        )

        if not isinstance(
            execution,
            Mapping,
        ):
            raise ScanExecutionAgentProtocolError(
                "Renewal response is missing "
                "execution object"
            )

        if execution.get("status") != "RUNNING":
            raise ScanExecutionAgentProtocolError(
                "Renewal response execution "
                "status must be RUNNING"
            )

        return dict(execution)

    def mark_succeeded(
        self,
        *,
        scan_execution_id: int,
        lease_token: str,
        execution_metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        body = self._post(
            (
                f"/agent/jobs/"
                f"{scan_execution_id}/complete"
            ),
            {
                "status": "SUCCEEDED",
                "lease_token": lease_token,
                "execution_metadata": dict(
                    execution_metadata
                ),
            },
        )

        execution = body.get(
            "execution"
        )

        if not isinstance(
            execution,
            Mapping,
        ):
            raise ScanExecutionAgentProtocolError(
                "Completion response is missing "
                "execution object"
            )

        return dict(execution)

    def mark_failed(
        self,
        *,
        scan_execution_id: int,
        lease_token: str,
        failure_reason: str,
        exit_code: Optional[int],
        execution_metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": "FAILED",
            "lease_token": lease_token,
            "failure_reason": _require_nonblank(
                failure_reason,
                field_name="failure_reason",
            ),
            "execution_metadata": dict(
                execution_metadata
            ),
        }

        if exit_code is not None:
            payload["exit_code"] = (
                exit_code
            )

        body = self._post(
            (
                f"/agent/jobs/"
                f"{scan_execution_id}/complete"
            ),
            payload,
        )

        execution = body.get(
            "execution"
        )

        if not isinstance(
            execution,
            Mapping,
        ):
            raise ScanExecutionAgentProtocolError(
                "Completion response is missing "
                "execution object"
            )

        return dict(execution)

    def _assert_local_scanner(
        self,
        scanner_type: str,
    ) -> None:
        if scanner_type not in (
            self.supported_scanners
        ):
            raise ScanExecutionAgentJobError(
                "Leased scanner_type is not "
                "enabled on this execution node: "
                f"{scanner_type}"
            )

    def _build_command(
        self,
        job: Mapping[str, Any],
    ) -> list[str]:
        scanner_type = str(
            job["scanner_type"]
        )

        self._assert_local_scanner(
            scanner_type
        )

        try:
            return build_scanner_command(
                scanner_type=scanner_type,
                tenant_code=job[
                    "tenant_code"
                ],
                service_tier=job[
                    "service_tier"
                ],
                execution_model=job[
                    "execution_model"
                ],
                scanner_subject_type=job[
                    "scanner_subject_type"
                ],
                scanner_subject_value=job[
                    "scanner_subject_value"
                ],
                scanner_parameters=job[
                    "scanner_parameters"
                ],
                repository_root=(
                    self.repository_root
                ),
                python_executable=(
                    self.python_executable
                ),
            )
        except (
            ScannerAdapterValidationError,
            ScannerAdapterError,
        ) as exc:
            raise ScanExecutionAgentJobError(
                str(exc)
            ) from exc

    def _renewal_interval_seconds(
        self,
    ) -> float:
        return min(
            self.lease_seconds / 3.0,
            60.0,
        )

    def _terminate_process(
        self,
        process: subprocess.Popen,
    ) -> None:
        if process.poll() is not None:
            return

        process.terminate()

        try:
            process.wait(
                timeout=10.0
            )
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _run_scanner_with_lease_renewal(
        self,
        *,
        command: Sequence[str],
        scan_execution_id: int,
        lease_token: str,
    ) -> int:
        process = subprocess.Popen(
            list(command),
            shell=False,
        )

        renewal_interval = (
            self._renewal_interval_seconds()
        )

        next_renewal = (
            time.monotonic()
            + renewal_interval
        )

        while True:
            return_code = process.poll()

            if return_code is not None:
                return int(return_code)

            now = time.monotonic()

            if now >= next_renewal:
                try:
                    self.renew_lease(
                        scan_execution_id=(
                            scan_execution_id
                        ),
                        lease_token=lease_token,
                    )
                except Exception:
                    self._terminate_process(
                        process
                    )
                    raise

                next_renewal = (
                    time.monotonic()
                    + renewal_interval
                )

            sleep_seconds = min(
                1.0,
                max(
                    0.0,
                    next_renewal
                    - time.monotonic(),
                ),
            )

            if sleep_seconds > 0:
                time.sleep(
                    sleep_seconds
                )

    def execute_job(
        self,
        job: Mapping[str, Any],
    ) -> Dict[str, Any]:
        job = _validate_leased_job(
            job
        )

        scan_execution_id = int(
            job["scan_execution_id"]
        )
        lease_token = str(
            job["lease_token"]
        )
        scanner_type = str(
            job["scanner_type"]
        )

        self.mark_started(
            scan_execution_id=(
                scan_execution_id
            ),
            lease_token=lease_token,
        )

        started_monotonic = (
            time.monotonic()
        )

        metadata: Dict[str, Any] = {
            "scanner_type": scanner_type,
            "execution_agent": (
                "scan_coordination.execution_agent"
            ),
        }

        try:
            command = self._build_command(
                job
            )

            return_code = (
                self._run_scanner_with_lease_renewal(
                    command=command,
                    scan_execution_id=(
                        scan_execution_id
                    ),
                    lease_token=lease_token,
                )
            )

            elapsed_seconds = round(
                time.monotonic()
                - started_monotonic,
                3,
            )

            metadata[
                "duration_seconds"
            ] = elapsed_seconds

            if (
                return_code
                == SUCCESS_EXIT_CODE
            ):
                self.mark_succeeded(
                    scan_execution_id=(
                        scan_execution_id
                    ),
                    lease_token=lease_token,
                    execution_metadata=metadata,
                )

                return {
                    "scan_execution_id": (
                        scan_execution_id
                    ),
                    "scanner_type": (
                        scanner_type
                    ),
                    "status": "SUCCEEDED",
                    "exit_code": (
                        SUCCESS_EXIT_CODE
                    ),
                }

            failure_reason = (
                "Scanner orchestrator exited "
                "with non-zero status "
                f"{return_code}"
            )

            self.mark_failed(
                scan_execution_id=(
                    scan_execution_id
                ),
                lease_token=lease_token,
                failure_reason=(
                    failure_reason
                ),
                exit_code=(
                    return_code
                ),
                execution_metadata=metadata,
            )

            return {
                "scan_execution_id": (
                    scan_execution_id
                ),
                "scanner_type": (
                    scanner_type
                ),
                "status": "FAILED",
                "exit_code": (
                    return_code
                ),
            }

        except (
            ScanExecutionAgentAPIError,
            ScanExecutionAgentProtocolError,
        ):
            raise

        except Exception as exc:
            metadata[
                "duration_seconds"
            ] = round(
                time.monotonic()
                - started_monotonic,
                3,
            )

            failure_reason = (
                _failure_reason(exc)
            )

            self.mark_failed(
                scan_execution_id=(
                    scan_execution_id
                ),
                lease_token=lease_token,
                failure_reason=(
                    failure_reason
                ),
                exit_code=None,
                execution_metadata=metadata,
            )

            return {
                "scan_execution_id": (
                    scan_execution_id
                ),
                "scanner_type": (
                    scanner_type
                ),
                "status": "FAILED",
                "exit_code": None,
                "failure_reason": (
                    failure_reason
                ),
            }

    def run_once(
        self,
    ) -> Optional[Dict[str, Any]]:
        job = self.lease_job()

        if job is None:
            return None

        return self.execute_job(
            job
        )


def build_agent_from_environment(
    *,
    repository_root: Optional[Path] = None,
    session: Optional[requests.Session] = None,
) -> ScanExecutionAgent:
    api_url = os.getenv(
        "SCAN_EXECUTION_AGENT_API_URL",
        DEFAULT_API_URL,
    )

    node_credential = os.getenv(
        "SCAN_EXECUTION_NODE_CREDENTIAL",
        "",
    )

    supported_scanners = os.getenv(
        "SCAN_EXECUTION_SUPPORTED_SCANNERS",
        "",
    )

    http_timeout_seconds = os.getenv(
        "SCAN_EXECUTION_HTTP_TIMEOUT_SECONDS",
        str(
            DEFAULT_HTTP_TIMEOUT_SECONDS
        ),
    )

    lease_seconds = os.getenv(
        "SCAN_EXECUTION_LEASE_SECONDS",
        str(DEFAULT_LEASE_SECONDS),
    )

    return ScanExecutionAgent(
        api_url=api_url,
        node_credential=node_credential,
        supported_scanners=(
            supported_scanners
        ),
        repository_root=repository_root,
        http_timeout_seconds=(
            _require_positive_float(
                http_timeout_seconds,
                field_name=(
                    "SCAN_EXECUTION_HTTP_TIMEOUT_SECONDS"
                ),
            )
        ),
        lease_seconds=(
            _require_positive_int(
                lease_seconds,
                field_name=(
                    "SCAN_EXECUTION_LEASE_SECONDS"
                ),
            )
        ),
        session=session,
    )


def parse_args(
    argv: Optional[Sequence[str]] = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Scan Coordination "
            "node-local execution agent."
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "Lease at most one job and exit."
        ),
    )

    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(
            os.getenv(
                "SCAN_EXECUTION_POLL_INTERVAL_SECONDS",
                str(
                    DEFAULT_POLL_INTERVAL_SECONDS
                ),
            )
        ),
        help=(
            "Seconds between empty lease polls "
            "when running continuously."
        ),
    )

    return parser.parse_args(
        argv
    )


def main(
    argv: Optional[Sequence[str]] = None,
) -> int:
    args = parse_args(
        argv
    )

    try:
        poll_interval = (
            _require_positive_float(
                args.poll_interval,
                field_name="poll_interval",
            )
        )

        agent = (
            build_agent_from_environment()
        )

        if args.once:
            result = agent.run_once()

            if result is None:
                print(
                    "No scan execution available."
                )
                return 0

            print(
                f"Execution "
                f"{result['scan_execution_id']} "
                f"{result['status']}"
            )

            return (
                0
                if result["status"]
                == "SUCCEEDED"
                else 1
            )

        while True:
            result = agent.run_once()

            if result is None:
                time.sleep(
                    poll_interval
                )

    except KeyboardInterrupt:
        return 0

    except ScanExecutionAgentError as exc:
        print(
            f"Scan execution agent error: "
            f"{exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
