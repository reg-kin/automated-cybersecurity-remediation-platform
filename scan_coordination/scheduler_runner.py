#!/usr/bin/env python3

"""Runtime entry point for deterministic scan-policy scheduling.

The runner repeatedly materialises due CRON policy occurrences through
scan_coordination.scheduler.schedule_next_due_policy().

Transaction semantics:
- one scheduler invocation runs in one database transaction;
- successful execution creation and next_run_at advancement commit together;
- failures roll back the current occurrence completely;
- already committed earlier occurrences in the same poll cycle remain committed.

The scheduler itself remains responsible for policy locking, occurrence
idempotency, scanner-subject resolution and execution creation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict

from remediation.shared import db
from scan_coordination.scheduler import (
    initialise_next_scan_policy,
    schedule_next_due_policy,
)


LOG = logging.getLogger(
    "automated_remediation.scan_policy_scheduler"
)


def env_int(
    name: str,
    default: int,
    minimum: int = 1,
) -> int:
    raw = os.getenv(name)

    if raw in (None, ""):
        return default

    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer"
        ) from exc

    if value < minimum:
        raise ValueError(
            f"{name} must be >= {minimum}"
        )

    return value


def setup_logging() -> None:
    level = os.getenv(
        "SCAN_SCHEDULER_LOG_LEVEL",
        "INFO",
    ).upper()

    logging.basicConfig(
        level=getattr(
            logging,
            level,
            logging.INFO,
        ),
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s %(message)s"
        ),
    )


def run_once(
    batch_size: int,
) -> Dict[str, int]:
    """Process up to batch_size scheduler operations.

    Initialisation is performed before due-occurrence materialisation.

    Each operation receives its own transaction. A successful initialisation
    or materialisation therefore remains committed if a later operation in the
    same poll cycle fails.
    """

    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or batch_size <= 0
    ):
        raise ValueError(
            "batch_size must be a positive integer"
        )

    counts: Dict[str, int] = {}
    conn = db.connect()

    try:
        operations = 0

        while operations < batch_size:
            with conn:
                result = initialise_next_scan_policy(
                    conn
                )

            if result is None:
                break

            operations += 1

            action = result["action"]

            counts[action] = (
                counts.get(action, 0) + 1
            )

            LOG.info(
                "policy=%s action=%s "
                "reference_time=%s next_run_at=%s",
                result["scan_policy_id"],
                action,
                result["reference_time"],
                result["next_run_at"],
            )

        while operations < batch_size:
            with conn:
                result = schedule_next_due_policy(
                    conn
                )

            if result is None:
                break

            operations += 1

            action = result["action"]

            counts[action] = (
                counts.get(action, 0) + 1
            )

            LOG.info(
                "policy=%s execution=%s action=%s "
                "scheduled_for=%s next_run_at=%s",
                result["scan_policy_id"],
                result["scan_execution_id"],
                action,
                result["scheduled_for"],
                result["next_run_at"],
            )

        return counts

    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deterministic scan-policy scheduler"
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one scheduling cycle and exit",
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously",
    )

    args = parser.parse_args()

    if args.once and args.loop:
        parser.error(
            "Choose only one of --once or --loop"
        )

    setup_logging()

    batch_size = env_int(
        "SCAN_SCHEDULER_BATCH_SIZE",
        50,
    )

    poll_seconds = env_int(
        "SCAN_SCHEDULER_POLL_SECONDS",
        15,
    )

    if not args.loop:
        summary = run_once(
            batch_size
        )

        print(
            json.dumps(
                {
                    "results": summary,
                },
                sort_keys=True,
            )
        )

        return 0

    LOG.info(
        "starting scan-policy scheduler "
        "batch=%d poll=%ds",
        batch_size,
        poll_seconds,
    )

    while True:
        try:
            summary = run_once(
                batch_size
            )

            if summary:
                LOG.info(
                    "scheduler cycle completed "
                    "results=%s",
                    summary,
                )

        except Exception:
            LOG.exception(
                "scan-policy scheduling cycle failed"
            )

        time.sleep(
            poll_seconds
        )


if __name__ == "__main__":
    sys.exit(main())
