"""Cron and timezone calculation helpers for scan policy scheduling."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter


class ScheduleValidationError(ValueError):
    """Raised when scan-policy scheduling input is invalid."""


def _validate_cron_expression(expression: str) -> str:
    if not isinstance(expression, str):
        raise ScheduleValidationError(
            "schedule_expression must be a string"
        )

    expression = expression.strip()

    if not expression:
        raise ScheduleValidationError(
            "schedule_expression must not be empty"
        )

    fields = expression.split()

    if len(fields) != 5:
        raise ScheduleValidationError(
            "schedule_expression must use exactly 5 cron fields"
        )

    if not croniter.is_valid(expression, strict=True):
        raise ScheduleValidationError(
            "schedule_expression is not a valid 5-field cron expression"
        )

    return expression


def _load_timezone(timezone_name: str) -> ZoneInfo:
    if not isinstance(timezone_name, str):
        raise ScheduleValidationError(
            "schedule_timezone must be a string"
        )

    timezone_name = timezone_name.strip()

    if not timezone_name:
        raise ScheduleValidationError(
            "schedule_timezone must not be empty"
        )

    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ScheduleValidationError(
            f"unknown IANA timezone: {timezone_name}"
        ) from exc


def _validate_reference_time(reference_time: datetime) -> datetime:
    if not isinstance(reference_time, datetime):
        raise ScheduleValidationError(
            "reference_time must be a datetime"
        )

    if (
        reference_time.tzinfo is None
        or reference_time.utcoffset() is None
    ):
        raise ScheduleValidationError(
            "reference_time must be timezone-aware"
        )

    return reference_time


def _resolve_local_wall_time(
    wall_time: datetime,
    schedule_timezone: ZoneInfo,
) -> datetime | None:
    """Resolve a naive local wall time to one canonical UTC instant.

    Returns None when the wall time does not exist because of a DST
    spring-forward transition.

    When the wall time is ambiguous during a fall-back transition, the first
    occurrence is selected.
    """

    if wall_time.tzinfo is not None:
        raise RuntimeError(
            "wall_time must be timezone-naive"
        )

    candidates = []

    for fold in (0, 1):
        local_candidate = wall_time.replace(
            tzinfo=schedule_timezone,
            fold=fold,
        )
        candidate_utc = local_candidate.astimezone(timezone.utc)

        # A real local wall time must survive a UTC round trip unchanged.
        round_tripped = candidate_utc.astimezone(schedule_timezone)

        if (
            round_tripped.replace(tzinfo=None) == wall_time
            and round_tripped.fold == fold
        ):
            candidates.append(candidate_utc)

    if not candidates:
        return None

    # For an ordinary, unambiguous time fold=0 and fold=1 can resolve to the
    # same instant. Deduplicate those values before handling ambiguity.
    unique_candidates = sorted(set(candidates))

    # An ambiguous fall-back wall time resolves to two distinct UTC instants.
    # The platform defines one cron occurrence and chooses the first instant.
    return unique_candidates[0]


def next_cron_occurrence(
    expression: str,
    timezone_name: str,
    reference_time: datetime,
) -> datetime:
    """Return the next scheduled instant strictly after reference_time.

    Cron iteration is performed in local wall-clock time. Timezone resolution
    is then applied explicitly so DST behaviour is deterministic:

    - nonexistent spring-forward wall times are skipped;
    - ambiguous fall-back wall times occur once, using the first occurrence.

    The returned datetime is always timezone-aware UTC.
    """

    expression = _validate_cron_expression(expression)
    schedule_timezone = _load_timezone(timezone_name)
    reference_time = _validate_reference_time(reference_time)

    reference_utc = reference_time.astimezone(timezone.utc)
    local_reference = reference_utc.astimezone(schedule_timezone)

    # croniter must operate on naive local wall-clock values here. Allowing it
    # to iterate timezone-aware values would delegate DST transition semantics
    # to croniter rather than to this platform layer.
    wall_reference = local_reference.replace(tzinfo=None)

    iterator = croniter(
        expression,
        wall_reference,
        day_or=True,
    )

    while True:
        wall_candidate = iterator.get_next(datetime)

        if wall_candidate.tzinfo is not None:
            raise RuntimeError(
                "croniter returned a timezone-aware wall-clock datetime"
            )

        candidate_utc = _resolve_local_wall_time(
            wall_candidate,
            schedule_timezone,
        )

        # The scheduled wall-clock slot does not exist on this date.
        if candidate_utc is None:
            continue

        # This also suppresses the second occurrence of an ambiguous local
        # time when the reference instant lies between the two DST folds.
        if candidate_utc <= reference_utc:
            continue

        return candidate_utc
