"""Datetime utilities for handling timezone-aware datetime objects."""
from datetime import datetime, timezone


def ensure_aware(dt: datetime | None) -> datetime | None:
    """
    Convert naive datetime to aware UTC datetime.

    This function handles datetime objects that come from the database,
    which are typically naive (no timezone info) but represent UTC time.
    It adds UTC timezone info to naive datetimes to allow safe comparisons
    with timezone-aware datetime objects.

    Args:
        dt: A datetime object, which may be naive or aware.

    Returns:
        A timezone-aware datetime in UTC, or None if input is None.

    Examples:
        >>> from datetime import datetime, timezone
        >>> naive_dt = datetime(2025, 1, 1, 12, 0)
        >>> aware_dt = ensure_aware(naive_dt)
        >>> aware_dt.tzinfo
        datetime.timezone.utc
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Assume naive datetimes from DB are in UTC
        return dt.replace(tzinfo=timezone.utc)
    return dt
