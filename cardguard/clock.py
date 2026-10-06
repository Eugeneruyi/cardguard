from datetime import datetime, timedelta, timezone

class Clock:
    def now(self) -> datetime:
        """Returns the current UTC time."""
        return datetime.now(timezone.utc)

class FakeClock(Clock):
    """Deterministic clock for testing purposes."""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        """Returns the current time of the fake clock."""
        return self._now

    def advance(self, seconds: float) -> None:
        """Advances the fake clock by the specified number of seconds."""
        self._now += timedelta(seconds=seconds)