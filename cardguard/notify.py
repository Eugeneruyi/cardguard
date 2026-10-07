from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol


@dataclass(frozen=True)
class PushMessage:
    """Keep the real push payload minimal. Production: send only the
    challenge id, and let the app fetch details and the code over an
    authenticated API after biometric unlock."""
    device_id: str
    push_token: str
    challenge_id: str
    code: str
    summary: dict            # amount, merchant, city, country, lat, lon, channel
    requests_location: bool = True


class Notifier(Protocol):
    def push(self, msg: PushMessage) -> bool: ...
    def sms(self, msisdn: str, text: str) -> None: ...
    def alert(self, customer_id: str, text: str) -> None: ...


class FakeNotifier:
    """Test double. `on_push` simulates the phone reacting to the push."""

    def __init__(self, deliver: bool = True, on_push: Optional[Callable] = None):
        self.deliver = deliver
        self.on_push = on_push
        self.pushes: list[PushMessage] = []
        self.sent_sms: list[tuple[str, str]] = []
        self.alerts: list[tuple[str, str]] = []

    def push(self, msg: PushMessage) -> bool:
        self.pushes.append(msg)
        if not self.deliver:
            return False
        if self.on_push is not None:
            self.on_push(msg)
        return True

    def sms(self, msisdn: str, text: str) -> None:
        self.sent_sms.append((msisdn, text))

    def alert(self, customer_id: str, text: str) -> None:
        # Production: fan out to SMS + email + push (queued for a phone that is off).
        self.alerts.append((customer_id, text))
