"""In-memory store. Swap for a database; the locking points show where you
need transactions / row locks (SELECT ... FOR UPDATE)."""
from __future__ import annotations

import threading
from concurrent.futures import Future
from datetime import timedelta
from typing import Optional

from .clock import Clock
from .models import Card, CardStatus, Challenge, Device, FraudCase, Transaction


class Store:
    def __init__(self, clock: Clock):
        self.clock = clock
        self.lock = threading.RLock()
        self.cards: dict[str, Card] = {}
        self.devices: dict[str, Device] = {}
        self.challenges: dict[str, Challenge] = {}
        self.events: dict[str, threading.Event] = {}
        self.fraud_cases: list[FraudCase] = []
        self.audit_log: list[dict] = []
        self._idem: dict[str, Future] = {}
        self._last_cp: dict[str, Transaction] = {}
        self._countries: dict[str, set] = {}
        self._failures: dict[str, list] = {}
        # offline (emergency) mode
        self.offline_modes: dict = {}
        self.offline_spend: dict[str, list] = {}     # card_id -> [(time, amount)]
        self.offline_failures: dict[str, list] = {}  # card_id -> [time]
        self.used_nonces: set = set()
        # USSD approval
        self.customers: dict = {}
        self.txns: dict = {}
        self.ussd_credentials: dict = {}
        self.ussd_failures: dict[str, list] = {}   # customer_id -> [time]
        self.retry_grants: dict = {}               # card_id -> RetryGrant

    def add_card(self, card: Card) -> None:
        with self.lock:
            self.cards[card.id] = card

    def add_customer(self, customer) -> None:
        with self.lock:
            self.customers[customer.id] = customer

    def customer_by_msisdn(self, msisdn: str):
        with self.lock:
            return next((c for c in self.customers.values() if c.msisdn == msisdn), None)

    def add_device(self, device: Device) -> None:
        with self.lock:
            self.devices[device.id] = device

    def add_known_country(self, customer_id: str, country: str) -> None:
        with self.lock:
            self._countries.setdefault(customer_id, set()).add(country)

    def known_countries(self, customer_id: str) -> frozenset:
        with self.lock:
            return frozenset(self._countries.get(customer_id, ()))

    def audit(self, event: str, **fields) -> None:
        with self.lock:
            self.audit_log.append({"at": self.clock.now(), "event": event, **fields})

    def freeze_card(self, card_id: str) -> None:
        with self.lock:
            self.cards[card_id].status = CardStatus.FROZEN

    def claim(self, idempotency_key: str):
        """Returns (is_owner, future). Duplicates wait on the owner's result."""
        with self.lock:
            fut = self._idem.get(idempotency_key)
            if fut is not None:
                return False, fut
            fut = Future()
            self._idem[idempotency_key] = fut
            return True, fut

    def last_card_present(self, card_id: str) -> Optional[Transaction]:
        with self.lock:
            return self._last_cp.get(card_id)

    def record_approved(self, txn: Transaction, customer_id: str) -> None:
        with self.lock:
            if txn.channel.card_present:
                self._last_cp[txn.card_id] = txn
            self._countries.setdefault(customer_id, set()).add(txn.merchant_country)

    def record_failure(self, card_id: str, now, window_s: float) -> int:
        with self.lock:
            events = self._failures.setdefault(card_id, [])
            events.append(now)
            cutoff = now - timedelta(seconds=window_s)
            events[:] = [t for t in events if t >= cutoff]
            return len(events)

    def add_fraud_case(self, case: FraudCase) -> None:
        with self.lock:
            self.fraud_cases.append(case)
