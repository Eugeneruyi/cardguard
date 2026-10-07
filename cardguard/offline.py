"""Customer-controlled "phone offline" (emergency) mode.

The phone cannot approve anything while it is dead, lost or faulty, so the
customer can switch the card into a restricted mode instead of being locked
out. Because this is a deliberate bypass of the approval step, it is the most
attractive target for an attacker. The design therefore is:

  * enabling needs strong authentication on a channel the customer controls
    (device-signed from the app, or USSD / web / call centre / branch through
    an injected verifier). Holding the card alone is never enough;
  * it is capped (per transaction, rolling 24h total), card-present only,
    blocked in a new country, and it expires on its own;
  * impossible-travel detection and card freeze still apply;
  * the customer is alerted on every enable, disable, use, and failed attempt;
  * repeated failed ENABLE attempts lock enabling, but never block DISABLE.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import timedelta
from typing import Optional, Protocol

from .clock import Clock
from ..models import (AppCredentials, AuthDecision, Card, CardStatus,
                     EnableChannel, OfflineMode, Transaction)
from .money import money
from .notify import Notifier
from .risk import RiskConfig, RiskResult
from .store import Store

DAY = timedelta(hours=24)


class OfflineModeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sign_offline_request(device_key: bytes, action: str, card_id: str, nonce: str) -> bytes:
    """What the app computes (after biometric unlock) to enable or disable the mode."""
    msg = f"offline:{action}:{card_id}:{nonce}".encode()
    return hmac.new(device_key, msg, hashlib.sha256).digest()


class ChannelVerifier(Protocol):
    def verify(self, customer_id: str, channel: EnableChannel, credentials: dict) -> bool:
        """USSD / web / call-centre / branch authentication. Must check the
        customer's PIN or ID checks plus a second factor, and refuse recent SIM swaps."""


class FakeVerifier:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls: list[tuple] = []

    def verify(self, customer_id, channel, credentials) -> bool:
        self.calls.append((customer_id, channel))
        return self.ok


class OfflineModeService:
    def __init__(self, store: Store, clock: Clock, cfg: RiskConfig,
                 notifier: Notifier, verifier: ChannelVerifier):
        self.store = store
        self.clock = clock
        self.cfg = cfg
        self.notifier = notifier
        self.verifier = verifier

    # ---- customer actions -------------------------------------------------
    def enable(self, card_id: str, via: EnableChannel, credentials,
               ttl_s: Optional[float] = None, per_txn_cap: Optional[int] = None,
               total_cap: Optional[int] = None) -> OfflineMode:
        card = self._card(card_id)
        if card.status is not CardStatus.ACTIVE:
            raise OfflineModeError("CARD_NOT_ACTIVE")

        ttl = self.cfg.offline_default_ttl_s if ttl_s is None else ttl_s
        per_txn = self.cfg.offline_max_per_txn if per_txn_cap is None else per_txn_cap
        total = self.cfg.offline_max_total_24h if total_cap is None else total_cap
        if ttl <= 0 or ttl > self.cfg.offline_max_ttl_s:
            raise OfflineModeError("TTL_ABOVE_LIMIT")
        if not (0 < per_txn <= self.cfg.offline_max_per_txn) or \
           not (0 < total <= self.cfg.offline_max_total_24h):
            raise OfflineModeError("CAP_ABOVE_LIMIT")

        self._authenticate(card, via, "ENABLE", credentials)

        now = self.clock.now()
        mode = OfflineMode(card.id, via, now, now + timedelta(seconds=ttl), per_txn, total)
        with self.store.lock:
            self.store.offline_modes[card.id] = mode
        self.store.audit("OFFLINE_MODE_ENABLED", card_id=card.id, via=via.value,
                         expires_at=mode.expires_at)
        self.notifier.alert(card.customer_id,
                            f"Offline mode ON via {via.value}. Per-transaction limit {per_txn}, "
                            f"24h limit {total}, ends {mode.expires_at.isoformat()}. "
                            f"Not you? Freeze your card now.")
        return mode

    def disable(self, card_id: str, via: EnableChannel, credentials) -> None:
        card = self._card(card_id)
        self._authenticate(card, via, "DISABLE", credentials)
        with self.store.lock:
            removed = self.store.offline_modes.pop(card.id, None)
        if removed is not None:
            self.store.audit("OFFLINE_MODE_DISABLED", card_id=card.id, via=via.value)
            self.notifier.alert(card.customer_id, f"Offline mode OFF via {via.value}.")

    def is_active(self, card_id: str) -> bool:
        with self.store.lock:
            mode = self.store.offline_modes.get(card_id)
            return mode is not None and self.clock.now() < mode.expires_at

    # ---- called by AuthService -------------------------------------------
    def try_authorize(self, card: Card, txn: Transaction,
                      pre: RiskResult) -> Optional[AuthDecision]:
        """None means offline mode is not active: use the normal approval flow."""
        now = self.clock.now()
        with self.store.lock:
            mode = self.store.offline_modes.get(card.id)
            if mode is None:
                return None
            if now >= mode.expires_at:
                del self.store.offline_modes[card.id]
                expired = True
            else:
                expired = False
        if expired:
            self.store.audit("OFFLINE_MODE_EXPIRED", card_id=card.id)
            self.notifier.alert(card.customer_id, "Offline mode ended (expired). "
                                "Normal approval is back on.")
            return None

        reason = None
        if not txn.channel.card_present:
            reason = "OFFLINE_ECOM_BLOCKED"
        elif "NEW_COUNTRY" in pre.reasons:
            reason = "OFFLINE_NEW_COUNTRY"
        elif txn.amount > mode.per_txn_cap:
            reason = "OFFLINE_CAP_EXCEEDED"

        if reason is None:
            # Check-and-record under one lock so parallel transactions cannot
            # overspend the cap together.
            with self.store.lock:
                spend = [(t, a) for t, a in self.store.offline_spend.get(card.id, [])
                         if now - t < DAY]
                if sum(a for _, a in spend) + txn.amount > mode.total_cap:
                    reason = "OFFLINE_CAP_EXCEEDED"
                else:
                    spend.append((now, txn.amount))
                self.store.offline_spend[card.id] = spend

        if reason is not None:
            self.store.audit("DECLINED", txn_id=txn.id, reason=reason)
            self.notifier.alert(card.customer_id,
                                f"Declined in offline mode ({reason}): "
                                f"{money(txn.amount, txn.currency)} at {txn.merchant_name}.")
            return AuthDecision(False, reason)

        self.store.record_approved(txn, card.customer_id)
        self.store.audit("OFFLINE_APPROVED", txn_id=txn.id, amount=txn.amount)
        self.notifier.alert(card.customer_id,
                            f"Card used in offline mode: {money(txn.amount, txn.currency)} at "
                            f"{txn.merchant_name}, {txn.merchant_city}.")
        return AuthDecision(True, "APPROVED_OFFLINE")

    # ---- internals --------------------------------------------------------
    def _card(self, card_id: str) -> Card:
        card = self.store.cards.get(card_id)
        if card is None:
            raise OfflineModeError("CARD_NOT_FOUND")
        return card

    def _authenticate(self, card: Card, via: EnableChannel, action: str, credentials) -> None:
        now = self.clock.now()
        if action == "ENABLE":
            # Lockout protects the bypass. It never applies to DISABLE, because
            # turning protection back on must always work.
            with self.store.lock:
                window = timedelta(seconds=self.cfg.offline_lockout_s)
                fails = [t for t in self.store.offline_failures.get(card.id, [])
                         if now - t < window]
                self.store.offline_failures[card.id] = fails
                locked = len(fails) >= self.cfg.offline_auth_failure_limit
            if locked:
                self.store.audit("OFFLINE_ENABLE_LOCKED_OUT", card_id=card.id)
                raise OfflineModeError("LOCKED_OUT")

        if self._credentials_ok(card, via, action, credentials):
            return

        with self.store.lock:
            self.store.offline_failures.setdefault(card.id, []).append(now)
            n = len(self.store.offline_failures[card.id])
        self.store.audit("OFFLINE_AUTH_FAILED", card_id=card.id, via=via.value, action=action)
        text = f"Failed attempt to {action.lower()} offline mode via {via.value}."
        if action == "ENABLE" and n >= self.cfg.offline_auth_failure_limit:
            text += " Enabling is locked for a while."
        self.notifier.alert(card.customer_id, text)
        raise OfflineModeError("BAD_CREDENTIALS")

    def _credentials_ok(self, card: Card, via: EnableChannel, action: str, credentials) -> bool:
        if via is EnableChannel.APP:
            if not isinstance(credentials, AppCredentials):
                return False
            if credentials.device_id != card.device_id:
                return False
            device = self.store.devices.get(credentials.device_id)
            if device is None or not device.active:
                return False
            expected = sign_offline_request(device.key, action, card.id, credentials.nonce)
            if not hmac.compare_digest(expected, credentials.signature):
                return False
            with self.store.lock:            # one-time nonce: blocks replay
                if credentials.nonce in self.store.used_nonces:
                    return False
                self.store.used_nonces.add(credentials.nonce)
            return True
        return bool(self.verifier.verify(card.customer_id, via, credentials))
