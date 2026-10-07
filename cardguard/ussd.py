"""USSD approval for when the phone is off, dead or faulty.

The customer authorizes a held transaction with two things:
  1. a one-time code the bank sends by SMS to the number registered when the
     account was opened (possession: the SIM), and
  2. a password the customer created in advance (knowledge).

USSD can only carry digits, so the "password" is a numeric code.

Hard requirements this module enforces:
  * the MSISDN comes from the telco gateway, never from what the user types;
  * the password is set only through a strong channel (never over USSD itself),
    stored as a salted scrypt hash, and unusable for a cooling-off period;
  * a recent SIM swap blocks approval (SMS no longer proves possession);
  * wrong passwords lock approvals; the lock never blocks Deny / Not me;
  * if the terminal already timed out, an approval becomes a short, single-use
    grant for ONE retry of the same purchase (same card, merchant, amount cap);
  * USSD screens must show generic errors ("details incorrect"). The specific
    error codes here are for logs and tests only.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import uuid
from datetime import timedelta
from typing import Optional, Protocol

from .challenge import ChallengeError, ChallengeService
from ..clock import Clock
from .models import (AppCredentials, Card, CardStatus, Challenge, ChallengeStatus,
                     Customer, EnableChannel, FraudCase, PendingApproval, PhoneFix,
                     ResponseDecision, RetryGrant, Transaction, UssdCredential)
from .money import money
from ..notify import Notifier
from .offline import ChannelVerifier
from .risk import RiskConfig
from .store import Store


class UssdError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class SimSwapChecker(Protocol):
    def swapped_within(self, msisdn: str, seconds: float) -> bool:
        """Ask the telco whether the SIM behind this number was swapped recently."""


class FakeSimSwapChecker:
    def __init__(self, swapped: bool = False):
        self.swapped = swapped

    def swapped_within(self, msisdn: str, seconds: float) -> bool:
        return self.swapped


def sign_password_request(device_key: bytes, customer_id: str, nonce: str, password: str) -> bytes:
    """App-side signature that binds the request to the exact new password."""
    digest = hashlib.sha256(password.encode()).hexdigest()
    msg = f"ussd-password:{customer_id}:{nonce}:{digest}".encode()
    return hmac.new(device_key, msg, hashlib.sha256).digest()


def validate_password(pw: str) -> None:
    if not (pw.isascii() and pw.isdigit() and 6 <= len(pw) <= 12):
        raise UssdError("WEAK_PASSWORD")
    if any(len(pw) % k == 0 and pw[:k] * (len(pw) // k) == pw for k in (1, 2, 3)):
        raise UssdError("WEAK_PASSWORD")                      # 111111, 121212, 123123
    diffs = {int(b) - int(a) for a, b in zip(pw, pw[1:])}
    if diffs <= {1} or diffs <= {-1}:
        raise UssdError("WEAK_PASSWORD")                      # 123456, 654321


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


class UssdService:
    def __init__(self, store: Store, challenges: ChallengeService, clock: Clock,
                 cfg: RiskConfig, notifier: Notifier, verifier: ChannelVerifier,
                 sim_checker: SimSwapChecker, short_code: str = "*123#"):
        self.store = store
        self.challenges = challenges
        self.clock = clock
        self.cfg = cfg
        self.notifier = notifier
        self.verifier = verifier
        self.sim = sim_checker
        self.short_code = short_code

    # ---- enrolment ---------------------------------------------------------
    def set_password(self, customer_id: str, password: str,
                     via: EnableChannel, credentials) -> None:
        """Create or change the USSD password. Never allowed over USSD itself:
        someone holding a swapped SIM must not be able to set their own password."""
        if via is EnableChannel.USSD:
            raise UssdError("CHANNEL_NOT_ALLOWED")
        if customer_id not in self.store.customers:
            raise UssdError("UNKNOWN_CUSTOMER")
        validate_password(password)
        if not self._authenticate_enrolment(customer_id, password, via, credentials):
            self.store.audit("USSD_PASSWORD_AUTH_FAILED", customer_id=customer_id, via=via.value)
            self.notifier.alert(customer_id, f"Failed attempt to set your USSD password via {via.value}.")
            raise UssdError("BAD_CREDENTIALS")
        salt = os.urandom(16)
        cred = UssdCredential(customer_id, salt, _scrypt(password, salt), self.clock.now())
        with self.store.lock:
            self.store.ussd_credentials[customer_id] = cred
        self.store.audit("USSD_PASSWORD_SET", customer_id=customer_id, via=via.value)
        self.notifier.alert(customer_id, f"USSD password set via {via.value}. It becomes usable in "
                            f"{int(self.cfg.ussd_password_cooldown_s // 3600)}h. Not you? Contact the bank now.")

    def _authenticate_enrolment(self, customer_id, password, via, credentials) -> bool:
        if via is EnableChannel.APP:
            if not isinstance(credentials, AppCredentials):
                return False
            device = self.store.devices.get(credentials.device_id)
            if device is None or not device.active or device.customer_id != customer_id:
                return False
            expected = sign_password_request(device.key, customer_id, credentials.nonce, password)
            if not hmac.compare_digest(expected, credentials.signature):
                return False
            with self.store.lock:
                if credentials.nonce in self.store.used_nonces:
                    return False
                self.store.used_nonces.add(credentials.nonce)
            return True
        return bool(self.verifier.verify(customer_id, via, credentials))

    # ---- the USSD session --------------------------------------------------
    def pending(self, msisdn: str) -> list:
        """Menu 1: transactions waiting for this customer (those with an SMS prompt)."""
        customer = self._customer(msisdn)
        now = self.clock.now()
        items = []
        with self.store.lock:
            for ch in self.store.challenges.values():
                card = self.store.cards.get(ch.card_id)
                if card is None or card.customer_id != customer.id or ch.ussd_code_hash is None:
                    continue
                if ch.status not in (ChallengeStatus.PENDING, ChallengeStatus.EXPIRED):
                    continue
                if ch.ussd_valid_until is None or now >= ch.ussd_valid_until:
                    continue
                t = self.store.txns[ch.txn_id]
                items.append(PendingApproval(ch.id, t.amount, t.currency, t.merchant_name,
                                             t.merchant_city, t.merchant_country,
                                             now >= ch.expires_at, ch.ussd_valid_until))
        return items

    def approve(self, msisdn: str, challenge_id: str, otp: str, password: str,
                fix: Optional[PhoneFix] = None) -> Challenge:
        """`fix` is optional telco cell-site location from the USSD gateway.
        It is coarse (cell level), so it is not a substitute for a GPS fix."""
        customer = self._customer(msisdn)
        card = self._owned_card(customer, challenge_id)
        if self.sim.swapped_within(msisdn, self.cfg.ussd_sim_swap_window_s):
            self.store.audit("USSD_SIM_SWAP_BLOCK", customer_id=customer.id)
            self.notifier.alert(customer.id, "A USSD approval was blocked because your SIM was "
                                "swapped recently. If this was not you, contact the bank.")
            raise UssdError("SIM_SWAP_SUSPECTED")
        self._check_password(customer, password)
        try:
            ch = self.challenges.respond_ussd(challenge_id, ResponseDecision.APPROVE, otp, fix)
        except ChallengeError as e:
            raise UssdError(e.code) from e

        txn = self.store.txns[ch.txn_id]
        if ch.status is ChallengeStatus.LATE_APPROVED:
            grant = RetryGrant(card.id, txn.merchant_name, txn.merchant_country, txn.currency,
                               txn.amount, self.clock.now() + timedelta(seconds=self.cfg.ussd_retry_window_s),
                               ch.phone_fix)
            with self.store.lock:
                self.store.retry_grants[card.id] = grant
            note = "Retry the same purchase now."
        else:
            note = "Approved."
        self.store.audit("USSD_APPROVED", challenge_id=challenge_id, late=ch.status is ChallengeStatus.LATE_APPROVED)
        self.notifier.alert(customer.id, f"USSD approval for {money(txn.amount, txn.currency)} at "
                            f"{txn.merchant_name}. {note}")
        return ch

    def deny(self, msisdn: str, challenge_id: str, fix: Optional[PhoneFix] = None) -> Challenge:
        return self._decline(msisdn, challenge_id, ResponseDecision.DENY, fix)

    def report_not_me(self, msisdn: str, challenge_id: str, fix: Optional[PhoneFix] = None) -> Challenge:
        try:
            return self._decline(msisdn, challenge_id, ResponseDecision.NOT_ME, fix)
        except UssdError as e:
            if e.code != "EXPIRED":
                raise
        # The terminal already gave up, so no AuthService call is waiting to
        # freeze the card for us. "Not me" must still protect the customer.
        return self._block_after_timeout(msisdn, challenge_id)

    def _block_after_timeout(self, msisdn: str, challenge_id: str) -> Challenge:
        customer = self._customer(msisdn)
        card = self._owned_card(customer, challenge_id)
        now = self.clock.now()
        with self.store.lock:
            ch = self.store.challenges[challenge_id]
            if ch.ussd_valid_until is None or now >= ch.ussd_valid_until:
                raise UssdError("EXPIRED")
            txn = self.store.txns[ch.txn_id]
            if card.status is CardStatus.ACTIVE:
                self.store.freeze_card(card.id)
                self.store.add_fraud_case(FraudCase(
                    id=uuid.uuid4().hex, card_id=card.id, txn_id=txn.id,
                    reason="NOT_ME_AFTER_TIMEOUT",
                    evidence={"merchant": [txn.merchant_name, txn.merchant_city, txn.merchant_country],
                              "merchant_coords": [txn.merchant_lat, txn.merchant_lon]},
                    opened_at=now))
            self.store.retry_grants.pop(card.id, None)      # revoke any pending retry
            snapshot = dataclasses.replace(ch)
        self.store.audit("CARD_FROZEN", card_id=card.id, reason="NOT_ME_AFTER_TIMEOUT")
        self.notifier.alert(customer.id, "Your card was blocked at your request via USSD.")
        return snapshot

    # ---- used by AuthService ----------------------------------------------
    def consume_grant(self, card: Card, txn: Transaction) -> Optional[RetryGrant]:
        """Single use. A non-matching purchase leaves the grant untouched."""
        now = self.clock.now()
        with self.store.lock:
            g = self.store.retry_grants.get(card.id)
            if g is None:
                return None
            if now >= g.expires_at:
                del self.store.retry_grants[card.id]
                return None
            if (txn.merchant_name, txn.merchant_country, txn.currency) != \
               (g.merchant_name, g.merchant_country, g.currency) or txn.amount > g.max_amount:
                return None
            del self.store.retry_grants[card.id]
            return g

    # ---- internals ---------------------------------------------------------
    def _decline(self, msisdn, challenge_id, decision, fix) -> Challenge:
        customer = self._customer(msisdn)
        self._owned_card(customer, challenge_id)
        try:
            ch = self.challenges.respond_ussd(challenge_id, decision, "", fix)
        except ChallengeError as e:
            raise UssdError(e.code) from e
        self.store.audit("USSD_" + decision.value, challenge_id=challenge_id)
        return ch

    def _customer(self, msisdn: str) -> Customer:
        customer = self.store.customer_by_msisdn(msisdn)
        if customer is None:
            raise UssdError("UNKNOWN_NUMBER")
        return customer

    def _owned_card(self, customer: Customer, challenge_id: str) -> Card:
        ch = self.store.challenges.get(challenge_id)
        if ch is None:
            raise UssdError("NOT_FOUND")
        card = self.store.cards.get(ch.card_id)
        if card is None or card.customer_id != customer.id:
            raise UssdError("NOT_YOUR_TRANSACTION")
        return card

    def _check_password(self, customer: Customer, password: str) -> None:
        now = self.clock.now()
        cred = self.store.ussd_credentials.get(customer.id)
        if cred is None:
            raise UssdError("NO_PASSWORD")
        if now - cred.set_at < timedelta(seconds=self.cfg.ussd_password_cooldown_s):
            raise UssdError("PASSWORD_COOLDOWN")
        window = timedelta(seconds=self.cfg.ussd_lockout_s)
        with self.store.lock:
            fails = [t for t in self.store.ussd_failures.get(customer.id, []) if now - t < window]
            self.store.ussd_failures[customer.id] = fails
            if len(fails) >= self.cfg.ussd_failure_limit:
                raise UssdError("LOCKED_OUT")
        if hmac.compare_digest(_scrypt(password, cred.salt), cred.password_hash):
            return
        with self.store.lock:
            self.store.ussd_failures[customer.id].append(now)
            n = len(self.store.ussd_failures[customer.id])
        self.store.audit("USSD_BAD_PASSWORD", customer_id=customer.id)
        text = "Wrong USSD password entered."
        if n >= self.cfg.ussd_failure_limit:
            text += " USSD approvals are locked for a while."
        self.notifier.alert(customer.id, text)
        raise UssdError("BAD_PASSWORD")
