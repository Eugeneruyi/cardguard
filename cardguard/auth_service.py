from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from .challenge import ChallengeError, ChallengeService
from .clock import Clock
from .money import money
from .models import (AuthDecision, Card, CardStatus, ChallengeStatus, FraudCase,
                     Transaction)
from .notify import Notifier, PushMessage
from .offline import OfflineModeService
from .risk import Action, RiskConfig, RiskResult, location_risk, pre_authorization_risk
from .store import Store
from .ussd import UssdService

log = logging.getLogger("cardguard")


class AuthService:
    """Entry point called by the card-network gateway for each authorization."""

    def __init__(self, store: Store, challenges: ChallengeService,
                 notifier: Notifier, cfg: RiskConfig, clock: Clock,
                 offline: Optional[OfflineModeService] = None,
                 ussd: Optional[UssdService] = None):
        self.store = store
        self.challenges = challenges
        self.notifier = notifier
        self.cfg = cfg
        self.clock = clock
        self.offline = offline
        self.ussd = ussd

    def authorize(self, txn: Transaction) -> AuthDecision:
        # Network retries must not create a second challenge or a second push.
        owner, fut = self.store.claim(txn.idempotency_key)
        if not owner:
            return fut.result(timeout=self.cfg.hold_window_s[txn.channel] + 30)
        try:
            decision = self._authorize(txn)
        except Exception:
            log.exception("authorization failed; failing closed")
            self.store.audit("INTERNAL_ERROR", txn_id=txn.id)
            decision = AuthDecision(False, "INTERNAL_ERROR")
        fut.set_result(decision)
        return decision

    def _authorize(self, txn: Transaction) -> AuthDecision:
        card = self.store.cards.get(txn.card_id)
        if card is None:
            return self._decline(txn, "CARD_NOT_FOUND")
        if card.status is not CardStatus.ACTIVE:
            return self._decline(txn, "CARD_NOT_ACTIVE")
        device = self.store.devices.get(card.device_id)
        if device is None or not device.active:
            return self._decline(txn, "NO_REGISTERED_DEVICE")  # fail closed

        pre = pre_authorization_risk(
            txn, self.store.last_card_present(card.id),
            self.store.known_countries(card.customer_id), self.cfg,
        )
        if pre.action is Action.DECLINE_AND_FREEZE:
            self._freeze(card, txn, pre.reasons[0], pre)
            return self._decline(txn, pre.reasons[0])

        # The customer approved by USSD after the terminal gave up: honour ONE retry.
        if self.ussd is not None:
            grant = self.ussd.consume_grant(card, txn)
            if grant is not None:
                loc = location_risk(txn, grant.fix, self.clock.now(), self.cfg)
                self.store.audit("LOCATION_RISK", txn_id=txn.id, level=loc.level.value,
                                 reasons=loc.reasons, distance_km=loc.distance_km)
                if loc.action is not Action.PROCEED:
                    return self._decline(txn, "LOCATION_RISK")
                self.store.record_approved(txn, card.customer_id)
                self.store.audit("USSD_RETRY_APPROVED", txn_id=txn.id)
                return AuthDecision(True, "APPROVED_VIA_USSD_RETRY")

        # Customer-enabled emergency mode: no phone round-trip, but strict limits.
        if self.offline is not None:
            offline_decision = self.offline.try_authorize(card, txn, pre)
            if offline_decision is not None:
                return offline_decision

        ttl = self.cfg.hold_window_s[txn.channel]
        ch, code = self.challenges.create(txn, device.id, ttl)
        delivered = self._deliver(device, ch.id, code, txn)

        # Hold the authorization. If the app has not answered in time (or the push
        # failed outright) the phone is probably off: prompt the registered number.
        event = self.store.events[ch.id]
        start = time.monotonic()
        if self.ussd is not None:
            answered = delivered and event.wait(timeout=min(self.cfg.ussd_escalation_after_s, ttl))
            if not answered:
                self._escalate_to_ussd(card, ch.id, txn)
        event.wait(timeout=max(0.0, ttl - (time.monotonic() - start)))
        ch = self.challenges.expire_if_pending(ch.id)    # no-op if already answered

        if ch.status is ChallengeStatus.APPROVED:
            loc = location_risk(txn, ch.phone_fix, self.clock.now(), self.cfg)
            self.store.audit("LOCATION_RISK", txn_id=txn.id, level=loc.level.value,
                             reasons=loc.reasons, distance_km=loc.distance_km)
            if loc.action is not Action.PROCEED:
                return self._decline(txn, "LOCATION_RISK", ch.id)
            self.store.record_approved(txn, card.customer_id)
            return AuthDecision(True, "APPROVED", ch.id)

        if ch.status is ChallengeStatus.NOT_ME:
            self._freeze(card, txn, "NOT_ME", pre, ch.phone_fix)
            return self._decline(txn, "CARDHOLDER_REPORTED_FRAUD", ch.id)

        if ch.status in (ChallengeStatus.DENIED, ChallengeStatus.LOCKED):
            n = self.store.record_failure(card.id, self.clock.now(), self.cfg.failure_window_s)
            if n >= self.cfg.failure_limit:
                self._freeze(card, txn, "REPEATED_FAILED_CHALLENGES", pre, ch.phone_fix)
            return self._decline(txn, ch.status.value, ch.id)

        return self._decline(txn, "TIMEOUT", ch.id)

    def _deliver(self, device, challenge_id: str, code: str, txn: Transaction) -> bool:
        msg = PushMessage(
            device_id=device.id, push_token=device.push_token,
            challenge_id=challenge_id, code=code,
            summary={
                "amount": txn.amount, "currency": txn.currency,
                "merchant": txn.merchant_name, "city": txn.merchant_city,
                "country": txn.merchant_country, "lat": txn.merchant_lat,
                "lon": txn.merchant_lon, "channel": txn.channel.value,
            },
        )
        for _ in range(1 + self.cfg.push_retries):
            if self.notifier.push(msg):
                return True
        self.store.audit("PUSH_FAILED", challenge_id=challenge_id)
        return False

    def _escalate_to_ussd(self, card: Card, challenge_id: str, txn: Transaction) -> None:
        customer = self.store.customers.get(card.customer_id)
        if customer is None:
            self.store.audit("USSD_NO_REGISTERED_NUMBER", card_id=card.id)
            return
        try:
            otp = self.challenges.issue_ussd_code(challenge_id, self.cfg.ussd_retry_window_s)
        except ChallengeError:
            return  # answered in the meantime
        code = self.ussd.short_code
        minutes = int(self.cfg.ussd_retry_window_s // 60)
        self.notifier.sms(
            customer.msisdn,
            f"Card use: {money(txn.amount, txn.currency)} at {txn.merchant_name}, {txn.merchant_city} "
            f"({txn.merchant_country}). To approve dial {code}, enter code {otp} and your USSD "
            f"password. If the terminal already declined, approve then retry the same purchase "
            f"within {minutes} min. Not you? Dial {code} and choose Not me.")
        self.store.audit("USSD_PROMPT_SENT", challenge_id=challenge_id)

    def _freeze(self, card: Card, txn: Transaction, reason: str,
                risk: RiskResult, fix=None) -> None:
        self.store.freeze_card(card.id)
        self.store.add_fraud_case(FraudCase(
            id=uuid.uuid4().hex, card_id=card.id, txn_id=txn.id, reason=reason,
            evidence={
                "merchant": [txn.merchant_name, txn.merchant_city, txn.merchant_country],
                "merchant_coords": [txn.merchant_lat, txn.merchant_lon],
                "phone_fix": None if fix is None else [fix.lat, fix.lon, fix.accuracy_m],
                "risk_reasons": list(risk.reasons),
            },
            opened_at=self.clock.now(),
        ))
        self.store.audit("CARD_FROZEN", card_id=card.id, reason=reason)

    def _decline(self, txn: Transaction, reason: str, challenge_id=None) -> AuthDecision:
        self.store.audit("DECLINED", txn_id=txn.id, reason=reason)
        return AuthDecision(False, reason, challenge_id)
