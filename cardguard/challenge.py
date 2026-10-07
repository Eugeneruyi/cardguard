from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets
import threading
import uuid
from datetime import timedelta
from typing import Optional

from .clock import Clock
from .models import (Challenge, ChallengeStatus, PhoneFix, ResponseDecision,
                     Transaction)
from .store import Store


class ChallengeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"  # CSPRNG, never `random`


def hash_code(server_key: bytes, challenge_id: str, code: str) -> bytes:
    return hmac.new(server_key, f"{challenge_id}:{code}".encode(), hashlib.sha256).digest()


def sign_response(device_key: bytes, challenge_id: str,
                  decision: ResponseDecision, code: str) -> bytes:
    """What the app computes after biometric unlock. Binds the answer to this
    challenge and this device, which stops replay and cross-device approval."""
    msg = f"{challenge_id}:{decision.value}:{code}".encode()
    return hmac.new(device_key, msg, hashlib.sha256).digest()


class ChallengeService:
    def __init__(self, store: Store, clock: Clock, server_key: bytes, max_attempts: int = 3):
        self.store = store
        self.clock = clock
        self.server_key = server_key
        self.max_attempts = max_attempts

    def create(self, txn: Transaction, device_id: str, ttl_s: float):
        """Returns (challenge, plaintext_code). The code goes to the device
        only; the store keeps just the HMAC."""
        now = self.clock.now()
        cid = uuid.uuid4().hex
        code = new_code()
        ch = Challenge(
            id=cid, txn_id=txn.id, card_id=txn.card_id, device_id=device_id,
            code_hash=hash_code(self.server_key, cid, code),
            created_at=now, expires_at=now + timedelta(seconds=ttl_s),
        )
        with self.store.lock:
            self.store.challenges[cid] = ch
            self.store.txns[txn.id] = txn
            self.store.events[cid] = threading.Event()
        self.store.audit("CHALLENGE_CREATED", challenge_id=cid, txn_id=txn.id)
        return dataclasses.replace(ch), code

    def respond(self, challenge_id: str, device_id: str, decision: ResponseDecision,
                code: str, signature: bytes, fix: Optional[PhoneFix] = None) -> Challenge:
        # One lock covers read-check-write, so two simultaneous approvals
        # cannot both succeed.
        with self.store.lock:
            ch = self.store.challenges.get(challenge_id)
            if ch is None:
                raise ChallengeError("NOT_FOUND")
            if ch.status is not ChallengeStatus.PENDING:
                raise ChallengeError("NOT_PENDING")
            if self.clock.now() >= ch.expires_at:
                self._finish(ch, ChallengeStatus.EXPIRED)
                raise ChallengeError("EXPIRED")
            if ch.device_id != device_id:
                self.store.audit("WRONG_DEVICE", challenge_id=ch.id, device_id=device_id)
                raise ChallengeError("WRONG_DEVICE")
            device = self.store.devices.get(device_id)
            if device is None or not device.active:
                raise ChallengeError("UNKNOWN_DEVICE")

            expected = sign_response(device.key, ch.id, decision, code)
            if not hmac.compare_digest(expected, signature):
                self.store.audit("BAD_SIGNATURE", challenge_id=ch.id)
                raise ChallengeError("BAD_SIGNATURE")

            ch.phone_fix = fix  # kept for every decision: it is fraud-case evidence

            # Deny and "Not me" never need a valid code: they must always work.
            if decision is ResponseDecision.DENY:
                self._finish(ch, ChallengeStatus.DENIED)
                return dataclasses.replace(ch)
            if decision is ResponseDecision.NOT_ME:
                self._finish(ch, ChallengeStatus.NOT_ME)
                return dataclasses.replace(ch)

            candidate = hash_code(self.server_key, ch.id, code)
            if not hmac.compare_digest(candidate, ch.code_hash):
                ch.attempts += 1  # persisted before we raise
                self.store.audit("INVALID_CODE", challenge_id=ch.id, attempts=ch.attempts)
                if ch.attempts >= self.max_attempts:
                    self._finish(ch, ChallengeStatus.LOCKED)
                    raise ChallengeError("LOCKED")
                raise ChallengeError("INVALID_CODE")

            self._finish(ch, ChallengeStatus.APPROVED)
            return dataclasses.replace(ch)

    # ---- USSD path (phone off) -------------------------------------------
    def issue_ussd_code(self, challenge_id: str, valid_for_s: float) -> str:
        """A second, independent one-time code for the SMS sent to the
        registered number. It is never the app code, and its hash is bound to
        this challenge."""
        with self.store.lock:
            ch = self.store.challenges.get(challenge_id)
            if ch is None:
                raise ChallengeError("NOT_FOUND")
            if ch.status is not ChallengeStatus.PENDING:
                raise ChallengeError("NOT_PENDING")
            code = new_code()
            ch.ussd_code_hash = hash_code(self.server_key, "ussd:" + ch.id, code)
            ch.ussd_valid_until = self.clock.now() + timedelta(seconds=valid_for_s)
            self.store.audit("USSD_CODE_ISSUED", challenge_id=ch.id)
            return code

    def respond_ussd(self, challenge_id: str, decision: ResponseDecision,
                     otp: str, fix: Optional[PhoneFix] = None) -> Challenge:
        """The caller (UssdService) has already proven the number and password."""
        with self.store.lock:
            ch = self.store.challenges.get(challenge_id)
            if ch is None:
                raise ChallengeError("NOT_FOUND")
            now = self.clock.now()
            if ch.status is ChallengeStatus.PENDING and now >= ch.expires_at:
                self._finish(ch, ChallengeStatus.EXPIRED)
            if ch.status not in (ChallengeStatus.PENDING, ChallengeStatus.EXPIRED):
                raise ChallengeError("NOT_PENDING")
            late = ch.status is ChallengeStatus.EXPIRED

            if decision is not ResponseDecision.APPROVE:      # DENY / NOT_ME: live only
                if late:
                    raise ChallengeError("EXPIRED")
                if fix is not None:
                    ch.phone_fix = fix
                self._finish(ch, ChallengeStatus.DENIED if decision is ResponseDecision.DENY
                             else ChallengeStatus.NOT_ME)
                return dataclasses.replace(ch)

            if ch.ussd_code_hash is None:
                raise ChallengeError("NO_USSD_CODE")
            if ch.ussd_valid_until is None or now >= ch.ussd_valid_until:
                raise ChallengeError("EXPIRED")
            if ch.ussd_attempts >= self.max_attempts:
                raise ChallengeError("LOCKED")
            candidate = hash_code(self.server_key, "ussd:" + ch.id, otp)
            if not hmac.compare_digest(candidate, ch.ussd_code_hash):
                ch.ussd_attempts += 1
                self.store.audit("USSD_INVALID_CODE", challenge_id=ch.id, attempts=ch.ussd_attempts)
                if ch.ussd_attempts >= self.max_attempts:
                    if not late:
                        self._finish(ch, ChallengeStatus.LOCKED)
                    raise ChallengeError("LOCKED")
                raise ChallengeError("INVALID_CODE")

            if fix is not None:
                ch.phone_fix = fix
            if late:
                ch.status = ChallengeStatus.LATE_APPROVED   # single use: later calls see NOT_PENDING
                self.store.audit("CHALLENGE_LATE_APPROVED", challenge_id=ch.id)
            else:
                self._finish(ch, ChallengeStatus.APPROVED)
            return dataclasses.replace(ch)

    def expire_if_pending(self, challenge_id: str) -> Challenge:
        with self.store.lock:
            ch = self.store.challenges[challenge_id]
            if ch.status is ChallengeStatus.PENDING:
                self._finish(ch, ChallengeStatus.EXPIRED)
            return dataclasses.replace(ch)

    def _finish(self, ch: Challenge, status: ChallengeStatus) -> None:
        ch.status = status
        self.store.events[ch.id].set()
        self.store.audit("CHALLENGE_" + status.value, challenge_id=ch.id)
