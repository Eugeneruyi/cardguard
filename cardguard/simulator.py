"""A fake phone, used by tests and demo.py. It reacts to a push the way the
real app would: unlock, read location, sign, submit."""
from __future__ import annotations

from typing import Optional

from .challenge import ChallengeError, ChallengeService, sign_response
from .clock import Clock
from .models import Device, PhoneFix, ResponseDecision
from .notify import PushMessage


class SimulatedPhone:
    def __init__(self, challenges: ChallengeService, device: Device, clock: Clock,
                 decision: ResponseDecision = ResponseDecision.APPROVE,
                 location: Optional[tuple] = None, attested: bool = True,
                 wrong_code: bool = False):
        self.challenges = challenges
        self.device = device
        self.clock = clock
        self.decision = decision
        self.location = location
        self.attested = attested
        self.wrong_code = wrong_code
        self.errors: list[str] = []
        self.seen: list[PushMessage] = []

    def __call__(self, msg: PushMessage) -> None:
        self.seen.append(msg)
        if self.decision is ResponseDecision.APPROVE:
            code = msg.code
            if self.wrong_code:
                code = f"{(int(msg.code) + 1) % 1_000_000:06d}"
        else:
            code = ""
        fix = None
        if self.location is not None:
            fix = PhoneFix(self.location[0], self.location[1], 20.0,
                           self.clock.now(), self.attested)
        sig = sign_response(self.device.key, msg.challenge_id, self.decision, code)
        try:
            self.challenges.respond(msg.challenge_id, self.device.id,
                                    self.decision, code, sig, fix)
        except ChallengeError as e:
            self.errors.append(e.code)
