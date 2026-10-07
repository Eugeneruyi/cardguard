import threading
import unittest

from cardguard.challenge import ChallengeError, ChallengeService, sign_response
from cardguard.clock import FakeClock
from cardguard.models import ChallengeStatus as S
from cardguard.models import ResponseDecision as D
from cardguard.models import Card, Device
from cardguard.store import Store
from tests.helpers import make_txn

KEY = b"server-key"


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = Store(self.clock)
        self.svc = ChallengeService(self.store, self.clock, KEY, max_attempts=3)
        self.dev = Device("d1", "u1", "tok", b"device-key")
        self.other = Device("d2", "u1", "tok2", b"other-key")
        self.store.add_device(self.dev)
        self.store.add_device(self.other)
        self.store.add_card(Card("c1", "u1", "d1"))
        self.ch, self.code = self.svc.create(make_txn(self.clock), "d1", ttl_s=60)

    def answer(self, decision=D.APPROVE, code=None, device=None, key=None, fix=None):
        device = device or self.dev
        code = self.code if code is None else code
        sig = sign_response(key or device.key, self.ch.id, decision, code)
        return self.svc.respond(self.ch.id, device.id, decision, code, sig, fix)

    def wrong(self):
        return f"{(int(self.code) + 1) % 1_000_000:06d}"

    def code_of(self, exc):
        return exc.exception.code


class Challenges(Base):
    def test_code_is_six_digits_and_stored_hashed(self):
        self.assertRegex(self.code, r"^\d{6}$")
        self.assertNotEqual(self.ch.code_hash, self.code.encode())
        self.assertEqual(len(self.ch.code_hash), 32)

    def test_correct_code_approves(self):
        self.assertEqual(self.answer().status, S.APPROVED)

    def test_replay_of_approved_code_rejected(self):
        self.answer()
        with self.assertRaises(ChallengeError) as e:
            self.answer()
        self.assertEqual(self.code_of(e), "NOT_PENDING")

    def test_wrong_code_counts_attempts_then_locks(self):
        for _ in range(2):
            with self.assertRaises(ChallengeError) as e:
                self.answer(code=self.wrong())
            self.assertEqual(self.code_of(e), "INVALID_CODE")
        with self.assertRaises(ChallengeError) as e:
            self.answer(code=self.wrong())
        self.assertEqual(self.code_of(e), "LOCKED")
        self.assertEqual(self.store.challenges[self.ch.id].status, S.LOCKED)

    def test_correct_code_after_lock_is_rejected(self):
        for _ in range(3):
            with self.assertRaises(ChallengeError):
                self.answer(code=self.wrong())
        with self.assertRaises(ChallengeError) as e:
            self.answer()
        self.assertEqual(self.code_of(e), "NOT_PENDING")

    def test_expired_challenge_rejected(self):
        self.clock.advance(61)
        with self.assertRaises(ChallengeError) as e:
            self.answer()
        self.assertEqual(self.code_of(e), "EXPIRED")
        self.assertEqual(self.store.challenges[self.ch.id].status, S.EXPIRED)

    def test_wrong_device_rejected_even_with_valid_code(self):
        with self.assertRaises(ChallengeError) as e:
            self.answer(device=self.other)
        self.assertEqual(self.code_of(e), "WRONG_DEVICE")

    def test_bad_signature_rejected(self):
        with self.assertRaises(ChallengeError) as e:
            self.answer(key=b"attacker-key")
        self.assertEqual(self.code_of(e), "BAD_SIGNATURE")

    def test_signature_is_bound_to_decision(self):
        # A captured APPROVE signature cannot be reused as a different decision.
        sig = sign_response(self.dev.key, self.ch.id, D.APPROVE, self.code)
        with self.assertRaises(ChallengeError) as e:
            self.svc.respond(self.ch.id, "d1", D.DENY, self.code, sig)
        self.assertEqual(self.code_of(e), "BAD_SIGNATURE")

    def test_deny_needs_no_code(self):
        self.assertEqual(self.answer(D.DENY, code="").status, S.DENIED)

    def test_not_me_needs_no_code(self):
        self.assertEqual(self.answer(D.NOT_ME, code="").status, S.NOT_ME)

    def test_unknown_challenge(self):
        with self.assertRaises(ChallengeError) as e:
            self.svc.respond("nope", "d1", D.APPROVE, "000000", b"x")
        self.assertEqual(self.code_of(e), "NOT_FOUND")

    def test_concurrent_approvals_only_one_wins(self):
        results = []

        def attempt():
            try:
                self.answer()
                results.append("ok")
            except ChallengeError as e:
                results.append(e.code)

        threads = [threading.Thread(target=attempt) for _ in range(12)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("NOT_PENDING"), 11)


if __name__ == "__main__":
    unittest.main()
