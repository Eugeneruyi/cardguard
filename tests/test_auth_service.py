import threading
import unittest
from datetime import timedelta

from cardguard.models import CardStatus, Channel
from cardguard.models import ResponseDecision as D
from cardguard.notify import FakeNotifier
from cardguard.risk import RiskConfig
from cardguard.simulator import SimulatedPhone
from tests.helpers import LONDON, MANCHESTER, NEARBY, World


class AuthBase(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def phone(self, **kw):
        p = SimulatedPhone(self.w.challenges, self.w.device, self.w.clock, **kw)
        self.w.notifier.on_push = p
        return p


class HappyAndUnhappyPaths(AuthBase):
    def test_phone_near_merchant_is_approved(self):
        self.phone(location=NEARBY)
        d = self.w.auth.authorize(self.w.txn())
        self.assertTrue(d.approved)
        self.assertEqual(len(self.w.notifier.pushes), 1)
        self.assertTrue(self.w.notifier.pushes[0].requests_location)

    def test_push_goes_only_to_the_registered_device(self):
        self.phone(location=NEARBY)
        self.w.auth.authorize(self.w.txn())
        msg = self.w.notifier.pushes[0]
        self.assertEqual((msg.device_id, msg.push_token), ("d1", "push-token-1"))

    def test_phone_far_with_high_amount_is_declined(self):
        self.phone(location=MANCHESTER)
        d = self.w.auth.authorize(self.w.txn(amount=self.w.cfg.high_amount + 1))
        self.assertEqual((d.approved, d.reason), (False, "LOCATION_RISK"))

    def test_no_location_fix_above_cap_is_declined(self):
        self.phone(location=None)
        d = self.w.auth.authorize(self.w.txn(amount=self.w.cfg.unverified_amount_cap + 1))
        self.assertEqual((d.approved, d.reason), (False, "LOCATION_RISK"))

    def test_no_location_fix_small_amount_is_approved(self):
        self.phone(location=None)
        self.assertTrue(self.w.auth.authorize(self.w.txn()).approved)

    def test_ecom_approved_without_location(self):
        self.phone(location=None)
        self.assertTrue(self.w.auth.authorize(self.w.txn(channel=Channel.ECOM)).approved)

    def test_deny_declines_without_freezing(self):
        self.phone(decision=D.DENY, location=NEARBY)
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (False, "DENIED"))
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.ACTIVE)


class FraudResponse(AuthBase):
    def test_not_me_freezes_card_and_opens_case(self):
        self.phone(decision=D.NOT_ME, location=MANCHESTER)
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (False, "CARDHOLDER_REPORTED_FRAUD"))
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.FROZEN)
        case = self.w.store.fraud_cases[0]
        self.assertEqual(case.reason, "NOT_ME")
        self.assertEqual(case.evidence["phone_fix"][:2], [MANCHESTER[0], MANCHESTER[1]])

    def test_frozen_card_declines_instantly_with_no_push(self):
        self.phone(decision=D.NOT_ME)
        self.w.auth.authorize(self.w.txn())
        pushes_before = len(self.w.notifier.pushes)
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual(d.reason, "CARD_NOT_ACTIVE")
        self.assertEqual(len(self.w.notifier.pushes), pushes_before)

    def test_three_denials_in_window_freeze_the_card(self):
        self.phone(decision=D.DENY, location=NEARBY)
        for _ in range(3):
            self.w.auth.authorize(self.w.txn())
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.FROZEN)
        self.assertEqual(self.w.store.fraud_cases[0].reason, "REPEATED_FAILED_CHALLENGES")

    def test_two_denials_do_not_freeze(self):
        self.phone(decision=D.DENY, location=NEARBY)
        for _ in range(2):
            self.w.auth.authorize(self.w.txn())
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.ACTIVE)

    def test_impossible_travel_declines_and_freezes_without_bothering_customer(self):
        phone = self.phone(location=LONDON)
        first = self.w.txn(created_at=self.w.clock.now() - timedelta(minutes=10))
        self.assertTrue(self.w.auth.authorize(first).approved)
        pushes = len(self.w.notifier.pushes)
        second = self.w.txn(merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1],
                            merchant_city="Manchester")
        d = self.w.auth.authorize(second)
        self.assertEqual((d.approved, d.reason), (False, "IMPOSSIBLE_TRAVEL"))
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.FROZEN)
        self.assertEqual(len(self.w.notifier.pushes), pushes)


class FailureHandling(AuthBase):
    def test_customer_ignores_prompt_times_out_and_declines(self):
        self.w.notifier.on_push = None
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (False, "TIMEOUT"))
        ch = next(iter(self.w.store.challenges.values()))
        self.assertEqual(ch.status.value, "EXPIRED")

    def test_push_undeliverable_retries_then_prompts_registered_number_then_declines(self):
        self.w.notifier.deliver = False
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual(len(self.w.notifier.pushes), 2)   # 1 try + 1 retry
        self.assertEqual(len(self.w.notifier.sent_sms), 1)
        self.assertEqual(d.reason, "TIMEOUT")

    def test_sms_never_contains_the_app_code(self):
        self.w.notifier.deliver = False
        self.w.auth.authorize(self.w.txn())
        _, text = self.w.notifier.sent_sms[0]
        self.assertNotIn(self.w.notifier.pushes[0].code, text)

    def test_wrong_code_does_not_approve(self):
        p = self.phone(wrong_code=True, location=NEARBY)
        d = self.w.auth.authorize(self.w.txn())
        self.assertFalse(d.approved)
        self.assertEqual(p.errors, ["INVALID_CODE"])

    def test_duplicate_network_requests_create_one_challenge(self):
        self.w.notifier.on_push = None
        txn = self.w.txn()
        out = []
        threads = [threading.Thread(target=lambda: out.append(self.w.auth.authorize(txn)))
                   for _ in range(3)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(self.w.notifier.pushes), 1)
        self.assertEqual(len(self.w.store.challenges), 1)
        self.assertEqual({d.reason for d in out}, {"TIMEOUT"})

    def test_duplicate_after_completion_returns_same_decision(self):
        self.phone(location=NEARBY)
        txn = self.w.txn()
        a = self.w.auth.authorize(txn)
        b = self.w.auth.authorize(txn)
        self.assertEqual(a, b)
        self.assertEqual(len(self.w.notifier.pushes), 1)

    def test_no_registered_device_fails_closed(self):
        self.w.device.active = False
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual(d.reason, "NO_REGISTERED_DEVICE")
        self.assertEqual(self.w.notifier.pushes, [])

    def test_unknown_card_declined(self):
        d = self.w.auth.authorize(self.w.txn(card_id="nope"))
        self.assertEqual(d.reason, "CARD_NOT_FOUND")

    def test_internal_error_fails_closed(self):
        class Boom(FakeNotifier):
            def push(self, msg):
                raise RuntimeError("push provider down")
        self.w.auth.notifier = Boom()
        with self.assertLogs("cardguard", level="ERROR"):
            d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (False, "INTERNAL_ERROR"))


if __name__ == "__main__":
    unittest.main()
