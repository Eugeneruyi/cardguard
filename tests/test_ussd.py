import itertools
import threading
import unittest
from datetime import timedelta

from cardguard.clock import FakeClock
from cardguard.models import (AppCredentials, Card, CardStatus, ChallengeStatus,
                              Channel, Customer, EnableChannel, PhoneFix)
from cardguard.simulator import SimulatedPhone
from cardguard.ussd import UssdError, sign_password_request, validate_password
from tests.helpers import MANCHESTER, MSISDN, NEARBY, World, otp_from, wait_for_sms

APP = EnableChannel.APP
_n = itertools.count(1)
GOOD_PW = "493817"


def app_creds(w, password, key=None, device_id="d1", nonce=None):
    nonce = nonce or f"pw{next(_n)}"
    sig = sign_password_request(key or w.device.key, "u1", nonce, password)
    return AppCredentials(device_id, nonce, sig)


def enrol(w, password=GOOD_PW):
    w.ussd.set_password("u1", password, APP, app_creds(w, password))


class Base(unittest.TestCase):
    def code(self, fn):
        with self.assertRaises(UssdError) as e:
            fn()
        return e.exception.code


class Enrolment(Base):
    def setUp(self):
        self.w = World(clock=FakeClock())

    def test_weak_passwords_rejected(self):
        for pw in ("123456", "654321", "111111", "121212", "123123", "12345", "12ab56", "1" * 13, ""):
            with self.subTest(pw=pw), self.assertRaises(UssdError) as e:
                validate_password(pw)
            self.assertEqual(e.exception.code, "WEAK_PASSWORD")

    def test_reasonable_password_accepted(self):
        validate_password(GOOD_PW)

    def test_set_via_app_stores_only_a_salted_hash(self):
        enrol(self.w)
        cred = self.w.store.ussd_credentials["u1"]
        self.assertNotIn(GOOD_PW.encode(), cred.password_hash)
        self.assertEqual(len(cred.salt), 16)
        self.assertIn("USSD password set", " ".join(t for _, t in self.w.notifier.alerts))

    def test_two_customers_same_password_get_different_hashes(self):
        self.w.store.add_customer(Customer("u2", "+15550100002"))
        enrol(self.w)
        sig_dev = self.w.device
        self.w.store.add_device(type(sig_dev)("d9", "u2", "tok9", b"k9"))
        self.w.ussd.set_password("u2", GOOD_PW, APP, AppCredentials(
            "d9", "x1", sign_password_request(b"k9", "u2", "x1", GOOD_PW)))
        c = self.w.store.ussd_credentials
        self.assertNotEqual(c["u1"].password_hash, c["u2"].password_hash)

    def test_cannot_set_password_over_ussd(self):
        self.assertEqual(self.code(lambda: self.w.ussd.set_password(
            "u1", GOOD_PW, EnableChannel.USSD, {})), "CHANNEL_NOT_ALLOWED")

    def test_set_via_web_uses_verifier(self):
        self.w.ussd.set_password("u1", GOOD_PW, EnableChannel.WEB, {"x": 1})
        self.assertIn("u1", self.w.store.ussd_credentials)
        self.w.verifier.ok = False
        self.assertEqual(self.code(lambda: self.w.ussd.set_password(
            "u1", "582913", EnableChannel.WEB, {})), "BAD_CREDENTIALS")

    def test_bad_signature_other_device_and_replay_rejected(self):
        self.assertEqual(self.code(lambda: self.w.ussd.set_password(
            "u1", GOOD_PW, APP, app_creds(self.w, GOOD_PW, key=b"attacker"))), "BAD_CREDENTIALS")
        self.assertEqual(self.code(lambda: self.w.ussd.set_password(
            "u1", GOOD_PW, APP, app_creds(self.w, GOOD_PW, device_id="nope"))), "BAD_CREDENTIALS")
        c = app_creds(self.w, GOOD_PW)
        self.w.ussd.set_password("u1", GOOD_PW, APP, c)
        self.assertEqual(self.code(lambda: self.w.ussd.set_password("u1", GOOD_PW, APP, c)), "BAD_CREDENTIALS")

    def test_signature_is_bound_to_the_password(self):
        c = app_creds(self.w, GOOD_PW)
        self.assertEqual(self.code(lambda: self.w.ussd.set_password("u1", "582913", APP, c)),
                         "BAD_CREDENTIALS")

    def test_unknown_customer(self):
        self.assertEqual(self.code(lambda: self.w.ussd.set_password(
            "zz", GOOD_PW, APP, None)), "UNKNOWN_CUSTOMER")

    def test_new_password_unusable_during_cooldown(self):
        w = World(clock=FakeClock(), ussd_password_cooldown_s=24 * 3600)
        enrol(w)
        ch, otp = new_challenge(w)
        self.assertEqual(self.code(lambda: w.ussd.approve(MSISDN, ch.id, otp, GOOD_PW)), "PASSWORD_COOLDOWN")
        w.clock.advance(24 * 3600 + 1)
        ch, otp = new_challenge(w)
        self.assertEqual(w.ussd.approve(MSISDN, ch.id, otp, GOOD_PW).status, ChallengeStatus.APPROVED)


def new_challenge(w, **txn_kw):
    txn = w.txn(**txn_kw)
    ch, _app_code = w.challenges.create(txn, "d1", ttl_s=60)
    otp = w.challenges.issue_ussd_code(ch.id, valid_for_s=600)
    return ch, otp


class Approval(Base):
    def setUp(self):
        self.w = World(clock=FakeClock())
        enrol(self.w)
        self.ch, self.otp = new_challenge(self.w)

    def approve(self, otp=None, password=GOOD_PW, msisdn=MSISDN, cid=None, **kw):
        return self.w.ussd.approve(msisdn, cid or self.ch.id, otp or self.otp, password, **kw)

    def status(self):
        return self.w.store.challenges[self.ch.id].status

    def wrong_otp(self):
        return f"{(int(self.otp) + 1) % 1_000_000:06d}"

    def test_correct_otp_and_password_approves_and_alerts(self):
        self.assertEqual(self.approve().status, ChallengeStatus.APPROVED)
        self.assertIn("USSD approval", " ".join(t for _, t in self.w.notifier.alerts))

    def test_unknown_number_rejected(self):
        self.assertEqual(self.code(lambda: self.approve(msisdn="+15550199999")), "UNKNOWN_NUMBER")

    def test_other_customers_transaction_rejected(self):
        self.w.store.add_customer(Customer("u2", "+15550100002"))
        self.assertEqual(self.code(lambda: self.approve(msisdn="+15550100002")), "NOT_YOUR_TRANSACTION")

    def test_no_password_enrolled(self):
        self.w.store.ussd_credentials.clear()
        self.assertEqual(self.code(self.approve), "NO_PASSWORD")

    def test_wrong_password_does_not_approve(self):
        self.assertEqual(self.code(lambda: self.approve(password="582913")), "BAD_PASSWORD")
        self.assertEqual(self.status(), ChallengeStatus.PENDING)

    def test_password_lockout_blocks_approve_but_not_deny_and_expires(self):
        for _ in range(3):
            self.code(lambda: self.approve(password="582913"))
        self.assertEqual(self.code(self.approve), "LOCKED_OUT")        # even with the right password
        self.assertIn("locked", " ".join(t for _, t in self.w.notifier.alerts))
        self.w.clock.advance(self.w.cfg.ussd_lockout_s + 1)
        ch, otp = new_challenge(self.w)
        self.assertEqual(self.w.ussd.approve(MSISDN, ch.id, otp, GOOD_PW).status, ChallengeStatus.APPROVED)

    def test_deny_and_not_me_work_while_locked_out(self):
        for _ in range(3):
            self.code(lambda: self.approve(password="582913"))
        self.assertEqual(self.w.ussd.deny(MSISDN, self.ch.id).status, ChallengeStatus.DENIED)
        ch2, _ = new_challenge(self.w)
        self.assertEqual(self.w.ussd.report_not_me(MSISDN, ch2.id).status, ChallengeStatus.NOT_ME)

    def test_wrong_otp_counts_then_locks_the_challenge(self):
        for _ in range(2):
            self.assertEqual(self.code(lambda: self.approve(otp=self.wrong_otp())), "INVALID_CODE")
        self.assertEqual(self.code(lambda: self.approve(otp=self.wrong_otp())), "LOCKED")
        self.assertEqual(self.status(), ChallengeStatus.LOCKED)
        self.assertEqual(self.code(self.approve), "NOT_PENDING")

    def test_otp_of_one_challenge_cannot_approve_another(self):
        ch2, otp2 = new_challenge(self.w)
        self.assertEqual(self.code(lambda: self.approve(otp=self.otp, cid=ch2.id)), "INVALID_CODE")

    def test_otp_not_issued_yet(self):
        ch, _ = self.w.challenges.create(self.w.txn(), "d1", ttl_s=60)
        self.assertEqual(self.code(lambda: self.approve(cid=ch.id)), "NO_USSD_CODE")

    def test_replay_after_approval_rejected(self):
        self.approve()
        self.assertEqual(self.code(self.approve), "NOT_PENDING")

    def test_sim_swap_blocks_approval_but_not_deny(self):
        self.w.sim.swapped = True
        self.assertEqual(self.code(self.approve), "SIM_SWAP_SUSPECTED")
        self.assertEqual(self.status(), ChallengeStatus.PENDING)
        self.assertIn("SIM was swapped", " ".join(t for _, t in self.w.notifier.alerts))
        self.assertEqual(self.w.ussd.deny(MSISDN, self.ch.id).status, ChallengeStatus.DENIED)

    def test_otp_expires_after_retry_window(self):
        self.w.clock.advance(self.w.cfg.ussd_retry_window_s + 1)
        self.assertEqual(self.code(self.approve), "EXPIRED")

    def test_telco_location_is_recorded(self):
        fix = PhoneFix(NEARBY[0], NEARBY[1], 1500.0, self.w.clock.now(), True)
        self.assertEqual(self.approve(fix=fix).phone_fix, fix)

    def test_pending_list_shows_only_own_open_prompts(self):
        self.w.store.add_customer(Customer("u2", "+15550100002"))
        items = self.w.ussd.pending(MSISDN)
        self.assertEqual([i.challenge_id for i in items], [self.ch.id])
        self.assertEqual((items[0].merchant, items[0].amount, items[0].expired), ("Corner Shop", 10_000, False))
        self.assertEqual(self.w.ussd.pending("+15550100002"), [])
        self.approve()
        self.assertEqual(self.w.ussd.pending(MSISDN), [])


class LateApproval(Base):
    """The terminal timed out first; the customer approves afterwards."""

    def setUp(self):
        self.w = World(clock=FakeClock())
        enrol(self.w)
        self.txn = self.w.txn()
        self.ch, _ = self.w.challenges.create(self.txn, "d1", ttl_s=60)
        self.otp = self.w.challenges.issue_ussd_code(self.ch.id, 600)
        self.w.clock.advance(61)                      # hold window over

    def late_approve(self):
        return self.w.ussd.approve(MSISDN, self.ch.id, self.otp, GOOD_PW)

    def test_late_approval_creates_single_retry_grant(self):
        self.assertTrue(self.w.ussd.pending(MSISDN)[0].expired)
        self.assertEqual(self.late_approve().status, ChallengeStatus.LATE_APPROVED)
        self.assertIn("c1", self.w.store.retry_grants)

    def test_retry_of_same_purchase_succeeds_once(self):
        self.late_approve()
        self.w.notifier.on_push = None
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (True, "APPROVED_VIA_USSD_RETRY"))
        self.assertEqual(self.w.store.challenges.keys() - {self.ch.id}, set())   # no new challenge
        d2 = self.w.auth.authorize(self.w.txn())
        self.assertFalse(d2.approved)                  # grant was single use

    def test_other_merchant_or_higher_amount_does_not_use_grant(self):
        self.late_approve()
        self.assertFalse(self.w.auth.authorize(self.w.txn(merchant_name="Other Store")).approved)
        self.assertFalse(self.w.auth.authorize(self.w.txn(amount=10_001)).approved)
        self.assertIn("c1", self.w.store.retry_grants)  # still available for the real retry
        self.assertTrue(self.w.auth.authorize(self.w.txn(amount=9_000)).approved)

    def test_grant_expires(self):
        self.late_approve()
        self.w.clock.advance(self.w.cfg.ussd_retry_window_s + 1)
        self.assertFalse(self.w.auth.authorize(self.w.txn()).approved)

    def test_grant_does_not_survive_a_freeze(self):
        self.late_approve()
        self.w.store.freeze_card("c1")
        self.assertEqual(self.w.auth.authorize(self.w.txn()).reason, "CARD_NOT_ACTIVE")

    def test_grant_still_subject_to_location_risk(self):
        self.w.store.freeze_card("c1"); self.w.store.cards["c1"].status = CardStatus.ACTIVE
        # approve with a far-away telco fix and a large amount
        txn = self.w.txn(amount=self.w.cfg.high_amount + 1)
        ch, _ = self.w.challenges.create(txn, "d1", ttl_s=60)
        otp = self.w.challenges.issue_ussd_code(ch.id, 600)
        self.w.clock.advance(61)
        fix = PhoneFix(MANCHESTER[0], MANCHESTER[1], 1500.0, self.w.clock.now(), True)
        self.w.ussd.approve(MSISDN, ch.id, otp, GOOD_PW, fix=fix)
        d = self.w.auth.authorize(self.w.txn(amount=self.w.cfg.high_amount + 1))
        self.assertEqual((d.approved, d.reason), (False, "LOCATION_RISK"))

    def test_deny_after_timeout_is_rejected(self):
        self.assertEqual(self.code(lambda: self.w.ussd.deny(MSISDN, self.ch.id)), "EXPIRED")

    def test_late_otp_cannot_be_reused(self):
        self.late_approve()
        self.assertEqual(self.code(self.late_approve), "NOT_PENDING")


class EndToEnd(Base):
    """Real AuthService, real threads, the phone is off."""

    def setUp(self):
        self.w = World(hold=3.0, ussd_escalation_after_s=0.05)
        enrol(self.w)

    def start(self, **txn_kw):
        out = {}
        t = threading.Thread(target=lambda: out.update(d=self.w.auth.authorize(self.w.txn(**txn_kw))))
        t.start()
        return t, out

    def test_push_fails_sms_to_registered_number_customer_approves_by_ussd(self):
        self.w.notifier.deliver = False
        t, out = self.start()
        sms = wait_for_sms(self.w)
        self.assertEqual(self.w.notifier.sent_sms[0][0], MSISDN)
        self.assertIn("*123#", sms)
        self.assertNotIn(self.w.notifier.pushes[0].code, sms)
        self.w.ussd.approve(MSISDN, self.w.ussd.pending(MSISDN)[0].challenge_id, otp_from(sms), GOOD_PW)
        t.join(5)
        self.assertEqual((out["d"].approved, out["d"].reason), (True, "APPROVED"))

    def test_push_accepted_but_unanswered_also_escalates(self):
        self.w.notifier.on_push = None      # provider accepted it, phone never reacts
        t, out = self.start()
        sms = wait_for_sms(self.w)
        cid = self.w.ussd.pending(MSISDN)[0].challenge_id
        self.w.ussd.approve(MSISDN, cid, otp_from(sms), GOOD_PW)
        t.join(5)
        self.assertTrue(out["d"].approved)

    def test_no_sms_when_the_app_answers_in_time(self):
        self.w.notifier.on_push = SimulatedPhone(self.w.challenges, self.w.device, self.w.clock, location=NEARBY)
        t, out = self.start()
        t.join(5)
        self.assertTrue(out["d"].approved)
        self.assertEqual(self.w.notifier.sent_sms, [])

    def test_ussd_approval_without_location_respects_the_unverified_cap(self):
        self.w.notifier.deliver = False
        t, out = self.start(amount=self.w.cfg.unverified_amount_cap + 1)
        sms = wait_for_sms(self.w)
        self.w.ussd.approve(MSISDN, self.w.ussd.pending(MSISDN)[0].challenge_id, otp_from(sms), GOOD_PW)
        t.join(5)
        self.assertEqual((out["d"].approved, out["d"].reason), (False, "LOCATION_RISK"))

    def test_ussd_approval_with_telco_location_near_merchant_allows_larger_amount(self):
        self.w.notifier.deliver = False
        t, out = self.start(amount=self.w.cfg.unverified_amount_cap + 1)
        sms = wait_for_sms(self.w)
        fix = PhoneFix(NEARBY[0], NEARBY[1], 1500.0, self.w.clock.now(), True)
        self.w.ussd.approve(MSISDN, self.w.ussd.pending(MSISDN)[0].challenge_id, otp_from(sms), GOOD_PW, fix=fix)
        t.join(5)
        self.assertTrue(out["d"].approved)

    def test_not_me_by_ussd_freezes_card_and_opens_case(self):
        self.w.notifier.deliver = False
        t, out = self.start()
        wait_for_sms(self.w)
        self.w.ussd.report_not_me(MSISDN, self.w.ussd.pending(MSISDN)[0].challenge_id)
        t.join(5)
        self.assertEqual(out["d"].reason, "CARDHOLDER_REPORTED_FRAUD")
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.FROZEN)
        self.assertEqual(self.w.store.fraud_cases[0].reason, "NOT_ME")

    def test_sim_swap_attacker_with_the_sms_still_cannot_approve(self):
        self.w.notifier.deliver = False
        self.w.sim.swapped = True
        t, out = self.start()
        sms = wait_for_sms(self.w)
        cid = self.w.ussd.pending(MSISDN)[0].challenge_id
        self.assertEqual(self.code(lambda: self.w.ussd.approve(MSISDN, cid, otp_from(sms), GOOD_PW)),
                         "SIM_SWAP_SUSPECTED")
        t.join(5)
        self.assertEqual((out["d"].approved, out["d"].reason), (False, "TIMEOUT"))

    def test_thief_with_sms_but_no_password_cannot_approve(self):
        self.w.notifier.deliver = False
        w = self.w
        t, out = self.start()
        sms = wait_for_sms(w)
        cid = w.ussd.pending(MSISDN)[0].challenge_id
        for _ in range(3):
            self.code(lambda: w.ussd.approve(MSISDN, cid, otp_from(sms), "000999"))
        t.join(5)
        self.assertFalse(out["d"].approved)

    def test_customer_ignores_everything_declines_on_timeout(self):
        w = World(hold=0.4, ussd_escalation_after_s=0.05)
        w.notifier.deliver = False
        d = w.auth.authorize(w.txn())
        self.assertEqual(d.reason, "TIMEOUT")
        self.assertEqual(len(w.notifier.sent_sms), 1)       # exactly one prompt per challenge

    def test_customer_without_registered_number_gets_no_sms(self):
        w = World(hold=0.3)
        w.store.customers.clear()
        w.notifier.deliver = False
        d = w.auth.authorize(w.txn())
        self.assertEqual(d.reason, "TIMEOUT")
        self.assertEqual(w.notifier.sent_sms, [])

    def test_ecom_can_be_approved_by_ussd_too(self):
        self.w.notifier.deliver = False
        t, out = self.start(channel=Channel.ECOM)
        sms = wait_for_sms(self.w)
        self.w.ussd.approve(MSISDN, self.w.ussd.pending(MSISDN)[0].challenge_id, otp_from(sms), GOOD_PW)
        t.join(5)
        self.assertTrue(out["d"].approved)


if __name__ == "__main__":
    unittest.main()
