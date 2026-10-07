import itertools
import unittest
from datetime import timedelta

from cardguard.clock import FakeClock
from cardguard.models import AppCredentials, CardStatus, Channel, EnableChannel
from cardguard.offline import OfflineModeError, sign_offline_request
from cardguard.simulator import SimulatedPhone
from tests.helpers import LONDON, MANCHESTER, NEARBY, World

_nonce = itertools.count(1)
APP, USSD = EnableChannel.APP, EnableChannel.USSD


def creds(w, action, key=None, device_id="d1", nonce=None):
    nonce = nonce or f"n{next(_nonce)}"
    sig = sign_offline_request(key or w.device.key, action, "c1", nonce)
    return AppCredentials(device_id, nonce, sig)


class OfflineBase(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def enable_app(self, **kw):
        return self.w.offline.enable("c1", APP, creds(self.w, "ENABLE"), **kw)

    def disable_app(self):
        self.w.offline.disable("c1", APP, creds(self.w, "DISABLE"))

    def code(self, fn):
        with self.assertRaises(OfflineModeError) as e:
            fn()
        return e.exception.code

    def events(self):
        return [e["event"] for e in self.w.store.audit_log]


class EnableDisable(OfflineBase):
    def test_enable_via_app_approves_without_any_challenge(self):
        self.enable_app()
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual((d.approved, d.reason), (True, "APPROVED_OFFLINE"))
        self.assertEqual(self.w.store.challenges, {})
        self.assertEqual(self.w.notifier.pushes, [])

    def test_enable_via_ussd_uses_verifier(self):
        self.w.offline.enable("c1", USSD, {"pin": "x"})
        self.assertEqual(self.w.verifier.calls, [("u1", USSD)])
        self.assertTrue(self.w.offline.is_active("c1"))

    def test_verifier_rejection_does_not_enable(self):
        self.w.verifier.ok = False
        self.assertEqual(self.code(lambda: self.w.offline.enable("c1", USSD, {})), "BAD_CREDENTIALS")
        self.assertFalse(self.w.offline.is_active("c1"))

    def test_app_bad_signature_rejected(self):
        c = creds(self.w, "ENABLE", key=b"attacker")
        self.assertEqual(self.code(lambda: self.w.offline.enable("c1", APP, c)), "BAD_CREDENTIALS")

    def test_app_request_from_other_device_rejected(self):
        c = creds(self.w, "ENABLE", device_id="d2")
        self.assertEqual(self.code(lambda: self.w.offline.enable("c1", APP, c)), "BAD_CREDENTIALS")

    def test_enable_signature_cannot_be_reused_as_disable(self):
        self.enable_app()
        c = creds(self.w, "ENABLE", nonce="same")
        # a signature made for ENABLE does not authorize DISABLE
        self.assertEqual(self.code(lambda: self.w.offline.disable("c1", APP, c)), "BAD_CREDENTIALS")
        self.assertTrue(self.w.offline.is_active("c1"))

    def test_replayed_request_rejected(self):
        c = creds(self.w, "ENABLE")
        self.w.offline.enable("c1", APP, c)
        self.assertEqual(self.code(lambda: self.w.offline.enable("c1", APP, c)), "BAD_CREDENTIALS")

    def test_lockout_blocks_enable_but_never_disable(self):
        self.enable_app()
        for _ in range(3):
            self.code(lambda: self.w.offline.enable("c1", APP, creds(self.w, "ENABLE", key=b"bad")))
        self.assertEqual(self.code(self.enable_app), "LOCKED_OUT")
        self.disable_app()                                    # must still work
        self.assertFalse(self.w.offline.is_active("c1"))

    def test_lockout_expires(self):
        w = World(clock=FakeClock())
        for _ in range(3):
            with self.assertRaises(OfflineModeError):
                w.offline.enable("c1", APP, creds(w, "ENABLE", key=b"bad"))
        w.clock.advance(w.cfg.offline_lockout_s + 1)
        w.offline.enable("c1", APP, creds(w, "ENABLE"))
        self.assertTrue(w.offline.is_active("c1"))

    def test_limits_cannot_exceed_bank_ceilings(self):
        cfg = self.w.cfg
        self.assertEqual(self.code(lambda: self.enable_app(ttl_s=cfg.offline_max_ttl_s + 1)), "TTL_ABOVE_LIMIT")
        self.assertEqual(self.code(lambda: self.enable_app(per_txn_cap=cfg.offline_max_per_txn + 1)), "CAP_ABOVE_LIMIT")
        self.assertEqual(self.code(lambda: self.enable_app(total_cap=cfg.offline_max_total_24h + 1)), "CAP_ABOVE_LIMIT")
        self.assertEqual(self.code(lambda: self.enable_app(ttl_s=0)), "TTL_ABOVE_LIMIT")

    def test_cannot_enable_on_frozen_card(self):
        self.w.store.freeze_card("c1")
        self.assertEqual(self.code(self.enable_app), "CARD_NOT_ACTIVE")

    def test_unknown_card(self):
        self.assertEqual(self.code(lambda: self.w.offline.enable("zzz", USSD, {})), "CARD_NOT_FOUND")

    def test_disable_restores_normal_approval_flow(self):
        self.enable_app()
        self.disable_app()
        SimulatedPhone_ = SimulatedPhone(self.w.challenges, self.w.device, self.w.clock, location=NEARBY)
        self.w.notifier.on_push = SimulatedPhone_
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual(d.reason, "APPROVED")
        self.assertEqual(len(self.w.notifier.pushes), 1)

    def test_disable_via_ussd(self):
        self.enable_app()
        self.w.offline.disable("c1", USSD, {"pin": "x"})
        self.assertFalse(self.w.offline.is_active("c1"))

    def test_customer_is_alerted_on_enable_disable_use_and_failure(self):
        self.enable_app()
        self.w.auth.authorize(self.w.txn())
        self.code(lambda: self.w.offline.enable("c1", APP, creds(self.w, "ENABLE", key=b"bad")))
        self.disable_app()
        text = " | ".join(t for _, t in self.w.notifier.alerts)
        for needle in ("mode ON", "used in offline mode", "Failed attempt", "mode OFF"):
            self.assertIn(needle, text)

    def test_audit_trail(self):
        self.enable_app()
        self.w.auth.authorize(self.w.txn())
        self.disable_app()
        ev = self.events()
        for e in ("OFFLINE_MODE_ENABLED", "OFFLINE_APPROVED", "OFFLINE_MODE_DISABLED"):
            self.assertIn(e, ev)


class OfflineLimits(OfflineBase):
    def test_per_transaction_cap(self):
        self.enable_app(per_txn_cap=50_000)
        d = self.w.auth.authorize(self.w.txn(amount=50_001))
        self.assertEqual((d.approved, d.reason), (False, "OFFLINE_CAP_EXCEEDED"))
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.ACTIVE)
        self.assertTrue(self.w.auth.authorize(self.w.txn(amount=50_000)).approved)

    def test_rolling_total_cap(self):
        self.enable_app(per_txn_cap=1_000_000, total_cap=1_500_000)
        self.assertTrue(self.w.auth.authorize(self.w.txn(amount=1_000_000)).approved)
        self.assertFalse(self.w.auth.authorize(self.w.txn(amount=600_000)).approved)
        self.assertTrue(self.w.auth.authorize(self.w.txn(amount=500_000)).approved)  # exactly at cap

    def test_reenabling_does_not_reset_the_cap(self):
        self.enable_app(total_cap=1_000_000)
        self.assertTrue(self.w.auth.authorize(self.w.txn(amount=1_000_000)).approved)
        self.disable_app()
        self.enable_app(total_cap=1_000_000)
        self.assertFalse(self.w.auth.authorize(self.w.txn(amount=1)).approved)

    def test_cap_window_rolls_after_24h(self):
        w = World(clock=FakeClock())
        w.offline.enable("c1", APP, creds(w, "ENABLE"), ttl_s=72 * 3600, total_cap=1_000_000)
        self.assertTrue(w.auth.authorize(w.txn(amount=1_000_000)).approved)
        w.clock.advance(24 * 3600 + 1)
        self.assertTrue(w.auth.authorize(w.txn(amount=1_000_000)).approved)

    def test_online_purchases_blocked(self):
        self.enable_app()
        d = self.w.auth.authorize(self.w.txn(channel=Channel.ECOM))
        self.assertEqual((d.approved, d.reason), (False, "OFFLINE_ECOM_BLOCKED"))

    def test_new_country_blocked(self):
        self.enable_app()
        d = self.w.auth.authorize(self.w.txn(merchant_country="FR"))
        self.assertEqual((d.approved, d.reason), (False, "OFFLINE_NEW_COUNTRY"))

    def test_impossible_travel_still_freezes(self):
        self.enable_app()
        first = self.w.txn(created_at=self.w.clock.now() - timedelta(minutes=10))
        self.assertTrue(self.w.auth.authorize(first).approved)
        second = self.w.txn(merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1])
        d = self.w.auth.authorize(second)
        self.assertEqual((d.approved, d.reason), (False, "IMPOSSIBLE_TRAVEL"))
        self.assertEqual(self.w.store.cards["c1"].status, CardStatus.FROZEN)

    def test_frozen_card_stays_declined_in_offline_mode(self):
        self.enable_app()
        self.w.store.freeze_card("c1")
        d = self.w.auth.authorize(self.w.txn())
        self.assertEqual(d.reason, "CARD_NOT_ACTIVE")

    def test_mode_expires_on_its_own(self):
        w = World(clock=FakeClock())
        w.offline.enable("c1", APP, creds(w, "ENABLE"), ttl_s=3600)
        self.assertEqual(w.auth.authorize(w.txn()).reason, "APPROVED_OFFLINE")
        w.clock.advance(3601)
        w.notifier.on_push = SimulatedPhone(w.challenges, w.device, w.clock, location=NEARBY)
        d = w.auth.authorize(w.txn())
        self.assertEqual(d.reason, "APPROVED")             # normal flow again
        self.assertFalse(w.offline.is_active("c1"))
        self.assertIn("ended", " ".join(t for _, t in w.notifier.alerts))

    def test_duplicate_network_request_spends_only_once(self):
        self.enable_app(total_cap=100_000, per_txn_cap=100_000)
        txn = self.w.txn(amount=100_000)
        self.assertTrue(self.w.auth.authorize(txn).approved)
        self.assertTrue(self.w.auth.authorize(txn).approved)   # same idempotency key
        self.assertEqual(len(self.w.store.offline_spend["c1"]), 1)


if __name__ == "__main__":
    unittest.main()
