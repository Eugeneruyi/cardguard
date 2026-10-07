import unittest
from datetime import timedelta

from cardguard.clock import Clock
from cardguard.geo import haversine_km
from cardguard.models import Channel, PhoneFix
from cardguard.risk import (Action, Level, RiskConfig, location_risk,
                            pre_authorization_risk)
from tests.helpers import LONDON, MANCHESTER, NEARBY, make_txn

CFG = RiskConfig()
CLOCK = Clock()


def fix(loc, age_s=0, attested=True):
    return PhoneFix(loc[0], loc[1], 20.0, CLOCK.now() - timedelta(seconds=age_s), attested)


class Haversine(unittest.TestCase):
    def test_zero_distance(self):
        self.assertAlmostEqual(haversine_km(*LONDON, *LONDON), 0.0)

    def test_london_manchester(self):
        self.assertTrue(255 < haversine_km(*LONDON, *MANCHESTER) < 270)

    def test_symmetric(self):
        self.assertAlmostEqual(haversine_km(*LONDON, *MANCHESTER),
                               haversine_km(*MANCHESTER, *LONDON))


class LocationRisk(unittest.TestCase):
    def risk(self, f, **txn_kw):
        return location_risk(make_txn(CLOCK, **txn_kw), f, CLOCK.now(), CFG)

    def test_phone_near_is_low(self):
        r = self.risk(fix(NEARBY))
        self.assertEqual((r.level, r.action), (Level.LOW, Action.PROCEED))

    def test_phone_mid_distance_is_elevated(self):
        # roughly 20 km north of the merchant
        r = self.risk(fix((51.69, -0.1278)))
        self.assertEqual((r.level, r.action), (Level.ELEVATED, Action.PROCEED))
        self.assertIn("PHONE_NOT_NEAR", r.reasons)

    def test_phone_far_low_amount_proceeds_with_warning(self):
        r = self.risk(fix(MANCHESTER))
        self.assertEqual((r.level, r.action), (Level.HIGH, Action.PROCEED))

    def test_phone_far_high_amount_declines(self):
        r = self.risk(fix(MANCHESTER), amount=CFG.high_amount + 1)
        self.assertEqual(r.action, Action.DECLINE)

    def test_no_fix_small_amount_proceeds_unverified(self):
        r = self.risk(None)
        self.assertEqual((r.level, r.action), (Level.ELEVATED, Action.PROCEED))
        self.assertIn("NO_FIX", r.reasons)

    def test_no_fix_above_cap_declines(self):
        r = self.risk(None, amount=CFG.unverified_amount_cap + 1)
        self.assertEqual(r.action, Action.DECLINE)

    def test_stale_fix_treated_as_unverified(self):
        r = self.risk(fix(NEARBY, age_s=CFG.max_fix_age_s + 5))
        self.assertIn("STALE_FIX", r.reasons)

    def test_unattested_fix_treated_as_unverified(self):
        r = self.risk(fix(NEARBY, attested=False))
        self.assertIn("NOT_ATTESTED", r.reasons)

    def test_ecom_skips_distance(self):
        r = self.risk(fix(MANCHESTER), channel=Channel.ECOM)
        self.assertEqual((r.level, r.action), (Level.LOW, Action.PROCEED))

    def test_boundaries(self):
        # exactly at the near threshold is still LOW
        cfg = RiskConfig(near_km=0.0)
        t = make_txn(CLOCK)
        r = location_risk(t, fix(LONDON), CLOCK.now(), cfg)
        self.assertEqual(r.level, Level.LOW)


class PreAuthRisk(unittest.TestCase):
    def test_impossible_travel_declines_and_freezes(self):
        prior = make_txn(CLOCK, created_at=CLOCK.now() - timedelta(minutes=10))
        now = make_txn(CLOCK, merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1])
        r = pre_authorization_risk(now, prior, {"GB"}, CFG)
        self.assertEqual(r.action, Action.DECLINE_AND_FREEZE)
        self.assertEqual(r.reasons, ("IMPOSSIBLE_TRAVEL",))

    def test_plausible_travel_ok(self):
        prior = make_txn(CLOCK, created_at=CLOCK.now() - timedelta(hours=8))
        now = make_txn(CLOCK, merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1])
        r = pre_authorization_risk(now, prior, {"GB"}, CFG)
        self.assertEqual(r.action, Action.PROCEED)

    def test_short_hop_quickly_is_not_travel(self):
        prior = make_txn(CLOCK, created_at=CLOCK.now() - timedelta(minutes=1))
        now = make_txn(CLOCK, merchant_lat=NEARBY[0], merchant_lon=NEARBY[1])
        self.assertEqual(pre_authorization_risk(now, prior, {"GB"}, CFG).action, Action.PROCEED)

    def test_ecom_ignores_travel(self):
        prior = make_txn(CLOCK, created_at=CLOCK.now() - timedelta(minutes=10))
        now = make_txn(CLOCK, channel=Channel.ECOM,
                       merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1])
        self.assertEqual(pre_authorization_risk(now, prior, {"GB"}, CFG).action, Action.PROCEED)

    def test_new_country_is_elevated(self):
        t = make_txn(CLOCK, merchant_country="FR")
        r = pre_authorization_risk(t, None, {"GB"}, CFG)
        self.assertEqual((r.level, r.reasons), (Level.ELEVATED, ("NEW_COUNTRY",)))

    def test_no_history_means_no_country_flag(self):
        t = make_txn(CLOCK, merchant_country="FR")
        self.assertEqual(pre_authorization_risk(t, None, set(), CFG).level, Level.LOW)


if __name__ == "__main__":
    unittest.main()
