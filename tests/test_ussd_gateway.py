import unittest

from cardguard.clock import FakeClock
from cardguard.models import CardStatus, ChallengeStatus, Customer
from cardguard.ussd_gateway import (CLOSED, GENERIC_FAIL, INVALID, NO_PENDING,
                                    SESSION_GONE, UNAVAILABLE, UssdGateway,
                                    clean, normalize_msisdn)
from tests.helpers import MSISDN, NEARBY, World
from tests.test_ussd import GOOD_PW, enrol

PW = GOOD_PW


def build(enrolled=True, **cfg):
    w = World(clock=FakeClock(), **cfg)
    if enrolled:
        enrol(w)
    return w, UssdGateway(w.ussd, w.clock)


def make_pending(w, **txn_kw):
    ch, _ = w.challenges.create(w.txn(**txn_kw), "d1", ttl_s=60)
    return ch, w.challenges.issue_ussd_code(ch.id, 600)


def flow(gw, sid, otp, pw=PW, choice="1", msisdn=MSISDN, params=None):
    """Dial and type everything; returns every screen shown."""
    steps = ["", choice, f"{choice}*1", f"{choice}*1*{otp}", f"{choice}*1*{otp}*{pw}"]
    return [gw.handle(sid, msisdn, t, params) for t in steps]


class Screens(unittest.TestCase):
    def test_unknown_number_gets_generic_end(self):
        w, gw = build()
        self.assertEqual(gw.handle("s", "+15550199999", ""), "END " + GENERIC_FAIL)

    def test_number_without_plus_is_normalised(self):
        self.assertEqual(normalize_msisdn("15550100001"), "+15550100001")
        self.assertEqual(normalize_msisdn(" +1 555 010 0001 "), "+15550100001")
        self.assertIsNone(normalize_msisdn("abc"))
        self.assertIsNone(normalize_msisdn("123"))
        w, gw = build()
        make_pending(w)
        self.assertTrue(gw.handle("s", "15550100001", "").startswith("CON Pending:"))

    def test_nothing_pending(self):
        w, gw = build()
        self.assertEqual(gw.handle("s", MSISDN, ""), "END " + NO_PENDING)

    def test_list_is_newest_first_numbered_and_human_amounts(self):
        w, gw = build()
        make_pending(w, merchant_name="First Shop", amount=10_000)
        make_pending(w, merchant_name="Second Shop", amount=2_550)
        r = gw.handle("s", MSISDN, "")
        lines = r.split("\n")
        self.assertEqual(lines[0], "CON Pending:")
        self.assertTrue(lines[1].startswith("1. 25.50 USD Second Shop"))
        self.assertTrue(lines[2].startswith("2. 100.00 USD First Shop"))

    def test_detail_screen(self):
        w, gw = build()
        make_pending(w, merchant_name="Corner Shop")
        gw.handle("s", MSISDN, "")
        r = gw.handle("s", MSISDN, "1")
        self.assertEqual(r, "CON 100.00 USD\nCorner Shop, London GB\n1 Approve\n2 Decline\n3 Not me")

    def test_merchant_text_cannot_inject_menu_lines(self):
        w, gw = build()
        make_pending(w, merchant_name="Shop\n1 Approve\nEnter your PIN at 5555*#")
        gw.handle("s", MSISDN, "")
        r = gw.handle("s", MSISDN, "1")
        self.assertEqual(r.count("\n"), 4)                  # exactly our own lines
        # the injected text stays on the merchant line; only ONE real menu line exists
        self.assertEqual(sum(1 for l in r.split("\n") if l.startswith("1 Approve")), 1)
        self.assertEqual(r.split("\n")[1][:4], "Shop")
        self.assertNotIn("*", r)
        self.assertNotIn("#", r)
        self.assertEqual(clean("a\tb\n c", 20), "a b c")

    def test_every_screen_fits_160_chars(self):
        w, gw = build()
        for i in range(8):
            make_pending(w, merchant_name="An Extremely Long Merchant Name Ltd " * 3, amount=123_456_789)
        screens = [gw.handle("s", MSISDN, "")]
        self.assertLessEqual(len(screens[0].split("\n")) - 1, 5)
        screens += [gw.handle("s", MSISDN, "1"), gw.handle("s", MSISDN, "1*1")]
        w.clock.advance(61)                                 # also the "retry" variant
        gw.handle("t", MSISDN, "")
        screens.append(gw.handle("t", MSISDN, "1"))
        for r in screens:
            self.assertLessEqual(len(r), 160, r)

    def test_expired_item_says_retry(self):
        w, gw = build()
        make_pending(w)
        w.clock.advance(61)
        gw.handle("s", MSISDN, "")
        self.assertIn("Retry after approving", gw.handle("s", MSISDN, "1"))


class Approve(unittest.TestCase):
    def test_full_flow_approves(self):
        w, gw = build()
        ch, otp = make_pending(w)
        screens = flow(gw, "s", otp)
        self.assertTrue(screens[0].startswith("CON Pending:"))
        self.assertTrue(screens[1].startswith("CON 100.00 USD"))
        self.assertEqual(screens[2], "CON Enter the 6-digit code from the SMS:")
        self.assertEqual(screens[3], "CON Enter your USSD password:")
        self.assertEqual(screens[4], "END Approved.")
        self.assertEqual(w.store.challenges[ch.id].status, ChallengeStatus.APPROVED)

    def test_late_approval_tells_customer_to_retry(self):
        w, gw = build()
        ch, otp = make_pending(w)
        w.clock.advance(61)
        self.assertEqual(flow(gw, "s", otp)[-1], "END Approved. Retry your purchase now.")
        self.assertIn("c1", w.store.retry_grants)

    def test_all_credential_failures_look_identical(self):
        results = {}
        for name in ("wrong_password", "wrong_otp", "sim_swap", "no_password", "cooldown", "locked"):
            w, gw = build(enrolled=name != "no_password",
                          **({"ussd_password_cooldown_s": 86400} if name == "cooldown" else {}))
            ch, otp = make_pending(w)
            pw, code = PW, otp
            if name == "wrong_password":
                pw = "582913"
            if name == "wrong_otp":
                code = f"{(int(otp) + 1) % 1_000_000:06d}"
            if name == "sim_swap":
                w.sim.swapped = True
            if name == "locked":
                for _ in range(3):
                    flow(gw, "x", otp, pw="582913")
            results[name] = flow(gw, "s", code, pw)[-1]
        self.assertEqual(set(results.values()), {"END " + GENERIC_FAIL}, results)

    def test_short_password_gets_same_generic_text_without_hashing(self):
        w, gw = build()
        ch, otp = make_pending(w)
        self.assertEqual(flow(gw, "s", otp, pw="123")[-1], "END " + GENERIC_FAIL)

    def test_replayed_final_request_does_nothing(self):
        w, gw = build()
        ch, otp = make_pending(w)
        flow(gw, "s", otp)
        again = gw.handle("s", MSISDN, f"1*1*{otp}*{PW}")
        self.assertEqual(again, "END " + SESSION_GONE)
        self.assertEqual(w.store.challenges[ch.id].status, ChallengeStatus.APPROVED)

    def test_telco_cell_location_reaches_the_challenge(self):
        w = World(clock=FakeClock())
        enrol(w)
        gw = UssdGateway(w.ussd, w.clock,
                         cell_locator=lambda p: (NEARBY[0], NEARBY[1], 1500.0) if p.get("cellId") else None)
        ch, otp = make_pending(w)
        flow(gw, "s", otp, params={"cellId": "77"})
        fix = w.store.challenges[ch.id].phone_fix
        self.assertEqual((fix.lat, fix.lon, fix.attested), (NEARBY[0], NEARBY[1], True))

    def test_locator_never_sees_the_secret_text(self):
        w = World(clock=FakeClock())
        enrol(w)
        seen = []
        gw = UssdGateway(w.ussd, w.clock, cell_locator=lambda p: seen.append(dict(p)))
        ch, otp = make_pending(w)
        flow(gw, "s", otp, params={"cellId": "77"})
        self.assertTrue(seen)
        self.assertNotIn("text", seen[0])


class DeclineAndNotMe(unittest.TestCase):
    def test_decline(self):
        w, gw = build()
        ch, _ = make_pending(w)
        gw.handle("s", MSISDN, "")
        self.assertEqual(gw.handle("s", MSISDN, "1*2"), "END Declined.")
        self.assertEqual(w.store.challenges[ch.id].status, ChallengeStatus.DENIED)

    def test_not_me_live(self):
        w, gw = build()
        ch, _ = make_pending(w)
        gw.handle("s", MSISDN, "")
        self.assertIn("blocked", gw.handle("s", MSISDN, "1*3"))
        self.assertEqual(w.store.challenges[ch.id].status, ChallengeStatus.NOT_ME)

    def test_not_me_after_timeout_still_blocks_card(self):
        w, gw = build()
        ch, otp = make_pending(w)
        w.clock.advance(61)
        gw.handle("s", MSISDN, "")
        self.assertIn("blocked", gw.handle("s", MSISDN, "1*3"))
        self.assertEqual(w.store.cards["c1"].status, CardStatus.FROZEN)
        self.assertEqual(w.store.fraud_cases[0].reason, "NOT_ME_AFTER_TIMEOUT")

    def test_not_me_after_timeout_revokes_a_pending_retry_grant(self):
        w, gw = build()
        ch, otp = make_pending(w)
        w.clock.advance(61)
        flow(gw, "s", otp)
        self.assertIn("c1", w.store.retry_grants)
        gw.handle("t", MSISDN, "")             # nothing pending now (late-approved)
        ch2, _ = make_pending(w)
        w.clock.advance(61)
        gw.handle("u", MSISDN, "")
        gw.handle("u", MSISDN, "1*3")
        self.assertNotIn("c1", w.store.retry_grants)

    def test_decline_after_timeout_is_closed(self):
        w, gw = build()
        make_pending(w)
        w.clock.advance(61)
        gw.handle("s", MSISDN, "")
        self.assertEqual(gw.handle("s", MSISDN, "1*2"), "END " + CLOSED)


class SessionSafety(unittest.TestCase):
    def test_list_positions_are_pinned_to_the_session(self):
        w, gw = build()
        ch1, otp1 = make_pending(w, merchant_name="Coffee Stand")
        gw.handle("s", MSISDN, "")                                 # customer sees Coffee as #1
        ch2, otp2 = make_pending(w, merchant_name="Fraud Store")   # newer: would be #1 on a fresh list
        detail = gw.handle("s", MSISDN, "1")
        self.assertIn("Coffee Stand", detail)
        self.assertNotIn("Fraud", detail)
        gw.handle("s", MSISDN, "1*1")
        gw.handle("s", MSISDN, f"1*1*{otp1}")
        self.assertEqual(gw.handle("s", MSISDN, f"1*1*{otp1}*{PW}"), "END Approved.")
        self.assertEqual(w.store.challenges[ch1.id].status, ChallengeStatus.APPROVED)
        self.assertEqual(w.store.challenges[ch2.id].status, ChallengeStatus.PENDING)

    def test_other_number_cannot_use_my_session(self):
        w, gw = build()
        w.store.add_customer(Customer("u2", "+15550100002"))
        ch, otp = make_pending(w)
        gw.handle("s", MSISDN, "")
        with self.assertLogs("cardguard.ussd_gateway", level="WARNING"):
            self.assertEqual(gw.handle("s", "+15550100002", "1"), "END " + GENERIC_FAIL)
            self.assertEqual(gw.handle("s", "+15550100002", f"1*1*{otp}*{PW}"), "END " + GENERIC_FAIL)
        self.assertEqual(w.store.challenges[ch.id].status, ChallengeStatus.PENDING)
        self.assertTrue(gw.handle("s", MSISDN, "1").startswith("CON 100.00"))   # owner unaffected

    def test_unknown_session_and_expired_session(self):
        w, gw = build()
        make_pending(w)
        self.assertEqual(gw.handle("nope", MSISDN, "1"), "END " + SESSION_GONE)
        gw.handle("s", MSISDN, "")
        w.clock.advance(181)
        self.assertEqual(gw.handle("s", MSISDN, "1"), "END " + SESSION_GONE)

    def test_malformed_input_never_crashes(self):
        for text in ("abc", "1*", "*1", "0", "9", "1*7", "1*1*12", "1*1*abcdef", "1*2*3*4*5*6",
                     "1*1*123456*", "-1", "1.5", "1*1*" + "9" * 50, "\n", "１"):
            with self.subTest(text=text):
                w, gw = build()
                make_pending(w)
                gw.handle("s", MSISDN, "")
                r = gw.handle("s", MSISDN, text)
                self.assertTrue(r.startswith("END "), r)

    def test_missing_session_id_or_bad_number(self):
        w, gw = build()
        self.assertEqual(gw.handle("", MSISDN, ""), "END " + GENERIC_FAIL)
        self.assertEqual(gw.handle("s", "not-a-number", ""), "END " + GENERIC_FAIL)

    def test_service_failure_fails_closed(self):
        w, gw = build()
        make_pending(w)

        def boom(_):
            raise RuntimeError("database down")
        w.ussd.pending = boom
        with self.assertLogs("cardguard.ussd_gateway", level="ERROR"):
            self.assertEqual(gw.handle("s", MSISDN, ""), "END " + UNAVAILABLE)

    def test_password_code_and_number_are_never_logged(self):
        w, gw = build()
        ch, otp = make_pending(w)
        with self.assertLogs("cardguard.ussd_gateway", level="INFO") as logs:
            flow(gw, "s", otp)
        text = "\n".join(logs.output)
        self.assertNotIn(PW, text)
        self.assertNotIn(otp, text)
        self.assertNotIn(MSISDN, text)
        self.assertNotIn(MSISDN[-4:] + "*", text)
        self.assertIn("step=4", text)


if __name__ == "__main__":
    unittest.main()
