import itertools
import re
import time
from datetime import timedelta

from cardguard.auth_service import AuthService
from cardguard.challenge import ChallengeService
from cardguard.clock import Clock
from cardguard.models import Card, Channel, Customer, Device, Transaction
from cardguard.notify import FakeNotifier
from cardguard.offline import FakeVerifier, OfflineModeService
from cardguard.risk import RiskConfig
from cardguard.store import Store
from cardguard.ussd import FakeSimSwapChecker, UssdService

LONDON = (51.5074, -0.1278)
MANCHESTER = (53.4808, -2.2426)   # ~260 km from London
NEARBY = (51.5080, -0.1290)       # a few hundred metres from LONDON
MSISDN = "+15550100001"           # fictional number "registered at account opening"

_counter = itertools.count(1)


def make_txn(clock, **kw):
    n = next(_counter)
    base = dict(
        id=f"t{n}", card_id="c1", amount=10_000, currency="USD",
        merchant_name="Corner Shop", merchant_city="London", merchant_country="GB",
        merchant_lat=LONDON[0], merchant_lon=LONDON[1], mcc="5411",
        terminal_id="T1", channel=Channel.POS, idempotency_key=f"k{n}",
        created_at=clock.now(),
    )
    base.update(kw)
    return Transaction(**base)


class World:
    """Wires the whole system with short hold windows so timeouts are fast."""

    def __init__(self, clock=None, hold=0.3, **cfg_overrides):
        cfg_overrides.setdefault("ussd_escalation_after_s", 0.1)
        cfg_overrides.setdefault("ussd_password_cooldown_s", 0.0)
        self.clock = clock or Clock()
        self.store = Store(self.clock)
        self.cfg = RiskConfig(
            hold_window_s={Channel.POS: hold, Channel.ATM: hold, Channel.ECOM: hold},
            **cfg_overrides,
        )
        self.challenges = ChallengeService(self.store, self.clock, b"server-key",
                                           self.cfg.max_attempts)
        self.device = Device("d1", "u1", "push-token-1", b"device-secret-key")
        self.store.add_card(Card("c1", "u1", "d1"))
        self.store.add_device(self.device)
        self.store.add_known_country("u1", "GB")
        self.store.add_customer(Customer("u1", MSISDN))
        self.notifier = FakeNotifier()
        self.verifier = FakeVerifier()
        self.offline = OfflineModeService(self.store, self.clock, self.cfg,
                                          self.notifier, self.verifier)
        self.sim = FakeSimSwapChecker()
        self.ussd = UssdService(self.store, self.challenges, self.clock, self.cfg,
                                self.notifier, self.verifier, self.sim)
        self.auth = AuthService(self.store, self.challenges, self.notifier,
                                self.cfg, self.clock, offline=self.offline, ussd=self.ussd)

    def txn(self, **kw):
        return make_txn(self.clock, **kw)


def wait_for_sms(world, count=1, timeout=3.0):
    """Block until the system has sent `count` SMS messages; return the latest text."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(world.notifier.sent_sms) >= count:
            return world.notifier.sent_sms[count - 1][1]
        time.sleep(0.01)
    raise AssertionError("no SMS was sent")


def otp_from(sms_text):
    return re.search(r"code (\d{6})", sms_text).group(1)
