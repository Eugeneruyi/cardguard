"""Pure risk functions: no I/O, easy to table-test.

Two stages:
  pre_authorization_risk: needs only the transaction and history (runs before
                          the customer is bothered).
  location_risk:          needs the phone fix returned with the approval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable, Optional

from .geo import haversine_km
from .models import Channel, PhoneFix, Transaction


class Level(str, Enum):
    LOW = "LOW"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"


class Action(str, Enum):
    PROCEED = "PROCEED"
    DECLINE = "DECLINE"
    DECLINE_AND_FREEZE = "DECLINE_AND_FREEZE"


@dataclass(frozen=True)
class RiskConfig:
    # distance between phone and merchant (card-present only)
    near_km: float = 2.0
    far_km: float = 50.0
    # amounts in minor units
    high_amount: int = 5_000_000
    unverified_amount_cap: int = 2_000_000
    max_fix_age_s: float = 300.0
    # impossible travel
    max_speed_kmh: float = 900.0
    min_travel_km: float = 50.0
    # challenge handling
    max_attempts: int = 3
    failure_window_s: float = 600.0
    failure_limit: int = 3
    push_retries: int = 1
    # offline (emergency) mode: bank-level ceilings the customer cannot exceed
    offline_default_ttl_s: float = 24 * 3600.0
    offline_max_ttl_s: float = 72 * 3600.0
    offline_max_per_txn: int = 1_000_000
    offline_max_total_24h: int = 3_000_000
    offline_auth_failure_limit: int = 3
    offline_lockout_s: float = 3600.0
    # USSD approval (phone off)
    ussd_escalation_after_s: float = 10.0     # no app answer by then -> SMS prompt
    ussd_retry_window_s: float = 600.0        # OTP and retry grant stay valid this long
    ussd_password_cooldown_s: float = 24 * 3600.0
    ussd_failure_limit: int = 3
    ussd_lockout_s: float = 3600.0
    ussd_sim_swap_window_s: float = 72 * 3600.0
    # how long the authorization is held, per channel (seconds)
    hold_window_s: dict = field(
        default_factory=lambda: {Channel.POS: 45.0, Channel.ATM: 60.0, Channel.ECOM: 180.0}
    )


@dataclass(frozen=True)
class RiskResult:
    level: Level
    action: Action
    reasons: tuple = ()
    distance_km: Optional[float] = None


def pre_authorization_risk(
    txn: Transaction,
    prior_card_present: Optional[Transaction],
    known_countries: Iterable[str],
    cfg: RiskConfig,
) -> RiskResult:
    if txn.channel.card_present and prior_card_present is not None:
        d = haversine_km(
            prior_card_present.merchant_lat, prior_card_present.merchant_lon,
            txn.merchant_lat, txn.merchant_lon,
        )
        if d >= cfg.min_travel_km:
            elapsed = (txn.created_at - prior_card_present.created_at).total_seconds()
            hours = max(elapsed / 3600.0, 1 / 60)  # floor at one minute
            if d / hours > cfg.max_speed_kmh:
                return RiskResult(Level.HIGH, Action.DECLINE_AND_FREEZE, ("IMPOSSIBLE_TRAVEL",), d)

    known = set(known_countries)
    if known and txn.merchant_country not in known:
        return RiskResult(Level.ELEVATED, Action.PROCEED, ("NEW_COUNTRY",))
    return RiskResult(Level.LOW, Action.PROCEED)


def location_risk(
    txn: Transaction,
    fix: Optional[PhoneFix],
    now: datetime,
    cfg: RiskConfig,
) -> RiskResult:
    if not txn.channel.card_present:
        # Card-not-present: the phone-to-merchant distance means nothing.
        return RiskResult(Level.LOW, Action.PROCEED, ("CNP_NO_DISTANCE_CHECK",))

    problems = []
    if fix is None:
        problems.append("NO_FIX")
    else:
        if (now - fix.taken_at).total_seconds() > cfg.max_fix_age_s:
            problems.append("STALE_FIX")
        if not fix.attested:
            problems.append("NOT_ATTESTED")
    if problems:
        action = Action.DECLINE if txn.amount > cfg.unverified_amount_cap else Action.PROCEED
        return RiskResult(Level.ELEVATED, action, ("LOCATION_UNVERIFIED", *problems))

    d = haversine_km(fix.lat, fix.lon, txn.merchant_lat, txn.merchant_lon)
    if d <= cfg.near_km:
        return RiskResult(Level.LOW, Action.PROCEED, (), d)
    if d <= cfg.far_km:
        return RiskResult(Level.ELEVATED, Action.PROCEED, ("PHONE_NOT_NEAR",), d)
    action = Action.DECLINE if txn.amount > cfg.high_amount else Action.PROCEED
    return RiskResult(Level.HIGH, action, ("PHONE_FAR",), d)
