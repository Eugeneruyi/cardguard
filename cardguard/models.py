from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class CardStatus(str, Enum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    BLOCKED = "BLOCKED"


class Channel(str, Enum):
    POS = "POS"
    ATM = "ATM"
    ECOM = "ECOM"

    @property
    def card_present(self) -> bool:
        return self in (Channel.POS, Channel.ATM)


class ChallengeStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    NOT_ME = "NOT_ME"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"
    LATE_APPROVED = "LATE_APPROVED"  # USSD approval that arrived after the network timed out


class ResponseDecision(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"
    NOT_ME = "NOT_ME"  # "this is fraud": freezes the card


@dataclass
class Card:
    """No PAN, CVV or PIN is ever stored. `id` is a token issued by your vault."""
    id: str
    customer_id: str
    device_id: str
    status: CardStatus = CardStatus.ACTIVE


@dataclass
class Device:
    """`key` simulates the device-bound signing key. In production use an
    asymmetric key pair held in Secure Enclave / Android Keystore and store
    only the public key here."""
    id: str
    customer_id: str
    push_token: str
    key: bytes
    active: bool = True


@dataclass(frozen=True)
class Transaction:
    id: str
    card_id: str
    amount: int  # minor units
    currency: str
    merchant_name: str
    merchant_city: str
    merchant_country: str
    merchant_lat: float
    merchant_lon: float
    mcc: str
    terminal_id: str
    channel: Channel
    idempotency_key: str
    created_at: datetime


@dataclass(frozen=True)
class PhoneFix:
    lat: float
    lon: float
    accuracy_m: float
    taken_at: datetime
    attested: bool  # server-verified Play Integrity / App Attest result


@dataclass
class Challenge:
    id: str
    txn_id: str
    card_id: str
    device_id: str
    code_hash: bytes
    created_at: datetime
    expires_at: datetime
    status: ChallengeStatus = ChallengeStatus.PENDING
    attempts: int = 0
    phone_fix: Optional[PhoneFix] = None
    # USSD path (phone off): a separate one-time code sent by SMS to the registered number
    ussd_code_hash: Optional[bytes] = None
    ussd_attempts: int = 0
    ussd_valid_until: Optional[datetime] = None


@dataclass
class FraudCase:
    id: str
    card_id: str
    txn_id: str
    reason: str
    evidence: dict
    opened_at: datetime
    status: str = "OPEN"


@dataclass(frozen=True)
class AuthDecision:
    approved: bool
    reason: str
    challenge_id: Optional[str] = None


class EnableChannel(str, Enum):
    """Where an offline-mode request comes from. Only APP needs the phone."""
    APP = "APP"
    USSD = "USSD"
    WEB = "WEB"
    CALL_CENTER = "CALL_CENTER"
    BRANCH = "BRANCH"


@dataclass(frozen=True)
class AppCredentials:
    """Device-signed request from the banking app (see offline.sign_offline_request)."""
    device_id: str
    nonce: str
    signature: bytes


@dataclass(frozen=True)
class OfflineMode:
    card_id: str
    enabled_via: EnableChannel
    enabled_at: datetime
    expires_at: datetime
    per_txn_cap: int
    total_cap: int  # rolling 24h, tracked per card, not per activation


@dataclass(frozen=True)
class Customer:
    id: str
    msisdn: str  # the number registered when the account was opened


@dataclass
class UssdCredential:
    """The customer's self-created USSD password. Only a salted scrypt hash is kept."""
    customer_id: str
    salt: bytes
    password_hash: bytes
    set_at: datetime


@dataclass(frozen=True)
class PendingApproval:
    challenge_id: str
    amount: int
    currency: str
    merchant: str
    city: str
    country: str
    expired: bool          # True: the terminal already timed out; approving authorizes a retry
    valid_until: datetime


@dataclass(frozen=True)
class RetryGrant:
    """Result of approving after the terminal gave up: one retry of the same
    purchase (same card, merchant and country, amount <= max) is allowed."""
    card_id: str
    merchant_name: str
    merchant_country: str
    currency: str
    max_amount: int
    expires_at: datetime
    fix: Optional[PhoneFix]
