from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

class CardStatus(str, Enum):
    """Represents the status of a card."""

    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    BLOCKED = "BLOCKED"

    class Channel(str, Enum):
        """Represents the channel through which a card is blocked."""

        POS = "POS"
        ATM = "ATM"
        ECOM = "ECOM"

        @property
        def card_present(self) -> bool:
            """Returns True if the channel is card-present, False otherwise."""
            return self in (self.POS, self.ATM)

class ChallengeStatus(str, Enum):
    """Represents the status of a challenge."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    NOT_ME = "NOT_ME"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"

class ResponseDecision(str, Enum):
    """Represents the decision made in response to a challenge."""

    APPROVE = "APPROVE"
    DENY = "DENY"
    NOT_ME = "NOT_ME"  #"this ia a fraud" freezes the card.

@dataclass
class Card:
    """No PAN, CVV or PIN is ever stored.'id is token issued by yuor wallet."""
    id: str
    customer_id: str
    device_id: str
    status: CardStatus = CardStatus.ACTIVE

@dataclass
class Device:
    """'Key' simulates the device-bond signing key. In production use an asymmetric key 
    pair held in a secure Enclave/ Andriod keystore and store only the public key here."""
    
id: str
customer_id: str
push_token: str
key: bytes
active: bool = True

