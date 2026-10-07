"""USSD session layer: turns what the telco aggregator sends into screens.

Protocol (aggregator style): every user keystroke produces one request with
  session_id  unique per USSD session
  msisdn      the caller's number, supplied by the network (never typed)
  text        everything entered so far, joined by '*' ('' on first dial)
and we answer 'CON <screen>' (keep session open) or 'END <screen>' (close).

Menu (digits only, <=160 chars per screen):
  ''            list of pending transactions (newest first)
  N             details of item N: 1 Approve / 2 Decline / 3 Not me
  N*1           ask for the 6-digit code from the SMS
  N*1*code      ask for the USSD password
  N*1*code*pw   verify everything and approve
  N*2           decline        N*3   block the card

Security properties:
  * list position is pinned to the session when the list is shown, so a new
    transaction arriving mid-session can never shift what "1" means;
  * the session is bound to the number that opened it;
  * merchant text is untrusted: sanitised and truncated, so it cannot inject
    fake menu lines or instructions;
  * every credential failure shows the SAME generic message;
  * `text` holds the password and code: it is never logged, and it is not
    passed on to the location hook;
  * any unexpected error ends the session (fails closed).
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from .clock import Clock
from .models import ChallengeStatus, PhoneFix
from .money import money
from .ussd import UssdError, UssdService

log = logging.getLogger("cardguard.ussd_gateway")

MAX_SCREEN = 160
MAX_LIST = 5

NO_PENDING = "No card transactions are waiting."
GENERIC_FAIL = "Could not verify your details. Contact your bank if this continues."
CLOSED = "This request is no longer open."
UNAVAILABLE = "Service unavailable. Try again later."
SESSION_GONE = "Session expired. Dial again."
INVALID = "Invalid input. Dial again."

_MSISDN_RE = re.compile(r"^\+?\d{8,15}$")


def normalize_msisdn(raw: str) -> Optional[str]:
    raw = (raw or "").strip().replace(" ", "")
    if not _MSISDN_RE.match(raw):
        return None
    return raw if raw.startswith("+") else "+" + raw


def clean(text: str, limit: int) -> str:
    """Untrusted network text -> safe screen text (no newlines, no symbols)."""
    text = re.sub(r"[^A-Za-z0-9 .,&'\-]", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _con(body: str) -> str:
    return "CON " + body


def _end(body: str) -> str:
    return "END " + body


@dataclass(frozen=True)
class SessionState:
    msisdn: str
    challenge_ids: tuple      # what 1..N meant when the list was shown
    created_at: datetime


class SessionStore:
    """In-memory. For several gateway instances use Redis with the same TTL."""

    def __init__(self, clock: Clock, ttl_s: float = 180.0):
        self.clock = clock
        self.ttl = timedelta(seconds=ttl_s)
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionState] = {}

    def put(self, session_id: str, state: SessionState) -> None:
        now = self.clock.now()
        with self._lock:
            self._sessions = {k: v for k, v in self._sessions.items() if now - v.created_at < self.ttl}
            self._sessions[session_id] = state

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is not None and self.clock.now() - state.created_at >= self.ttl:
                del self._sessions[session_id]
                return None
            return state

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


class UssdGateway:
    def __init__(self, ussd: UssdService, clock: Clock, session_ttl_s: float = 180.0,
                 cell_locator: Optional[Callable[[dict], Optional[tuple]]] = None):
        """`cell_locator(params) -> (lat, lon, accuracy_m) | None` is an optional
        hook for telco cell-site location. It receives only non-secret gateway
        parameters (never `text`)."""
        self.ussd = ussd
        self.clock = clock
        self.sessions = SessionStore(clock, session_ttl_s)
        self.cell_locator = cell_locator

    # ------------------------------------------------------------------
    def handle(self, session_id: str, msisdn: str, text: str, params: Optional[dict] = None) -> str:
        try:
            return self._handle(session_id, msisdn, text or "", params or {})
        except Exception:
            log.exception("ussd gateway error; closing session")
            self.sessions.delete(session_id)
            return _end(UNAVAILABLE)

    def _handle(self, session_id: str, raw_msisdn: str, text: str, params: dict) -> str:
        msisdn = normalize_msisdn(raw_msisdn)
        if msisdn is None or not session_id:
            return _end(GENERIC_FAIL)
        parts = [] if text == "" else text.split("*")
        if len(parts) > 5 or any(not (p.isascii() and p.isdigit()) for p in parts):
            self.sessions.delete(session_id)
            return _end(INVALID)
        # Never log `text` (it carries the code and password), only the step.
        log.info("ussd session=%s msisdn=***%s step=%d",
                 hashlib.sha256(session_id.encode()).hexdigest()[:8], msisdn[-4:], len(parts))

        if not parts:
            return self._start(session_id, msisdn)

        state = self.sessions.get(session_id)
        if state is None:
            return _end(SESSION_GONE)
        if state.msisdn != msisdn:
            log.warning("ussd session used by a different number")
            return _end(GENERIC_FAIL)          # do not delete: the real owner may be mid-session

        choice = int(parts[0])
        if not 1 <= choice <= len(state.challenge_ids):
            return self._finish(session_id, INVALID)
        cid = state.challenge_ids[choice - 1]
        item = self._find(msisdn, cid)
        if item is None:
            return self._finish(session_id, CLOSED)

        if len(parts) == 1:
            return self._detail(item)

        action = parts[1]
        fix = self._fix(params)
        if len(parts) == 2:
            if action == "1":
                return _con("Enter the 6-digit code from the SMS:")
            if action == "2":
                return self._run(session_id, lambda: self.ussd.deny(msisdn, cid, fix), "Declined.")
            if action == "3":
                return self._run(session_id, lambda: self.ussd.report_not_me(msisdn, cid, fix),
                                 "Your card is being blocked. Call your bank.")
            return self._finish(session_id, INVALID)

        if action != "1":
            return self._finish(session_id, INVALID)
        otp = parts[2]
        if len(otp) != 6:
            return self._finish(session_id, INVALID)
        if len(parts) == 3:
            return _con("Enter your USSD password:")

        password = parts[3]
        if not 6 <= len(password) <= 12:
            return self._finish(session_id, GENERIC_FAIL)   # same text as a wrong password
        try:
            ch = self.ussd.approve(msisdn, cid, otp, password, fix)
        except UssdError as e:
            return self._finish(session_id, self._error_text(e.code))
        done = "Approved. Retry your purchase now." if ch.status is ChallengeStatus.LATE_APPROVED else "Approved."
        return self._finish(session_id, done)

    # ------------------------------------------------------------------
    def _start(self, session_id: str, msisdn: str) -> str:
        try:
            items = list(reversed(self.ussd.pending(msisdn)))     # newest first
        except UssdError:
            return _end(GENERIC_FAIL)
        if not items:
            return _end(NO_PENDING)
        lines, shown = ["CON Pending:"], []
        for item in items[:MAX_LIST]:
            line = f"{len(shown) + 1}. {money(item.amount, item.currency)} {clean(item.merchant, 12)}"
            if len("\n".join(lines + [line])) > MAX_SCREEN:
                break
            lines.append(line)
            shown.append(item.challenge_id)
        self.sessions.put(session_id, SessionState(msisdn, tuple(shown), self.clock.now()))
        return "\n".join(lines)

    def _detail(self, item) -> str:
        where = f"{clean(item.merchant, 20)}, {clean(item.city, 12)} {clean(item.country, 3)}"
        note = ["Terminal timed out. Retry after approving."] if item.expired else []
        return _con("\n".join([money(item.amount, item.currency), where, *note,
                               "1 Approve", "2 Decline", "3 Not me"]))

    def _find(self, msisdn: str, challenge_id: str):
        try:
            return next((i for i in self.ussd.pending(msisdn) if i.challenge_id == challenge_id), None)
        except UssdError:
            return None

    def _run(self, session_id: str, action, ok_text: str) -> str:
        try:
            action()
        except UssdError as e:
            return self._finish(session_id, self._error_text(e.code))
        return self._finish(session_id, ok_text)

    def _finish(self, session_id: str, message: str) -> str:
        self.sessions.delete(session_id)
        return _end(message)

    @staticmethod
    def _error_text(code: str) -> str:
        # Wrong password, wrong code, lockout, SIM swap, no password, cooling-off
        # and unknown numbers all look identical on purpose.
        if code in ("EXPIRED", "NOT_PENDING"):
            return CLOSED
        return GENERIC_FAIL

    def _fix(self, params: dict) -> Optional[PhoneFix]:
        if self.cell_locator is None:
            return None
        loc = self.cell_locator(params)
        if loc is None:
            return None
        return PhoneFix(loc[0], loc[1], loc[2], self.clock.now(), True)
