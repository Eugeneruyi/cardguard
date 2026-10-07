"""End-to-end demo: python3 demo.py"""
import logging
import threading
from datetime import timedelta

from cardguard.models import AppCredentials, Channel, EnableChannel
from cardguard.models import ResponseDecision as D
from cardguard.simulator import SimulatedPhone
from cardguard.ussd import sign_password_request
from tests.helpers import LONDON, MANCHESTER, MSISDN, NEARBY, World, otp_from, wait_for_sms

logging.basicConfig(level=logging.WARNING)


def run(title, world, txn):
    d = world.auth.authorize(txn)
    status = "APPROVED" if d.approved else "DECLINED"
    print(f"{title:<52} -> {status:<9} {d.reason}")
    return d


def fresh(**kw):
    w = World(hold=0.5)
    return w


# 1. Legitimate purchase, phone is at the shop
w = fresh()
w.notifier.on_push = SimulatedPhone(w.challenges, w.device, w.clock, location=NEARBY)
run("1. Cardholder pays at a shop near their phone", w, w.txn())

# 2. Cloned card used far from the phone; the owner taps "Not me"
w = fresh()
w.notifier.on_push = SimulatedPhone(w.challenges, w.device, w.clock,
                                    decision=D.NOT_ME, location=NEARBY)
run("2. Clone used elsewhere, owner taps 'Not me'", w, w.txn(
    merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1], merchant_city="Manchester"))
print("   card status:", w.store.cards["c1"].status.value,
      "| fraud case:", w.store.fraud_cases[0].reason)
run("   thief retries with the frozen card", w, w.txn())

# 3. Big withdrawal far from the phone, even though the code was entered
w = fresh()
w.notifier.on_push = SimulatedPhone(w.challenges, w.device, w.clock, location=LONDON)
run("3. Large card-present spend 260 km from the phone", w, w.txn(
    amount=6_000_000, merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1]))

# 4. Phone offline: push fails, SMS link sent, authorization expires
w = fresh()
w.notifier.deliver = False
run("4. Phone offline (push fails)", w, w.txn())
print("   push attempts:", len(w.notifier.pushes), "| SMS prompts to registered number:", len(w.notifier.sent_sms))

# 5. Impossible travel
w = fresh()
w.notifier.on_push = SimulatedPhone(w.challenges, w.device, w.clock, location=LONDON)
run("5a. Purchase in city A", w, w.txn(created_at=w.clock.now() - timedelta(minutes=10)))
run("5b. Same card 10 min later, 260 km away", w, w.txn(
    merchant_lat=MANCHESTER[0], merchant_lon=MANCHESTER[1], merchant_city="Manchester"))
print("   card status:", w.store.cards["c1"].status.value)


# 6. Phone dead or faulty: customer switches on offline mode from another channel (USSD)
w = fresh()
w.notifier.deliver = False                     # phone unreachable
run("6a. Phone dead, no offline mode", w, w.txn())
w.offline.enable("c1", EnableChannel.USSD, {"pin": "****"},
                 ttl_s=4 * 3600, per_txn_cap=50_000, total_cap=80_000)
run("6b. Offline mode ON: small purchase", w, w.txn(amount=30_000))
run("6c. Offline mode ON: above per-transaction cap", w, w.txn(amount=60_000))
run("6d. Offline mode ON: online purchase", w, w.txn(channel=Channel.ECOM))
run("6e. Offline mode ON: new country", w, w.txn(merchant_country="FR"))
run("6f. Offline mode ON: pushes the 24h cap over", w, w.txn(amount=50_001))
w.offline.disable("c1", EnableChannel.USSD, {"pin": "****"})
run("6g. Offline mode OFF: approval required again", w, w.txn())
print("   customer alerts sent:", len(w.notifier.alerts))
for _, text in w.notifier.alerts[:3]:
    print("    -", text)


# 7. Phone off: approve by USSD with a self-created password + SMS code
PW = "493817"
def usseded_world(hold):
    w = World(hold=hold, ussd_escalation_after_s=0.05)
    w.notifier.deliver = False                         # phone is off
    sig = sign_password_request(w.device.key, "u1", "setup-1", PW)
    w.ussd.set_password("u1", PW, EnableChannel.APP, AppCredentials("d1", "setup-1", sig))
    return w

w = usseded_world(hold=3.0)
out = {}
t = threading.Thread(target=lambda: out.update(d=w.auth.authorize(w.txn())))
t.start()
sms = wait_for_sms(w)
print("7a. SMS to", w.notifier.sent_sms[0][0], "->", sms[:78] + "...")
cid = w.ussd.pending(MSISDN)[0].challenge_id
w.ussd.approve(MSISDN, cid, otp_from(sms), PW)
t.join()
print(f"{'7a. Phone off, customer approves by USSD in time':<52} -> {'APPROVED' if out['d'].approved else 'DECLINED':<9} {out['d'].reason}")

# 7b. The terminal gave up first; the customer approves afterwards, then retries
w = usseded_world(hold=0.3)
run("7b. Phone off, terminal times out first", w, w.txn())
sms = w.notifier.sent_sms[0][1]
item = w.ussd.pending(MSISDN)[0]
print("   pending prompt still open after timeout:", item.expired)
w.ussd.approve(MSISDN, item.challenge_id, otp_from(sms), PW)
run("7c. Customer retries the same purchase", w, w.txn())
run("7d. Same purchase again (grant was single use)", w, w.txn())

# 7e. SMS and code stolen via SIM swap, but no password / swap detected
w = usseded_world(hold=0.3)
w.sim.swapped = True
t = threading.Thread(target=lambda: w.auth.authorize(w.txn()))
t.start()
sms = wait_for_sms(w)
try:
    w.ussd.approve(MSISDN, w.ussd.pending(MSISDN)[0].challenge_id, otp_from(sms), PW)
except Exception as e:
    print("7e. SIM-swapped attacker holding the SMS ->", e)
t.join()


# 8. The same emergency, but through the real HTTP callback, as the telco aggregator would call it
import http.client
from urllib.parse import urlencode
from cardguard.ussd_gateway import UssdGateway
from cardguard.ussd_http import UssdHttpApp, sign

SECRET = b"aggregator-shared-secret"
w = usseded_world(hold=5.0)
server = UssdHttpApp(UssdGateway(w.ussd, w.clock), SECRET).make_server()
threading.Thread(target=server.serve_forever, daemon=True).start()
port = server.server_address[1]


def aggregator(session, text, phone=MSISDN, secret=SECRET):
    body = urlencode({"sessionId": session, "phoneNumber": phone, "text": text,
                      "serviceCode": "*123#"}).encode()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/ussd", body=body, headers={"X-Signature": sign(secret, body)})
    r = conn.getresponse()
    return r.status, r.read().decode()


out = {}
t = threading.Thread(target=lambda: out.update(d=w.auth.authorize(w.txn(merchant_name="Corner Shop"))))
t.start()
sms = wait_for_sms(w)
otp = otp_from(sms)
print("8. Phone off. Customer dials the USSD code; the aggregator calls our server:")
for typed in ("", "1", "1*1", f"1*1*{otp}", f"1*1*{otp}*{PW}"):
    status, screen = aggregator("sess-1", typed)
    shown = typed.replace(PW, "<password>").replace(otp, "<sms-code>")
    print(f"   input {shown!r:<28} HTTP {status} -> " + screen.replace("\n", " | "))
t.join()
print("   authorization result:", out["d"].reason)
print("   forged request (wrong signature):", aggregator("x", "", secret=b"attacker")[0])
server.shutdown()
