import http.client
import threading
import unittest
from urllib.parse import urlencode

from cardguard.ussd_gateway import GENERIC_FAIL, NO_PENDING, UssdGateway
from cardguard.ussd_http import UssdHttpApp, sign
from tests.helpers import MSISDN, World
from tests.test_ussd import GOOD_PW, enrol

SECRET = b"aggregator-shared-secret"


class HttpBase(unittest.TestCase):
    def setUp(self):
        self.w = World()
        enrol(self.w)
        self.gw = UssdGateway(self.w.ussd, self.w.clock)
        self.start()

    def start(self, **kw):
        self.app = UssdHttpApp(self.gw, SECRET, **kw)
        self.server = self.app.make_server()
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, fields=None, body=None, signature=None, path="/ussd", headers=None, method="POST"):
        raw = body if body is not None else urlencode(fields or {}).encode()
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        hdrs["X-Signature"] = signature if signature is not None else sign(SECRET, raw)
        hdrs.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=raw if method == "POST" else None, headers=hdrs)
        r = conn.getresponse()
        data = r.read().decode()
        ctype = r.getheader("Content-Type")
        conn.close()
        return r.status, data, ctype

    def dial(self, sid, text, phone=MSISDN, **extra):
        return self.post({"sessionId": sid, "phoneNumber": phone, "text": text,
                          "serviceCode": "*123#", **extra})


class Http(HttpBase):
    def test_signed_request_gets_text_plain_reply(self):
        status, body, ctype = self.dial("s1", "")
        self.assertEqual((status, body), (200, "END " + NO_PENDING))
        self.assertTrue(ctype.startswith("text/plain"))

    def test_unsigned_or_badly_signed_requests_are_rejected_before_any_logic(self):
        fields = {"sessionId": "s", "phoneNumber": MSISDN, "text": ""}
        self.assertEqual(self.post(fields, signature="")[0], 403)
        self.assertEqual(self.post(fields, signature="00" * 32)[0], 403)
        self.assertEqual(self.post(fields, signature="é")[0], 403)
        body = urlencode(fields).encode()
        self.assertEqual(self.post(body=body + b"&x=1", signature=sign(SECRET, body))[0], 403)  # body tampered

    def test_wrong_secret_rejected(self):
        raw = urlencode({"sessionId": "s", "phoneNumber": MSISDN, "text": ""}).encode()
        self.assertEqual(self.post(body=raw, signature=sign(b"other", raw))[0], 403)

    def test_method_path_size_and_fields(self):
        self.assertEqual(self.post(method="GET")[0], 405)
        self.assertEqual(self.post({"sessionId": "s"}, path="/other")[0], 404)
        self.assertEqual(self.post({"phoneNumber": MSISDN, "text": ""})[0], 400)      # no sessionId
        self.assertEqual(self.post({"sessionId": "s", "text": ""})[0], 400)           # no phone
        big = urlencode({"sessionId": "s", "phoneNumber": MSISDN, "text": "1" * 5000}).encode()
        self.assertEqual(self.post(body=big)[0], 413)

    def test_source_ip_allowlist(self):
        self.server.shutdown(); self.server.server_close()
        self.start(allowed_ips={"10.9.9.9"})
        self.assertEqual(self.dial("s", "")[0], 403)
        self.server.shutdown(); self.server.server_close()
        self.start(allowed_ips={"127.0.0.1"})
        self.assertEqual(self.dial("s", "")[0], 200)

    def test_full_emergency_flow_over_http(self):
        ch, _ = self.w.challenges.create(self.w.txn(merchant_name="Corner Shop"), "d1", 30)
        otp = self.w.challenges.issue_ussd_code(ch.id, 600)
        s, screen, _ = self.dial("S1", "")
        self.assertTrue(screen.startswith("CON Pending:"))
        self.assertIn("100.00 USD Corner Shop", screen)
        self.assertTrue(self.dial("S1", "1")[1].startswith("CON 100.00 USD"))
        self.assertEqual(self.dial("S1", "1*1")[1], "CON Enter the 6-digit code from the SMS:")
        self.assertEqual(self.dial("S1", f"1*1*{otp}")[1], "CON Enter your USSD password:")
        self.assertEqual(self.dial("S1", f"1*1*{otp}*{GOOD_PW}")[1], "END Approved.")
        self.assertEqual(self.w.store.challenges[ch.id].status.value, "APPROVED")

    def test_spoofed_number_without_signature_cannot_approve(self):
        ch, _ = self.w.challenges.create(self.w.txn(), "d1", 30)
        otp = self.w.challenges.issue_ussd_code(ch.id, 600)
        fields = {"sessionId": "S", "phoneNumber": MSISDN, "text": f"1*1*{otp}*{GOOD_PW}"}
        self.assertEqual(self.post(fields, signature="bad")[0], 403)
        self.assertEqual(self.w.store.challenges[ch.id].status.value, "PENDING")

    def test_extra_gateway_fields_reach_the_locator_but_text_does_not(self):
        seen = []
        self.gw.cell_locator = lambda p: seen.append(dict(p))
        ch, _ = self.w.challenges.create(self.w.txn(), "d1", 30)
        otp = self.w.challenges.issue_ussd_code(ch.id, 600)
        for t in ("", "1", "1*1", f"1*1*{otp}", f"1*1*{otp}*{GOOD_PW}"):
            self.dial("S2", t, cellId="4411", networkCode="99999")
        self.assertTrue(seen)
        self.assertEqual(seen[0].get("cellId"), "4411")
        self.assertTrue(all("text" not in p and "phoneNumber" not in p and "sessionId" not in p for p in seen))


if __name__ == "__main__":
    unittest.main()
