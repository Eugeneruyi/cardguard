"""HTTP callback the telco aggregator posts to: POST /ussd (form-encoded).

Fields: sessionId, phoneNumber, text (+ optional serviceCode, networkCode, ...).
Authenticity matters more here than anywhere else: the phone number in the
request is what identifies the customer, so a forged request is a forged
identity. Therefore:
  * the body must carry X-Signature = hex HMAC-SHA256(shared secret, raw body);
  * optionally only allow listed source IPs;
  * bodies are size-limited and sockets time out (no slow-loris);
  * serve it ONLY behind TLS (reverse proxy), never plain HTTP on the internet.
Replies are text/plain 'CON ...' / 'END ...'. Request bodies are never logged.
"""
from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs

from .ussd_gateway import UssdGateway


class UssdHttpApp:
    def __init__(self, gateway: UssdGateway, secret: bytes,
                 allowed_ips: Optional[set] = None, max_body: int = 4096):
        self.gateway = gateway
        self.secret = secret
        self.allowed_ips = allowed_ips
        self.max_body = max_body

    def make_server(self, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
        app = self

        class Handler(BaseHTTPRequestHandler):
            timeout = 10

            def log_message(self, *args):    # default access log would add noise, never bodies
                pass

            def _send(self, status: int, body: str):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._send(405, "Method not allowed")

            def do_POST(self):
                if self.path != "/ussd":
                    return self._send(404, "Not found")
                if app.allowed_ips is not None and self.client_address[0] not in app.allowed_ips:
                    return self._send(403, "Forbidden")
                length = self.headers.get("Content-Length", "")
                if not length.isdigit():
                    return self._send(411, "Length required")
                if int(length) > app.max_body:
                    return self._send(413, "Too large")
                body = self.rfile.read(int(length))
                expected = hmac.new(app.secret, body, hashlib.sha256).hexdigest().encode()
                given = self.headers.get("X-Signature", "").encode()
                if not hmac.compare_digest(expected, given):
                    return self._send(403, "Forbidden")

                fields = {k: v[0] for k, v in
                          parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
                session_id = fields.pop("sessionId", "")
                phone = fields.pop("phoneNumber", "")
                text = fields.pop("text", "")        # secrets travel here: keep out of `params`
                if not session_id or not phone:
                    return self._send(400, "Bad request")
                self._send(200, app.gateway.handle(session_id, phone, text, fields))

        return ThreadingHTTPServer((host, port), Handler)


def sign(secret: bytes, body: bytes) -> str:
    """What the aggregator (or a test client) puts in X-Signature."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()
