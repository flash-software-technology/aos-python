from __future__ import annotations

import hashlib
import hmac
import json
import time

from .errors import BadSignatureError


def verify_webhook(secret: str, header: str | None, body: bytes | str, tolerance: int = 300, now: float | None = None) -> dict:
    """Checks the X-AOS-Signature header ("t=<unix>,v1=<hex>") of a
    delivery and returns the event. Pass the raw body as received."""
    raw = body.encode() if isinstance(body, str) else bytes(body)
    ts, sigs = "", []
    for part in (header or "").split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            ts = v
        elif k == "v1" and v:
            sigs.append(v)
    if not ts.isdigit() or not sigs:
        raise BadSignatureError()
    if abs((time.time() if now is None else now) - int(ts)) > tolerance:
        raise BadSignatureError()
    want = hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(want, s) for s in sigs):
        raise BadSignatureError()
    return json.loads(raw)


def sign_webhook(secret: str, body: bytes | str, now: float | None = None) -> str:
    """Makes a signature header, for tests of your own webhook handler."""
    raw = body.encode() if isinstance(body, str) else bytes(body)
    ts = str(int(time.time() if now is None else now))
    return f"t={ts},v1=" + hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
