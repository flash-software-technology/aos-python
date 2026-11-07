from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import InvalidTokenError


@dataclass(frozen=True)
class Claims:
    """What a verified session token says."""

    user_id: str
    session_id: str
    tenant_id: str
    assurance_level: int
    issued_at: int
    expires_at: int
    organization: str | None = None
    """The active organization's id in the application (its slug), if any."""
    organization_id: str | None = None
    type: str | None = None


def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def parse_header(token: str) -> tuple[str, list[str]]:
    parts = (token or "").split(".")
    if len(parts) != 3:
        raise InvalidTokenError()
    try:
        header = json.loads(_b64(parts[0]))
    except Exception:
        raise InvalidTokenError() from None
    if header.get("alg") != "EdDSA" or not header.get("kid"):
        raise InvalidTokenError()
    return header["kid"], parts


def check(parts: list[str], key: Ed25519PublicKey | None, now: float) -> Claims:
    if key is None:
        raise InvalidTokenError()
    try:
        key.verify(_b64(parts[2]), (parts[0] + "." + parts[1]).encode())
        payload = json.loads(_b64(parts[1]))
    except (InvalidSignature, ValueError):
        raise InvalidTokenError() from None
    sub, exp = payload.get("sub"), payload.get("exp")
    if not isinstance(sub, str) or not sub or not isinstance(exp, (int, float)):
        raise InvalidTokenError()
    # A minute of clock skew is allowed.
    if int(now) > exp + 60:
        raise InvalidTokenError()
    return Claims(
        user_id=sub,
        session_id=str(payload.get("sid", "")),
        tenant_id=str(payload.get("tid", "")),
        assurance_level=int(payload.get("aal", 0)),
        issued_at=int(payload.get("iat", 0)),
        expires_at=int(exp),
        organization=payload.get("org") or None,
        organization_id=payload.get("org_id") or None,
        type=payload.get("typ") or None,
    )


class KeyCache:
    """The tenant's public keys. Refetched after ttl, or for an unknown
    key id at most every 10 seconds."""

    def __init__(self, ttl: float, now: Callable[[], float]):
        self.ttl = ttl
        self.now = now
        self.keys: dict[str, Ed25519PublicKey] = {}
        self.fetched_at = 0.0
        self.last_fetch = 0.0

    def lookup(self, kid: str) -> tuple[Ed25519PublicKey | None, bool]:
        """Returns the key and whether a fetch is due."""
        known = self.keys.get(kid)
        fresh = self.now() - self.fetched_at < self.ttl
        if known is not None and fresh:
            return known, False
        may_fetch = not fresh or (known is None and self.now() - self.last_fetch > 10)
        return known, may_fetch

    def store(self, jwks: dict) -> None:
        keys = {}
        for k in jwks.get("keys", []):
            if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("kid") and k.get("x"):
                keys[k["kid"]] = Ed25519PublicKey.from_public_bytes(_b64(k["x"]))
        self.keys = keys
        self.fetched_at = self.last_fetch = self.now()


def token_from_header(value: str | None) -> str:
    if not value:
        return ""
    scheme, _, token = value.strip().partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


_ = time  # the clock is injected; kept for type checkers
