import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from aos_auth import Aos, AosError, AsyncAos, BadSignatureError, InvalidTokenError, sign_webhook, verify_webhook
from aos_auth.fastapi import AosAuth

NOW = 1_800_000_000
KEY = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()
PUB = base64.urlsafe_b64encode(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).rstrip(b"=").decode()
BASE = {"sub": "user-1", "sid": "sess-1", "tid": "ten-1", "aal": 1, "iat": NOW, "exp": NOW + 60}


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token(claims=BASE, key=KEY, kid="k1", alg="EdDSA") -> str:
    head = b64(json.dumps({"alg": alg, "kid": kid}).encode()) + "." + b64(json.dumps(claims).encode())
    return head + "." + b64(key.sign(head.encode()))


class Engine:
    """A fake engine: keys, and /v1/can allowing invoice.read on organization acme."""

    def __init__(self):
        self.calls = []

    def allow(self, c):
        return c["permission"] == "invoice.read" and c["resource"] in ({"type": "organization", "id": "acme"}, {"type": "tenant", "id": "root"})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if request.url.path == "/v1/jwks.json":
            if request.headers.get("x-aos-publishable-key") != "pk_test_1":
                return httpx.Response(401)
            return httpx.Response(200, json={"keys": [{"kty": "OKP", "crv": "Ed25519", "x": PUB, "kid": "k1"}]})
        if request.headers.get("authorization") != "Bearer sk_test_1":
            return httpx.Response(401, json={"error": {"code": "invalid_key", "message": "no"}})
        body = json.loads(request.content or b"null")
        if request.url.path == "/v1/can":
            ok = self.allow(body)
            return httpx.Response(200, json={"data": {"allowed": ok, "reason": "allowed" if ok else "no_matching_grant"}})
        if request.url.path == "/v1/can/batch":
            return httpx.Response(200, json={"data": {"results": [{"allowed": self.allow(c)} for c in body["checks"]]}})
        if request.url.path == "/v1/grants":
            return httpx.Response(201, json={"data": {"id": "g1"}})
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "user not found"}})


def sync_client(engine, now=lambda: NOW):
    return Aos("http://engine.test/", "pk_test_1", "sk_test_1", http=httpx.Client(transport=httpx.MockTransport(engine)), now=now)


def async_client(engine):
    return AsyncAos("http://engine.test", "pk_test_1", "sk_test_1", http=httpx.AsyncClient(transport=httpx.MockTransport(engine)), now=lambda: NOW)


def test_verify_good_token():
    c = sync_client(Engine()).verify_token(token({**BASE, "org": "acme", "org_id": "r1", "typ": "access"}))
    assert (c.user_id, c.session_id, c.organization, c.organization_id, c.assurance_level) == ("user-1", "sess-1", "acme", "r1", 1)


@pytest.mark.parametrize("bad", [
    token(key=OTHER),
    token({**BASE, "exp": NOW - 61}),
    token(alg="none"),
    token(kid="unknown"),
    token({**BASE, "sub": ""}),
    "a.b", "", "x.y.z",
])
def test_bad_tokens(bad):
    with pytest.raises(InvalidTokenError):
        sync_client(Engine()).verify_token(bad)


def test_forged_payload():
    h, _, s = token().split(".")
    forged = h + "." + b64(json.dumps({**BASE, "sub": "admin"}).encode()) + "." + s
    with pytest.raises(InvalidTokenError):
        sync_client(Engine()).verify_token(forged)


def test_keys_cached_and_refetched_at_most_every_10s():
    engine, now = Engine(), [NOW]
    c = sync_client(engine, now=lambda: now[0])
    for _ in range(3):
        c.verify_token(token())
    assert engine.calls.count("/v1/jwks.json") == 1
    with pytest.raises(InvalidTokenError):
        c.verify_token(token(kid="new"))
    assert engine.calls.count("/v1/jwks.json") == 1
    now[0] += 11
    with pytest.raises(InvalidTokenError):
        c.verify_token(token(kid="new"))
    assert engine.calls.count("/v1/jwks.json") == 2


def test_backend_calls_and_errors():
    c = sync_client(Engine())
    assert c.can("u", "invoice.read")["allowed"] is True
    assert c.grants.create("Billing", principal_id="u") == "g1"
    with pytest.raises(AosError) as e:
        c.users.get("missing")
    assert (e.value.status, e.value.code) == (404, "not_found")
    with pytest.raises(ValueError):
        Aos("http://x", secret_key="pk_wrong")
    with pytest.raises(ValueError, match="secret_key"):
        Aos("http://x").can("u", "p")


async def test_async_client():
    c = async_client(Engine())
    assert (await c.verify_token(token())).user_id == "user-1"
    assert [r["allowed"] for r in await c.can_batch([{"principal_id": "u", "permission": p, "resource": {"type": "tenant", "id": "root"}} for p in ("invoice.read", "x")])] == [True, False]
    assert await c.grants.create("Billing", principal_id="u") == "g1"


def test_webhooks():
    body = json.dumps({"id": "ev1", "event": "user.created", "data": {"id": "u1"}})
    header = sign_webhook("whsec_1", body, now=NOW)
    assert verify_webhook("whsec_1", header, body, now=NOW)["event"] == "user.created"
    assert verify_webhook("whsec_1", header, body.encode(), now=NOW)["id"] == "ev1"
    for secret, h, b, now in [("whsec_2", header, body, NOW), ("whsec_1", header, body, NOW + 301), ("whsec_1", header, body.replace("u1", "u2"), NOW), ("whsec_1", "", body, NOW)]:
        with pytest.raises(BadSignatureError):
            verify_webhook(secret, h, b, now=now)


def test_fastapi_dependencies():
    app = FastAPI()
    auth = AosAuth(async_client(Engine()))

    @app.get("/me")
    async def me(claims=Depends(auth.require)):
        return {"user": claims.user_id}

    @app.get("/invoices", dependencies=[Depends(auth.permission("invoice.read"))])
    async def invoices():
        return {"ok": True}

    @app.get("/refund", dependencies=[Depends(auth.permission("invoice.refund"))])
    async def refund():
        return {"ok": True}

    app.include_router(auth.can_router())
    http = TestClient(app)
    bearer = {"Authorization": "Bearer " + token({**BASE, "org": "acme"})}
    assert http.get("/me").status_code == 401
    assert http.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401
    assert http.get("/me", headers=bearer).json() == {"user": "user-1"}
    assert http.get("/invoices", headers=bearer).status_code == 200
    r = http.get("/refund", headers=bearer)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "no_matching_grant"
    r = http.post("/api/aos/can", headers=bearer, json={"permissions": ["invoice.read", "invoice.refund", 3]})
    assert r.json() == {"results": {"invoice.read": True, "invoice.refund": False}}
