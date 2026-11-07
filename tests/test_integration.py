"""Runs against a real engine: ../scripts/with-engine.sh .venv/bin/python -m pytest -m integration"""
import os
import time
import uuid

import httpx
import pytest

from aos_auth import Aos, AosError, AsyncAos, InvalidTokenError

URL = os.environ.get("AOS_IT_URL")
PK = os.environ.get("AOS_IT_PUBLISHABLE_KEY")
SK = os.environ.get("AOS_IT_SECRET_KEY")
pytestmark = [pytest.mark.integration, pytest.mark.skipif(not URL, reason="run through sdk/scripts/with-engine.sh")]
PASSWORD = "correct horse battery staple 42"


def mail_for(email: str, pred) -> dict:
    for _ in range(50):
        data = httpx.get(f"{URL}/dev/mail", params={"to": email}).json()["data"] or []
        for m in data:
            if pred(m):
                return m
        time.sleep(0.1)
    raise AssertionError("no email for " + email)


def signed_up_session() -> tuple[str, str]:
    """Signs a new person up through the frontend door; returns (user id, backend token)."""
    email = f"py-{uuid.uuid4().hex[:10]}@example.com"
    front = {"X-AOS-Publishable-Key": PK}
    httpx.post(f"{URL}/v1/sign-up", json={"email": email, "password": PASSWORD}, headers=front).raise_for_status()
    mail = mail_for(email, lambda m: any("/auth/verify-email" in l for l in m["links"]))
    data = httpx.post(f"{URL}/v1/verify-email", json={"token": mail["token"]}, headers=front).json()["data"]
    tok = httpx.post(f"{URL}/v1/session/token", headers={**front, "X-AOS-Session": data["session_token"]}).json()["data"]["token"]
    return data["user"]["id"], tok


def test_sync_client_end_to_end():
    aos = Aos(URL, PK, SK)
    user_id, tok = signed_up_session()
    claims = aos.verify_token(tok)
    assert claims.user_id == user_id
    with pytest.raises(InvalidTokenError):
        aos.verify_token(tok[:-4] + "AAAA")

    aos.permissions.put("report.read", "Read reports")
    aos.roles.put("Reader", ["report.read"])
    assert any(p["name"] == "report.read" for p in aos.permissions.list())
    assert aos.can(user_id, "report.read")["allowed"] is False
    gid = aos.grants.create("Reader", principal_id=user_id)
    assert aos.can(user_id, "report.read", session_id=claims.session_id)["allowed"] is True
    aos.grants.delete(gid)
    assert aos.can(user_id, "report.read")["allowed"] is False

    with pytest.raises(AosError) as e:
        aos.users.get(str(uuid.uuid4()))
    assert e.value.status == 404
    page = aos.users.list(limit=200)
    assert any(u["id"] == user_id for u in page["users"])


async def test_async_client_end_to_end():
    aos = AsyncAos(URL, PK, SK)
    user_id, tok = signed_up_session()
    assert (await aos.verify_token(tok)).user_id == user_id
    await aos.resources.put("project", "p-1")
    await aos.permissions.put("project.read")
    await aos.roles.put("ProjectReader", ["project.read"])
    await aos.grants.create("ProjectReader", {"type": "project", "id": "p-1"}, principal_id=user_id)
    results = await aos.can_batch([{"principal_id": user_id, "permission": "project.read", "resource": {"type": "project", "id": "p-1"}}])
    assert results[0]["allowed"] is True
    assert "p-1" in (await aos.filter(user_id, "project.read", "project"))["allowed"]
    await aos.aclose()
