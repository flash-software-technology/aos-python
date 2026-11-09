"""The engine run by the application itself, against a real database:
../scripts/with-engine.sh .venv/bin/python -m pytest -m integration"""
import os
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aos_auth.local import start_local

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not os.environ.get("AOS_IT_ENGINE"), reason="run through sdk/scripts/with-engine.sh")]


def test_application_runs_its_own_engine():
    with start_local(database_url=os.environ["AOS_IT_DATABASE_URL"], master_key=os.environ["AOS_IT_MASTER_KEY"],
                     app_url="http://shop.test", development=True, engine=os.environ["AOS_IT_ENGINE"],
                     slug="py-local", log=False) as local:
        assert local.publishable_key.startswith("pk_")
        app = FastAPI()
        app.mount("/aos", local.asgi())
        http = TestClient(app, headers={"Origin": "http://shop.test"})

        email = f"py-local-{time.time_ns()}@shop.test"
        assert http.post("/aos/v1/sign-up", json={"email": email, "password": "correct horse battery staple 42"}).status_code == 202
        assert http.post("/aos/v1/sign-up", json={"email": "x@y.test", "password": "correct horse battery staple 42"}, headers={"Origin": "http://evil.test"}).status_code == 403
        token = ""
        for _ in range(50):
            # The development inbox answers this machine only; the proxy forwards the caller's address.
            data = httpx.get(local.url + "/aos/dev/mail", params={"to": email}).json()["data"]
            if data:
                token = data[0]["token"]
                break
            time.sleep(0.1)
        assert token
        verified = http.post("/aos/v1/verify-email", json={"token": token}).json()["data"]
        jwt = http.post("/aos/v1/session/token", headers={"X-AOS-Session": verified["session_token"]}).json()["data"]["token"]

        aos = local.client()
        claims = aos.verify_token(jwt)
        assert claims.user_id == verified["user"]["id"]
        aos.permissions.put("report.read")
        aos.roles.put("Reader", ["report.read"])
        assert aos.can(claims.user_id, "report.read")["allowed"] is False
        aos.grants.create("Reader", principal_id=claims.user_id)
        assert aos.can(claims.user_id, "report.read")["allowed"] is True

        forged = http.post("/aos/v1/can", json={}, headers={"Authorization": "Bearer sk_local_" + "x" * 43})
        assert forged.status_code != 200
        assert httpx.post(local.url + "/v1/can", json={}, headers={"Authorization": "Bearer sk_local_" + "y" * 43}).status_code == 401
    assert local._process.poll() is not None, "the engine stopped with the application"
