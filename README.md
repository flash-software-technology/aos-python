# aos-auth

AOS for Python backends: check session tokens, ask about permissions, guard routes, manage users, roles, organizations, API keys and webhooks. `Aos` is synchronous (Django, Flask, scripts); `AsyncAos` has the same methods for async code (FastAPI, Starlette).

```sh
pip install "aos-auth[fastapi]"     # or [django], or plain aos-auth
```

## FastAPI

```python
import os
from fastapi import Depends, FastAPI
from aos_auth import AsyncAos, Claims
from aos_auth.fastapi import AosAuth

aos = AsyncAos(os.environ["AOS_URL"], os.environ["AOS_PUBLISHABLE_KEY"], os.environ["AOS_SECRET_KEY"])
auth = AosAuth(aos)
app = FastAPI()
app.include_router(auth.can_router("/api/aos/can"))          # answers <Protect> in @aos-auth/react

@app.get("/api/me")
async def me(claims: Claims = Depends(auth.require)):         # 401 without a valid token
    return {"user_id": claims.user_id, "organization": claims.organization}

@app.get("/api/invoices", dependencies=[Depends(auth.permission("invoice.read"))])   # 403 without it
async def invoices(): ...
```

## Django

```python
# settings.py
AOS_URL = ...; AOS_PUBLISHABLE_KEY = ...; AOS_SECRET_KEY = ...
MIDDLEWARE = [..., "aos_auth.django.AosMiddleware"]

# views.py
from aos_auth.django import require_permission

@require_permission("invoice.read")
def invoices(request):            # request.aos is the Claims
    ...
```

## Anything else

```python
from aos_auth import Aos, verify_webhook

aos = Aos(url, publishable_key, secret_key)
claims = aos.verify_token(token)                              # raises InvalidTokenError
aos.can(claims.user_id, "invoice.refund", {"type": "invoice", "id": "inv_1"})["allowed"]
aos.users.create("ana@example.com", name="Ana", role="Viewer")
event = verify_webhook(secret, request.headers["X-AOS-Signature"], raw_body)
```

Tokens are checked locally against the engine's public keys, fetched once and cached. A deny is an answer (`allowed: False` with a `reason`), not an error. Engine errors are `AosError` with a stable `code`.

## Develop

```sh
uv venv .venv && uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest -m "not integration"
```

Source and issues: https://github.com/flash-softeware/aos-python
