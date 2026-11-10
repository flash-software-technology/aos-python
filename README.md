# aos-auth

The Python SDK for AOS: verify sign-in tokens, check permissions, guard routes and manage users from a Python backend.

Part of **AOS**, an identity and access platform (sign-up and sign-in, sessions, MFA, passkeys, social and enterprise SSO, organizations, roles and permissions, webhooks, audit).

- `Aos` is the synchronous client (Django, Flask, scripts).
- `AsyncAos` has the same methods, awaited (FastAPI, Starlette).
- Ready-made helpers for **FastAPI** and **Django**.
- `start_local()` runs the AOS engine beside your app, with users in **your own Postgres**. No auth server to deploy.

## Where it fits

| Piece | What it does | Get it |
|---|---|---|
| [Engine](https://github.com/flash-software-technology/aos) | The server that holds users, sessions and permissions | v0.5.0 |
| [`aosctl`](https://github.com/flash-software-technology/aos-cli) | CLI: scaffold an app, run the engine for development, seed data | v0.6.0 |
| [`@aos-auth/js`, `@aos-auth/react`](https://github.com/flash-software-technology/aos-js) | Sign-in in the browser | 0.3.0 |
| [`@aos-auth/node`](https://github.com/flash-software-technology/aos-js) | Node backends | 0.4.0 |
| [`aos-go`](https://github.com/flash-software-technology/aos-go) | Go backends | 0.4.0 |
| **`aos-auth`** (this package) | Python backends | 0.4.0 |

The browser signs people in and sends a short-lived access token (a JWT) to your backend. This package checks that token and asks the engine what the person may do.

Two keys, two places:

- **Publishable key** `pk_...`: safe in the browser. The SDK also uses it to fetch the engine's public keys.
- **Secret key** `sk_...`: server only. Never send it to the browser.

## Install

Python 3.10+. Not on PyPI yet (`pip install aos-auth` is coming). Install from GitHub:

```sh
pip install "aos-auth[fastapi] @ git+https://github.com/flash-software-technology/aos-python@v0.4.0"
# or with uv
uv add "aos-auth[fastapi] @ git+https://github.com/flash-software-technology/aos-python@v0.4.0"
```

Extras: `[fastapi]` (FastAPI helpers), `[django]` (Django helpers), or none for the plain clients.

## Quick start

The fastest way to see everything working is a scaffolded app. You need Go 1.24+ (for `aosctl`), Docker, and Node 22.9+ (for the web app).

```sh
go install github.com/flash-software-technology/aos-cli/cmd/aosctl@latest
aosctl init my-app --frontend react-vite --backend python --published
cd my-app
aosctl dev                      # terminal 1: Postgres + engine, writes keys to .env
aosctl seed                     # sample permissions, roles (Viewer, Billing), user ana@example.com
```

Until `aos-auth` is on PyPI, open `api/requirements.txt` and change the `aos-auth[fastapi]>=0.4` line to
`aos-auth[fastapi] @ git+https://github.com/flash-software-technology/aos-python@v0.4.0`. Then:

```sh
cd api && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt \
  && .venv/bin/uvicorn main:app --port 4000 --reload        # terminal 2: backend on :4000
cd web && npm install && npm run dev                        # terminal 3: open http://localhost:5173
aosctl mail                     # dev inbox: verification and setup links land here
aosctl grant --user you@example.com --role Viewer
```

### A complete FastAPI backend

This is the same shape as the `aosctl` template. `aosctl dev` writes `AOS_URL`, `AOS_PUBLISHABLE_KEY` and `AOS_SECRET_KEY` to `.env`.

```python
# main.py — run with: uvicorn main:app --port 4000
import os
from fastapi import Depends, FastAPI, Request, Response
from aos_auth import AsyncAos, BadSignatureError, Claims, verify_webhook
from aos_auth.fastapi import AosAuth

aos = AsyncAos(
    url=os.environ.get("AOS_URL", "http://127.0.0.1:8080"),
    publishable_key=os.environ["AOS_PUBLISHABLE_KEY"],
    secret_key=os.environ["AOS_SECRET_KEY"],
)
auth = AosAuth(aos)
app = FastAPI()
app.include_router(auth.can_router("/api/aos/can"))   # answers <Protect> in @aos-auth/react

@app.get("/api/me")
async def me(claims: Claims = Depends(auth.require)):  # 401 without a valid token
    return {"user_id": claims.user_id, "organization": claims.organization}

# The browser may hide a page with <Protect>; the server checks again.
@app.get("/api/invoices", dependencies=[Depends(auth.permission("invoice.read"))])  # 403 without it
async def invoices():
    return [{"id": "INV-1001", "amount": 1250}]

@app.post("/api/webhooks/aos")
async def webhook(request: Request) -> Response:
    try:
        event = verify_webhook(os.environ["AOS_WEBHOOK_SECRET"],
                               request.headers.get("x-aos-signature"), await request.body())
    except BadSignatureError:
        return Response("bad signature", status_code=400)
    print("aos event", event.get("event"), event.get("id"))
    return Response(status_code=204)
```

```sh
curl -i localhost:4000/api/me                 # HTTP/1.1 401 ... {"detail":{"code":"unauthenticated",...}}
curl -H "Authorization: Bearer $TOKEN" localhost:4000/api/me
```

## Common tasks

### Verify a token yourself

```python
from aos_auth import Aos, InvalidTokenError, token_from_header

aos = Aos(url, publishable_key="pk_test_...", secret_key="sk_test_...")
token = token_from_header(request.headers.get("Authorization"))   # "" if not "Bearer ..."
try:
    claims = aos.verify_token(token)        # AsyncAos: await aos.verify_token(token)
except InvalidTokenError:
    ...                                     # answer 401
```

Tokens are checked **locally** with the engine's public keys (`/v1/jwks.json`), fetched once and cached for `keys_ttl` seconds (default 600). An unknown key id triggers a refetch at most every 10 seconds. One minute of clock skew is allowed. Verifying needs only the publishable key.

`Claims` fields: `user_id`, `session_id`, `tenant_id`, `assurance_level`, `issued_at`, `expires_at`, `organization` (active organization's slug, or `None`), `organization_id`, `type`.

### Check a permission

```python
answer = aos.can(claims.user_id, "invoice.refund", {"type": "invoice", "id": "inv_1"},
                 session_id=claims.session_id)
if not answer["allowed"]:
    print(answer["reason"])                 # a deny is an answer, not an exception
```

- No resource means the whole application (`ROOT`, `{"type": "tenant", "id": "root"}`).
- Extra keyword arguments are passed to the engine: `session_id`, `context`, `agent_id`, `approval_id`, `details`, `scopes`.
- `aos.can_batch([{"principal_id": ..., "permission": ..., "resource": ...}, ...])` returns a list of answers.
- `aos.filter(user_id, "invoice.read", "invoice")` returns your own ids where the permission holds, for list queries.
- `aos.explain(user_id, permission, resource)` says why an answer is what it is.

### FastAPI helpers (`aos_auth.fastapi`)

`AosAuth(async_aos)` gives you dependencies:

| Helper | What it does |
|---|---|
| `auth.require` | Verified `Claims`, or 401. Also sets `request.state.aos`. |
| `auth.optional` | `Claims` or `None`; never fails. |
| `auth.permission(name, resource=active_organization)` | 401 if signed out, 403 unless allowed. |
| `auth.can_router(path="/api/aos/can")` | `POST {"permissions": [...], "resource"?: {...}}` → `{"results": {name: bool}}` for `<Protect>`. At most 100 permissions. |

`resource` is a function `(request, claims) -> dict`. The module ships `active_organization` (the person's active organization, else the root) and `root`:

```python
from aos_auth.fastapi import root

@app.post("/api/settings", dependencies=[Depends(auth.permission("settings.write", root))])
async def settings(): ...

def invoice(request, claims):
    return {"type": "invoice", "id": request.path_params["invoice_id"]}

@app.post("/api/invoices/{invoice_id}/refund", dependencies=[Depends(auth.permission("invoice.refund", invoice))])
async def refund(invoice_id: str): ...
```

### Django (`aos_auth.django`)

```python
# settings.py
AOS_URL = "http://127.0.0.1:8080"
AOS_PUBLISHABLE_KEY = "pk_test_..."
AOS_SECRET_KEY = "sk_test_..."
MIDDLEWARE = [..., "aos_auth.django.AosMiddleware"]   # sets request.aos to Claims or None

# views.py
from aos_auth.django import client, require_auth, require_permission

@require_auth                       # 401 JSON if signed out
def me(request):
    ...

@require_permission("invoice.read") # 401 if signed out, 403 unless allowed
def invoices(request):
    ...                             # request.aos is the Claims
```

`require_permission(name, resource=active_organization)` takes a function `(request) -> dict` for the resource. `client()` returns the shared `Aos` made from settings. Errors are JSON: `{"error": {"code": ..., "message": ...}}`.

### Flask and other frameworks

There is no Flask helper; the plain client is enough:

```python
from flask import Flask, abort, g, request
from aos_auth import Aos, InvalidTokenError, token_from_header

aos = Aos(AOS_URL, AOS_PUBLISHABLE_KEY, AOS_SECRET_KEY)
app = Flask(__name__)

@app.before_request
def load_claims():
    token = token_from_header(request.headers.get("Authorization"))
    try:
        g.aos = aos.verify_token(token) if token else None
    except InvalidTokenError:
        g.aos = None

@app.get("/api/invoices")
def invoices():
    if g.aos is None:
        abort(401)
    if not aos.can(g.aos.user_id, "invoice.read", session_id=g.aos.session_id)["allowed"]:
        abort(403)
    return []
```

### Manage permissions, roles, users and more

Backend calls need the secret key. Methods return the engine's `data` as plain dicts and lists.

```python
aos.permissions.put("invoice.read", description="See invoices")
aos.roles.put("Billing", ["invoice.read", "invoice.refund"])
aos.resources.put("invoice", "inv_1", parent={"type": "organization", "id": "acme"})

grant_id = aos.grants.create("Billing", principal_id=user_id)          # whole app
aos.grants.create("Billing", {"type": "organization", "id": "acme"}, principal_id=user_id)
aos.grants.delete(grant_id)

aos.users.create("ana@example.com", name="Ana", role="Viewer")         # emails a setup link
page = aos.users.list(limit=50)                                        # {"users": [...], "next_cursor": ...}
aos.users.suspend(user_id, reason="chargeback"); aos.users.reinstate(user_id)

aos.organizations.create("Acme", "acme", owner_principal_id=user_id)
aos.organizations.invite(organization_id, "bo@example.com", "Billing")

key = aos.api_keys.create(user_id, "ci", scopes=["invoice.read"])
aos.api_keys.check(presented_key, "invoice.read")                      # for keys your callers send you

aos.webhooks.create("https://shop.example.com/api/webhooks/aos", ["user.created"])
```

### Verify webhooks

```python
from aos_auth import BadSignatureError, verify_webhook

event = verify_webhook(secret, headers["X-AOS-Signature"], raw_body)   # raw bytes, as received
```

The header looks like `t=<unix>,v1=<hex>` (HMAC-SHA256). Deliveries older than `tolerance` (300 s) are rejected. In tests, `sign_webhook(secret, body)` makes a valid header. With `aosctl`, `aosctl webhooks listen` forwards events to your app.

## Your own database: `start_local()`

`start_local` runs the AOS engine as a child process of your app, with its tables in **your** Postgres. Nothing else to deploy. The SDK downloads the engine release it is tested with (`ENGINE_VERSION = "v0.5.0"`), checks its SHA-256 checksum, caches it, starts it on a free local port, and stops it when your process exits.

```python
import os
from fastapi import Depends, FastAPI
from aos_auth import Claims
from aos_auth.fastapi import AosAuth
from aos_auth.local import start_local

local = start_local(
    database_url=os.environ["DATABASE_URL"],
    master_key=os.environ["AOS_MASTER_KEY"],     # base64 of 32 random bytes
    app_url="https://shop.example.com",          # email links point here
)
app = FastAPI()
app.mount("/aos", local.asgi())                  # the browser SDK's routes go to the engine
auth = AosAuth(local.async_client())             # same helpers as above

@app.get("/api/me")
async def me(claims: Claims = Depends(auth.require)):
    return {"user_id": claims.user_id}

# In the browser: url = "https://shop.example.com/aos", publishable key = local.publishable_key
```

Make a master key once and keep it out of git and out of the database (it encrypts the engine's keys):

```sh
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

The engine creates or upgrades its own schemas (`aos`, `aos_platform`) on start.

**Mounting.** Mount `asgi()` at the same `path` you gave `start_local` (default `/aos`), with Starlette's `app.mount(path, ...)` or FastAPI's (which is Starlette's). The proxy forwards HTTP requests under that path to the engine, adds `X-Forwarded-For`, and drops any `sk_local_` key a browser tries to send.

### `start_local` parameters (keyword only)

| Parameter | Default | Meaning |
|---|---|---|
| `database_url` | required | Your Postgres |
| `master_key` | required | Base64 of 32 random bytes |
| `app_url` | required | Your app's address; its origin may call the browser routes |
| `path` | `"/aos"` | Where you mount `asgi()` |
| `origins` | `None` | More allowed browser origins, e.g. `["http://localhost:5173"]` |
| `slug`, `name` | `"app"`, `"App"` | Names the application |
| `kind` | `"multi"` | `"multi"` (with organizations) or `"single"` |
| `development` | `False` | Keep email in a dev inbox at `<path>/dev/mail` when no SMTP is set |
| `engine` | `None` | Path to an engine program; else `$AOS_ENGINE`; else download |
| `engine_version` | `ENGINE_VERSION` | Release to download |
| `env` | `None` | Extra environment for the engine, e.g. `AOS_SMTP_ADDR`, `AOS_SMTP_USERNAME`, `AOS_SMTP_PASSWORD`, `AOS_MAIL_FROM` |
| `log` | `True` | Show the engine's log on stderr |

### `LocalEngine`

| Member | What it is |
|---|---|
| `url`, `path`, `publishable_key`, `version` | Where the engine listens, its browser path, the app's `pk_...`, engine version |
| `client()` / `async_client()` | An `Aos` / `AsyncAos` already holding a one-time backend key |
| `asgi()` | ASGI app to mount at `path` |
| `stop(timeout=10)` | Stop the engine (also runs at exit) |
| `with start_local(...) as local:` | Stops the engine when the block ends |

`download_engine(version=ENGINE_VERSION)` fetches the engine ahead of time (e.g. in a Docker build) and returns its path.

## API reference

| Name | Kind | Notes |
|---|---|---|
| `Aos(url, publishable_key=None, secret_key=None, *, keys_ttl=600, http=None, now=None)` | class | `http` is an `httpx.Client`; `close()` |
| `AsyncAos(...)` | class | same, `http` is an `httpx.AsyncClient`; `await aclose()` |
| `.verify_token(token)` | method | `Claims`, or `InvalidTokenError` |
| `.can / .can_batch / .filter / .explain` | methods | permission questions |
| `.permissions` `.roles` `.resources` `.grants` `.users` `.organizations` `.api_keys` `.webhooks` | namespaces | admin calls (secret key) |
| `Claims` | dataclass | see above |
| `token_from_header(value)` | function | token from `Bearer ...`, else `""` |
| `verify_webhook(secret, header, body, tolerance=300)` / `sign_webhook(secret, body)` | functions | webhooks |
| `ROOT`, `VERSION` | constants | the whole-app resource; SDK version |
| `AosError` | exception | engine error: `.status`, `.code`, `.message`, `.details` |
| `InvalidTokenError` | exception | malformed, foreign, tampered or expired token |
| `BadSignatureError` | exception | webhook signature wrong or too old |

The constructor checks key types: a `secret_key` must start with `sk_`, a `publishable_key` with `pk_` (`ValueError` otherwise).

## Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `AOS_URL`, `AOS_PUBLISHABLE_KEY`, `AOS_SECRET_KEY` | your code / Django settings | Engine address and keys (`aosctl dev` writes them) |
| `AOS_WEBHOOK_SECRET` | your code | Secret for `verify_webhook` |
| `AOS_ENGINE` | `start_local` | Use this engine program instead of downloading |
| `AOSCTL_CACHE_DIR` | `download_engine` | Download cache (default: `~/.cache/aos`, shared with `aosctl`) |
| `AOSCTL_RELEASES_URL` | `download_engine` | Mirror of the engine releases |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ValueError: aos: secret_key must be a secret key (sk_...)` | Keys swapped. `pk_...` is publishable, `sk_...` is secret. |
| `ValueError: aos: verifying tokens needs publishable_key` | Pass `publishable_key` to the client. |
| `ValueError: aos: backend calls need secret_key` | Admin and `can` calls need `secret_key`. |
| Every request is **401** | No `Authorization: Bearer <token>` header, the token expired, or it comes from a different engine/tenant than your keys. |
| **403** with a reason | The token is fine; the person lacks the permission. Grant a role: `aosctl grant --user you@example.com --role Viewer`. |
| `AosError ... [jwks_unavailable]` or connection errors | The engine is not reachable at `AOS_URL`. Is `aosctl dev` running? |
| Browser calls blocked (CORS / 403 on sign-up) | The page's origin is not allowed. With `start_local`, add it to `origins` (e.g. your Vite dev server). |
| `RuntimeError: aos: no engine build for ...` | No release for your OS/CPU. Build the engine and set `AOS_ENGINE`. |
| `RuntimeError: aos: the engine stopped while starting` | Read the engine log above it: usually a bad `DATABASE_URL` or master key. |
| `pip install aos-auth` finds nothing | Not on PyPI yet; use the git URL in [Install](#install). |

## Developing this package

```
src/aos_auth/
  client.py    Aos, AsyncAos and the admin namespaces
  token.py     Claims, token checking, public-key cache
  webhook.py   verify_webhook, sign_webhook
  fastapi.py   AosAuth
  django.py    AosMiddleware, require_auth, require_permission
  local.py     start_local, LocalEngine, download_engine
tests/         unit tests; integration tests need a running engine
```

```sh
uv venv .venv && uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest -m "not integration"     # or: uv run pytest -q tests
```

Integration tests skip unless an engine is running; in the AOS monorepo, run them with
`../scripts/with-engine.sh .venv/bin/python -m pytest -m integration`.

Source and issues: https://github.com/flash-software-technology/aos-python

## Licence

Apache-2.0. See [LICENSE](LICENSE).
