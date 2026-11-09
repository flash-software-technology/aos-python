from __future__ import annotations

import inspect
import time
from typing import Any, Callable
from urllib.parse import quote, urlencode

import httpx

from .errors import AosError
from .token import Claims, KeyCache, check, parse_header

VERSION = "0.4.0"
ROOT = {"type": "tenant", "id": "root"}


def _then(value: Any, fn: Callable[[Any], Any]) -> Any:
    """Applies fn to a value, or to a coroutine's result."""
    if inspect.isawaitable(value):
        async def chain() -> Any:
            return fn(await value)
        return chain()
    return fn(value)


def _q(s: str) -> str:
    return quote(s, safe="")


def _error(resp: httpx.Response) -> AosError:
    try:
        e = resp.json().get("error") or {}
    except ValueError:
        e = {}
    return AosError(resp.status_code, e.get("code") or f"http_{resp.status_code}", e.get("message") or f"the engine answered {resp.status_code}", e.get("details"))


def _data(resp: httpx.Response) -> Any:
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if resp.status_code >= 300 or (isinstance(payload, dict) and payload.get("error")):
        raise _error(resp)
    return payload.get("data") if isinstance(payload, dict) else None


class _Base:
    """Everything the two clients share. _request returns a value in Aos
    and a coroutine in AsyncAos; every method passes that through."""

    def __init__(self, url: str, publishable_key: str | None, secret_key: str | None, keys_ttl: float, now: Callable[[], float] | None):
        if not url:
            raise ValueError("aos: url is required")
        if secret_key and not secret_key.startswith("sk_"):
            raise ValueError("aos: secret_key must be a secret key (sk_...)")
        if publishable_key and not publishable_key.startswith("pk_"):
            raise ValueError("aos: publishable_key must be a publishable key (pk_...)")
        self.url = url.rstrip("/")
        self.publishable_key = publishable_key
        self.secret_key = secret_key
        self._now = now or time.time
        self._keys = KeyCache(keys_ttl, self._now)
        self.permissions = _Permissions(self)
        self.roles = _Roles(self)
        self.resources = _Resources(self)
        self.grants = _Grants(self)
        self.users = _Users(self)
        self.organizations = _Organizations(self)
        self.api_keys = _APIKeys(self)
        self.webhooks = _Webhooks(self)

    def _headers(self) -> dict[str, str]:
        if not self.secret_key:
            raise ValueError("aos: backend calls need secret_key")
        return {"Authorization": f"Bearer {self.secret_key}", "Accept": "application/json", "User-Agent": f"aos-python/{VERSION}"}

    def _jwks_headers(self) -> dict[str, str]:
        if not self.publishable_key:
            raise ValueError("aos: verifying tokens needs publishable_key")
        return {"X-AOS-Publishable-Key": self.publishable_key}

    def _request(self, method: str, path: str, body: Any = None) -> Any:  # pragma: no cover
        raise NotImplementedError

    # Permissions -------------------------------------------------------

    def can(self, principal_id: str, permission: str, resource: dict | None = None, **extra: Any) -> Any:
        """{"allowed": bool, "reason": str, ...}. extra: session_id, context, agent_id, approval_id, details, scopes."""
        return self._request("POST", "/v1/can", {"principal_id": principal_id, "permission": permission, "resource": resource or ROOT, **extra})

    def can_batch(self, checks: list[dict]) -> Any:
        return _then(self._request("POST", "/v1/can/batch", {"checks": checks}), lambda d: d["results"])

    def filter(self, principal_id: str, permission: str, resource_type: str) -> Any:
        """The application's own ids where a permission holds, for list queries."""
        return self._request("POST", "/v1/filter", {"principal_id": principal_id, "permission": permission, "resource_type": resource_type})

    def explain(self, principal_id: str, permission: str, resource: dict | None = None, **extra: Any) -> Any:
        return self._request("POST", "/v1/explain", {"principal_id": principal_id, "permission": permission, "resource": resource or ROOT, **extra})


class _NS:
    def __init__(self, c: _Base):
        self._c = c


class _Permissions(_NS):
    def put(self, name: str, description: str = "", step_up_seconds: int = 0, needs_approval: bool = False) -> Any:
        return self._c._request("PUT", "/v1/permissions", {"name": name, "description": description, "step_up_seconds": step_up_seconds, "needs_approval": needs_approval})

    def list(self) -> Any:
        return self._c._request("GET", "/v1/permissions")


class _Roles(_NS):
    def put(self, name: str, permissions: list[str], description: str = "") -> Any:
        return self._c._request("PUT", "/v1/roles", {"name": name, "permissions": permissions, "description": description})

    def list(self) -> Any:
        return self._c._request("GET", "/v1/roles")


class _Resources(_NS):
    def put(self, type: str, id: str, parent: dict | None = None, display_name: str = "") -> Any:
        body: dict[str, Any] = {"type": type, "id": id, "display_name": display_name}
        if parent:
            body["parent"] = parent
        return self._c._request("PUT", "/v1/resources", body)


class _Grants(_NS):
    def create(self, role: str, resource: dict | None = None, principal_id: str | None = None, group_id: str | None = None, **extra: Any) -> Any:
        """Returns the grant id. extra: effect, condition, expires_at, reason."""
        body = {"role": role, "resource": resource or ROOT, **extra}
        if principal_id:
            body["principal_id"] = principal_id
        if group_id:
            body["group_id"] = group_id
        return _then(self._c._request("POST", "/v1/grants", body), lambda d: d["id"])

    def delete(self, grant_id: str) -> Any:
        return self._c._request("DELETE", f"/v1/grants/{_q(grant_id)}")


class _Users(_NS):
    def create(self, email: str, name: str = "", role: str | None = None, resource: dict | None = None) -> Any:
        """Makes an account and emails a setup link. With a role, the user holds it from the start."""
        body: dict[str, Any] = {"email": email, "name": name}
        if role:
            body["role"] = role
            body["resource"] = resource or ROOT
        return self._c._request("POST", "/v1/users", body)

    def get(self, user_id: str) -> Any:
        return self._c._request("GET", f"/v1/users/{_q(user_id)}")

    def list(self, cursor: str | None = None, limit: int | None = None) -> Any:
        """{"users": [...], "next_cursor": "..."}"""
        q = {k: v for k, v in {"cursor": cursor, "limit": limit}.items() if v}
        return self._c._request("GET", "/v1/users" + ("?" + urlencode(q) if q else ""))

    def suspend(self, user_id: str, reason: str = "") -> Any:
        return self._c._request("POST", f"/v1/users/{_q(user_id)}/suspend", {"reason": reason})

    def reinstate(self, user_id: str) -> Any:
        return self._c._request("POST", f"/v1/users/{_q(user_id)}/reinstate")

    def delete(self, user_id: str) -> Any:
        return self._c._request("DELETE", f"/v1/users/{_q(user_id)}")


class _Organizations(_NS):
    def create(self, name: str, slug: str, owner_principal_id: str | None = None) -> Any:
        return self._c._request("POST", "/v1/admin/organizations", {"name": name, "slug": slug, "owner_principal_id": owner_principal_id})

    def list(self) -> Any:
        return self._c._request("GET", "/v1/admin/organizations")

    def members(self, organization_id: str) -> Any:
        return self._c._request("GET", f"/v1/admin/organizations/{_q(organization_id)}/members")

    def invite(self, organization_id: str, email: str, role: str) -> Any:
        return self._c._request("POST", f"/v1/admin/organizations/{_q(organization_id)}/invitations", {"email": email, "role": role})


class _APIKeys(_NS):
    def create(self, principal_id: str, name: str, scopes: list[str] | None = None) -> Any:
        return self._c._request("POST", "/v1/api-keys", {"principal_id": principal_id, "name": name, "scopes": scopes or []})

    def check(self, key: str, permission: str | None = None, resource: dict | None = None) -> Any:
        """Identifies a key a caller presented; with a permission, checks it within the key's scopes."""
        body: dict[str, Any] = {"key": key}
        if permission:
            body["permission"] = permission
            body["resource"] = resource or ROOT
        return self._c._request("POST", "/v1/api-keys/check", body)


class _Webhooks(_NS):
    def create(self, url: str, event_types: list[str] | None = None) -> Any:
        return self._c._request("POST", "/v1/webhooks", {"url": url, "event_types": event_types or []})


class Aos(_Base):
    """The AOS client for synchronous code (Django, Flask, scripts).

    aos = Aos(url=os.environ["AOS_URL"], publishable_key=..., secret_key=...)
    claims = aos.verify_token(token)
    aos.can(claims.user_id, "invoice.refund", {"type": "invoice", "id": "inv_1"})["allowed"]
    """

    def __init__(self, url: str, publishable_key: str | None = None, secret_key: str | None = None, *, keys_ttl: float = 600, http: httpx.Client | None = None, now: Callable[[], float] | None = None):
        super().__init__(url, publishable_key, secret_key, keys_ttl, now)
        self._http = http or httpx.Client(timeout=10)

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        return _data(self._http.request(method, self.url + path, headers=self._headers(), json=body))

    def verify_token(self, token: str) -> Claims:
        """Verifies a session token locally; raises InvalidTokenError."""
        kid, parts = parse_header(token)
        key, due = self._keys.lookup(kid)
        if due:
            try:
                resp = self._http.get(self.url + "/v1/jwks.json", headers=self._jwks_headers())
                if resp.status_code != 200:
                    raise AosError(resp.status_code, "jwks_unavailable", "the engine did not return its public keys")
                self._keys.store(resp.json())
                key = self._keys.keys.get(kid)
            except (httpx.HTTPError, AosError):
                if key is None:
                    raise
        return check(parts, key, self._now())

    def close(self) -> None:
        self._http.close()


class AsyncAos(_Base):
    """The AOS client for async code (FastAPI, Starlette). Same methods as
    Aos; each is awaited."""

    def __init__(self, url: str, publishable_key: str | None = None, secret_key: str | None = None, *, keys_ttl: float = 600, http: httpx.AsyncClient | None = None, now: Callable[[], float] | None = None):
        super().__init__(url, publishable_key, secret_key, keys_ttl, now)
        self._http = http or httpx.AsyncClient(timeout=10)

    async def _request(self, method: str, path: str, body: Any = None) -> Any:
        return _data(await self._http.request(method, self.url + path, headers=self._headers(), json=body))

    async def verify_token(self, token: str) -> Claims:
        kid, parts = parse_header(token)
        key, due = self._keys.lookup(kid)
        if due:
            try:
                resp = await self._http.get(self.url + "/v1/jwks.json", headers=self._jwks_headers())
                if resp.status_code != 200:
                    raise AosError(resp.status_code, "jwks_unavailable", "the engine did not return its public keys")
                self._keys.store(resp.json())
                key = self._keys.keys.get(kid)
            except (httpx.HTTPError, AosError):
                if key is None:
                    raise
        return check(parts, key, self._now())

    async def aclose(self) -> None:
        await self._http.aclose()
