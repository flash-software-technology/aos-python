"""FastAPI helpers.

    aos = AsyncAos(url=..., publishable_key=..., secret_key=...)
    auth = AosAuth(aos)

    @app.get("/api/me")
    async def me(claims: Claims = Depends(auth.require)):
        return {"user_id": claims.user_id}

    @app.get("/api/invoices", dependencies=[Depends(auth.permission("invoice.read"))])
    async def invoices(): ...

    app.include_router(auth.can_router())   # POST /api/aos/can for <Protect>
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Request

from .client import AsyncAos
from .errors import InvalidTokenError
from .token import Claims, token_from_header

ResourceFn = Callable[[Request, Claims], dict]


def root(_: Request, __: Claims) -> dict:
    return {"type": "tenant", "id": "root"}


def active_organization(_: Request, claims: Claims) -> dict:
    """The organization the person is working in, or the root."""
    if claims.organization:
        return {"type": "organization", "id": claims.organization}
    return {"type": "tenant", "id": "root"}


def _unauthenticated() -> HTTPException:
    return HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "sign in to continue"})


class AosAuth:
    def __init__(self, aos: AsyncAos):
        self.aos = aos

    async def require(self, request: Request) -> Claims:
        """A dependency: the verified claims, or 401."""
        token = token_from_header(request.headers.get("authorization"))
        if not token:
            raise _unauthenticated()
        try:
            claims = await self.aos.verify_token(token)
        except InvalidTokenError:
            raise _unauthenticated() from None
        request.state.aos = claims
        return claims

    async def optional(self, request: Request) -> Claims | None:
        token = token_from_header(request.headers.get("authorization"))
        if not token:
            return None
        try:
            return await self.aos.verify_token(token)
        except InvalidTokenError:
            return None

    def permission(self, permission: str, resource: ResourceFn = active_organization) -> Callable[..., Awaitable[Claims]]:
        """A dependency: 403 unless the signed-in person holds the permission."""

        async def dep(request: Request, claims: Claims = Depends(self.require)) -> Claims:
            answer = await self.aos.can(claims.user_id, permission, resource(request, claims), session_id=claims.session_id)
            if not answer.get("allowed"):
                raise HTTPException(status_code=403, detail={"code": answer.get("reason"), "message": "you may not do this"})
            return claims

        return dep

    def can_router(self, path: str = "/api/aos/can") -> APIRouter:
        """POST {"permissions": [...], "resource"?: {...}} → {"results": {...}}, for <Protect>."""
        router = APIRouter()

        @router.post(path)
        async def can(request: Request, claims: Claims = Depends(self.require)) -> dict[str, Any]:
            try:
                body = await request.json()
            except ValueError:
                body = {}
            perms = [p for p in (body.get("permissions") or []) if isinstance(p, str)][:100]
            res = body.get("resource") or {}
            resource = res if res.get("type") and res.get("id") else active_organization(request, claims)
            if not perms:
                return {"results": {}}
            answers = await self.aos.can_batch([{"principal_id": claims.user_id, "permission": p, "resource": resource, "session_id": claims.session_id} for p in perms])
            return {"results": {p: bool(answers[i].get("allowed")) for i, p in enumerate(perms)}}

        return router
