"""Django helpers.

settings.py:
    AOS_URL, AOS_PUBLISHABLE_KEY, AOS_SECRET_KEY
    MIDDLEWARE = [..., "aos_auth.django.AosMiddleware"]

views.py:
    from aos_auth.django import require_auth, require_permission

    @require_permission("invoice.read")
    def invoices(request): ...       # request.aos is the Claims
"""
from __future__ import annotations

import functools
from typing import Callable

from django.conf import settings
from django.http import HttpRequest, JsonResponse

from .client import Aos
from .errors import InvalidTokenError
from .token import Claims, token_from_header

_client: Aos | None = None


def client() -> Aos:
    """The shared client, made from settings on first use."""
    global _client
    if _client is None:
        _client = Aos(url=settings.AOS_URL, publishable_key=getattr(settings, "AOS_PUBLISHABLE_KEY", None), secret_key=getattr(settings, "AOS_SECRET_KEY", None))
    return _client


class AosMiddleware:
    """Sets request.aos to the verified Claims, or None."""

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        request.aos = None  # type: ignore[attr-defined]
        token = token_from_header(request.headers.get("Authorization"))
        if token:
            try:
                request.aos = client().verify_token(token)  # type: ignore[attr-defined]
            except InvalidTokenError:
                pass
        return self.get_response(request)


def _deny(status: int, code: str, message: str) -> JsonResponse:
    return JsonResponse({"error": {"code": code, "message": message}}, status=status)


def require_auth(view: Callable) -> Callable:
    @functools.wraps(view)
    def wrapped(request: HttpRequest, *args, **kwargs):
        if getattr(request, "aos", None) is None:
            return _deny(401, "unauthenticated", "sign in to continue")
        return view(request, *args, **kwargs)

    return wrapped


def active_organization(request: HttpRequest) -> dict:
    claims: Claims = request.aos  # type: ignore[attr-defined]
    if claims.organization:
        return {"type": "organization", "id": claims.organization}
    return {"type": "tenant", "id": "root"}


def require_permission(permission: str, resource: Callable[[HttpRequest], dict] = active_organization) -> Callable:
    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args, **kwargs):
            claims = getattr(request, "aos", None)
            if claims is None:
                return _deny(401, "unauthenticated", "sign in to continue")
            answer = client().can(claims.user_id, permission, resource(request), session_id=claims.session_id)
            if not answer.get("allowed"):
                return _deny(403, answer.get("reason", "forbidden"), "you may not do this")
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
