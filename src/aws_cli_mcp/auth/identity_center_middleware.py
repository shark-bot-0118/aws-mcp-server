"""IAM Identity Center authentication middleware."""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from aws_cli_mcp.auth.context import RequestContext, reset_request_context, set_request_context
from aws_cli_mcp.auth.multi_user_guard import (
    MultiUserViolationError,
    enforce_single_user_mode,
)
from aws_cli_mcp.utils.hashing import sha256_text

logger = logging.getLogger(__name__)

EXEMPT_PATHS = frozenset({"/health", "/ready"})
EXEMPT_PREFIXES = ("/.well-known/",)


def is_exempt_path(path: str) -> bool:
    """Return True if the request path should bypass auth."""
    if path in EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)


def _token_to_user_id(token: str) -> str:
    """Derive a stable, non-reversible user id from an access token."""
    return sha256_text(token)[:16]


class IdentityCenterAuthMiddleware(BaseHTTPMiddleware):
    """Identity Center access token middleware."""

    def __init__(self, app, allow_multi_user: bool = False) -> None:
        super().__init__(app)
        self._allow_multi_user = allow_multi_user

    async def dispatch(self, request: Request, call_next):
        if is_exempt_path(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._unauthorized(
                "Missing or invalid Authorization header",
                "missing_access_token",
            )

        access_token = auth_header[7:]
        user_id = _token_to_user_id(access_token)
        try:
            enforce_single_user_mode(
                user_id=user_id,
                issuer="identity-center",
                allow_multi_user=self._allow_multi_user,
            )
        except MultiUserViolationError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "multi_user_disabled",
                    "message": str(exc),
                },
            )

        ctx = RequestContext(
            user_id=user_id,
            issuer="identity-center",
            access_token=access_token,
        )

        request.state.access_token = access_token

        context_token = set_request_context(ctx)
        try:
            return await call_next(request)
        finally:
            reset_request_context(context_token)

    def _unauthorized(self, message: str, code: str = "unauthorized") -> JSONResponse:
        body = {"error": "unauthorized", "error_description": message, "error_code": code}
        return JSONResponse(
            body,
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer error="{code}"'},
        )
