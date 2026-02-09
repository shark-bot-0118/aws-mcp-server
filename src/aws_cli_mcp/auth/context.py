"""Request-scoped authentication context."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable


@dataclass(frozen=True)
class AWSCredentials:
    """Immutable temporary AWS credentials."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime

    def __repr__(self) -> str:
        return f"AWSCredentials(access_key_id={self.access_key_id[:8]}***, ...)"


# Fields that must never appear in logs
SENSITIVE_FIELDS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "secret",
        "password",
        "credential",
        "authorization",
        "secret_access_key",
        "session_token",
    }
)


@dataclass(frozen=True)
class RequestContext:
    """
    Immutable request-scoped context.

    SECURITY: access_token is stored for STS calls but MUST NEVER be logged.
    - repr=False prevents accidental logging via print/str
    - __repr__ is overridden to exclude sensitive fields
    - Use SENSITIVE_FIELDS for audit log masking
    """

    user_id: str
    email: str | None = None
    groups: tuple[str, ...] | None = None  # Optional: may be missing or huge
    issuer: str = ""
    token_expiry: datetime | None = None
    token_jti: str | None = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # SENSITIVE: Never log these fields
    access_token: str | None = field(default=None, repr=False)
    id_token: str | None = field(default=None, repr=False)  # Deprecated, kept for compatibility
    aws_credentials: AWSCredentials | None = None
    aws_account_id: str | None = None
    aws_role_arn: str | None = None
    raw_claims: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        # Defensive copy to prevent external mutations from leaking into context.
        object.__setattr__(self, "raw_claims", MappingProxyType(dict(self.raw_claims)))

    def __repr__(self) -> str:
        """Safe repr that never includes sensitive fields."""
        return (
            f"RequestContext("
            f"user_id={self.user_id!r}, "
            f"email={self.email!r}, "
            f"issuer={self.issuer!r}, "
            f"request_id={self.request_id!r}, "
            f"aws_account_id={self.aws_account_id!r}, "
            f"aws_role_arn={self.aws_role_arn!r})"
        )

    def __str__(self) -> str:
        """Safe str that never includes sensitive fields."""
        return self.__repr__()

    def with_aws_credentials(
        self,
        creds: AWSCredentials,
        account_id: str,
        role_arn: str,
    ) -> "RequestContext":
        """Return new context with AWS credentials."""
        return RequestContext(
            user_id=self.user_id,
            email=self.email,
            groups=self.groups,
            issuer=self.issuer,
            token_expiry=self.token_expiry,
            token_jti=self.token_jti,
            request_id=self.request_id,
            received_at=self.received_at,
            access_token=self.access_token,
            id_token=self.id_token,
            aws_credentials=creds,
            aws_account_id=account_id,
            aws_role_arn=role_arn,
            raw_claims=self.raw_claims,
        )


_request_context: ContextVar[RequestContext | None] = ContextVar(
    "request_context",
    default=None,
)


def set_request_context(ctx: RequestContext) -> Token[RequestContext | None]:
    """Set context and return reset token."""
    return _request_context.set(ctx)


def reset_request_context(token: Token[RequestContext | None]) -> None:
    """Reset context using token from set_request_context()."""
    _request_context.reset(token)


def get_request_context() -> RequestContext:
    """Get context or raise RuntimeError."""
    ctx = _request_context.get()
    if ctx is None:
        raise RuntimeError("No request context set")
    return ctx


def get_request_context_optional() -> RequestContext | None:
    """Get context or None (for dual-mode code)."""
    return _request_context.get()


def update_request_context(
    updater: Callable[[RequestContext], RequestContext],
) -> Token[RequestContext | None]:
    """Update context with a function and return reset token."""
    current = get_request_context()
    return _request_context.set(updater(current))
