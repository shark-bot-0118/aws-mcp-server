from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType

import pytest

from aws_cli_mcp.auth.context import (
    AWSCredentials,
    RequestContext,
    get_request_context,
    get_request_context_optional,
    reset_request_context,
    set_request_context,
    update_request_context,
)


def test_credentials_and_context_repr_are_safe() -> None:
    creds = AWSCredentials(
        access_key_id="AKIA1234567890",
        secret_access_key="secret",
        session_token="token",
        expiration=datetime.now(timezone.utc),
    )
    assert "AKIA1234" in repr(creds)

    ctx = RequestContext(user_id="u1", email="u1@example.com", issuer="https://issuer")
    rendered = repr(ctx)
    assert "u1@example.com" in rendered
    assert "access_token" not in rendered
    assert str(ctx) == rendered


def test_context_var_lifecycle() -> None:
    ctx = RequestContext(user_id="u1", issuer="https://issuer")
    token = set_request_context(ctx)

    assert get_request_context().user_id == "u1"
    assert get_request_context_optional() is not None

    update_request_context(
        lambda current: RequestContext(
            user_id=current.user_id, issuer=current.issuer, email="u1@example.com"
        )
    )
    assert get_request_context().email == "u1@example.com"

    reset_request_context(token)
    assert get_request_context_optional() is None


def test_get_request_context_raises_without_context() -> None:
    token = set_request_context(RequestContext(user_id="temp", issuer="https://issuer"))
    reset_request_context(token)

    with pytest.raises(RuntimeError, match="No request context set"):
        get_request_context()


def test_raw_claims_defensive_copy_from_dict() -> None:
    source = {"sub": "user-1"}
    ctx = RequestContext(user_id="u1", issuer="https://issuer", raw_claims=source)

    source["sub"] = "tampered"

    assert ctx.raw_claims["sub"] == "user-1"
    with pytest.raises(TypeError):
        ctx.raw_claims["sub"] = "mutate"  # type: ignore[index]


def test_raw_claims_defensive_copy_from_mapping_proxy() -> None:
    backing = {"scope": "read"}
    proxy = MappingProxyType(backing)
    ctx = RequestContext(user_id="u1", issuer="https://issuer", raw_claims=proxy)

    backing["scope"] = "write"

    assert ctx.raw_claims["scope"] == "read"
