"""Tests for audit middleware masking and request logging."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from aws_cli_mcp.auth.context import RequestContext, reset_request_context, set_request_context
from aws_cli_mcp.auth.idp_config import AuditConfig
from aws_cli_mcp.middleware.audit import (
    AuditMiddleware,
    _get_mask_pattern,
    mask_exception_message,
    mask_sensitive_data,
)


def _request(path: str = "/mcp", headers: dict[str, str] | None = None) -> Request:
    raw_headers = [
        (k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": raw_headers,
        "scheme": "https",
        "server": ("example.com", 443),
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


def test_get_mask_pattern_cached() -> None:
    first = _get_mask_pattern("token")
    second = _get_mask_pattern("token")
    assert first is second


def test_mask_sensitive_data_recursive() -> None:
    masked = mask_sensitive_data(
        {
            "password": "secret",
            "nested": {"token": "abc", "ok": "v"},
            "list": [{"apiKey": "x"}, "plain"],
            "value": 1,
        },
        frozenset({"password", "token", "apikey"}),
    )
    assert masked["password"] == "***MASKED***"
    assert masked["nested"]["token"] == "***MASKED***"
    assert masked["nested"]["ok"] == "v"
    assert masked["list"][0]["apiKey"] == "***MASKED***"
    assert masked["list"][1] == "plain"
    assert masked["value"] == 1


def test_mask_sensitive_data_string_and_exception() -> None:
    text = 'Authorization="Bearer abc" and password=secret'
    fields = frozenset({"authorization", "password"})
    masked_text = mask_sensitive_data(text, fields)
    assert "***MASKED***" in masked_text
    assert mask_exception_message(text, fields).count("***MASKED***") >= 1


@pytest.mark.asyncio
async def test_dispatch_disabled_bypasses_logging() -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=False),
        trust_forwarded_headers=False,
    )
    response = await middleware.dispatch(
        _request(), AsyncMock(return_value=JSONResponse({"ok": True}))
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_dispatch_exempt_path_bypasses_logging() -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=True),
        trust_forwarded_headers=False,
    )
    response = await middleware.dispatch(
        _request("/health"),
        AsyncMock(return_value=JSONResponse({"ok": True})),
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_dispatch_success_logs_end(caplog: pytest.LogCaptureFixture) -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=True),
        trust_forwarded_headers=False,
    )
    caplog.set_level(logging.INFO)

    ctx_token = set_request_context(RequestContext(user_id="user-1", issuer="iss"))
    try:
        response = await middleware.dispatch(
            _request(headers={"x-request-id": "req-1"}),
            AsyncMock(return_value=JSONResponse({"ok": True}, status_code=201)),
        )
    finally:
        reset_request_context(ctx_token)

    assert response.status_code == 201
    assert "REQUEST_START request_id=req-1" in caplog.text
    assert "REQUEST_END request_id=req-1 user_id=user-1" in caplog.text


@pytest.mark.asyncio
async def test_dispatch_sanitizes_request_and_user_ids(caplog: pytest.LogCaptureFixture) -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=True),
        trust_forwarded_headers=False,
    )
    caplog.set_level(logging.INFO)

    ctx_token = set_request_context(RequestContext(user_id="user-\n1", issuer="iss"))
    try:
        response = await middleware.dispatch(
            _request(headers={"x-request-id": "req-\n1"}),
            AsyncMock(return_value=JSONResponse({"ok": True}, status_code=200)),
        )
    finally:
        reset_request_context(ctx_token)

    assert response.status_code == 200
    assert "REQUEST_START request_id=req-_1" in caplog.text
    assert "REQUEST_END request_id=req-_1 user_id=user-_1" in caplog.text


@pytest.mark.asyncio
async def test_dispatch_exception_masks_error(caplog: pytest.LogCaptureFixture) -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=True),
        trust_forwarded_headers=False,
    )
    caplog.set_level(logging.ERROR)

    async def _raise(_: Request) -> JSONResponse:
        raise RuntimeError("authorization=Bearer very-secret-token")

    with pytest.raises(RuntimeError):
        await middleware.dispatch(_request(), _raise)

    assert "***MASKED***" in caplog.text


def test_mask_sensitive_data_depth_limit() -> None:
    """When nesting exceeds _MAX_MASK_DEPTH, return ***MASKED***."""
    from aws_cli_mcp.middleware.audit import _MAX_MASK_DEPTH

    # Build a structure deeper than _MAX_MASK_DEPTH
    data: dict = {"ok": "value"}
    for _ in range(_MAX_MASK_DEPTH + 1):
        data = {"nested": data}

    result = mask_sensitive_data(data, frozenset({"secret"}))
    # Walk down to the depth limit
    current = result
    for _ in range(_MAX_MASK_DEPTH):
        current = current["nested"]
    assert current == "***MASKED***"


def test_mask_sensitive_data_top_level_list_and_primitive() -> None:
    """Cover list, depth-limit and else branches at the top level of mask_sensitive_data."""
    from aws_cli_mcp.middleware.audit import _MAX_MASK_DEPTH

    fields = frozenset({"token"})

    # Top-level list
    masked_list = mask_sensitive_data([{"token": "x"}, "plain"], fields)
    assert masked_list[0]["token"] == "***MASKED***"
    assert masked_list[1] == "plain"

    # Top-level primitive (else branch)
    assert mask_sensitive_data(42, fields) == 42

    # Top-level depth overflow
    assert mask_sensitive_data({"a": 1}, fields, depth=_MAX_MASK_DEPTH) == "***MASKED***"


def test_public_mask_data_method() -> None:
    middleware = AuditMiddleware(
        AsyncMock(),
        AuditConfig(enabled=True),
        trust_forwarded_headers=False,
    )
    masked = middleware.mask_data({"secret": "value", "ok": "x"})
    assert masked["secret"] == "***MASKED***"
    assert masked["ok"] == "x"
