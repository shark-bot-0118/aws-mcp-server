from __future__ import annotations

import asyncio


def test_http_mode_uses_to_thread_for_blocking_io(monkeypatch):
    from aws_cli_mcp import config as config_module
    from aws_cli_mcp.app import get_app_context
    from aws_cli_mcp.tools.aws_unified import execute_operation

    monkeypatch.setenv("TRANSPORT_MODE", "http")
    config_module._load_settings_cached.cache_clear()
    get_app_context.cache_clear()

    calls = {"count": 0}

    async def fake_to_thread(func, *args, **kwargs):
        calls["count"] += 1
        return func(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    payload = {
        "action": "validate",
        "service": "s3",
        "operation": "ListBuckets",
        "payload": {},
    }
    result = asyncio.run(execute_operation(payload))

    assert result is not None
    assert calls["count"] >= 1
