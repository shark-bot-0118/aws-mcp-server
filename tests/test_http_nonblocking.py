from __future__ import annotations

import asyncio
from types import SimpleNamespace


def test_http_mode_uses_to_thread_for_blocking_io(monkeypatch):
    from aws_cli_mcp.tools.aws_unified import _run_blocking

    calls = {"count": 0}

    async def fake_to_thread(func, *args, **kwargs):
        calls["count"] += 1
        return func(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)
    ctx = SimpleNamespace(
        settings=SimpleNamespace(
            server=SimpleNamespace(transport_mode="http"),
        )
    )

    result = asyncio.run(_run_blocking(ctx, lambda x: x + 1, 41))

    assert result == 42
    assert calls["count"] == 1
