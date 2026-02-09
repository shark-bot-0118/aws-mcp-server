from __future__ import annotations

import asyncio
import contextlib
import os

import pytest


def pytest_sessionstart(session: pytest.Session) -> None:
    # Prevent network-dependent Smithy sync during unit test runs.
    os.environ.setdefault("SMITHY_AUTO_SYNC", "false")


@pytest.fixture(autouse=True)
def _close_default_event_loop() -> None:
    yield
    policy = asyncio.get_event_loop_policy()
    local = getattr(policy, "_local", None)
    loop = getattr(local, "_loop", None) if local is not None else None
    if loop is not None and not loop.is_running() and not loop.is_closed():
        with contextlib.suppress(Exception):
            loop.close()
    if loop is not None:
        with contextlib.suppress(Exception):
            policy.set_event_loop(None)
