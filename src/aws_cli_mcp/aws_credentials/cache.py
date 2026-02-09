"""Credential cache with async refresh support."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from aws_cli_mcp.aws_credentials.sts_provider import TemporaryCredentials


@dataclass(frozen=True)
class CacheKey:
    user_id: str
    account_id: str
    role_arn: str
    token_hash: str = ""


@dataclass
class CacheEntry:
    credentials: TemporaryCredentials
    cached_at: datetime

    @property
    def expiration(self) -> datetime:
        return self.credentials.expiration

    def is_expiring_soon(self, buffer_seconds: int) -> bool:
        exp = self.expiration
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc) + timedelta(seconds=buffer_seconds)

    @classmethod
    def from_credentials(cls, creds: TemporaryCredentials) -> "CacheEntry":
        return cls(credentials=creds, cached_at=datetime.now(timezone.utc))


class CredentialCache:
    """Async credential cache with single-flight refresh."""

    def __init__(self, refresh_buffer_seconds: int, max_entries: int) -> None:
        self._refresh_buffer_seconds = refresh_buffer_seconds
        self._max_entries = max_entries
        self._cache: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._in_flight: dict[CacheKey, asyncio.Future[TemporaryCredentials]] = {}
        self._lock = asyncio.Lock()

    async def get_or_refresh(
        self,
        key: CacheKey,
        refresh_fn: Callable[[], Awaitable[TemporaryCredentials]],
    ) -> TemporaryCredentials:
        async with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.is_expiring_soon(self._refresh_buffer_seconds):
                self._cache.move_to_end(key)
                return entry.credentials

            in_flight = self._in_flight.get(key)
            if in_flight is None:
                in_flight = asyncio.get_running_loop().create_future()
                self._in_flight[key] = in_flight
                should_refresh = True
            else:
                should_refresh = False

        if not should_refresh:
            return await in_flight

        try:
            creds = await refresh_fn()
        except BaseException as exc:
            async with self._lock:
                future = self._in_flight.pop(key, None)
                if future and not future.done():
                    future.set_exception(exc)
            raise

        async with self._lock:
            self._cache[key] = CacheEntry.from_credentials(creds)
            self._cache.move_to_end(key)
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)

            future = self._in_flight.pop(key, None)
            if future and not future.done():
                future.set_result(creds)

        return creds
