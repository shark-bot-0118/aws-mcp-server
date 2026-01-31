"""Time helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()
