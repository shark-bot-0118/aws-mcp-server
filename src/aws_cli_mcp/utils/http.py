"""Shared HTTP utilities."""

from __future__ import annotations


def first_forwarded_value(value: str | None) -> str | None:
    """Extract the first value from a comma-separated forwarded header.

    Used with X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, etc.
    """
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None
