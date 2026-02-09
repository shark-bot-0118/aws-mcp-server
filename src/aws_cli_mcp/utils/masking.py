"""Shared sensitive-field masking utilities.

Provides ``redact_sensitive_fields`` — a recursive, depth-limited function
that replaces values whose keys match known sensitive markers.

Both ``tools._helpers._redact`` and ``middleware.audit.mask_sensitive_data``
delegate to this function so the masking logic is defined once.
"""

from __future__ import annotations

_MAX_REDACT_DEPTH = 20

# Canonical list of sensitive key markers (substring match, case-insensitive).
SENSITIVE_KEY_MARKERS: list[str] = [
    "password",
    "secret",
    "token",
    "accesskey",
    "secretaccesskey",
    "sessiontoken",
    "clientsecret",
    "apikey",
    "credential",
    "authorization",
]


def redact_sensitive_fields(
    value: object,
    *,
    mask: str = "***",
    depth: int = 0,
    max_depth: int = _MAX_REDACT_DEPTH,
) -> object:
    """Recursively replace sensitive values in dicts/lists.

    Keys are matched by *substring* against ``SENSITIVE_KEY_MARKERS``
    (case-insensitive).  When ``max_depth`` is exceeded the entire
    sub-tree is replaced with *mask*.
    """
    if depth >= max_depth:
        return mask
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, val in value.items():
            if any(marker in key.lower() for marker in SENSITIVE_KEY_MARKERS):
                redacted[key] = mask
            else:
                redacted[key] = redact_sensitive_fields(
                    val, mask=mask, depth=depth + 1, max_depth=max_depth,
                )
        return redacted
    if isinstance(value, list):
        return [
            redact_sensitive_fields(
                item, mask=mask, depth=depth + 1, max_depth=max_depth,
            )
            for item in value
        ]
    return value
