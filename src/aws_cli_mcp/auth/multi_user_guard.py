"""Process-local guard for single-user mode."""

from __future__ import annotations

import threading


class MultiUserViolationError(RuntimeError):
    """Raised when a different principal is blocked in single-user mode."""


class _SinglePrincipalGuard:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active_principal: str | None = None

    def enforce(self, principal: str, allow_multi_user: bool) -> None:
        if allow_multi_user:
            return

        with self._lock:
            if self._active_principal is None:
                self._active_principal = principal
                return
            if self._active_principal != principal:
                raise MultiUserViolationError(
                    "Multiple principals are disabled by server policy. "
                    "Set AUTH_ALLOW_MULTI_USER=true to allow this mode."
                )


_guard = _SinglePrincipalGuard()


def enforce_single_user_mode(*, user_id: str, issuer: str, allow_multi_user: bool) -> None:
    principal = f"{issuer}:{user_id}"
    _guard.enforce(principal, allow_multi_user)
