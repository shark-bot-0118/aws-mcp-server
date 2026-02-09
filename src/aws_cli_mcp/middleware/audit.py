"""Audit logging middleware with sensitive field masking."""

from __future__ import annotations

import logging
import re
import time
import uuid
from functools import lru_cache
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..auth.context import SENSITIVE_FIELDS, get_request_context_optional
from ..auth.idp_config import AuditConfig
from ..middleware.security import get_client_ip
from ..utils.masking import redact_sensitive_fields

logger = logging.getLogger(__name__)

_MAX_MASK_DEPTH = 20

# Control character pattern for log injection prevention.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _sanitize_log_value(value: str) -> str:
    """Replace control characters (newlines, tabs, etc.) to prevent log injection."""
    return _CONTROL_CHAR_RE.sub("_", value)


@lru_cache(maxsize=128)
def _get_mask_pattern(field: str) -> re.Pattern:
    """Get or create regex pattern for field masking."""
    return re.compile(
        rf'(["\']?{re.escape(field)}["\']?\s*[:=]\s*)["\']?[^"\']*["\']?',
        re.IGNORECASE,
    )


def mask_sensitive_data(data: Any, mask_fields: frozenset[str], depth: int = 0) -> Any:
    """Recursively mask sensitive fields in data structures.

    Delegates dict/list masking to the shared ``redact_sensitive_fields``
    utility.  String-level regex masking (for log messages) remains here.
    """
    if depth >= _MAX_MASK_DEPTH:
        return "***MASKED***"
    if isinstance(data, dict):
        return redact_sensitive_fields(
            data, mask="***MASKED***", depth=depth, max_depth=_MAX_MASK_DEPTH,
        )
    elif isinstance(data, list):
        return [mask_sensitive_data(item, mask_fields, depth + 1) for item in data]
    elif isinstance(data, str):
        masked = data
        for field in mask_fields:
            pattern = _get_mask_pattern(field)
            masked = pattern.sub(r"\1***MASKED***", masked)
        return masked
    else:
        return data


def mask_exception_message(message: str, mask_fields: frozenset[str]) -> str:
    """Mask sensitive data in exception messages."""
    masked = message
    for field in mask_fields:
        pattern = _get_mask_pattern(field)
        masked = pattern.sub(r"\1***MASKED***", masked)
    return masked


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Audit logging middleware.

    Features:
    - Logs user_id, operation, timestamp, result
    - Masks sensitive fields (access_token, password, etc.)
    - Masks sensitive data in exception messages
    """

    # Paths exempt from audit logging
    EXEMPT_PATHS = frozenset({"/health", "/ready"})

    def __init__(
        self,
        app: Callable,
        config: AuditConfig,
        trust_forwarded_headers: bool = False,
    ) -> None:
        super().__init__(app)
        self.config = config
        self._mask_fields = frozenset(f.lower() for f in config.mask_fields) | SENSITIVE_FIELDS
        self._trust_forwarded_headers = trust_forwarded_headers

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with audit logging."""
        if not self.config.enabled:
            return await call_next(request)

        # Skip audit for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Generate request ID if not present
        request_id = _sanitize_log_value(request.headers.get("x-request-id", str(uuid.uuid4())))
        start_time = time.time()

        # Get client info
        client_ip = get_client_ip(
            request,
            trust_forwarded_headers=self._trust_forwarded_headers,
        )

        # Sanitize user-controlled values to prevent log injection.
        safe_path = _sanitize_log_value(request.url.path)
        safe_ip = _sanitize_log_value(client_ip)

        # Log request start
        logger.info(
            "REQUEST_START request_id=%s method=%s path=%s client_ip=%s",
            request_id,
            request.method,
            safe_path,
            safe_ip,
        )

        error_message: str | None = None
        status_code: int = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response

        except Exception as e:
            error_message = mask_exception_message(str(e), self._mask_fields)
            raise

        finally:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Get user info from context (if authenticated)
            user_id = "anonymous"
            ctx = get_request_context_optional()
            if ctx:
                user_id = ctx.user_id
            safe_user_id = _sanitize_log_value(user_id)

            # Log request end
            if error_message:
                logger.error(
                    "REQUEST_END request_id=%s user_id=%s method=%s path=%s "
                    "status=%s duration_ms=%d error=%s",
                    request_id,
                    safe_user_id,
                    request.method,
                    safe_path,
                    status_code,
                    duration_ms,
                    error_message,
                )
            else:
                logger.info(
                    "REQUEST_END request_id=%s user_id=%s method=%s path=%s "
                    "status=%s duration_ms=%d",
                    request_id,
                    safe_user_id,
                    request.method,
                    safe_path,
                    status_code,
                    duration_ms,
                )

    def mask_data(self, data: Any) -> Any:
        """Public method to mask sensitive data (for external use)."""
        return mask_sensitive_data(data, self._mask_fields)
