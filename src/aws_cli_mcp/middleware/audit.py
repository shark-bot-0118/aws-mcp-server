"""Audit logging middleware with sensitive field masking."""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..auth.context import SENSITIVE_FIELDS, get_request_context_optional
from ..auth.idp_config import AuditConfig
from ..middleware.security import get_client_ip

logger = logging.getLogger(__name__)

# Compile regex patterns for masking
_MASK_PATTERNS: dict[str, re.Pattern] = {}


def _get_mask_pattern(field: str) -> re.Pattern:
    """Get or create regex pattern for field masking."""
    if field not in _MASK_PATTERNS:
        # Match field in JSON-like strings: "field": "value" or 'field': 'value'
        _MASK_PATTERNS[field] = re.compile(
            rf'(["\']?{re.escape(field)}["\']?\s*[:=]\s*)["\']?[^"\']*["\']?',
            re.IGNORECASE,
        )
    return _MASK_PATTERNS[field]


def mask_sensitive_data(data: Any, mask_fields: frozenset[str]) -> Any:
    """
    Recursively mask sensitive fields in data structures.

    Handles:
    - Dictionaries: masks values of sensitive keys
    - Lists: recursively processes items
    - Strings: masks patterns like "field": "value"
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            lower_key = key.lower()
            if lower_key in mask_fields or any(f in lower_key for f in mask_fields):
                result[key] = "***MASKED***"
            else:
                result[key] = mask_sensitive_data(value, mask_fields)
        return result
    elif isinstance(data, list):
        return [mask_sensitive_data(item, mask_fields) for item in data]
    elif isinstance(data, str):
        # Mask patterns in strings
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
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        start_time = time.time()

        # Get client info
        client_ip = get_client_ip(
            request,
            trust_forwarded_headers=self._trust_forwarded_headers,
        )

        # Log request start
        logger.info(
            "REQUEST_START request_id=%s method=%s path=%s client_ip=%s",
            request_id,
            request.method,
            request.url.path,
            client_ip,
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

            # Log request end
            if error_message:
                logger.error(
                    "REQUEST_END request_id=%s user_id=%s method=%s path=%s "
                    "status=%s duration_ms=%d error=%s",
                    request_id,
                    user_id,
                    request.method,
                    request.url.path,
                    status_code,
                    duration_ms,
                    error_message,
                )
            else:
                logger.info(
                    "REQUEST_END request_id=%s user_id=%s method=%s path=%s "
                    "status=%s duration_ms=%d",
                    request_id,
                    user_id,
                    request.method,
                    request.url.path,
                    status_code,
                    duration_ms,
                )

    def mask_data(self, data: Any) -> Any:
        """Public method to mask sensitive data (for external use)."""
        return mask_sensitive_data(data, self._mask_fields)
