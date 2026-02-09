"""Security middleware for rate limiting, size limits, and timeouts."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..auth.idp_config import SecurityConfig

logger = logging.getLogger(__name__)

_SECURITY_EXEMPT_PATHS = frozenset(
    {
        "/health",
        "/ready",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    }
)


class BodySizeLimitExceeded(Exception):
    """Raised when request body exceeds size limit."""

    pass


@dataclass
class RateLimitBucket:
    """Sliding window rate limit bucket."""

    timestamps: list[float] = field(default_factory=list)

    def cleanup(self, now: float, window_seconds: float) -> None:
        """Cleanup timestamps outside of the active window."""
        cutoff = now - window_seconds
        self.timestamps = [t for t in self.timestamps if t > cutoff]

    def add_request(self, now: float) -> None:
        self.timestamps.append(now)

    def count(self) -> int:
        return len(self.timestamps)


class SlidingWindowRateLimiter:
    """Sliding window rate limiter."""

    _CLEANUP_INTERVAL: float = 60.0  # Run cleanup at most every 60 seconds
    _BUCKET_MAX_AGE: float = 300.0  # Remove buckets idle for 5 minutes

    def __init__(self) -> None:
        self._buckets: dict[str, RateLimitBucket] = defaultdict(RateLimitBucket)
        self._window_seconds: float = 60.0  # 1 minute window
        self._lock = asyncio.Lock()
        self._last_cleanup: float = 0.0

    async def allow(self, key: str, limit: int) -> bool:
        """Check if request is allowed under rate limit."""
        async with self._lock:
            now = time.time()

            # Periodic cleanup to prevent unbounded growth
            if now - self._last_cleanup > self._CLEANUP_INTERVAL:
                self._cleanup_old_buckets_unlocked(now)
                self._last_cleanup = now

            bucket = self._buckets[key]
            bucket.cleanup(now, self._window_seconds)

            if bucket.count() >= limit:
                return False

            bucket.add_request(now)
            return True

    def _cleanup_old_buckets_unlocked(self, now: float) -> None:
        """Remove buckets with no recent activity. Must be called under lock."""
        cutoff = now - self._BUCKET_MAX_AGE
        keys_to_remove = [
            key
            for key, bucket in self._buckets.items()
            if not bucket.timestamps or max(bucket.timestamps) < cutoff
        ]
        for key in keys_to_remove:
            del self._buckets[key]


# Shared rate limiter instance for both middlewares.
# WARNING: This is a process-local singleton. With Uvicorn --workers N (N > 1),
# each worker maintains an independent counter. Effective per-IP/per-user limits
# become limit * N in aggregate. Deploy with workers=1 or use an external
# rate-limit store (e.g. Redis) for strict enforcement.
_shared_rate_limiter = SlidingWindowRateLimiter()


def _sanitize_ip(value: str) -> str:
    """Strip control characters from an IP string to prevent log injection."""
    # Only allow printable ASCII minus common injection chars.
    return "".join(c for c in value if 0x20 <= ord(c) < 0x7F)


def get_client_ip(request: Request, trust_forwarded_headers: bool = False) -> str:
    """Get client IP with optional trusted proxy header support."""
    if trust_forwarded_headers:
        # Check X-Forwarded-For (from reverse proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP (original client), sanitise user-controlled value.
            return _sanitize_ip(forwarded_for.split(",")[0].strip())

        # Check X-Real-IP
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return _sanitize_ip(real_ip.strip())

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "unknown"


def _request_too_large_response(max_body_size_bytes: int) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={
            "error": "request_too_large",
            "message": f"Request body exceeds {max_body_size_bytes} bytes",
        },
    )


class PreAuthSecurityMiddleware(BaseHTTPMiddleware):
    """
    Pre-authentication security middleware.

    Runs BEFORE authentication to protect against DoS attacks.

    Features:
    - Request body size limit
    - Header size limit
    - IP-based rate limiting
    - Request timeout

    NOTE: TLS check is NOT performed here.
    HTTPS termination is assumed to be handled by ingress/LB.
    """

    # Paths exempt from security checks
    EXEMPT_PATHS = _SECURITY_EXEMPT_PATHS

    def __init__(
        self,
        app: Callable,
        config: SecurityConfig,
        trust_forwarded_headers: bool = False,
    ) -> None:
        super().__init__(app)
        self.config = config
        self.rate_limiter = _shared_rate_limiter
        self._trust_forwarded_headers = trust_forwarded_headers

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with pre-auth security checks."""
        # Skip security for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # 1. Request size check
        # Content-Length check is a fast-path only. For body-carrying methods and
        # chunked transfer, we always enforce a streaming limit to prevent bypass
        # via mismatched/forged Content-Length.
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size < 0:
                    raise ValueError("negative content-length")
                if size > self.config.max_body_size_bytes:
                    logger.warning(
                        "Request body too large: %d > %d",
                        size,
                        self.config.max_body_size_bytes,
                    )
                    return _request_too_large_response(self.config.max_body_size_bytes)
            except ValueError:
                logger.warning("Invalid Content-Length header: %r", content_length)

        transfer_encoding = request.headers.get("transfer-encoding", "").lower()
        should_stream_check = "chunked" in transfer_encoding or request.method in (
            "POST",
            "PUT",
            "PATCH",
        )
        if should_stream_check:
            try:
                # Use streaming read with early termination.
                body_size = await self._check_body_size_streaming(
                    request, self.config.max_body_size_bytes
                )
                if body_size > self.config.max_body_size_bytes:
                    logger.warning(
                        "Request body too large (stream): %d > %d",
                        body_size,
                        self.config.max_body_size_bytes,
                    )
                    return _request_too_large_response(self.config.max_body_size_bytes)
            except BodySizeLimitExceeded:
                logger.warning("Request body exceeded limit during streaming")
                return _request_too_large_response(self.config.max_body_size_bytes)
            except Exception as exc:
                logger.warning("Failed to read request body: %s", exc)
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "message": "Failed to read request body",
                    },
                )

        # 2. Header size check
        total_header_size = sum(len(k) + len(v) for k, v in request.headers.items())
        if total_header_size > self.config.max_header_size_bytes:
            logger.warning(
                "Headers too large: %d > %d",
                total_header_size,
                self.config.max_header_size_bytes,
            )
            return JSONResponse(
                status_code=431,
                content={
                    "error": "headers_too_large",
                    "message": f"Headers exceed {self.config.max_header_size_bytes} bytes",
                },
            )

        # 3. IP-based rate limiting
        client_ip = get_client_ip(
            request,
            trust_forwarded_headers=self._trust_forwarded_headers,
        )
        ip_key = f"ip:{client_ip}"
        if not await self.rate_limiter.allow(ip_key, self.config.rate_limit_per_ip):
            logger.warning("Rate limit exceeded for IP: %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests from this IP",
                },
                headers={"Retry-After": "60"},
            )

        # 4. Request timeout
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=self.config.request_timeout_seconds,
            )
            return response
        except asyncio.TimeoutError:
            logger.error("Request timeout after %s seconds", self.config.request_timeout_seconds)
            return JSONResponse(
                status_code=504,
                content={
                    "error": "request_timeout",
                    "message": (
                        f"Request timed out after {self.config.request_timeout_seconds} seconds"
                    ),
                },
            )

    async def _check_body_size_streaming(self, request: Request, max_size: int) -> int:
        """Read body with streaming size check, failing early if limit exceeded.

        Uses a ``bytearray`` buffer instead of a list of chunks to avoid
        the peak-memory spike caused by ``b"".join(chunks)`` (which
        temporarily holds both the chunk list and the joined copy).
        """
        buf = bytearray()
        async for chunk in request.stream():
            buf.extend(chunk)
            if len(buf) > max_size:
                # Fail early - don't read more than needed
                raise BodySizeLimitExceeded(f"Body exceeded {max_size} bytes")
        # Cache the body so downstream handlers can read it
        request._body = bytes(buf)
        return len(buf)


class UserRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Post-authentication user rate limit middleware.

    Runs AFTER authentication to enforce per-user rate limits.
    Requires user_id to be set on request.state by auth middleware.
    """

    # Paths exempt from user rate limiting
    EXEMPT_PATHS = _SECURITY_EXEMPT_PATHS

    def __init__(
        self,
        app: Callable,
        config: SecurityConfig,
    ) -> None:
        super().__init__(app)
        self.config = config
        self.rate_limiter = _shared_rate_limiter

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with user rate limiting."""
        # Skip for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # User-based rate limit (if user is authenticated)
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            user_key = f"user:{user_id}"
            if not await self.rate_limiter.allow(user_key, self.config.rate_limit_per_user):
                logger.warning("Rate limit exceeded for user: %s", user_id)
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests from this user",
                    },
                    headers={"Retry-After": "60"},
                )

        return await call_next(request)
