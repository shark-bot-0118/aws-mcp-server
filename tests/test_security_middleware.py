"""Tests for Security Middleware."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio(loop_scope="function")
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.testclient import TestClient

from aws_cli_mcp.auth.idp_config import SecurityConfig
from aws_cli_mcp.middleware.security import (
    PreAuthSecurityMiddleware,
    SlidingWindowRateLimiter,
    UserRateLimitMiddleware,
    get_client_ip,
)


def _create_security_config(
    rate_limit_per_ip: int = 100,
    rate_limit_per_user: int = 50,
    max_body_size_bytes: int = 10 * 1024 * 1024,  # 10MB
    max_header_size_bytes: int = 8 * 1024,  # 8KB
    request_timeout_seconds: float = 30.0,
) -> SecurityConfig:
    """Create test SecurityConfig."""
    return SecurityConfig(
        rate_limit_per_ip=rate_limit_per_ip,
        rate_limit_per_user=rate_limit_per_user,
        max_body_size_bytes=max_body_size_bytes,
        max_header_size_bytes=max_header_size_bytes,
        request_timeout_seconds=request_timeout_seconds,
    )


class TestSlidingWindowRateLimiter:
    """Tests for SlidingWindowRateLimiter."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self) -> None:
        """Requests within limit should be allowed."""
        limiter = SlidingWindowRateLimiter()

        for _ in range(5):
            assert await limiter.allow("test-key", 10) is True

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self) -> None:
        """Requests over limit should be blocked."""
        limiter = SlidingWindowRateLimiter()

        # Use up the limit
        for _ in range(5):
            assert await limiter.allow("test-key", 5) is True

        # Next request should be blocked
        assert await limiter.allow("test-key", 5) is False

    @pytest.mark.asyncio
    async def test_separate_keys(self) -> None:
        """Different keys should have separate limits."""
        limiter = SlidingWindowRateLimiter()

        # Use up limit for key1
        for _ in range(3):
            await limiter.allow("key1", 3)

        # key1 should be blocked
        assert await limiter.allow("key1", 3) is False

        # key2 should still be allowed
        assert await limiter.allow("key2", 3) is True


class TestGetClientIp:
    """Tests for get_client_ip function."""

    def test_x_forwarded_for(self) -> None:
        """X-Forwarded-For header should be used first."""
        request = MagicMock(spec=Request)
        request.headers = {"x-forwarded-for": "1.2.3.4, 5.6.7.8"}
        request.client = MagicMock(host="10.0.0.1")

        assert get_client_ip(request) == "1.2.3.4"

    def test_x_real_ip(self) -> None:
        """X-Real-IP should be used if X-Forwarded-For is missing."""
        request = MagicMock(spec=Request)
        request.headers = {"x-real-ip": "1.2.3.4"}
        request.client = MagicMock(host="10.0.0.1")

        assert get_client_ip(request) == "1.2.3.4"

    def test_client_host(self) -> None:
        """Client host should be used as fallback."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = MagicMock(host="1.2.3.4")

        assert get_client_ip(request) == "1.2.3.4"

    def test_unknown_when_no_client(self) -> None:
        """Should return 'unknown' when no client info available."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = None

        assert get_client_ip(request) == "unknown"


class TestPreAuthSecurityMiddleware:
    """Tests for PreAuthSecurityMiddleware."""

    def test_exempt_paths_bypass_security(self) -> None:
        """Exempt paths should bypass security checks."""
        config = _create_security_config(rate_limit_per_ip=1)

        async def app(scope, receive, send):
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)

        # Health endpoint should always work
        from starlette.testclient import TestClient
        client = TestClient(middleware)

        # Multiple requests to health should all succeed
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200

    def test_ip_rate_limit_applies_before_auth(self) -> None:
        """IP rate limiting should work even without authentication."""
        config = _create_security_config(rate_limit_per_ip=2)

        call_count = 0

        async def app(scope, receive, send):
            nonlocal call_count
            call_count += 1
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)
        client = TestClient(middleware)

        # First 2 requests should succeed
        response1 = client.get("/mcp")
        assert response1.status_code == 200

        response2 = client.get("/mcp")
        assert response2.status_code == 200

        # 3rd request should be rate limited
        response3 = client.get("/mcp")
        assert response3.status_code == 429
        assert response3.json()["error"] == "rate_limit_exceeded"

        # App should only have been called twice
        assert call_count == 2

    def test_body_size_limit(self) -> None:
        """Large bodies should be rejected."""
        config = _create_security_config(max_body_size_bytes=1 * 1024 * 1024)  # 1MB limit

        async def app(scope, receive, send):
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)
        client = TestClient(middleware)

        # Request with too large body should be rejected
        # Note: We're testing via Content-Length header check
        response = client.post(
            "/mcp",
            content="x" * 100,  # Small content
            headers={"Content-Length": str(2 * 1024 * 1024)}  # Claim 2MB
        )
        assert response.status_code == 413
        assert response.json()["error"] == "request_too_large"

    def test_header_size_limit(self) -> None:
        """Large headers should be rejected."""
        config = _create_security_config(max_header_size_bytes=1 * 1024)  # 1KB limit

        async def app(scope, receive, send):
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)
        client = TestClient(middleware)

        # Request with too large headers should be rejected
        large_header = "x" * 2000  # 2KB header value
        response = client.get("/mcp", headers={"X-Large-Header": large_header})
        assert response.status_code == 431
        assert response.json()["error"] == "headers_too_large"

    def test_chunked_transfer_body_size_limit(self) -> None:
        """Chunked transfer encoding should not bypass body size limit."""
        config = _create_security_config(max_body_size_bytes=100)  # 100 bytes limit

        call_count = 0

        async def app(scope, receive, send):
            nonlocal call_count
            call_count += 1
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)
        # Reset rate limiter to avoid interference
        middleware.rate_limiter = SlidingWindowRateLimiter()

        client = TestClient(middleware)

        # Request with chunked encoding (no Content-Length) exceeding limit
        # TestClient automatically handles this, but we simulate by sending
        # a POST without explicit Content-Length header
        large_body = "x" * 200  # 200 bytes > 100 byte limit
        response = client.post(
            "/mcp",
            content=large_body,
            headers={"Transfer-Encoding": "chunked"},
        )
        assert response.status_code == 413
        assert response.json()["error"] == "request_too_large"
        # App should not have been called
        assert call_count == 0

    def test_post_without_content_length_enforces_limit(self) -> None:
        """POST without Content-Length should still enforce body size limit."""
        config = _create_security_config(max_body_size_bytes=50)  # 50 bytes limit

        call_count = 0

        async def app(scope, receive, send):
            nonlocal call_count
            call_count += 1
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = PreAuthSecurityMiddleware(app, config)
        middleware.rate_limiter = SlidingWindowRateLimiter()

        client = TestClient(middleware)

        # Small body should succeed
        small_body = "x" * 30
        response = client.post("/mcp", content=small_body)
        assert response.status_code == 200
        assert call_count == 1

        # Large body should fail
        large_body = "x" * 100
        response = client.post("/mcp", content=large_body)
        assert response.status_code == 413
        assert call_count == 1  # Not incremented


class TestUserRateLimitMiddleware:
    """Tests for UserRateLimitMiddleware."""

    def test_user_rate_limit_requires_user_id(self) -> None:
        """User rate limit should only apply when user_id is set."""
        config = _create_security_config(rate_limit_per_user=2)

        call_count = 0

        async def app(scope, receive, send):
            nonlocal call_count
            call_count += 1
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = UserRateLimitMiddleware(app, config)
        client = TestClient(middleware)

        # Without user_id, requests should not be user-rate-limited
        for _ in range(10):
            response = client.get("/mcp")
            assert response.status_code == 200

        # All 10 requests should have gone through
        assert call_count == 10

    def test_exempt_paths_bypass_user_rate_limit(self) -> None:
        """Exempt paths should bypass user rate limiting."""
        config = _create_security_config(rate_limit_per_user=1)

        async def app(scope, receive, send):
            # Set user_id on request state
            request = Request(scope, receive, send)
            request.state.user_id = "test-user"
            response = JSONResponse({"status": "ok"})
            await response(scope, receive, send)

        middleware = UserRateLimitMiddleware(app, config)
        client = TestClient(middleware)

        # Health endpoint should always work even with user_id
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200


class TestMiddlewareOrder:
    """Tests for correct middleware ordering."""

    def test_preauth_runs_before_auth_failure(self) -> None:
        """PreAuthSecurity should run even when auth will fail."""
        # This test verifies that IP rate limiting works for failed auth attempts

        preauth_config = _create_security_config(rate_limit_per_ip=2)

        preauth_called = 0
        auth_called = 0

        async def mock_auth_middleware(scope, receive, send):
            nonlocal auth_called
            auth_called += 1
            # Simulate auth failure
            response = JSONResponse(
                status_code=401,
                content={"error": "invalid_token"}
            )
            await response(scope, receive, send)

        async def count_preauth(scope, receive, send):
            nonlocal preauth_called
            preauth_called += 1
            # Forward to auth middleware
            await mock_auth_middleware(scope, receive, send)

        # Stack: PreAuthSecurity -> Auth (which fails)
        # Create middleware with fresh rate limiter to avoid cross-test pollution
        middleware = PreAuthSecurityMiddleware(count_preauth, preauth_config)
        # Reset the shared rate limiter for this test
        middleware.rate_limiter = SlidingWindowRateLimiter()

        client = TestClient(middleware)

        # First 2 requests hit auth (which fails)
        response1 = client.get("/mcp")
        assert response1.status_code == 401
        assert preauth_called == 1
        assert auth_called == 1

        response2 = client.get("/mcp")
        assert response2.status_code == 401
        assert preauth_called == 2
        assert auth_called == 2

        # 3rd request should be rate limited BEFORE reaching auth
        response3 = client.get("/mcp")
        assert response3.status_code == 429
        # When rate limited, the inner app (count_preauth) is NOT called
        # because PreAuthSecurityMiddleware returns early
        assert preauth_called == 2  # Inner app NOT called (rate limited)
        assert auth_called == 2  # Auth NOT called (rate limited)
        assert response3.json()["error"] == "rate_limit_exceeded"
