"""Tests for IdentityCenterAuthMiddleware."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from aws_cli_mcp.auth.identity_center_middleware import IdentityCenterAuthMiddleware, is_exempt_path
from aws_cli_mcp.auth.multi_user_guard import MultiUserViolationError


class TestIsExemptPath:
    """Tests for is_exempt_path."""

    def test_exact_matches(self) -> None:
        """Exact path matches should be exempt."""
        assert is_exempt_path("/health") is True
        assert is_exempt_path("/ready") is True

    def test_prefix_matches(self) -> None:
        """Prefix matches should be exempt."""
        assert is_exempt_path("/.well-known/openid-configuration") is True
        assert is_exempt_path("/.well-known/oauth-protected-resource") is True

    def test_non_exempt_paths(self) -> None:
        """Regular paths should not be exempt."""
        assert is_exempt_path("/") is False
        assert is_exempt_path("/mcp") is False
        assert is_exempt_path("/api/v1/resource") is False


class TestIdentityCenterAuthMiddleware:
    """Tests for IdentityCenterAuthMiddleware."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create a TestClient with the middleware."""

        async def homepage(request: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "status": "ok",
                    "user_id": request.state.access_token
                    if hasattr(request.state, "access_token")
                    else None,
                }
            )

        app = Starlette(
            routes=[
                Route("/mcp", homepage),
                Route("/health", homepage),
                Route("/.well-known/openid-configuration", homepage),
            ]
        )
        # We need to wrap the app with the middleware manually for testing different configs
        return TestClient(app)

    def test_exempt_path_bypass(self) -> None:
        """Exempt paths should bypass auth check."""

        async def homepage(request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        app = Starlette(routes=[Route("/health", homepage)])
        app.add_middleware(IdentityCenterAuthMiddleware)

        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

    def test_missing_auth_header(self) -> None:
        """Missing Authorization header should return 401."""

        async def endpoint(request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        app = Starlette(routes=[Route("/mcp", endpoint)])
        app.add_middleware(IdentityCenterAuthMiddleware)

        with TestClient(app) as client:
            response = client.get("/mcp")
            assert response.status_code == 401
            data = response.json()
            assert data["error"] == "unauthorized"
            assert data["error_code"] == "missing_access_token"

    def test_invalid_auth_header_scheme(self) -> None:
        """Non-Bearer auth header should return 401."""

        async def endpoint(request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        app = Starlette(routes=[Route("/mcp", endpoint)])
        app.add_middleware(IdentityCenterAuthMiddleware)

        with TestClient(app) as client:
            response = client.get("/mcp", headers={"Authorization": "Basic 123"})
            assert response.status_code == 401
            assert response.json()["error_code"] == "missing_access_token"

    def test_valid_auth_success(self) -> None:
        """Valid Bearer token should set context and proceed."""

        async def endpoint(request: Request) -> JSONResponse:
            from aws_cli_mcp.auth.context import get_request_context

            ctx = get_request_context()
            return JSONResponse(
                {
                    "status": "ok",
                    "user_id": ctx.user_id if ctx else None,
                    "token": ctx.access_token if ctx else None,
                    "state_user_id": getattr(request.state, "user_id", None),
                }
            )

        app = Starlette(routes=[Route("/mcp", endpoint)])
        app.add_middleware(IdentityCenterAuthMiddleware, allow_multi_user=True)

        token = "valid_token"
        with TestClient(app) as client:
            response = client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            data = response.json()
            assert data["token"] == token
            assert data["user_id"] is not None
            assert data["state_user_id"] == data["user_id"]

    def test_multi_user_violation(self) -> None:
        """Should return 403 on subsequent user with allow_multi_user=False."""

        async def endpoint(request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})

        app = Starlette(routes=[Route("/mcp", endpoint)])
        app.add_middleware(IdentityCenterAuthMiddleware, allow_multi_user=False)

        from unittest.mock import patch

        # We need to patch where it's used
        with patch(
            "aws_cli_mcp.auth.identity_center_middleware.enforce_single_user_mode"
        ) as mock_enforce:
            mock_enforce.side_effect = MultiUserViolationError("Different user")

            with TestClient(app) as client:
                response = client.get("/mcp", headers={"Authorization": "Bearer token2"})

                assert response.status_code == 403
                assert response.json()["error"] == "multi_user_disabled"
