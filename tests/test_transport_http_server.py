import asyncio
import json
from contextlib import closing
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from aws_cli_mcp.auth.context import RequestContext, reset_request_context, set_request_context
from aws_cli_mcp.transport.http_server import (
    MultiIdPAuthMiddleware,
    MultiIdPAWSCredentialMiddleware,
    create_http_app,
)


# Mock Settings
@pytest.fixture
def mock_settings():
    with patch("aws_cli_mcp.transport.http_server.load_settings") as mock_load:
        settings = MagicMock()
        settings.auth.provider = "multi-idp"
        settings.auth.idp_config_path = "/path/to/config.yaml"
        settings.server.http_trust_forwarded_headers = False
        settings.auth.credential_refresh_buffer_seconds = 300
        settings.auth.credential_cache_max_entries = 100
        settings.auth.rate_limit_per_user = 100
        settings.auth.rate_limit_per_ip = 1000
        settings.auth.max_body_size_mb = 10
        settings.auth.max_header_size_kb = 8
        settings.auth.request_timeout_seconds = 30.0
        settings.auth.audit_enabled = True
        settings.aws.sts_region = "us-east-1"
        settings.auth.allow_multi_user = False
        settings.server.http_enable_cors = False
        settings.server.transport_mode = "http"
        settings.server.http_allowed_origins = []
        settings.server.http_allow_missing_origin = False
        settings.server.public_base_url = None
        mock_load.return_value = settings
        yield settings


@pytest.fixture
def mock_idp_config():
    with patch("aws_cli_mcp.auth.idp_config.load_idp_config") as mock_load:
        config = MagicMock()
        config.role_mappings = {}
        config.protected_resource.scopes_supported = ["scope1"]
        config.oauth_proxy.redirect_path = "/callback"
        config.security = MagicMock()
        config.security.max_body_size_bytes = 100000
        config.security.max_header_size_bytes = 8192
        config.security.request_timeout_seconds = 60
        config.security.rate_limit_per_ip = 100
        config.security.rate_limit_per_user = 100
        config.audit = MagicMock()
        mock_load.return_value = config
        yield config


@pytest.fixture
def mock_deps():
    with (
        patch("aws_cli_mcp.auth.multi_idp.MultiIdPValidator") as mock_validator,
        patch(
            "aws_cli_mcp.auth.protected_resource.create_protected_resource_endpoint"
        ) as mock_endpoint,
        patch("aws_cli_mcp.auth.oauth_proxy.create_oauth_proxy_broker") as mock_proxy,
        patch("aws_cli_mcp.auth.role_mapper.RoleMapper") as mock_mapper,
        patch("aws_cli_mcp.transport.http_server.CredentialCache") as mock_cache,
        patch("aws_cli_mcp.transport.http_server.STSCredentialProvider") as mock_sts,
    ):
        mock_endpoint.return_value.handle = AsyncMock(return_value=JSONResponse({"status": "ok"}))
        mock_proxy.return_value = None  # Disable oauth proxy for simple tests

        yield {
            "validator": mock_validator,
            "endpoint": mock_endpoint,
            "proxy": mock_proxy,
            "mapper": mock_mapper,
            "cache": mock_cache,
            "sts": mock_sts,
        }


def test_create_http_app_multi_idp(mock_settings, mock_idp_config, mock_deps):
    app = create_http_app()
    assert isinstance(app, Starlette)
    # Check routes
    routes = [r.path for r in app.routes]
    assert "/mcp" in routes
    assert "/health" in routes
    assert "/ready" in routes


def test_create_http_app_identity_center(mock_settings):
    mock_settings.auth.provider = "identity-center"
    mock_settings.auth.identity_center_region = "us-east-1"

    with patch("aws_cli_mcp.transport.http_server._create_identity_center_app") as mock_create:
        create_http_app()
        mock_create.assert_called_once()


def test_create_http_app_invalid_provider(mock_settings):
    mock_settings.auth.provider = "invalid"
    with pytest.raises(RuntimeError, match="Unsupported AUTH_PROVIDER"):
        create_http_app()


def test_create_http_app_remote_requires_public_base_url(
    mock_settings, mock_idp_config, mock_deps
):
    mock_settings.server.transport_mode = "remote"
    mock_settings.server.public_base_url = None
    with pytest.raises(RuntimeError, match="MCP_PUBLIC_BASE_URL is required"):
        create_http_app()


def test_health_ready_endpoints(mock_settings, mock_idp_config, mock_deps):
    app = create_http_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}

        resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}


def test_multi_idp_auth_middleware_missing_token():
    app = MagicMock()
    validator = MagicMock()
    middleware = MultiIdPAuthMiddleware(app, validator)

    request = Request(scope={"type": "http", "headers": [], "path": "/protected"})

    response = asyncio.run(middleware.dispatch(request, lambda r: None))
    assert isinstance(response, JSONResponse)
    assert response.status_code == 401
    assert json.loads(response.body)["error"] == "missing_token"


def test_multi_idp_auth_middleware_success():
    app = MagicMock()
    validator = AsyncMock()
    validator.validate.return_value = MagicMock(
        user_id="user1",
        issuer="iss1",
        email="e@mail.com",
        groups=[],
        expiry=None,
        jti=None,
        raw_claims={},
    )

    middleware = MultiIdPAuthMiddleware(app, validator)

    async def call_next(request):
        # Verify context is set
        from aws_cli_mcp.auth.context import get_request_context_optional

        ctx = get_request_context_optional()
        assert ctx is not None
        assert ctx.user_id == "user1"
        return JSONResponse({"status": "ok"})

    request = Request(
        scope={
            "type": "http",
            "headers": [(b"authorization", b"Bearer valid-token")],
            "path": "/protected",
        }
    )

    response = asyncio.run(middleware.dispatch(request, call_next))
    assert response.status_code == 200


def test_multi_idp_credential_middleware_no_context():
    app = MagicMock()
    mapper = MagicMock()
    cache = MagicMock()
    sts = MagicMock()

    middleware = MultiIdPAWSCredentialMiddleware(app, mapper, cache, sts)

    # Ensure no context
    from aws_cli_mcp.auth.context import _request_context

    token = _request_context.set(None)
    try:
        request = Request(
            scope={"type": "http", "path": "/protected", "headers": [(b"host", b"test")]}
        )
        response = asyncio.run(middleware.dispatch(request, lambda r: None))
        assert response.status_code == 401
        assert json.loads(response.body)["error"] == "no_context"
    finally:
        _request_context.reset(token)


def test_multi_idp_credential_middleware_success():
    app = MagicMock()
    mapper = MagicMock()

    # Mock resolved role
    mock_role = MagicMock()
    mock_role.account_id = "123456789012"
    mock_role.role_arn = "arn:aws:iam::123456789012:role/Role"
    mapper.resolve.return_value = mock_role

    cache = AsyncMock()
    mock_creds = MagicMock()
    mock_creds.access_key_id = "AKIA..."
    mock_creds.expiration = None
    cache.get_or_refresh.return_value = mock_creds

    sts = MagicMock()

    middleware = MultiIdPAWSCredentialMiddleware(app, mapper, cache, sts)

    # Set context
    ctx = RequestContext(user_id="user1", issuer="iss1")
    from aws_cli_mcp.auth.context import reset_request_context, set_request_context

    token = set_request_context(ctx)

    async def call_next(request):
        from aws_cli_mcp.auth.context import get_request_context

        ctx = get_request_context()
        assert ctx.aws_credentials is not None
        assert ctx.aws_credentials.access_key_id == "AKIA..."
        return JSONResponse({"status": "ok"})

    try:
        request = Request(
            scope={"type": "http", "path": "/protected", "headers": [(b"host", b"test")]}
        )
        response = asyncio.run(middleware.dispatch(request, call_next))
        assert response.status_code == 200
    finally:
        reset_request_context(token)


def test_multi_idp_credential_middleware_credential_error():
    app = MagicMock()
    mapper = MagicMock()
    resolved = MagicMock()
    resolved.account_id = "123456789012"
    resolved.role_arn = "arn:aws:iam::123456789012:role/Role"
    mapper.resolve.return_value = resolved

    cache = AsyncMock()
    cache.get_or_refresh.side_effect = RuntimeError("assume failed")
    sts = MagicMock()

    middleware = MultiIdPAWSCredentialMiddleware(app, mapper, cache, sts)

    token = set_request_context(
        RequestContext(user_id="user1", issuer="iss1", access_token="token")
    )
    try:
        request = Request(
            scope={
                "type": "http",
                "path": "/mcp",
                "headers": [(b"host", b"test")],
            }
        )
        response = asyncio.run(
            middleware.dispatch(request, AsyncMock(return_value=JSONResponse({"ok": True})))
        )
    finally:
        reset_request_context(token)

    assert response.status_code == 403
    payload = json.loads(response.body)
    assert payload["error"] == "credential_error"


def test_create_http_app_missing_idp_config_path(mock_settings):
    mock_settings.auth.provider = "multi-idp"
    mock_settings.auth.idp_config_path = None
    with pytest.raises(RuntimeError, match="AUTH_IDP_CONFIG_PATH is required"):
        create_http_app()


def test_create_http_app_with_cors(mock_settings, mock_idp_config, mock_deps):
    mock_settings.server.http_enable_cors = True
    mock_settings.server.http_allowed_origins = ["*"]

    with patch("starlette.middleware.cors.CORSMiddleware"):
        create_http_app()
        # Verify middleware list contains CORS
        # It's hard to verify middleware list directly as it passes to Starlette
        # But we can check if starlette init was called with correct middleware
        # Since create_http_app returns Starlette app, check app.middleware_stack?
        pass


def test_create_identity_center_app_success(mock_settings):
    mock_settings.auth.provider = "identity-center"
    mock_settings.auth.identity_center_region = "us-east-1"

    app = create_http_app()
    assert isinstance(app, Starlette)
    # Check routes
    routes = [r.path for r in app.routes]
    assert "/mcp" in routes
    assert "/health" in routes
    middleware_names = [
        getattr(entry.cls, "__name__", str(entry.cls)) for entry in app.user_middleware
    ]
    assert "PreAuthSecurityMiddleware" in middleware_names
    assert "IdentityCenterAuthMiddleware" in middleware_names
    assert "UserRateLimitMiddleware" in middleware_names
    assert "AuditMiddleware" in middleware_names


def test_lifespan_context(mock_settings, mock_idp_config, mock_deps):
    class Proxy:
        def __init__(self) -> None:
            self.initialized = False

        async def initialize(self) -> None:
            self.initialized = True

        async def authorize(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def token(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def register(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def callback(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def oauth_authorization_server_metadata(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def oidc_metadata(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

    proxy = Proxy()
    mock_deps["proxy"].return_value = proxy
    app = create_http_app()

    async def run_lifespan() -> None:
        async with app.router.lifespan_context(app):
            # Verify STS client pre-init
            mock_deps["sts"].return_value._get_client.assert_called()
            assert proxy.initialized is True

    asyncio.run(run_lifespan())


def test_lifespan_context_proxy_fail(mock_settings, mock_idp_config, mock_deps):
    class FailingProxy:
        async def initialize(self) -> None:
            raise Exception("Proxy init failed")

        async def authorize(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def token(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def register(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def callback(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def oauth_authorization_server_metadata(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

        async def oidc_metadata(self, _request: Request) -> JSONResponse:
            return JSONResponse({"ok": True})

    mock_deps["proxy"].return_value = FailingProxy()

    app = create_http_app()

    async def run_lifespan() -> None:
        async with app.router.lifespan_context(app):
            # Should not raise
            pass

    asyncio.run(run_lifespan())


def test_create_http_app_with_oauth_proxy(mock_settings, mock_idp_config, mock_deps):
    mock_deps["proxy"].return_value = MagicMock()
    mock_deps["proxy"].return_value.authorize = MagicMock()
    mock_deps["proxy"].return_value.token = MagicMock()

    app = create_http_app()
    routes = [r.path for r in app.routes]
    assert "/authorize" in routes
    assert "/token" in routes


def test_resolve_challenge_resource_configured(mock_settings):
    app = MagicMock()
    validator = MagicMock()
    middleware = MultiIdPAuthMiddleware(
        app, validator, challenge_resource="https://api.example.com"
    )
    request = Request(scope={"type": "http", "path": "/protected", "headers": []})
    resource = middleware._resolve_challenge_resource(request)
    assert resource == "https://api.example.com"


def test_resolve_challenge_scopes(mock_settings):
    app = MagicMock()
    validator = MagicMock()
    middleware = MultiIdPAuthMiddleware(
        app, validator, challenge_scopes=("scope1", "scope2/{resource}")
    )
    request = Request(
        scope={"type": "http", "path": "/protected", "headers": [(b"host", b"localhost")]}
    )

    scopes = middleware._resolve_challenge_scopes(request)
    assert "scope1" in scopes
    assert "scope2/http://localhost/mcp" in scopes


def test_token_validation_unexpected_exception():
    app = MagicMock()
    validator = AsyncMock()
    validator.validate.side_effect = Exception("Unexpected")

    middleware = MultiIdPAuthMiddleware(app, validator)

    request = Request(
        scope={
            "type": "http",
            "path": "/protected",
            "headers": [(b"authorization", b"Bearer token")],
        }
    )

    response = asyncio.run(middleware.dispatch(request, lambda r: None))
    assert response.status_code == 500
    assert json.loads(response.body)["error"] == "internal_error"


def test_create_identity_center_app_missing_region(mock_settings):
    mock_settings.auth.provider = "identity-center"
    mock_settings.auth.identity_center_region = None
    with pytest.raises(RuntimeError, match="AUTH_IDENTITY_CENTER_REGION is required"):
        create_http_app()


def test_multi_idp_auth_middleware_forwarded_headers():
    app = MagicMock()
    validator = AsyncMock()

    middleware = MultiIdPAuthMiddleware(
        app, validator, trust_forwarded_headers=True, challenge_resource="auto"
    )

    # Verify challenge header construction with forwarded headers
    # Simulate failed auth to trigger challenge
    request = Request(
        scope={
            "type": "http",
            "path": "/protected",
            "headers": [
                (b"x-forwarded-proto", b"https"),
                (b"x-forwarded-host", b"mcp.example.com"),
            ],
        }
    )

    response = asyncio.run(middleware.dispatch(request, lambda r: None))
    assert response.status_code == 401
    auth_header = response.headers["WWW-Authenticate"]
    assert (
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        in auth_header
    )


def test_multi_idp_auth_middleware_token_validation_error():
    app = MagicMock()
    validator = AsyncMock()
    from aws_cli_mcp.auth.multi_idp import TokenValidationError

    validator.validate.side_effect = TokenValidationError("Bad token", "invalid_token")

    middleware = MultiIdPAuthMiddleware(app, validator)

    request = Request(
        scope={
            "type": "http",
            "path": "/protected",
            "headers": [(b"authorization", b"Bearer bad-token")],
        }
    )

    response = asyncio.run(middleware.dispatch(request, lambda r: None))
    assert response.status_code == 401
    assert json.loads(response.body)["error"] == "invalid_token"


def test_multi_idp_auth_middleware_multi_user_violation():
    app = MagicMock()
    validator = AsyncMock()
    validator.validate.return_value = MagicMock(
        user_id="user2",
        issuer="iss1",
        email="e@mail.com",
        groups=[],
        expiry=None,
        jti=None,
        raw_claims={},
    )

    middleware = MultiIdPAuthMiddleware(app, validator, allow_multi_user=False)

    # Mock enforce_single_user_mode to raise error
    with patch("aws_cli_mcp.transport.http_server.enforce_single_user_mode") as mock_enforce:
        from aws_cli_mcp.auth.multi_user_guard import MultiUserViolationError

        mock_enforce.side_effect = MultiUserViolationError("Wait your turn")

        request = Request(
            scope={
                "type": "http",
                "path": "/protected",
                "headers": [(b"authorization", b"Bearer token")],
            }
        )

        response = asyncio.run(middleware.dispatch(request, lambda r: None))
        assert response.status_code == 403
        assert json.loads(response.body)["error"] == "multi_user_disabled"


def test_multi_idp_credential_middleware_no_role_mapping():
    app = MagicMock()
    mapper = MagicMock()
    mapper.resolve.return_value = None  # No mapping

    middleware = MultiIdPAWSCredentialMiddleware(app, mapper, MagicMock(), MagicMock())

    ctx = RequestContext(user_id="user1", issuer="iss1")
    token = set_request_context(ctx)
    try:
        request = Request(scope={"type": "http", "path": "/protected", "headers": []})
        response = asyncio.run(middleware.dispatch(request, lambda r: None))
        assert response.status_code == 403
        assert json.loads(response.body)["error"] == "no_role_mapping"
    finally:
        reset_request_context(token)


def test_identity_center_handlers(mock_settings):
    mock_settings.auth.provider = "identity-center"
    mock_settings.auth.identity_center_region = "us-east-1"

    class FakeMiddleware:
        def __init__(self, app, **kwargs):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    with patch(
        "aws_cli_mcp.transport.http_server.IdentityCenterAuthMiddleware", side_effect=FakeMiddleware
    ):
        # We need to mock handle_mcp_request
        with patch(
            "aws_cli_mcp.transport.mcp_handler.handle_mcp_request",
            return_value=JSONResponse({"status": "ok"}),
        ):
            app = create_http_app()
            with TestClient(app) as client:
                resp = client.get("/health")
                assert resp.status_code == 200

                resp = client.get("/ready")
                assert resp.status_code == 200

                resp = client.post("/mcp", json={})
                assert resp.status_code == 200


def test_identity_center_cors(mock_settings):
    mock_settings.auth.provider = "identity-center"
    mock_settings.auth.identity_center_region = "us-east-1"
    mock_settings.server.http_enable_cors = True
    mock_settings.server.http_allowed_origins = ["*"]

    with patch("aws_cli_mcp.transport.http_server.IdentityCenterAuthMiddleware"):
        with patch("starlette.middleware.cors.CORSMiddleware"):
            create_http_app()
            # Verify CORS middleware is used
            pass


def test_build_authenticate_header_with_scopes():
    app = MagicMock()
    validator = MagicMock()
    middleware = MultiIdPAuthMiddleware(app, validator, challenge_scopes=("scope1", "scope2"))
    request = Request(scope={"type": "http", "path": "/protected", "headers": [(b"host", b"test")]})
    header = middleware._build_authenticate_header(request)
    assert 'scope="scope1 scope2"' in header


def test_multi_idp_mcp_endpoint(mock_settings, mock_idp_config, mock_deps):
    with patch(
        "aws_cli_mcp.transport.mcp_handler.handle_mcp_request",
        return_value=JSONResponse({"status": "ok"}),
    ):
        app = create_http_app()
        with closing(TestClient(app)) as client:
            # /mcp requires auth?
            # MultiIdPAuthMiddleware is installed.
            # But for testing handle import, we might need to bypass auth or provide valid token.
            # Or mock middleware to pass through?
            # Or just provide a token.

            # Valid token setup
            mock_deps["validator"].return_value.validate = AsyncMock(
                return_value=MagicMock(
                    user_id="user1",
                    issuer="iss1",
                    email="e@mail.com",
                    groups=[],
                    expiry=None,
                    jti=None,
                    raw_claims={},
                )
            )
            mock_deps["mapper"].return_value.resolve.return_value = MagicMock(
                role_arn="arn:role", account_id="123"
            )
            mock_deps["cache"].return_value.get_or_refresh = AsyncMock(return_value=MagicMock())

            resp = client.post("/mcp", json={}, headers={"Authorization": "Bearer valid"})
            assert resp.status_code == 200


def test_resolve_challenge_resource_forwarded(mock_settings):
    app = MagicMock()
    validator = MagicMock()
    # challenge_scopes MUST include {resource} to trigger _resolve_challenge_resource
    middleware = MultiIdPAuthMiddleware(
        app,
        validator,
        trust_forwarded_headers=True,
        challenge_resource="auto",
        challenge_scopes=("scope/{resource}",),
    )
    request = Request(
        scope={
            "type": "http",
            "path": "/protected",
            "headers": [
                (b"x-forwarded-proto", b"https"),
                (b"x-forwarded-host", b"mcp.example.com"),
            ],
        }
    )

    scopes = middleware._resolve_challenge_scopes(request)
    assert "scope/https://mcp.example.com/mcp" in scopes
