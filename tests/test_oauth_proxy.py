"""Tests for OAuth proxy/broker mode."""

from __future__ import annotations

import base64
import hashlib
import time

import httpx
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from aws_cli_mcp.auth.idp_config import (
    AuditConfig,
    IdPConfig,
    JWKSCacheConfig,
    MultiIdPConfig,
    OAuthProxyConfig,
    ProtectedResourceConfig,
    RoleMappingEntry,
    SecurityConfig,
)
from aws_cli_mcp.auth.oauth_proxy import (
    AuthorizationCodeRecord,
    OAuthTransaction,
    create_oauth_proxy_broker,
)


def _build_config() -> MultiIdPConfig:
    return MultiIdPConfig(
        idps=[
            IdPConfig(
                name="entra",
                issuer="https://login.microsoftonline.com/test-tenant/v2.0",
                audience="api://test-app",
            )
        ],
        jwks_cache=JWKSCacheConfig(),
        security=SecurityConfig(),
        audit=AuditConfig(),
        role_mappings=[
            RoleMappingEntry(
                account_id="111111111111",
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            )
        ],
        protected_resource=ProtectedResourceConfig(resource="auto"),
        oauth_proxy=OAuthProxyConfig(
            enabled=True,
            upstream_idp="entra",
            upstream_client_id="upstream-client-id",
            upstream_client_secret="upstream-client-secret",
            upstream_token_auth_method="client_secret_post",
            upstream_scopes=("openid", "profile", "offline_access", "api://test-app/aws.execute"),
            redirect_path="/oauth/callback",
        ),
    )


def test_authorize_does_not_forward_resource_param(monkeypatch) -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    async def _fake_discovery() -> dict:
        return {
            "authorization_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/token",
        }

    monkeypatch.setattr(broker, "_discover_upstream_oidc", _fake_discovery)

    app = Starlette(routes=[Route("/authorize", endpoint=broker.authorize, methods=["GET"])])
    with TestClient(app) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "local-client-id",
                "redirect_uri": "http://localhost:8080/callback",
                "state": "test-state",
                "code_challenge": "A" * 43,
                "code_challenge_method": "S256",
                "resource": "http://localhost:8000/mcp",
                "scope": "openid profile",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith("https://login.microsoftonline.com/test/oauth2/v2.0/authorize?")
        assert "resource=" not in location
        assert "client_id=upstream-client-id" in location
        assert "api%3A%2F%2Ftest-app%2Faws.execute" in location
        assert "code_challenge=" in location
        assert "code_challenge_method=S256" in location


def test_token_authorization_code_validates_pkce_and_returns_tokens() -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    verifier = "A" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest())
    challenge = challenge.rstrip(b"=").decode("ascii")

    broker._codes["local-auth-code"] = AuthorizationCodeRecord(  # noqa: SLF001
        client_id="local-client-id",
        redirect_uri="http://localhost:8080/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
        token_response={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
        created_at=time.time(),
    )

    app = Starlette(routes=[Route("/token", endpoint=broker.token, methods=["POST"])])
    with TestClient(app) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "local-auth-code",
                "client_id": "local-client-id",
                "redirect_uri": "http://localhost:8080/callback",
                "code_verifier": verifier,
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["access_token"] == "access-token"
        assert payload["refresh_token"] == "refresh-token"


def test_authorize_rejects_unregistered_non_loopback_redirect(monkeypatch) -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    async def _fake_discovery() -> dict:
        return {
            "authorization_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/token",
        }

    monkeypatch.setattr(broker, "_discover_upstream_oidc", _fake_discovery)

    app = Starlette(routes=[Route("/authorize", endpoint=broker.authorize, methods=["GET"])])
    with TestClient(app) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "local-client-id",
                "redirect_uri": "https://attacker.example/callback",
                "state": "test-state",
                "code_challenge": "A" * 43,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        payload = response.json()
        assert payload["error"] == "invalid_request"


def test_token_requires_client_id_and_redirect_uri() -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    app = Starlette(routes=[Route("/token", endpoint=broker.token, methods=["POST"])])
    with TestClient(app) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "some-code",
                "code_verifier": "A" * 43,
            },
        )
        assert response.status_code == 400
        payload = response.json()
        assert payload["error"] == "invalid_request"


def test_callback_public_client_does_not_send_client_secret(monkeypatch) -> None:
    config = _build_config()
    config.oauth_proxy = OAuthProxyConfig(
        enabled=True,
        upstream_idp="entra",
        upstream_client_id="public-upstream-client-id",
        upstream_client_secret=None,
        upstream_token_auth_method="none",
        upstream_scopes=("openid", "profile", "offline_access", "api://test-app/aws.execute"),
        redirect_path="/oauth/callback",
    )
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    async def _fake_discovery() -> dict:
        return {
            "authorization_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/token",
        }

    broker._transactions["txn-1"] = OAuthTransaction(  # noqa: SLF001
        client_id="local-client-id",
        redirect_uri="http://localhost:8080/callback",
        original_state="client-state",
        code_challenge=None,
        code_challenge_method="plain",
        upstream_code_verifier="upstream-verifier",
        created_at=time.time(),
    )

    captured: dict[str, str] = {}

    class _FakeAsyncClient:
        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

        async def post(self, url: str, data: dict[str, str], timeout: float) -> httpx.Response:
            assert url == "https://login.microsoftonline.com/test/oauth2/v2.0/token"
            assert timeout == 15.0
            captured.update(data)
            return httpx.Response(
                200,
                json={
                    "access_token": "upstream-access-token",
                    "refresh_token": "upstream-refresh-token",
                    "token_type": "Bearer",
                },
            )

    monkeypatch.setattr(broker, "_discover_upstream_oidc", _fake_discovery)
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    app = Starlette(routes=[Route("/oauth/callback", endpoint=broker.callback, methods=["GET"])])
    with TestClient(app) as client:
        response = client.get(
            "/oauth/callback",
            params={
                "code": "upstream-code",
                "state": "txn-1",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith("http://localhost:8080/callback?code=")
        assert "state=client-state" in location

    assert captured["grant_type"] == "authorization_code"
    assert captured["client_id"] == "public-upstream-client-id"
    assert captured["code_verifier"] == "upstream-verifier"
    assert "client_secret" not in captured


def test_callback_sanitizes_upstream_token_error(monkeypatch) -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    async def _fake_discovery() -> dict:
        return {
            "authorization_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/token",
        }

    broker._transactions["txn-2"] = OAuthTransaction(  # noqa: SLF001
        client_id="local-client-id",
        redirect_uri="http://localhost:8080/callback",
        original_state="client-state",
        code_challenge="A" * 43,
        code_challenge_method="S256",
        upstream_code_verifier="A" * 43,
        created_at=time.time(),
    )

    class _FakeAsyncClient:
        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

        async def post(self, url: str, data: dict[str, str], timeout: float) -> httpx.Response:
            assert url == "https://login.microsoftonline.com/test/oauth2/v2.0/token"
            assert timeout == 15.0
            return httpx.Response(
                400,
                text='{"error":"invalid_client","error_description":"AADSTS700025 details"}',
            )

    monkeypatch.setattr(broker, "_discover_upstream_oidc", _fake_discovery)
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    app = Starlette(routes=[Route("/oauth/callback", endpoint=broker.callback, methods=["GET"])])
    with TestClient(app) as client:
        response = client.get(
            "/oauth/callback",
            params={
                "code": "upstream-code",
                "state": "txn-2",
            },
            follow_redirects=False,
        )
        assert response.status_code == 502
        payload = response.json()
        assert payload["error"] == "upstream_token_error"
        assert payload["error_description"] == "upstream token exchange failed"


def test_refresh_token_sanitizes_upstream_error(monkeypatch) -> None:
    config = _build_config()
    broker = create_oauth_proxy_broker(config)
    assert broker is not None

    async def _fake_discovery() -> dict:
        return {"token_endpoint": "https://login.microsoftonline.com/test/oauth2/v2.0/token"}

    class _FakeAsyncClient:
        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

        async def post(self, url: str, data: dict[str, str], timeout: float) -> httpx.Response:
            assert url == "https://login.microsoftonline.com/test/oauth2/v2.0/token"
            assert timeout == 15.0
            return httpx.Response(401, text="upstream raw error")

    monkeypatch.setattr(broker, "_discover_upstream_oidc", _fake_discovery)
    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    app = Starlette(routes=[Route("/token", endpoint=broker.token, methods=["POST"])])
    with TestClient(app) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "dummy",
            },
        )
        assert response.status_code == 502
        payload = response.json()
        assert payload["error"] == "upstream_token_error"
        assert payload["error_description"] == "upstream token refresh failed"
