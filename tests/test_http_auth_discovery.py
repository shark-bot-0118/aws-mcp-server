"""Tests for OAuth discovery metadata and auth challenge headers."""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
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
from aws_cli_mcp.auth.protected_resource import create_protected_resource_endpoint
from aws_cli_mcp.transport.http_server import MultiIdPAuthMiddleware


def _build_config(resource: str) -> MultiIdPConfig:
    return MultiIdPConfig(
        idps=[
            IdPConfig(
                name="test-idp",
                issuer="https://login.example.com",
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
        protected_resource=ProtectedResourceConfig(
            resource=resource,
            scopes_supported=("openid", "profile", "offline_access", "api://test-app/aws.execute"),
        ),
    )


def test_protected_resource_auto_uses_request_origin() -> None:
    config = _build_config("auto")
    endpoint = create_protected_resource_endpoint(config, trust_forwarded_headers=True)

    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=endpoint.handle,
                methods=["GET"],
            )
        ]
    )

    with TestClient(app) as client:
        response = client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        assert response.json()["resource"] == "http://testserver/mcp"

        forwarded = client.get(
            "/.well-known/oauth-protected-resource",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "mcp.local.test",
            },
        )
        assert forwarded.status_code == 200
        assert forwarded.json()["resource"] == "https://mcp.local.test/mcp"


def test_protected_resource_uses_proxy_origin_as_authorization_server() -> None:
    config = _build_config("auto")
    config.oauth_proxy = OAuthProxyConfig(
        enabled=True,
        upstream_client_id="proxy-client-id",
        upstream_client_secret="proxy-client-secret",
    )
    endpoint = create_protected_resource_endpoint(config, trust_forwarded_headers=True)

    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=endpoint.handle,
                methods=["GET"],
            )
        ]
    )

    with TestClient(app) as client:
        response = client.get(
            "/.well-known/oauth-protected-resource",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "mcp.proxy.test",
            },
        )
        assert response.status_code == 200
        assert response.json()["authorization_servers"] == ["https://mcp.proxy.test"]


def test_protected_resource_public_base_url_overrides_request_origin() -> None:
    config = _build_config("auto")
    config.oauth_proxy = OAuthProxyConfig(
        enabled=True,
        upstream_client_id="proxy-client-id",
    )
    endpoint = create_protected_resource_endpoint(
        config,
        trust_forwarded_headers=True,
        public_base_url="https://mcp.public.example.com/base",
    )

    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=endpoint.handle,
                methods=["GET"],
            )
        ]
    )

    with TestClient(app) as client:
        response = client.get(
            "/.well-known/oauth-protected-resource",
            headers={
                "Host": "internal.local",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "attacker.example.com",
            },
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["resource"] == "https://mcp.public.example.com/base/mcp"
        assert payload["authorization_servers"] == ["https://mcp.public.example.com/base"]


class _DummyValidator:
    async def validate(self, token: str) -> Any:  # pragma: no cover - not called in this test
        raise AssertionError("validate should not be called for missing token")


def test_missing_token_challenge_contains_discovery_metadata() -> None:
    async def _mcp_handler(request) -> Response:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", endpoint=_mcp_handler, methods=["POST"])])
    app.add_middleware(
        MultiIdPAuthMiddleware,
        validator=_DummyValidator(),
        challenge_resource="auto",
        challenge_scopes=("openid", "profile", "api://test-app/aws.execute"),
        resource_metadata_path="/.well-known/oauth-protected-resource/mcp",
    )

    with TestClient(app) as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert response.status_code == 401
        header = response.headers["www-authenticate"]
        assert 'realm="mcp"' in header
        expected_metadata = (
            'resource_metadata="http://testserver/.well-known/oauth-protected-resource/mcp"'
        )
        assert expected_metadata in header
        assert 'scope="openid profile api://test-app/aws.execute"' in header
        assert 'error="invalid_token"' in header


def test_missing_token_challenge_expands_resource_template_scope() -> None:
    async def _mcp_handler(request) -> Response:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", endpoint=_mcp_handler, methods=["POST"])])
    app.add_middleware(
        MultiIdPAuthMiddleware,
        validator=_DummyValidator(),
        challenge_resource="auto",
        challenge_scopes=("openid", "{resource}/aws.execute"),
        resource_metadata_path="/.well-known/oauth-protected-resource/mcp",
        trust_forwarded_headers=True,
    )

    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "mcp.local.test",
            },
        )
        assert response.status_code == 401
        header = response.headers["www-authenticate"]
        assert 'scope="openid https://mcp.local.test/mcp/aws.execute"' in header


def test_missing_token_challenge_uses_public_base_url() -> None:
    async def _mcp_handler(request) -> Response:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", endpoint=_mcp_handler, methods=["POST"])])
    app.add_middleware(
        MultiIdPAuthMiddleware,
        validator=_DummyValidator(),
        challenge_resource="auto",
        challenge_scopes=("openid", "{resource}/aws.execute"),
        resource_metadata_path="/.well-known/oauth-protected-resource/mcp",
        trust_forwarded_headers=True,
        public_base_url="https://mcp.public.example.com",
    )

    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={
                "Host": "internal.local",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "attacker.example.com",
            },
        )
        assert response.status_code == 401
        header = response.headers["www-authenticate"]
        assert (
            'resource_metadata="https://mcp.public.example.com/.well-known/oauth-protected-resource/mcp"'
            in header
        )
        assert 'scope="openid https://mcp.public.example.com/mcp/aws.execute"' in header
