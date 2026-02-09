"""Tests for OAuthProxyBroker."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import RedirectResponse

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
from aws_cli_mcp.auth.oauth_proxy import OAuthProxyBroker, create_oauth_proxy_broker


def _create_config(proxy_config: OAuthProxyConfig | None = None) -> MultiIdPConfig:
    """Create test config."""
    if proxy_config is None:
        proxy_config = OAuthProxyConfig(enabled=False)

    return MultiIdPConfig(
        idps=[
            IdPConfig(
                name="test-idp",
                issuer="https://test-idp.com",
                audience="test-aud",
            )
        ],
        jwks_cache=JWKSCacheConfig(),
        security=SecurityConfig(),
        audit=AuditConfig(),
        role_mappings=[RoleMappingEntry("123456789012", "arn:aws:iam::123456789012:role/Role")],
        protected_resource=ProtectedResourceConfig("https://resource"),
        oauth_proxy=proxy_config,
    )


class TestCreateOAuthProxyBroker:
    """Tests for factory function."""

    def test_disabled_returns_none(self) -> None:
        """Should return None if disabled."""
        config = _create_config()
        assert create_oauth_proxy_broker(config) is None

    def test_enabled_returns_instance(self) -> None:
        """Should return instance if enabled."""
        config = _create_config(
            OAuthProxyConfig(
                enabled=True,
                upstream_client_id="client",
                upstream_token_auth_method="none",
            )
        )
        assert create_oauth_proxy_broker(config) is not None


class TestOAuthProxyBroker:
    """Tests for OAuthProxyBroker methods."""

    @pytest.fixture
    def config(self) -> MultiIdPConfig:
        return _create_config(
            OAuthProxyConfig(
                enabled=True,
                upstream_client_id="upstream-client",
                upstream_client_secret="upstream-secret",
                upstream_token_auth_method="client_secret_post",
                redirect_path="/oauth/callback",
            )
        )

    @pytest.fixture
    def broker(self, config: MultiIdPConfig) -> OAuthProxyBroker:
        return OAuthProxyBroker(config)

    @pytest.mark.asyncio
    async def test_authorize_missing_params(self, broker: OAuthProxyBroker) -> None:
        """Test authorize with missing required params."""
        scope = {
            "type": "http",
            "path": "/authorize",
            "query_string": b"response_type=code",
            "headers": [],
        }
        request = Request(scope)
        response = await broker.authorize(request)

        assert response.status_code == 400
        body = json.loads(response.body)
        assert body["error"] == "invalid_request"

    @pytest.mark.asyncio
    async def test_authorize_invalid_response_type(self, broker: OAuthProxyBroker) -> None:
        """Test authorize with invalid response_type."""
        scope = {
            "type": "http",
            "path": "/authorize",
            "query_string": b"response_type=token",
            "headers": [],
        }
        request = Request(scope)
        response = await broker.authorize(request)

        assert response.status_code == 400
        body = json.loads(response.body)
        assert body["error"] == "unsupported_response_type"

    @pytest.mark.asyncio
    async def test_authorize_redirect_uri_mismatch(self, broker: OAuthProxyBroker) -> None:
        """Test authorize with unregistered redirect URI for registered client."""
        # Register a client first
        client_id = "test-client"
        mock_client = MagicMock()
        mock_client.redirect_uris = ("https://app.com/cb",)
        mock_client.created_at = time.time()  # Add created_at to avoid TypeError in comparison
        broker._clients[client_id] = mock_client

        valid_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        query = f"response_type=code&client_id={client_id}&redirect_uri=https://evil.com&state=state&code_challenge={valid_challenge}&code_challenge_method=S256"
        scope = {
            "type": "http",
            "path": "/authorize",
            "query_string": query.encode(),
            "headers": [],
        }
        request = Request(scope)
        response = await broker.authorize(request)

        assert response.status_code == 400
        body = json.loads(response.body)
        assert body["error"] == "invalid_request"
        assert "not registered" in body["error_description"]

    @pytest.mark.asyncio
    async def test_authorize_success(self, broker: OAuthProxyBroker) -> None:
        """Test successful authorization redirect."""
        # Mock upstream discovery
        with patch.object(broker, "_discover_upstream_oidc") as mock_discover:
            mock_discover.return_value = {"authorization_endpoint": "https://idp/auth"}

            # Using loopback redirect_uri for unregistered client
            redirect_uri = "http://localhost:8080/cb"
            code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

            query = f"response_type=code&client_id=new-client&redirect_uri={redirect_uri}&state=xyz&code_challenge={code_challenge}&code_challenge_method=S256"
            scope = {
                "type": "http",
                "path": "/authorize",
                "query_string": query.encode(),
                "scheme": "http",
                "server": ("localhost", 8000),
                "headers": [],
            }
            request = Request(scope)
            response = await broker.authorize(request)

            assert response.status_code == 302
            assert response.headers["location"].startswith("https://idp/auth")
            assert len(broker._transactions) == 1

    @pytest.mark.asyncio
    async def test_token_authorization_code_flow(self, broker: OAuthProxyBroker) -> None:
        """Test token exchange flow."""
        # Pre-populate a code record
        code = "test-code"
        client_id = "test-client"
        redirect_uri = "http://localhost/cb"

        # PKCE Setup
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

        from aws_cli_mcp.auth.oauth_proxy import AuthorizationCodeRecord

        broker._codes[code] = AuthorizationCodeRecord(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=challenge,
            code_challenge_method="S256",
            token_response={"access_token": "at", "id_token": "it"},
            created_at=time.time(),
        )

        # Make request
        body = f"grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={redirect_uri}&code_verifier={verifier}"
        scope = {
            "type": "http",
            "path": "/token",
        }
        request = Request(scope)

        # Mock body reading
        async def receive():
            return {"type": "http.request", "body": body.encode(), "more_body": False}

        request._receive = receive

        response = await broker.token(request)

        assert response.status_code == 200
        data = json.loads(response.body)
        assert data["access_token"] == "at"
        assert broker._codes[code].consumed is True

    @pytest.mark.asyncio
    async def test_register_client(self, broker: OAuthProxyBroker) -> None:
        """Test dynamic client registration."""
        body_json = {
            "redirect_uris": ["https://app.com/cb"],
            "token_endpoint_auth_method": "none",
        }
        scope = {
            "type": "http",
            "path": "/register",
        }
        request = Request(scope)

        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(body_json).encode(),
                "more_body": False,
            }

        request._receive = receive

        response = await broker.register(request)

        assert response.status_code == 201
        data = json.loads(response.body)
        assert data["client_id"].startswith("mcp-")
        assert data["redirect_uris"] == ["https://app.com/cb"]
        assert len(broker._clients) == 1

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, broker: OAuthProxyBroker) -> None:
        """Test cleanup of expired transactions/codes/clients."""
        # Add expired items
        broker._transactions["expired"] = MagicMock(created_at=time.time() - 1000)
        broker._codes["expired"] = MagicMock(created_at=time.time() - 1000)
        broker._clients["expired"] = MagicMock(created_at=time.time() - 100000)

        # Add valid items
        broker._transactions["valid"] = MagicMock(created_at=time.time())
        broker._codes["valid"] = MagicMock(created_at=time.time())
        broker._clients["valid"] = MagicMock(created_at=time.time())

        broker._cleanup_expired()

        assert "expired" not in broker._transactions
        assert "expired" not in broker._codes
        assert "expired" not in broker._clients
        assert "valid" in broker._transactions
        assert "valid" in broker._codes
        assert "valid" in broker._clients

    def test_cleanup_expired_if_due_interval(self, broker: OAuthProxyBroker) -> None:
        with patch.object(broker, "_cleanup_expired") as cleanup:
            broker._cleanup_expired_if_due(now=100.0)
            broker._cleanup_expired_if_due(now=105.0)
            broker._cleanup_expired_if_due(now=111.0)

        assert cleanup.call_count == 2

    @pytest.mark.asyncio
    async def test_callback_error_param(self, broker: OAuthProxyBroker) -> None:
        """Test callback with error param from upstream."""
        txn_id = "txn-1"
        broker._transactions[txn_id] = MagicMock(
            redirect_uri="https://app.com/cb", original_state="orig-state", created_at=time.time()
        )

        query = f"state={txn_id}&error=access_denied&error_description=User denied"
        scope = {
            "type": "http",
            "path": "/oauth/callback",
            "query_string": query.encode(),
        }
        request = Request(scope)
        response = await broker.callback(request)

        assert response.status_code == 302
        assert "error=access_denied" in response.headers["location"]
        assert "state=orig-state" in response.headers["location"]

    @pytest.mark.asyncio
    async def test_token_refresh_token_flow(self, broker: OAuthProxyBroker) -> None:
        """Test refresh_token flow."""
        from aws_cli_mcp.auth.oauth_proxy import RegisteredClient

        client_id = "refresh-client"
        broker._clients[client_id] = RegisteredClient(
            client_id=client_id,
            client_secret=None,
            redirect_uris=("http://localhost/cb",),
            scope=None,
            token_endpoint_auth_method="none",
            created_at=int(time.time()),
        )
        with patch.object(broker, "_discover_upstream_oidc") as mock_discover:
            mock_discover.return_value = {"token_endpoint": "https://idp/token"}

            # Mock upstream response
            with patch("httpx.AsyncClient.post") as mock_post:
                mock_post.return_value = MagicMock(
                    status_code=200, json=lambda: {"access_token": "new_at", "id_token": "new_it"}
                )

                body = f"grant_type=refresh_token&refresh_token=rt&client_id={client_id}"
                scope = {
                    "type": "http",
                    "path": "/token",
                }
                request = Request(scope)

                async def receive():
                    return {"type": "http.request", "body": body.encode(), "more_body": False}

                request._receive = receive

                response = await broker.token(request)

                assert response.status_code == 200
                data = json.loads(response.body)
                assert data["access_token"] == "new_at"

    @pytest.mark.asyncio
    async def test_token_invalid_grant_type(self, broker: OAuthProxyBroker) -> None:
        """Test token endpoint with invalid grant type."""
        body = "grant_type=password&username=user&password=pass"
        scope = {
            "type": "http",
            "path": "/token",
        }
        request = Request(scope)

        async def receive():
            return {"type": "http.request", "body": body.encode(), "more_body": False}

        request._receive = receive

        response = await broker.token(request)

        assert response.status_code == 400
        data = json.loads(response.body)
        assert data["error"] == "unsupported_grant_type"

    @pytest.mark.asyncio
    async def test_register_validation_limits(self, broker: OAuthProxyBroker) -> None:
        """Test registration validation limits."""
        # Test too many redirect URIs (simulated by filling capacity)
        with patch.object(broker, "_has_capacity", return_value=False):
            body_json = {"redirect_uris": ["https://app.com/cb"]}
            scope = {"type": "http", "path": "/register"}
            request = Request(scope)

            async def receive():
                return {
                    "type": "http.request",
                    "body": json.dumps(body_json).encode(),
                    "more_body": False,
                }

            request._receive = receive

            response = await broker.register(request)
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_register_invalid_redirect_uri(self, broker: OAuthProxyBroker) -> None:
        """Test registration with invalid redirect URI."""
        body_json = {"redirect_uris": ["not-a-uri"]}
        scope = {"type": "http", "path": "/register"}
        request = Request(scope)

        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps(body_json).encode(),
                "more_body": False,
            }

        request._receive = receive

        response = await broker.register(request)
        assert response.status_code == 400
        assert "invalid_client_metadata" in json.loads(response.body)["error"]

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        query: str = "",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        scheme: str = "https",
        host: str = "proxy.example.com",
    ) -> Request:
        raw_headers = [
            (k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in (headers or {}).items()
        ]
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query.encode("utf-8"),
            "headers": raw_headers,
            "scheme": scheme,
            "server": (host, 443 if scheme == "https" else 80),
        }
        request = Request(scope)
        if body is not None:
            body_bytes = body if isinstance(body, bytes) else body.encode("utf-8")

            async def receive() -> dict:
                return {"type": "http.request", "body": body_bytes, "more_body": False}

            request._receive = receive
        return request

    def test_validate_redirect_uri_and_loopback_helpers(self, broker: OAuthProxyBroker) -> None:
        assert broker._is_loopback_host(None) is False
        assert broker._is_loopback_host("[::1]") is True
        assert broker._validate_redirect_uri("https://example.com/cb") is None
        assert broker._validate_redirect_uri("http://example.com/cb")
        assert broker._validate_redirect_uri("https://")
        assert broker._validate_redirect_uri("http://[::1]:8000/cb") is None
        assert broker._validate_redirect_uri("myapp://localhost/cb")
        assert broker._validate_redirect_uri("file://localhost/cb")
        with patch("aws_cli_mcp.auth.oauth_proxy.urlparse", side_effect=ValueError("boom")):
            assert broker._validate_redirect_uri("x")
            assert broker._is_loopback_redirect_uri("http://localhost/cb") is False
        assert broker._is_loopback_redirect_uri("myapp://localhost/cb") is False
        assert broker._is_loopback_redirect_uri("http://localhost:8000/cb") is True
        assert broker._is_loopback_redirect_uri("http://[::1]:8000/cb") is True

    def test_pkce_validation_helpers(self, broker: OAuthProxyBroker) -> None:
        assert broker._is_valid_pkce_code_challenge("a" * 43) is True
        assert broker._is_valid_pkce_code_challenge("a" * 42) is False
        assert broker._is_valid_pkce_code_challenge("!" * 43) is False
        assert broker._is_valid_pkce_code_verifier("a" * 43) is True
        assert broker._is_valid_pkce_code_verifier("a" * 42) is False
        assert broker._is_valid_pkce_code_verifier("!" * 43) is False

    def test_upstream_auth_method_resolution(self, broker: OAuthProxyBroker) -> None:
        with_secret = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_client_secret="sec",
                    upstream_token_auth_method="auto",
                )
            )
        )
        assert with_secret._resolve_upstream_token_auth_method() == "client_secret_post"

        without_secret = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_client_secret=None,
                    upstream_token_auth_method="auto",
                )
            )
        )
        assert without_secret._resolve_upstream_token_auth_method() == "none"

        explicit_none = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_token_auth_method="none",
                )
            )
        )
        assert explicit_none._resolve_upstream_token_auth_method() == "none"

        unsupported = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_token_auth_method="unsupported",
                )
            )
        )
        with pytest.raises(RuntimeError, match="Unsupported upstream token auth method"):
            unsupported._resolve_upstream_token_auth_method()

    def test_origin_forwarded_headers(self, config: MultiIdPConfig) -> None:
        broker = OAuthProxyBroker(config, trust_forwarded_headers=True)
        request = self._request(
            "/authorize",
            headers={
                "host": "internal.local:8080",
                "x-forwarded-proto": "https,http",
                "x-forwarded-host": "proxy.example.com,internal.local:8080",
            },
        )
        assert broker._origin(request) == "https://proxy.example.com"

    def test_origin_uses_public_base_url(self, config: MultiIdPConfig) -> None:
        broker = OAuthProxyBroker(
            config,
            trust_forwarded_headers=True,
            public_base_url="https://mcp.public.example.com/base/",
        )
        request = self._request(
            "/authorize",
            headers={
                "host": "internal.local:8080",
                "x-forwarded-proto": "https,http",
                "x-forwarded-host": "attacker.example.com,internal.local:8080",
            },
        )
        assert broker._origin(request) == "https://mcp.public.example.com/base"

    @pytest.mark.asyncio
    async def test_discover_upstream_oidc_cache_hit(self, broker: OAuthProxyBroker) -> None:
        broker._oidc_metadata = {"authorization_endpoint": "https://idp/auth"}
        broker._oidc_metadata_fetched_at = time.time()
        with patch("httpx.AsyncClient.get") as mock_get:
            data = await broker._discover_upstream_oidc()
        assert data["authorization_endpoint"] == "https://idp/auth"
        mock_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_discover_upstream_oidc_fetch_and_initialize(
        self, broker: OAuthProxyBroker
    ) -> None:
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {
            "authorization_endpoint": "https://idp/auth",
            "token_endpoint": "https://idp/token",
        }
        with patch("httpx.AsyncClient.get", return_value=response):
            fetched = await broker._discover_upstream_oidc()
            assert fetched["token_endpoint"] == "https://idp/token"
            await broker.initialize()
            upstream = broker._upstream_idp()
            assert upstream.name == "test-idp"

    def test_upstream_idp_not_found(self, broker: OAuthProxyBroker) -> None:
        broker = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_idp="missing-idp",
                )
            )
        )
        with pytest.raises(RuntimeError, match="Upstream IdP not found"):
            broker._upstream_idp()

    def test_require_upstream_client_id_missing_raises(self) -> None:
        broker = OAuthProxyBroker(_create_config(OAuthProxyConfig(enabled=True)))
        with pytest.raises(RuntimeError, match="upstream_client_id is required"):
            broker._require_upstream_client_id()

    def test_upstream_idp_named_lookup(self) -> None:
        broker = OAuthProxyBroker(
            _create_config(
                OAuthProxyConfig(
                    enabled=True,
                    upstream_client_id="cid",
                    upstream_idp="test-idp",
                )
            )
        )
        assert broker._upstream_idp().name == "test-idp"

    @pytest.mark.asyncio
    async def test_authorize_validation_branches(self, broker: OAuthProxyBroker) -> None:
        long_client = "c" * 257
        req = self._request(
            "/authorize",
            query=f"response_type=code&client_id={long_client}&redirect_uri=http://localhost/cb&state=s&code_challenge={'a' * 43}&code_challenge_method=S256",
        )
        assert (await broker.authorize(req)).status_code == 400

        long_uri = "https://a.com/" + ("x" * 2100)
        req = self._request(
            "/authorize",
            query=f"response_type=code&client_id=c&redirect_uri={long_uri}&state=s&code_challenge={'a' * 43}&code_challenge_method=S256",
        )
        assert (await broker.authorize(req)).status_code == 400

        long_state = "s" * 1025
        req = self._request(
            "/authorize",
            query=f"response_type=code&client_id=c&redirect_uri=http://localhost/cb&state={long_state}&code_challenge={'a' * 43}&code_challenge_method=S256",
        )
        assert (await broker.authorize(req)).status_code == 400

        req = self._request(
            "/authorize",
            query="response_type=code&client_id=c&redirect_uri=notaurl&state=s&code_challenge="
            + ("a" * 43)
            + "&code_challenge_method=S256",
        )
        assert (await broker.authorize(req)).status_code == 400

        req = self._request(
            "/authorize",
            query="response_type=code&client_id=c&redirect_uri=https://app.example.com/cb&state=s&code_challenge="
            + ("a" * 43)
            + "&code_challenge_method=S256",
        )
        body = json.loads((await broker.authorize(req)).body)
        assert "loopback" in body["error_description"]

        req = self._request(
            "/authorize",
            query="response_type=code&client_id=c&redirect_uri=http://localhost/cb&state=s",
        )
        body = json.loads((await broker.authorize(req)).body)
        assert body["error"] == "invalid_request"

        req = self._request(
            "/authorize",
            query="response_type=code&client_id=c&redirect_uri=http://localhost/cb&state=s&code_challenge="
            + ("a" * 43)
            + "&code_challenge_method=plain",
        )
        body = json.loads((await broker.authorize(req)).body)
        assert "S256" in body["error_description"]

        req = self._request(
            "/authorize",
            query="response_type=code&client_id=c&redirect_uri=http://localhost/cb&state=s&code_challenge=!!!&code_challenge_method=S256",
        )
        body = json.loads((await broker.authorize(req)).body)
        assert "format is invalid" in body["error_description"]

        assert broker._is_registered_redirect_uri("missing-client", "http://localhost/cb") is False

    @pytest.mark.asyncio
    async def test_authorize_capacity_and_missing_upstream_endpoint(
        self,
        broker: OAuthProxyBroker,
    ) -> None:
        query = (
            "response_type=code&client_id=c&redirect_uri=http://localhost/cb&state=s"
            f"&code_challenge={'a' * 43}&code_challenge_method=S256"
        )
        req = self._request("/authorize", query=query)
        with patch.object(broker, "_has_capacity", return_value=False):
            resp = await broker.authorize(req)
        assert resp.status_code == 503

        req2 = self._request("/authorize", query=query)
        with patch.object(broker, "_discover_upstream_oidc", return_value={}):
            resp2 = await broker.authorize(req2)
        assert resp2.status_code == 502

    @pytest.mark.asyncio
    async def test_callback_validation_and_upstream_errors(self, broker: OAuthProxyBroker) -> None:
        missing = await broker.callback(self._request("/oauth/callback", query="state=missing"))
        assert missing.status_code == 400

        def _make_txn():
            return MagicMock(
                redirect_uri="http://localhost/cb",
                original_state="orig",
                upstream_code_verifier="v" * 43,
                client_id="cid",
                code_challenge="a" * 43,
                code_challenge_method="S256",
                created_at=time.time(),
            )

        # callback() atomically pops the transaction, so each test step
        # needs a fresh transaction entry.
        broker._transactions["t1"] = _make_txn()
        no_code = await broker.callback(self._request("/oauth/callback", query="state=t1"))
        assert no_code.status_code == 400

        broker._transactions["t2"] = _make_txn()
        with patch.object(broker, "_discover_upstream_oidc", return_value={}):
            resp = await broker.callback(
                self._request("/oauth/callback", query="state=t2&code=abc")
            )
        assert resp.status_code == 502

        broker._transactions["t3"] = _make_txn()
        with (
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch("httpx.AsyncClient.post", return_value=MagicMock(status_code=500, text="bad")),
        ):
            resp = await broker.callback(
                self._request("/oauth/callback", query="state=t3&code=abc")
            )
        assert resp.status_code == 502

        broker._transactions["t4"] = _make_txn()
        bad_json = MagicMock(status_code=200)
        bad_json.json.side_effect = ValueError("not json")
        with (
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch("httpx.AsyncClient.post", return_value=bad_json),
        ):
            resp = await broker.callback(
                self._request("/oauth/callback", query="state=t4&code=abc")
            )
        assert resp.status_code == 502

        broker._transactions["t5"] = _make_txn()
        with (
            patch.object(broker, "_has_capacity", return_value=False),
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch(
                "httpx.AsyncClient.post",
                return_value=MagicMock(status_code=200, json=lambda: {"access_token": "at"}),
            ),
        ):
            resp = await broker.callback(
                self._request("/oauth/callback", query="state=t5&code=abc")
            )
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_callback_success_code_exchange(self, broker: OAuthProxyBroker) -> None:
        broker._transactions["txn"] = MagicMock(
            redirect_uri="http://localhost/cb",
            original_state="orig",
            upstream_code_verifier="v" * 43,
            client_id="cid",
            code_challenge="a" * 43,
            code_challenge_method="S256",
            created_at=time.time(),
        )
        with (
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch(
                "httpx.AsyncClient.post",
                return_value=MagicMock(status_code=200, json=lambda: {"access_token": "at"}),
            ),
        ):
            resp = await broker.callback(
                self._request("/oauth/callback", query="state=txn&code=abc")
            )
        assert isinstance(resp, RedirectResponse)
        assert resp.status_code == 302
        assert "code=" in resp.headers["location"]
        assert "state=orig" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_token_authorization_code_error_paths(self, broker: OAuthProxyBroker) -> None:
        assert (
            await broker.token(
                self._request("/token", method="POST", body="grant_type=authorization_code")
            )
        ).status_code == 400
        assert (
            await broker.token(
                self._request(
                    "/token",
                    method="POST",
                    body="grant_type=authorization_code&code=c&redirect_uri=http://localhost/cb",
                )
            )
        ).status_code == 400
        assert (
            await broker.token(
                self._request(
                    "/token",
                    method="POST",
                    body="grant_type=authorization_code&code=c&client_id=cid",
                )
            )
        ).status_code == 400

        too_long_client = "c" * 257
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c&client_id={too_long_client}&redirect_uri=http://localhost/cb",
            )
        )
        assert resp.status_code == 400

        long_redirect = "http://localhost/" + ("x" * 2100)
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c&client_id=cid&redirect_uri={long_redirect}",
            )
        )
        assert resp.status_code == 400

        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body="grant_type=authorization_code&code=c&client_id=cid&redirect_uri=http://localhost/cb&code_verifier=bad",
            )
        )
        assert resp.status_code == 400

        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body="grant_type=authorization_code&code=missing&client_id=cid&redirect_uri=http://localhost/cb&code_verifier="
                + ("v" * 43),
            )
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_token_authorization_code_record_validation(
        self, broker: OAuthProxyBroker
    ) -> None:
        from aws_cli_mcp.auth.oauth_proxy import AuthorizationCodeRecord, RegisteredClient

        verifier = "v" * 43
        challenge = broker._build_s256_challenge(verifier)

        def _fresh_code(code_key: str, consumed: bool = False, **overrides):
            defaults = dict(
                client_id="cid",
                redirect_uri="http://localhost/cb",
                code_challenge=challenge,
                code_challenge_method="S256",
                token_response={"access_token": "at"},
                created_at=time.time(),
                consumed=consumed,
            )
            defaults.update(overrides)
            broker._codes[code_key] = AuthorizationCodeRecord(**defaults)

        # Consumed code → 400
        _fresh_code("c1", consumed=True)
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c1&client_id=cid&redirect_uri=http://localhost/cb&code_verifier={verifier}",
            )
        )
        assert resp.status_code == 400

        # client_id mismatch → 401 (each step needs a fresh code because
        # token() atomically consumes the code under lock)
        _fresh_code("c2")
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c2&client_id=other&redirect_uri=http://localhost/cb&code_verifier={verifier}",
            )
        )
        assert resp.status_code == 401

        # redirect_uri mismatch → 400
        _fresh_code("c3")
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c3&client_id=cid&redirect_uri=http://localhost/other&code_verifier={verifier}",
            )
        )
        assert resp.status_code == 400

        # client_secret mismatch → 401
        broker._clients["cid"] = RegisteredClient(
            client_id="cid",
            client_secret="expected",
            redirect_uris=("http://localhost/cb",),
            scope=None,
            token_endpoint_auth_method="client_secret_post",
            created_at=int(time.time()),
        )
        _fresh_code("c4")
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c4&client_id=cid&client_secret=wrong&redirect_uri=http://localhost/cb&code_verifier={verifier}",
            )
        )
        assert resp.status_code == 401

        # PKCE mismatch → 400
        _fresh_code("c5", code_challenge="x" * 43)
        resp = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=authorization_code&code=c5&client_id=cid&client_secret=expected&redirect_uri=http://localhost/cb&code_verifier={verifier}",
            )
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_token_refresh_error_paths(self, broker: OAuthProxyBroker) -> None:
        from aws_cli_mcp.auth.oauth_proxy import RegisteredClient

        resp = await broker.token(
            self._request("/token", method="POST", body="grant_type=refresh_token")
        )
        assert resp.status_code == 400

        missing_client = await broker.token(
            self._request(
                "/token",
                method="POST",
                body="grant_type=refresh_token&refresh_token=rt",
            )
        )
        assert missing_client.status_code == 400

        too_long_client = await broker.token(
            self._request(
                "/token",
                method="POST",
                body="grant_type=refresh_token&refresh_token=rt&client_id=" + ("c" * 257),
            )
        )
        assert too_long_client.status_code == 400

        unregistered_client = await broker.token(
            self._request(
                "/token",
                method="POST",
                body="grant_type=refresh_token&refresh_token=rt&client_id=unknown",
            )
        )
        assert unregistered_client.status_code == 401

        client_id = "refresh-client"
        broker._clients[client_id] = RegisteredClient(
            client_id=client_id,
            client_secret="expected",
            redirect_uris=("http://localhost/cb",),
            scope=None,
            token_endpoint_auth_method="client_secret_post",
            created_at=int(time.time()),
        )
        bad_secret = await broker.token(
            self._request(
                "/token",
                method="POST",
                body=f"grant_type=refresh_token&refresh_token=rt&client_id={client_id}&client_secret=wrong",
            )
        )
        assert bad_secret.status_code == 401

        with patch.object(broker, "_discover_upstream_oidc", return_value={}):
            resp = await broker.token(
                self._request(
                    "/token",
                    method="POST",
                    body=f"grant_type=refresh_token&refresh_token=rt&client_id={client_id}&client_secret=expected",
                )
            )
        assert resp.status_code == 502

        with (
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch("httpx.AsyncClient.post", return_value=MagicMock(status_code=500, text="bad")),
        ):
            resp = await broker.token(
                self._request(
                    "/token",
                    method="POST",
                    body=f"grant_type=refresh_token&refresh_token=rt&client_id={client_id}&client_secret=expected",
                )
            )
        assert resp.status_code == 502

        bad_json = MagicMock(status_code=200)
        bad_json.json.side_effect = ValueError("bad")
        with (
            patch.object(
                broker,
                "_discover_upstream_oidc",
                return_value={"token_endpoint": "https://idp/token"},
            ),
            patch("httpx.AsyncClient.post", return_value=bad_json),
        ):
            resp = await broker.token(
                self._request(
                    "/token",
                    method="POST",
                    body=f"grant_type=refresh_token&refresh_token=rt&client_id={client_id}&client_secret=expected",
                )
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_register_extra_branches(self, broker: OAuthProxyBroker) -> None:
        req = self._request("/register", method="POST", body=b"{bad json")
        resp = await broker.register(req)
        assert resp.status_code == 400

        long_uri = "https://example.com/" + ("x" * 2100)
        body = json.dumps({"redirect_uris": [long_uri]})
        resp = await broker.register(self._request("/register", method="POST", body=body))
        assert resp.status_code == 400

        body = json.dumps(
            {
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
            }
        )
        resp = await broker.register(self._request("/register", method="POST", body=body))
        assert resp.status_code == 400

        body = json.dumps(
            {
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "client_secret_post",
            }
        )
        resp = await broker.register(self._request("/register", method="POST", body=body))
        assert resp.status_code == 201
        payload = json.loads(resp.body)
        assert payload["token_endpoint_auth_method"] == "client_secret_post"
        assert "client_secret" in payload

    @pytest.mark.asyncio
    async def test_proxy_metadata_endpoints(self, config: MultiIdPConfig) -> None:
        broker = OAuthProxyBroker(config, trust_forwarded_headers=True)
        request = self._request(
            "/.well-known/oauth-authorization-server",
            headers={
                "x-forwarded-proto": "https,http",
                "x-forwarded-host": "proxy.example.com,internal.local",
            },
        )
        oauth_meta = await broker.oauth_authorization_server_metadata(request)
        oidc_meta = await broker.oidc_metadata(request)
        oauth_payload = json.loads(oauth_meta.body)
        oidc_payload = json.loads(oidc_meta.body)
        assert oauth_payload["issuer"] == "https://proxy.example.com"
        assert oidc_payload["issuer"] == "https://proxy.example.com"

    def test_verify_pkce_negative_cases(self, broker: OAuthProxyBroker) -> None:
        from aws_cli_mcp.auth.oauth_proxy import AuthorizationCodeRecord

        record = AuthorizationCodeRecord(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            code_challenge=None,
            code_challenge_method="S256",
            token_response={},
            created_at=time.time(),
        )
        assert broker._verify_pkce(record, "v" * 43) is False

        record.code_challenge = "x" * 43
        record.code_challenge_method = "plain"
        assert broker._verify_pkce(record, "v" * 43) is False
