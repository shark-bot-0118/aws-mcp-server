"""OAuth proxy/broker endpoints for upstream IdP compatibility."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from aws_cli_mcp.auth.idp_config import IdPConfig, MultiIdPConfig, OAuthProxyConfig
from aws_cli_mcp.utils.http import (
    normalize_public_base_url,
    resolve_request_origin,
    validate_oidc_url,
)

_logger = logging.getLogger(__name__)

_CLIENT_TTL_SECONDS: int = 86400  # 24 hours
_MAX_REDIRECT_URI_LENGTH: int = 2048
_MAX_CLIENT_ID_LENGTH: int = 256
_MAX_STATE_LENGTH: int = 1024
_MAX_CODE_CHALLENGE_LENGTH: int = 128
_MIN_CODE_CHALLENGE_LENGTH: int = 43
_MAX_CODE_VERIFIER_LENGTH: int = 128
_MIN_CODE_VERIFIER_LENGTH: int = 43
_MAX_TRANSACTIONS: int = 10_000
_MAX_AUTHORIZATION_CODES: int = 10_000
_MAX_REGISTERED_CLIENTS: int = 10_000

_PKCE_ALLOWED_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]+$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Standard OAuth 2.0 token response fields (RFC 6749 §5.1 + OIDC).
# Upstream IdP responses may contain extra internal fields (session IDs, PII)
# that should not be forwarded to the client.
_ALLOWED_TOKEN_FIELDS = frozenset(
    {
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "scope",
        "id_token",
    }
)


def _filter_token_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Return only standard OAuth fields from an upstream token response."""
    return {k: v for k, v in payload.items() if k in _ALLOWED_TOKEN_FIELDS}


@dataclass
class OAuthTransaction:
    client_id: str
    redirect_uri: str
    original_state: str
    code_challenge: str | None
    code_challenge_method: str
    upstream_code_verifier: str
    created_at: float


@dataclass
class AuthorizationCodeRecord:
    client_id: str
    redirect_uri: str
    code_challenge: str | None
    code_challenge_method: str
    token_response: dict[str, Any]
    created_at: float
    consumed: bool = False


@dataclass
class RegisteredClient:
    client_id: str
    client_secret: str | None
    redirect_uris: tuple[str, ...]
    scope: str | None
    token_endpoint_auth_method: str
    created_at: int


class OAuthProxyBroker:
    """Small in-memory OAuth proxy to bridge MCP clients and upstream IdP."""

    def __init__(
        self,
        config: MultiIdPConfig,
        trust_forwarded_headers: bool = False,
        public_base_url: str | None = None,
    ) -> None:
        self.config = config
        self.proxy: OAuthProxyConfig = config.oauth_proxy
        self._trust_forwarded_headers = trust_forwarded_headers
        self._public_base_url = (
            normalize_public_base_url(public_base_url) if public_base_url else None
        )
        self._transactions: dict[str, OAuthTransaction] = {}
        self._codes: dict[str, AuthorizationCodeRecord] = {}
        self._clients: dict[str, RegisteredClient] = {}
        self._oidc_metadata: dict[str, Any] | None = None
        self._oidc_metadata_fetched_at: float = 0.0
        self._state_lock = asyncio.Lock()

    @staticmethod
    def _is_loopback_host(hostname: str | None) -> bool:
        if hostname is None:
            return False
        normalized = hostname.strip().lower()
        if normalized.startswith("[") and normalized.endswith("]"):
            normalized = normalized[1:-1]
        return normalized in _LOOPBACK_HOSTS

    @staticmethod
    def _validate_redirect_uri(uri: str) -> str | None:
        """Validate a redirect URI. Returns error message or None if valid."""
        try:
            parsed = urlparse(uri)
        except Exception:
            return f"Invalid URI: {uri}"
        if not parsed.scheme or not parsed.netloc:
            return f"Malformed redirect_uri: {uri}"
        is_localhost = OAuthProxyBroker._is_loopback_host(parsed.hostname)
        if not is_localhost and parsed.scheme != "https":
            return f"redirect_uri must use https (got {parsed.scheme}): {uri}"
        return None

    @staticmethod
    def _is_loopback_redirect_uri(uri: str) -> bool:
        try:
            parsed = urlparse(uri)
        except Exception:
            return False
        return OAuthProxyBroker._is_loopback_host(parsed.hostname)

    @staticmethod
    def _is_valid_pkce_code_challenge(value: str) -> bool:
        if not (_MIN_CODE_CHALLENGE_LENGTH <= len(value) <= _MAX_CODE_CHALLENGE_LENGTH):
            return False
        return bool(_BASE64URL_PATTERN.fullmatch(value))

    @staticmethod
    def _is_valid_pkce_code_verifier(value: str) -> bool:
        if not (_MIN_CODE_VERIFIER_LENGTH <= len(value) <= _MAX_CODE_VERIFIER_LENGTH):
            return False
        return bool(_PKCE_ALLOWED_PATTERN.fullmatch(value))

    @staticmethod
    def _build_s256_challenge(code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _resolve_upstream_token_auth_method(self) -> str:
        method = (self.proxy.upstream_token_auth_method or "auto").strip().lower()
        if method == "auto":
            return "client_secret_post" if self.proxy.upstream_client_secret else "none"
        if method in {"client_secret_post", "none"}:
            return method
        raise RuntimeError(f"Unsupported upstream token auth method: {method}")

    def _apply_upstream_client_auth(self, payload: dict[str, str]) -> None:
        payload["client_id"] = self._require_upstream_client_id()
        auth_method = self._resolve_upstream_token_auth_method()
        if auth_method == "client_secret_post" and self.proxy.upstream_client_secret:
            payload["client_secret"] = self.proxy.upstream_client_secret

    def _require_upstream_client_id(self) -> str:
        client_id = self.proxy.upstream_client_id
        if not client_id:
            raise RuntimeError("oauth_proxy.upstream_client_id is required")
        return client_id

    def _origin(self, request: Request) -> str:
        return resolve_request_origin(
            request,
            trust_forwarded_headers=self._trust_forwarded_headers,
            public_base_url=self._public_base_url,
        )

    def _callback_url(self, request: Request) -> str:
        return f"{self._origin(request)}{self.proxy.redirect_path}"

    def _upstream_idp(self) -> IdPConfig:
        if self.proxy.upstream_idp:
            idp = self.config.get_idp_by_name(self.proxy.upstream_idp)
            if not idp:
                raise RuntimeError(f"Upstream IdP not found: {self.proxy.upstream_idp}")
            return idp
        return self.config.idps[0]

    async def _discover_upstream_oidc(self) -> dict[str, Any]:
        now = time.time()
        if self._oidc_metadata and now - self._oidc_metadata_fetched_at < 300:
            return self._oidc_metadata

        idp = self._upstream_idp()
        url = f"{idp.get_normalized_issuer()}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()

        # SSRF protection: validate discovered endpoint URLs before caching.
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            endpoint = data.get(key)
            if isinstance(endpoint, str) and endpoint:
                validate_oidc_url(endpoint, label=key)

        self._oidc_metadata = data
        self._oidc_metadata_fetched_at = now
        return data

    @staticmethod
    def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={
                "error": error,
                "error_description": description,
            },
        )

    def _cleanup_expired(self) -> None:
        now = time.time()
        txn_ttl = self.proxy.transaction_ttl_seconds
        code_ttl = self.proxy.auth_code_ttl_seconds

        self._transactions = {
            key: value
            for key, value in self._transactions.items()
            if now - value.created_at <= txn_ttl
        }
        self._codes = {
            key: value for key, value in self._codes.items() if now - value.created_at <= code_ttl
        }
        self._clients = {
            key: value
            for key, value in self._clients.items()
            if now - value.created_at <= _CLIENT_TTL_SECONDS
        }

    def _has_capacity(self, current_size: int, limit: int) -> bool:
        return current_size < limit

    def _is_registered_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        registration = self._clients.get(client_id)
        if not registration:
            return False
        return redirect_uri in registration.redirect_uris

    async def initialize(self) -> None:
        """Warm up upstream OIDC metadata cache."""
        await self._discover_upstream_oidc()

    async def authorize(self, request: Request) -> Response:
        """Client-facing /authorize endpoint."""
        qp = request.query_params

        if qp.get("response_type") != "code":
            return self._oauth_error("unsupported_response_type", "response_type must be 'code'")

        client_id = (qp.get("client_id") or "").strip()
        redirect_uri = (qp.get("redirect_uri") or "").strip()
        state = (qp.get("state") or "").strip()
        if not client_id or not redirect_uri or not state:
            return self._oauth_error(
                "invalid_request",
                "client_id, redirect_uri, and state are required",
            )
        if len(client_id) > _MAX_CLIENT_ID_LENGTH:
            return self._oauth_error("invalid_request", "client_id is too long")
        if len(redirect_uri) > _MAX_REDIRECT_URI_LENGTH:
            return self._oauth_error("invalid_request", "redirect_uri is too long")
        if len(state) > _MAX_STATE_LENGTH:
            return self._oauth_error("invalid_request", "state is too long")

        redirect_error = self._validate_redirect_uri(redirect_uri)
        if redirect_error:
            return self._oauth_error("invalid_request", redirect_error)

        # Validate PKCE parameters before acquiring the state lock.
        code_challenge = (qp.get("code_challenge") or "").strip() or None
        code_challenge_method = (qp.get("code_challenge_method") or "S256").strip()
        if not code_challenge:
            return self._oauth_error(
                "invalid_request",
                "code_challenge is required for PKCE authorization code flow",
            )
        if code_challenge_method.upper() != "S256":
            return self._oauth_error(
                "invalid_request",
                "Only S256 code_challenge_method is supported (RFC 7636)",
            )
        if not self._is_valid_pkce_code_challenge(code_challenge):
            return self._oauth_error("invalid_request", "code_challenge format is invalid")

        async with self._state_lock:
            self._cleanup_expired()

            if self._clients.get(client_id):
                if not self._is_registered_redirect_uri(client_id, redirect_uri):
                    return self._oauth_error("invalid_request", "redirect_uri is not registered")
            elif not self._is_loopback_redirect_uri(redirect_uri):
                return self._oauth_error(
                    "invalid_request",
                    "unregistered clients must use localhost loopback redirect_uri",
                )

            if not self._has_capacity(len(self._transactions), _MAX_TRANSACTIONS):
                return self._oauth_error(
                    "temporarily_unavailable",
                    "too many pending authorization transactions",
                    503,
                )

            upstream_code_verifier = secrets.token_urlsafe(64)
            upstream_code_challenge = self._build_s256_challenge(upstream_code_verifier)

            txn_id = secrets.token_urlsafe(24)
            self._transactions[txn_id] = OAuthTransaction(
                client_id=client_id,
                redirect_uri=redirect_uri,
                original_state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                upstream_code_verifier=upstream_code_verifier,
                created_at=time.time(),
            )

        upstream_metadata = await self._discover_upstream_oidc()
        authorize_endpoint = upstream_metadata.get("authorization_endpoint")
        if not authorize_endpoint:
            return self._oauth_error("server_error", "upstream authorization endpoint missing", 502)

        params = {
            "response_type": "code",
            "client_id": self._require_upstream_client_id(),
            "redirect_uri": self._callback_url(request),
            "state": txn_id,
            "scope": " ".join(self.proxy.upstream_scopes),
            "code_challenge": upstream_code_challenge,
            "code_challenge_method": "S256",
        }
        # Intentionally do not forward resource parameter from incoming request.
        url = f"{authorize_endpoint}?{urlencode(params)}"
        return RedirectResponse(url=url, status_code=302)

    async def callback(self, request: Request) -> Response:
        """Upstream IdP callback endpoint."""
        qp = request.query_params
        txn_id = (qp.get("state") or "").strip()
        async with self._state_lock:
            self._cleanup_expired()
            transaction = self._transactions.pop(txn_id, None)
        if not transaction:
            return self._oauth_error("invalid_request", "OAuth transaction not found", 400)

        if qp.get("error"):
            # Sanitize upstream error values to prevent reflected content injection.
            raw_error = (qp.get("error") or "")[:64]
            raw_desc = (qp.get("error_description") or "")[:256]
            safe_error = "".join(c for c in raw_error if c.isalnum() or c in "_- ")
            safe_desc = "".join(c for c in raw_desc if 0x20 <= ord(c) < 0x7F)
            params = urlencode(
                {
                    "error": safe_error,
                    "error_description": safe_desc,
                    "state": transaction.original_state,
                }
            )
            return RedirectResponse(f"{transaction.redirect_uri}?{params}", status_code=302)

        upstream_code = (qp.get("code") or "").strip()
        if not upstream_code:
            return self._oauth_error("invalid_request", "Missing code in callback")

        metadata = await self._discover_upstream_oidc()
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            return self._oauth_error("server_error", "upstream token endpoint missing", 502)

        token_data = {
            "grant_type": "authorization_code",
            "code": upstream_code,
            "code_verifier": transaction.upstream_code_verifier,
            "redirect_uri": self._callback_url(request),
        }
        self._apply_upstream_client_auth(token_data)

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(token_endpoint, data=token_data, timeout=15.0)

        if token_resp.status_code != 200:
            body = token_resp.text[:1000]
            _logger.warning(
                "upstream token exchange failed: status=%s body=%s",
                token_resp.status_code,
                body,
            )
            return self._oauth_error(
                "upstream_token_error",
                "upstream token exchange failed",
                502,
            )

        try:
            token_payload = token_resp.json()
        except Exception:
            _logger.warning("upstream token exchange returned non-JSON response")
            return self._oauth_error(
                "upstream_token_error",
                "upstream token exchange failed",
                502,
            )

        async with self._state_lock:
            if not self._has_capacity(len(self._codes), _MAX_AUTHORIZATION_CODES):
                return self._oauth_error(
                    "temporarily_unavailable",
                    "too many pending authorization codes",
                    503,
                )

            local_code = secrets.token_urlsafe(32)
            self._codes[local_code] = AuthorizationCodeRecord(
                client_id=transaction.client_id,
                redirect_uri=transaction.redirect_uri,
                code_challenge=transaction.code_challenge,
                code_challenge_method=transaction.code_challenge_method,
                token_response=token_payload,
                created_at=time.time(),
                consumed=False,
            )

        params = urlencode({"code": local_code, "state": transaction.original_state})
        return RedirectResponse(f"{transaction.redirect_uri}?{params}", status_code=302)

    @staticmethod
    def _verify_pkce(record: AuthorizationCodeRecord, code_verifier: str | None) -> bool:
        challenge = record.code_challenge
        if not challenge or not code_verifier:
            return False

        method = (record.code_challenge_method or "S256").upper()
        if method != "S256":
            return False  # Only S256 is accepted per RFC 7636
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, challenge)

    async def token(self, request: Request) -> Response:
        """Client-facing /token endpoint."""
        async with self._state_lock:
            self._cleanup_expired()
        raw_body = (await request.body()).decode("utf-8", errors="replace")
        form_values = parse_qs(raw_body, keep_blank_values=True)

        def form_get(key: str) -> str:
            values = form_values.get(key)
            if not values:
                return ""
            return values[-1]

        grant_type = form_get("grant_type").strip()

        if grant_type == "authorization_code":
            code = form_get("code").strip()
            client_id = form_get("client_id").strip()
            redirect_uri = form_get("redirect_uri").strip()
            code_verifier = form_get("code_verifier").strip() or None

            if not code:
                return self._oauth_error("invalid_request", "code is required")
            if not client_id:
                return self._oauth_error("invalid_request", "client_id is required")
            if not redirect_uri:
                return self._oauth_error("invalid_request", "redirect_uri is required")
            if len(client_id) > _MAX_CLIENT_ID_LENGTH:
                return self._oauth_error("invalid_request", "client_id is too long")
            if len(redirect_uri) > _MAX_REDIRECT_URI_LENGTH:
                return self._oauth_error("invalid_request", "redirect_uri is too long")
            if code_verifier and not self._is_valid_pkce_code_verifier(code_verifier):
                return self._oauth_error("invalid_grant", "PKCE code_verifier is invalid")

            async with self._state_lock:
                record = self._codes.get(code)
                if not record:
                    return self._oauth_error(
                        "invalid_grant",
                        "authorization code is invalid or expired",
                    )
                if record.consumed:
                    return self._oauth_error("invalid_grant", "authorization code already used")
                # Validate client_id and redirect_uri BEFORE consuming the
                # code to prevent a DoS where an attacker with a valid code
                # but wrong client_id wastes it.
                if client_id != record.client_id:
                    return self._oauth_error("invalid_client", "client_id mismatch", 401)
                if redirect_uri != record.redirect_uri:
                    return self._oauth_error("invalid_grant", "redirect_uri mismatch")
                # Verify PKCE before consuming code so failed verification
                # doesn't permanently invalidate a legitimate code.
                if not self._verify_pkce(record, code_verifier):
                    return self._oauth_error("invalid_grant", "PKCE verification failed")
                # Mark consumed after all validation passes.
                record.consumed = True
                registration = self._clients.get(client_id)
            if registration and registration.token_endpoint_auth_method == "client_secret_post":
                provided_secret = form_get("client_secret").strip()
                expected_secret = registration.client_secret or ""
                if not provided_secret or not secrets.compare_digest(
                    provided_secret, expected_secret
                ):
                    return self._oauth_error("invalid_client", "client_secret mismatch", 401)

            payload = _filter_token_response(record.token_response)
            payload.setdefault("token_type", "Bearer")
            return JSONResponse(payload)

        if grant_type == "refresh_token":
            refresh_token = form_get("refresh_token").strip()
            client_id = form_get("client_id").strip()
            client_secret = form_get("client_secret").strip()
            if not refresh_token:
                return self._oauth_error("invalid_request", "refresh_token is required")
            if not client_id:
                return self._oauth_error("invalid_request", "client_id is required")
            if len(client_id) > _MAX_CLIENT_ID_LENGTH:
                return self._oauth_error("invalid_request", "client_id is too long")

            async with self._state_lock:
                registration = self._clients.get(client_id)
            if registration is None:
                return self._oauth_error("invalid_client", "client is not registered", 401)
            if registration.token_endpoint_auth_method == "client_secret_post":
                expected_secret = registration.client_secret or ""
                if not client_secret or not secrets.compare_digest(client_secret, expected_secret):
                    return self._oauth_error("invalid_client", "client_secret mismatch", 401)

            metadata = await self._discover_upstream_oidc()
            token_endpoint = metadata.get("token_endpoint")
            if not token_endpoint:
                return self._oauth_error("server_error", "upstream token endpoint missing", 502)

            refresh_data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
            self._apply_upstream_client_auth(refresh_data)
            async with httpx.AsyncClient() as client:
                token_resp = await client.post(token_endpoint, data=refresh_data, timeout=15.0)

            if token_resp.status_code != 200:
                body = token_resp.text[:1000]
                _logger.warning(
                    "upstream refresh exchange failed: status=%s body=%s",
                    token_resp.status_code,
                    body,
                )
                return self._oauth_error(
                    "upstream_token_error",
                    "upstream token refresh failed",
                    502,
                )
            try:
                return JSONResponse(
                    _filter_token_response(token_resp.json()), status_code=200
                )
            except Exception:
                _logger.warning("upstream refresh exchange returned non-JSON response")
                return self._oauth_error(
                    "upstream_token_error",
                    "upstream token refresh failed",
                    502,
                )

        return self._oauth_error("unsupported_grant_type", "grant_type is not supported")

    async def register(self, request: Request) -> Response:
        """Client registration endpoint for MCP OAuth clients."""
        try:
            body = await request.json()
        except Exception:
            body = {}

        redirect_uris = body.get("redirect_uris") or []
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return self._oauth_error("invalid_client_metadata", "redirect_uris is required")

        for uri in redirect_uris:
            if len(str(uri)) > _MAX_REDIRECT_URI_LENGTH:
                return self._oauth_error("invalid_client_metadata", "redirect_uri is too long")
            error = self._validate_redirect_uri(str(uri))
            if error:
                return self._oauth_error("invalid_client_metadata", error)

        token_auth_method = str(body.get("token_endpoint_auth_method") or "none")
        if token_auth_method not in {"none", "client_secret_post"}:
            return self._oauth_error(
                "invalid_client_metadata",
                "token_endpoint_auth_method must be 'none' or 'client_secret_post'",
            )
        client_secret = None
        if token_auth_method == "client_secret_post":
            client_secret = secrets.token_urlsafe(32)

        client_id = f"mcp-{secrets.token_urlsafe(10)}"
        issued_at = int(time.time())
        scope = body.get("scope")
        registration = RegisteredClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=tuple(str(u) for u in redirect_uris),
            scope=scope if isinstance(scope, str) else None,
            token_endpoint_auth_method=token_auth_method,
            created_at=issued_at,
        )
        async with self._state_lock:
            if not self._has_capacity(len(self._clients), _MAX_REGISTERED_CLIENTS):
                return self._oauth_error(
                    "temporarily_unavailable",
                    "too many registered clients",
                    503,
                )
            self._clients[client_id] = registration

        response = {
            "client_id": registration.client_id,
            "client_id_issued_at": issued_at,
            "client_secret_expires_at": 0,
            "redirect_uris": list(registration.redirect_uris),
            "token_endpoint_auth_method": registration.token_endpoint_auth_method,
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
            "scope": registration.scope,
        }
        if registration.client_secret:
            response["client_secret"] = registration.client_secret
        return JSONResponse(response, status_code=201)

    async def oauth_authorization_server_metadata(self, request: Request) -> Response:
        """OAuth Authorization Server metadata endpoint (RFC 8414)."""
        origin = self._origin(request)
        metadata = {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "registration_endpoint": f"{origin}/register",
            "scopes_supported": list(self.proxy.upstream_scopes),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
        }
        return JSONResponse(metadata)

    async def oidc_metadata(self, request: Request) -> Response:
        """OpenID Connect metadata endpoint."""
        origin = self._origin(request)
        metadata = {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "registration_endpoint": f"{origin}/register",
            "scopes_supported": list(self.proxy.upstream_scopes),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        return JSONResponse(metadata)


def create_oauth_proxy_broker(
    config: MultiIdPConfig,
    trust_forwarded_headers: bool = False,
    public_base_url: str | None = None,
) -> OAuthProxyBroker | None:
    """Factory for optional OAuth proxy broker."""
    if not config.oauth_proxy.enabled:
        return None
    return OAuthProxyBroker(
        config,
        trust_forwarded_headers=trust_forwarded_headers,
        public_base_url=public_base_url,
    )
