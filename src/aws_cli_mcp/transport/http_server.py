"""Starlette HTTP server assembly with OAuth 2.0 Protected Resource support."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from aws_cli_mcp.auth.context import (
    RequestContext,
    reset_request_context,
    set_request_context,
)
from aws_cli_mcp.auth.identity_center_middleware import IdentityCenterAuthMiddleware
from aws_cli_mcp.auth.multi_user_guard import (
    MultiUserViolationError,
    enforce_single_user_mode,
)
from aws_cli_mcp.aws_credentials.cache import CredentialCache
from aws_cli_mcp.aws_credentials.sts_provider import STSCredentialProvider
from aws_cli_mcp.config import load_settings
from aws_cli_mcp.utils.hashing import sha256_text
from aws_cli_mcp.utils.http import normalize_public_base_url, resolve_request_origin

logger = logging.getLogger(__name__)

_BASE_EXEMPT_PATHS = frozenset(
    {
        "/health",
        "/ready",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    }
)


def create_http_app() -> Starlette:
    """Create the HTTP MCP server application."""
    settings = load_settings()
    auth_provider = settings.auth.provider.lower()

    if auth_provider == "multi-idp":
        return _create_multi_idp_app(settings)
    if auth_provider == "identity-center":
        return _create_identity_center_app(settings)

    raise RuntimeError("Unsupported AUTH_PROVIDER. Use one of: multi-idp, identity-center")


def _create_multi_idp_app(settings: Any) -> Starlette:
    """Create app with multi-IdP OAuth 2.0 Protected Resource support."""
    from aws_cli_mcp.auth.idp_config import (
        load_idp_config,
    )
    from aws_cli_mcp.auth.multi_idp import MultiIdPValidator
    from aws_cli_mcp.auth.oauth_proxy import create_oauth_proxy_broker
    from aws_cli_mcp.auth.protected_resource import create_protected_resource_endpoint
    from aws_cli_mcp.auth.role_mapper import RoleMapper
    from aws_cli_mcp.middleware.audit import AuditMiddleware
    from aws_cli_mcp.middleware.security import PreAuthSecurityMiddleware, UserRateLimitMiddleware

    # Load IdP config
    idp_config_path = settings.auth.idp_config_path
    if not idp_config_path:
        raise RuntimeError(
            "AUTH_IDP_CONFIG_PATH is required for multi-idp mode. "
            "Set AUTH_IDP_CONFIG_PATH to path of idp_config.yaml"
        )

    logger.info("Loading IdP config from: %s", idp_config_path)
    idp_config = load_idp_config(idp_config_path)
    transport_mode = str(settings.server.transport_mode).strip().lower()
    public_base_url = getattr(settings.server, "public_base_url", None)
    if transport_mode == "remote" and not public_base_url:
        raise RuntimeError(
            "MCP_PUBLIC_BASE_URL is required for TRANSPORT_MODE=remote with "
            "AUTH_PROVIDER=multi-idp"
        )

    # Create validators and handlers
    multi_idp_validator = MultiIdPValidator(idp_config)
    protected_resource_endpoint = create_protected_resource_endpoint(
        idp_config,
        trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        public_base_url=public_base_url,
    )
    oauth_proxy = create_oauth_proxy_broker(
        idp_config,
        trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        public_base_url=public_base_url,
    )
    role_mapper = RoleMapper(idp_config.role_mappings)

    oauth_exempt_paths: tuple[str, ...] = ()
    if oauth_proxy:
        oauth_exempt_paths = (
            "/authorize",
            "/token",
            "/register",
            idp_config.oauth_proxy.redirect_path,
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        )

    # Create credential infrastructure
    credential_cache = CredentialCache(
        refresh_buffer_seconds=settings.auth.credential_refresh_buffer_seconds,
        max_entries=settings.auth.credential_cache_max_entries,
    )
    sts_provider = STSCredentialProvider(region=settings.aws.sts_region)

    # Build middleware stack
    # Order: PreAuthSecurity -> Auth -> UserRateLimit -> Audit -> AWSCredential
    #
    # Rationale:
    # 1. PreAuthSecurityMiddleware runs FIRST for DoS protection:
    #    - IP rate limiting (blocks brute-force attacks)
    #    - Body/header size limits (blocks payload attacks)
    #    - Request timeout (prevents slowloris)
    # 2. Auth validates token and sets user_id
    # 3. UserRateLimitMiddleware enforces per-user limits (needs user_id)
    # 4. AuditMiddleware logs with user_id
    # 5. AWSCredentialMiddleware assumes role
    middleware: list[Middleware] = [
        Middleware(
            PreAuthSecurityMiddleware,
            config=idp_config.security,
            trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        ),
        Middleware(
            MultiIdPAuthMiddleware,
            validator=multi_idp_validator,
            challenge_resource=idp_config.protected_resource.resource,
            challenge_scopes=tuple(idp_config.protected_resource.scopes_supported),
            resource_metadata_path="/.well-known/oauth-protected-resource/mcp",
            exempt_paths=oauth_exempt_paths,
            allow_multi_user=settings.auth.allow_multi_user,
            trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
            public_base_url=public_base_url,
        ),
        Middleware(
            UserRateLimitMiddleware,
            config=idp_config.security,
        ),
        Middleware(
            AuditMiddleware,
            config=idp_config.audit,
            trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        ),
        Middleware(
            MultiIdPAWSCredentialMiddleware,
            role_mapper=role_mapper,
            credential_cache=credential_cache,
            sts_provider=sts_provider,
            exempt_paths=oauth_exempt_paths,
        ),
    ]

    # Add CORS if configured — MUST be outermost (list head) so that
    # OPTIONS preflight requests receive CORS headers before any auth
    # middleware can reject them with 401.
    if settings.server.http_enable_cors and settings.server.http_allowed_origins:
        from starlette.middleware.cors import CORSMiddleware

        middleware.insert(
            0,
            Middleware(
                CORSMiddleware,
                allow_origins=list(settings.server.http_allowed_origins),
                allow_methods=["POST", "GET", "OPTIONS"],
                allow_headers=[
                    "Authorization",
                    "Content-Type",
                    "Accept",
                    "MCP-Protocol-Version",
                ],
            ),
        )

    # Route handlers
    async def mcp_handler(request: Request) -> Response:
        from aws_cli_mcp.transport.mcp_handler import handle_mcp_request

        return await handle_mcp_request(request)

    async def health_handler(request: Request) -> Response:
        return JSONResponse({"status": "healthy"})

    async def ready_handler(request: Request) -> Response:
        return JSONResponse({"status": "ready"})

    routes = [
        Route("/mcp", endpoint=mcp_handler, methods=["POST", "OPTIONS"]),
        Route("/health", endpoint=health_handler, methods=["GET"]),
        Route("/ready", endpoint=ready_handler, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource",
            endpoint=protected_resource_endpoint.handle,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            endpoint=protected_resource_endpoint.handle,
            methods=["GET"],
        ),
    ]

    if oauth_proxy:
        routes.extend(
            [
                Route("/authorize", endpoint=oauth_proxy.authorize, methods=["GET"]),
                Route("/token", endpoint=oauth_proxy.token, methods=["POST"]),
                Route("/register", endpoint=oauth_proxy.register, methods=["POST"]),
                Route(
                    idp_config.oauth_proxy.redirect_path,
                    endpoint=oauth_proxy.callback,
                    methods=["GET"],
                ),
                Route(
                    "/.well-known/oauth-authorization-server",
                    endpoint=oauth_proxy.oauth_authorization_server_metadata,
                    methods=["GET"],
                ),
                Route(
                    "/.well-known/openid-configuration",
                    endpoint=oauth_proxy.oidc_metadata,
                    methods=["GET"],
                ),
            ]
        )

    @asynccontextmanager
    async def lifespan(app: Starlette):
        logger.info("Starting multi-IdP HTTP server...")
        # Pre-initialize STS client
        await asyncio.to_thread(sts_provider._get_client)
        if oauth_proxy:
            try:
                await oauth_proxy.initialize()
            except Exception:
                logger.warning(
                    "OAuth proxy upstream discovery failed at startup; "
                    "will retry lazily on first auth request",
                    exc_info=True,
                )
        logger.info("Multi-IdP HTTP server started")
        try:
            yield
        finally:
            logger.info("Stopping multi-IdP HTTP server...")

    app = Starlette(
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
    )
    app.state.strict_mcp_http = settings.server.transport_mode == "remote"
    app.state.http_allowed_origins = tuple(settings.server.http_allowed_origins)
    app.state.http_allow_missing_origin = settings.server.http_allow_missing_origin
    return app


def _create_identity_center_app(settings: Any) -> Starlette:
    """Create app with IAM Identity Center auth."""
    from aws_cli_mcp.auth.idp_config import AuditConfig, SecurityConfig
    from aws_cli_mcp.middleware.audit import AuditMiddleware
    from aws_cli_mcp.middleware.security import PreAuthSecurityMiddleware, UserRateLimitMiddleware

    _validate_identity_center_settings(settings)

    security_config = SecurityConfig(
        rate_limit_per_user=settings.auth.rate_limit_per_user,
        rate_limit_per_ip=settings.auth.rate_limit_per_ip,
        max_body_size_bytes=settings.auth.max_body_size_mb * 1024 * 1024,
        max_header_size_bytes=settings.auth.max_header_size_kb * 1024,
        request_timeout_seconds=settings.auth.request_timeout_seconds,
    )
    audit_config = AuditConfig(enabled=settings.auth.audit_enabled)

    middleware = [
        Middleware(
            PreAuthSecurityMiddleware,
            config=security_config,
            trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        ),
        Middleware(
            IdentityCenterAuthMiddleware,
            allow_multi_user=settings.auth.allow_multi_user,
        ),
        Middleware(
            UserRateLimitMiddleware,
            config=security_config,
        ),
        Middleware(
            AuditMiddleware,
            config=audit_config,
            trust_forwarded_headers=settings.server.http_trust_forwarded_headers,
        ),
    ]

    if settings.server.http_enable_cors and settings.server.http_allowed_origins:
        from starlette.middleware.cors import CORSMiddleware

        middleware.insert(
            0,
            Middleware(
                CORSMiddleware,
                allow_origins=list(settings.server.http_allowed_origins),
                allow_methods=["POST", "GET", "OPTIONS"],
                allow_headers=[
                    "Authorization",
                    "Content-Type",
                    "Accept",
                    "MCP-Protocol-Version",
                ],
            ),
        )

    async def mcp_handler(request: Request) -> Response:
        from aws_cli_mcp.transport.mcp_handler import handle_mcp_request

        return await handle_mcp_request(request)

    async def health_handler(request: Request) -> Response:
        return JSONResponse({"status": "healthy"})

    async def ready_handler(request: Request) -> Response:
        return JSONResponse({"status": "ready"})

    routes = [
        Route("/mcp", endpoint=mcp_handler, methods=["POST", "OPTIONS"]),
        Route("/health", endpoint=health_handler, methods=["GET"]),
        Route("/ready", endpoint=ready_handler, methods=["GET"]),
    ]

    app = Starlette(
        routes=routes,
        middleware=middleware,
    )
    app.state.strict_mcp_http = settings.server.transport_mode == "remote"
    app.state.http_allowed_origins = tuple(settings.server.http_allowed_origins)
    app.state.http_allow_missing_origin = settings.server.http_allow_missing_origin
    return app


def _validate_identity_center_settings(settings: Any) -> None:
    """Validate settings for Identity Center mode."""
    if not settings.auth.identity_center_region:
        raise RuntimeError("AUTH_IDENTITY_CENTER_REGION is required for identity-center mode")


# ============================================================================
# Multi-IdP Middleware Classes
# ============================================================================


class MultiIdPAuthMiddleware(BaseHTTPMiddleware):
    """
    Multi-IdP authentication middleware.

    Validates JWT access_token from Authorization header against
    configured IdP allowlist.
    """

    EXEMPT_PATHS = _BASE_EXEMPT_PATHS

    def __init__(
        self,
        app: Any,
        validator: Any,
        challenge_resource: str = "auto",
        challenge_scopes: tuple[str, ...] = (),
        resource_metadata_path: str = "/.well-known/oauth-protected-resource/mcp",
        exempt_paths: tuple[str, ...] = (),
        allow_multi_user: bool = False,
        trust_forwarded_headers: bool = False,
        public_base_url: str | None = None,
    ) -> None:
        super().__init__(app)
        self.validator = validator
        self.challenge_resource = challenge_resource
        self.challenge_scopes = challenge_scopes
        self.resource_metadata_path = resource_metadata_path
        self.exempt_paths = self.EXEMPT_PATHS | set(exempt_paths)
        self.allow_multi_user = allow_multi_user
        self.trust_forwarded_headers = trust_forwarded_headers
        self.public_base_url = (
            normalize_public_base_url(public_base_url) if public_base_url else None
        )

    def _build_resource_metadata_url(self, request: Request) -> str:
        origin = resolve_request_origin(
            request,
            trust_forwarded_headers=self.trust_forwarded_headers,
            public_base_url=self.public_base_url,
        )
        return f"{origin}{self.resource_metadata_path}"

    def _resolve_challenge_resource(self, request: Request) -> str:
        configured = (self.challenge_resource or "").strip()
        if configured and configured.lower() != "auto":
            return configured

        origin = resolve_request_origin(
            request,
            trust_forwarded_headers=self.trust_forwarded_headers,
            public_base_url=self.public_base_url,
        )
        return f"{origin}/mcp"

    def _resolve_challenge_scopes(self, request: Request) -> tuple[str, ...]:
        if not self.challenge_scopes:
            return ()
        resource = self._resolve_challenge_resource(request)
        return tuple(scope.replace("{resource}", resource) for scope in self.challenge_scopes)

    def _build_authenticate_header(self, request: Request, error: str | None = None) -> str:
        parts = ['realm="mcp"']
        parts.append(f'resource_metadata="{self._build_resource_metadata_url(request)}"')
        resolved_scopes = self._resolve_challenge_scopes(request)
        if resolved_scopes:
            scope_value = " ".join(resolved_scopes)
            parts.append(f'scope="{scope_value}"')
        if error:
            parts.append(f'error="{error}"')
        return f"Bearer {', '.join(parts)}"

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Skip auth for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "missing_token",
                    "message": "Authorization header with Bearer token required",
                },
                headers={
                    "WWW-Authenticate": self._build_authenticate_header(
                        request,
                        "invalid_token",
                    )
                },
            )

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate token
        try:
            from aws_cli_mcp.auth.multi_idp import TokenValidationError

            validated = await self.validator.validate(token)
        except TokenValidationError as e:
            logger.warning("Token validation failed: %s (%s)", e, e.code)
            return JSONResponse(
                status_code=401,
                content={
                    "error": e.code,
                    "message": str(e),
                },
                headers={"WWW-Authenticate": self._build_authenticate_header(request, e.code)},
            )
        except Exception:
            logger.exception("Unexpected error during token validation")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_error",
                    "message": "Token validation failed",
                },
            )

        # Create RequestContext
        context = RequestContext(
            user_id=validated.user_id,
            email=validated.email,
            groups=validated.groups,
            issuer=validated.issuer,
            token_expiry=validated.expiry,
            token_jti=validated.jti,
            access_token=token,  # Store for STS (never logged)
            raw_claims=validated.raw_claims,
        )
        try:
            enforce_single_user_mode(
                user_id=validated.user_id,
                issuer=validated.issuer,
                allow_multi_user=self.allow_multi_user,
            )
        except MultiUserViolationError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "multi_user_disabled",
                    "message": str(exc),
                },
            )

        # Set context and process request
        ctx_token = set_request_context(context)
        try:
            # Also set user_id on request.state for rate limiting
            request.state.user_id = validated.user_id
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)


class MultiIdPAWSCredentialMiddleware(BaseHTTPMiddleware):
    """
    AWS credential middleware for multi-IdP mode.

    Resolves role from allowlist and assumes role using STS
    with access_token as web identity token.
    """

    EXEMPT_PATHS = _BASE_EXEMPT_PATHS

    def __init__(
        self,
        app: Any,
        role_mapper: Any,
        credential_cache: CredentialCache,
        sts_provider: STSCredentialProvider,
        exempt_paths: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self.role_mapper = role_mapper
        self.credential_cache = credential_cache
        self.sts_provider = sts_provider
        self.exempt_paths = self.EXEMPT_PATHS | set(exempt_paths)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Skip for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Get current context
        from aws_cli_mcp.auth.context import get_request_context_optional, update_request_context

        context = get_request_context_optional()
        if not context:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "no_context",
                    "message": "Authentication required",
                },
            )

        # Resolve role from allowlist
        resolved = self.role_mapper.resolve(context)
        if not resolved:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "no_role_mapping",
                    "message": "No role mapping found for this user",
                },
            )

        # Get or refresh credentials
        try:
            from aws_cli_mcp.aws_credentials.cache import CacheKey

            cache_key = CacheKey(
                user_id=context.user_id,
                account_id=resolved.account_id,
                role_arn=resolved.role_arn,
                token_hash=sha256_text(context.access_token or ""),
            )

            credentials = await self.credential_cache.get_or_refresh(
                key=cache_key,
                refresh_fn=lambda: self.sts_provider.assume_role_for_context(
                    role_arn=resolved.role_arn,
                    context=context,
                ),
            )
        except Exception:
            logger.exception("Failed to assume role: %s", resolved.role_arn)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "credential_error",
                    "message": "Failed to assume role for this user",
                },
            )

        # Update context with AWS credentials
        from aws_cli_mcp.auth.context import AWSCredentials

        aws_creds = AWSCredentials(
            access_key_id=credentials.access_key_id,
            secret_access_key=credentials.secret_access_key,
            session_token=credentials.session_token,
            expiration=credentials.expiration,
        )

        update_request_context(
            lambda ctx: ctx.with_aws_credentials(
                creds=aws_creds,
                account_id=resolved.account_id,
                role_arn=resolved.role_arn,
            )
        )

        return await call_next(request)
