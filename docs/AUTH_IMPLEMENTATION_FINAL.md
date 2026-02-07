# Final Authentication Implementation Plan

## Overview

This document provides the finalized design for HTTP + OAuth authentication with per-user AWS credential isolation. All constraints are explicitly addressed.

---

## 1. STS Client: UNSIGNED, Thread-Safe Initialization

### Design

- STS `AssumeRoleWithWebIdentity` is an **unsigned** API call
- Authentication is via `WebIdentityToken` parameter, not SigV4
- Client initialized once at startup (thread-safe singleton)
- No ambient AWS credentials required on the server

### Implementation

```python
# src/aws_cli_mcp/aws_credentials/sts_provider.py

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import botocore.session
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TemporaryCredentials:
    """Immutable temporary AWS credentials from STS."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str
    assumed_role_id: str

    def __repr__(self) -> str:
        return (
            f"TemporaryCredentials(access_key_id={self.access_key_id[:8]}***, "
            f"expiration={self.expiration.isoformat()})"
        )


class STSCredentialError(Exception):
    """Raised when STS credential acquisition fails."""
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class STSCredentialProvider:
    """
    Thread-safe STS provider for AssumeRoleWithWebIdentity.

    Uses UNSIGNED signature - no ambient AWS credentials required.
    Client is lazily initialized with thread-safe locking.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self._region = region
        self._client: Any = None
        self._lock = threading.Lock()

    def _get_client(self) -> Any:
        """
        Get or create the STS client (thread-safe).

        Uses UNSIGNED signature because AssumeRoleWithWebIdentity
        authenticates via the WebIdentityToken, not SigV4.
        """
        if self._client is not None:
            return self._client

        with self._lock:
            # Double-check after acquiring lock
            if self._client is not None:
                return self._client

            session = botocore.session.get_session()
            self._client = session.create_client(
                "sts",
                region_name=self._region,
                config=Config(
                    signature_version=UNSIGNED,  # CRITICAL: No SigV4 signing
                    connect_timeout=5,
                    read_timeout=15,
                    retries={"max_attempts": 2},
                ),
            )
            logger.info(f"STS client initialized (UNSIGNED, region={self._region})")
            return self._client

    async def assume_role_with_web_identity(
        self,
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int = 3600,
        session_tags: dict[str, str] | None = None,
    ) -> TemporaryCredentials:
        """
        Exchange OIDC token for temporary AWS credentials.

        ASYNC: Runs the synchronous STS call in a thread pool
        to avoid blocking the ASGI event loop.

        Args:
            role_arn: IAM role to assume (must trust the OIDC provider)
            web_identity_token: The OIDC JWT selected for STS (see section 3)
            session_name: Session identifier for CloudTrail
            duration_seconds: Credential validity (900-43200, role-dependent)
            session_tags: Optional ABAC session tags

        Returns:
            TemporaryCredentials instance

        Raises:
            STSCredentialError: If STS call fails
        """
        return await asyncio.to_thread(
            self._assume_role_sync,
            role_arn,
            web_identity_token,
            session_name,
            duration_seconds,
            session_tags,
        )

    def _assume_role_sync(
        self,
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int,
        session_tags: dict[str, str] | None,
    ) -> TemporaryCredentials:
        """Synchronous STS call (runs in thread pool)."""
        client = self._get_client()
        safe_session_name = self._sanitize_session_name(session_name)

        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": safe_session_name,
            "WebIdentityToken": web_identity_token,
            "DurationSeconds": duration_seconds,
        }

        if session_tags:
            params["Tags"] = [
                {"Key": k, "Value": v}
                for k, v in session_tags.items()
            ]

        try:
            response = client.assume_role_with_web_identity(**params)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            code_map = {
                "MalformedPolicyDocument": "policy_error",
                "PackedPolicyTooLarge": "policy_too_large",
                "IDPRejectedClaim": "idp_rejected",
                "IDPCommunicationError": "idp_error",
                "InvalidIdentityToken": "invalid_token",
                "ExpiredTokenException": "token_expired",
                "RegionDisabledException": "region_disabled",
                "AccessDenied": "access_denied",
            }

            logger.warning(
                f"STS failed: role={role_arn}, session={safe_session_name}, "
                f"error={error_code}: {error_message}"
            )
            raise STSCredentialError(error_message, code=code_map.get(error_code, "sts_error")) from e

        creds = response["Credentials"]
        assumed = response["AssumedRoleUser"]

        logger.info(f"Assumed role: {role_arn}, session={safe_session_name}")

        return TemporaryCredentials(
            access_key_id=creds["AccessKeyId"],
            secret_access_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            expiration=creds["Expiration"],
            assumed_role_arn=assumed["Arn"],
            assumed_role_id=assumed["AssumedRoleId"],
        )

    def _sanitize_session_name(self, name: str) -> str:
        """Sanitize for STS (2-64 chars, alphanumeric/=.@-)."""
        safe = re.sub(r"[^a-zA-Z0-9=.@-]", "-", name)
        safe = re.sub(r"-+", "-", safe).strip("-")
        if len(safe) > 64:
            suffix = hashlib.sha256(name.encode()).hexdigest()[:8]
            safe = safe[:55] + "-" + suffix
        return safe if len(safe) >= 2 else "mcp-" + safe
```

---

## 2. Async Wrappers for All Blocking I/O

### Design

All boto3/botocore network calls MUST be wrapped in `asyncio.to_thread()`:
- STS AssumeRoleWithWebIdentity (covered above)
- JWKS fetching and JWT verification
- All AWS service API calls in tools

### 2.1 OIDC Validator (Async-Safe)

Initialize must be idempotent and safe under concurrent calls. Guard the entire
async initialize path with an asyncio.Lock to avoid duplicate discovery/JWKS
initialization under load.

```python
# src/aws_cli_mcp/auth/oidc.py

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OIDCConfig:
    """OIDC provider configuration."""
    issuer: str
    audience: str
    jwks_uri: str | None = None
    clock_skew_seconds: int = 30
    jwt_algs: tuple[str, ...] = ("RS256", "ES256", "RS384", "ES384")


class TokenValidationError(Exception):
    """Token validation failure."""
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class OIDCValidator:
    """
    Async-safe OIDC token validator.

    All potentially blocking operations (JWKS fetch, JWT decode)
    are run in thread pool via asyncio.to_thread().
    """

    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
        self._jwks_client: Any = None
        self._jwks_uri: str | None = config.jwks_uri
        self._init_lock = threading.Lock()
        self._async_init_lock = asyncio.Lock()
        self._async_init_done = False

    async def initialize(self) -> None:
        """
        Pre-initialize JWKS client (call at startup).

        This warms the cache to avoid cold-start latency.
        """
        if self._async_init_done:
            return

        # Guard against concurrent initialization under load
        async with self._async_init_lock:
            if self._async_init_done:
                return

            # Discover JWKS URI if not provided
            if not self._jwks_uri:
                self._jwks_uri = await self._discover_jwks_uri_async()

            # Initialize PyJWKClient in thread (it may fetch on init)
            await asyncio.to_thread(self._init_jwks_client_sync)
            self._async_init_done = True
            logger.info(f"OIDC validator initialized: {self.config.issuer}")

    def _init_jwks_client_sync(self) -> None:
        """Initialize PyJWKClient (sync, runs in thread)."""
        with self._init_lock:
            if self._jwks_client is not None:
                return
            from jwt import PyJWKClient
            self._jwks_client = PyJWKClient(
                self._jwks_uri,
                cache_jwk_set=True,
                lifespan=3600,
            )

    async def _discover_jwks_uri_async(self) -> str:
        """Discover JWKS URI from OIDC configuration (async httpx)."""
        url = f"{self.config.issuer.rstrip('/')}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(url, timeout=10.0)
                resp.raise_for_status()
                doc = resp.json()
            except httpx.HTTPError as e:
                raise TokenValidationError(f"OIDC discovery failed: {e}", "discovery_error") from e

        jwks_uri = doc.get("jwks_uri")
        if not jwks_uri:
            raise TokenValidationError("Missing jwks_uri in discovery", "discovery_error")
        logger.info(f"Discovered JWKS: {jwks_uri}")
        return jwks_uri

    async def validate_token(self, token: str) -> dict[str, Any]:
        """
        Validate JWT token (async-safe).

        Runs synchronous PyJWT operations in thread pool.
        """
        if not self._async_init_done:
            await self.initialize()

        return await asyncio.to_thread(self._validate_token_sync, token)

    def _validate_token_sync(self, token: str) -> dict[str, Any]:
        """Synchronous JWT validation (runs in thread pool)."""
        import jwt

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self.config.jwt_algs),
                issuer=self.config.issuer,
                audience=self.config.audience,
                leeway=self.config.clock_skew_seconds,
                options={
                    "require": ["sub", "iss", "aud", "exp", "iat"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
            return claims

        except jwt.ExpiredSignatureError:
            raise TokenValidationError("Token expired", "token_expired")
        except jwt.InvalidAudienceError:
            raise TokenValidationError("Invalid audience", "invalid_audience")
        except jwt.InvalidIssuerError:
            raise TokenValidationError("Invalid issuer", "invalid_issuer")
        except jwt.ImmatureSignatureError:
            raise TokenValidationError("Token not yet valid", "token_immature")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid token: {e}", "invalid_token")
```

### 2.2 AWS Client Factory (Async Wrapper)

Minimal diff to existing `aws_client.py`:

```python
# src/aws_cli_mcp/execution/aws_client.py (MODIFIED)

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config

from aws_cli_mcp.config import load_settings

if TYPE_CHECKING:
    from aws_cli_mcp.auth.context import RequestContext

# Existing cache for stdio mode
_CLIENT_CACHE: dict[tuple[str, str | None, str | None], object] = {}

# NOTE: _CLIENT_CACHE is not thread-safe when get_client() is executed via
# asyncio.to_thread(). Choose one:
# - Remove _CLIENT_CACHE entirely (preferred for simplicity), OR
# - Protect _CLIENT_CACHE with threading.Lock, OR
# - Ensure stdio and HTTP modes never run concurrently in the same process.
# Plan choice: protect _CLIENT_CACHE with threading.Lock and use it only in stdio
# mode. HTTP mode must not rely on any global client cache.


def get_client(
    service: str,
    region: str | None,
    profile: str | None = None,
    ctx: "RequestContext | None" = None,
):
    """
    Get boto3 client (synchronous).

    In HTTP mode (ctx provided): Uses request-scoped credentials.
    In stdio mode (ctx=None): Uses ambient credentials.
    """
    settings = load_settings()

    # HTTP mode: per-request credentials from context
    if ctx is not None and ctx.aws_credentials is not None:
        return _create_client_with_credentials(service, ctx, region, settings)

    # stdio mode: cached client with ambient credentials
    key = (service, region, profile)
    if key in _CLIENT_CACHE:
        return _CLIENT_CACHE[key]

    session = boto3.Session(
        profile_name=profile or settings.aws_default_profile,
        region_name=region or settings.aws_default_region,
    )
    config = _get_service_config(service, settings)
    client = session.client(service, config=config)
    _CLIENT_CACHE[key] = client
    return client


def _create_client_with_credentials(
    service: str,
    ctx: "RequestContext",
    region: str | None,
    settings,
):
    """Create client with explicit credentials from context."""
    creds = ctx.aws_credentials
    session = boto3.Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        region_name=region or settings.aws_default_region,
    )
    config = _get_service_config(service, settings)
    return session.client(service, config=config)


def _get_service_config(service: str, settings) -> Config:
    """Get service-specific botocore config."""
    base = {
        "connect_timeout": settings.execution.sdk_timeout_seconds,
        "read_timeout": settings.execution.sdk_timeout_seconds,
    }
    if service == "s3":
        base["request_checksum_calculation"] = "when_required"
        base["response_checksum_validation"] = "when_required"
    return Config(**base)


# === ASYNC WRAPPERS (NEW) ===

async def get_client_async(
    service: str,
    region: str | None,
    profile: str | None = None,
    ctx: "RequestContext | None" = None,
):
    """Async wrapper for get_client (runs in thread pool)."""
    return await asyncio.to_thread(get_client, service, region, profile, ctx)


async def call_aws_api_async(
    client,
    method_name: str,
    **kwargs,
):
    """
    Execute AWS API call asynchronously.

    Wraps the synchronous boto3 call in asyncio.to_thread()
    to avoid blocking the ASGI event loop.

    Usage:
        client = await get_client_async("s3", "us-east-1", ctx=ctx)
        result = await call_aws_api_async(client, "list_buckets")
    """
    method = getattr(client, method_name)
    return await asyncio.to_thread(method, **kwargs)
```

### 2.3 Tool Integration Point

Minimal change to `tools/aws_unified.py` execution path:

```python
# src/aws_cli_mcp/tools/aws_unified.py (execution section, MODIFIED)

# BEFORE (synchronous):
# client = get_client(service, region, profile)
# result = getattr(client, method_name)(**params)

# AFTER (async with context):
from aws_cli_mcp.execution.aws_client import get_client_async, call_aws_api_async
from aws_cli_mcp.auth.context import get_request_context_optional

async def _execute_aws_operation(
    service: str,
    operation: str,
    params: dict,
    region: str | None,
) -> dict:
    """Execute AWS operation with proper async handling."""
    # Get request context (None in stdio mode)
    ctx = get_request_context_optional()

    # Get client (async to avoid blocking)
    client = await get_client_async(service, region, ctx=ctx)

    # Convert operation to method name
    method_name = _to_snake_case(operation)

    # Execute API call (async)
    result = await call_aws_api_async(client, method_name, **params)

    return result
```

---

## 3. Token Model (Strict Two-Token)

### Required Headers

```
Authorization: Bearer <ACCESS_TOKEN>
X-Id-Token: <ID_TOKEN>
```

Both headers are mandatory. Requests missing either token MUST be rejected with 401.

### Validation & Claim Authority

- **Access Token**: Validated at the HTTP boundary (JWKS + iss/aud/exp/nbf/iat).
  Its claims are the **only authority** for API authorization decisions (groups,
  roles, email, sub) and for role mapping.
- **ID Token**: Validated before calling STS (JWKS + iss/aud/exp/nbf/iat). It is
  **only** used as the WebIdentityToken for STS and for subject matching.
- **Anti-substitution**: `access.sub` MUST equal `id.sub` and `access.iss` MUST
  equal `id.iss`. If mismatch, hard-fail with `error_code="token_subject_mismatch"`
  or `error_code="token_issuer_mismatch"` and do NOT call STS.

### Token Flow (Two-Token Model)

```
Client                                 MCP Server                           STS
  |                                       |                                 |
  |-- Authorization: Bearer <ACCESS> ---->|                                 |
  |-- X-Id-Token: <ID_TOKEN> ------------>|                                 |
  |                                       |-- Validate ACCESS (JWKS) ------>|
  |                                       |<- access claims ----------------|
  |                                       |-- Validate ID (JWKS) ---------->|
  |                                       |<- id claims --------------------|
  |                                       |-- Enforce access.sub == id.sub  |
  |                                       |-- AssumeRoleWithWebIdentity ----|
  |                                       |   WebIdentityToken: <ID_TOKEN>  |
  |                                       |<- Temp Credentials -------------|
  |<-- MCP Response ---------------------|                                 |
```

### STS Token Selection & IAM Trust Policy Alignment

- **STS token**: The **ID token only** (never the access token).
- **IAM trust policy**: Conditions (issuer string, aud/sub/token_use/etc.) MUST
  match the ID token’s claims exactly.
- **Checklist before rollout**: validate `iss`, `aud`, and `token_use` (or
  equivalent) for both tokens; verify the IAM trust policy matches the ID token.

### IAM Role Trust Policy

The IAM role must trust the OIDC provider and validate token claims:

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "Federated": "arn:aws:iam::111111111111:oidc-provider/login.example.com"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {
                "login.example.com:aud": "YOUR_CLIENT_ID"
            }
        }
    }]
}
```

Where:
- The **issuer string** and the **IAM OIDC provider identifier** must be configured
  per IdP and must match the **ID token** claim format exactly.
- `YOUR_CLIENT_ID` = Expected audience (from the ID token’s `aud` claim).

### Issuer & Condition-Key Configuration (Avoid Fragile Parsing)

Do not derive condition keys from hostname only. Configure explicitly:
- `iam_condition_key_prefix`: Exact IAM condition key prefix for your IdP.
  (Example: Cognito uses `cognito-idp.<region>.amazonaws.com/<pool_id>:aud`).

TODO: Provide IdP-specific examples for issuer and IAM condition keys
(Cognito/Azure/Okta/Auth0/Google).

### Implementation Notes

```python
# In OIDCAuthMiddleware:
# 1. Extract Authorization (access token) + X-Id-Token (id token)
# 2. Validate both tokens
# 3. Enforce access.sub == id.sub
# 4. Store access/id tokens + claims on request.state
# 5. Build RequestContext from ACCESS token claims only

# In AWSCredentialMiddleware:
# 1. Read ID token from request.state (do NOT parse headers)
# 2. Pass ID token to STS AssumeRoleWithWebIdentity
```

### Provider-Specific Configuration

Both access and ID tokens are required; claim structure and issuer/audience may
differ by IdP. Configure validation for each token explicitly.

---

## 4. ContextVar Lifecycle: Strict set()/reset(token) Pattern

### Implementation

```python
# src/aws_cli_mcp/auth/context.py

from __future__ import annotations

import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable


@dataclass(frozen=True)
class AWSCredentials:
    """Immutable temporary AWS credentials."""
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime

    def __repr__(self) -> str:
        return f"AWSCredentials(access_key_id={self.access_key_id[:8]}***, ...)"


@dataclass(frozen=True)
class RequestContext:
    """Immutable request-scoped context."""
    user_id: str
    email: str | None = None
    groups: tuple[str, ...] = ()
    issuer: str = ""
    token_expiry: datetime | None = None
    token_jti: str | None = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    received_at: datetime = field(default_factory=datetime.utcnow)
    aws_credentials: AWSCredentials | None = None
    aws_account_id: str | None = None
    aws_role_arn: str | None = None
    raw_claims: dict[str, Any] = field(default_factory=dict)

    def with_aws_credentials(
        self,
        creds: AWSCredentials,
        account_id: str,
        role_arn: str,
    ) -> RequestContext:
        """Return new context with AWS credentials."""
        return RequestContext(
            user_id=self.user_id,
            email=self.email,
            groups=self.groups,
            issuer=self.issuer,
            token_expiry=self.token_expiry,
            token_jti=self.token_jti,
            request_id=self.request_id,
            received_at=self.received_at,
            aws_credentials=creds,
            aws_account_id=account_id,
            aws_role_arn=role_arn,
            raw_claims=self.raw_claims,
        )


# ContextVar (default=None means "no context")
_request_context: ContextVar[RequestContext | None] = ContextVar(
    "request_context",
    default=None,
)


def set_request_context(ctx: RequestContext) -> Token[RequestContext | None]:
    """
    Set context, return reset token.

    MUST call reset_request_context(token) in finally block.
    """
    return _request_context.set(ctx)


def reset_request_context(token: Token[RequestContext | None]) -> None:
    """Reset context using token from set_request_context()."""
    _request_context.reset(token)


def get_request_context() -> RequestContext:
    """Get context or raise RuntimeError."""
    ctx = _request_context.get()
    if ctx is None:
        raise RuntimeError("No request context set")
    return ctx


def get_request_context_optional() -> RequestContext | None:
    """Get context or None (for dual-mode code)."""
    return _request_context.get()


def update_request_context(
    updater: Callable[[RequestContext], RequestContext],
) -> Token[RequestContext | None]:
    """
    Update context with a function, return reset token.

    Usage:
        token = update_request_context(lambda c: c.with_aws_credentials(...))
        try:
            ...
        finally:
            reset_request_context(token)
    """
    current = get_request_context()
    return _request_context.set(updater(current))
```

---

## 5. Middleware Stack: Correct Ordering with Exemptions

### Middleware Order

```
Request Flow:
  ↓ RequestIdMiddleware (always runs)
  ↓ OIDCAuthMiddleware (skips exempt paths)
  ↓ AWSCredentialMiddleware (skips exempt paths)
  ↓ MCP Handler

Response Flow:
  ↑ MCP Handler
  ↑ AWSCredentialMiddleware (reset context)
  ↑ OIDCAuthMiddleware (reset context)
  ↑ RequestIdMiddleware
```

### Exempt Paths

Both auth middlewares MUST skip the same paths:

```python
EXEMPT_PATHS = frozenset({"/health", "/ready"})
EXEMPT_PREFIXES = ("/.well-known/",)
```

### Implementation

```python
# src/aws_cli_mcp/auth/middleware.py

from __future__ import annotations

import logging
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from aws_cli_mcp.auth.context import (
    RequestContext,
    set_request_context,
    reset_request_context,
)
from aws_cli_mcp.auth.oidc import OIDCValidator, TokenValidationError

logger = logging.getLogger(__name__)

# Shared exemption configuration
EXEMPT_PATHS = frozenset({"/health", "/ready"})
EXEMPT_PREFIXES = ("/.well-known/",)


def is_exempt_path(path: str) -> bool:
    """Check if path is exempt from authentication."""
    if path in EXEMPT_PATHS:
        return True
    return any(path.startswith(p) for p in EXEMPT_PREFIXES)


class OIDCAuthMiddleware(BaseHTTPMiddleware):
    """
    OIDC authentication middleware.

    - Validates Bearer JWT from Authorization header
    - Sets RequestContext for downstream middleware
    - Skips exempt paths (health checks, etc.)
    - Uses strict set()/reset(token) for context lifecycle
    """

    def __init__(self, app, access_validator: OIDCValidator, id_validator: OIDCValidator, auth_url: str | None = None):
        super().__init__(app)
        self.access_validator = access_validator
        self.id_validator = id_validator
        self.auth_url = auth_url

    async def dispatch(self, request: Request, call_next):
        # Exempt paths bypass auth entirely
        if is_exempt_path(request.url.path):
            return await call_next(request)

        # Extract Authorization + X-Id-Token headers
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._unauthorized("Missing or invalid Authorization header", "missing_access_token")

        access_token = auth_header[7:]  # Strip "Bearer "
        id_token = request.headers.get("X-Id-Token", "")
        if not id_token:
            return self._unauthorized("Missing X-Id-Token header", "missing_id_token")

        # Validate access token
        try:
            access_claims = await self.access_validator.validate_token(access_token)
        except TokenValidationError as e:
            logger.warning(f"Token validation failed: {e.code}")
            return self._unauthorized(str(e), e.code)

        # Validate ID token
        try:
            id_claims = await self.id_validator.validate_token(id_token)
        except TokenValidationError as e:
            logger.warning(f"Token validation failed: {e.code}")
            return self._unauthorized(str(e), e.code)

        # Anti-substitution
        if access_claims.get("sub") != id_claims.get("sub"):
            return self._unauthorized("Token subject mismatch", "token_subject_mismatch")

        # Build context from validated claims
        ctx = RequestContext(
            user_id=access_claims["sub"],
            email=access_claims.get("email"),
            groups=tuple(self._extract_groups(access_claims)),
            issuer=access_claims["iss"],
            token_expiry=datetime.utcfromtimestamp(access_claims["exp"]),
            token_jti=access_claims.get("jti"),
            raw_claims=access_claims,
        )

        # Store validated tokens/claims for downstream use
        request.state.access_token = access_token
        request.state.id_token = id_token
        request.state.access_claims = access_claims
        request.state.id_claims = id_claims

        # Set context with proper lifecycle
        context_token = set_request_context(ctx)
        try:
            response = await call_next(request)
            return response
        finally:
            reset_request_context(context_token)

    def _extract_groups(self, claims: dict) -> list[str]:
        """Extract groups from various claim formats."""
        for key in ("groups", "roles", "cognito:groups"):
            if key in claims:
                val = claims[key]
                return val if isinstance(val, list) else [val]
        return []

    def _unauthorized(self, message: str, code: str = "unauthorized") -> JSONResponse:
        body = {"error": "unauthorized", "error_description": message, "error_code": code}
        if self.auth_url:
            body["auth_url"] = self.auth_url
        return JSONResponse(body, status_code=401, headers={
            "WWW-Authenticate": f'Bearer error="{code}"',
        })
```

```python
# src/aws_cli_mcp/auth/aws_credential_middleware.py

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from aws_cli_mcp.auth.context import (
    AWSCredentials,
    get_request_context_optional,
    reset_request_context,
    update_request_context,
)
from aws_cli_mcp.auth.middleware import is_exempt_path
from aws_cli_mcp.aws_credentials.cache import CacheKey, CredentialCache
from aws_cli_mcp.aws_credentials.role_mapping import RoleMapper
from aws_cli_mcp.aws_credentials.sts_provider import (
    STSCredentialError,
    STSCredentialProvider,
)

logger = logging.getLogger(__name__)


class AWSCredentialMiddleware(BaseHTTPMiddleware):
    """
    AWS credential acquisition middleware.

    MUST run after OIDCAuthMiddleware.
    Uses same exempt paths as OIDCAuthMiddleware.
    Uses strict set()/reset(token) for context lifecycle.
    """

    def __init__(
        self,
        app,
        role_mapper: RoleMapper,
        credential_cache: CredentialCache,
        sts_provider: STSCredentialProvider,
    ):
        super().__init__(app)
        self.role_mapper = role_mapper
        self.cache = credential_cache
        self.sts = sts_provider

    async def dispatch(self, request: Request, call_next):
        # Same exemptions as auth middleware
        if is_exempt_path(request.url.path):
            return await call_next(request)

        # Get context from auth middleware
        ctx = get_request_context_optional()
        if ctx is None:
            logger.error("No context set - middleware order incorrect?")
            return JSONResponse(
                {"error": "internal_error", "message": "Auth context missing"},
                status_code=500,
            )

        # Resolve role mapping
        mapping = self.role_mapper.resolve_role(
            user_id=ctx.user_id,
            email=ctx.email,
            groups=ctx.groups,
            raw_claims=ctx.raw_claims,
        )

        if mapping is None:
            logger.warning(f"No role mapping for: {ctx.user_id}")
            return JSONResponse(
                {"error": "access_denied", "error_description": "No role mapping"},
                status_code=403,
            )

        # Get the validated ID token (stored by auth middleware)
        id_token = getattr(request.state, "id_token", None)
        if not id_token:
            logger.error("No ID token in request state")
            return JSONResponse(
                {"error": "internal_error", "message": "Token not propagated"},
                status_code=500,
            )

        # Get or refresh credentials
        cache_key = CacheKey(
            user_id=ctx.user_id,
            account_id=mapping.account_id,
            role_arn=mapping.role_arn,
        )

        try:
            async def refresh():
                return await self.sts.assume_role_with_web_identity(
                    role_arn=mapping.role_arn,
                    web_identity_token=id_token,
                    session_name=f"mcp-{ctx.user_id[:32]}",
                    session_tags={
                        "mcp:user_id": ctx.user_id[:128],
                        "mcp:request_id": ctx.request_id[:128],
                    },
                )

            temp_creds = await self.cache.get_or_refresh(cache_key, refresh)
        except STSCredentialError as e:
            logger.warning(f"STS error for {ctx.user_id}: {e.code}")
            return JSONResponse(
                {"error": "credential_error", "error_code": e.code, "error_description": str(e)},
                status_code=403,
            )

        # Update context with credentials
        aws_creds = AWSCredentials(
            access_key_id=temp_creds.access_key_id,
            secret_access_key=temp_creds.secret_access_key,
            session_token=temp_creds.session_token,
            expiration=temp_creds.expiration,
        )

        # Strict context lifecycle
        context_token = update_request_context(
            lambda c: c.with_aws_credentials(aws_creds, mapping.account_id, mapping.role_arn)
        )

        try:
            return await call_next(request)
        finally:
            reset_request_context(context_token)
```

### Credential Cache (Async Contract)

```python
# src/aws_cli_mcp/aws_credentials/cache.py

from __future__ import annotations

from typing import Awaitable, Callable

class CredentialCache:
    async def get_or_refresh(
        self,
        key: CacheKey,
        refresh_fn: Callable[[], Awaitable[TemporaryCredentials]],
    ) -> TemporaryCredentials:
        ...
        # MUST await refresh_fn() to avoid caching coroutine objects
        creds = await refresh_fn()
        ...
        return creds
```

### Application Assembly

```python
# src/aws_cli_mcp/transport/http_server.py

from pathlib import Path

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

from aws_cli_mcp.auth.oidc import OIDCValidator, OIDCConfig
from aws_cli_mcp.auth.middleware import OIDCAuthMiddleware
from aws_cli_mcp.auth.aws_credential_middleware import AWSCredentialMiddleware
from aws_cli_mcp.aws_credentials.cache import CredentialCache
from aws_cli_mcp.aws_credentials.role_mapping import RoleMapper
from aws_cli_mcp.aws_credentials.sts_provider import STSCredentialProvider
from aws_cli_mcp.config import load_settings


def create_http_app() -> Starlette:
    """Create the HTTP MCP server application."""
    settings = load_settings()

    # Initialize services
    access_validator = OIDCValidator(OIDCConfig(
        issuer=settings.auth.access_token_issuer,
        audience=settings.auth.access_token_audience,
        jwks_uri=settings.auth.access_token_jwks_uri,
        jwt_algs=settings.auth.access_token_algs,
    ))

    id_validator = OIDCValidator(OIDCConfig(
        issuer=settings.auth.id_token_issuer,
        audience=settings.auth.id_token_audience,
        jwks_uri=settings.auth.id_token_jwks_uri,
        jwt_algs=settings.auth.id_token_algs,
    ))

    role_mapper = RoleMapper.from_yaml(Path(settings.auth.role_mapping_path))

    credential_cache = CredentialCache(
        refresh_buffer_seconds=settings.auth.credential_refresh_buffer_seconds,
        max_entries=settings.auth.credential_cache_max_entries,
    )

    sts_provider = STSCredentialProvider(region=settings.aws.sts_region)

    # Middleware stack (Starlette applies in REVERSE order)
    # So list them: first-to-run at the END
    middleware = [
        # Runs LAST (closest to handler): AWS credentials
        Middleware(
            AWSCredentialMiddleware,
            role_mapper=role_mapper,
            credential_cache=credential_cache,
            sts_provider=sts_provider,
        ),
        # Runs SECOND: OIDC authentication
        Middleware(
            OIDCAuthMiddleware,
            access_validator=access_validator,
            id_validator=id_validator,
            auth_url=settings.auth.authorization_url,
        ),
        # Runs FIRST: Request ID (could add logging here)
        # Middleware(RequestIdMiddleware),
    ]

    async def mcp_handler(request):
        """MCP JSON-RPC endpoint."""
        from aws_cli_mcp.transport.mcp_handler import handle_mcp_request
        return await handle_mcp_request(request)

    async def health_handler(request):
        """Health check - no auth required."""
        return JSONResponse({"status": "healthy"})

    async def ready_handler(request):
        """Readiness check - no auth required."""
        return JSONResponse({"status": "ready"})

    routes = [
        Route("/mcp", endpoint=mcp_handler, methods=["POST"]),
        Route("/health", endpoint=health_handler, methods=["GET"]),
        Route("/ready", endpoint=ready_handler, methods=["GET"]),
    ]

    async def startup() -> None:
        await _startup(oidc_validator, sts_provider)

    app = Starlette(
        routes=routes,
        middleware=middleware,
        on_startup=[startup],  # async callable; Starlette will await
    )

    return app


async def _startup(
    access_validator: OIDCValidator,
    id_validator: OIDCValidator,
    sts_provider: STSCredentialProvider,
):
    """Initialize services at startup."""
    # Warm OIDC JWKS cache
    await access_validator.initialize()
    await id_validator.initialize()
    # Initialize STS client (thread-safe, but good to do early)
    # If strict non-blocking startup is desired:
    # await asyncio.to_thread(sts_provider._get_client)
    sts_provider._get_client()
```

---

## Summary: Key Integration Points

### Files to Create

| File | Purpose |
|------|---------|
| `src/aws_cli_mcp/auth/__init__.py` | Auth module exports |
| `src/aws_cli_mcp/auth/context.py` | RequestContext, ContextVar management |
| `src/aws_cli_mcp/auth/oidc.py` | OIDC token validation (async-safe) |
| `src/aws_cli_mcp/auth/middleware.py` | OIDCAuthMiddleware |
| `src/aws_cli_mcp/auth/aws_credential_middleware.py` | AWSCredentialMiddleware |
| `src/aws_cli_mcp/aws_credentials/__init__.py` | Credentials module exports |
| `src/aws_cli_mcp/aws_credentials/sts_provider.py` | STS with UNSIGNED client |
| `src/aws_cli_mcp/aws_credentials/cache.py` | Credential cache (single-flight) |
| `src/aws_cli_mcp/aws_credentials/role_mapping.py` | Claims → Role ARN mapping |
| `src/aws_cli_mcp/transport/http_server.py` | Starlette app assembly |

### Files to Modify

| File | Changes |
|------|---------|
| `src/aws_cli_mcp/execution/aws_client.py` | Add `ctx` parameter, `get_client_async`, `call_aws_api_async` |
| `src/aws_cli_mcp/tools/aws_unified.py` | Use async wrappers in execution path |
| `src/aws_cli_mcp/config.py` | Add auth settings |
| `src/aws_cli_mcp/server.py` | Add HTTP transport mode |

### Configuration Files

| File | Purpose |
|------|---------|
| `role_mappings.yaml` | User claims → AWS role mapping |
| `.env` additions | Auth settings (issuer, audience, etc.) |

---

## Environment Variables (New)

```bash
# Access Token (API auth)
AUTH_ACCESS_TOKEN_ISSUER=https://example.com/issuer
AUTH_ACCESS_TOKEN_AUDIENCE=your-api-audience
AUTH_ACCESS_TOKEN_JWKS_URI=  # Optional, auto-discovered
AUTH_ACCESS_TOKEN_ALGS=RS256,PS256

# ID Token (STS)
AUTH_ID_TOKEN_ISSUER=https://example.com/issuer
AUTH_ID_TOKEN_AUDIENCE=your-app-client-id
AUTH_ID_TOKEN_JWKS_URI=  # Optional, auto-discovered
AUTH_ID_TOKEN_ALGS=RS256,PS256

AUTH_IAM_CONDITION_KEY_PREFIX=  # e.g., cognito-idp.<region>.amazonaws.com/<pool_id>

# Auth URLs (for 401 responses)
AUTH_AUTHORIZATION_URL=https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize

# Role mapping
AUTH_ROLE_MAPPING_PATH=./role_mappings.yaml

# Credential cache
AUTH_CREDENTIAL_REFRESH_BUFFER_SECONDS=300
AUTH_CREDENTIAL_CACHE_MAX_ENTRIES=1000

# STS
AWS_STS_REGION=us-east-1

# Operational hardening
AWS_EC2_METADATA_DISABLED=true

# Transport mode
TRANSPORT_MODE=http  # or "stdio" for local dev
```
