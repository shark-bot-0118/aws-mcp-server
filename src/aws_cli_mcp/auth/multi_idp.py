"""Multi-IdP JWT token validator for OAuth 2.0 Protected Resource."""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from ..utils.http import validate_oidc_url
from .idp_config import IdPConfig, JWKSCacheConfig, MultiIdPConfig

logger = logging.getLogger(__name__)


class TokenValidationError(Exception):
    """Token validation failure with error code."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ValidatedClaims:
    """Validated JWT claims."""

    user_id: str
    email: str | None
    groups: tuple[str, ...] | None
    issuer: str
    expiry: datetime
    jti: str | None
    raw_claims: dict[str, Any]


class JWKSClient:
    """JWKS client with caching and backoff."""

    def __init__(self, jwks_uri: str, config: JWKSCacheConfig) -> None:
        self.jwks_uri = jwks_uri
        self.config = config
        self._jwks_data: dict[str, Any] | None = None
        self._last_fetch: datetime | None = None
        self._last_failure: datetime | None = None
        self._lock = asyncio.Lock()

    async def get_signing_key(self, kid: str | None) -> Any:
        """Get signing key by kid, refreshing JWKS if needed."""
        await self._ensure_jwks_loaded()

        if self._jwks_data is None:
            raise TokenValidationError("JWKS not available", "jwks_error")

        keys = self._jwks_data.get("keys", [])
        if not keys:
            raise TokenValidationError("No keys in JWKS", "jwks_error")

        # Find key by kid if provided
        if kid:
            for key in keys:
                if key.get("kid") == kid:
                    return self._jwk_to_key(key)
            # Kid not found, try refreshing JWKS (key rotation)
            await self._refresh_jwks(force=True)
            if self._jwks_data:
                for key in self._jwks_data.get("keys", []):
                    if key.get("kid") == kid:
                        return self._jwk_to_key(key)
            raise TokenValidationError("Signing key not found", "key_not_found")

        # No kid specified, use first key
        return self._jwk_to_key(keys[0])

    @staticmethod
    def _jwk_to_key(jwk: dict[str, Any]) -> Any:
        """Convert JWK to appropriate key object based on key type."""
        import jwt

        kty = jwk.get("kty", "").upper()

        if kty == "RSA":
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        elif kty == "EC":
            return jwt.algorithms.ECAlgorithm.from_jwk(jwk)
        elif kty == "OKP":
            # Ed25519/Ed448 keys (EdDSA algorithm)
            return jwt.algorithms.OKPAlgorithm.from_jwk(jwk)
        else:
            raise TokenValidationError(
                f"Unsupported key type: {kty}. Supported: RSA, EC, OKP",
                "unsupported_key_type",
            )

    async def _ensure_jwks_loaded(self) -> None:
        """Ensure JWKS is loaded, refreshing if needed."""
        async with self._lock:
            if self._should_refresh():
                await self._refresh_jwks()

    def _should_refresh(self) -> bool:
        """Check if JWKS should be refreshed."""
        if self._jwks_data is None:
            return True

        if self._last_fetch is None:
            return True

        now = datetime.now(timezone.utc)
        age = (now - self._last_fetch).total_seconds()
        threshold = self.config.ttl_seconds - self.config.refresh_before_seconds
        return age >= threshold

    def _can_retry(self) -> bool:
        """Check if we can retry after failure."""
        if self._last_failure is None:
            return True

        now = datetime.now(timezone.utc)
        elapsed = (now - self._last_failure).total_seconds()
        return elapsed >= self.config.failure_backoff_seconds

    async def _refresh_jwks(self, force: bool = False) -> None:
        """Refresh JWKS from remote."""
        if not force and not self._can_retry():
            logger.debug("JWKS refresh skipped (backoff)")
            return

        for attempt in range(self.config.max_retries):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(self.jwks_uri, timeout=10.0)
                    resp.raise_for_status()
                    self._jwks_data = resp.json()
                    self._last_fetch = datetime.now(timezone.utc)
                    self._last_failure = None
                    logger.info("JWKS refreshed from %s", self.jwks_uri)
                    return
            except Exception as e:
                logger.warning("JWKS fetch attempt %d failed: %s", attempt + 1, e)
                if attempt == self.config.max_retries - 1:
                    self._last_failure = datetime.now(timezone.utc)
                    if self._jwks_data is None:
                        raise TokenValidationError(f"JWKS fetch failed: {e}", "jwks_error")
                else:
                    await asyncio.sleep(min(2**attempt, 30))


class SingleIdPValidator:
    """Validator for a single IdP."""

    def __init__(self, idp: IdPConfig, jwks_cache_config: JWKSCacheConfig) -> None:
        self.idp = idp
        self._jwks_client: JWKSClient | None = None
        self._jwks_cache_config = jwks_cache_config
        self._jwks_uri: str | None = idp.jwks_uri
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize JWKS client (discovers JWKS URI if needed)."""
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            if not self._jwks_uri:
                self._jwks_uri = await self._discover_jwks_uri()

            self._jwks_client = JWKSClient(self._jwks_uri, self._jwks_cache_config)
            self._initialized = True
            logger.info("IdP validator initialized: %s", self.idp.name)

    async def _discover_jwks_uri(self) -> str:
        """Discover JWKS URI from OIDC configuration."""
        issuer = self.idp.get_normalized_issuer()
        url = f"{issuer}/.well-known/openid-configuration"

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

        try:
            validate_oidc_url(str(jwks_uri), label="jwks_uri")
        except ValueError as exc:
            raise TokenValidationError(str(exc), "discovery_error") from exc

        logger.info("Discovered JWKS URI for %s: %s", self.idp.name, jwks_uri)
        return str(jwks_uri)

    async def validate_token(self, token: str, header: dict, claims: dict) -> dict[str, Any]:
        """Validate token signature and claims."""
        import jwt

        if not self._initialized:
            await self.initialize()

        if self._jwks_client is None:
            raise TokenValidationError("Validator not initialized", "internal_error")

        # Get signing key
        kid = header.get("kid")
        try:
            key = await self._jwks_client.get_signing_key(kid)
        except TokenValidationError:
            raise
        except Exception as e:
            raise TokenValidationError(f"Failed to get signing key: {e}", "key_error") from e

        # Validate token
        # NOTE: verify_aud is disabled because PyJWT doesn't support azp.
        # aud/azp validation is done manually in MultiIdPValidator._validate_audience_or_azp()
        # before this method is called.
        try:
            validated = jwt.decode(
                token,
                key,
                algorithms=list(self.idp.allowed_algorithms),
                issuer=self.idp.get_normalized_issuer(),
                leeway=self.idp.clock_skew_seconds,
                options={
                    "require": ["iss", "sub", "exp"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": False,
                    "verify_iss": True,
                    "verify_aud": False,  # Handled manually (azp priority)
                },
            )
            return validated
        except jwt.ExpiredSignatureError as e:
            raise TokenValidationError("Token expired", "token_expired") from e
        except jwt.InvalidAudienceError as e:
            raise TokenValidationError("Invalid audience", "invalid_audience") from e
        except jwt.InvalidIssuerError as e:
            raise TokenValidationError("Invalid issuer", "invalid_issuer") from e
        except jwt.ImmatureSignatureError as e:
            raise TokenValidationError("Token not yet valid (nbf)", "token_immature") from e
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid token: {e}", "invalid_token") from e


class MultiIdPValidator:
    """
    Multi-IdP JWT token validator.

    Security features:
    - JWT format detection (rejects opaque tokens)
    - alg=none rejection
    - Issuer allowlist with normalization
    - Required claims: iss + (aud OR azp) + sub + exp
    - aud/azp handling: azp takes priority (AWS STS compatibility)
    - JWKS caching with TTL and failure backoff
    - exp/nbf validation with configurable leeway
    """

    def __init__(self, config: MultiIdPConfig) -> None:
        self.config = config
        self._validators: dict[str, SingleIdPValidator] = {}
        self._allowed_issuers: set[str] = set()

        for idp in config.idps:
            normalized = idp.get_normalized_issuer()
            self._allowed_issuers.add(normalized)
            self._validators[normalized] = SingleIdPValidator(idp, config.jwks_cache)

    @staticmethod
    def _is_jwt_format(token: str) -> bool:
        """Check if token is in JWT format (3 dot-separated base64 parts)."""
        if not token:
            return False

        parts = token.split(".")
        if len(parts) != 3:
            return False

        for part in parts[:2]:  # Only check header and payload
            if not part:  # Empty part is invalid
                return False
            try:
                # Add padding if needed (base64url uses no padding or missing padding)
                # Padding is only needed when len % 4 != 0
                remainder = len(part) % 4
                if remainder:
                    part += "=" * (4 - remainder)
                base64.urlsafe_b64decode(part)
            except Exception:
                return False

        return True

    @staticmethod
    def _normalize_issuer(issuer: str) -> str:
        """Normalize issuer by removing trailing slash."""
        return issuer.rstrip("/")

    def _validate_required_claims(self, claims: dict) -> None:
        """Validate required claims: iss + (aud OR azp) + sub + exp."""
        if "iss" not in claims:
            raise TokenValidationError("Missing required claim: iss", "missing_claim")

        if "sub" not in claims:
            raise TokenValidationError("Missing required claim: sub", "missing_claim")

        if "exp" not in claims:
            raise TokenValidationError("Missing required claim: exp", "missing_claim")

        if "aud" not in claims and "azp" not in claims:
            raise TokenValidationError("Missing required claim: aud or azp", "missing_claim")

    def _validate_audience_or_azp(self, claims: dict, allowed: set[str]) -> bool:
        """
        Validate aud/azp (AWS STS compatible: azp takes priority).

        If both aud and azp are present, AWS STS uses azp as the audience.
        """
        # azp takes priority (AWS STS compatibility)
        if "azp" in claims:
            azp = claims.get("azp")
            return isinstance(azp, str) and azp in allowed

        # Fall back to aud
        aud = claims.get("aud")
        if aud is None:
            return False

        if isinstance(aud, str):
            return aud in allowed

        if isinstance(aud, list):
            aud_values = {value for value in aud if isinstance(value, str)}
            return bool(aud_values & allowed)

        return False

    def _extract_claims(
        self,
        claims: dict,
        idp: IdPConfig,
    ) -> ValidatedClaims:
        """Extract and normalize claims according to IdP mapping."""
        mapping = idp.claims_mapping

        # User ID
        user_id_claim = mapping.get("user_id", "sub")
        user_id = claims.get(user_id_claim, claims.get("sub"))
        if not user_id:
            raise TokenValidationError("Could not determine user_id", "missing_claim")

        # Email (optional)
        email_claim = mapping.get("email", "email")
        email = claims.get(email_claim)

        # Groups (optional, may be huge or missing)
        groups_claim = mapping.get("groups")
        groups = None
        if groups_claim and groups_claim in claims:
            raw_groups = claims[groups_claim]
            if isinstance(raw_groups, list):
                groups = tuple(str(g) for g in raw_groups)
            elif isinstance(raw_groups, str):
                groups = (raw_groups,)

        # Expiry
        exp = claims["exp"]
        if isinstance(exp, (int, float)):
            expiry = datetime.fromtimestamp(exp, tz=timezone.utc)
        else:
            raise TokenValidationError("Invalid exp claim format", "invalid_token")

        return ValidatedClaims(
            user_id=str(user_id),
            email=email,
            groups=groups,
            issuer=idp.get_normalized_issuer(),
            expiry=expiry,
            jti=claims.get("jti"),
            raw_claims=claims,
        )

    async def validate(self, token: str) -> ValidatedClaims:
        """
        Validate JWT token and return validated claims.

        Raises TokenValidationError on any validation failure.
        """
        import jwt

        # 1. Check JWT format (reject opaque tokens)
        if not self._is_jwt_format(token):
            raise TokenValidationError(
                "Token is not in JWT format. Opaque tokens are not supported. "
                "Ensure your IdP is configured to issue JWT-format access tokens.",
                "opaque_token_not_supported",
            )

        # 2. Decode header (unverified)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as e:
            raise TokenValidationError(f"Invalid token header: {e}", "invalid_token")

        # 3. Reject alg=none
        alg = header.get("alg", "")
        if alg.lower() == "none":
            raise TokenValidationError(
                "Algorithm 'none' is not allowed",
                "invalid_algorithm",
            )

        # 4. Decode claims (unverified, for pre-validation)
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as e:
            raise TokenValidationError(f"Invalid token payload: {e}", "invalid_token")

        # 5. Validate required claims
        self._validate_required_claims(unverified)

        # 6. Check issuer allowlist
        raw_issuer = unverified["iss"]
        normalized_issuer = self._normalize_issuer(raw_issuer)

        if normalized_issuer not in self._allowed_issuers:
            # Use generic error message to avoid revealing allowlist contents
            # via error message differentiation.
            raise TokenValidationError(
                "Token validation failed",
                "invalid_token",
            )

        # 7. Get IdP config and validator
        idp = self.config.get_idp_by_issuer(normalized_issuer)
        if idp is None:
            raise TokenValidationError(
                f"No IdP config for issuer: {normalized_issuer}",
                "unknown_issuer",
            )

        validator = self._validators.get(normalized_issuer)
        if validator is None:
            raise TokenValidationError(
                f"No validator for issuer: {normalized_issuer}",
                "internal_error",
            )

        # 8. Check algorithm is allowed
        if alg not in idp.allowed_algorithms:
            raise TokenValidationError(
                f"Algorithm '{alg}' not allowed for issuer {idp.name}",
                "invalid_algorithm",
            )

        # 9. Pre-validate aud/azp before signature verification
        if not self._validate_audience_or_azp(unverified, idp.get_audience_set()):
            raise TokenValidationError("Invalid audience", "invalid_audience")

        # 10. Full validation (signature, exp, nbf, etc.)
        validated_claims = await validator.validate_token(token, header, unverified)

        # 11. Extract and normalize claims
        return self._extract_claims(validated_claims, idp)
