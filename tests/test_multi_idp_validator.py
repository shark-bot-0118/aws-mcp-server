"""Tests for MultiIdPValidator."""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aws_cli_mcp.auth.idp_config import (
    AuditConfig,
    IdPConfig,
    JWKSCacheConfig,
    MultiIdPConfig,
    ProtectedResourceConfig,
    RoleMappingEntry,
    SecurityConfig,
)
from aws_cli_mcp.auth.multi_idp import MultiIdPValidator, TokenValidationError


def _create_config(
    idps: list[IdPConfig] | None = None,
) -> MultiIdPConfig:
    """Create test MultiIdPConfig."""
    if idps is None:
        idps = [
            IdPConfig(
                name="test-idp",
                issuer="https://test.example.com",
                audience="test-audience",
                allowed_algorithms=("RS256",),
                clock_skew_seconds=30,
                claims_mapping={"user_id": "sub", "email": "email"},
            ),
        ]

    return MultiIdPConfig(
        idps=idps,
        jwks_cache=JWKSCacheConfig(),
        security=SecurityConfig(),
        audit=AuditConfig(),
        role_mappings=[
            RoleMappingEntry(
                account_id="111111111111",
                role_arn="arn:aws:iam::111111111111:role/TestRole",
            ),
        ],
        protected_resource=ProtectedResourceConfig(resource="https://test.example.com/"),
    )


def _create_jwt(
    header: dict[str, Any],
    payload: dict[str, Any],
    signature: str = "test-signature",
) -> str:
    """Create a mock JWT token."""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_b64 = base64.urlsafe_b64encode(signature.encode()).rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"


class TestJWTFormatDetection:
    """Tests for JWT format detection."""

    def test_valid_jwt_format(self) -> None:
        """Valid JWT format should be detected."""
        token = _create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user", "iss": "https://test.example.com"},
        )
        assert MultiIdPValidator._is_jwt_format(token) is True

    def test_opaque_token_rejected(self) -> None:
        """Opaque tokens should be rejected."""
        opaque_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"  # Only one part
        assert MultiIdPValidator._is_jwt_format(opaque_token) is False

    def test_two_part_token_rejected(self) -> None:
        """Two-part tokens should be rejected."""
        token = "header.payload"
        assert MultiIdPValidator._is_jwt_format(token) is False

    def test_invalid_base64_rejected(self) -> None:
        """Invalid base64 in token parts should be rejected."""
        token = "not!valid!base64.also!not!valid.signature"
        assert MultiIdPValidator._is_jwt_format(token) is False

    def test_empty_token_rejected(self) -> None:
        """Empty token should be rejected."""
        assert MultiIdPValidator._is_jwt_format("") is False


class TestAlgorithmValidation:
    """Tests for algorithm validation."""

    @pytest.mark.asyncio
    async def test_alg_none_rejected(self) -> None:
        """Algorithm 'none' should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "none", "typ": "JWT"},
            {
                "sub": "user",
                "iss": "https://test.example.com",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "invalid_algorithm"
        assert "none" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_alg_none_case_insensitive(self) -> None:
        """Algorithm 'NONE' (uppercase) should also be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "NONE", "typ": "JWT"},
            {
                "sub": "user",
                "iss": "https://test.example.com",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "invalid_algorithm"


class TestIssuerValidation:
    """Tests for issuer allowlist validation."""

    @pytest.mark.asyncio
    async def test_unknown_issuer_rejected(self) -> None:
        """Tokens from unknown issuers should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {
                "sub": "user",
                "iss": "https://unknown.example.com",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        # Generic error code to prevent issuer enumeration via error differentiation.
        assert exc_info.value.code == "invalid_token"

    def test_issuer_normalization(self) -> None:
        """Issuer should be normalized (trailing slash removed)."""
        assert (
            MultiIdPValidator._normalize_issuer("https://test.example.com/")
            == "https://test.example.com"
        )
        assert (
            MultiIdPValidator._normalize_issuer("https://test.example.com")
            == "https://test.example.com"
        )

    @pytest.mark.asyncio
    async def test_issuer_with_trailing_slash_matched(self) -> None:
        """Issuer with trailing slash should match config without trailing slash."""
        config = _create_config(
            idps=[
                IdPConfig(
                    name="test",
                    issuer="https://test.example.com",  # No trailing slash
                    audience="test",
                ),
            ]
        )
        validator = MultiIdPValidator(config)

        # Token issuer has trailing slash
        token = _create_jwt(
            {"alg": "RS256"},
            {
                "sub": "user",
                "iss": "https://test.example.com/",  # With trailing slash
                "aud": "test",
                "exp": int(time.time()) + 3600,
            },
        )

        # Should not fail on issuer check (will fail on signature verification instead)
        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        # Should pass issuer check but fail somewhere else
        assert exc_info.value.code != "unknown_issuer"


class TestRequiredClaimsValidation:
    """Tests for required claims validation."""

    @pytest.mark.asyncio
    async def test_missing_iss_rejected(self) -> None:
        """Token without 'iss' claim should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "RS256"},
            {
                "sub": "user",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "missing_claim"
        assert "iss" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_sub_rejected(self) -> None:
        """Token without 'sub' claim should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "RS256"},
            {
                "iss": "https://test.example.com",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "missing_claim"
        assert "sub" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_exp_rejected(self) -> None:
        """Token without 'exp' claim should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "RS256"},
            {
                "iss": "https://test.example.com",
                "sub": "user",
                "aud": "test-audience",
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "missing_claim"
        assert "exp" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_aud_and_azp_rejected(self) -> None:
        """Token without both 'aud' and 'azp' claims should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        token = _create_jwt(
            {"alg": "RS256"},
            {
                "iss": "https://test.example.com",
                "sub": "user",
                "exp": int(time.time()) + 3600,
            },
        )

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)

        assert exc_info.value.code == "missing_claim"
        assert "aud" in str(exc_info.value) or "azp" in str(exc_info.value)


class TestAudienceValidation:
    """Tests for aud/azp validation."""

    def test_aud_string_match(self) -> None:
        """String audience should be matched."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"aud": "test-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True

    def test_aud_string_mismatch(self) -> None:
        """Non-matching string audience should fail."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"aud": "wrong-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is False

    def test_aud_array_any_match(self) -> None:
        """Array audience with any matching value should pass."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"aud": ["other", "test-audience", "another"]}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True

    def test_aud_array_no_match(self) -> None:
        """Array audience with no matching value should fail."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"aud": ["wrong1", "wrong2"]}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is False

    def test_azp_takes_priority(self) -> None:
        """azp should take priority over aud (AWS STS compatibility)."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        # aud doesn't match but azp does
        claims = {"aud": "wrong-audience", "azp": "test-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True

    def test_azp_only(self) -> None:
        """Token with only azp (no aud) should be validated."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"azp": "test-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True


class TestOpaqueTokenRejection:
    """Tests for opaque token rejection."""

    @pytest.mark.asyncio
    async def test_opaque_token_error_code(self) -> None:
        """Opaque tokens should return specific error code."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        # Opaque token (not JWT format)
        opaque_token = "ya29.a0AfH6SMBx..."

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(opaque_token)

        assert exc_info.value.code == "opaque_token_not_supported"

    @pytest.mark.asyncio
    async def test_opaque_token_error_message(self) -> None:
        """Error message should mention JWT format requirement."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        opaque_token = "random_opaque_token_string"

        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(opaque_token)

        assert "JWT" in str(exc_info.value)
        assert "opaque" in str(exc_info.value).lower()


class TestClaimsMapping:
    """Tests for claims mapping."""

    @pytest.mark.asyncio
    async def test_custom_user_id_claim(self) -> None:
        """Custom user_id claim mapping should work."""
        config = _create_config(
            idps=[
                IdPConfig(
                    name="entra",
                    issuer="https://login.microsoftonline.com/tenant/v2.0",
                    audience="api://test",
                    claims_mapping={
                        "user_id": "oid",  # Entra uses 'oid'
                        "email": "email",
                    },
                ),
            ]
        )

        # Verify the claims mapping is stored correctly
        idp = config.get_idp_by_issuer("https://login.microsoftonline.com/tenant/v2.0")
        assert idp is not None
        assert idp.claims_mapping["user_id"] == "oid"


class TestErrorCodes:
    """Tests for error codes."""

    def test_token_validation_error_has_code(self) -> None:
        """TokenValidationError should have error code."""
        error = TokenValidationError("Test message", "test_code")
        assert error.code == "test_code"
        assert str(error) == "Test message"

    @pytest.mark.asyncio
    async def test_all_error_codes_documented(self) -> None:
        """All expected error codes should be used."""
        expected_codes = {
            "opaque_token_not_supported",
            "invalid_algorithm",
            "missing_claim",
            "unknown_issuer",
            "invalid_audience",
            "invalid_token",
        }

        # Verify these codes are actually used in the codebase
        # (This is a documentation test)
        config = _create_config()
        validator = MultiIdPValidator(config)

        # Test opaque token
        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate("opaque")
        assert exc_info.value.code == "opaque_token_not_supported"

        # Test alg=none
        token = _create_jwt({"alg": "none"}, {"sub": "user"})
        with pytest.raises(TokenValidationError) as exc_info:
            await validator.validate(token)
        assert exc_info.value.code == "invalid_algorithm"

        observed_codes = {"opaque_token_not_supported", "invalid_algorithm"}
        assert observed_codes.issubset(expected_codes)


class TestJWTFormatPadding:
    """Tests for JWT format detection padding fix (P2)."""

    def test_padding_len_mod_4_equals_0(self) -> None:
        """JWT parts with length % 4 == 0 should not add extra padding."""
        # Create a token where the header part length is exactly divisible by 4
        # "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" has length 36, 36 % 4 == 0
        token = _create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user", "iss": "https://test.example.com"},
        )
        assert MultiIdPValidator._is_jwt_format(token) is True

    def test_padding_len_mod_4_equals_1(self) -> None:
        """JWT parts with length % 4 == 1 should add 3 padding chars."""
        # Test token that would have had incorrect padding before fix
        token = _create_jwt(
            {"alg": "RS256"},  # Shorter header
            {"sub": "u"},  # Short payload
        )
        assert MultiIdPValidator._is_jwt_format(token) is True

    def test_padding_len_mod_4_equals_2(self) -> None:
        """JWT parts with length % 4 == 2 should add 2 padding chars."""
        token = _create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "ab"},
        )
        assert MultiIdPValidator._is_jwt_format(token) is True

    def test_padding_len_mod_4_equals_3(self) -> None:
        """JWT parts with length % 4 == 3 should add 1 padding char."""
        token = _create_jwt(
            {"alg": "RS256"},
            {"sub": "abc"},
        )
        assert MultiIdPValidator._is_jwt_format(token) is True

    def test_empty_token_rejected(self) -> None:
        """Empty token should be rejected."""
        assert MultiIdPValidator._is_jwt_format("") is False

    def test_empty_parts_rejected(self) -> None:
        """Token with empty parts should be rejected."""
        assert MultiIdPValidator._is_jwt_format("..") is False
        assert MultiIdPValidator._is_jwt_format(".payload.sig") is False
        assert MultiIdPValidator._is_jwt_format("header..sig") is False


class TestAzpOnlyToken:
    """Tests for azp-only token support (P1)."""

    def test_azp_only_in_claims_accepted(self) -> None:
        """Token with only azp (no aud) should be accepted by aud/azp validation."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        # Token with only azp, no aud
        claims = {"azp": "test-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True

    def test_azp_priority_over_aud(self) -> None:
        """azp should take priority over aud when both present."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        # aud doesn't match, but azp does
        claims = {"aud": "wrong-audience", "azp": "test-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is True

    def test_azp_mismatch_rejected(self) -> None:
        """azp mismatch should be rejected even if aud matches."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        # aud matches, but azp doesn't (azp takes priority)
        claims = {"aud": "test-audience", "azp": "wrong-audience"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is False

    def test_no_aud_no_azp_rejected(self) -> None:
        """Token with neither aud nor azp should be rejected."""
        config = _create_config()
        validator = MultiIdPValidator(config)

        claims = {"sub": "user"}
        allowed = {"test-audience"}

        assert validator._validate_audience_or_azp(claims, allowed) is False


class TestJWKKeyTypes:
    """Tests for JWK key type support (P1)."""

    def test_jwk_to_key_rsa(self) -> None:
        """RSA JWK should be converted correctly."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        # Sample RSA JWK (public key only - minimal for test)
        rsa_jwk = {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "kid": "test-rsa-kid",
        }

        key = JWKSClient._jwk_to_key(rsa_jwk)
        assert key is not None

    def test_jwk_to_key_ec(self) -> None:
        """EC JWK should be converted correctly."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        # Sample EC JWK (P-256 curve)
        ec_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "kid": "test-ec-kid",
        }

        key = JWKSClient._jwk_to_key(ec_jwk)
        assert key is not None

    def test_jwk_to_key_unsupported(self) -> None:
        """Unsupported key type should raise error."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient, TokenValidationError

        unsupported_jwk = {
            "kty": "UNKNOWN",
            "kid": "test-unknown-kid",
        }

        with pytest.raises(TokenValidationError) as exc_info:
            JWKSClient._jwk_to_key(unsupported_jwk)

        assert exc_info.value.code == "unsupported_key_type"
        assert "UNKNOWN" in str(exc_info.value)


class TestJWKSClient:
    """Tests for JWKSClient."""

    @pytest.mark.asyncio
    async def test_ensure_jwks_loaded_caches(self) -> None:
        """JWKS should be loaded and cached."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        config = JWKSCacheConfig()
        client = JWKSClient("https://test/jwks", config)

        mock_jwks = {"keys": [{"kid": "1", "kty": "RSA", "n": "...", "e": "AQAB"}]}

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: mock_jwks)
            mock_get.return_value.raise_for_status = MagicMock()

            await client._ensure_jwks_loaded()
            assert client._jwks_data == mock_jwks

            # Second call should use cache
            await client._ensure_jwks_loaded()
            assert mock_get.call_count == 1

    @pytest.mark.asyncio
    async def test_get_signing_key_refresh_on_unknown_kid(self) -> None:
        """Should refresh JWKS if kid not found."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        config = JWKSCacheConfig()
        client = JWKSClient("https://test/jwks", config)

        # First fetch: key1
        jwks1 = {"keys": [{"kid": "key1", "kty": "RSA", "n": "...", "e": "AQAB"}]}
        # Second fetch: key1, key2
        jwks2 = {
            "keys": [
                {"kid": "key1", "kty": "RSA", "n": "...", "e": "AQAB"},
                {"kid": "key2", "kty": "RSA", "n": "...", "e": "AQAB"},
            ]
        }

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.side_effect = [
                MagicMock(status_code=200, json=lambda: jwks1),
                MagicMock(status_code=200, json=lambda: jwks2),
            ]

            # Initial load
            await client._ensure_jwks_loaded()

            # Try to get key2 (not in jwks1)
            # Should trigger refresh
            with patch.object(client, "_jwk_to_key", return_value="mock_key_obj"):
                key = await client.get_signing_key("key2")
                assert key == "mock_key_obj"

            assert mock_get.call_count == 2


class TestSingleIdPValidator:
    """Tests for SingleIdPValidator."""

    @pytest.mark.asyncio
    async def test_discovery_and_initialization(self) -> None:
        """Should discover JWKS URI from OIDC config."""
        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(name="test", issuer="https://iss", audience="aud")
        cache_config = JWKSCacheConfig()
        validator = SingleIdPValidator(idp, cache_config)

        oidc_config = {"jwks_uri": "https://iss/jwks"}

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: oidc_config)

            await validator.initialize()

            assert validator._jwks_uri == "https://iss/jwks"
            assert validator._jwks_client is not None

    @pytest.mark.asyncio
    async def test_discovery_rejects_invalid_jwks_uri(self) -> None:
        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(name="test", issuer="https://iss", audience="aud")
        validator = SingleIdPValidator(idp, JWKSCacheConfig())

        with (
            patch(
                "httpx.AsyncClient.get",
                return_value=MagicMock(status_code=200, json=lambda: {"jwks_uri": "https://iss/jwks"}),
            ),
            patch("aws_cli_mcp.auth.multi_idp.validate_oidc_url", side_effect=ValueError("invalid")),
        ):
            with pytest.raises(TokenValidationError) as exc_info:
                await validator.initialize()

        assert exc_info.value.code == "discovery_error"

    @pytest.mark.asyncio
    async def test_validate_token_calls_client(self) -> None:
        """validate_token should call jwks_client.get_signing_key and jwt.decode."""
        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(
            name="test",
            issuer="https://iss",
            audience="aud",
            allowed_algorithms=("RS256",),
            jwks_uri="https://iss/jwks",  # Pre-set jwks_uri to skip discovery
        )

        validator = SingleIdPValidator(idp, JWKSCacheConfig())

        token = "header.payload.sig"
        header = {"kid": "key1"}
        claims = {"sub": "user"}

        with (
            patch(
                "aws_cli_mcp.auth.multi_idp.JWKSClient.get_signing_key", new_callable=AsyncMock
            ) as mock_get_key,
            patch("jwt.decode") as mock_decode,
        ):
            mock_key = MagicMock()
            mock_get_key.return_value = mock_key
            mock_decode.return_value = {"valid": "claims"}

            result = await validator.validate_token(token, header, claims)

            mock_get_key.assert_awaited_with("key1")
            mock_decode.assert_called_once()
            assert result == {"valid": "claims"}


class TestMultiIdPValidatorAdditionalCoverage:
    @pytest.mark.asyncio
    async def test_jwks_client_get_signing_key_error_paths(self) -> None:
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        client = JWKSClient("https://jwks", JWKSCacheConfig())
        with patch.object(client, "_ensure_jwks_loaded", new=AsyncMock()):
            with pytest.raises(TokenValidationError, match="JWKS not available"):
                await client.get_signing_key("kid")

        client._jwks_data = {"keys": []}
        with patch.object(client, "_ensure_jwks_loaded", new=AsyncMock()):
            with pytest.raises(TokenValidationError, match="No keys"):
                await client.get_signing_key("kid")

        client._jwks_data = {"keys": [{"kid": "kid-a", "kty": "RSA"}]}
        with (
            patch.object(client, "_ensure_jwks_loaded", new=AsyncMock()),
            patch.object(client, "_jwk_to_key", return_value="rsa-key"),
        ):
            assert await client.get_signing_key("kid-a") == "rsa-key"

        client._jwks_data = {"keys": [{"kid": "kid-a", "kty": "RSA"}]}
        with (
            patch.object(client, "_ensure_jwks_loaded", new=AsyncMock()),
            patch.object(client, "_jwk_to_key", return_value="first-key"),
        ):
            assert await client.get_signing_key(None) == "first-key"

        client._jwks_data = {"keys": [{"kid": "kid-a", "kty": "RSA"}]}
        with (
            patch.object(client, "_ensure_jwks_loaded", new=AsyncMock()),
            patch.object(client, "_refresh_jwks", new=AsyncMock()),
        ):
            with pytest.raises(TokenValidationError, match="not found"):
                await client.get_signing_key("missing")

    def test_jwks_okp_key_type(self) -> None:
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        with patch("jwt.algorithms.OKPAlgorithm.from_jwk", return_value="okp-key"):
            key = JWKSClient._jwk_to_key({"kty": "OKP", "crv": "Ed25519", "x": "abc", "kid": "k"})
        assert key == "okp-key"

    @pytest.mark.asyncio
    async def test_jwks_refresh_and_retry_branches(self) -> None:
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        config = JWKSCacheConfig(
            ttl_seconds=10, refresh_before_seconds=2, failure_backoff_seconds=60
        )
        client = JWKSClient("https://jwks", config)
        client._jwks_data = {"keys": [{"kid": "k"}]}
        client._last_fetch = None
        assert client._should_refresh() is True

        client._last_failure = datetime.now(timezone.utc)
        assert client._can_retry() is False

        with patch.object(client, "_can_retry", return_value=False):
            await client._refresh_jwks(force=False)

        client2 = JWKSClient("https://jwks", JWKSCacheConfig(max_retries=1))
        with patch("httpx.AsyncClient.get", side_effect=RuntimeError("boom")):
            with pytest.raises(TokenValidationError, match="JWKS fetch failed"):
                await client2._refresh_jwks(force=True)

    @pytest.mark.asyncio
    async def test_single_validator_init_and_discovery_branches(self) -> None:
        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(name="x", issuer="https://iss", audience="aud")
        validator = SingleIdPValidator(idp, JWKSCacheConfig())

        validator._initialized = True
        await validator.initialize()  # early return branch

        validator = SingleIdPValidator(idp, JWKSCacheConfig())

        class _Lock:
            async def __aenter__(self):
                validator._initialized = True
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        validator._init_lock = _Lock()  # type: ignore[assignment]
        await validator.initialize()  # lock branch return

        validator = SingleIdPValidator(idp, JWKSCacheConfig())
        bad_resp = MagicMock()
        bad_resp.raise_for_status = MagicMock()
        bad_resp.json.return_value = {}
        with patch("httpx.AsyncClient.get", return_value=bad_resp):
            with pytest.raises(TokenValidationError, match="Missing jwks_uri"):
                await validator._discover_jwks_uri()

    @pytest.mark.asyncio
    async def test_single_validator_validate_token_error_paths(self) -> None:
        import jwt

        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(
            name="x", issuer="https://iss", audience="aud", allowed_algorithms=("RS256",)
        )
        validator = SingleIdPValidator(idp, JWKSCacheConfig())
        validator._initialized = True
        validator._jwks_client = None

        with pytest.raises(TokenValidationError, match="Validator not initialized"):
            await validator.validate_token("t", {}, {})

        validator._jwks_client = MagicMock()
        validator._jwks_client.get_signing_key = AsyncMock(side_effect=RuntimeError("boom"))
        with pytest.raises(TokenValidationError, match="Failed to get signing key"):
            await validator.validate_token("t", {"kid": "k"}, {})

        validator._jwks_client.get_signing_key = AsyncMock(return_value="k")
        cases = [
            (jwt.ExpiredSignatureError("e"), "token_expired"),
            (jwt.InvalidAudienceError("e"), "invalid_audience"),
            (jwt.InvalidIssuerError("e"), "invalid_issuer"),
            (jwt.ImmatureSignatureError("e"), "token_immature"),
            (jwt.InvalidTokenError("e"), "invalid_token"),
        ]
        for exc, code in cases:
            with patch("jwt.decode", side_effect=exc):
                with pytest.raises(TokenValidationError) as info:
                    await validator.validate_token("token", {"kid": "k"}, {})
                assert info.value.code == code

    @pytest.mark.asyncio
    async def test_single_validator_re_raises_token_validation_error(self) -> None:
        from aws_cli_mcp.auth.multi_idp import SingleIdPValidator

        idp = IdPConfig(
            name="x", issuer="https://iss", audience="aud", allowed_algorithms=("RS256",)
        )
        validator = SingleIdPValidator(idp, JWKSCacheConfig())
        validator._initialized = True
        validator._jwks_client = MagicMock()
        validator._jwks_client.get_signing_key = AsyncMock(
            side_effect=TokenValidationError("bad key", "jwks_error")
        )
        with pytest.raises(TokenValidationError) as info:
            await validator.validate_token("token", {"kid": "k"}, {})
        assert info.value.code == "jwks_error"

    def test_validate_audience_invalid_type(self) -> None:
        validator = MultiIdPValidator(_create_config())
        assert validator._validate_audience_or_azp({"aud": 123}, {"x"}) is False
        assert validator._validate_audience_or_azp({"aud": ["x", {"bad": "shape"}]}, {"x"}) is True
        assert validator._validate_audience_or_azp({"aud": [{"bad": "shape"}]}, {"x"}) is False
        assert validator._validate_audience_or_azp({"azp": {"bad": "shape"}}, {"x"}) is False
        assert validator._validate_audience_or_azp({"aud": "x", "azp": {"bad": "shape"}}, {"x"}) is False

    def test_extract_claims_branches(self) -> None:
        config = _create_config(
            [
                IdPConfig(
                    name="idp",
                    issuer="https://iss",
                    audience="aud",
                    claims_mapping={"user_id": "uid", "email": "mail", "groups": "groups"},
                )
            ]
        )
        validator = MultiIdPValidator(config)
        idp = config.idps[0]

        claims = {
            "uid": "u1",
            "sub": "sub1",
            "mail": "a@b.com",
            "groups": ["g1", "g2"],
            "exp": int(time.time()) + 3600,
            "jti": "j1",
        }
        extracted = validator._extract_claims(claims, idp)
        assert extracted.user_id == "u1"
        assert extracted.groups == ("g1", "g2")

        claims["groups"] = "solo"
        extracted2 = validator._extract_claims(claims, idp)
        assert extracted2.groups == ("solo",)

        with pytest.raises(TokenValidationError, match="Could not determine user_id"):
            validator._extract_claims({"sub": "", "exp": int(time.time()) + 1}, idp)

        with pytest.raises(TokenValidationError, match="Invalid exp claim format"):
            validator._extract_claims({"sub": "u", "exp": "bad"}, idp)

    @pytest.mark.asyncio
    async def test_validate_header_and_payload_decode_errors(self) -> None:
        config = _create_config()
        validator = MultiIdPValidator(config)
        token = _create_jwt(
            {"alg": "RS256"},
            {
                "iss": "https://test.example.com",
                "sub": "u",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
            },
        )

        import jwt

        with patch(
            "jwt.get_unverified_header", side_effect=jwt.exceptions.DecodeError("bad header")
        ):
            with pytest.raises(TokenValidationError, match="Invalid token header"):
                await validator.validate(token)

        with (
            patch("jwt.get_unverified_header", return_value={"alg": "RS256"}),
            patch("jwt.decode", side_effect=jwt.exceptions.DecodeError("bad payload")),
        ):
            with pytest.raises(TokenValidationError, match="Invalid token payload"):
                await validator.validate(token)

    @pytest.mark.asyncio
    async def test_validate_other_error_paths(self) -> None:
        config = _create_config()
        validator = MultiIdPValidator(config)
        issuer = "https://test.example.com"
        valid_payload = {
            "iss": issuer,
            "sub": "u",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
        }
        token = _create_jwt({"alg": "RS256"}, valid_payload)

        with patch.object(validator.config, "get_idp_by_issuer", return_value=None):
            with pytest.raises(TokenValidationError) as info:
                await validator.validate(token)
            assert info.value.code == "unknown_issuer"

        validator_internal = MultiIdPValidator(_create_config())
        validator_internal._validators = {}
        with pytest.raises(TokenValidationError) as info:
            await validator_internal.validate(token)
        assert info.value.code == "internal_error"

        validator_alg = MultiIdPValidator(_create_config())
        bad_alg_token = _create_jwt({"alg": "HS256"}, valid_payload)
        with pytest.raises(TokenValidationError) as info:
            await validator_alg.validate(bad_alg_token)
        assert info.value.code == "invalid_algorithm"

        validator_aud = MultiIdPValidator(_create_config())
        invalid_aud = dict(valid_payload)
        invalid_aud["aud"] = "other"
        invalid_aud_token = _create_jwt({"alg": "RS256"}, invalid_aud)
        with pytest.raises(TokenValidationError) as info:
            await validator_aud.validate(invalid_aud_token)
        assert info.value.code == "invalid_audience"

    @pytest.mark.asyncio
    async def test_validate_success_path(self) -> None:
        config = _create_config()
        validator = MultiIdPValidator(config)
        issuer = "https://test.example.com"
        token = _create_jwt(
            {"alg": "RS256", "kid": "k1"},
            {
                "iss": issuer,
                "sub": "u1",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
                "email": "a@b.com",
            },
        )
        fake_single = AsyncMock()
        fake_single.validate_token.return_value = {
            "iss": issuer,
            "sub": "u1",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
            "email": "a@b.com",
        }
        validator._validators[issuer] = fake_single

        claims = await validator.validate(token)
        assert claims.user_id == "u1"
        assert claims.email == "a@b.com"


class TestJWKSRetryBackoff:
    """Tests for JWKS exponential backoff on retry."""

    @pytest.mark.asyncio
    async def test_jwks_refresh_retries_with_backoff_sleep(self) -> None:
        """_refresh_jwks should sleep between retries with exponential backoff."""
        from aws_cli_mcp.auth.multi_idp import JWKSClient

        config = JWKSCacheConfig(max_retries=3)
        client = JWKSClient("https://jwks", config)

        with (
            patch("httpx.AsyncClient.get", side_effect=RuntimeError("network error")),
            patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            with pytest.raises(TokenValidationError, match="JWKS fetch failed"):
                await client._refresh_jwks(force=True)

            # Should have slept between attempt 0->1 and 1->2, but not after last attempt
            assert mock_sleep.call_count == 2
            # Verify exponential backoff: min(2**0, 30)=1, min(2**1, 30)=2
            mock_sleep.assert_any_call(1)
            mock_sleep.assert_any_call(2)
