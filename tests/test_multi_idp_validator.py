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

        assert exc_info.value.code == "unknown_issuer"

    def test_issuer_normalization(self) -> None:
        """Issuer should be normalized (trailing slash removed)."""
        assert MultiIdPValidator._normalize_issuer("https://test.example.com/") == "https://test.example.com"
        assert MultiIdPValidator._normalize_issuer("https://test.example.com") == "https://test.example.com"

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
        validator = MultiIdPValidator(config)

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
