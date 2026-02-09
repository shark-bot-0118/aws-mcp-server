"""Tests for AWS credentials cache and providers."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_cli_mcp.auth.context import RequestContext
from aws_cli_mcp.aws_credentials.cache import CacheKey, CredentialCache
from aws_cli_mcp.aws_credentials.identity_center import (
    IdentityCenterError,
    IdentityCenterProvider,
    get_identity_center_provider,
)
from aws_cli_mcp.aws_credentials.sts_provider import (
    STSCredentialError,
    STSCredentialProvider,
    TemporaryCredentials,
)


def _temp_creds(expiration: datetime | None = None) -> TemporaryCredentials:
    expires_at = expiration or (datetime.now(timezone.utc) + timedelta(hours=1))
    return TemporaryCredentials(
        access_key_id="key",
        secret_access_key="secret",
        session_token="token",
        expiration=expires_at,
        assumed_role_arn="arn:aws:iam::123456789012:role/Role",
        assumed_role_id="role-id",
    )


class TestCredentialCache:
    """Tests for CredentialCache."""

    @pytest.mark.asyncio
    async def test_get_or_refresh_caches_result(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        calls = {"count": 0}

        async def refresh() -> TemporaryCredentials:
            calls["count"] += 1
            return _temp_creds()

        first = await cache.get_or_refresh(key, refresh)
        second = await cache.get_or_refresh(key, refresh)

        assert first == second
        assert calls["count"] == 1

    @pytest.mark.asyncio
    async def test_get_or_refresh_refreshes_expiring_entry(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=3600, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        results = [
            _temp_creds(datetime.now(timezone.utc) + timedelta(minutes=5)),
            _temp_creds(datetime.now(timezone.utc) + timedelta(hours=2)),
        ]

        async def refresh() -> TemporaryCredentials:
            return results.pop(0)

        first = await cache.get_or_refresh(key, refresh)
        second = await cache.get_or_refresh(key, refresh)

        assert second.expiration > first.expiration

    @pytest.mark.asyncio
    async def test_get_or_refresh_single_flight(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        calls = {"count": 0}

        async def refresh() -> TemporaryCredentials:
            calls["count"] += 1
            await asyncio.sleep(0.01)
            return _temp_creds()

        results = await asyncio.gather(
            cache.get_or_refresh(key, refresh),
            cache.get_or_refresh(key, refresh),
            cache.get_or_refresh(key, refresh),
        )

        assert calls["count"] == 1
        assert results[0] == results[1] == results[2]

    @pytest.mark.asyncio
    async def test_get_or_refresh_propagates_refresh_error(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")

        async def refresh() -> TemporaryCredentials:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            await cache.get_or_refresh(key, refresh)

        # Ensure in-flight state is cleaned up and retry is possible.
        with pytest.raises(RuntimeError, match="boom"):
            await cache.get_or_refresh(key, refresh)

    @pytest.mark.asyncio
    async def test_get_or_refresh_cleans_in_flight_on_cancellation(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        gate = asyncio.Event()

        async def blocked_refresh() -> TemporaryCredentials:
            await gate.wait()
            return _temp_creds()

        first = asyncio.create_task(cache.get_or_refresh(key, blocked_refresh))
        for _ in range(100):
            if key in cache._in_flight:
                break
            await asyncio.sleep(0)
        else:
            pytest.fail("single-flight state was not established")

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        async def fast_refresh() -> TemporaryCredentials:
            return _temp_creds(datetime.now(timezone.utc) + timedelta(hours=2))

        result = await asyncio.wait_for(cache.get_or_refresh(key, fast_refresh), timeout=0.5)
        assert result.expiration > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_get_or_refresh_evicts_lru_entry(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=1)
        key1 = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        key2 = CacheKey(user_id="u2", account_id="123", role_arn="arn:role/admin")
        calls = {"k1": 0, "k2": 0}

        async def refresh1() -> TemporaryCredentials:
            calls["k1"] += 1
            return _temp_creds()

        async def refresh2() -> TemporaryCredentials:
            calls["k2"] += 1
            return _temp_creds()

        await cache.get_or_refresh(key1, refresh1)
        await cache.get_or_refresh(key2, refresh2)
        await cache.get_or_refresh(key1, refresh1)

        assert calls["k1"] == 2
        assert calls["k2"] == 1

    @pytest.mark.asyncio
    async def test_get_or_refresh_handles_naive_expiration(self) -> None:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        key = CacheKey(user_id="u1", account_id="123", role_arn="arn:role/read")
        calls = {"count": 0}

        async def refresh() -> TemporaryCredentials:
            calls["count"] += 1
            return TemporaryCredentials(
                access_key_id="key",
                secret_access_key="secret",
                session_token="token",
                expiration=(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None),
                assumed_role_arn="arn:aws:iam::123456789012:role/Role",
                assumed_role_id="role-id",
            )

        await cache.get_or_refresh(key, refresh)
        await cache.get_or_refresh(key, refresh)

        assert calls["count"] == 1


class TestSTSCredentialProvider:
    """Tests for STS provider."""

    @pytest.fixture
    def provider(self) -> STSCredentialProvider:
        return STSCredentialProvider(region="us-east-1")

    @pytest.mark.asyncio
    async def test_assume_role_with_web_identity_success(
        self,
        provider: STSCredentialProvider,
    ) -> None:
        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "key",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::123:assumed-role/Role/session",
                "AssumedRoleId": "role-id:session",
            },
        }

        with patch.object(provider, "_get_client", return_value=mock_sts):
            creds = await provider.assume_role_with_web_identity(
                role_arn="arn:aws:iam::123:role/Role",
                web_identity_token="jwt-token",
                session_name="session",
            )

        assert creds.access_key_id == "key"
        call_kwargs = mock_sts.assume_role_with_web_identity.call_args.kwargs
        assert call_kwargs["RoleArn"] == "arn:aws:iam::123:role/Role"
        assert call_kwargs["WebIdentityToken"] == "jwt-token"
        assert call_kwargs["RoleSessionName"] == "session"

    @pytest.mark.asyncio
    async def test_assume_role_with_web_identity_maps_client_error(
        self,
        provider: STSCredentialProvider,
    ) -> None:
        mock_sts = MagicMock()
        mock_sts.assume_role_with_web_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "AssumeRoleWithWebIdentity",
        )

        with patch.object(provider, "_get_client", return_value=mock_sts):
            with pytest.raises(STSCredentialError) as exc_info:
                await provider.assume_role_with_web_identity(
                    role_arn="arn:aws:iam::123:role/Role",
                    web_identity_token="jwt-token",
                    session_name="session",
                )

        assert exc_info.value.code == "access_denied"

    @pytest.mark.asyncio
    async def test_assume_role_for_context_requires_access_token(
        self,
        provider: STSCredentialProvider,
    ) -> None:
        context = RequestContext(user_id="user-1", issuer="https://issuer.example.com")

        with pytest.raises(STSCredentialError) as exc_info:
            await provider.assume_role_for_context(
                role_arn="arn:aws:iam::123:role/Role",
                context=context,
            )

        assert exc_info.value.code == "missing_token"


class TestIdentityCenterProvider:
    """Tests for Identity Center provider."""

    @pytest.fixture
    def provider(self) -> IdentityCenterProvider:
        cache = CredentialCache(refresh_buffer_seconds=300, max_entries=10)
        return IdentityCenterProvider(region="us-east-1", cache=cache)

    @pytest.mark.asyncio
    async def test_list_accounts_pagination(self, provider: IdentityCenterProvider) -> None:
        mock_sso = MagicMock()
        mock_sso.list_accounts.side_effect = [
            {
                "accountList": [{"accountId": "111111111111", "accountName": "A"}],
                "nextToken": "next",
            },
            {
                "accountList": [{"accountId": "222222222222", "accountName": "B"}],
            },
        ]

        with patch.object(provider, "_get_client", return_value=mock_sso):
            accounts = await provider.list_accounts("sso-token")

        assert [a.account_id for a in accounts] == ["111111111111", "222222222222"]

    @pytest.mark.asyncio
    async def test_list_account_roles_pagination(self, provider: IdentityCenterProvider) -> None:
        mock_sso = MagicMock()
        mock_sso.list_account_roles.side_effect = [
            {"roleList": [{"roleName": "ReadOnly"}], "nextToken": "next"},
            {"roleList": [{"roleName": "Admin"}]},
        ]

        with patch.object(provider, "_get_client", return_value=mock_sso):
            roles = await provider.list_account_roles("sso-token", "111111111111")

        assert [r.role_name for r in roles] == ["ReadOnly", "Admin"]
        assert all(r.account_id == "111111111111" for r in roles)

    @pytest.mark.asyncio
    async def test_list_accounts_pagination_limit(self, provider: IdentityCenterProvider) -> None:
        """When _MAX_PAGES is reached, stop gracefully."""
        from aws_cli_mcp.aws_credentials.identity_center import _MAX_PAGES

        mock_sso = MagicMock()
        # Always return nextToken to simulate infinite pagination
        mock_sso.list_accounts.return_value = {
            "accountList": [{"accountId": "111111111111"}],
            "nextToken": "always",
        }

        with patch.object(provider, "_get_client", return_value=mock_sso):
            accounts = await provider.list_accounts("sso-token")

        assert mock_sso.list_accounts.call_count == _MAX_PAGES
        assert len(accounts) == _MAX_PAGES

    @pytest.mark.asyncio
    async def test_list_account_roles_pagination_limit(
        self, provider: IdentityCenterProvider
    ) -> None:
        """When _MAX_PAGES is reached for roles, stop gracefully."""
        from aws_cli_mcp.aws_credentials.identity_center import _MAX_PAGES

        mock_sso = MagicMock()
        mock_sso.list_account_roles.return_value = {
            "roleList": [{"roleName": "R"}],
            "nextToken": "always",
        }

        with patch.object(provider, "_get_client", return_value=mock_sso):
            roles = await provider.list_account_roles("sso-token", "111111111111")

        assert mock_sso.list_account_roles.call_count == _MAX_PAGES
        assert len(roles) == _MAX_PAGES

    @pytest.mark.asyncio
    async def test_get_role_credentials(self, provider: IdentityCenterProvider) -> None:
        mock_sso = MagicMock()
        mock_sso.get_role_credentials.return_value = {
            "roleCredentials": {
                "accessKeyId": "key",
                "secretAccessKey": "secret",
                "sessionToken": "token",
                "expiration": 1234567890000,
            }
        }

        with patch.object(provider, "_get_client", return_value=mock_sso):
            creds = await provider.get_role_credentials(
                access_token="sso-token",
                account_id="111111111111",
                role_name="ReadOnly",
            )

        assert creds.access_key_id == "key"
        assert creds.assumed_role_arn == "arn:aws:iam::111111111111:role/ReadOnly"
        assert creds.expiration.timestamp() == 1234567890

    @pytest.mark.asyncio
    async def test_get_cached_role_credentials_uses_cache(
        self,
        provider: IdentityCenterProvider,
    ) -> None:
        creds = _temp_creds(datetime.now(timezone.utc) + timedelta(hours=2))
        provider.get_role_credentials = AsyncMock(return_value=creds)  # type: ignore[method-assign]

        first = await provider.get_cached_role_credentials(
            access_token="sso-token",
            account_id="111111111111",
            role_name="ReadOnly",
            user_id="user-1",
        )
        second = await provider.get_cached_role_credentials(
            access_token="sso-token",
            account_id="111111111111",
            role_name="ReadOnly",
            user_id="user-1",
        )

        assert first == second
        assert provider.get_role_credentials.await_count == 1  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_list_accounts_maps_client_error(self, provider: IdentityCenterProvider) -> None:
        mock_sso = MagicMock()
        mock_sso.list_accounts.side_effect = ClientError(
            {"Error": {"Code": "InvalidTokenException", "Message": "invalid"}},
            "ListAccounts",
        )

        with patch.object(provider, "_get_client", return_value=mock_sso):
            with pytest.raises(IdentityCenterError) as exc_info:
                await provider.list_accounts("sso-token")

        assert exc_info.value.code == "invalid_token"

    @pytest.mark.asyncio
    async def test_list_account_roles_maps_client_error(
        self, provider: IdentityCenterProvider
    ) -> None:
        mock_sso = MagicMock()
        mock_sso.list_account_roles.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "slow down"}},
            "ListAccountRoles",
        )
        with patch.object(provider, "_get_client", return_value=mock_sso):
            with pytest.raises(IdentityCenterError) as exc_info:
                await provider.list_account_roles("token", "111111111111")
        assert exc_info.value.code == "throttled"

    @pytest.mark.asyncio
    async def test_get_role_credentials_maps_client_error(
        self, provider: IdentityCenterProvider
    ) -> None:
        mock_sso = MagicMock()
        mock_sso.get_role_credentials.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedException", "Message": "unauthorized"}},
            "GetRoleCredentials",
        )
        with patch.object(provider, "_get_client", return_value=mock_sso):
            with pytest.raises(IdentityCenterError) as exc_info:
                await provider.get_role_credentials("token", "111111111111", "ReadOnly")
        assert exc_info.value.code == "unauthorized"

    def test_get_client_initializes_once(self, provider: IdentityCenterProvider) -> None:
        session = MagicMock()
        session.create_client.return_value = MagicMock()
        with patch(
            "aws_cli_mcp.aws_credentials.identity_center.botocore.session.get_session",
            return_value=session,
        ):
            first = provider._get_client()
            second = provider._get_client()
        assert first is second
        session.create_client.assert_called_once()

    def test_get_client_double_checked_lock_branch(self, provider: IdentityCenterProvider) -> None:
        class _Lock:
            def __enter__(self_nonlocal):
                provider._client = "ready-in-lock"
                return self_nonlocal

            def __exit__(self_nonlocal, exc_type, exc, tb):
                return False

        provider._client = None
        provider._lock = _Lock()  # type: ignore[assignment]
        assert provider._get_client() == "ready-in-lock"


def test_get_identity_center_provider_validates_region() -> None:
    get_identity_center_provider.cache_clear()
    settings = MagicMock()
    settings.auth.identity_center_region = None
    settings.auth.credential_refresh_buffer_seconds = 300
    settings.auth.credential_cache_max_entries = 100
    with patch("aws_cli_mcp.aws_credentials.identity_center.load_settings", return_value=settings):
        with pytest.raises(RuntimeError, match="AUTH_IDENTITY_CENTER_REGION is required"):
            get_identity_center_provider()
    get_identity_center_provider.cache_clear()


def test_get_identity_center_provider_cached_singleton() -> None:
    get_identity_center_provider.cache_clear()
    settings = MagicMock()
    settings.auth.identity_center_region = "us-east-1"
    settings.auth.credential_refresh_buffer_seconds = 60
    settings.auth.credential_cache_max_entries = 10
    with patch("aws_cli_mcp.aws_credentials.identity_center.load_settings", return_value=settings):
        first = get_identity_center_provider()
        second = get_identity_center_provider()
    assert first is second
    get_identity_center_provider.cache_clear()
