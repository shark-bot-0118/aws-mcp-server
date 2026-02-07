"""IAM Identity Center (SSO) credential provider."""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

import botocore.session
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli_mcp.aws_credentials.cache import CacheKey, CredentialCache
from aws_cli_mcp.aws_credentials.sts_provider import TemporaryCredentials
from aws_cli_mcp.config import load_settings
from aws_cli_mcp.utils.hashing import sha256_text

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AccountEntry:
    account_id: str
    account_name: str | None = None
    email_address: str | None = None


@dataclass(frozen=True)
class RoleEntry:
    account_id: str
    role_name: str


class IdentityCenterError(Exception):
    """Raised when Identity Center credential acquisition fails."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class IdentityCenterProvider:
    """Thread-safe Identity Center provider for SSO access tokens."""

    def __init__(self, region: str, cache: CredentialCache) -> None:
        self._region = region
        self._cache = cache
        self._client: Any = None
        self._lock = threading.Lock()

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        with self._lock:
            if self._client is not None:
                return self._client
            session = botocore.session.get_session()
            self._client = session.create_client(
                "sso",
                region_name=self._region,
                config=Config(
                    signature_version=UNSIGNED,
                    connect_timeout=5,
                    read_timeout=15,
                    retries={"max_attempts": 2},
                ),
            )
            logger.info("Identity Center SSO client initialized (region=%s)", self._region)
            return self._client

    async def list_accounts(self, access_token: str) -> list[AccountEntry]:
        return await asyncio.to_thread(self._list_accounts_sync, access_token)

    async def list_account_roles(self, access_token: str, account_id: str) -> list[RoleEntry]:
        return await asyncio.to_thread(self._list_account_roles_sync, access_token, account_id)

    async def get_role_credentials(
        self,
        access_token: str,
        account_id: str,
        role_name: str,
    ) -> TemporaryCredentials:
        return await asyncio.to_thread(
            self._get_role_credentials_sync,
            access_token,
            account_id,
            role_name,
        )

    async def get_cached_role_credentials(
        self,
        access_token: str,
        account_id: str,
        role_name: str,
        user_id: str,
    ) -> TemporaryCredentials:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        token_hash = sha256_text(access_token)
        key = CacheKey(
            user_id=user_id,
            account_id=account_id,
            role_arn=role_arn,
            token_hash=token_hash,
        )

        async def refresh() -> TemporaryCredentials:
            return await self.get_role_credentials(access_token, account_id, role_name)

        return await self._cache.get_or_refresh(key, refresh)

    def _list_accounts_sync(self, access_token: str) -> list[AccountEntry]:
        client = self._get_client()
        accounts: list[AccountEntry] = []
        token: str | None = None

        try:
            while True:
                params: dict[str, Any] = {"accessToken": access_token}
                if token:
                    params["nextToken"] = token
                resp = client.list_accounts(**params)
                for entry in resp.get("accountList", []) or []:
                    accounts.append(
                        AccountEntry(
                            account_id=str(entry.get("accountId")),
                            account_name=entry.get("accountName"),
                            email_address=entry.get("emailAddress"),
                        )
                    )
                token = resp.get("nextToken")
                if not token:
                    break
        except ClientError as exc:
            raise self._map_client_error(exc)

        return accounts

    def _list_account_roles_sync(self, access_token: str, account_id: str) -> list[RoleEntry]:
        client = self._get_client()
        roles: list[RoleEntry] = []
        token: str | None = None

        try:
            while True:
                params: dict[str, Any] = {"accessToken": access_token, "accountId": account_id}
                if token:
                    params["nextToken"] = token
                resp = client.list_account_roles(**params)
                for entry in resp.get("roleList", []) or []:
                    roles.append(
                        RoleEntry(
                            account_id=account_id,
                            role_name=str(entry.get("roleName")),
                        )
                    )
                token = resp.get("nextToken")
                if not token:
                    break
        except ClientError as exc:
            raise self._map_client_error(exc)

        return roles

    def _get_role_credentials_sync(
        self,
        access_token: str,
        account_id: str,
        role_name: str,
    ) -> TemporaryCredentials:
        client = self._get_client()
        try:
            resp = client.get_role_credentials(
                accessToken=access_token,
                accountId=account_id,
                roleName=role_name,
            )
        except ClientError as exc:
            raise self._map_client_error(exc)

        creds = resp.get("roleCredentials") or {}
        expiration_ms = int(creds.get("expiration", 0))
        expiration = datetime.fromtimestamp(expiration_ms / 1000, tz=timezone.utc)

        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        return TemporaryCredentials(
            access_key_id=creds.get("accessKeyId", ""),
            secret_access_key=creds.get("secretAccessKey", ""),
            session_token=creds.get("sessionToken", ""),
            expiration=expiration,
            assumed_role_arn=role_arn,
            assumed_role_id=role_name,
        )

    def _map_client_error(self, exc: ClientError) -> IdentityCenterError:
        error = exc.response.get("Error", {})
        code = error.get("Code", "Unknown")
        message = error.get("Message", str(exc))

        code_map = {
            "UnauthorizedException": "unauthorized",
            "InvalidRequestException": "invalid_request",
            "InvalidTokenException": "invalid_token",
            "TooManyRequestsException": "throttled",
        }

        logger.warning("Identity Center error: %s: %s", code, message)
        return IdentityCenterError(message, code=code_map.get(code, "sso_error"))


@lru_cache(maxsize=1)
def get_identity_center_provider() -> IdentityCenterProvider:
    settings = load_settings()
    region = settings.auth.identity_center_region
    if not region:
        raise RuntimeError("AUTH_IDENTITY_CENTER_REGION is required for identity-center auth provider")
    cache = CredentialCache(
        refresh_buffer_seconds=settings.auth.credential_refresh_buffer_seconds,
        max_entries=settings.auth.credential_cache_max_entries,
    )
    return IdentityCenterProvider(region=region, cache=cache)
