"""STS AssumeRoleWithWebIdentity credential provider.

IMPORTANT: This provider uses access_token (not id_token) for web identity federation.
AWS STS accepts both OAuth 2.0 access tokens and OIDC ID tokens as long as they:
- Are in JWT format
- Contain required claims: iss, sub, exp, and (aud or azp)
- Are signed by a key from the OIDC provider's JWKS

The RoleSessionName is mandatory for audit traceability.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import botocore.session
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from ..auth.context import RequestContext

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
    """Thread-safe STS provider for AssumeRoleWithWebIdentity."""

    def __init__(self, region: str = "us-east-1") -> None:
        self._region = region
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
                "sts",
                region_name=self._region,
                config=Config(
                    signature_version=UNSIGNED,
                    connect_timeout=5,
                    read_timeout=15,
                    retries={"max_attempts": 2},
                ),
            )
            logger.info("STS client initialized (UNSIGNED, region=%s)", self._region)
            return self._client

    async def assume_role_with_web_identity(
        self,
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int = 3600,
    ) -> TemporaryCredentials:
        """
        Assume role using web identity token (access_token).

        Args:
            role_arn: The ARN of the role to assume
            web_identity_token: The access_token from IdP (JWT format required)
            session_name: Session name for audit trail (MANDATORY)
            duration_seconds: Credential validity duration

        Returns:
            TemporaryCredentials with AWS access keys

        Raises:
            STSCredentialError: If STS call fails
        """
        return await asyncio.to_thread(
            self._assume_role_sync,
            role_arn,
            web_identity_token,
            session_name,
            duration_seconds,
        )

    async def assume_role_for_context(
        self,
        role_arn: str,
        context: "RequestContext",
        duration_seconds: int = 3600,
    ) -> TemporaryCredentials:
        """
        Assume role using RequestContext (recommended method).

        This method:
        - Uses access_token from context (NOT id_token)
        - Generates mandatory RoleSessionName from user_id

        Args:
            role_arn: The ARN of the role to assume
            context: RequestContext with access_token and user info
            duration_seconds: Credential validity duration

        Returns:
            TemporaryCredentials with AWS access keys

        Raises:
            STSCredentialError: If access_token is missing or STS call fails
        """
        if not context.access_token:
            raise STSCredentialError(
                "access_token is required for STS AssumeRoleWithWebIdentity",
                "missing_token",
            )

        # Generate session name from user_id (mandatory)
        session_name = f"mcp-{context.user_id[:32]}"

        return await self.assume_role_with_web_identity(
            role_arn=role_arn,
            web_identity_token=context.access_token,
            session_name=session_name,
            duration_seconds=duration_seconds,
        )

    def _assume_role_sync(
        self,
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int,
    ) -> TemporaryCredentials:
        client = self._get_client()
        safe_session_name = self._sanitize_session_name(session_name)

        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": safe_session_name,
            "WebIdentityToken": web_identity_token,
            "DurationSeconds": duration_seconds,
        }

        try:
            response = client.assume_role_with_web_identity(**params)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            error_message = exc.response.get("Error", {}).get("Message", str(exc))

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
                "STS failed: role=%s, session=%s, error=%s: %s",
                role_arn,
                safe_session_name,
                error_code,
                error_message,
            )
            raise STSCredentialError(
                error_message, code=code_map.get(error_code, "sts_error")
            ) from exc

        creds = response["Credentials"]
        assumed = response["AssumedRoleUser"]

        logger.info("Assumed role: %s, session=%s", role_arn, safe_session_name)

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
