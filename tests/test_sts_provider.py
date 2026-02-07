"""Tests for STSCredentialProvider web identity flow."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aws_cli_mcp.auth.context import RequestContext
from aws_cli_mcp.aws_credentials.sts_provider import (
    STSCredentialProvider,
    TemporaryCredentials,
)


class _FakeSTSClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def assume_role_with_web_identity(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {
            "Credentials": {
                "AccessKeyId": "ASIAXXXXXXXX",
                "SecretAccessKey": "secret",
                "SessionToken": "session-token",
                "Expiration": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::111111111111:assumed-role/TestRole/mcp-user",
                "AssumedRoleId": "AROATEST:mcp-user",
            },
        }


def test_assume_role_sync_omits_tags_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = STSCredentialProvider(region="us-east-1")
    fake_client = _FakeSTSClient()
    monkeypatch.setattr(provider, "_get_client", lambda: fake_client)

    creds = provider._assume_role_sync(  # noqa: SLF001
        role_arn="arn:aws:iam::111111111111:role/TestRole",
        web_identity_token="jwt-token",
        session_name="mcp-user",
        duration_seconds=3600,
    )

    assert isinstance(creds, TemporaryCredentials)
    assert len(fake_client.calls) == 1
    call = fake_client.calls[0]
    assert call["RoleArn"] == "arn:aws:iam::111111111111:role/TestRole"
    assert call["RoleSessionName"] == "mcp-user"
    assert call["WebIdentityToken"] == "jwt-token"
    assert call["DurationSeconds"] == 3600
    assert "Tags" not in call


@pytest.mark.asyncio
async def test_assume_role_for_context_calls_web_identity_without_tags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = STSCredentialProvider(region="us-east-1")
    captured: dict[str, object] = {}

    async def _fake_assume_role_with_web_identity(  # noqa: ANN202
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int = 3600,
    ) -> TemporaryCredentials:
        captured["role_arn"] = role_arn
        captured["web_identity_token"] = web_identity_token
        captured["session_name"] = session_name
        captured["duration_seconds"] = duration_seconds
        return TemporaryCredentials(
            access_key_id="ASIAXXXXXXXX",
            secret_access_key="secret",
            session_token="session-token",
            expiration=datetime(2026, 1, 1, tzinfo=timezone.utc),
            assumed_role_arn="arn:aws:sts::111111111111:assumed-role/TestRole/mcp-user",
            assumed_role_id="AROATEST:mcp-user",
        )

    monkeypatch.setattr(
        provider,
        "assume_role_with_web_identity",
        _fake_assume_role_with_web_identity,
    )

    ctx = RequestContext(
        user_id="user-123",
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        access_token="jwt-token",
    )
    creds = await provider.assume_role_for_context(
        role_arn="arn:aws:iam::111111111111:role/TestRole",
        context=ctx,
        duration_seconds=1800,
    )

    assert isinstance(creds, TemporaryCredentials)
    assert captured["role_arn"] == "arn:aws:iam::111111111111:role/TestRole"
    assert captured["web_identity_token"] == "jwt-token"
    assert captured["duration_seconds"] == 1800
    assert isinstance(captured["session_name"], str)
    assert str(captured["session_name"]).startswith("mcp-user-123")
