"""AWS client factory."""

from __future__ import annotations

import asyncio
import base64
import threading

import boto3
from botocore.config import Config

from aws_cli_mcp.auth.context import get_request_context_optional
from aws_cli_mcp.config import load_settings

_CLIENT_CACHE: dict[tuple[str, str | None, str | None], object] = {}
_CLIENT_CACHE_LOCK = threading.Lock()


class RequestContextError(RuntimeError):
    pass


def get_client(
    service: str,
    region: str | None,
    profile: str | None,
    ctx=None,
):
    settings = load_settings()
    if ctx is None:
        ctx = get_request_context_optional()

    if settings.server.transport_mode in {"http", "remote"}:
        if ctx is None or getattr(ctx, "aws_credentials", None) is None:
            raise RequestContextError(
                "HTTP/remote mode requires request-scoped AWS credentials"
            )
        # In HTTP mode, we always use the context credentials
        return _create_client_with_credentials(service, ctx, region, settings)

    # In stdio mode, use context credentials if present (unlikely but possible)
    if ctx is not None and getattr(ctx, "aws_credentials", None) is not None:
        return _create_client_with_credentials(service, ctx, region, settings)

    key = (service, region, profile)
    with _CLIENT_CACHE_LOCK:
        if key in _CLIENT_CACHE:
            return _CLIENT_CACHE[key]

    session = boto3.Session(
        profile_name=profile or settings.aws.default_profile,
        region_name=region or settings.aws.default_region,
    )
    config = _get_service_config(service, settings)
    client = session.client(service, config=config)
    with _CLIENT_CACHE_LOCK:
        _CLIENT_CACHE[key] = client
    return client


def _create_client_with_credentials(service: str, ctx, region: str | None, settings):
    creds = ctx.aws_credentials
    session = boto3.Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        region_name=region or settings.aws.default_region,
    )
    config = _get_service_config(service, settings)
    return session.client(service, config=config)


def _get_service_config(service: str, settings) -> Config:
    base = {
        "read_timeout": settings.execution.sdk_timeout_seconds,
        "connect_timeout": settings.execution.sdk_timeout_seconds,
    }
    if service == "s3":
        base["request_checksum_calculation"] = "when_required"
        base["response_checksum_validation"] = "when_required"
    return Config(**base)


def _truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3] + "..."


def _read_streaming_fields(
    response: dict[str, object],
    max_output_characters: int,
) -> None:
    streaming_keys = ("Body", "Payload", "body", "AudioStream", "audioStream")
    max_chars = max(1, max_output_characters)
    for key in streaming_keys:
        if key not in response:
            continue
        obj = response[key]
        if not (hasattr(obj, "read") and callable(obj.read)):
            continue
        try:
            content = obj.read(max_chars + 1)
            truncated = False
            if isinstance(content, bytes):
                if len(content) > max_chars:
                    content = content[:max_chars]
                    truncated = True
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    text = base64.b64encode(content).decode("utf-8")
                if truncated:
                    text = _truncate_text(text, max_chars)
                response[key] = text
            else:
                text = str(content) if content is not None else ""
                response[key] = _truncate_text(text, max_chars)
        except Exception:
            response[key] = ""


def _call_method(
    client,
    method_name: str,
    kwargs: dict[str, object],
    max_output_characters: int,
):
    method = getattr(client, method_name)
    response = method(**kwargs)
    if isinstance(response, dict):
        _read_streaming_fields(
            response,
            max_output_characters=max_output_characters,
        )
        return response
    return {"result": response}


async def get_client_async(
    service: str,
    region: str | None,
    profile: str | None = None,
    ctx=None,
):
    return await asyncio.to_thread(get_client, service, region, profile, ctx)


async def call_aws_api_async(
    client,
    method_name: str,
    max_output_characters: int,
    **kwargs,
):
    return await asyncio.to_thread(
        _call_method,
        client,
        method_name,
        kwargs,
        max_output_characters,
    )
