"""AWS client factory."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

import boto3
from botocore.config import Config

from aws_cli_mcp.auth.context import AWSCredentials, RequestContext, get_request_context_optional
from aws_cli_mcp.config import Settings, load_settings

ClientCacheKey = tuple[str, ...]

_CLIENT_CACHE: OrderedDict[ClientCacheKey, tuple[object, float]] = OrderedDict()
_CLIENT_CACHE_LOCK = threading.Lock()
_CLIENT_TTL_SECONDS = 3600  # 1 hour
_CLIENT_CACHE_MAX_SIZE = 256


class RequestContextError(RuntimeError):
    pass


def _get_cached_client(
    key: ClientCacheKey,
    build_client: Callable[[], object],
) -> object:
    now = time.monotonic()
    with _CLIENT_CACHE_LOCK:
        cached = _CLIENT_CACHE.get(key)
        if cached is not None:
            client, created_at = cached
            if now - created_at < _CLIENT_TTL_SECONDS:
                _CLIENT_CACHE.move_to_end(key)
                return client
            # TTL expired — remove stale entry
            del _CLIENT_CACHE[key]
        client = build_client()
        _CLIENT_CACHE[key] = (client, now)
        # Evict LRU entries if cache exceeds max size
        while len(_CLIENT_CACHE) > _CLIENT_CACHE_MAX_SIZE:
            _CLIENT_CACHE.popitem(last=False)
        return client


def _credential_fingerprint(access_key_id: str, secret_access_key: str, session_token: str) -> str:
    material = "\x1f".join((access_key_id, secret_access_key, session_token))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _profile_cache_key(
    service: str,
    region: str | None,
    profile: str | None,
    settings: Settings,
) -> ClientCacheKey:
    return (
        "profile",
        service,
        region or settings.aws.default_region or "",
        profile or settings.aws.default_profile or "",
    )


def _credential_cache_key(
    service: str,
    region: str | None,
    ctx: RequestContext,
    settings: Settings,
) -> ClientCacheKey:
    creds = _require_aws_credentials(ctx)
    return (
        "credentials",
        service,
        region or settings.aws.default_region or "",
        # Only the fingerprint hash — no plaintext access key in cache key.
        _credential_fingerprint(
            creds.access_key_id,
            creds.secret_access_key,
            creds.session_token,
        ),
    )


def _require_aws_credentials(ctx: RequestContext) -> AWSCredentials:
    creds = ctx.aws_credentials
    if creds is None:
        raise RequestContextError("Missing request-scoped AWS credentials")
    return creds


def get_client(
    service: str,
    region: str | None,
    profile: str | None,
    ctx: RequestContext | None = None,
):
    settings = load_settings()
    if ctx is None:
        ctx = get_request_context_optional()

    if settings.server.transport_mode in {"http", "remote"}:
        if ctx is None or getattr(ctx, "aws_credentials", None) is None:
            raise RequestContextError("HTTP/remote mode requires request-scoped AWS credentials")
        key = _credential_cache_key(service, region, ctx, settings)
        return _get_cached_client(
            key,
            lambda: _create_client_with_credentials(service, ctx, region, settings),
        )

    # In stdio mode, use context credentials if present (unlikely but possible)
    if ctx is not None and getattr(ctx, "aws_credentials", None) is not None:
        key = _credential_cache_key(service, region, ctx, settings)
        return _get_cached_client(
            key,
            lambda: _create_client_with_credentials(service, ctx, region, settings),
        )

    key = _profile_cache_key(service, region, profile, settings)
    return _get_cached_client(
        key,
        lambda: _create_client_with_profile(service, region, profile, settings),
    )


def _create_client_with_profile(
    service: str,
    region: str | None,
    profile: str | None,
    settings: Settings,
):
    session = boto3.Session(
        profile_name=profile or settings.aws.default_profile,
        region_name=region or settings.aws.default_region,
    )
    config = _get_service_config(service, settings)
    return session.client(service, config=config)


def _create_client_with_credentials(
    service: str,
    ctx: RequestContext,
    region: str | None,
    settings: Settings,
):
    creds = _require_aws_credentials(ctx)
    session = boto3.Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        region_name=region or settings.aws.default_region,
    )
    config = _get_service_config(service, settings)
    return session.client(service, config=config)


def _get_service_config(service: str, settings: Settings) -> Config:
    base: dict[str, object] = {
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
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Failed to read streaming field '%s': %s", key, exc
            )
            response[key] = "<Error reading stream>"


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
    ctx: RequestContext | None = None,
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
