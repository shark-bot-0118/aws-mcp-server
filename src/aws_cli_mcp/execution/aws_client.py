"""AWS client factory."""

from __future__ import annotations

import boto3
from botocore.config import Config

from aws_cli_mcp.config import load_settings

_CLIENT_CACHE: dict[tuple[str, str | None, str | None], object] = {}


def get_client(service: str, region: str | None, profile: str | None):
    key = (service, region, profile)
    if key in _CLIENT_CACHE:
        return _CLIENT_CACHE[key]

    settings = load_settings()
    session = boto3.Session(
        profile_name=profile or settings.aws_default_profile,
        region_name=region or settings.aws_default_region,
    )
    # S3: Disable response checksum validation to prevent StreamingChecksumBody
    # from consuming the stream before we can read it
    if service == "s3":
        config = Config(
            read_timeout=settings.execution.sdk_timeout_seconds,
            connect_timeout=settings.execution.sdk_timeout_seconds,
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        )
    else:
        config = Config(
            read_timeout=settings.execution.sdk_timeout_seconds,
            connect_timeout=settings.execution.sdk_timeout_seconds,
        )
    client = session.client(service, config=config)

    _CLIENT_CACHE[key] = client
    return client
