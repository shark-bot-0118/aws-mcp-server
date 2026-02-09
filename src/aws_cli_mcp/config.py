"""Configuration management for the AWS Tool-Execution MCP server."""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, field_validator

from aws_cli_mcp.utils.http import normalize_public_base_url

_config_logger = logging.getLogger(__name__)


class LoggingSettings(BaseModel):
    level: str = Field(default="INFO", description="Python logging level name")
    file: str | None = Field(default=None, description="Optional log file path")


class ExecutionSettings(BaseModel):
    sdk_timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_output_characters: int = Field(default=20_000, ge=1, le=200_000)
    max_retries: int = Field(default=2, ge=0, le=10)


class StorageSettings(BaseModel):
    sqlite_path: str = Field(default="./data/aws_mcp.sqlite")
    sqlite_wal: bool = Field(default=True)
    artifact_path: str = Field(default="./data/artifacts")


class PolicySettings(BaseModel):
    path: str = Field(default="./policy.yaml")


class SmithySettings(BaseModel):
    model_path: str = Field(default="./data/smithy_cache/models")
    sync_url: str | None = Field(default="https://github.com/aws/api-models-aws.git")
    sync_ref: str = Field(default="main")
    cache_path: str = Field(default="./data/smithy_cache")
    auto_sync: bool = Field(default=False)
    model_cache_size: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of model versions to cache in memory.",
    )


class AuthSettings(BaseModel):
    """Authentication settings.

    Supports two modes:
    - multi-idp: OAuth 2.0 Protected Resource with multiple IdPs (recommended)
    - identity-center: AWS IAM Identity Center

    For multi-idp mode, use AUTH_IDP_CONFIG_PATH to specify the IdP config file.
    """

    provider: Literal["multi-idp", "identity-center"] = Field(
        default="multi-idp",
        description="Auth provider: multi-idp | identity-center",
    )
    idp_config_path: str | None = Field(
        default=None,
        description="Path to idp_config.yaml for multi-idp mode",
    )

    # Credential caching
    credential_refresh_buffer_seconds: int = Field(default=300, ge=0, le=3600)
    credential_cache_max_entries: int = Field(default=1000, ge=1, le=10000)
    allow_multi_user: bool = Field(
        default=False,
        description=(
            "If False, only the first authenticated principal is accepted in this process. "
            "Set True to allow multiple principals."
        ),
    )

    identity_center_region: str | None = Field(default=None)
    rate_limit_per_user: int = Field(default=100, ge=1)
    rate_limit_per_ip: int = Field(default=1000, ge=1)
    max_body_size_mb: int = Field(default=10, ge=1)
    max_header_size_kb: int = Field(default=8, ge=1)
    request_timeout_seconds: float = Field(default=30.0, ge=0.1)
    audit_enabled: bool = Field(default=True)


class AWSSettings(BaseModel):
    default_region: str | None = Field(default=None)
    default_profile: str | None = Field(default=None)
    sts_region: str = Field(default="us-east-1")


class ServerSettings(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1024, le=65535)
    instructions: str = Field(
        default=(
            "Use these tools to plan, diff, and apply AWS operations. "
            "Always request approval for destructive actions."
        )
    )
    require_approval: bool = Field(default=False)
    auto_approve_destructive: bool = Field(
        default=False,
        description="If True, skips the forced two-step confirmation for destructive operations.",
    )
    transport_mode: Literal["stdio", "http", "remote"] = Field(default="stdio")
    http_allowed_origins: tuple[str, ...] = Field(default=())
    http_allow_missing_origin: bool = Field(default=True)
    http_enable_cors: bool = Field(default=False)
    http_trust_forwarded_headers: bool = Field(default=False)
    public_base_url: str | None = Field(
        default=None,
        description=(
            "Externally visible base URL used for OAuth/resource metadata in remote mode "
            "(e.g. https://mcp.example.com)."
        ),
    )

    @field_validator("public_base_url")
    @classmethod
    def _validate_public_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_public_base_url(value)


class Settings(BaseModel):
    server: ServerSettings = Field(default_factory=ServerSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    smithy: SmithySettings = Field(default_factory=SmithySettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    aws: AWSSettings = Field(default_factory=AWSSettings)


ENV_KEYS = {
    "auth_provider": "AUTH_PROVIDER",
    "host": "MCP_HOST",
    "port": "MCP_PORT",
    "public_base_url": "MCP_PUBLIC_BASE_URL",
    "instructions": "MCP_INSTRUCTIONS",
    "require_approval": "MCP_REQUIRE_APPROVAL",
    "log_level": "LOG_LEVEL",
    "log_file": "LOG_FILE",
    "sqlite_path": "SQLITE_PATH",
    "artifact_path": "ARTIFACT_PATH",
    "policy_path": "POLICY_PATH",
    "smithy_path": "SMITHY_MODEL_PATH",
    "smithy_sync_url": "SMITHY_SYNC_URL",
    "smithy_cache_path": "SMITHY_CACHE_PATH",
    "smithy_sync_ref": "SMITHY_SYNC_REF",
    "smithy_auto_sync": "SMITHY_AUTO_SYNC",
    "smithy_model_cache_size": "SMITHY_MODEL_CACHE_SIZE",
    "aws_region": "AWS_DEFAULT_REGION",
    "aws_profile": "AWS_PROFILE",
    "max_retries": "AWS_MCP_MAX_RETRIES",
}

_TRUE_VALUES = frozenset({"1", "true", "yes"})


def _split_csv_preserve_case(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_path(path: str) -> str:
    candidate = Path(path)
    root = _project_root().resolve()
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"Path traversal detected: '{path}' resolves outside project root")
    return str(resolved)


def _env_bool(key: str, default: bool) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip().lower() in _TRUE_VALUES


def _env_int(key: str, default: int) -> int:
    value = os.getenv(key)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        _config_logger.warning(
            "Invalid integer value for %s: %r, using default %d", key, value, default
        )
        return default


def _env_float(key: str, default: float) -> float:
    value = os.getenv(key)
    if value is None or value.strip() == "":
        return default
    try:
        return float(value)
    except ValueError:
        _config_logger.warning(
            "Invalid float value for %s: %r, using default %s", key, value, default
        )
        return default


def load_settings() -> Settings:
    """Load configuration and cache the result."""

    return _load_settings_cached()


@lru_cache(maxsize=1)
def _load_settings_cached() -> Settings:
    load_dotenv(dotenv_path=_project_root() / ".env")
    log_file_env = os.getenv(ENV_KEYS["log_file"])
    idp_config_path_env = os.getenv("AUTH_IDP_CONFIG_PATH")

    settings_data: dict[str, object] = {
        "server": {
            "host": os.getenv(ENV_KEYS["host"], ServerSettings().host),
            "port": _env_int(ENV_KEYS["port"], ServerSettings().port),
            "instructions": os.getenv(ENV_KEYS["instructions"], ServerSettings().instructions),
            "require_approval": _env_bool(
                ENV_KEYS["require_approval"], ServerSettings().require_approval
            ),
            "auto_approve_destructive": _env_bool(
                "AWS_MCP_AUTO_APPROVE_DESTRUCTIVE",
                ServerSettings().auto_approve_destructive,
            ),
            "transport_mode": os.getenv("TRANSPORT_MODE", ServerSettings().transport_mode),
            "http_allowed_origins": tuple(
                _split_csv_preserve_case(os.getenv("HTTP_ALLOWED_ORIGINS"))
            ),
            "http_allow_missing_origin": _env_bool(
                "HTTP_ALLOW_MISSING_ORIGIN",
                ServerSettings().http_allow_missing_origin,
            ),
            "http_enable_cors": _env_bool(
                "HTTP_ENABLE_CORS",
                ServerSettings().http_enable_cors,
            ),
            "http_trust_forwarded_headers": _env_bool(
                "HTTP_TRUST_FORWARDED_HEADERS",
                ServerSettings().http_trust_forwarded_headers,
            ),
            "public_base_url": (
                os.getenv(ENV_KEYS["public_base_url"], "").strip() or None
            ),
        },
        "logging": {
            "level": os.getenv(ENV_KEYS["log_level"], LoggingSettings().level),
            "file": _resolve_path(log_file_env) if log_file_env else None,
        },
        "execution": {
            "sdk_timeout_seconds": _env_int(
                "SDK_TIMEOUT_SECONDS",
                ExecutionSettings().sdk_timeout_seconds,
            ),
            "max_output_characters": _env_int(
                "MAX_OUTPUT_CHARACTERS",
                ExecutionSettings().max_output_characters,
            ),
            "max_retries": _env_int(
                ENV_KEYS["max_retries"],
                ExecutionSettings().max_retries,
            ),
        },
        "storage": {
            "sqlite_path": _resolve_path(
                os.getenv(ENV_KEYS["sqlite_path"], StorageSettings().sqlite_path)
            ),
            "sqlite_wal": _env_bool("SQLITE_WAL", StorageSettings().sqlite_wal),
            "artifact_path": _resolve_path(
                os.getenv(ENV_KEYS["artifact_path"], StorageSettings().artifact_path)
            ),
        },
        "policy": {
            "path": _resolve_path(os.getenv(ENV_KEYS["policy_path"], PolicySettings().path)),
        },
        "smithy": {
            "model_path": _resolve_path(
                os.getenv(ENV_KEYS["smithy_path"], SmithySettings().model_path)
            ),
            "sync_url": os.getenv(ENV_KEYS["smithy_sync_url"], SmithySettings().sync_url),
            "sync_ref": os.getenv(ENV_KEYS["smithy_sync_ref"], SmithySettings().sync_ref),
            "cache_path": _resolve_path(
                os.getenv(ENV_KEYS["smithy_cache_path"], SmithySettings().cache_path)
            ),
            "auto_sync": _env_bool(
                ENV_KEYS["smithy_auto_sync"],
                SmithySettings().auto_sync,
            ),
            "model_cache_size": _env_int(
                ENV_KEYS["smithy_model_cache_size"],
                SmithySettings().model_cache_size,
            ),
        },
        "auth": {
            "provider": os.getenv(ENV_KEYS["auth_provider"], AuthSettings().provider),
            "idp_config_path": _resolve_path(idp_config_path_env) if idp_config_path_env else None,
            "credential_refresh_buffer_seconds": _env_int(
                "AUTH_CREDENTIAL_REFRESH_BUFFER_SECONDS",
                AuthSettings().credential_refresh_buffer_seconds,
            ),
            "credential_cache_max_entries": _env_int(
                "AUTH_CREDENTIAL_CACHE_MAX_ENTRIES",
                AuthSettings().credential_cache_max_entries,
            ),
            "allow_multi_user": _env_bool(
                "AUTH_ALLOW_MULTI_USER",
                AuthSettings().allow_multi_user,
            ),
            "identity_center_region": os.getenv(
                "AUTH_IDENTITY_CENTER_REGION", AuthSettings().identity_center_region
            ),
            "rate_limit_per_user": _env_int(
                "AUTH_RATE_LIMIT_PER_USER",
                AuthSettings().rate_limit_per_user,
            ),
            "rate_limit_per_ip": _env_int(
                "AUTH_RATE_LIMIT_PER_IP",
                AuthSettings().rate_limit_per_ip,
            ),
            "max_body_size_mb": _env_int(
                "AUTH_MAX_BODY_SIZE_MB",
                AuthSettings().max_body_size_mb,
            ),
            "max_header_size_kb": _env_int(
                "AUTH_MAX_HEADER_SIZE_KB",
                AuthSettings().max_header_size_kb,
            ),
            "request_timeout_seconds": _env_float(
                "AUTH_REQUEST_TIMEOUT_SECONDS",
                AuthSettings().request_timeout_seconds,
            ),
            "audit_enabled": _env_bool(
                "AUTH_AUDIT_ENABLED",
                AuthSettings().audit_enabled,
            ),
        },
        "aws": {
            "default_region": os.getenv("AWS_REGION") or os.getenv(ENV_KEYS["aws_region"]),
            "default_profile": os.getenv(ENV_KEYS["aws_profile"]),
            "sts_region": os.getenv("AWS_STS_REGION", AWSSettings().sts_region),
        },
    }

    try:
        settings = Settings.model_validate(settings_data)
    except ValidationError as exc:
        raise RuntimeError(f"Invalid configuration: {exc}") from exc

    if (
        settings.server.transport_mode.strip().lower() == "remote"
        and settings.auth.provider == "multi-idp"
        and not settings.server.public_base_url
    ):
        raise RuntimeError(
            "Invalid configuration: MCP_PUBLIC_BASE_URL is required for "
            "TRANSPORT_MODE=remote with AUTH_PROVIDER=multi-idp"
        )

    Path(settings.storage.artifact_path).mkdir(parents=True, exist_ok=True)
    Path(settings.storage.sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    return settings
