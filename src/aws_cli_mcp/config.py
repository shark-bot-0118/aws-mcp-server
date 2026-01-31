"""Configuration management for the AWS Tool-Execution MCP server."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError


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
    auto_sync: bool = Field(default=True)
    allowlist_services: list[str] = Field(default_factory=list)
    allowlist_operations: list[str] = Field(default_factory=list)
    default_model_version: str | None = Field(
        default=None,
        description="Pin to a specific model version (commit SHA). None uses latest.",
    )
    model_cache_size: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of model versions to cache in memory.",
    )





class ServerSettings(BaseModel):
    host: str = Field(default="0.0.0.0")
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


class Settings(BaseModel):
    server: ServerSettings = Field(default_factory=ServerSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    smithy: SmithySettings = Field(default_factory=SmithySettings)


    aws_default_region: str | None = Field(default=None)
    aws_default_profile: str | None = Field(default=None)


ENV_KEYS = {
    "host": "MCP_HOST",
    "port": "MCP_PORT",
    "instructions": "MCP_INSTRUCTIONS",
    "require_approval": "MCP_REQUIRE_APPROVAL",
    "log_level": "LOG_LEVEL",
    "log_file": "LOG_FILE",
    "sqlite_path": "SQLITE_PATH",
    "artifact_path": "ARTIFACT_PATH",
    "policy_path": "POLICY_PATH",
    "smithy_path": "SMITHY_MODEL_PATH",
    "smithy_sync_url": "SMITHY_SYNC_URL",
    "smithy_allowlist_services": "SMITHY_ALLOWLIST_SERVICES",
    "smithy_allowlist_operations": "SMITHY_ALLOWLIST_OPERATIONS",
    "smithy_cache_path": "SMITHY_CACHE_PATH",
    "smithy_sync_ref": "SMITHY_SYNC_REF",
    "smithy_auto_sync": "SMITHY_AUTO_SYNC",
    "smithy_default_model_version": "SMITHY_DEFAULT_MODEL_VERSION",
    "smithy_model_cache_size": "SMITHY_MODEL_CACHE_SIZE",
    "aws_region": "AWS_DEFAULT_REGION",
    "aws_profile": "AWS_PROFILE",
    "max_retries": "AWS_MCP_MAX_RETRIES",
}

# Deprecated env keys (kept for backwards compatibility)



def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_path(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        return str(candidate)
    return str((_project_root() / candidate).resolve())


def load_settings() -> Settings:
    """Load configuration and cache the result."""

    return _load_settings_cached()


@lru_cache(maxsize=1)
def _load_settings_cached() -> Settings:
    load_dotenv(dotenv_path=_project_root() / ".env")

    settings_data: dict[str, object] = {
        "server": {
            "host": os.getenv(ENV_KEYS["host"], ServerSettings().host),
            "port": int(os.getenv(ENV_KEYS["port"], ServerSettings().port)),
            "instructions": os.getenv(
                ENV_KEYS["instructions"], ServerSettings().instructions
            ),
            "require_approval": os.getenv(ENV_KEYS["require_approval"], "false").lower()
            in {"1", "true", "yes"},
            "auto_approve_destructive": os.getenv("AWS_MCP_AUTO_APPROVE_DESTRUCTIVE", "false").lower()
            in {"1", "true", "yes"},
        },
        "logging": {
            "level": os.getenv(ENV_KEYS["log_level"], LoggingSettings().level),
            "file": _resolve_path(os.getenv(ENV_KEYS["log_file"])) if os.getenv(ENV_KEYS["log_file"]) else None,
        },
        "execution": {
            "sdk_timeout_seconds": int(
                os.getenv(
                    "SDK_TIMEOUT_SECONDS", ExecutionSettings().sdk_timeout_seconds
                )
            ),
            "max_output_characters": int(
                os.getenv(
                    "MAX_OUTPUT_CHARACTERS",
                    ExecutionSettings().max_output_characters,
                )
            ),
            "max_retries": int(
                os.getenv(ENV_KEYS["max_retries"], ExecutionSettings().max_retries)
            ),
        },
        "storage": {
            "sqlite_path": _resolve_path(
                os.getenv(ENV_KEYS["sqlite_path"], StorageSettings().sqlite_path)
            ),
            "sqlite_wal": os.getenv("SQLITE_WAL", "true").lower() in {"1", "true", "yes"},
            "artifact_path": _resolve_path(
                os.getenv(ENV_KEYS["artifact_path"], StorageSettings().artifact_path)
            ),
        },
        "policy": {
            "path": _resolve_path(
                os.getenv(ENV_KEYS["policy_path"], PolicySettings().path)
            ),
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
            "auto_sync": os.getenv(ENV_KEYS["smithy_auto_sync"], "true").lower()
            in {"1", "true", "yes"},
            "allowlist_services": _split_csv(
                os.getenv(ENV_KEYS["smithy_allowlist_services"])
            ),
            "allowlist_operations": _split_csv(
                os.getenv(ENV_KEYS["smithy_allowlist_operations"])
            ),
            "default_model_version": os.getenv(ENV_KEYS["smithy_default_model_version"]),
            "model_cache_size": int(
                os.getenv(ENV_KEYS["smithy_model_cache_size"], SmithySettings().model_cache_size)
            ),
        },

        "aws_default_region": os.getenv("AWS_REGION") or os.getenv(ENV_KEYS["aws_region"]),
        "aws_default_profile": os.getenv(ENV_KEYS["aws_profile"]),
    }

    try:
        settings = Settings(**settings_data)
    except ValidationError as exc:
        raise RuntimeError(f"Invalid configuration: {exc}") from exc

    Path(settings.storage.artifact_path).mkdir(parents=True, exist_ok=True)
    Path(settings.storage.sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    return settings
