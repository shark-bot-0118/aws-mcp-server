"""Application context assembly."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from aws_cli_mcp.audit.artifacts import ArtifactStore
from aws_cli_mcp.audit.db import SqliteStore
from aws_cli_mcp.config import Settings, load_settings
from aws_cli_mcp.policy.engine import PolicyEngine
from aws_cli_mcp.policy.loader import load_policy
from aws_cli_mcp.smithy.catalog import SmithyCatalog
from aws_cli_mcp.smithy.loader import load_models, load_models_from_paths
from aws_cli_mcp.smithy.parser import SmithyModel
from aws_cli_mcp.smithy.registry import resolve_service_model_paths
from aws_cli_mcp.smithy.schema_generator import SchemaGenerator
from aws_cli_mcp.smithy.sync import sync_models
from aws_cli_mcp.smithy.version_manager import init_version_manager


@dataclass
class AppContext:
    """Application-wide dependency container.

    Provides access to all core services and configuration.
    Initialized once at startup and cached for the lifetime of the process.
    """

    settings: Settings
    store: SqliteStore
    artifacts: ArtifactStore
    catalog: SmithyCatalog
    schema_generator: SchemaGenerator
    policy_engine: PolicyEngine
    smithy_model: SmithyModel


@lru_cache(maxsize=1)
def get_app_context() -> AppContext:
    """Get or create the application context.

    Returns a cached singleton instance of AppContext with all
    dependencies initialized.
    """
    settings = load_settings()
    policy_config = load_policy(settings.policy.path)
    policy_engine = PolicyEngine(policy_config)

    store = SqliteStore(settings.storage.sqlite_path, wal=settings.storage.sqlite_wal)
    artifacts = ArtifactStore(settings.storage.artifact_path)

    model_path = sync_models(settings.smithy)
    service_allowlist = [s.lower() for s in policy_config.services.allowlist]

    if service_allowlist:
        paths = resolve_service_model_paths(model_path, service_allowlist)
        if paths:
            smithy_model = load_models_from_paths(list(paths.values()))
        else:
            fallback_paths = list(Path(model_path).glob("**/*.json"))
            if fallback_paths:
                smithy_model = load_models_from_paths(fallback_paths)
            else:
                raise RuntimeError(
                    "No Smithy models found for allowlisted services. "
                    "Check SMITHY_MODEL_PATH/SMITHY_SYNC_* settings or policy services.allowlist."
                )
    else:
        smithy_model = load_models(model_path)

    catalog = SmithyCatalog(smithy_model)
    schema_generator = SchemaGenerator(smithy_model)

    init_version_manager(
        cache_path=settings.smithy.cache_path,
        model_path=model_path,
        service_allowlist=service_allowlist if service_allowlist else None,
        max_cached_versions=settings.smithy.model_cache_size,
    )

    return AppContext(
        settings=settings,
        store=store,
        artifacts=artifacts,
        catalog=catalog,
        schema_generator=schema_generator,
        policy_engine=policy_engine,
        smithy_model=smithy_model,
    )
