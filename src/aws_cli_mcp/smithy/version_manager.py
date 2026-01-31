"""Model version management for Smithy models.

Provides centralized model version tracking, caching, and schema resolution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from aws_cli_mcp.smithy.catalog import SmithyCatalog
from aws_cli_mcp.smithy.loader import load_models, load_models_from_paths
from aws_cli_mcp.smithy.parser import SmithyModel
from aws_cli_mcp.smithy.registry import resolve_service_model_paths
from aws_cli_mcp.smithy.schema_generator import SchemaGenerator
from aws_cli_mcp.smithy.sync import get_model_commit_sha
from aws_cli_mcp.utils.time import utc_now_iso


@dataclass
class OperationMeta:
    """Metadata for a single operation."""

    shape_id: str
    summary: str | None


@dataclass
class ServiceIndex:
    """Index of operations for a single service."""

    operations: dict[str, OperationMeta] = field(default_factory=dict)


@dataclass
class ModelSnapshot:
    """A snapshot of loaded Smithy models at a specific version.

    This represents a fully-loaded and indexed set of AWS service models,
    pinned to a specific commit SHA for reproducibility.
    """

    version: str
    loaded_at: str
    services: dict[str, ServiceIndex] = field(default_factory=dict)
    _model: SmithyModel | None = field(default=None, repr=False)
    _catalog: SmithyCatalog | None = field(default=None, repr=False)
    _schema_generator: SchemaGenerator | None = field(default=None, repr=False)

    @property
    def model(self) -> SmithyModel:
        if self._model is None:
            raise RuntimeError("ModelSnapshot not fully initialized")
        return self._model

    @property
    def catalog(self) -> SmithyCatalog:
        if self._catalog is None:
            raise RuntimeError("ModelSnapshot not fully initialized")
        return self._catalog

    @property
    def schema_generator(self) -> SchemaGenerator:
        if self._schema_generator is None:
            raise RuntimeError("ModelSnapshot not fully initialized")
        return self._schema_generator


class VersionManager:
    """Manages model versions and provides cached access to model snapshots."""

    def __init__(
        self,
        cache_path: str,
        model_path: str,
        service_allowlist: list[str] | None = None,
        max_cached_versions: int = 3,
    ) -> None:
        self._cache_path = cache_path
        self._model_path = model_path
        self._service_allowlist = service_allowlist or []
        self._max_cached_versions = max_cached_versions
        self._snapshots: dict[str, ModelSnapshot] = {}
        self._current_version: str | None = None

    def get_current_version(self) -> str | None:
        """Get the current model version (git commit SHA).

        Returns None if no git repository is available.
        """
        if self._current_version is None:
            self._current_version = get_model_commit_sha(self._cache_path)
        return self._current_version

    def load_snapshot(self, version: str | None = None) -> ModelSnapshot:
        """Load a model snapshot for the specified version.

        Args:
            version: The commit SHA to load. If None, uses the current version.

        Returns:
            A fully initialized ModelSnapshot.

        Raises:
            RuntimeError: If models cannot be loaded.
        """
        if version is None:
            version = self.get_current_version() or "latest"

        if version in self._snapshots:
            return self._snapshots[version]

        snapshot = self._create_snapshot(version)
        self._cache_snapshot(version, snapshot)
        return snapshot

    def resolve_schema(
        self,
        service: str,
        operation: str,
        version: str | None = None,
    ) -> dict[str, object]:
        """Resolve the JSON Schema for an operation.

        Args:
            service: The AWS service name.
            operation: The operation name.
            version: The model version. If None, uses the current version.

        Returns:
            The JSON Schema for the operation input.

        Raises:
            ValueError: If the operation is not found.
        """
        snapshot = self.load_snapshot(version)
        entry = snapshot.catalog.find_operation(service, operation)
        if entry is None:
            raise ValueError(f"Operation not found: {service}:{operation}")
        return snapshot.schema_generator.generate_operation_input_schema(
            entry.operation_shape_id
        )

    def _create_snapshot(self, version: str) -> ModelSnapshot:
        """Create a new model snapshot."""
        model = self._load_models()
        catalog = SmithyCatalog(model)
        schema_generator = SchemaGenerator(model)

        services: dict[str, ServiceIndex] = {}
        for entry in catalog.list_operations():
            service_name = entry.ref.service
            if service_name not in services:
                services[service_name] = ServiceIndex()
            services[service_name].operations[entry.ref.operation] = OperationMeta(
                shape_id=entry.operation_shape_id,
                summary=entry.documentation,
            )

        snapshot = ModelSnapshot(
            version=version,
            loaded_at=utc_now_iso(),
            services=services,
        )
        snapshot._model = model
        snapshot._catalog = catalog
        snapshot._schema_generator = schema_generator
        return snapshot

    def _load_models(self) -> SmithyModel:
        """Load Smithy models from the configured path."""
        if self._service_allowlist:
            paths = resolve_service_model_paths(
                self._model_path,
                [s.lower() for s in self._service_allowlist],
            )
            if paths:
                return load_models_from_paths(list(paths.values()))
            fallback_paths = list(Path(self._model_path).glob("**/*.json"))
            if fallback_paths:
                return load_models_from_paths(fallback_paths)
            raise RuntimeError(
                "No Smithy models found for allowlisted services. "
                "Check model_path or service allowlist configuration."
            )
        return load_models(self._model_path)

    def _cache_snapshot(self, version: str, snapshot: ModelSnapshot) -> None:
        """Cache a snapshot with LRU eviction."""
        if len(self._snapshots) >= self._max_cached_versions:
            oldest_key = next(iter(self._snapshots))
            del self._snapshots[oldest_key]
        self._snapshots[version] = snapshot


_version_manager: VersionManager | None = None


def get_version_manager() -> VersionManager:
    """Get the global version manager instance.

    This is lazily initialized when first called via init_version_manager().
    """
    if _version_manager is None:
        raise RuntimeError(
            "Version manager not initialized. Call init_version_manager() first."
        )
    return _version_manager


def init_version_manager(
    cache_path: str,
    model_path: str,
    service_allowlist: list[str] | None = None,
    max_cached_versions: int = 3,
) -> VersionManager:
    """Initialize the global version manager.

    Args:
        cache_path: Path to the Smithy cache directory (contains git repo).
        model_path: Path to the models directory.
        service_allowlist: Optional list of services to load.
        max_cached_versions: Maximum number of model versions to cache.

    Returns:
        The initialized VersionManager instance.
    """
    global _version_manager
    _version_manager = VersionManager(
        cache_path=cache_path,
        model_path=model_path,
        service_allowlist=service_allowlist,
        max_cached_versions=max_cached_versions,
    )
    return _version_manager


def get_model_version() -> str | None:
    """Get the current model version.

    Convenience function that delegates to the global version manager.
    """
    return get_version_manager().get_current_version()


def load_model_snapshot(version: str | None = None) -> ModelSnapshot:
    """Load a model snapshot.

    Convenience function that delegates to the global version manager.
    """
    return get_version_manager().load_snapshot(version)


def resolve_schema(
    service: str,
    operation: str,
    version: str | None = None,
) -> dict[str, object]:
    """Resolve the JSON Schema for an operation.

    Convenience function that delegates to the global version manager.
    """
    return get_version_manager().resolve_schema(service, operation, version)
