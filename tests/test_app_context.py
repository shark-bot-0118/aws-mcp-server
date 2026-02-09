from unittest.mock import MagicMock, patch

import pytest

from aws_cli_mcp.app import AppContext, get_app_context
from aws_cli_mcp.config import Settings


@pytest.fixture
def clean_context():
    get_app_context.cache_clear()
    yield
    get_app_context.cache_clear()


@patch("aws_cli_mcp.app.load_settings")
@patch("aws_cli_mcp.app.load_policy")
@patch("aws_cli_mcp.app.PolicyEngine")
@patch("aws_cli_mcp.app.SqliteStore")
@patch("aws_cli_mcp.app.ArtifactStore")
@patch("aws_cli_mcp.app.sync_models")
@patch("aws_cli_mcp.app.load_models")
@patch("aws_cli_mcp.app.load_models_from_paths")
@patch("aws_cli_mcp.app.resolve_service_model_paths")
@patch("aws_cli_mcp.app.init_version_manager")
@patch("aws_cli_mcp.app.SmithyCatalog")
@patch("aws_cli_mcp.app.SchemaGenerator")
def test_app_context_initialization(
    mock_gen,
    mock_cat,
    mock_init_ver,
    mock_resolve,
    mock_load_paths,
    mock_load_full,
    mock_sync,
    mock_artifacts,
    mock_store,
    mock_engine,
    mock_load_policy,
    mock_load_settings,
    clean_context,
):
    # Setup Settings
    settings = MagicMock(spec=Settings)
    # Configure nested attributes
    mock_policy_settings = MagicMock()
    mock_policy_settings.path = "policy.yaml"
    settings.policy = mock_policy_settings

    mock_storage = MagicMock()
    mock_storage.sqlite_path = "db.sqlite"
    mock_storage.sqlite_wal = True
    mock_storage.artifact_path = "artifacts"
    settings.storage = mock_storage

    mock_smithy = MagicMock()
    mock_smithy.cache_path = "cache"
    mock_smithy.model_cache_size = 5
    settings.smithy = mock_smithy

    mock_load_settings.return_value = settings

    # Setup Policy
    policy = MagicMock()
    policy.services.allowlist = ["s3"]  # Has allowlist
    mock_load_policy.return_value = policy

    # Setup Models
    mock_sync.return_value = "model_path"
    mock_resolve.return_value = {"s3": "path/to/s3.json"}
    mock_load_paths.return_value = MagicMock()  # The loaded model

    # Run
    ctx = get_app_context()

    assert isinstance(ctx, AppContext)

    # Verification
    mock_sync.assert_called_once()
    mock_resolve.assert_called_once_with("model_path", ["s3"])
    mock_load_paths.assert_called_once()
    mock_load_full.assert_not_called()  # Should use paths
    mock_init_ver.assert_called_once()
    assert not hasattr(ctx, "model_version")


@patch("aws_cli_mcp.app.load_settings")
@patch("aws_cli_mcp.app.load_policy")
@patch("aws_cli_mcp.app.PolicyEngine")
@patch("aws_cli_mcp.app.SqliteStore")
@patch("aws_cli_mcp.app.ArtifactStore")
@patch("aws_cli_mcp.app.sync_models")
@patch("aws_cli_mcp.app.load_models")
@patch("aws_cli_mcp.app.init_version_manager")
@patch("aws_cli_mcp.app.SmithyCatalog")
@patch("aws_cli_mcp.app.SchemaGenerator")
def test_app_context_no_allowlist(
    mock_gen,
    mock_cat,
    mock_init_ver,
    mock_load_full,
    mock_sync,
    mock_artifacts,
    mock_store,
    mock_engine,
    mock_load_policy,
    mock_load_settings,
    clean_context,
):
    # Setup Settings
    settings = MagicMock(spec=Settings)
    mock_smithy = MagicMock()
    mock_smithy.cache_path = "cache"
    mock_smithy.model_cache_size = 5
    settings.smithy = mock_smithy

    mock_storage = MagicMock()
    mock_storage.sqlite_path = ":memory:"
    mock_storage.sqlite_wal = False
    mock_storage.artifact_path = "art"
    settings.storage = mock_storage

    mock_policy = MagicMock()
    mock_policy.path = "pol"
    settings.policy = mock_policy

    mock_load_settings.return_value = settings

    # Setup Policy (Empty allowlist)
    policy = MagicMock()
    policy.services.allowlist = []
    mock_load_policy.return_value = policy

    mock_sync.return_value = "model_path"

    # Run
    ctx = get_app_context()

    # Verification
    mock_load_full.assert_called_once_with("model_path")
    assert not hasattr(ctx, "model_version")


@patch("aws_cli_mcp.app.load_settings")
@patch("aws_cli_mcp.app.load_policy")
@patch("aws_cli_mcp.app.PolicyEngine")
@patch("aws_cli_mcp.app.SqliteStore")
@patch("aws_cli_mcp.app.ArtifactStore")
@patch("aws_cli_mcp.app.sync_models")
@patch("aws_cli_mcp.app.resolve_service_model_paths")
@patch("aws_cli_mcp.app.Path.glob")
def test_app_context_allowlist_without_models_raises(
    mock_glob,
    mock_resolve,
    mock_sync,
    mock_artifacts,
    mock_store,
    mock_engine,
    mock_load_policy,
    mock_load_settings,
    clean_context,
):
    settings = MagicMock(spec=Settings)
    settings.policy = MagicMock(path="policy.yaml")
    settings.storage = MagicMock(
        sqlite_path="db.sqlite", sqlite_wal=True, artifact_path="artifacts"
    )
    settings.smithy = MagicMock(cache_path="cache", model_cache_size=3)
    mock_load_settings.return_value = settings

    policy = MagicMock()
    policy.services.allowlist = ["s3"]
    mock_load_policy.return_value = policy

    mock_sync.return_value = "model_path"
    mock_resolve.return_value = {}
    mock_glob.return_value = []

    with pytest.raises(RuntimeError, match="No Smithy models found for allowlisted services"):
        get_app_context()


@patch("aws_cli_mcp.app.load_settings")
@patch("aws_cli_mcp.app.load_policy")
@patch("aws_cli_mcp.app.PolicyEngine")
@patch("aws_cli_mcp.app.SqliteStore")
@patch("aws_cli_mcp.app.ArtifactStore")
@patch("aws_cli_mcp.app.sync_models")
@patch("aws_cli_mcp.app.resolve_service_model_paths")
@patch("aws_cli_mcp.app.load_models_from_paths")
@patch("aws_cli_mcp.app.Path.glob")
@patch("aws_cli_mcp.app.init_version_manager")
@patch("aws_cli_mcp.app.SmithyCatalog")
@patch("aws_cli_mcp.app.SchemaGenerator")
def test_app_context_allowlist_uses_fallback_json_paths(
    _mock_gen,
    _mock_catalog,
    _mock_init_ver,
    mock_glob,
    mock_load_from_paths,
    mock_resolve,
    mock_sync,
    _mock_artifacts,
    _mock_store,
    _mock_engine,
    mock_load_policy,
    mock_load_settings,
    clean_context,
):
    settings = MagicMock(spec=Settings)
    settings.policy = MagicMock(path="policy.yaml")
    settings.storage = MagicMock(
        sqlite_path="db.sqlite", sqlite_wal=True, artifact_path="artifacts"
    )
    settings.smithy = MagicMock(cache_path="cache", model_cache_size=3)
    mock_load_settings.return_value = settings

    policy = MagicMock()
    policy.services.allowlist = ["s3"]
    mock_load_policy.return_value = policy

    mock_sync.return_value = "model_path"
    mock_resolve.return_value = {}
    mock_glob.return_value = ["fallback.json"]

    get_app_context()
    mock_load_from_paths.assert_called_once_with(["fallback.json"])
