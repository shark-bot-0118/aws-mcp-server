import pytest
from unittest.mock import MagicMock, patch
from aws_cli_mcp.app import get_app_context, AppContext
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
@patch("aws_cli_mcp.app.get_model_commit_sha")
def test_app_context_initialization(
    mock_get_sha, mock_gen, mock_cat, mock_init_ver, mock_resolve,
    mock_load_paths, mock_load_full, mock_sync, mock_artifacts, mock_store,
    mock_engine, mock_load_policy, mock_load_settings, clean_context
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
    mock_smithy.default_model_version = None
    mock_smithy.model_cache_size = 5
    settings.smithy = mock_smithy
    
    mock_load_settings.return_value = settings
    
    # Setup Policy
    policy = MagicMock()
    policy.services.allowlist = ["s3"] # Has allowlist
    mock_load_policy.return_value = policy
    
    # Setup Models
    mock_sync.return_value = "model_path"
    mock_resolve.return_value = {"s3": "path/to/s3.json"}
    mock_load_paths.return_value = MagicMock() # The loaded model
    mock_get_sha.return_value = "sha123"

    # Run
    ctx = get_app_context()
    
    assert isinstance(ctx, AppContext)
    
    # Verification
    mock_sync.assert_called_once()
    mock_resolve.assert_called_once_with("model_path", ["s3"])
    mock_load_paths.assert_called_once()
    mock_load_full.assert_not_called() # Should use paths
    mock_init_ver.assert_called_once()
    assert ctx.model_version == "sha123"

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
    mock_gen, mock_cat, mock_init_ver, mock_load_full, mock_sync, 
    mock_artifacts, mock_store, mock_engine, mock_load_policy, 
    mock_load_settings, clean_context
):
    # Setup Settings
    settings = MagicMock(spec=Settings)
    mock_smithy = MagicMock()
    mock_smithy.default_model_version = "v1"
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
    assert ctx.model_version == "v1"
