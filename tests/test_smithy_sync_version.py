import pytest
from unittest.mock import MagicMock, patch

from aws_cli_mcp.config import SmithySettings
from aws_cli_mcp.smithy.sync import sync_models, get_model_commit_sha
from aws_cli_mcp.smithy.version_manager import (
    init_version_manager, get_version_manager, 
    resolve_schema, load_model_snapshot, get_model_version
)
from aws_cli_mcp.smithy.catalog import OperationEntry
from aws_cli_mcp.domain.operations import OperationRef

# --- Sync Tests ---

@patch("aws_cli_mcp.smithy.sync.subprocess.run")
def test_sync_models_clone(mock_run, tmp_path):
    settings = SmithySettings(
        auto_sync=True,
        sync_url="https://repo.git",
        sync_ref="main",
        cache_path=str(tmp_path)
    )
    
    mock_run.return_value.returncode = 0
    
    # repo_path not exists
    res = sync_models(settings)
    
    assert res == str(tmp_path / "api-models-aws" / "models")
    assert mock_run.call_count == 1
    args = mock_run.call_args[0][0]
    assert "clone" in args
    assert "https://repo.git" in args

@patch("aws_cli_mcp.smithy.sync.subprocess.run")
def test_sync_models_update(mock_run, tmp_path):
    # Create repo dir to trigger update path
    repo_path = tmp_path / "api-models-aws"
    repo_path.mkdir(parents=True)
    
    settings = SmithySettings(
        auto_sync=True,
        sync_url="https://repo.git",
        cache_path=str(tmp_path)
    )
    
    mock_run.return_value.returncode = 0
    
    res = sync_models(settings)
    
    assert res == str(repo_path / "models")
    # Fetch, checkout, reset
    assert mock_run.call_count == 3
    assert "fetch" in mock_run.call_args_list[0][0][0]

def test_sync_models_disabled():
    settings = SmithySettings(auto_sync=False, model_path="local")
    assert sync_models(settings) == "local"

@patch("aws_cli_mcp.smithy.sync.subprocess.run")
def test_get_model_commit_sha(mock_run, tmp_path):
    # Setup .git dir
    repo_path = tmp_path / "api-models-aws"
    (repo_path / ".git").mkdir(parents=True)
    
    # Success
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "sha123\n"
    
    sha = get_model_commit_sha(str(tmp_path))
    assert sha == "sha123"
    
    # Failure
    mock_run.return_value.returncode = 1
    sha = get_model_commit_sha(str(tmp_path))
    assert sha is None

# --- Version Manager Tests ---

@pytest.fixture
def clean_vm():
    # Reset singleton
    import aws_cli_mcp.smithy.version_manager as vm
    old = vm._version_manager
    vm._version_manager = None
    yield
    vm._version_manager = old

@patch("aws_cli_mcp.smithy.version_manager.load_models")
@patch("aws_cli_mcp.smithy.version_manager.load_models_from_paths")
@patch("aws_cli_mcp.smithy.version_manager.resolve_service_model_paths")
@patch("aws_cli_mcp.smithy.version_manager.get_model_commit_sha")
def test_version_manager_flow(
    mock_sha, mock_resolve, mock_load_paths, mock_load_std, clean_vm
):
    mock_sha.return_value = "v1"
    
    # Mock model structure
    mock_model = MagicMock()
    mock_load_std.return_value = mock_model
    mock_load_paths.return_value = mock_model
    
    vm = init_version_manager("cache", "model_path", max_cached_versions=2)
    
    # Check singleton access
    assert get_version_manager() == vm
    
    # Check convenience functions
    assert get_model_version() == "v1"
    
    # Load snapshot (cache miss)
    snap1 = load_model_snapshot() # uses current version v1
    assert snap1.version == "v1"
    assert len(vm._snapshots) == 1
    
    # Load snapshot (cache hit)
    snap1_again = load_model_snapshot("v1")
    assert snap1_again is snap1
    
    # Load another version (v2)
    snap2 = load_model_snapshot("v2")
    assert snap2.version == "v2"
    assert len(vm._snapshots) == 2
    
    # Load another version (v3) -> should evict v1 (max=2)
    load_model_snapshot("v3")
    assert len(vm._snapshots) == 2
    assert "v2" in vm._snapshots
    assert "v3" in vm._snapshots
    assert "v1" not in vm._snapshots

@patch("aws_cli_mcp.smithy.version_manager.load_models")
def test_resolve_schema_proxy(mock_load, clean_vm):
    # Setup mock snapshot chain
    vm = init_version_manager("cache", "path")
    
    mock_model = MagicMock()
    mock_load.return_value = mock_model
    
    # Manually populate snapshot with mocks
    snap = vm.load_snapshot("v1")
    snap._catalog = MagicMock()
    snap._schema_generator = MagicMock()
    
    # Found
    op_entry = OperationEntry(ref=OperationRef("s3", "List"), operation_shape_id="id", documentation="")
    snap.catalog.find_operation.return_value = op_entry
    snap.schema_generator.generate_operation_input_schema.return_value = {"type": "object"}
    
    schema = resolve_schema("s3", "List", "v1")
    assert schema == {"type": "object"}
    
    # Not found
    snap.catalog.find_operation.return_value = None
    with pytest.raises(ValueError):
        resolve_schema("s3", "Unknown", "v1")

def test_get_vm_uninitialized(clean_vm):
    with pytest.raises(RuntimeError):
        get_version_manager()
