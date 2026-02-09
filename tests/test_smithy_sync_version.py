from unittest.mock import MagicMock, patch

import pytest

from aws_cli_mcp.config import SmithySettings
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.smithy.catalog import OperationEntry
from aws_cli_mcp.smithy.sync import get_model_commit_sha, sync_models
from aws_cli_mcp.smithy.version_manager import (
    ModelSnapshot,
    get_model_version,
    get_version_manager,
    init_version_manager,
    load_model_snapshot,
    resolve_schema,
)

# --- Sync Tests ---


@patch("aws_cli_mcp.smithy.sync.subprocess.run")
def test_sync_models_clone(mock_run, tmp_path):
    settings = SmithySettings(
        auto_sync=True, sync_url="https://repo.git", sync_ref="main", cache_path=str(tmp_path)
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

    settings = SmithySettings(auto_sync=True, sync_url="https://repo.git", cache_path=str(tmp_path))

    mock_run.return_value.returncode = 0

    res = sync_models(settings)

    assert res == str(repo_path / "models")
    # Fetch, checkout, reset
    assert mock_run.call_count == 3
    assert "fetch" in mock_run.call_args_list[0][0][0]


def test_sync_models_disabled():
    settings = SmithySettings(auto_sync=False, model_path="local")
    assert sync_models(settings) == "local"


def test_sync_models_without_sync_url_returns_model_path():
    settings = SmithySettings(auto_sync=True, sync_url="", model_path="local-model-path")
    assert sync_models(settings) == "local-model-path"


def test_sync_models_rejects_non_https_sync_url(tmp_path):
    settings = SmithySettings(
        auto_sync=True,
        sync_url="ssh://repo.git",
        sync_ref="main",
        cache_path=str(tmp_path),
    )
    with pytest.raises(ValueError, match="must use HTTPS"):
        sync_models(settings)


def test_sync_models_rejects_invalid_sync_ref_characters(tmp_path):
    settings = SmithySettings(
        auto_sync=True,
        sync_url="https://repo.git",
        sync_ref="main;rm",
        cache_path=str(tmp_path),
    )
    with pytest.raises(ValueError, match="invalid characters"):
        sync_models(settings)


def test_sync_models_rejects_sync_ref_starting_with_dash(tmp_path):
    settings = SmithySettings(
        auto_sync=True,
        sync_url="https://repo.git",
        sync_ref="-danger",
        cache_path=str(tmp_path),
    )
    with pytest.raises(ValueError, match="must not start"):
        sync_models(settings)


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


def test_get_model_commit_sha_repo_or_git_missing(tmp_path):
    assert get_model_commit_sha(str(tmp_path)) is None
    repo_path = tmp_path / "api-models-aws"
    repo_path.mkdir(parents=True)
    assert get_model_commit_sha(str(tmp_path)) is None


@patch("aws_cli_mcp.smithy.sync.subprocess.run", side_effect=RuntimeError("git error"))
def test_get_model_commit_sha_handles_exception(mock_run, tmp_path):
    repo_path = tmp_path / "api-models-aws"
    (repo_path / ".git").mkdir(parents=True)
    assert get_model_commit_sha(str(tmp_path)) is None


@patch("aws_cli_mcp.smithy.sync.subprocess.run")
def test_sync_models_raises_on_clone_failure(mock_run, tmp_path):
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = "out"
    mock_run.return_value.stderr = "err"
    settings = SmithySettings(
        auto_sync=True,
        sync_url="https://repo.git",
        sync_ref="main",
        cache_path=str(tmp_path),
    )
    with pytest.raises(RuntimeError, match="git clone failed"):
        sync_models(settings)


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
def test_version_manager_flow(mock_sha, mock_resolve, mock_load_paths, mock_load_std, clean_vm):
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
    snap1 = load_model_snapshot()  # uses current version v1
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
    op_entry = OperationEntry(
        ref=OperationRef("s3", "List"), operation_shape_id="id", documentation=""
    )
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


def test_model_snapshot_properties_raise_when_uninitialized() -> None:
    snapshot = ModelSnapshot(version="v1", loaded_at="now")
    with pytest.raises(RuntimeError, match="not fully initialized"):
        _ = snapshot.model
    with pytest.raises(RuntimeError, match="not fully initialized"):
        _ = snapshot.catalog
    with pytest.raises(RuntimeError, match="not fully initialized"):
        _ = snapshot.schema_generator


def test_model_snapshot_properties_return_initialized_values() -> None:
    snapshot = ModelSnapshot(version="v1", loaded_at="now")
    snapshot._model = MagicMock()
    snapshot._catalog = MagicMock()
    snapshot._schema_generator = MagicMock()
    assert snapshot.model is snapshot._model
    assert snapshot.catalog is snapshot._catalog
    assert snapshot.schema_generator is snapshot._schema_generator


@patch("aws_cli_mcp.smithy.version_manager.resolve_service_model_paths")
@patch("aws_cli_mcp.smithy.version_manager.load_models_from_paths")
def test_version_manager_load_models_allowlist_paths(
    mock_load_from_paths,
    mock_resolve_paths,
    clean_vm,
):
    vm = init_version_manager(
        "cache", "model-path", service_allowlist=["s3"], max_cached_versions=2
    )
    mock_resolve_paths.return_value = {"s3": "s3.json"}
    mock_model = MagicMock()
    mock_load_from_paths.return_value = mock_model
    loaded = vm._load_models()
    assert loaded is mock_model
    mock_load_from_paths.assert_called_once_with(["s3.json"])


@patch("aws_cli_mcp.smithy.version_manager.resolve_service_model_paths", return_value={})
@patch("aws_cli_mcp.smithy.version_manager.load_models_from_paths")
def test_version_manager_load_models_allowlist_fallback_glob(
    mock_load_from_paths,
    mock_resolve_paths,
    tmp_path,
    clean_vm,
):
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True)
    (model_dir / "a.json").write_text("{}", encoding="utf-8")
    vm = init_version_manager(
        "cache", str(model_dir), service_allowlist=["s3"], max_cached_versions=2
    )
    mock_model = MagicMock()
    mock_load_from_paths.return_value = mock_model
    loaded = vm._load_models()
    assert loaded is mock_model
    assert mock_load_from_paths.call_count == 1


@patch("aws_cli_mcp.smithy.version_manager.resolve_service_model_paths", return_value={})
def test_version_manager_load_models_allowlist_no_models_raises(
    mock_resolve_paths,
    tmp_path,
    clean_vm,
):
    model_dir = tmp_path / "models"
    model_dir.mkdir(parents=True)
    vm = init_version_manager(
        "cache", str(model_dir), service_allowlist=["s3"], max_cached_versions=2
    )
    with pytest.raises(RuntimeError, match="No Smithy models found"):
        vm._load_models()


@patch("aws_cli_mcp.smithy.version_manager.SchemaGenerator")
@patch("aws_cli_mcp.smithy.version_manager.SmithyCatalog")
@patch("aws_cli_mcp.smithy.version_manager.load_models")
def test_version_manager_create_snapshot_builds_services(
    mock_load_models,
    mock_catalog_cls,
    mock_schema_cls,
    clean_vm,
):
    mock_model = MagicMock()
    mock_load_models.return_value = mock_model
    catalog = MagicMock()
    catalog.list_operations.return_value = [
        OperationEntry(
            ref=OperationRef("s3", "ListBuckets"),
            operation_shape_id="op1",
            documentation="list",
        )
    ]
    mock_catalog_cls.return_value = catalog
    mock_schema_cls.return_value = MagicMock()

    vm = init_version_manager("cache", "path", max_cached_versions=2)
    snap = vm.load_snapshot("vX")
    assert "s3" in snap.services
    assert "ListBuckets" in snap.services["s3"].operations
