import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from unittest.mock import MagicMock, patch
from pathlib import Path
from aws_cli_mcp.utils.local_file import (
    get_file_info,
    check_size_limit,
    resolve_path_for_blob,
    create_zip_from_folder,
    is_path_spec,
    parse_path_spec,
    LocalFileInfo,
    PathNotFoundError,
    FileTooLargeError,
    FolderNotSupportedError,
    LocalFileError
)

@pytest.fixture
def mock_path(tmp_path):
    # Create a dummy file structure
    (tmp_path / "file.txt").write_text("content")
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder" / "sub.txt").write_text("sub content")
    
    return tmp_path

def test_is_path_spec():
    assert is_path_spec({"$path": "/tmp"}) is True
    assert is_path_spec({"path": "/tmp"}) is False
    assert is_path_spec(None) is False

def test_parse_path_spec():
    path, opts = parse_path_spec({"$path": "/tmp", "keyPrefix": "pre/"})
    assert path == "/tmp"
    assert opts == {"keyPrefix": "pre/"}

def test_get_file_info(mock_path):
    # File
    info = get_file_info(str(mock_path / "file.txt"))
    assert info.is_file is True
    assert info.size == 7
    
    # Folder
    info = get_file_info(str(mock_path / "folder"))
    assert info.is_folder is True
    assert info.size > 0
    
    # Missing
    with pytest.raises(PathNotFoundError):
        get_file_info(str(mock_path / "missing"))

def test_check_size_limit(mock_path):
    info = LocalFileInfo(
        path=Path("dummy"),
        is_file=True,
        is_folder=False,
        size=100,
        content_type="text/plain"
    )
    
    # Within limit
    with patch("aws_cli_mcp.utils.local_file.BLOB_SIZE_LIMITS", {"svc": {"field": 200}}):
        check_size_limit(info, "svc", "field")

    # Exceeds limit
    with patch("aws_cli_mcp.utils.local_file.BLOB_SIZE_LIMITS", {"svc": {"field": 50}}):
        with pytest.raises(FileTooLargeError):
            check_size_limit(info, "svc", "field")
            
    # Default limit check (no specific limit definition)
    check_size_limit(info, "unknown_svc", "field") # 100 < 100MB default

def test_resolve_path_single_file(mock_path):
    val = {"$path": str(mock_path / "file.txt")}
    
    # Basic file read
    content = resolve_path_for_blob(val, "s3", "PutObject", "Body")
    assert content == b"content"

def test_resolve_path_lambda_zip(mock_path):
    val = {"$path": str(mock_path / "folder")}
    
    # Lambda folder -> Zip
    content = resolve_path_for_blob(val, "lambda", "CreateFunction", "ZipFile")
    assert content.startswith(b"PK") # Zip magic bytes

def test_resolve_path_s3_folder(mock_path):
    val = {"$path": str(mock_path / "folder"), "keyPrefix": "upload/"}
    
    # S3 folder -> list of files
    result = resolve_path_for_blob(val, "s3", "PutObject", "Body")
    assert isinstance(result, list)
    assert len(result) == 1
    key, content, ctype = result[0]
    assert key == "upload/sub.txt"
    assert content == b"sub content"

def test_resolve_path_unsupported_folder(mock_path):
    val = {"$path": str(mock_path / "folder")}
    
    # Unsupported service
    with pytest.raises(FolderNotSupportedError):
        resolve_path_for_blob(val, "sqs", "SendMessage", "Body")

def test_create_zip_from_folder(mock_path):
    zip_bytes = create_zip_from_folder(mock_path / "folder")
    assert len(zip_bytes) > 0
    assert zip_bytes.startswith(b"PK")
