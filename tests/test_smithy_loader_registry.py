import pytest
import json

from aws_cli_mcp.smithy.loader import load_models
from aws_cli_mcp.smithy.registry import resolve_service_model_paths

@pytest.fixture
def mock_fs(tmp_path):
    # s3/2006-03-01/s3-2006-03-01.json
    s3_dir = tmp_path / "models" / "s3" / "2006-03-01"
    s3_dir.mkdir(parents=True)
    (s3_dir / "s3-2006-03-01.json").write_text(
        json.dumps({"shapes": {"ns#S3": {"type": "service"}}})
    )
    
    # ec2/2016-11-15/ec2-2016.json (Custom name fallback)
    ec2_dir = tmp_path / "models" / "ec2" / "2016-11-15"
    ec2_dir.mkdir(parents=True)
    (ec2_dir / "ec2-2016.json").write_text(
        json.dumps({"shapes": {"ns#EC2": {"type": "service"}}})
    )

    # Empty service
    (tmp_path / "models" / "empty").mkdir(parents=True)
    
    return tmp_path

def test_load_models_directory(mock_fs):
    model = load_models(str(mock_fs / "models"))
    assert "ns#S3" in model.shapes
    assert "ns#EC2" in model.shapes

def test_load_models_file(mock_fs):
    file_path = mock_fs / "models" / "s3" / "2006-03-01" / "s3-2006-03-01.json"
    model = load_models(str(file_path))
    assert "ns#S3" in model.shapes
    assert "ns#EC2" not in model.shapes

def test_load_models_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_models(str(tmp_path / "nonexistent"))

def test_resolve_service_model_paths(mock_fs):
    base_path = str(mock_fs)
    
    # 1. Standard pattern (s3)
    resolved = resolve_service_model_paths(base_path, ["s3"])
    assert "s3" in resolved
    assert resolved["s3"].name == "s3-2006-03-01.json"
    
    # 2. Fallback pattern (ec2)
    resolved = resolve_service_model_paths(base_path, ["ec2"])
    assert "ec2" in resolved
    assert resolved["ec2"].name == "ec2-2016.json"
    
    # 3. Non-existent service
    resolved = resolve_service_model_paths(base_path, ["foo"])
    assert "foo" not in resolved
    
    # 4. Empty service dir (no versions/files)
    resolved = resolve_service_model_paths(base_path, ["empty"])
    assert "empty" not in resolved

def test_resolve_root_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        resolve_service_model_paths(str(tmp_path / "missing"), ["s3"])
