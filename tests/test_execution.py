import pytest
from unittest.mock import MagicMock, patch
from aws_cli_mcp.execution.aws_client import get_client, _CLIENT_CACHE
from aws_cli_mcp.execution.idempotency import inject_idempotency_tokens
from aws_cli_mcp.smithy.parser import SmithyModel, OperationShape, StructureShape, Member

@pytest.fixture
def clear_cache():
    _CLIENT_CACHE.clear()
    yield
    _CLIENT_CACHE.clear()

@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_caching(mock_session_cls, mock_settings, clear_cache):
    # Setup
    mock_settings.return_value.aws_default_profile = "default-prof"
    mock_settings.return_value.aws_default_region = "us-east-1"
    
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    
    # First call
    c1 = get_client("s3", None, None)
    mock_session_cls.assert_called_once()
    mock_session.client.assert_called_once()
    assert c1 == mock_client
    
    # Second call (cached)
    c2 = get_client("s3", None, None)
    # Should use cache, so call count unchanged
    assert mock_session_cls.call_count == 1
    assert c2 == c1
    
    # Different parameters -> new call
    get_client("ec2", "us-west-2", "prof")
    assert mock_session_cls.call_count == 2 # New session for different profile/region? 
    # Wait, implementation creates new session every cache miss.
    
def test_get_client_s3_config(clear_cache):
    with patch("aws_cli_mcp.execution.aws_client.boto3.Session"):
        with patch("aws_cli_mcp.execution.aws_client.Config"):
             mock_settings = MagicMock()
             with patch("aws_cli_mcp.execution.aws_client.load_settings", return_value=mock_settings):
                 get_client("s3", None, None)
                 
                 # Check S3 specific config args
                 kwargs = MockConfig.call_args.kwargs
                 assert kwargs["request_checksum_calculation"] == "when_required"
                 assert kwargs["response_checksum_validation"] == "when_required"

def test_get_client_other_config(clear_cache):
    with patch("aws_cli_mcp.execution.aws_client.boto3.Session"):
        with patch("aws_cli_mcp.execution.aws_client.Config"):
             mock_settings = MagicMock()
             with patch("aws_cli_mcp.execution.aws_client.load_settings", return_value=mock_settings):
                 get_client("ec2", None, None)
                 
                 # Check default config args (no checksum stuff)
                 kwargs = MockConfig.call_args.kwargs
                 assert "request_checksum_calculation" not in kwargs

def test_inject_idempotency_tokens():
    model = MagicMock(spec=SmithyModel)
    
    # Setup shapes
    op = MagicMock(spec=OperationShape)
    op.input = "input-struct"
    
    input_shape = MagicMock(spec=StructureShape)
    input_shape.members = {
        "Token": Member(target="str", traits={"smithy.api#idempotencyToken": {}}),
        "Data": Member(target="str", traits={})
    }
    
    model.get_shape.side_effect = lambda sid: {
        "op": op,
        "input-struct": input_shape
    }.get(sid)
    
    # 1. Inject token if missing
    params = {"Data": "foo"}
    updated, injected = inject_idempotency_tokens(model, "op", params)
    assert "Token" in updated
    assert len(updated["Token"]) > 0
    assert "Token" in injected
    
    # 2. Don't overwrite if present
    params = {"Data": "foo", "Token": "existing"}
    updated, injected = inject_idempotency_tokens(model, "op", params)
    assert updated["Token"] == "existing"
    assert "Token" not in injected # Not injected by us

    # 3. No input shape
    op_no_input = MagicMock(spec=OperationShape)
    op_no_input.input = None
    model.get_shape.side_effect = lambda sid: op_no_input if sid == "op-no-input" else None
    
    params = {}
    updated, injected = inject_idempotency_tokens(model, "op-no-input", params)
    assert updated == params
    assert injected == []
