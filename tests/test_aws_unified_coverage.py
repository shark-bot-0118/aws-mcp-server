import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import base64
from unittest.mock import MagicMock, patch
from aws_cli_mcp.tools.aws_unified import (
    _coerce_payload_types,
    _coerce_timestamp,
    _coerce_integer,
    _coerce_float,
    _coerce_boolean,
    _coerce_blob,
    _is_exposed,
    search_operations,
    execute_operation
)
from aws_cli_mcp.smithy.parser import SmithyModel, StructureShape, Member, StringShape, Shape, UnionShape
from aws_cli_mcp.domain.operations import OperationRef

def test_is_exposed_allowlists():
    ctx = MagicMock()
    ctx.policy_engine.is_service_allowed.return_value = True
    ctx.policy_engine.is_operation_allowed.return_value = True
    
    op_ref = OperationRef("s3", "ListBuckets")
    
    # Empty lists (default allow)
    ctx.settings.smithy.allowlist_services = []
    ctx.settings.smithy.allowlist_operations = []
    assert _is_exposed(ctx, op_ref) is True
    
    # Service allowlist
    ctx.settings.smithy.allowlist_services = ["s3"]
    assert _is_exposed(ctx, op_ref) is True
    
    ctx.settings.smithy.allowlist_services = ["ec2"]
    assert _is_exposed(ctx, op_ref) is False
    
    # Operation allowlist
    ctx.settings.smithy.allowlist_services = []
    ctx.settings.smithy.allowlist_operations = ["s3:ListBuckets"]
    assert _is_exposed(ctx, op_ref) is True
    
    ctx.settings.smithy.allowlist_operations = ["s3:GetObject"]
    assert _is_exposed(ctx, op_ref) is False

def test_coerce_timestamp():
    # Valid ISO
    assert _coerce_timestamp("2023-01-01T00:00:00Z", "p") == "2023-01-01T00:00:00Z"
    assert _coerce_timestamp("2023-01-01", "p") == "2023-01-01"
    
    # Unix timestamp
    assert _coerce_timestamp(1672531200, "p") == "2023-01-01T00:00:00Z"
    
    # Invalid types
    with pytest.raises(ValueError, match="Expected timestamp string"):
        _coerce_timestamp([], "p")
        
    # Invalid format
    with pytest.raises(ValueError, match="Invalid timestamp format"):
        _coerce_timestamp("bad-date", "p")

def test_coerce_integer():
    assert _coerce_integer("123", "p", "integer") == 123
    assert _coerce_integer(123.0, "p", "integer") == 123
    
    with pytest.raises(ValueError, match="got boolean"):
        _coerce_integer(True, "p", "integer")
        
    with pytest.raises(ValueError, match="Cannot convert"):
        _coerce_integer("bad", "p", "integer")
    
    with pytest.raises(ValueError, match="decimal part"):
        _coerce_integer(12.34, "p", "integer")
        
    # Range checks
    with pytest.raises(ValueError, match="out of range"):
        _coerce_integer(128, "p", "byte")

def test_coerce_boolean():
    assert _coerce_boolean("true", "p") is True
    assert _coerce_boolean("OFF", "p") is False
    assert _coerce_boolean(1, "p") is True
    assert _coerce_boolean(0, "p") is False
    
    with pytest.raises(ValueError, match="Cannot convert"):
        _coerce_boolean("maybe", "p")
        
    with pytest.raises(ValueError, match="Expected boolean"):
        _coerce_boolean([], "p")

def test_coerce_blob():
    # Helper to test deep blob coercion via _coerce_payload_types
    model = MagicMock(spec=SmithyModel)
    blob_shape = Shape("id", "blob", {})
    struct_shape = StructureShape("struct", "structure", {}, {
        "Data": Member("blob", {})
    })
    
    model.get_shape.side_effect = lambda sid: {
        "blob": blob_shape,
        "struct": struct_shape
    }.get(sid)
    
    # Valid base64
    payload = {"Data": base64.b64encode(b"hello").decode()}
    coerced = _coerce_payload_types(model, "struct", payload)
    assert coerced["Data"] == b"hello"
    
    # Invalid base64
    with pytest.raises(ValueError, match="Invalid base64 encoding"):
        _coerce_blob("invalid-base64", "")

def test_coercion_missing_branches():
    mock_model = MagicMock(spec=SmithyModel)
    
    # 1. Shape Lookup Failures
    mock_model.get_shape.return_value = None
    assert _coerce_payload_types(mock_model, "unknown", {"a": 1}) == {"a": 1}
    assert _coerce_payload_types(mock_model, None, {"a": 1}) == {"a": 1}

    # 2. Union Validation
    union_shape = UnionShape("union", "union", {}, {"A": Member("str", {}), "B": Member("int", {})})
    mock_model.get_shape.side_effect = lambda sid: {"union": union_shape}.get(sid)
    
    # 0 members
    with pytest.raises(ValueError, match="requires exactly one member"):
        _coerce_payload_types(mock_model, "union", {})
        
    # >1 members
    with pytest.raises(ValueError, match="requires exactly one member"):
        _coerce_payload_types(mock_model, "union", {"A": "val", "B": 1})

    # 3. Structure Coercion Branches
    struct_shape = StructureShape("struct", "structure", {}, {
        "S": Member("str", {}),
        "I": Member("int", {}),
        "F": Member("float", {}),
        "B": Member("bool", {}),
        "T": Member("ts", {}),
        "D": Member("blob", {}), # Blob
        "Missing": Member("missing_target", {})
    })
    
    # Define primitives
    str_shape = StringShape("str", "string", {})
    int_shape = Shape("int", "integer", {})
    float_shape = Shape("float", "float", {})
    bool_shape = Shape("bool", "boolean", {})
    ts_shape = Shape("ts", "timestamp", {})
    blob_shape = Shape("blob", "blob", {})
    
    mock_model.get_shape.side_effect = lambda sid: {
        "struct": struct_shape,
        "str": str_shape,
        "int": int_shape,
        "float": float_shape,
        "bool": bool_shape,
        "ts": ts_shape,
        "blob": blob_shape,
        "missing_target": None
    }.get(sid)
    
    # Full payload to hit all branches
    payload = {
        "S": "value",
        "I": "123", # String to Int
        "F": "10.5", # String to Float
        "B": "true", # String to Bool
        "T": "2024-01-01T00:00:00Z",
        "D": "SGVsbG8=", # Base64
        "UnknownField": "Ignored",
        "Missing": "Value" # Target shape not found (continue)
    }
    
    result = _coerce_payload_types(mock_model, "struct", payload)
    
    assert result["I"] == 123
    assert result["F"] == 10.5
    assert result["B"] is True
    assert result["D"] == b"Hello"
    # UnknownField should be preserved?
    assert result["UnknownField"] == "Ignored"
    
    # 4. Specific Coercion Errors (Helpers)
    # Integer from Bool
    with pytest.raises(ValueError, match="Expected integer.*got boolean"):
        _coerce_integer(True, "path", "integer")
        
    # Integer from bad String
    with pytest.raises(ValueError, match="Cannot convert"):
         _coerce_integer("invalid", "path", "integer")
    
    # Coerce Blob invalid type
    with pytest.raises(ValueError, match="Expected base64 string or bytes"):
        _coerce_blob(123, "path")
        
    # Coerce Float
    assert _coerce_float("1.5", "") == 1.5
    assert _coerce_float(1.5, "") == 1.5
    with pytest.raises(ValueError, match="Cannot convert"):
        _coerce_float("abc", "")

def test_coerce_union():
    model = MagicMock(spec=SmithyModel)
    union_shape = UnionShape("union", "union", {}, {
        "A": Member("str", {}),
        "B": Member("str", {})
    })
    str_shape = StringShape("str", "string", {})
    
    model.get_shape.side_effect = lambda sid: {
        "union": union_shape,
        "str": str_shape
    }.get(sid)
    
    # Valid (one member)
    assert _coerce_payload_types(model, "union", {"A": "val"}) == {"A": "val"}
    
    # Invalid (none)
    with pytest.raises(ValueError, match="requires exactly one member"):
        _coerce_payload_types(model, "union", {})
        
    # Invalid (multiple)
    with pytest.raises(ValueError, match="requires exactly one member"):
        _coerce_payload_types(model, "union", {"A": "1", "B": "2"})

def test_read_streaming_fields_coverage():
    from aws_cli_mcp.tools.aws_unified import _read_streaming_fields

    
    # 1. Exception during read
    mock_body = MagicMock()
    mock_body.read.side_effect = Exception("Read error")
    response = {"Body": mock_body}
    _read_streaming_fields(response)
    assert response["Body"] == ""
    
    # 2. Bytes content (UTF-8)
    mock_body.read.side_effect = None
    mock_body.read.return_value = b"hello"
    response = {"Body": mock_body}
    _read_streaming_fields(response)
    assert response["Body"] == "hello"
    
    # 3. Bytes content (Binary -> Base64)
    # Mocking read such that subsequent calls return binary?
    # Actually need a fresh mock or reset
    mock_body = MagicMock()
    mock_body.read.return_value = b"\xff\xff" # Invalid UTF-8
    response = {"Body": mock_body}
    _read_streaming_fields(response)
    # base64.b64encode(b'\xff\xff') -> b'//8='
    assert response["Body"] == "//8="
    
    # 4. String content / Empty
    mock_body = MagicMock()
    mock_body.read.return_value = None
    response = {"Body": mock_body}
    _read_streaming_fields(response)
    assert response["Body"] == ""
    
    # 5. Not readable
    response = {"Body": "already_string"}
    _read_streaming_fields(response)
    assert response["Body"] == "already_string"

def test_truncate_json():
    from aws_cli_mcp.tools.aws_unified import _truncate_json
    
    long_str = "a" * 10
    payload = {"key": long_str}
    
    # No truncate
    assert "..." not in _truncate_json(payload, 100)
    
    # Truncate
    truncated = _truncate_json(payload, 5)
    assert truncated.endswith("...")

def test_redact():
    from aws_cli_mcp.tools.aws_unified import _redact
    
    payload = {
        "password": "secret",
        "nested": {
            "token": "secret",
            "normal": "value"
        },
        "list": [
            {"accessKey": "secret"},
            "visible"
        ]
    }
    
    redacted = _redact(payload)
    assert redacted["password"] == "***"
    assert redacted["nested"]["token"] == "***"
    assert redacted["nested"]["normal"] == "value"
    assert redacted["list"][0]["accessKey"] == "***"
    assert redacted["list"][1] == "visible"
    assert "visible" == _redact("visible")

def test_retry_break():
    # Directly test the retry loop logic by mocking _call_boto3 to raise exception
    # This effectively happens in execute_operation, but we need to ensure max_retries break is hit
    

    from botocore.exceptions import BotoCoreError
    
    with patch("aws_cli_mcp.tools.aws_unified._call_boto3") as mock_call:
        with patch("time.sleep"):
            mock_call.side_effect = BotoCoreError(error_code="Throttling", msg="Throttle")
            
            ctx = MagicMock()
            ctx.settings.execution.max_retries = 1 # Correct attribute
            # Ensure it retries a few times then breaks
        # Ensure it retries a few times then breaks
        # But we need to control ctx.settings or constants?
        # execute_operation has max_retries=3 hardcoded or from somewhere?
        # "for attempt in range(max_retries + 1):" where max_retries=3
        
        # We need validation to pass first
        with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
             with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx):
                 ctx.policy_engine.evaluate.return_value.allowed = True
                 ctx.settings.server.auto_approve_destructive = True
                 ctx.catalog.find_operation.return_value = MagicMock(op_ref=MagicMock(service="s", operation="o"))
                 
                 result = execute_operation({
                     "action": "invoke", "service": "s", "operation": "o", "payload": {}
                 })
                 
                 # It should fail with ExecutionError
                 assert "ExecutionError" in str(result)
                 # Should have called multiple times
                 assert mock_call.call_count > 1
