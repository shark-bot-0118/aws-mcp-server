from unittest.mock import MagicMock, patch, ANY
import pytest
import json
from botocore.exceptions import ClientError
from aws_cli_mcp.tools.aws_unified import (
    search_operations,
    get_operation_schema,
    execute_operation,
    _coerce_payload_types,
    _is_retryable,
    _redact,
    _truncate_json,
    _read_streaming_fields,
    _snake_case
)
from aws_cli_mcp.domain.operations import OperationRef

@pytest.fixture
def mock_ctx():
    with patch("aws_cli_mcp.tools.aws_unified.get_app_context") as mock_get:
        ctx = MagicMock()
        mock_get.return_value = ctx
        
        # Setup common context attributes
        ctx.model_version = "test-version"
        ctx.settings.smithy.allowlist_services = None # Allow all by default
        ctx.settings.smithy.allowlist_operations = None
        ctx.settings.server.require_approval = False
        ctx.settings.server.auto_approve_destructive = False
        ctx.settings.execution.max_retries = 1
        
        # Mock components
        ctx.catalog = MagicMock()
        ctx.policy_engine = MagicMock()
        ctx.schema_generator = MagicMock()
        ctx.store = MagicMock()
        ctx.artifacts = MagicMock()
        ctx.smithy_model = MagicMock()
        
        # Default policy to allowed
        ctx.policy_engine.is_service_allowed.return_value = True
        ctx.policy_engine.is_operation_allowed.return_value = True
        ctx.policy_engine.risk_for_operation.return_value = "low"
        
        yield ctx

@pytest.fixture
def mock_sleep():
    with patch("time.sleep") as mock:
        yield mock

def test_search_operations(mock_ctx):
    # Setup mock return
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "ListBuckets")
    mock_entry.documentation = "Lists S3 buckets"
    mock_ctx.catalog.search.return_value = [mock_entry]
    
    result = search_operations({"query": "s3 list"})
    
    assert result.content is not None
    data = json.loads(result.content)
    assert data["count"] == 1
    assert data["results"][0]["service"] == "s3"
    assert data["results"][0]["operation"] == "ListBuckets"

def test_search_operations_filtered(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "DeleteBucket")
    mock_ctx.catalog.search.return_value = [mock_entry]
    
    # Simulate policy deny
    mock_ctx.policy_engine.is_operation_allowed.return_value = False
    
    result = search_operations({"query": "delete"})
    data = json.loads(result.content)
    assert data["count"] == 0

def test_get_operation_schema(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "smithy.api#ListBuckets"
    mock_entry.documentation = "Lists S3 buckets"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    mock_ctx.schema_generator.generate_operation_input_schema.return_value = {"type": "object"}
    
    result = get_operation_schema({"service": "s3", "operation": "ListBuckets"})
    
    data = json.loads(result.content)
    assert data["service"] == "s3"
    assert data["schema"] == {"type": "object"}

def test_get_operation_schema_not_found(mock_ctx):
    mock_ctx.catalog.find_operation.return_value = None
    with pytest.raises(ValueError, match="Operation not found"):
        get_operation_schema({"service": "unknown", "operation": "Unknown"})

def test_execute_validate_success(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    # Mock validation success (returns empty list of errors)
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        # Mock policy allow
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.require_approval = False
        mock_decision.risk = "low"
        mock_decision.reasons = [] # Added reasons
        mock_ctx.policy_engine.evaluate.return_value = mock_decision
        
        result = execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        
        data = json.loads(result.content)
        assert data["valid"] is True

def test_execute_invoke_success(mock_ctx, mock_sleep):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    # Mock inject_idempotency
    with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
        # Mock coerce
        with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
            # Mock boto3 call
            with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={"Buckets": []}):
                # Mock validation
                with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
                    # Mock policy
                    mock_decision = MagicMock()
                    mock_decision.allowed = True
                    mock_decision.require_approval = False # explicit
                    mock_ctx.policy_engine.evaluate.return_value = mock_decision
                    
                    result = execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                    
                    data = json.loads(result.content)
                    assert "result" in data
                    assert data["result"] == {"Buckets": []}

def test_coercion_primitives(mock_ctx):
    # Test _coerce_integer
    from aws_cli_mcp.tools.aws_unified import _coerce_integer
    assert _coerce_integer("123", "", "integer") == 123
    assert _coerce_integer(123, "", "integer") == 123
    with pytest.raises(ValueError):
        _coerce_integer("abc", "", "integer")
    
    # Test _coerce_boolean
    from aws_cli_mcp.tools.aws_unified import _coerce_boolean
    assert _coerce_boolean("true", "") is True
    assert _coerce_boolean("False", "") is False
    with pytest.raises(ValueError):
        _coerce_boolean("maybe", "")

def test_snake_case():
    assert _snake_case("ListBuckets") == "list_buckets"
    assert _snake_case("DescribeDBInstances") == "describe_db_instances"

def test_redact():
    payload = {"password": "secret", "nested": {"apiKey": "123"}}
    redacted = _redact(payload)
    assert redacted["password"] == "***"
    assert redacted["nested"]["apiKey"] == "***"

def test_retryable_exception():
    exc = ClientError({"Error": {"Code": "Throttling"}}, "op")
    assert _is_retryable(exc)
    
    exc = ClientError({"Error": {"Code": "Other"}}, "op")
    assert not _is_retryable(exc)

def test_truncate_json():
    payload = {"key": "x" * 100}
    truncated = _truncate_json(payload, 50)
    assert len(truncated) <= 50
    assert truncated.endswith("...")

def test_read_streaming_fields():
    from io import BytesIO
    # Case 1: Bytes
    body = BytesIO(b"Hello")
    response = {"Body": body}
    _read_streaming_fields(response)
    assert response["Body"] == "Hello"
    
    # Case 2: String (shouldn't happen for Body usually but code handles it)
    response = {"Body": "StringContent"}
    _read_streaming_fields(response)
    assert response["Body"] == "StringContent"
    
    # Case 3: Error reading
    mock_body = MagicMock()
    mock_body.read.side_effect = Exception("Read failed")
    response = {"Body": mock_body}
    _read_streaming_fields(response)
    assert response["Body"] == ""

def test_confirmation_flow(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.require_approval = True
        mock_decision.reasons = []
        mock_ctx.policy_engine.evaluate.return_value = mock_decision
        
        # Ensure auto-approve is False
        mock_ctx.settings.server.auto_approve_destructive = False
        
        # Case 1: Confirmation required (no token)
        result = execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "DeleteBucket",
            "payload": {}
        })
        data = json.loads(result.content)
        assert data["error"]["type"] == "ConfirmationRequired"
        assert "confirmationToken" in data["error"]["hint"]
        
        # Case 2: Valid confirmation check
        valid_token = "ABCDEF"
        mock_tx = MagicMock()
        mock_tx.status = "PendingConfirmation"
        mock_ctx.store.get_tx.return_value = mock_tx
        
        # Mock internal calls for execution
        with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
            with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={"Success": True}):
                    result = execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "DeleteBucket",
                        "payload": {},
                        "options": {"confirmationToken": valid_token}
                    })
                    data = json.loads(result.content)
                    assert "result" in data
                    mock_ctx.store.update_tx_status.assert_any_call(valid_token, "Started", None)
                    
        # Case 3: Invalid/Expired Token
        mock_ctx.store.get_tx.return_value = None
        result = execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "DeleteBucket",
            "payload": {},
            "options": {"confirmationToken": "bad-token"}
        })
        data = json.loads(result.content)
        assert data["error"]["type"] == "InvalidConfirmationToken"

def test_coercion_complex_types(mock_ctx):
    # Mock model definitions
    mock_ctx.smithy_model.get_shape.side_effect = lambda sid: {
        "list-id": MagicMock(type="list", member=MagicMock(target="int-id")),
        "int-id": MagicMock(type="integer"),
        "map-id": MagicMock(type="map", value=MagicMock(target="string-id")),
        "string-id": MagicMock(type="string"),
        "blob-id": MagicMock(type="blob"),
        "timestamp-id": MagicMock(type="timestamp"),
    }.get(sid)
    
    from aws_cli_mcp.tools.aws_unified import _coerce_list, _coerce_map, _coerce_blob, _coerce_timestamp
    from aws_cli_mcp.smithy.parser import ListShape, MapShape

    # Test List
    list_shape = MagicMock()
    list_shape.member.target = "int-id"
    result = _coerce_list(mock_ctx.smithy_model, list_shape, ["1", "2"], "")
    assert result == [1, 2]
    
    # Test Map
    map_shape = MagicMock()
    map_shape.value.target = "string-id" # Actually map keys are always strings in JSON
    # Wait, maps in smithy have Key and Value. But JSON keys are strings.
    # _coerce_map only coerces values.
    result = _coerce_map(mock_ctx.smithy_model, map_shape, {"a": "val"}, "")
    assert result == {"a": "val"}
    
    # Test Blob
    blob_b64 = "SGVsbG8=" # Hello
    assert _coerce_blob(blob_b64, "") == b"Hello"
    assert _coerce_blob(b"Hello", "") == b"Hello"
    with pytest.raises(ValueError):
        _coerce_blob("!!!", "")
    
    # Test Timestamp
    assert _coerce_timestamp("2024-01-01T00:00:00Z", "") == "2024-01-01T00:00:00Z"
    # Unix timestamp
    assert "2024" in _coerce_timestamp(1704067200, "") # Just check it converts to string

# def test_is_exposed(mock_ctx):
#     mock_entry = MagicMock()
#     mock_entry.ref = OperationRef("s3", "ListBuckets")
#     
#     # Case 1: Allowed
#     mock_ctx.settings.smithy.allowlist_services = None
#     mock_ctx.policy_engine.is_service_allowed.return_value = True
#     mock_ctx.policy_engine.is_operation_allowed.return_value = True
#     
#     # Access private function? No, search_operations uses it.
#     mock_ctx.catalog.search.return_value = [mock_entry]
#     result = search_operations({"query": "s3"})
#     assert json.loads(result.content)["count"] == 1
#     
#     # Case 2: Service not allowed by policy
#     mock_ctx.policy_engine.is_service_allowed.return_value = False
#     result = search_operations({"query": "s3"})
#     assert json.loads(result.content)["count"] == 0
#     
#     # Case 3: Service allowed, but not in allowlist settings
#     mock_ctx.policy_engine.is_service_allowed.return_value = True
#     mock_ctx.settings.smithy.allowlist_services = ["ec2"]
#     result = search_operations({"query": "s3"})
#     assert json.loads(result.content)["count"] == 0
# 
# def test_is_exposed_operation_allowlist(mock_ctx):
#     mock_entry = MagicMock()
#     mock_entry.ref = OperationRef("s3", "ListBuckets")
#     mock_ctx.catalog.search.return_value = [mock_entry]
# 
#     # Case: Operation allowlist is active
#     mock_ctx.settings.smithy.allowlist_services = None
#     mock_ctx.settings.smithy.allowlist_operations = ["s3:ListBuckets"]
#     result = search_operations({"query": "s3"})
#     assert json.loads(result.content)["count"] == 1
# 
#     # Case: Operation not in allowlist
#     mock_ctx.settings.smithy.allowlist_operations = ["s3:OtherOp"]
#     result = search_operations({"query": "s3"})
#     assert json.loads(result.content)["count"] == 0

def test_execute_json_string_parsing(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        
        # Valid JSON strings
        with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={}):
            result = execute_operation({
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": "{}",
                "options": "{\"skipApproval\": true}"
            })
            assert "result" in json.loads(result.content)

        # Invalid JSON payload
        result = execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": "{invalid"
        })
        data = json.loads(result.content)
        assert data["error"]["type"] == "InvalidPayload"

        # Invalid JSON options (fall back to empty dict)
        with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={}):
             result = execute_operation({
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {},
                "options": "{invalid"
            })
             assert "result" in json.loads(result.content)

def test_execute_operation_not_found(mock_ctx):
    mock_ctx.catalog.find_operation.return_value = None
    result = execute_operation({
        "action": "validate",
        "service": "s3",
        "operation": "Unknown",
        "payload": {}
    })
    data = json.loads(result.content)
    assert data["error"]["type"] == "OperationNotFound"

def test_execute_operation_not_exposed(mock_ctx):
    mock_entry = MagicMock()
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.policy_engine.is_service_allowed.return_value = False
    
    result = execute_operation({
        "action": "validate",
        "service": "s3",
        "operation": "ListBuckets",
        "payload": {}
    })
    data = json.loads(result.content)
    assert data["error"]["type"] == "OperationNotAllowed"

def test_execute_validation_error(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured") as mock_validate:
        from aws_cli_mcp.utils.jsonschema import ValidationError
        mock_validate.return_value = [ValidationError(type="missing_required", message="Error 1")]
        
        result = execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        data = json.loads(result.content)
        assert data["error"]["type"] == "ValidationError"

def test_execute_policy_denied(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = False
        mock_ctx.policy_engine.evaluate.return_value.reasons = ["Denied"]
        
        result = execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        data = json.loads(result.content)
        assert data["error"]["type"] == "PolicyDenied"

def test_execute_type_coercion_error(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        
        with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", side_effect=ValueError("Coercion failed")):
            result = execute_operation({
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {}
            })
            data = json.loads(result.content)
            assert data["error"]["type"] == "TypeCoercionError"

def test_execute_boto3_error_handling(mock_ctx, mock_sleep):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        
        with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
            with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
                
                # Case 1: Generic Exception
                with patch("aws_cli_mcp.tools.aws_unified._call_boto3", side_effect=Exception("Generic Error")):
                     result = execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                     data = json.loads(result.content)
                     assert data["error"]["type"] == "ExecutionError"
                     assert "Generic Error" in data["error"]["message"]

                # Case 2: Retryable ClientError (Throttling)
                mock_ctx.settings.execution.max_retries = 1
                with patch("aws_cli_mcp.tools.aws_unified._call_boto3") as mock_call:
                    mock_call.side_effect = [
                        ClientError({"Error": {"Code": "Throttling"}}, "op"),
                        {"Success": True}
                    ]
                    result = execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                    data = json.loads(result.content)
                    assert data["result"] == {"Success": True}
                    assert mock_call.call_count == 2
