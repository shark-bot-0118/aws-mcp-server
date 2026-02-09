import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_cli_mcp.auth.context import RequestContext, reset_request_context, set_request_context
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.execution.aws_client import RequestContextError
from aws_cli_mcp.tools.aws_unified import (
    _is_retryable,
    _redact,
    _snake_case,
    _truncate_json,
    execute_operation,
    get_operation_schema,
    search_operations,
)


@pytest.fixture
def mock_ctx():
    with patch("aws_cli_mcp.tools.aws_unified.get_app_context") as mock_get:
        with patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot") as mock_load_snapshot:
            ctx = MagicMock()
            mock_get.return_value = ctx

            # Setup common context attributes
            ctx.settings.server.require_approval = False
            ctx.settings.server.auto_approve_destructive = False
            ctx.settings.execution.max_retries = 1
            ctx.settings.execution.max_output_characters = 10000

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
            ctx.user_id = "test-user"

            # Setup snapshot mock
            mock_snapshot = MagicMock()
            mock_snapshot.catalog = ctx.catalog
            mock_snapshot.schema_generator = ctx.schema_generator
            mock_snapshot.model = ctx.smithy_model
            mock_load_snapshot.return_value = mock_snapshot

            # Setup RequestContext
            req_ctx = RequestContext(
                user_id="test-user",
                issuer="test-issuer",
                access_token="test-token"
            )
            token = set_request_context(req_ctx)
            
            try:
                yield ctx
            finally:
                reset_request_context(token)

@pytest.fixture
def mock_sleep():
    with patch("asyncio.sleep") as mock:
        yield mock

def test_search_operations(mock_ctx):
    # Setup mock return
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "ListBuckets")
    mock_entry.documentation = "Lists S3 buckets"
    mock_ctx.catalog.search.return_value = [mock_entry]
    
    result = search_operations({"query": "s3 list"})
    
    assert result.content is not None
    data = json.loads(result.content[0]["text"])
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
    data = json.loads(result.content[0]["text"])
    assert data["count"] == 0

def test_get_operation_schema(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "ListBuckets")
    mock_entry.operation_shape_id = "smithy.api#ListBuckets"
    mock_entry.documentation = "Lists S3 buckets"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    mock_ctx.schema_generator.generate_operation_input_schema.return_value = {"type": "object"}
    
    result = get_operation_schema({"service": "s3", "operation": "ListBuckets"})
    
    data = json.loads(result.content[0]["text"])
    assert data["service"] == "s3"
    assert data["operation"] == "ListBuckets"
    assert data["schema"] == {"type": "object"}

def test_get_operation_schema_normalizes_operation_name(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "ListBuckets")
    mock_entry.operation_shape_id = "smithy.api#ListBuckets"
    mock_entry.documentation = "Lists S3 buckets"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.schema_generator.generate_operation_input_schema.return_value = {"type": "object"}

    result = get_operation_schema({"service": "s3", "operation": "list-buckets"})

    data = json.loads(result.content[0]["text"])
    assert data["operation"] == "ListBuckets"

def test_get_operation_schema_not_found(mock_ctx):
    mock_ctx.catalog.find_operation.return_value = None
    with pytest.raises(ValueError, match="Operation not found"):
        get_operation_schema({"service": "unknown", "operation": "Unknown"})

@pytest.mark.asyncio
async def test_execute_validate_success(mock_ctx):
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
        
        result = await execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        
        data = json.loads(result.content[0]["text"])
        assert data["valid"] is True

@pytest.mark.asyncio
async def test_execute_invoke_success(mock_ctx, mock_sleep):
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
                    
                    result = await execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                    
                    data = json.loads(result.content[0]["text"])
                    assert "result" in data
                    assert data["result"] == {"Buckets": []}

@pytest.mark.asyncio
async def test_execute_invoke_normalizes_operation_name_for_call(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.ref = OperationRef("s3", "ListBuckets")
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry

    with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
        with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
            with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={"Buckets": []}) as mock_call:
                with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
                    mock_decision = MagicMock()
                    mock_decision.allowed = True
                    mock_decision.require_approval = False
                    mock_ctx.policy_engine.evaluate.return_value = mock_decision

                    result = await execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "list-buckets",
                        "payload": {},
                    })

    data = json.loads(result.content[0]["text"])
    assert "result" in data
    mock_call.assert_called_once()
    assert mock_call.call_args.args[1] == "ListBuckets"

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
    from botocore.exceptions import BotoCoreError

    exc = ClientError({"Error": {"Code": "Throttling"}}, "op")
    assert _is_retryable(exc)
    
    exc = ClientError({"Error": {"Code": "Other"}}, "op")
    assert not _is_retryable(exc)

    assert _is_retryable(BotoCoreError(error_code="ReadTimeout", msg="timeout"))

def test_truncate_json():
    payload = {"key": "x" * 100}
    truncated = _truncate_json(payload, 50)
    assert len(truncated) <= 50
    assert truncated.endswith("...")


@pytest.mark.asyncio
async def test_confirmation_flow(mock_ctx):
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
        result = await execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "DeleteBucket",
            "payload": {}
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "ConfirmationRequired"
        assert "confirmationToken" in data["error"]["hint"]
        
        # Case 2: Valid confirmation check
        valid_token = "ABCDEF"
        mock_tx = MagicMock()
        mock_tx.status = "PendingConfirmation"
        mock_tx.user_id = "test-user"
        mock_tx.actor = "test-issuer:test-user"
        mock_ctx.store.get_tx.return_value = mock_tx
        # Atomic claim returns True (caller wins the race)
        mock_ctx.store.claim_pending_tx.return_value = True

        # Mock pending op
        mock_op = MagicMock()
        mock_op.service = "s3"
        mock_op.operation = "DeleteBucket"
        # We need to match hash. Let's mock _compute_request_hash
        with patch("aws_cli_mcp.tools.aws_unified._compute_request_hash", return_value="hash-123"):
             mock_op.request_hash = "hash-123"
             mock_ctx.store.get_pending_op.return_value = mock_op

             # Mock internal calls for execution
             with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
                 with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                     with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={"Success": True}):

                         result = await execute_operation({
                             "action": "invoke",
                             "service": "s3",
                             "operation": "DeleteBucket",
                             "payload": {},
                             "options": {"confirmationToken": valid_token}
                         })
                         data = json.loads(result.content[0]["text"])
                         assert "result" in data
                         mock_ctx.store.claim_pending_tx.assert_called_once_with(valid_token)
                         
        # Case 3: Invalid/Expired Token
        mock_ctx.store.get_tx.return_value = None
        result = await execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "DeleteBucket",
            "payload": {},
            "options": {"confirmationToken": valid_token}
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "InvalidConfirmationToken"


@pytest.mark.asyncio
async def test_execute_global_approval_requires_confirmation(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.require_approval = True
    mock_ctx.settings.server.auto_approve_destructive = True

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.require_approval = False
        mock_decision.require_approval_for_destructive = False
        mock_decision.require_approval_for_risk = False
        mock_decision.risk = None
        mock_decision.reasons = []
        mock_ctx.policy_engine.evaluate.return_value = mock_decision

        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {},
            }
        )

    data = json.loads(result.content[0]["text"])
    assert data["error"]["type"] == "ConfirmationRequired"
    assert data["error"]["message"] == "Operation requires confirmation."
    assert any("ApprovalSource: server" in reason for reason in data["error"]["reasons"])


@pytest.mark.asyncio
async def test_execute_auto_approve_destructive_keeps_risk_confirmation(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.require_approval = False
    mock_ctx.settings.server.auto_approve_destructive = True

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.require_approval = True
        mock_decision.require_approval_for_destructive = True
        mock_decision.require_approval_for_risk = True
        mock_decision.risk = "high"
        mock_decision.reasons = []
        mock_ctx.policy_engine.evaluate.return_value = mock_decision

        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
            }
        )

    data = json.loads(result.content[0]["text"])
    assert data["error"]["type"] == "ConfirmationRequired"
    assert any("policy:risk:high" in reason for reason in data["error"]["reasons"])


@pytest.mark.asyncio
async def test_execute_auto_approve_destructive_only_bypasses_confirmation(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.require_approval = False
    mock_ctx.settings.server.auto_approve_destructive = True

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.require_approval = True
        mock_decision.require_approval_for_destructive = True
        mock_decision.require_approval_for_risk = False
        mock_decision.risk = None
        mock_decision.reasons = []
        mock_ctx.policy_engine.evaluate.return_value = mock_decision

        with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
            with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={"ok": True}):
                    result = await execute_operation(
                        {
                            "action": "invoke",
                            "service": "s3",
                            "operation": "DeleteBucket",
                            "payload": {},
                        }
                    )

    data = json.loads(result.content[0]["text"])
    assert data["result"] == {"ok": True}
    mock_ctx.store.get_tx.assert_not_called()


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
    
    from aws_cli_mcp.tools.aws_unified import (
        _coerce_blob,
        _coerce_list,
        _coerce_map,
        _coerce_timestamp,
    )
    
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

@pytest.mark.asyncio
async def test_execute_json_string_parsing(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        
        # Valid JSON strings
        with patch("aws_cli_mcp.tools.aws_unified._call_boto3", return_value={}):
            result = await execute_operation({
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": "{}",
                "options": "{\"skipApproval\": true}"
            })
            assert "result" in json.loads(result.content[0]["text"])

        # Invalid JSON payload
        result = await execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": "{invalid"
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "InvalidPayload"

        # Invalid JSON options now returns an error
        result = await execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {},
            "options": "{invalid"
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "InvalidOptions"

@pytest.mark.asyncio
async def test_execute_operation_not_found(mock_ctx):
    mock_ctx.catalog.find_operation.return_value = None
    result = await execute_operation({
        "action": "validate",
        "service": "s3",
        "operation": "Unknown",
        "payload": {}
    })
    data = json.loads(result.content[0]["text"])
    assert data["error"]["type"] == "OperationNotFound"

@pytest.mark.asyncio
async def test_execute_operation_not_exposed(mock_ctx):
    mock_entry = MagicMock()
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.policy_engine.is_service_allowed.return_value = False
    
    result = await execute_operation({
        "action": "validate",
        "service": "s3",
        "operation": "ListBuckets",
        "payload": {}
    })
    data = json.loads(result.content[0]["text"])
    assert data["error"]["type"] == "OperationNotAllowed"

@pytest.mark.asyncio
async def test_execute_validation_error(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured") as mock_validate:
        from aws_cli_mcp.utils.jsonschema import ValidationError
        mock_validate.return_value = [ValidationError(type="missing_required", message="Error 1")]
        
        result = await execute_operation({
            "action": "validate",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "ValidationError"

@pytest.mark.asyncio
async def test_execute_policy_denied(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = False
        mock_ctx.policy_engine.evaluate.return_value.reasons = ["Denied"]
        
        result = await execute_operation({
            "action": "invoke",
            "service": "s3",
            "operation": "ListBuckets",
            "payload": {}
        })
        data = json.loads(result.content[0]["text"])
        assert data["error"]["type"] == "PolicyDenied"

@pytest.mark.asyncio
async def test_execute_type_coercion_error(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    
    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        
        with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", side_effect=ValueError("Coercion failed")):
            result = await execute_operation({
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {}
            })
            data = json.loads(result.content[0]["text"])
            assert data["error"]["type"] == "TypeCoercionError"

@pytest.mark.asyncio
async def test_execute_boto3_error_handling(mock_ctx, mock_sleep):
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
                     result = await execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                     data = json.loads(result.content[0]["text"])
                     assert data["error"]["type"] == "ExecutionError"
                     assert "Generic Error" in data["error"]["message"]

                # Case 2: Retryable ClientError (Throttling)
                mock_ctx.settings.execution.max_retries = 1
                with patch("aws_cli_mcp.tools.aws_unified._call_boto3") as mock_call:
                    mock_call.side_effect = [
                        ClientError({"Error": {"Code": "Throttling"}}, "op"),
                        {"Success": True}
                    ]
                    result = await execute_operation({
                        "action": "invoke",
                        "service": "s3",
                        "operation": "ListBuckets",
                        "payload": {}
                    })
                    data = json.loads(result.content[0]["text"])
                    assert data["result"] == {"Success": True}
                    assert mock_call.call_count == 2


@pytest.mark.asyncio
async def test_execute_cleanup_exception_and_request_context_error(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.store.cleanup_pending_txs.side_effect = RuntimeError("cleanup failed")

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        mock_ctx.policy_engine.evaluate.return_value.allowed = True
        mock_ctx.policy_engine.evaluate.return_value.require_approval = False
        with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
            with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                with patch(
                    "aws_cli_mcp.tools.aws_unified._call_boto3",
                    side_effect=RequestContextError("context missing"),
                ):
                    with pytest.raises(RequestContextError):
                        await execute_operation(
                            {
                                "action": "invoke",
                                "service": "s3",
                                "operation": "ListBuckets",
                                "payload": {},
                            }
                        )


@pytest.mark.asyncio
async def test_execute_confirmation_token_error_branches(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.auto_approve_destructive = False

    decision = MagicMock()
    decision.allowed = True
    decision.require_approval = True
    decision.reasons = []
    mock_ctx.policy_engine.evaluate.return_value = decision

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
        token = "CONFIRM"

        # status mismatch -> line 402
        tx = MagicMock(status="Started", actor="test-issuer:test-user")
        mock_ctx.store.get_tx.return_value = tx
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
                "options": {"confirmationToken": token},
            }
        )
        assert "already been used" in result.content[0]["text"]

        # actor mismatch -> line 409
        tx = MagicMock(status="PendingConfirmation", actor="other:user")
        mock_ctx.store.get_tx.return_value = tx
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
                "options": {"confirmationToken": token},
            }
        )
        assert "does not belong" in result.content[0]["text"]

        # pending_op missing -> line 418
        tx = MagicMock(status="PendingConfirmation", actor="test-issuer:test-user")
        mock_ctx.store.get_tx.return_value = tx
        mock_ctx.store.get_pending_op.return_value = None
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
                "options": {"confirmationToken": token},
            }
        )
        assert "invalid or expired" in result.content[0]["text"]

        # operation mismatch -> line 425
        op = MagicMock(service="ec2", operation="TerminateInstances", request_hash="h")
        mock_ctx.store.get_pending_op.return_value = op
        with patch("aws_cli_mcp.tools.aws_unified._compute_request_hash", return_value="h"):
            result = await execute_operation(
                {
                    "action": "invoke",
                    "service": "s3",
                    "operation": "DeleteBucket",
                    "payload": {},
                    "options": {"confirmationToken": token},
                }
            )
        assert "does not match this operation" in result.content[0]["text"]

        # hash mismatch -> line 433
        op = MagicMock(service="s3", operation="DeleteBucket", request_hash="h1")
        mock_ctx.store.get_pending_op.return_value = op
        with patch("aws_cli_mcp.tools.aws_unified._compute_request_hash", return_value="h2"):
            result = await execute_operation(
                {
                    "action": "invoke",
                    "service": "s3",
                    "operation": "DeleteBucket",
                    "payload": {},
                    "options": {"confirmationToken": token},
                }
            )
        assert "does not match this request payload" in result.content[0]["text"]


@pytest.mark.asyncio
async def test_execute_confirmation_token_missing_current_actor_branch(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.auto_approve_destructive = False

    decision = MagicMock()
    decision.allowed = True
    decision.require_approval = True
    decision.reasons = []
    mock_ctx.policy_engine.evaluate.return_value = decision

    tx = MagicMock(status="PendingConfirmation", actor="issuer:user")
    mock_ctx.store.get_tx.return_value = tx

    with (
        patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]),
        patch("aws_cli_mcp.tools.aws_unified._actor_from_request_context", return_value=None),
    ):
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
                "options": {"confirmationToken": "CONFIRM"},
            }
        )

    assert "does not belong" in result.content[0]["text"]


@pytest.mark.asyncio
async def test_execute_confirmation_token_claim_conflict_branch(mock_ctx):
    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.auto_approve_destructive = False

    decision = MagicMock()
    decision.allowed = True
    decision.require_approval = True
    decision.reasons = []
    mock_ctx.policy_engine.evaluate.return_value = decision

    tx = MagicMock(status="PendingConfirmation", actor="test-issuer:test-user")
    op = MagicMock(service="s3", operation="DeleteBucket", request_hash="hash")
    mock_ctx.store.get_tx.return_value = tx
    mock_ctx.store.get_pending_op.return_value = op
    mock_ctx.store.claim_pending_tx.return_value = False

    with (
        patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]),
        patch("aws_cli_mcp.tools.aws_unified._compute_request_hash", return_value="hash"),
    ):
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "DeleteBucket",
                "payload": {},
                "options": {"confirmationToken": "CONFIRM"},
            }
        )

    assert "already been used" in result.content[0]["text"]


@pytest.mark.asyncio
async def test_execute_identity_center_credential_error_branch(mock_ctx):
    from aws_cli_mcp.tools.aws_unified import _error_response

    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.transport_mode = "http"
    mock_ctx.settings.auth.provider = "identity-center"
    mock_ctx.settings.server.auto_approve_destructive = True
    mock_ctx.policy_engine.evaluate.return_value.allowed = True
    mock_ctx.policy_engine.evaluate.return_value.require_approval = False

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]), \
         patch("aws_cli_mcp.tools.aws_unified._resolve_identity_center_role_selection", AsyncMock(return_value=("123456789012", "ReadOnly"))), \
         patch(
             "aws_cli_mcp.tools.aws_unified._ensure_identity_center_credentials",
             AsyncMock(return_value=_error_response("IdentityCenterError", "bad creds")),
         ), \
         patch("aws_cli_mcp.tools.aws_unified._record_audit_log", AsyncMock()):
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {},
                "options": {},
            }
        )
    assert "IdentityCenterError" in result.content[0]["text"]


@pytest.mark.asyncio
async def test_execute_identity_center_role_selection_error_short_circuit(mock_ctx):
    from aws_cli_mcp.tools.aws_unified import _error_response

    mock_entry = MagicMock()
    mock_entry.operation_shape_id = "op-id"
    mock_ctx.catalog.find_operation.return_value = mock_entry
    mock_ctx.settings.server.transport_mode = "http"
    mock_ctx.settings.auth.provider = "identity-center"
    mock_ctx.settings.server.auto_approve_destructive = True
    mock_ctx.policy_engine.evaluate.return_value.allowed = True
    mock_ctx.policy_engine.evaluate.return_value.require_approval = False

    with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]), \
         patch(
             "aws_cli_mcp.tools.aws_unified._resolve_identity_center_role_selection",
             AsyncMock(return_value=_error_response("RoleSelectionRequired", "pick a role")),
         ):
        result = await execute_operation(
            {
                "action": "invoke",
                "service": "s3",
                "operation": "ListBuckets",
                "payload": {},
                "options": {},
            }
        )
    assert "RoleSelectionRequired" in result.content[0]["text"]
