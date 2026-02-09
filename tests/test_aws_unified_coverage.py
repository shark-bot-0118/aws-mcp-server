import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

from aws_cli_mcp.auth.context import (
    RequestContext,
    get_request_context_optional,
    reset_request_context,
    set_request_context,
)
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.smithy.parser import (
    Member,
    Shape,
    SmithyModel,
    StringShape,
    StructureShape,
    UnionShape,
)
from aws_cli_mcp.tools.aws_unified import (
    _coerce_blob,
    _coerce_boolean,
    _coerce_float,
    _coerce_integer,
    _coerce_payload_types,
    _coerce_timestamp,
    _is_exposed,
    _limit_result_payload,
    execute_operation,
    search_operations,
)


def test_is_exposed_policy_only():
    ctx = MagicMock()
    op_ref = OperationRef("s3", "ListBuckets")

    ctx.policy_engine.is_service_allowed.return_value = True
    ctx.policy_engine.is_operation_allowed.return_value = True
    assert _is_exposed(ctx, op_ref) is True

    ctx.policy_engine.is_service_allowed.return_value = False
    assert _is_exposed(ctx, op_ref) is False

    ctx.policy_engine.is_service_allowed.return_value = True
    ctx.policy_engine.is_operation_allowed.return_value = False
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
        _coerce_blob(123, "path")  # Now only accepts bytes or string
        
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

def test_truncate_json():
    from aws_cli_mcp.tools.aws_unified import _truncate_json
    
    long_str = "a" * 10
    payload = {"key": long_str}
    
    # No truncate
    assert "..." not in _truncate_json(payload, 100)
    
    # Truncate
    truncated = _truncate_json(payload, 5)
    assert truncated.endswith("...")


def test_limit_result_payload_compacts_lambda_listfunctions() -> None:
    large_prompt = "x" * 4000
    payload = {
        "Functions": [
            {
                "FunctionName": "chat-api",
                "FunctionArn": "arn:aws:lambda:ap-northeast-1:123:function:chat-api",
                "Runtime": "python3.13",
                "Environment": {"Variables": {"SYSTEM_PROMPT": large_prompt}},
                "Layers": [{"Arn": "layer-1"}] * 8,
                "Tags": {"team": "ai"},
            }
            for _ in range(20)
        ]
    }

    limited = _limit_result_payload(
        payload,
        max_chars=3000,
        service="lambda",
        operation="ListFunctions",
        options={},
    )

    assert limited["truncated"] is True
    assert limited["strategy"] == "compact"
    compact_result = limited["result"]
    assert isinstance(compact_result, dict)
    first = compact_result["Functions"][0]
    assert isinstance(first, dict)
    assert "Environment" not in first
    assert "Layers" not in first
    assert "Tags" not in first


def test_limit_result_payload_full_mode_uses_preview() -> None:
    payload = {"Functions": [{"FunctionName": "name", "Blob": "x" * 8000}]}
    limited = _limit_result_payload(
        payload,
        max_chars=500,
        service="lambda",
        operation="ListFunctions",
        options={"responseMode": "full"},
    )

    assert limited["truncated"] is True
    assert limited["strategy"] == "preview"
    assert "preview" in limited


def test_limit_result_payload_respects_omit_response_fields_option() -> None:
    payload = {
        "Functions": [
            {
                "FunctionName": "chat-api",
                "Runtime": "python3.13",
                "Description": "x" * 4000,
            }
        ]
    }
    limited = _limit_result_payload(
        payload,
        max_chars=500,
        service="lambda",
        operation="ListFunctions",
        options={"responseMode": "compact", "omitResponseFields": ["Runtime"]},
    )

    assert limited["truncated"] is True
    compact_result = limited["result"]
    assert isinstance(compact_result, dict)
    first = compact_result["Functions"][0]
    assert isinstance(first, dict)
    assert "Runtime" not in first


def test_limit_result_payload_compacts_generic_heavy_fields() -> None:
    payload = {
        "Items": [
            {
                "Name": "item-1",
                "Policy": "x" * 4000,
                "TemplateBody": "y" * 2500,
                "Tags": {"owner": "platform", "env": "prod"},
                "Status": "ACTIVE",
            }
            for _ in range(12)
        ]
    }
    limited = _limit_result_payload(
        payload,
        max_chars=2000,
        service="cloudformation",
        operation="ListStacks",
        options={},
    )

    assert limited["truncated"] is True
    assert limited["strategy"] == "compact"
    compact_result = limited["result"]
    assert isinstance(compact_result, dict)
    items = compact_result["Items"]
    assert isinstance(items, dict)
    assert items["_mcp_compacted_type"] == "list"
    assert items["itemCount"] == 12

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


def test_redact_depth_limit():
    from aws_cli_mcp.tools.aws_unified import _MAX_REDACT_DEPTH, _redact

    # Build a nested dict deeper than the limit
    data: dict = {"safe": "value"}
    for _ in range(_MAX_REDACT_DEPTH + 1):
        data = {"level": data}

    result = _redact(data)
    # Walk to the depth limit
    current = result
    for _ in range(_MAX_REDACT_DEPTH):
        current = current["level"]
    assert current == "***"


@pytest.mark.asyncio
async def test_retry_break():
    # Directly test the retry loop logic by mocking _call_boto3 to raise exception
    # This effectively happens in execute_operation, but we need to ensure max_retries break is hit
    
    from botocore.exceptions import BotoCoreError
    
    with patch("aws_cli_mcp.tools.aws_unified._call_boto3") as mock_call:
        with patch("asyncio.sleep"):
            mock_call.side_effect = BotoCoreError(error_code="Throttling", msg="Throttle")
            
            ctx = MagicMock()
            ctx.settings.execution.max_retries = 1 # Correct attribute
            ctx.settings.execution.max_output_characters = 10000
            ctx.settings.server.transport_mode = "stdio"
            ctx.store.update_op_status = MagicMock()
            ctx.store.update_tx_status = MagicMock()
            
            # We need validation to pass first
            with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
                 with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx):
                     # Mock policy
                     mock_decision = MagicMock()
                     mock_decision.allowed = True
                     mock_decision.require_approval = False
                     ctx.policy_engine.evaluate.return_value = mock_decision
                     ctx.policy_engine.is_service_allowed.return_value = True
                     ctx.policy_engine.is_operation_allowed.return_value = True
                     
                     ctx.settings.server.auto_approve_destructive = True
                     
                     # Mock catalog
                     mock_entry = MagicMock()
                     mock_entry.operation_shape_id = "op-id"
                     ctx.catalog.find_operation.return_value = mock_entry
                     
                     # Mock load_model_snapshot
                     with patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot") as mock_load:
                         mock_snapshot = MagicMock()
                         mock_snapshot.catalog = ctx.catalog
                         mock_snapshot.model = MagicMock()
                         mock_load.return_value = mock_snapshot
                         
                         # Mock coerce
                         with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                             # Mock inject
                             with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
                             
                                 result = await execute_operation({
                                     "action": "invoke", "service": "s", "operation": "o", "payload": {}
                                 })
                                 
                                 # It should fail with ExecutionError
                                 assert "ExecutionError" in str(result)
                                 # Should have called multiple times
                                 assert mock_call.call_count > 1


@pytest.mark.asyncio
async def test_keyboard_interrupt_re_raised_in_retry_loop():
    """KeyboardInterrupt inside the retry loop should be re-raised immediately."""
    with patch("aws_cli_mcp.tools.aws_unified._call_boto3", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = KeyboardInterrupt()

        ctx = MagicMock()
        ctx.settings.execution.max_retries = 2
        ctx.settings.execution.max_output_characters = 10000
        ctx.settings.server.transport_mode = "stdio"
        ctx.store.update_op_status = MagicMock()
        ctx.store.update_tx_status = MagicMock()

        with patch("aws_cli_mcp.tools.aws_unified.validate_payload_structured", return_value=[]):
            with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx):
                mock_decision = MagicMock()
                mock_decision.allowed = True
                mock_decision.require_approval = False
                ctx.policy_engine.evaluate.return_value = mock_decision
                ctx.policy_engine.is_service_allowed.return_value = True
                ctx.policy_engine.is_operation_allowed.return_value = True
                ctx.settings.server.auto_approve_destructive = True

                mock_entry = MagicMock()
                mock_entry.operation_shape_id = "op-id"
                ctx.catalog.find_operation.return_value = mock_entry

                with patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot") as mock_load:
                    mock_snapshot = MagicMock()
                    mock_snapshot.catalog = ctx.catalog
                    mock_snapshot.model = MagicMock()
                    mock_load.return_value = mock_snapshot

                    with patch("aws_cli_mcp.tools.aws_unified._coerce_payload_types", return_value={}):
                        with patch("aws_cli_mcp.tools.aws_unified.inject_idempotency_tokens", return_value=({}, [])):
                            with pytest.raises(KeyboardInterrupt):
                                await execute_operation({
                                    "action": "invoke", "service": "s", "operation": "o", "payload": {}
                                })


def test_search_operations_service_hint_limit_and_get_schema_not_allowlisted():
    from aws_cli_mcp.tools.aws_unified import get_operation_schema

    ctx = MagicMock()
    ctx.policy_engine.is_service_allowed.return_value = True
    ctx.policy_engine.is_operation_allowed.side_effect = [True, True, True, False]
    ctx.policy_engine.risk_for_operation.return_value = "low"

    entries = []
    for idx in range(4):
        e = MagicMock()
        e.ref = OperationRef("S3", f"List{idx}")
        e.documentation = f"doc-{idx}"
        entries.append(e)

    snapshot = MagicMock()
    snapshot.catalog.search.return_value = entries
    snapshot.catalog.find_operation.return_value = MagicMock(
        operation_shape_id="shape-id",
        documentation="desc",
    )
    snapshot.schema_generator.generate_operation_input_schema.return_value = {"type": "object"}

    with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx), \
         patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot", return_value=snapshot):
        result = search_operations({"query": "list", "serviceHint": "S3", "limit": 2})
        payload = json.loads(result.content[0]["text"])
        assert payload["count"] == 2
        assert snapshot.catalog.search.call_args.kwargs["service"] == "s3"

    deny_ctx = MagicMock()
    deny_ctx.policy_engine.is_service_allowed.return_value = True
    deny_ctx.policy_engine.is_operation_allowed.return_value = False
    with patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=deny_ctx), \
         patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot", return_value=snapshot):
        with pytest.raises(ValueError, match="allowlisted"):
            get_operation_schema({"service": "s3", "operation": "ListBuckets"})


def test_search_operations_limit_parsing_fallback_branches() -> None:
    ctx = MagicMock()
    ctx.policy_engine.is_service_allowed.return_value = True
    ctx.policy_engine.is_operation_allowed.return_value = True
    ctx.policy_engine.risk_for_operation.return_value = "low"

    entry = MagicMock()
    entry.ref = OperationRef("s3", "ListBuckets")
    entry.documentation = "doc"
    snapshot = MagicMock()
    snapshot.catalog.search.return_value = [entry]

    with (
        patch("aws_cli_mcp.tools.aws_unified.get_app_context", return_value=ctx),
        patch("aws_cli_mcp.tools.aws_unified.load_model_snapshot", return_value=snapshot),
        patch("aws_cli_mcp.tools.aws_unified.validate_or_raise"),
    ):
        bool_limit = search_operations({"query": "list", "limit": True})
        bool_payload = json.loads(bool_limit.content[0]["text"])
        assert bool_payload["count"] == 1

        invalid_limit = search_operations({"query": "list", "limit": {"x": 1}})
        invalid_payload = json.loads(invalid_limit.content[0]["text"])
        assert invalid_payload["count"] == 1


def test_resolve_catalog_operation_uses_ref_string_attributes() -> None:
    from aws_cli_mcp.tools.aws_unified import _resolve_catalog_operation

    class Ref:
        service = "ec2"
        operation = "DescribeInstances"

    class Entry:
        ref = Ref()

    service, operation = _resolve_catalog_operation(Entry(), "s3", "ListBuckets")
    assert service == "ec2"
    assert operation == "DescribeInstances"


def test_identity_center_helper_functions():
    from aws_cli_mcp.tools.aws_unified import (
        _compute_request_hash,
        _identity_center_error,
        _parse_role_arn,
        _role_selection_error,
    )

    assert _compute_request_hash({"a": 1}, {"accountId": "123"}) != _compute_request_hash({"a": 1})
    assert _parse_role_arn("arn:aws:iam::123456789012:role/RoleName") == ("123456789012", "RoleName")
    assert _parse_role_arn("bad") is None

    role_err = json.loads(_role_selection_error([{"accountId": "1", "roleName": "r"}]).content[0]["text"])
    assert role_err["error"]["type"] == "RoleSelectionRequired"

    idc_err = json.loads(_identity_center_error("boom").content[0]["text"])
    assert idc_err["error"]["type"] == "IdentityCenterError"


@pytest.mark.asyncio
async def test_resolve_identity_center_role_selection_branches():
    from aws_cli_mcp.aws_credentials.identity_center import IdentityCenterError
    from aws_cli_mcp.tools.aws_unified import _resolve_identity_center_role_selection

    ctx = MagicMock()
    ctx.settings.server.transport_mode = "http"

    no_ctx = await _resolve_identity_center_role_selection(ctx, {})
    assert "IdentityCenterAuthMissing" in no_ctx.content[0]["text"]

    token = set_request_context(RequestContext(user_id="u", issuer="iss", access_token="atk"))
    try:
        invalid = await _resolve_identity_center_role_selection(ctx, {"accountId": "123"})
        assert "RoleSelectionInvalid" in invalid.content[0]["text"]

        provider = MagicMock()
        provider.list_account_roles = AsyncMock(
            side_effect=IdentityCenterError("unexpected", "sso_error")
        )
        provider.list_accounts = AsyncMock(return_value=[])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            err = await _resolve_identity_center_role_selection(
                ctx,
                {"accountId": "123456789012", "roleName": "Admin"},
            )
        assert "IdentityCenterError" in err.content[0]["text"]

        provider = MagicMock()
        provider.list_account_roles = AsyncMock(return_value=[])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            not_assigned = await _resolve_identity_center_role_selection(
                ctx,
                {"accountId": "123456789012", "roleName": "Admin"},
            )
            assert "RoleNotAssigned" in not_assigned.content[0]["text"]

        role = MagicMock(account_id="123456789012", role_name="Admin")
        provider = MagicMock()
        provider.list_account_roles = AsyncMock(return_value=[role])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            ok = await _resolve_identity_center_role_selection(
                ctx,
                {"accountId": "123456789012", "roleName": "Admin"},
            )
            assert ok == ("123456789012", "Admin")

        provider = MagicMock()
        provider.list_accounts = AsyncMock(side_effect=IdentityCenterError("boom", "sso_error"))
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            failed_accounts = await _resolve_identity_center_role_selection(ctx, {})
            assert "IdentityCenterError" in failed_accounts.content[0]["text"]

        account = MagicMock(account_id="123", account_name="acct")
        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[account])
        provider.list_account_roles = AsyncMock(return_value=[])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            none_roles = await _resolve_identity_center_role_selection(ctx, {})
            assert "NoRolesAvailable" in none_roles.content[0]["text"]

        role = MagicMock(account_id="123", role_name="ReadOnly")
        provider.list_account_roles = AsyncMock(return_value=[role])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            single = await _resolve_identity_center_role_selection(ctx, {})
            assert single == ("123", "ReadOnly")

        role2 = MagicMock(account_id="123", role_name="Admin")
        provider.list_account_roles = AsyncMock(return_value=[role, role2])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            multi = await _resolve_identity_center_role_selection(ctx, {})
            assert "RoleSelectionRequired" in multi.content[0]["text"]

        # roleArn parse path (lines 754-756)
        provider = MagicMock()
        provider.list_account_roles = AsyncMock(
            return_value=[MagicMock(account_id="123456789012", role_name="ParsedRole")]
        )
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            parsed = await _resolve_identity_center_role_selection(
                ctx,
                {"roleArn": "arn:aws:iam::123456789012:role/ParsedRole"},
            )
            assert parsed == ("123456789012", "ParsedRole")

        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[])
        provider.list_account_roles = AsyncMock(return_value=[])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider), \
             patch("aws_cli_mcp.tools.aws_unified.asyncio.gather", side_effect=Exception("gather failed")):
            gather_err = await _resolve_identity_center_role_selection(ctx, {})
            assert "IdentityCenterError" in gather_err.content[0]["text"]

        account = MagicMock(account_id="123", account_name="acct")
        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[account])
        provider.list_account_roles = AsyncMock(
            side_effect=IdentityCenterError("bad", "sso_error")
        )
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            idc_result_err = await _resolve_identity_center_role_selection(ctx, {})
            assert "IdentityCenterError" in idc_result_err.content[0]["text"]

        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[account])
        provider.list_account_roles = AsyncMock(side_effect=RuntimeError("oops"))
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            generic_result_err = await _resolve_identity_center_role_selection(ctx, {})
            assert "Unexpected error fetching roles" in generic_result_err.content[0]["text"]

        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[])
        provider.list_account_roles = AsyncMock(return_value=[])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider), \
             patch(
                 "aws_cli_mcp.tools.aws_unified.asyncio.gather",
                 new=AsyncMock(return_value=[("bad", "not-a-list")]),
             ):
            bad_result_type = await _resolve_identity_center_role_selection(ctx, {})
            assert "Unexpected role selection result type" in bad_result_type.content[0]["text"]

        invalid_role = MagicMock(account_id=123, role_name=None)
        provider = MagicMock()
        provider.list_accounts = AsyncMock(return_value=[account])
        provider.list_account_roles = AsyncMock(return_value=[invalid_role])
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            filtered_roles = await _resolve_identity_center_role_selection(ctx, {})
            assert "NoRolesAvailable" in filtered_roles.content[0]["text"]
    finally:
        reset_request_context(token)


@pytest.mark.asyncio
async def test_ensure_identity_center_credentials_branches():
    from datetime import datetime, timezone

    from aws_cli_mcp.aws_credentials.identity_center import IdentityCenterError
    from aws_cli_mcp.tools.aws_unified import _ensure_identity_center_credentials

    ctx = MagicMock()
    no_ctx = await _ensure_identity_center_credentials(ctx, "123", "Role")
    assert "IdentityCenterAuthMissing" in no_ctx.content[0]["text"]

    token = set_request_context(RequestContext(user_id="u", issuer="iss", access_token="atk"))
    try:
        provider = MagicMock()
        provider.get_cached_role_credentials = AsyncMock(
            side_effect=IdentityCenterError("bad creds", "sso_error")
        )
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            err = await _ensure_identity_center_credentials(ctx, "123", "Role")
            assert "IdentityCenterError" in err.content[0]["text"]

        temp = MagicMock()
        temp.access_key_id = "ak"
        temp.secret_access_key = "sk"
        temp.session_token = "st"
        temp.expiration = datetime.now(timezone.utc)
        provider.get_cached_role_credentials = AsyncMock(return_value=temp)
        with patch("aws_cli_mcp.tools.aws_unified.get_identity_center_provider", return_value=provider):
            ok = await _ensure_identity_center_credentials(ctx, "123456789012", "Role")
            assert ok is None
            req = get_request_context_optional()
            assert req is not None and req.aws_credentials is not None
    finally:
        reset_request_context(token)


@pytest.mark.asyncio
async def test_call_boto3_and_parse_option_helpers():
    from aws_cli_mcp.tools.aws_unified import (
        _call_boto3,
        _compact_payload,
        _compact_summary_value,
        _parse_max_result_items,
        _parse_omit_response_fields,
        _parse_response_mode,
    )

    assert _parse_response_mode({"responseMode": 1}) == "auto"
    assert _parse_response_mode({"responseMode": "INVALID"}) == "auto"
    assert _parse_max_result_items({"maxResultItems": True}) is None
    assert _parse_max_result_items({"maxResultItems": "x"}) is None
    assert _parse_max_result_items({"maxResultItems": "999"}) == 200
    assert _parse_omit_response_fields({"omitResponseFields": "x"}) == set()
    assert _parse_omit_response_fields({"omitResponseFields": [1, "ok", " " * 2, "x" * 65]}) == {"ok"}

    assert _compact_summary_value([1, 2], 10)["_mcp_compacted_type"] == "list"
    assert _compact_summary_value({"a": 1}, 10)["_mcp_compacted_type"] == "object"
    assert _compact_payload(123, max_depth=1, max_list_items=1, max_string_chars=1, drop_fields=set()) == 123

    client = MagicMock()
    client.list_buckets = MagicMock(return_value={"Buckets": []})
    with patch("aws_cli_mcp.tools.aws_unified.get_client_async", AsyncMock(return_value=client)), \
         patch("aws_cli_mcp.tools.aws_unified.call_aws_api_async", AsyncMock(return_value={"Buckets": []})):
        out = await _call_boto3("s3", "ListBuckets", {}, "us-east-1", 100)
        assert out == {"Buckets": []}
    with patch("aws_cli_mcp.tools.aws_unified.get_client_async", AsyncMock(return_value=object())):
        with pytest.raises(AttributeError):
            await _call_boto3("s3", "NoSuchMethod", {}, "us-east-1", 100)


def test_limit_result_payload_additional_paths():
    payload = {"items": [{"k": "v", "nested": {"x": "y"}} for _ in range(500)]}

    limited = _limit_result_payload(
        payload,
        max_chars=300,
        service="s3",
        operation="ListObjects",
        options={"responseMode": "compact", "maxResultItems": 1},
    )
    assert limited["truncated"] is True

    fallback = _limit_result_payload(
        {"x": "a" * 20000},
        max_chars=50,
        service="s3",
        operation="ListObjects",
        options={"responseMode": "compact"},
    )
    assert fallback["truncated"] is True
    assert fallback["strategy"] == "preview"


def test_coercion_additional_paths():
    from aws_cli_mcp.smithy.parser import ListShape, MapShape, OperationShape
    from aws_cli_mcp.tools.aws_unified import _coerce_list, _coerce_map, _compact_summary_value

    model = MagicMock(spec=SmithyModel)
    struct = StructureShape("S", "structure", {}, {"i": Member("int", {})})
    op = OperationShape("Op", "operation", {}, input="S", output=None, documentation=None, examples=None)
    int_shape = Shape("int", "integer", {})
    float_shape = Shape("flt", "float", {})
    bool_shape = Shape("bool", "boolean", {})
    ts_shape = Shape("ts", "timestamp", {})
    blob_shape = Shape("blob", "blob", {})
    map_shape = MapShape("M", "map", {}, Member("str", {}), Member("int", {}))
    list_shape = ListShape("L", "list", {}, Member("int", {}))
    model.get_shape.side_effect = lambda sid: {
        "Op": op,
        "S": struct,
        "int": int_shape,
        "flt": float_shape,
        "bool": bool_shape,
        "ts": ts_shape,
        "blob": blob_shape,
        "M": map_shape,
        "L": list_shape,
        "str": StringShape("str", "string", {}),
    }.get(sid)

    coerced = _coerce_payload_types(model, "Op", {"i": "1"})
    assert coerced["i"] == 1

    with pytest.raises(ValueError):
        _coerce_integer([], "i", "integer")
    with pytest.raises(ValueError):
        _coerce_float(True, "f")
    with pytest.raises(ValueError):
        _coerce_float({}, "f")
    assert _coerce_boolean(True, "b") is True
    with pytest.raises(ValueError):
        _coerce_timestamp(10**20, "t")
    assert _coerce_timestamp("2024-01-01T00:00:00+09:00", "t").endswith("+09:00")

    # List branches
    list_shape.member.target = "blob"
    assert _coerce_list(model, list_shape, ["SGVsbG8="], "p") == [b"Hello"]
    list_shape.member.target = "int"
    assert _coerce_list(model, list_shape, ["1"], "p") == [1]
    list_shape.member.target = "flt"
    assert _coerce_list(model, list_shape, ["1.2"], "p") == [1.2]
    list_shape.member.target = "bool"
    assert _coerce_list(model, list_shape, ["true"], "p") == [True]
    list_shape.member.target = "ts"
    assert _coerce_list(model, list_shape, ["2024-01-01"], "p") == ["2024-01-01"]
    list_shape.member.target = "S"
    assert _coerce_list(model, list_shape, [{"i": "2"}], "p")[0]["i"] == 2
    assert _coerce_list(model, list_shape, ["raw"], "p")[0] == "raw"
    list_shape.member.target = "missing"
    assert _coerce_list(model, list_shape, [1], "p") == [1]

    # Map branches
    map_shape.value.target = "blob"
    assert _coerce_map(model, map_shape, {"a": "SGVsbG8="}, "p") == {"a": b"Hello"}
    map_shape.value.target = "int"
    assert _coerce_map(model, map_shape, {"a": "1"}, "p") == {"a": 1}
    map_shape.value.target = "flt"
    assert _coerce_map(model, map_shape, {"a": "1.5"}, "p") == {"a": 1.5}
    map_shape.value.target = "bool"
    assert _coerce_map(model, map_shape, {"a": "false"}, "p") == {"a": False}
    map_shape.value.target = "ts"
    assert _coerce_map(model, map_shape, {"a": "2024-01-01"}, "p") == {"a": "2024-01-01"}
    map_shape.value.target = "S"
    assert _coerce_map(model, map_shape, {"a": {"i": "3"}}, "p")["a"]["i"] == 3
    assert _coerce_map(model, map_shape, {"a": "raw"}, "p")["a"] == "raw"
    map_shape.value.target = "missing"
    assert _coerce_map(model, map_shape, {"a": 1}, "p") == {"a": 1}

    assert _compact_summary_value(123, 10) == 123

    # Nested structure/list/map branches in _coerce_payload_types (lines 1050/1056/1062)
    nested_struct = StructureShape("Nested", "structure", {}, {"x": Member("int", {})})
    root_struct = StructureShape(
        "Root",
        "structure",
        {},
        {
            "nested": Member("Nested", {}),
            "items": Member("L", {}),
            "attrs": Member("M", {}),
        },
    )
    model.get_shape.side_effect = lambda sid: {
        "Root": root_struct,
        "Nested": nested_struct,
        "L": ListShape("L", "list", {}, Member("int", {})),
        "M": MapShape("M", "map", {}, Member("str", {}), Member("int", {})),
        "int": int_shape,
        "str": StringShape("str", "string", {}),
    }.get(sid)
    nested_payload = {"nested": {"x": "1"}, "items": ["2", "3"], "attrs": {"a": "4"}}
    nested_out = _coerce_payload_types(model, "Root", nested_payload)
    assert nested_out["nested"]["x"] == 1
    assert nested_out["items"] == [2, 3]
    assert nested_out["attrs"] == {"a": 4}


@pytest.mark.asyncio
async def test_record_audit_log_request_context_override():
    from aws_cli_mcp.tools.aws_unified import _record_audit_log

    ctx = MagicMock()
    ctx.settings.server.transport_mode = "stdio"
    ctx.store.create_tx = MagicMock()
    ctx.store.create_op = MagicMock()
    ctx.store.add_audit_artifact = MagicMock()
    artifact = MagicMock()
    ctx.artifacts.write_json.return_value = artifact

    token = set_request_context(RequestContext(user_id="u1", issuer="iss", access_token="atk"))
    try:
        await _record_audit_log(
            ctx=ctx,
            tx_id="tx",
            op_id="op",
            service="s3",
            operation="ListBuckets",
            op_payload={},
            status="Started",
            region="us-east-1",
            is_new_tx=True,
            model=MagicMock(),
            operation_shape_id="op-shape",
            request_context={"accountId": "123456789012", "roleName": "ReadOnly"},
        )
    finally:
        reset_request_context(token)

    tx_arg = ctx.store.create_tx.call_args.args[0]
    assert tx_arg.account == "123456789012"
    assert tx_arg.role == "ReadOnly"


def test_parse_json_arg_additional_branches():
    from aws_cli_mcp.tools.aws_unified import _parse_json_arg

    non_object = _parse_json_arg('["x"]', "options")
    assert hasattr(non_object, "content")
    body = json.loads(non_object.content[0]["text"])
    assert body["error"]["type"] == "InvalidOptions"

    assert _parse_json_arg(123, "options") == {}


def test_coercion_depth_limit_branches():
    from aws_cli_mcp.smithy.parser import ListShape, MapShape
    from aws_cli_mcp.tools.aws_unified import _MAX_COERCE_DEPTH, _coerce_list, _coerce_map

    model = MagicMock(spec=SmithyModel)

    payload = {"value": "1"}
    assert _coerce_payload_types(model, "S", payload, depth=_MAX_COERCE_DEPTH) is payload
    model.get_shape.assert_not_called()

    list_shape = ListShape("L", "list", {}, Member("int", {}))
    list_payload = ["1"]
    assert _coerce_list(model, list_shape, list_payload, "path", depth=_MAX_COERCE_DEPTH) is list_payload

    map_shape = MapShape("M", "map", {}, Member("str", {}), Member("int", {}))
    map_payload = {"a": "1"}
    assert _coerce_map(model, map_shape, map_payload, "path", depth=_MAX_COERCE_DEPTH) is map_payload
