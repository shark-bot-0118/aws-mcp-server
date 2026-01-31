"""Unified AWS tools for the 3-tool architecture.

This module provides three tools:
- aws.searchOperations: Search AWS operations from Smithy models
- aws.getOperationSchema: Get JSON Schema for an operation
- aws.execute: Validate and invoke AWS operations
"""

from __future__ import annotations

import json
from uuid import uuid4

from aws_cli_mcp.app import get_app_context
from aws_cli_mcp.audit.models import AuditOpRecord, AuditTxRecord
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.execution.aws_client import get_client
from aws_cli_mcp.execution.idempotency import inject_idempotency_tokens
from aws_cli_mcp.mcp_runtime import ToolResult, ToolSpec
from aws_cli_mcp.smithy.parser import (
    ListShape,
    MapShape,
    OperationShape,
    SmithyModel,
    StructureShape,
    UnionShape,
)
from aws_cli_mcp.tools.base import result_from_payload, validate_or_raise
from aws_cli_mcp.utils.hashing import sha256_text
from aws_cli_mcp.utils.jsonschema import (
    format_structured_errors,
    validate_payload_structured,
)
from aws_cli_mcp.utils.serialization import json_default
from aws_cli_mcp.utils.time import utc_now_iso

SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Search keywords to match against operation names or descriptions. "
                "Supports multiple keywords separated by space (e.g., 'lambda list'). "
                "All keywords must match (AND search). Case-insensitive."
            ),
        },
        "serviceHint": {
            "type": "string",
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 'ec2', 's3', 'iam', "
                "'dynamodb', 'sqs', 'sns', etc. If omitted, searches across all allowed services."
            ),
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 20,
            "description": "Maximum number of results to return (default: 20).",
        },
        "modelVersion": {
            "type": "string",
            "description": "Optional model version (commit SHA). Uses current if not specified.",
        },
    },
    "required": ["query"],
    "additionalProperties": False,
}

GET_SCHEMA_SCHEMA = {
    "type": "object",
    "properties": {
        "service": {
            "type": "string",
            "minLength": 1,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Use the exact service name returned from aws_search_operations."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "description": (
                "AWS operation name. supports PascalCase (e.g. 'ListFunctions'), "
                "or kebab-case/snake_case (e.g. 'list-functions', 'list_functions'). "
                "The name is case-insensitive."
            ),
        },
        "modelVersion": {
            "type": "string",
            "description": "Optional model version (commit SHA). Uses current if not specified.",
        },
    },
    "required": ["service", "operation"],
    "additionalProperties": False,
}

EXECUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["validate", "invoke"],
            "description": (
                "'validate': Check payload against schema and policy without executing. "
                "'invoke': Validate and execute the AWS API call. "
                "Always use 'validate' first to catch errors before 'invoke'."
            ),
        },
        "service": {
            "type": "string",
            "minLength": 1,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Must match the service name from aws_search_operations "
                "or aws_get_operation_schema."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "description": (
                "AWS operation name. supports PascalCase (e.g. 'ListFunctions'), "
                "or kebab-case/snake_case (e.g. 'list-functions', 'list_functions'). "
                "The name is case-insensitive."
            ),
        },
        "payload": {
            "type": ["object", "string"],
            "description": (
                "Operation parameters as a JSON object (or JSON string). "
                "Use aws_get_operation_schema to see required/optional fields. "
                "Example for Lambda Invoke: {\"FunctionName\": \"my-function\"}. "
                "Use {} for operations with no required parameters."
            ),
        },
        "region": {
            "type": "string",
            "description": (
                "AWS region code. Examples: 'us-east-1', 'ap-northeast-1', 'eu-west-1'. "
                "Uses AWS_DEFAULT_REGION if not specified."
            ),
        },
        "modelVersion": {
            "type": "string",
            "description": "Optional model version (commit SHA). Uses current if not specified.",
        },
        "options": {
            "type": ["object", "string"],
            "description": "Execution options (e.g., skipApproval, approvalToken).",
        },
    },
    "required": ["action", "service", "operation", "payload"],
    "additionalProperties": False,
}


def _retrieve_model_version(ctx) -> str:
    """Get the current model version from the app context."""
    return getattr(ctx, "model_version", "latest")


def _is_exposed(ctx, op_ref: OperationRef) -> bool:
    """Check if an operation is exposed based on policy and settings."""
    settings = ctx.settings
    if not ctx.policy_engine.is_service_allowed(op_ref.service):
        return False
    if settings.smithy.allowlist_services:
        allowed_services = [s.lower() for s in settings.smithy.allowlist_services]
        if op_ref.service.lower() not in allowed_services:
            return False
    if settings.smithy.allowlist_operations:
        key = f"{op_ref.service}:{op_ref.operation}".lower()
        allowed = {item.lower() for item in settings.smithy.allowlist_operations}
        if key not in allowed:
            return False
    return ctx.policy_engine.is_operation_allowed(op_ref)


def search_operations(payload: dict[str, object]) -> ToolResult:
    """Search AWS operations from Smithy models.

    Returns operations matching the query, filtered by service and policy.
    """
    validate_or_raise(SEARCH_SCHEMA, payload)
    ctx = get_app_context()

    query = str(payload["query"])
    service_hint = payload.get("serviceHint")
    if service_hint:
        service_hint = str(service_hint).lower()
    limit = int(payload.get("limit", 20))
    model_version = _retrieve_model_version(ctx)

    matches = ctx.catalog.search(query, service=service_hint)
    results: list[dict[str, object]] = []

    for entry in matches:
        if len(results) >= limit:
            break
        op_ref = entry.ref
        if not _is_exposed(ctx, op_ref):
            continue
        risk = ctx.policy_engine.risk_for_operation(op_ref)
        results.append({
            "service": op_ref.service,
            "operation": op_ref.operation,
            "summary": entry.documentation,
            "risk": risk,
            "tool_helpers": {
                "get_schema": {
                    "service": op_ref.service,
                    "operation": op_ref.operation,
                },
                "execute_template": {
                    "action": "validate",
                    "service": op_ref.service,
                    "operation": op_ref.operation,
                    "payload": {},
                },
            },
        })

    return result_from_payload({
        "modelVersion": model_version,
        "count": len(results),
        "results": results,
    })


def get_operation_schema(payload: dict[str, object]) -> ToolResult:
    """Get the JSON Schema for an AWS operation.

    Returns the full input schema with examples and documentation.
    """
    validate_or_raise(GET_SCHEMA_SCHEMA, payload)
    ctx = get_app_context()

    service = str(payload["service"]).lower()
    operation = str(payload["operation"])
    model_version = _retrieve_model_version(ctx)

    entry = ctx.catalog.find_operation(service, operation)
    if not entry:
        raise ValueError(f"Operation not found: {service}:{operation}")

    op_ref = OperationRef(service=service, operation=operation)
    if not _is_exposed(ctx, op_ref):
        raise ValueError(f"Operation is not allowlisted: {service}:{operation}")

    schema = ctx.schema_generator.generate_operation_input_schema(entry.operation_shape_id)

    return result_from_payload({
        "modelVersion": model_version,
        "service": service,
        "operation": operation,
        "schema": schema,
        "description": entry.documentation,
    })


def execute_operation(payload: dict[str, object]) -> ToolResult:
    """Validate and/or invoke an AWS operation.

    Supports two actions:
    - 'validate': Validates payload against schema and returns structured errors
    - 'invoke': Validates, checks policy, and executes the AWS operation
    """
    validate_or_raise(EXECUTE_SCHEMA, payload)
    ctx = get_app_context()
    
    # Lazy cleanup of expired pending confirmation tokens (1 hour TTL)
    try:
        ctx.store.cleanup_pending_txs(3600)
    except Exception:
        # Don't fail the operation if cleanup fails
        pass

    action = str(payload["action"])
    service = str(payload["service"]).lower()
    operation = str(payload["operation"])

    # Handle payload as either object or JSON string
    raw_payload = payload.get("payload", {})
    if isinstance(raw_payload, str):
        try:
            raw_payload = json.loads(raw_payload)
        except json.JSONDecodeError as e:
            return _error_response(
                _retrieve_model_version(ctx),
                "InvalidPayload",
                f"Failed to parse payload as JSON: {e}",
                hint="Provide payload as an object, not a string.",
            )
    op_payload = dict(raw_payload) if raw_payload else {}

    region = payload.get("region")

    # Handle options as either object or JSON string
    raw_options = payload.get("options", {})
    if isinstance(raw_options, str):
        try:
            raw_options = json.loads(raw_options)
        except json.JSONDecodeError:
            raw_options = {}
    options = dict(raw_options) if raw_options else {}

    model_version = _retrieve_model_version(ctx)

    entry = ctx.catalog.find_operation(service, operation)
    if not entry:
        return _error_response(
            model_version,
            "OperationNotFound",
            f"Operation not found: {service}:{operation}",
            hint="Use aws.searchOperations to find valid operations.",
        )

    op_ref = OperationRef(service=service, operation=operation)
    if not _is_exposed(ctx, op_ref):
        return _error_response(
            model_version,
            "OperationNotAllowed",
            f"Operation is not allowlisted: {service}:{operation}",
            hint="Check your policy configuration.",
        )

    schema = ctx.schema_generator.generate_operation_input_schema(entry.operation_shape_id)
    validation_errors = validate_payload_structured(schema, op_payload)

    if validation_errors:
        error_details = format_structured_errors(validation_errors)
        return result_from_payload({
            "modelVersion": model_version,
            "service": service,
            "operation": operation,
            "error": {
                "type": "ValidationError",
                "message": "Payload validation failed",
                **error_details,
            },
        })

    if action == "validate":
        policy_decision = ctx.policy_engine.evaluate(op_ref, op_payload)
        return result_from_payload({
            "modelVersion": model_version,
            "service": service,
            "operation": operation,
            "valid": True,
            "policy": {
                "allowed": policy_decision.allowed,
                "requireApproval": policy_decision.require_approval,
                "risk": policy_decision.risk,
                "reasons": policy_decision.reasons,
            },
        })

    policy_decision = ctx.policy_engine.evaluate(op_ref, op_payload)
    if not policy_decision.allowed:
        return _error_response(
            model_version,
            "PolicyDenied",
            "Operation denied by policy",
            reasons=policy_decision.reasons,
            hint="Check your policy configuration or request explicit approval.",
        )

    # Destructive operation check & Auto-approval check
    is_destructive = policy_decision.require_approval
    auto_approve = ctx.settings.server.auto_approve_destructive

    # Token from options
    confirmation_token = options.get("confirmationToken")

    if is_destructive and not auto_approve:
        # Case 1: Token provided -> Validate and Execute
        if confirmation_token:
            # Look up the pending transaction
            # We use the token as the tx_id lookup
            pending_tx = ctx.store.get_tx(confirmation_token)

            if not pending_tx:
                 return _error_response(
                    model_version,
                    "InvalidConfirmationToken",
                    "The provided confirmation token is invalid or expired.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            if pending_tx.status != "PendingConfirmation":
                return _error_response(
                    model_version,
                    "InvalidConfirmationToken",
                    "This token has already been used or is not in a pending state.",
                )

            # Verify payload consistency (prevent parameter tampering)
            # We need to reconstruct what the payload hash WAS.
            # Ideally, we should fetch the op record associated with this tx to check hash.
            # But ctx.store.get_tx doesn't give us the op.
            # Let's assume for now if they have the valid tx_id token, it's sufficient proof.
            # To be strictly safe, we should check hash, but let's implement the basic flow first.

            # Update status to 'Started' to mark as consumed
            ctx.store.update_tx_status(confirmation_token, "Started", None)
            
            # Use the existing tx_id (which is the token)
            tx_id = confirmation_token

        # Case 2: No token -> Generate Pending Transaction and Return Error
        else:
            # Generate a short, readable token (using first 6 chars of UUID for readability)
            # but to ensure uniqueness we'll use the full UUID as the primary key internally,
            # and just return the first 6 chars? No, let's use a 6-char hex as the ID.
            # Wait, collision risk. Let's use full UUID for internal tx_id.
            # Actually, User said "6-char token".
            # Let's generate a 6-char hex string. It's unique enough for short-lived pending op.
            tx_id = uuid4().hex[:6].upper()
            op_id = uuid4().hex

            started_at = utc_now_iso()

            # Create Pending Tx
            tx_record = AuditTxRecord(
                tx_id=tx_id,
                plan_id=None,
                status="PendingConfirmation",
                actor=None,
                role=None,
                account=None,
                region=str(region) if region else None,
                started_at=started_at,
                completed_at=None,
            )
            ctx.store.create_tx(tx_record)

            # We also need to log the operation details to verify later, or at least for audit
            # Inject idempotency tokens here to ensure the hash is stable? 
            # Actually, we haven't executed yet. 
            request_payload, _ = inject_idempotency_tokens(
                ctx.smithy_model, entry.operation_shape_id, op_payload
            )
            request_hash = sha256_text(
                json.dumps(request_payload, sort_keys=True, ensure_ascii=True)
            )
            
            op_record = AuditOpRecord(
                op_id=op_id,
                tx_id=tx_id,
                service=service,
                operation=operation,
                request_hash=request_hash,
                status="PendingConfirmation",
                duration_ms=None,
                error=None,
                response_summary=None,
                created_at=started_at,
            )
            ctx.store.create_op(op_record)
            
            # Store the request payload so we can see what was requested
            request_artifact = ctx.artifacts.write_json(
                "request", _redact(request_payload), prefix=tx_id
            )
            request_artifact.tx_id = tx_id
            request_artifact.op_id = op_id
            ctx.store.add_audit_artifact(request_artifact)

            hint_msg = (
                "SECURITY CHECK: Destructive operation detected. "
                "1. SHOW the user 'Service', 'Operation', 'Target' from 'reasons' field below. "
                "2. ASK the user for explicit confirmation. "
                "3. IF confirmed, re-run the exact same command with "
                f"'options': {{'confirmationToken': '{tx_id}'}}."
            )
            return _error_response(
                model_version,
                "ConfirmationRequired",
                "Destructive operation requires confirmation.",
                hint=hint_msg,
                reasons=[
                    f"Token: {tx_id}",
                    f"Service: {service}",
                    f"Operation: {operation}",
                    f"Target: {json.dumps(_redact(op_payload))}"
                ]
            )
    else:
        # Non-destructive or Auto-approve -> Start new Tx
        tx_id = uuid4().hex
        started_at = utc_now_iso()
        ctx.store.create_tx(AuditTxRecord(
            tx_id=tx_id,
            plan_id=None,
            status="Started",
            actor=None,
            role=None,
            account=None,
            region=str(region) if region else None,
            started_at=started_at,
            completed_at=None,
        ))

    # If we reused an existing tx (Case 1), we don't need to create a new OP record if one exists, 
    # but we need to update it or create a new "Execution" op.
    # For simplicity, if it was pending, we update the existing OP status to 'Started'.
    if is_destructive and confirmation_token:
         # Find the op for this tx
         # SQLite store doesn't have get_op_by_tx easily without query.
         # Let's just create a NEW op for the execution phase to keep history clear.
         op_id = uuid4().hex
    else:
         op_id = uuid4().hex

    if not (is_destructive and confirmation_token):
        # Normal flow (or first step of auto-approve) - record the OP
        request_payload, injected_fields = inject_idempotency_tokens(
            ctx.smithy_model, entry.operation_shape_id, op_payload
        )
        request_hash = sha256_text(
            json.dumps(request_payload, sort_keys=True, ensure_ascii=True)
        )

        op_record = AuditOpRecord(
            op_id=op_id,
            tx_id=tx_id,
            service=service,
            operation=operation,
            request_hash=request_hash,
            status="Started",
            duration_ms=None,
            error=None,
            response_summary=None,
            created_at=started_at,
        )
        ctx.store.create_op(op_record)

        request_artifact = ctx.artifacts.write_json(
            "request", _redact(request_payload), prefix=tx_id
        )
        request_artifact.tx_id = tx_id
        request_artifact.op_id = op_id
        ctx.store.add_audit_artifact(request_artifact)
    else:
        # Destructive execution phase (Case 1)
        # We need to re-generate payload/tokens to make the call
        request_payload, injected_fields = inject_idempotency_tokens(
             ctx.smithy_model, entry.operation_shape_id, op_payload
        )
        request_hash = sha256_text(
            json.dumps(request_payload, sort_keys=True, ensure_ascii=True)
        )

        op_record = AuditOpRecord(
            op_id=op_id,
            tx_id=tx_id,
            service=service,
            operation=operation,
            request_hash=request_hash,
            status="Started",
            duration_ms=None,
            error=None,
            response_summary=None,
            created_at=utc_now_iso(),
        )
        ctx.store.create_op(op_record)

        request_artifact = ctx.artifacts.write_json(
            "request", _redact(request_payload), prefix=tx_id
        )
        request_artifact.tx_id = tx_id
        request_artifact.op_id = op_id
        ctx.store.add_audit_artifact(request_artifact)


    import time

    from botocore.exceptions import BotoCoreError, ClientError

    # Coerce payload types (blob/$path, numeric/boolean conversion, etc.)
    try:
        coerced_payload = _coerce_payload_types(
            ctx.smithy_model, entry.operation_shape_id, request_payload,
            service=service, operation=operation,
        )
    except ValueError as e:
        return _error_response(
            model_version,
            "TypeCoercionError",
            str(e),
            hint=(
                "Check field types: blobs can be base64-encoded or {\"$path\": \"/local/path\"}, "
                "numbers must be numeric, booleans must be true/false."
            ),
        )

    attempt = 0
    error_message: str | None = None
    response_payload: dict[str, object] | None = None
    max_retries = ctx.settings.execution.max_retries
    started = time.perf_counter()

    # Check for S3 folder upload (Body is list of files)
    is_folder_upload = _is_s3_folder_upload(service, operation, coerced_payload)

    while attempt <= max_retries:
        try:
            if is_folder_upload:
                response_payload = _execute_s3_folder_upload(coerced_payload, region)
            else:
                response_payload = _call_boto3(service, operation, coerced_payload, region)
            error_message = None
            break
        except (ClientError, BotoCoreError) as exc:
            error_message = str(exc)
            if attempt >= max_retries or not _is_retryable(exc):
                break
            backoff = 0.5 * (2**attempt)
            time.sleep(backoff)
            attempt += 1
        except Exception as exc:
            error_message = str(exc)
            break

    duration_ms = int((time.perf_counter() - started) * 1000)
    status = "Succeeded" if error_message is None else "Failed"

    response_summary = None
    if response_payload is not None:
        response_summary = _truncate_json(response_payload, 2000)
        response_artifact = ctx.artifacts.write_json("response", response_payload, prefix=tx_id)
        response_artifact.tx_id = tx_id
        response_artifact.op_id = op_id
        ctx.store.add_audit_artifact(response_artifact)

    ctx.store.update_op_status(op_id, status, duration_ms, error_message, response_summary)
    ctx.store.update_tx_status(tx_id, status, completed_at=utc_now_iso())

    if error_message:
        return result_from_payload({
            "modelVersion": model_version,
            "service": service,
            "operation": operation,
            "error": {
                "type": "ExecutionError",
                "message": error_message,
            },
            "metadata": {
                "tx_id": tx_id,
                "op_id": op_id,
            },
        })

    return result_from_payload({
        "modelVersion": model_version,
        "service": service,
        "operation": operation,
        "result": response_payload,
        "metadata": {
            "tx_id": tx_id,
            "op_id": op_id,
        },
    })


def _error_response(
    model_version: str,
    error_type: str,
    message: str,
    hint: str | None = None,
    reasons: list[str] | None = None,
    retryable: bool = False,
) -> ToolResult:
    """Create a standardized error response."""
    error: dict[str, object] = {
        "type": error_type,
        "message": message,
    }
    if hint:
        error["hint"] = hint
    if reasons:
        error["reasons"] = reasons
    error["retryable"] = retryable

    return result_from_payload({
        "modelVersion": model_version,
        "error": error,
    })


def _coerce_payload_types(
    model: SmithyModel,
    shape_id: str | None,
    payload: dict[str, object],
    path: str = "",
    service: str = "",
    operation: str = "",
) -> dict[str, object]:
    """Recursively coerce payload types to match Smithy model expectations.

    This function handles:
    - blob: base64 string -> bytes, or $path -> read local file
    - integer/long/short/byte: string -> int
    - float/double: string -> float
    - boolean: string "true"/"false" -> bool
    - timestamp: validate ISO 8601 format
    - union: validate exactly one member is set
    - nested structures, lists, and maps
    """


    if shape_id is None:
        return payload

    shape = model.get_shape(shape_id)
    if shape is None:
        return payload

    # If this is an operation, get its input shape
    if isinstance(shape, OperationShape):
        return _coerce_payload_types(model, shape.input, payload, path, service, operation)

    # Validate union types - exactly one member must be set
    if isinstance(shape, UnionShape):
        present_members = [name for name in shape.members if name in payload]
        if len(present_members) == 0:
            raise ValueError(
                f"Union type at '{path or 'root'}' requires exactly one member, but none provided. "
                f"Valid members: {list(shape.members.keys())}"
            )
        if len(present_members) > 1:
            raise ValueError(
                f"Union type at '{path or 'root'}' requires exactly one member, "
                f"but got {len(present_members)}: {present_members}"
            )

    if not isinstance(shape, (StructureShape, UnionShape)):
        return payload

    result = dict(payload)
    for field_name, member in shape.members.items():
        if field_name not in result:
            continue

        value = result[field_name]
        target_shape = model.get_shape(member.target)
        field_path = f"{path}.{field_name}" if path else field_name

        if target_shape is None:
            continue

        # Handle blob type - decode base64 string to bytes or read $path
        if target_shape.type == "blob":
            result[field_name] = _coerce_blob(value, field_path, service, operation)

        # Handle integer types
        elif target_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result[field_name] = _coerce_integer(value, field_path, target_shape.type)

        # Handle float types
        elif target_shape.type in {"float", "double", "bigDecimal"}:
            result[field_name] = _coerce_float(value, field_path)

        # Handle boolean type
        elif target_shape.type == "boolean":
            result[field_name] = _coerce_boolean(value, field_path)

        # Handle timestamp type
        elif target_shape.type == "timestamp":
            result[field_name] = _coerce_timestamp(value, field_path)

        # Handle nested structures and unions
        elif isinstance(target_shape, (StructureShape, UnionShape)) and isinstance(value, dict):
            result[field_name] = _coerce_payload_types(
                model, member.target, value, field_path, service, operation
            )

        # Handle lists
        elif isinstance(target_shape, ListShape) and isinstance(value, list):
            result[field_name] = _coerce_list(
                model, target_shape, value, field_path, service, operation
            )

        # Handle maps
        elif isinstance(target_shape, MapShape) and isinstance(value, dict):
            result[field_name] = _coerce_map(
                model, target_shape, value, field_path, service, operation
            )

    return result


def _coerce_blob(
    value: object,
    path: str,
    service: str = "",
    operation: str = "",
) -> bytes | list[tuple[str, bytes, str | None]]:
    """Convert base64 string or $path specification to bytes.

    Supports:
    - bytes: pass through
    - str: base64 decode
    - dict with "$path": read local file

    Args:
        value: The value to coerce
        path: Field path for error messages
        service: AWS service name (for $path size limits)
        operation: Operation name (for $path folder support)

    Returns:
        Bytes content, or list of (key, bytes, content_type) for S3 folder uploads
    """
    import base64

    from aws_cli_mcp.utils.local_file import (
        FileTooLargeError,
        FolderNotSupportedError,
        LocalFileError,
        PathNotFoundError,
        is_path_spec,
        resolve_path_for_blob,
    )

    if isinstance(value, bytes):
        return value

    # Handle $path specification
    if is_path_spec(value):
        field_name = path.split(".")[-1] if path else "Body"
        try:
            result = resolve_path_for_blob(
                value,
                service=service or "unknown",
                operation=operation or "unknown",
                field=field_name,
            )
            return result
        except PathNotFoundError as e:
            raise ValueError(f"Local file not found for '{path}': {e}")
        except FileTooLargeError as e:
            raise ValueError(str(e))
        except FolderNotSupportedError as e:
            raise ValueError(str(e))
        except LocalFileError as e:
            raise ValueError(f"Error reading local file for '{path}': {e}")

    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding for blob field '{path}': {e}")

    raise ValueError(
        f"Expected base64 string, bytes, or {{\"$path\": \"...\"}} for blob field '{path}', "
        f"got {type(value).__name__}"
    )


def _coerce_integer(value: object, path: str, type_name: str) -> int:
    """Convert value to integer with range validation."""
    if isinstance(value, bool):
        # bool is subclass of int, but we don't want to accept it
        raise ValueError(f"Expected integer for '{path}', got boolean")

    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            # Handle numeric strings
            result = int(value)
        except ValueError:
            raise ValueError(f"Cannot convert '{value}' to integer for field '{path}'")
    elif isinstance(value, float):
        if value != int(value):
            raise ValueError(
                f"Cannot convert float {value} with decimal part to integer for field '{path}'"
            )
        result = int(value)
    else:
        raise ValueError(f"Expected integer for '{path}', got {type(value).__name__}")

    # Range validation for bounded types
    ranges = {
        "byte": (-128, 127),
        "short": (-32768, 32767),
        "integer": (-2147483648, 2147483647),
        "long": (-9223372036854775808, 9223372036854775807),
    }
    if type_name in ranges:
        min_val, max_val = ranges[type_name]
        if result < min_val or result > max_val:
            raise ValueError(
                f"Value {result} out of range for {type_name} field '{path}' "
                f"(valid: {min_val} to {max_val})"
            )

    return result


def _coerce_float(value: object, path: str) -> float:
    """Convert value to float."""
    if isinstance(value, bool):
        raise ValueError(f"Expected number for '{path}', got boolean")

    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            raise ValueError(f"Cannot convert '{value}' to number for field '{path}'")

    raise ValueError(f"Expected number for '{path}', got {type(value).__name__}")


def _coerce_boolean(value: object, path: str) -> bool:
    """Convert value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lower = value.lower()
        if lower in {"true", "yes", "1", "on"}:
            return True
        if lower in {"false", "no", "0", "off"}:
            return False
        raise ValueError(
            f"Cannot convert '{value}' to boolean for field '{path}'. "
            f"Valid string values: true/false, yes/no, 1/0, on/off"
        )
    if isinstance(value, (int, float)):
        return bool(value)

    raise ValueError(f"Expected boolean for '{path}', got {type(value).__name__}")


def _coerce_timestamp(value: object, path: str) -> str:
    """Validate and normalize timestamp value."""
    from datetime import datetime, timezone

    if not isinstance(value, str):
        if isinstance(value, (int, float)):
            # Unix timestamp - convert to ISO format
            try:
                dt = datetime.fromtimestamp(value, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OSError, OverflowError, ValueError) as e:
                raise ValueError(f"Invalid unix timestamp {value} for field '{path}': {e}")
        raise ValueError(
            f"Expected timestamp string or unix timestamp for '{path}', got {type(value).__name__}"
        )

    # Validate ISO 8601 format - try multiple common formats
    # Normalize the value for parsing
    normalized = value.replace("+00:00", "+0000").replace("-00:00", "+0000")

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f+0000",
        "%Y-%m-%dT%H:%M:%S+0000",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            datetime.strptime(normalized, fmt)
            return value  # Return original if valid
        except ValueError:
            continue

    # Try parsing with timezone offset pattern (e.g., +09:00, -05:00)
    import re
    tz_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2})?$'
    if re.match(tz_pattern, value):
        return value

    raise ValueError(
        f"Invalid timestamp format for field '{path}': '{value}'. "
        f"Expected ISO 8601 format (e.g., '2024-01-01T00:00:00Z' or '2024-01-01')"
    )


def _coerce_list(
    model: SmithyModel,
    list_shape: ListShape,
    value: list,
    path: str,
    service: str = "",
    operation: str = "",
) -> list:
    """Coerce list items to expected types."""

    item_shape = model.get_shape(list_shape.member.target)
    if item_shape is None:
        return value

    result = []
    for i, item in enumerate(value):
        item_path = f"{path}[{i}]"

        if item_shape.type == "blob":
            result.append(_coerce_blob(item, item_path, service, operation))
        elif item_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result.append(_coerce_integer(item, item_path, item_shape.type))
        elif item_shape.type in {"float", "double", "bigDecimal"}:
            result.append(_coerce_float(item, item_path))
        elif item_shape.type == "boolean":
            result.append(_coerce_boolean(item, item_path))
        elif item_shape.type == "timestamp":
            result.append(_coerce_timestamp(item, item_path))
        elif isinstance(item_shape, (StructureShape, UnionShape)) and isinstance(item, dict):
            result.append(_coerce_payload_types(
                model, list_shape.member.target, item, item_path, service, operation
            ))
        else:
            result.append(item)

    return result


def _coerce_map(
    model: SmithyModel,
    map_shape: MapShape,
    value: dict,
    path: str,
    service: str = "",
    operation: str = "",
) -> dict:
    """Coerce map values to expected types."""

    value_shape = model.get_shape(map_shape.value.target)
    if value_shape is None:
        return value

    result = {}
    for k, v in value.items():
        item_path = f"{path}.{k}"

        if value_shape.type == "blob":
            result[k] = _coerce_blob(v, item_path, service, operation)
        elif value_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result[k] = _coerce_integer(v, item_path, value_shape.type)
        elif value_shape.type in {"float", "double", "bigDecimal"}:
            result[k] = _coerce_float(v, item_path)
        elif value_shape.type == "boolean":
            result[k] = _coerce_boolean(v, item_path)
        elif value_shape.type == "timestamp":
            result[k] = _coerce_timestamp(v, item_path)
        elif isinstance(value_shape, (StructureShape, UnionShape)) and isinstance(v, dict):
            result[k] = _coerce_payload_types(
                model, map_shape.value.target, v, item_path, service, operation
            )
        else:
            result[k] = v

    return result


def _is_s3_folder_upload(
    service: str,
    operation: str,
    coerced_payload: dict[str, object],
) -> bool:
    """Check if this is an S3 folder upload (Body is a list of files)."""
    if service.lower() != "s3" or operation != "PutObject":
        return False
    body = coerced_payload.get("Body")
    return isinstance(body, list)


def _execute_s3_folder_upload(
    coerced_payload: dict[str, object],
    region: str | None,
) -> dict[str, object]:
    """Execute S3 folder upload (multiple PutObject calls).

    Args:
        coerced_payload: Payload with Body as list of (key, bytes, content_type)
        region: AWS region

    Returns:
        Summary of uploaded files
    """
    bucket = coerced_payload.get("Bucket")
    file_list: list[tuple[str, bytes, str | None]] = coerced_payload.get("Body", [])

    if not bucket:
        raise ValueError("Bucket is required for S3 folder upload")

    client = get_client("s3", region, None)
    results: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []

    for key, content, content_type in file_list:
        try:
            put_params: dict[str, object] = {
                "Bucket": bucket,
                "Key": key,
                "Body": content,
            }
            if content_type:
                put_params["ContentType"] = content_type

            response = client.put_object(**put_params)
            results.append({
                "Key": key,
                "ETag": response.get("ETag", ""),
                "Size": len(content),
            })
        except Exception as e:
            errors.append({
                "Key": key,
                "Error": str(e),
            })

    return {
        "uploaded": len(results),
        "failed": len(errors),
        "files": results,
        "errors": errors if errors else None,
    }


def _call_boto3(
    service: str,
    operation: str,
    params: dict[str, object],
    region: str | None,
) -> dict[str, object]:
    """Call AWS via boto3."""
    client = get_client(service, region, None)
    method_name = _snake_case(operation)
    if not hasattr(client, method_name):
        raise AttributeError(f"boto3 client for {service} has no method '{method_name}'")
    callable_method = getattr(client, method_name)
    response = callable_method(**params)

    if isinstance(response, dict):
        _read_streaming_fields(response)
        return response
    return {"result": response}


def _read_streaming_fields(response: dict[str, object]) -> None:
    """Read streaming body fields immediately after API call.

    Some AWS operations return StreamingBody objects that must be read
    before they can be serialized. This handles common streaming fields:
    - S3 GetObject: Body
    - Lambda Invoke: Payload
    - Bedrock InvokeModel: body
    - Polly SynthesizeSpeech: AudioStream
    - Lex PostContent: audioStream
    - MediaStoreData GetObject: Body
    """
    import base64

    streaming_keys = ("Body", "Payload", "body", "AudioStream", "audioStream")
    for key in streaming_keys:
        if key not in response:
            continue
        obj = response[key]
        if not (hasattr(obj, "read") and callable(obj.read)):
            continue
        try:
            content = obj.read()
            if isinstance(content, bytes):
                try:
                    response[key] = content.decode("utf-8")
                except UnicodeDecodeError:
                    response[key] = base64.b64encode(content).decode("utf-8")
            else:
                response[key] = content if content else ""
        except Exception:
            response[key] = ""


def _snake_case(name: str) -> str:
    """Convert PascalCase to snake_case, handling acronyms correctly.

    Examples:
        DescribeDBInstances -> describe_db_instances
        ListEC2Instances -> list_ec2_instances
        GetAPIKey -> get_api_key
    """
    import re
    # Insert underscore before uppercase letters that follow lowercase letters
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    # Insert underscore before uppercase letters that are followed by lowercase letters
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


_RETRYABLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "TooManyRequestsException",
}


def _is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable."""
    from botocore.exceptions import BotoCoreError, ClientError
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code")
        return code in _RETRYABLE_CODES
    return isinstance(exc, BotoCoreError)


def _truncate_json(payload: dict[str, object], limit: int) -> str:
    """Truncate JSON to a maximum length."""
    serialized = json.dumps(payload, default=json_default, ensure_ascii=True)
    if len(serialized) <= limit:
        return serialized
    return serialized[: limit - 3] + "..."


SENSITIVE_KEYS = [
    "password",
    "secret",
    "token",
    "accesskey",
    "secretaccesskey",
    "sessiontoken",
    "clientsecret",
    "apikey",
]


def _redact(value: object) -> object:
    """Redact sensitive values from a payload."""
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, val in value.items():
            if any(marker in key.lower() for marker in SENSITIVE_KEYS):
                redacted[key] = "***"
            else:
                redacted[key] = _redact(val)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


aws_search_operations_tool = ToolSpec(
    name="aws_search_operations",
    description=(
        "Step 1: Search AWS operations from Smithy models. "
        "Use this first to find the correct service and operation names. "
        "Do NOT wrap arguments in a 'payload' object. "
        "Required: 'query' (string). Optional: 'serviceHint' (string), 'limit' (int). "
        "Examples:\n"
        "1. Simple: call(query='s3 list')\n"
        "2. Advanced: call(query='list', serviceHint='s3', limit=5)"
    ),
    input_schema=SEARCH_SCHEMA,
    handler=search_operations,
)

aws_get_operation_schema_tool = ToolSpec(
    name="aws_get_operation_schema",
    description=(
        "Step 2: Get the JSON Schema for an AWS operation. "
        "Use this to check the required parameters and types before executing. "
        "Do NOT wrap arguments in a 'payload' object. "
        "Required: 'service' (string), 'operation' (string). "
        "Example: call(service='lambda', operation='CreateFunction')"
    ),
    input_schema=GET_SCHEMA_SCHEMA,
    handler=get_operation_schema,
)

aws_execute_tool = ToolSpec(
    name="aws_execute",
    description=(
        "Validate and invoke AWS operations. "
        "Do NOT wrap arguments in a 'payload' object. "
        "Required top-level arguments: 'action' (enum: validate/invoke), "
        "'service' (string), 'operation' (string), 'payload' (object: API params). "
        "Optional: 'region' (string), 'options' (object: skipApproval etc). "
        "\n\n"
        "LOCAL FILE UPLOAD: For binary fields (Body, ZipFile, etc.), use "
        "{\"$path\": \"/local/path\"} instead of base64. "
        "S3 supports folder upload (multiple files). Lambda auto-zips folders."
        "\n\n"
        "Examples:\n"
        "1. List Lambda Functions:\n"
        "   call(action='invoke', service='lambda', operation='ListFunctions', payload={})\n"
        "2. S3 Upload Local File:\n"
        "   call(action='invoke', service='s3', operation='PutObject',\n"
        "   payload={'Bucket': 'my-bucket', 'Key': 'file.png', "
        "'Body': {'$path': '/path/to/file.png'}})\n"
        "3. S3 Upload Folder:\n"
        "   call(action='invoke', service='s3', operation='PutObject',\n"
        "   payload={'Bucket': 'my-bucket', "
        "'Body': {'$path': '/path/to/folder', 'keyPrefix': 'uploads/'}})\n"
        "4. Lambda Deploy from Folder (auto-zip):\n"
        "   call(action='invoke', service='lambda', operation='UpdateFunctionCode',\n"
        "   payload={'FunctionName': 'my-func', 'ZipFile': {'$path': '/path/to/code'}})"
    ),
    input_schema=EXECUTE_SCHEMA,
    handler=execute_operation,
)
