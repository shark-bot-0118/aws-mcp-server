"""
Unified AWS tools for the 3-tool architecture.

This module provides three tools:
- aws_search_operations: Search AWS operations from Smithy models
- aws_get_operation_schema: Get JSON Schema for an operation
- aws_execute: Validate and invoke AWS operations
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import ParamSpec, TypeVar
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from aws_cli_mcp.app import AppContext, get_app_context
from aws_cli_mcp.audit.models import AuditOpRecord, AuditTxRecord
from aws_cli_mcp.auth.context import (
    AWSCredentials,
    get_request_context_optional,
    update_request_context,
)
from aws_cli_mcp.aws_credentials.identity_center import (
    AccountEntry,
    IdentityCenterError,
    RoleEntry,
    get_identity_center_provider,
)
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.execution.aws_client import (
    RequestContextError,
    call_aws_api_async,
    get_client_async,
)
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
from aws_cli_mcp.smithy.version_manager import load_model_snapshot
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
            "maxLength": 256,
            "description": (
                "Search keywords to match against operation names or descriptions. "
                "Supports multiple keywords separated by space (e.g., 'lambda list'). "
                "All keywords must match (AND search). Case-insensitive."
            ),
        },
        "serviceHint": {
            "type": "string",
            "maxLength": 128,
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
            "maxLength": 128,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Use the exact service name returned from aws_search_operations."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": (
                "AWS operation name. supports PascalCase (e.g. 'ListFunctions'), "
                "or kebab-case/snake_case (e.g. 'list-functions', 'list_functions'). "
                "The name is case-insensitive."
            ),
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
            "maxLength": 128,
            "description": (
                "AWS service name in lowercase. Examples: 'lambda', 's3', 'ec2', 'iam'. "
                "Must match the service name from aws_search_operations "
                "or aws_get_operation_schema."
            ),
        },
        "operation": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
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
                'Example for Lambda Invoke: {"FunctionName": "my-function"}. '
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
        "options": {
            "type": ["object", "string"],
            "description": (
                "Execution options. For Identity Center, specify accountId + roleName "
                "(or roleArn) to select the role. Example: "
                "{'accountId': '123456789012', 'roleName': 'ReadOnly'}. "
                "Other options include confirmationToken for destructive operations. "
                "For large responses, responseMode ('auto'|'compact'|'full'), "
                "maxResultItems (int), and omitResponseFields (string array) are supported."
            ),
        },
    },
    "required": ["action", "service", "operation", "payload"],
    "additionalProperties": False,
}

P = ParamSpec("P")
T = TypeVar("T")


async def _run_blocking(
    ctx: AppContext,
    func: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    if ctx.settings.server.transport_mode in {"http", "remote"}:
        return await asyncio.to_thread(func, *args, **kwargs)
    return func(*args, **kwargs)


def _is_exposed(ctx: AppContext, op_ref: OperationRef) -> bool:
    """Check if an operation is exposed based on policy only."""
    if not ctx.policy_engine.is_service_allowed(op_ref.service):
        return False
    return ctx.policy_engine.is_operation_allowed(op_ref)


def search_operations(payload: dict[str, object]) -> ToolResult:
    """Search AWS operations from Smithy models.

    Returns operations matching the query, filtered by service and policy.
    """
    validate_or_raise(SEARCH_SCHEMA, payload)
    ctx = get_app_context()

    query = str(payload["query"])
    raw_service_hint = payload.get("serviceHint")
    service_hint: str | None = None
    if isinstance(raw_service_hint, str) and raw_service_hint.strip():
        service_hint = raw_service_hint.lower()
    raw_limit = payload.get("limit", 20)
    if isinstance(raw_limit, bool):
        limit = 20
    elif isinstance(raw_limit, (int, str)):
        limit = int(raw_limit)
    else:
        limit = 20
    snapshot = load_model_snapshot()

    matches = snapshot.catalog.search(query, service=service_hint)
    results: list[dict[str, object]] = []

    for entry in matches:
        if len(results) >= limit:
            break
        op_ref = entry.ref
        if not _is_exposed(ctx, op_ref):
            continue
        risk = ctx.policy_engine.risk_for_operation(op_ref)
        results.append(
            {
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
            }
        )

    return result_from_payload({"count": len(results), "results": results})


def get_operation_schema(payload: dict[str, object]) -> ToolResult:
    """Get the JSON Schema for an AWS operation.

    Returns the full input schema with examples and documentation.
    """
    validate_or_raise(GET_SCHEMA_SCHEMA, payload)
    ctx = get_app_context()

    service = str(payload["service"]).lower()
    operation = str(payload["operation"])
    snapshot = load_model_snapshot()

    entry = snapshot.catalog.find_operation(service, operation)
    if not entry:
        raise ValueError(f"Operation not found: {service}:{operation}")
    service, operation = _resolve_catalog_operation(entry, service, operation)

    op_ref = OperationRef(service=service, operation=operation)
    if not _is_exposed(ctx, op_ref):
        raise ValueError(f"Operation is not allowlisted: {service}:{operation}")

    schema = snapshot.schema_generator.generate_operation_input_schema(entry.operation_shape_id)

    return result_from_payload(
        {
            "service": service,
            "operation": operation,
            "schema": schema,
            "description": entry.documentation,
        }
    )


async def execute_operation(payload: dict[str, object]) -> ToolResult:
    """Validate and/or invoke an AWS operation.

    Supports two actions:
    - 'validate': Validates payload against schema and returns structured errors
    - 'invoke': Validates, checks policy, and executes the AWS operation
    """
    validate_or_raise(EXECUTE_SCHEMA, payload)
    ctx = get_app_context()

    # Lazy cleanup of expired pending confirmation tokens (1 hour TTL)
    try:
        await _run_blocking(
            ctx,
            ctx.store.cleanup_pending_txs,
            ctx.policy_engine.approval_ttl_seconds,
        )
    except Exception:
        # Don't fail the operation if cleanup fails
        pass

    action = str(payload["action"])
    service = str(payload["service"]).lower()
    operation = str(payload["operation"])

    snapshot = load_model_snapshot()

    raw_payload = _parse_json_arg(payload.get("payload"), "payload")
    if isinstance(raw_payload, ToolResult):
        return raw_payload
    op_payload = dict(raw_payload) if raw_payload else {}

    raw_region = payload.get("region")
    region = raw_region if isinstance(raw_region, str) and raw_region.strip() else None

    raw_options = _parse_json_arg(payload.get("options"), "options")
    if isinstance(raw_options, ToolResult):
        return raw_options
    options = dict(raw_options) if raw_options else {}

    entry = snapshot.catalog.find_operation(service, operation)
    if not entry:
        return _error_response(
            "OperationNotFound",
            f"Operation not found: {service}:{operation}",
            hint="Use aws_search_operations to find valid operations.",
        )
    service, operation = _resolve_catalog_operation(entry, service, operation)

    op_ref = OperationRef(service=service, operation=operation)
    if not _is_exposed(ctx, op_ref):
        return _error_response(
            "OperationNotAllowed",
            f"Operation is not allowlisted: {service}:{operation}",
            hint="Check your policy configuration.",
        )

    schema = snapshot.schema_generator.generate_operation_input_schema(entry.operation_shape_id)
    validation_errors = validate_payload_structured(schema, op_payload)

    if validation_errors:
        error_details = format_structured_errors(validation_errors)
        return result_from_payload(
            {
                "service": service,
                "operation": operation,
                "error": {
                    "type": "ValidationError",
                    "message": "Payload validation failed",
                    **error_details,
                },
            }
        )

    if action == "validate":
        policy_decision = ctx.policy_engine.evaluate(op_ref, op_payload)
        return result_from_payload(
            {
                "service": service,
                "operation": operation,
                "valid": True,
                "policy": {
                    "allowed": policy_decision.allowed,
                    "requireApproval": policy_decision.require_approval,
                    "risk": policy_decision.risk,
                    "reasons": policy_decision.reasons,
                },
            }
        )

    policy_decision = ctx.policy_engine.evaluate(op_ref, op_payload)
    if not policy_decision.allowed:
        return _error_response(
            "PolicyDenied",
            "Operation denied by policy",
            reasons=policy_decision.reasons,
            hint="Check your policy configuration or request explicit approval.",
        )

    selected_account_id: str | None = None
    selected_role_name: str | None = None
    role_context: dict[str, object] | None = None

    if (
        action == "invoke"
        and _identity_center_enabled(ctx)
        and ctx.settings.server.transport_mode in {"http", "remote"}
    ):
        selection = await _resolve_identity_center_role_selection(ctx, options)
        if isinstance(selection, ToolResult):
            return selection
        selected_account_id, selected_role_name = selection
        role_context = {"accountId": selected_account_id, "roleName": selected_role_name}

    policy_requires_confirmation = (
        policy_decision.require_approval
        if isinstance(policy_decision.require_approval, bool)
        else False
    )
    server_require_approval = ctx.settings.server.require_approval
    global_requires_confirmation = (
        server_require_approval if isinstance(server_require_approval, bool) else False
    )
    destructive_flag = getattr(policy_decision, "require_approval_for_destructive", False)
    destructive_policy_requirement = (
        destructive_flag if isinstance(destructive_flag, bool) else False
    )
    risk_flag = getattr(policy_decision, "require_approval_for_risk", False)
    risk_policy_requirement = risk_flag if isinstance(risk_flag, bool) else False
    auto_approve_raw = ctx.settings.server.auto_approve_destructive
    auto_approve_destructive = auto_approve_raw if isinstance(auto_approve_raw, bool) else False
    requires_confirmation = global_requires_confirmation or policy_requires_confirmation
    destructive_auto_approved = (
        auto_approve_destructive
        and destructive_policy_requirement
        and not risk_policy_requirement
        and not global_requires_confirmation
    )

    # Token from options
    raw_confirmation_token = options.get("confirmationToken")
    confirmation_token = (
        raw_confirmation_token
        if isinstance(raw_confirmation_token, str) and raw_confirmation_token.strip()
        else None
    )

    if requires_confirmation and not destructive_auto_approved:
        # Case 1: Token provided -> Validate and Execute
        if confirmation_token:
            # Look up the pending transaction
            # We use the token as the tx_id lookup
            pending_tx = await _run_blocking(ctx, ctx.store.get_tx, confirmation_token)

            if not pending_tx:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The provided confirmation token is invalid or expired.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            if pending_tx.status != "PendingConfirmation":
                return _error_response(
                    "InvalidConfirmationToken",
                    "This token has already been used or is not in a pending state.",
                )

            current_actor = _actor_from_request_context()
            # In stdio mode both actors are None — allow the match.
            if current_actor is None and pending_tx.actor is not None:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The confirmation token does not belong to this authenticated user.",
                    hint="Please re-run the command without a token to get a new one.",
                )
            if current_actor is not None and pending_tx.actor != current_actor:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The confirmation token does not belong to this authenticated user.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            pending_op = await _run_blocking(ctx, ctx.store.get_pending_op, confirmation_token)

            if not pending_op:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The provided confirmation token is invalid or expired.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            if pending_op.service != service or pending_op.operation != operation:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The confirmation token does not match this operation.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            current_hash = _compute_request_hash(op_payload, role_context)
            if pending_op.request_hash != current_hash:
                return _error_response(
                    "InvalidConfirmationToken",
                    "The confirmation token does not match this request payload.",
                    hint="Please re-run the command without a token to get a new one.",
                )

            # Atomically claim the token (UPDATE … WHERE status='PendingConfirmation').
            # If another concurrent request already consumed this token, claim
            # returns False and we reject the duplicate.
            claimed = await _run_blocking(
                ctx,
                ctx.store.claim_pending_tx,
                confirmation_token,
            )
            if not claimed:
                return _error_response(
                    "InvalidConfirmationToken",
                    "This token has already been used or is not in a pending state.",
                )

            tx_id = confirmation_token
            op_id = uuid4().hex

            # Destructive execution phase
            await _record_audit_log(
                ctx,
                tx_id,
                op_id,
                service,
                operation,
                op_payload,
                status="Started",
                region=region,
                is_new_tx=False,
                model=snapshot.model,
                operation_shape_id=entry.operation_shape_id,
                request_context=role_context,
            )

        # Case 2: No token -> Generate Pending Transaction and Return Error
        else:
            tx_id = uuid4().hex.upper()
            op_id = uuid4().hex

            await _record_audit_log(
                ctx,
                tx_id,
                op_id,
                service,
                operation,
                op_payload,
                status="PendingConfirmation",
                region=region,
                is_new_tx=True,
                model=snapshot.model,
                operation_shape_id=entry.operation_shape_id,
                request_context=role_context,
            )

            approval_sources: list[str] = []
            if global_requires_confirmation:
                approval_sources.append("server")
            if destructive_policy_requirement:
                approval_sources.append("policy:destructive")
            if risk_policy_requirement:
                risk_name = (
                    policy_decision.risk if isinstance(policy_decision.risk, str) else "unknown"
                )
                approval_sources.append(f"policy:risk:{risk_name}")
            if not approval_sources and policy_requires_confirmation:
                approval_sources.append("policy")

            hint_msg = (
                "SECURITY CHECK: Confirmation required before execution. "
                "1. SHOW the user 'Service', 'Operation', 'Target' from 'reasons' field below. "
                "2. ASK the user for explicit confirmation. "
                "3. IF confirmed, re-run the exact same command with "
                f"'options': {{'confirmationToken': '{tx_id}'}}."
            )
            return _error_response(
                "ConfirmationRequired",
                "Operation requires confirmation.",
                hint=hint_msg,
                reasons=[
                    f"Token: {tx_id}",
                    f"ApprovalSource: {', '.join(approval_sources)}",
                    f"Service: {service}",
                    f"Operation: {operation}",
                    f"Target: {json.dumps(_redact(op_payload))}",
                    f"Role: {role_context}" if role_context else "Role: (not specified)",
                ],
            )
    else:
        # Confirmation not required or safely auto-approved -> Start new Tx
        tx_id = uuid4().hex
        op_id = uuid4().hex

        await _record_audit_log(
            ctx,
            tx_id,
            op_id,
            service,
            operation,
            op_payload,
            status="Started",
            region=region,
            is_new_tx=True,
            model=snapshot.model,
            operation_shape_id=entry.operation_shape_id,
            request_context=role_context,
        )

    if (
        action == "invoke"
        and _identity_center_enabled(ctx)
        and selected_account_id
        and selected_role_name
    ):
        cred_error = await _ensure_identity_center_credentials(
            ctx,
            selected_account_id,
            selected_role_name,
        )
        if isinstance(cred_error, ToolResult):
            await _run_blocking(
                ctx,
                ctx.store.update_op_status,
                op_id,
                "Failed",
                0,
                "Identity Center credential error",
                None,
            )
            await _run_blocking(
                ctx, ctx.store.update_tx_status, tx_id, "Failed", completed_at=utc_now_iso()
            )
            return cred_error

    # Inject idempotency tokens BEFORE type coercion
    # This ensures tokens are included in the actual AWS request
    payload_with_tokens, _ = inject_idempotency_tokens(
        snapshot.model, entry.operation_shape_id, op_payload
    )

    # Coerce payload types (blob base64, numeric/boolean conversion, etc.)
    try:
        coerced_payload = _coerce_payload_types(
            snapshot.model,
            entry.operation_shape_id,
            payload_with_tokens,
            service=service,
            operation=operation,
        )
    except ValueError as e:
        return _error_response(
            "TypeCoercionError",
            str(e),
            hint=(
                "Check field types: blobs must be base64-encoded, "
                "numbers must be numeric, booleans must be true/false."
            ),
        )

    attempt = 0
    error_message: str | None = None
    response_payload: dict[str, object] | None = None
    max_retries = ctx.settings.execution.max_retries
    started = time.perf_counter()

    while attempt <= max_retries:
        try:
            response_payload = await _call_boto3(
                service,
                operation,
                coerced_payload,
                region,
                ctx.settings.execution.max_output_characters,
            )
            error_message = None
            break
        except RequestContextError:
            raise
        except (ClientError, BotoCoreError) as exc:
            error_message = str(exc)
            if attempt >= max_retries or not _is_retryable(exc):
                break
            backoff = 0.5 * (2**attempt)
            await asyncio.sleep(backoff)
            attempt += 1
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except Exception as exc:
            error_message = str(exc)
            break

    duration_ms = int((time.perf_counter() - started) * 1000)
    status = "Succeeded" if error_message is None else "Failed"

    response_summary = None
    if response_payload is not None:
        # Redact sensitive data from response before logging
        redacted_response = _redact(response_payload)
        limited_redacted_response = _limit_result_payload(
            redacted_response if isinstance(redacted_response, dict) else {},
            ctx.settings.execution.max_output_characters,
            service=service,
            operation=operation,
            options=options,
        )
        response_summary = _truncate_json(limited_redacted_response, 2000)

        response_artifact = await _run_blocking(
            ctx,
            ctx.artifacts.write_json,
            "response",
            limited_redacted_response,
            prefix=tx_id,
        )
        response_artifact.tx_id = tx_id
        response_artifact.op_id = op_id
        await _run_blocking(ctx, ctx.store.add_audit_artifact, response_artifact)

    await _run_blocking(
        ctx, ctx.store.update_op_status, op_id, status, duration_ms, error_message, response_summary
    )
    await _run_blocking(ctx, ctx.store.update_tx_status, tx_id, status, completed_at=utc_now_iso())

    if error_message:
        return result_from_payload(
            {
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
            }
        )

    limited_result = _limit_result_payload(
        response_payload if isinstance(response_payload, dict) else {},
        ctx.settings.execution.max_output_characters,
        service=service,
        operation=operation,
        options=options,
    )
    return result_from_payload(
        {
            "service": service,
            "operation": operation,
            "result": limited_result,
            "metadata": {
                "tx_id": tx_id,
                "op_id": op_id,
            },
        }
    )


def _error_response(
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

    return result_from_payload({"error": error})


def _resolve_catalog_operation(
    entry: object,
    service: str,
    operation: str,
) -> tuple[str, str]:
    """Resolve canonical service/operation from catalog entry when available."""
    ref = getattr(entry, "ref", None)
    if isinstance(ref, OperationRef):
        return ref.service, ref.operation

    resolved_service = service
    resolved_operation = operation
    candidate_service = getattr(ref, "service", None)
    candidate_operation = getattr(ref, "operation", None)
    if isinstance(candidate_service, str) and candidate_service:
        resolved_service = candidate_service
    if isinstance(candidate_operation, str) and candidate_operation:
        resolved_operation = candidate_operation
    return resolved_service, resolved_operation


def _compute_request_hash(
    payload: dict[str, object],
    context: dict[str, object] | None = None,
) -> str:
    """Compute a stable hash of the request payload plus optional context."""
    envelope: dict[str, object]
    if context:
        envelope = {"payload": payload, "context": context}
    else:
        envelope = payload
    normalized = json.dumps(
        envelope,
        sort_keys=True,
        ensure_ascii=True,
        default=json_default,
    )
    return sha256_text(normalized)


def _identity_center_enabled(ctx: AppContext) -> bool:
    return ctx.settings.auth.provider.lower() == "identity-center"


def _actor_from_request_context() -> str | None:
    request_ctx = get_request_context_optional()
    if request_ctx is None:
        return None
    return f"{request_ctx.issuer}:{request_ctx.user_id}"


def _parse_role_arn(role_arn: str) -> tuple[str, str] | None:
    match = re.match(r"^arn:aws(?:-cn|-us-gov)?:iam::(\d{12}):role/(.+)$", role_arn)
    if not match:
        return None
    return match.group(1), match.group(2)


def _role_selection_error(
    candidates: list[dict[str, object]],
) -> ToolResult:
    return result_from_payload(
        {
        "error": {
            "type": "RoleSelectionRequired",
            "message": (
                "Multiple roles available. "
                "Specify options.accountId and options.roleName."
            ),
            "candidates": candidates,
            "hint": (
                "Choose one of the listed roles and re-run the command with "
                    "options={'accountId': '...', 'roleName': '...'}."
                ),
                "retryable": True,
            },
        }
    )


def _identity_center_error(
    message: str,
) -> ToolResult:
    return _error_response(
        "IdentityCenterError",
        message,
        hint="Re-authenticate with IAM Identity Center and try again.",
        retryable=True,
    )


async def _resolve_identity_center_role_selection(
    ctx: AppContext,
    options: dict[str, object],
) -> tuple[str, str] | ToolResult:
    request_ctx = get_request_context_optional()
    if request_ctx is None or not request_ctx.access_token:
        return _error_response(
            "IdentityCenterAuthMissing",
            "Missing Identity Center access token.",
            hint="Provide an SSO access token via Authorization: Bearer <token>.",
        )
    access_token = request_ctx.access_token

    account_id: str | None = None
    role_name: str | None = None
    role_arn: str | None = None
    raw_account_id = options.get("accountId")
    raw_role_name = options.get("roleName")
    raw_role_arn = options.get("roleArn")
    if isinstance(raw_account_id, str) and raw_account_id.strip():
        account_id = raw_account_id
    if isinstance(raw_role_name, str) and raw_role_name.strip():
        role_name = raw_role_name
    if isinstance(raw_role_arn, str) and raw_role_arn.strip():
        role_arn = raw_role_arn

    if role_arn and not (account_id or role_name):
        parsed = _parse_role_arn(role_arn)
        if parsed:
            account_id, role_name = parsed

    if (account_id and not role_name) or (role_name and not account_id):
        return _error_response(
            "RoleSelectionInvalid",
            "Both options.accountId and options.roleName are required.",
            hint="Provide both accountId and roleName (or a roleArn).",
        )

    provider = get_identity_center_provider()

    if account_id and role_name:
        try:
            roles = await provider.list_account_roles(access_token, account_id)
        except IdentityCenterError as exc:
            return _identity_center_error(str(exc))
        if not any(role.role_name == role_name for role in roles):
            return _error_response(
                "RoleNotAssigned",
                "The specified role is not assigned to this user.",
                hint="Select a role from the available candidates.",
            )
        return account_id, role_name

    try:
        accounts = await provider.list_accounts(access_token)
    except IdentityCenterError as exc:
        return _identity_center_error(str(exc))

    # Fetch roles for all accounts in parallel with concurrency limit
    _semaphore = asyncio.Semaphore(10)

    async def fetch_roles_for_account(
        account: AccountEntry,
    ) -> tuple[AccountEntry, list[RoleEntry]]:
        async with _semaphore:
            roles = await provider.list_account_roles(access_token, account.account_id)
            return account, roles

    try:
        results = await asyncio.gather(
            *(fetch_roles_for_account(account) for account in accounts),
            return_exceptions=True,
        )
    except Exception as exc:
        return _identity_center_error(str(exc))

    candidates: list[dict[str, object]] = []
    for result in results:
        if isinstance(result, Exception):
            return _identity_center_error(
                f"Unexpected error fetching roles: {result}",
            )
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[1], list)
        ):
            return _identity_center_error(
                "Unexpected role selection result type",
            )
        account, roles = result
        account_name = getattr(account, "account_name", None)
        for role in roles:
            account_id = getattr(role, "account_id", None)
            role_name = getattr(role, "role_name", None)
            if not isinstance(account_id, str) or not isinstance(role_name, str):
                continue
            candidates.append(
                {
                    "accountId": account_id,
                    "accountName": account_name if isinstance(account_name, str) else None,
                    "roleName": role_name,
                }
            )

    if not candidates:
        return _error_response(
            "NoRolesAvailable",
            "No roles are available for this Identity Center user.",
            hint="Verify role assignments in IAM Identity Center.",
        )

    if len(candidates) == 1:
        only = candidates[0]
        return str(only["accountId"]), str(only["roleName"])

    return _role_selection_error(candidates)


async def _ensure_identity_center_credentials(
    ctx: AppContext,
    account_id: str,
    role_name: str,
) -> ToolResult | None:
    request_ctx = get_request_context_optional()
    if request_ctx is None or not request_ctx.access_token:
        return _error_response(
            "IdentityCenterAuthMissing",
            "Missing Identity Center access token.",
            hint="Provide an SSO access token via Authorization: Bearer <token>.",
        )

    provider = get_identity_center_provider()
    try:
        temp_creds = await provider.get_cached_role_credentials(
            request_ctx.access_token,
            account_id,
            role_name,
            request_ctx.user_id,
        )
    except IdentityCenterError as exc:
        return _identity_center_error(str(exc))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    aws_creds = AWSCredentials(
        access_key_id=temp_creds.access_key_id,
        secret_access_key=temp_creds.secret_access_key,
        session_token=temp_creds.session_token,
        expiration=temp_creds.expiration,
    )
    update_request_context(lambda c: c.with_aws_credentials(aws_creds, account_id, role_arn))
    return None


def _parse_json_arg(arg: object, name: str) -> dict[str, object] | ToolResult:
    """Parse JSON arg that might be string or dict."""
    if isinstance(arg, dict):
        return dict(arg)
    if isinstance(arg, str):
        try:
            parsed = json.loads(arg)
            if not isinstance(parsed, dict):
                return _error_response(
                    f"Invalid{name.capitalize()}",
                    f"Expected JSON object for '{name}', got {type(parsed).__name__}",
                    hint=f"Provide {name} as a JSON object.",
                )
            return dict(parsed)
        except json.JSONDecodeError as e:
            return _error_response(
                f"Invalid{name.capitalize()}",
                f"Failed to parse {name} as JSON: {e}",
                hint=f"Provide {name} as an object, not a string.",
            )
    if arg is None:
        return {}
    return {}


async def _record_audit_log(
    ctx: AppContext,
    tx_id: str,
    op_id: str,
    service: str,
    operation: str,
    op_payload: dict[str, object],
    status: str,
    region: str | None,
    is_new_tx: bool,
    model: SmithyModel,
    operation_shape_id: str,
    request_context: dict[str, object] | None = None,
) -> None:
    """Helper to record audit logs (Tx, Op, Artifact)."""
    started_at = utc_now_iso()
    request_ctx = get_request_context_optional()
    actor = _actor_from_request_context()
    account = request_ctx.aws_account_id if request_ctx else None
    role = request_ctx.aws_role_arn if request_ctx else None
    if request_context:
        if request_context.get("accountId"):
            account = str(request_context.get("accountId") or account)
        if request_context.get("roleName"):
            role = str(request_context.get("roleName") or role)

    if is_new_tx:
        await _run_blocking(
            ctx,
            ctx.store.create_tx,
            AuditTxRecord(
                tx_id=tx_id,
                plan_id=None,
                status=status,
                actor=actor,
                role=role,
                account=account,
                region=str(region) if region else None,
                started_at=started_at,
                completed_at=None,
            ),
        )

    request_hash = _compute_request_hash(op_payload, request_context)
    request_payload, _ = inject_idempotency_tokens(model, operation_shape_id, op_payload)

    op_record = AuditOpRecord(
        op_id=op_id,
        tx_id=tx_id,
        service=service,
        operation=operation,
        request_hash=request_hash,
        status=status,
        duration_ms=None,
        error=None,
        response_summary=None,
        created_at=started_at,
    )
    await _run_blocking(ctx, ctx.store.create_op, op_record)

    redacted_request_payload = _redact(request_payload)
    request_payload_for_artifact = (
        redacted_request_payload if isinstance(redacted_request_payload, dict) else {}
    )
    request_artifact = await _run_blocking(
        ctx,
        ctx.artifacts.write_json,
        "request",
        request_payload_for_artifact,
        prefix=tx_id,
    )
    request_artifact.tx_id = tx_id
    request_artifact.op_id = op_id
    await _run_blocking(ctx, ctx.store.add_audit_artifact, request_artifact)


_MAX_COERCE_DEPTH = 30


def _coerce_payload_types(
    model: SmithyModel,
    shape_id: str | None,
    payload: dict[str, object],
    path: str = "",
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> dict[str, object]:
    """Recursively coerce payload types to match Smithy model expectations.

    This function handles:
    - blob: base64 string -> bytes
    - integer/long/short/byte: string -> int
    - float/double: string -> float
    - boolean: string "true"/"false" -> bool
    - timestamp: validate ISO 8601 format
    - union: validate exactly one member is set
    - nested structures, lists, and maps
    """

    if depth >= _MAX_COERCE_DEPTH:
        return payload

    if shape_id is None:
        return payload

    shape = model.get_shape(shape_id)
    if shape is None:
        return payload

    # If this is an operation, get its input shape
    if isinstance(shape, OperationShape):
        return _coerce_payload_types(
            model, shape.input, payload, path, service, operation, depth
        )

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

        # Handle blob type - decode base64 string to bytes
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
                model, member.target, value, field_path, service, operation, depth + 1
            )

        # Handle lists
        elif isinstance(target_shape, ListShape) and isinstance(value, list):
            result[field_name] = _coerce_list(
                model, target_shape, value, field_path, service, operation, depth + 1
            )

        # Handle maps
        elif isinstance(target_shape, MapShape) and isinstance(value, dict):
            result[field_name] = _coerce_map(
                model, target_shape, value, field_path, service, operation, depth + 1
            )

    return result


def _coerce_blob(
    value: object,
    path: str,
    service: str = "",
    operation: str = "",
) -> bytes:
    """Convert base64 string to bytes.

    Supports:
    - bytes: pass through
    - str: base64 decode

    Args:
        value: The value to coerce
        path: Field path for error messages
        service: AWS service name (unused, kept for API compatibility)
        operation: Operation name (unused, kept for API compatibility)

    Returns:
        Bytes content
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding for blob field '{path}': {e}")

    raise ValueError(
        f"Expected base64 string or bytes for blob field '{path}', got {type(value).__name__}"
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
    tz_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2})?$"
    if re.match(tz_pattern, value):
        return value

    raise ValueError(
        f"Invalid timestamp format for field '{path}': '{value}'. "
        f"Expected ISO 8601 format (e.g., '2024-01-01T00:00:00Z' or '2024-01-01')"
    )


def _coerce_list(
    model: SmithyModel,
    list_shape: ListShape,
    value: list[object],
    path: str,
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> list[object]:
    """Coerce list items to expected types."""

    if depth >= _MAX_COERCE_DEPTH:
        return value

    item_shape = model.get_shape(list_shape.member.target)
    if item_shape is None:
        return value

    result: list[object] = []
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
            result.append(
                _coerce_payload_types(
                    model, list_shape.member.target, item, item_path, service, operation, depth + 1
                )
            )
        else:
            result.append(item)

    return result


def _coerce_map(
    model: SmithyModel,
    map_shape: MapShape,
    value: dict[str, object],
    path: str,
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> dict[str, object]:
    """Coerce map values to expected types."""

    if depth >= _MAX_COERCE_DEPTH:
        return value

    value_shape = model.get_shape(map_shape.value.target)
    if value_shape is None:
        return value

    result: dict[str, object] = {}
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
                model, map_shape.value.target, v, item_path, service, operation, depth + 1
            )
        else:
            result[k] = v

    return result


async def _call_boto3(
    service: str,
    operation: str,
    params: dict[str, object],
    region: str | None,
    max_output_characters: int,
) -> dict[str, object]:
    """Call AWS via boto3."""
    client = await get_client_async(service, region, None)
    method_name = _snake_case(operation)
    if not hasattr(client, method_name):
        raise AttributeError(f"boto3 client for {service} has no method '{method_name}'")
    response = await call_aws_api_async(
        client,
        method_name,
        max_output_characters=max_output_characters,
        **params,
    )
    return response


def _snake_case(name: str) -> str:
    """Convert PascalCase to snake_case, handling acronyms correctly.

    Examples:
        DescribeDBInstances -> describe_db_instances
        ListEC2Instances -> list_ec2_instances
        GetAPIKey -> get_api_key
    """
    # Insert underscore before uppercase letters that follow lowercase letters
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    # Insert underscore before uppercase letters that are followed by lowercase letters
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


_RETRYABLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "TooManyRequestsException",
}


def _is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable."""
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


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


_DEFAULT_COMPACT_DROP_FIELDS = frozenset(
    {
        "ResponseMetadata",
        "Metadata",
    }
)

_SECONDARY_COMPACT_DROP_FIELDS = frozenset(
    {
        "Environment",
        "Tags",
        "Policy",
        "Policies",
        "PolicyDocument",
        "AssumeRolePolicyDocument",
        "Definition",
        "TemplateBody",
        "Metadata",
        "LoggingConfig",
        "TracingConfig",
        "VpcConfig",
        "UserData",
        "Configuration",
        "Document",
    }
)

_OPERATION_COMPACT_DROP_FIELDS: dict[tuple[str, str], frozenset[str]] = {
    (
        "lambda",
        "listfunctions",
    ): frozenset(
        {
            "Code",
            "CodeSha256",
            "Environment",
            "EnvironmentResponse",
            "FileSystemConfigs",
            "ImageConfigResponse",
            "LastUpdateStatusReason",
            "LastUpdateStatusReasonCode",
            "Layers",
            "LoggingConfig",
            "RuntimeVersionConfig",
            "SigningJobArn",
            "SigningProfileVersionArn",
            "StateReason",
            "StateReasonCode",
            "Tags",
            "TracingConfig",
            "Variables",
            "VpcConfig",
        }
    ),
}

_COMPACT_PRESETS_AUTO: tuple[dict[str, int], ...] = (
    {"max_depth": 4, "max_list_items": 40, "max_string_chars": 400},
    {"max_depth": 3, "max_list_items": 25, "max_string_chars": 250},
    {"max_depth": 2, "max_list_items": 15, "max_string_chars": 160},
    {"max_depth": 1, "max_list_items": 8, "max_string_chars": 96},
)

_COMPACT_PRESETS_COMPACT: tuple[dict[str, int], ...] = (
    {"max_depth": 3, "max_list_items": 20, "max_string_chars": 200},
    {"max_depth": 2, "max_list_items": 10, "max_string_chars": 120},
    {"max_depth": 1, "max_list_items": 6, "max_string_chars": 80},
)


def _json_size(value: object) -> int:
    return len(json.dumps(value, default=json_default, ensure_ascii=True))


def _parse_response_mode(options: dict[str, object] | None) -> str:
    if not options:
        return "auto"
    raw = options.get("responseMode")
    if not isinstance(raw, str):
        return "auto"
    mode = raw.strip().lower()
    if mode in {"auto", "compact", "full"}:
        return mode
    return "auto"


def _parse_max_result_items(options: dict[str, object] | None) -> int | None:
    if not options:
        return None
    raw = options.get("maxResultItems")
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, (int, str)):
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return None
    return max(1, min(parsed, 200))


def _parse_omit_response_fields(options: dict[str, object] | None) -> set[str]:
    if not options:
        return set()
    raw = options.get("omitResponseFields")
    if not isinstance(raw, list):
        return set()
    fields: set[str] = set()
    for item in raw[:64]:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or len(normalized) > 64:
            continue
        fields.add(normalized)
    return fields


def _operation_drop_fields(
    service: str | None,
    operation: str | None,
    extra_fields: set[str],
) -> set[str]:
    fields = set(_DEFAULT_COMPACT_DROP_FIELDS)
    key = ((service or "").strip().lower(), (operation or "").strip().lower())
    fields.update(_OPERATION_COMPACT_DROP_FIELDS.get(key, frozenset()))
    fields.update(extra_fields)
    return fields


def _drop_field_levels(
    service: str | None,
    operation: str | None,
    extra_fields: set[str],
) -> tuple[set[str], ...]:
    base = _operation_drop_fields(service, operation, extra_fields)
    broadened = set(base)
    broadened.update(_SECONDARY_COMPACT_DROP_FIELDS)
    return base, broadened


def _compact_summary_value(value: object, max_string_chars: int) -> object:
    if isinstance(value, str):
        return _truncate_text(value, max_string_chars)
    if isinstance(value, list):
        return {
            "_mcp_compacted_type": "list",
            "itemCount": len(value),
        }
    if isinstance(value, dict):
        keys = list(value.keys())
        return {
            "_mcp_compacted_type": "object",
            "keyCount": len(keys),
            "keys": keys[:12],
        }
    return value


def _compact_payload(
    value: object,
    *,
    max_depth: int,
    max_list_items: int,
    max_string_chars: int,
    drop_fields: set[str],
    depth: int = 0,
) -> object:
    if isinstance(value, dict):
        compacted: dict[str, object] = {}
        omitted_fields: list[str] = []
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if key in drop_fields:
                omitted_fields.append(key)
                continue
            if depth >= max_depth:
                compacted[key] = _compact_summary_value(raw_value, max_string_chars)
                continue
            compacted[key] = _compact_payload(
                raw_value,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                drop_fields=drop_fields,
                depth=depth + 1,
            )
        if omitted_fields:
            compacted["_mcp_omitted_fields"] = sorted(set(omitted_fields))
        return compacted

    if isinstance(value, list):
        if depth >= max_depth:
            return {
                "_mcp_compacted_type": "list",
                "itemCount": len(value),
            }
        sliced = value[:max_list_items]
        compacted_list = [
            _compact_payload(
                item,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                drop_fields=drop_fields,
                depth=depth + 1,
            )
            for item in sliced
        ]
        if len(value) > max_list_items:
            compacted_list.append({"_mcp_truncated_items": len(value) - max_list_items})
        return compacted_list

    if isinstance(value, str):
        return _truncate_text(value, max_string_chars)

    return value


def _preview_payload(
    payload: dict[str, object],
    safe_limit: int,
    original_chars: int,
    hint: str,
) -> dict[str, object]:
    serialized = json.dumps(payload, default=json_default, ensure_ascii=True)
    return {
        "truncated": True,
        "maxCharacters": safe_limit,
        "originalCharacters": original_chars,
        "strategy": "preview",
        "preview": _truncate_text(serialized, safe_limit),
        "hint": hint,
    }


def _limit_result_payload(
    payload: dict[str, object],
    max_chars: int,
    *,
    service: str | None = None,
    operation: str | None = None,
    options: dict[str, object] | None = None,
) -> dict[str, object]:
    """Limit result payload size while preserving useful structure."""
    safe_limit = max(128, max_chars)
    original_chars = _json_size(payload)
    if original_chars <= safe_limit:
        return payload

    response_mode = _parse_response_mode(options)
    if response_mode == "full":
        return _preview_payload(
            payload,
            safe_limit,
            original_chars,
            "Use options.responseMode='compact' or reduce request scope (pagination/filter).",
        )

    extra_omit_fields = _parse_omit_response_fields(options)
    max_result_items = _parse_max_result_items(options)
    drop_field_levels = _drop_field_levels(service, operation, extra_omit_fields)
    presets = _COMPACT_PRESETS_COMPACT if response_mode == "compact" else _COMPACT_PRESETS_AUTO

    for drop_fields in drop_field_levels:
        for preset in presets:
            list_cap = preset["max_list_items"]
            if max_result_items is not None:
                list_cap = min(list_cap, max_result_items)
            compact_result = _compact_payload(
                payload,
                max_depth=preset["max_depth"],
                max_list_items=max(1, list_cap),
                max_string_chars=preset["max_string_chars"],
                drop_fields=drop_fields,
            )
            candidate = {
                "truncated": True,
                "maxCharacters": safe_limit,
                "originalCharacters": original_chars,
                "strategy": "compact",
                "responseMode": response_mode,
                "result": compact_result,
            }
            if _json_size(candidate) <= safe_limit:
                return candidate

    return _preview_payload(
        payload,
        safe_limit,
        original_chars,
        (
            "Compact output still exceeded MAX_OUTPUT_CHARACTERS; "
            "set lower maxResultItems or request a narrower operation scope."
        ),
    )


SENSITIVE_KEYS = [
    "password",
    "secret",
    "token",
    "accesskey",
    "secretaccesskey",
    "sessiontoken",
    "clientsecret",
    "apikey",
    "credential",
    "authorization",
]

_MAX_REDACT_DEPTH = 20


def _redact(value: object, depth: int = 0) -> object:
    """Redact sensitive values from a payload."""
    if depth >= _MAX_REDACT_DEPTH:
        return "***"
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, val in value.items():
            if any(marker in key.lower() for marker in SENSITIVE_KEYS):
                redacted[key] = "***"
            else:
                redacted[key] = _redact(val, depth + 1)
        return redacted
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value]
    return value


search_operations_tool = ToolSpec(
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

get_operation_schema_tool = ToolSpec(
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

execute_tool = ToolSpec(
    name="aws_execute",
    description=(
        "Validate and invoke AWS operations. "
        "Do NOT wrap arguments in a 'payload' object. "
        "Required top-level arguments: 'action' (enum: validate/invoke), "
        "'service' (string), 'operation' (string), 'payload' (object: API params). "
        "Optional: 'region' (string), 'options' (object: confirmationToken, "
        "accountId/roleName for Identity Center, responseMode/maxResultItems/"
        "omitResponseFields for large responses). "
        "\n\n"
        "LARGE RESPONSE RECOMMENDATION:\n"
        "- Default/recommended: options={'responseMode':'auto'}\n"
        "- For list APIs first try: options={'responseMode':'compact','maxResultItems':20}\n"
        "- For full fidelity: options={'responseMode':'full'} with narrower request scope\n\n"
        "BINARY DATA: For binary fields (Body, ZipFile, etc.), provide "
        "base64-encoded content as a string."
        "\n\n"
        "Examples:\n"
        "1. List Lambda Functions:\n"
        "   call(action='invoke', service='lambda', operation='ListFunctions', payload={})\n"
        "2. S3 Upload (base64 body):\n"
        "   call(action='invoke', service='s3', operation='PutObject',\n"
        "   payload={'Bucket': 'my-bucket', 'Key': 'file.txt', 'Body': 'SGVsbG8gV29ybGQ='})"
    ),
    input_schema=EXECUTE_SCHEMA,
    handler=execute_operation,
)
