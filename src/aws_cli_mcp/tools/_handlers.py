"""Tool handler functions: search_operations, get_operation_schema, execute_operation."""

from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from aws_cli_mcp.app import AppContext, get_app_context
from aws_cli_mcp.audit.models import AuditOpRecord, AuditTxRecord
from aws_cli_mcp.auth.context import get_request_context_optional
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.execution.aws_client import RequestContextError
from aws_cli_mcp.execution.idempotency import inject_idempotency_tokens
from aws_cli_mcp.mcp_runtime import ToolResult
from aws_cli_mcp.smithy.parser import SmithyModel
from aws_cli_mcp.smithy.version_manager import load_model_snapshot
from aws_cli_mcp.tools._coercion import _coerce_payload_types
from aws_cli_mcp.tools._helpers import (
    _actor_from_request_context,
    _call_boto3,
    _compute_request_hash,
    _error_response,
    _is_exposed,
    _is_retryable,
    _parse_json_arg,
    _redact,
    _resolve_catalog_operation,
    _run_blocking,
)
from aws_cli_mcp.tools._identity_center import (
    _ensure_identity_center_credentials,
    _identity_center_enabled,
    _resolve_identity_center_role_selection,
)
from aws_cli_mcp.tools._response_limiting import (
    _limit_result_payload,
    _truncate_json,
)
from aws_cli_mcp.tools._schemas import (
    EXECUTE_SCHEMA,
    GET_SCHEMA_SCHEMA,
    SEARCH_SCHEMA,
)
from aws_cli_mcp.tools.base import result_from_payload, validate_or_raise
from aws_cli_mcp.utils.jsonschema import (
    format_structured_errors,
    validate_payload_structured,
)
from aws_cli_mcp.utils.time import utc_now_iso


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
