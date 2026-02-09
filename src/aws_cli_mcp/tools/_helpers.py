"""Shared helper functions for the unified AWS tools."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from typing import ParamSpec, TypeVar

from botocore.exceptions import BotoCoreError, ClientError

from aws_cli_mcp.app import AppContext
from aws_cli_mcp.auth.context import get_request_context_optional
from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.execution.aws_client import call_aws_api_async, get_client_async
from aws_cli_mcp.mcp_runtime import ToolResult
from aws_cli_mcp.tools.base import result_from_payload
from aws_cli_mcp.utils.hashing import sha256_text
from aws_cli_mcp.utils.masking import (
    _MAX_REDACT_DEPTH,  # noqa: F401 — re-export for facade
    redact_sensitive_fields,
)
from aws_cli_mcp.utils.masking import (
    SENSITIVE_KEY_MARKERS as SENSITIVE_KEYS,  # noqa: F401 — re-export for facade
)
from aws_cli_mcp.utils.serialization import json_default

P = ParamSpec("P")
T = TypeVar("T")

_RETRYABLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "TooManyRequestsException",
}


# ---------------------------------------------------------------------------
# Thin wrapper around the shared masking utility
# ---------------------------------------------------------------------------

def _redact(value: object, depth: int = 0) -> object:
    """Redact sensitive values from a payload."""
    return redact_sensitive_fields(value, mask="***", depth=depth)


# ---------------------------------------------------------------------------
# Threading / async helpers
# ---------------------------------------------------------------------------

async def _run_blocking(
    ctx: AppContext,
    func: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    if ctx.settings.server.transport_mode in {"http", "remote"}:
        return await asyncio.to_thread(func, *args, **kwargs)
    return func(*args, **kwargs)


# ---------------------------------------------------------------------------
# Policy / exposure helpers
# ---------------------------------------------------------------------------

def _is_exposed(ctx: AppContext, op_ref: OperationRef) -> bool:
    """Check if an operation is exposed based on policy only."""
    if not ctx.policy_engine.is_service_allowed(op_ref.service):
        return False
    return ctx.policy_engine.is_operation_allowed(op_ref)


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Catalog helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# snake_case / retryable / boto3
# ---------------------------------------------------------------------------

def _snake_case(name: str) -> str:
    """Convert PascalCase to snake_case, handling acronyms correctly."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable."""
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code")
        return code in _RETRYABLE_CODES
    return isinstance(exc, BotoCoreError)


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


# ---------------------------------------------------------------------------
# Actor helper
# ---------------------------------------------------------------------------

def _actor_from_request_context() -> str | None:
    request_ctx = get_request_context_optional()
    if request_ctx is None:
        return None
    return f"{request_ctx.issuer}:{request_ctx.user_id}"
