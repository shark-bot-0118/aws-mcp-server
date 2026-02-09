"""Unified AWS tools — re-export facade.

This module re-exports every public symbol from the submodules so that
existing ``from aws_cli_mcp.tools.aws_unified import X`` statements
continue to work unchanged.

Sub-modules:
    _schemas           – JSON Schema dicts & ToolSpec factory
    _helpers           – shared utilities (_redact, _error_response, …)
    _handlers          – search_operations, get_operation_schema, execute_operation
    _coercion          – payload type coercion
    _response_limiting – response compaction & truncation
    _identity_center   – IAM Identity Center helpers
"""

from __future__ import annotations

# --- coercion --------------------------------------------------------------
from aws_cli_mcp.tools._coercion import (  # noqa: F401
    _MAX_COERCE_DEPTH,
    _coerce_blob,
    _coerce_boolean,
    _coerce_float,
    _coerce_integer,
    _coerce_list,
    _coerce_map,
    _coerce_payload_types,
    _coerce_timestamp,
)

# --- handlers --------------------------------------------------------------
from aws_cli_mcp.tools._handlers import (  # noqa: F401
    _record_audit_log,
    execute_operation,
    get_operation_schema,
    search_operations,
)

# --- helpers ---------------------------------------------------------------
from aws_cli_mcp.tools._helpers import (  # noqa: F401
    _MAX_REDACT_DEPTH,
    SENSITIVE_KEYS,
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
    _snake_case,
)

# --- identity center -------------------------------------------------------
from aws_cli_mcp.tools._identity_center import (  # noqa: F401
    _ensure_identity_center_credentials,
    _identity_center_enabled,
    _identity_center_error,
    _parse_role_arn,
    _resolve_identity_center_role_selection,
    _role_selection_error,
)

# --- response limiting -----------------------------------------------------
from aws_cli_mcp.tools._response_limiting import (  # noqa: F401
    _compact_payload,
    _compact_summary_value,
    _limit_result_payload,
    _parse_max_result_items,
    _parse_omit_response_fields,
    _parse_response_mode,
    _truncate_json,
    _truncate_text,
)

# --- schemas ---------------------------------------------------------------
from aws_cli_mcp.tools._schemas import (  # noqa: F401
    EXECUTE_SCHEMA,
    GET_SCHEMA_SCHEMA,
    SEARCH_SCHEMA,
    make_tool_specs,
)

# --- ToolSpec instances (created via factory) ------------------------------
search_operations_tool, get_operation_schema_tool, execute_tool = make_tool_specs(
    search_operations,
    get_operation_schema,
    execute_operation,
)
