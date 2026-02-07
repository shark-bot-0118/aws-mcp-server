"""Authentication and identity management.

OAuth 2.0 Protected Resource (RFC 9728) support with multi-IdP authentication.
"""

from aws_cli_mcp.auth.context import (
    SENSITIVE_FIELDS,
    AWSCredentials,
    RequestContext,
    get_request_context,
    get_request_context_optional,
    reset_request_context,
    set_request_context,
    update_request_context,
)

__all__ = [
    "AWSCredentials",
    "RequestContext",
    "SENSITIVE_FIELDS",
    "get_request_context",
    "get_request_context_optional",
    "reset_request_context",
    "set_request_context",
    "update_request_context",
]
