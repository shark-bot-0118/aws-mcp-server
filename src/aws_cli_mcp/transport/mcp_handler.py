"""HTTP JSON-RPC handler for MCP tools."""

from __future__ import annotations

import inspect
import json
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from aws_cli_mcp import __version__
from aws_cli_mcp.config import load_settings
from aws_cli_mcp.execution.aws_client import RequestContextError
from aws_cli_mcp.mcp_runtime import ToolResult
from aws_cli_mcp.tools import get_tool_registry
from aws_cli_mcp.utils.serialization import json_default

logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"
MAX_BATCH_REQUESTS = 50


async def handle_mcp_request(request: Request) -> Response:
    strict_mode = bool(getattr(request.app.state, "strict_mcp_http", False))
    origin_error = _validate_origin(request, strict_mode)
    if origin_error is not None:
        return origin_error

    if request.method == "OPTIONS":
        return Response(status_code=204)

    if request.method != "POST":
        return _error_response(
            None,
            "Method not allowed",
            status_code=405,
            code="method_not_allowed",
            protocol_version=_protocol_version(request),
        )

    if strict_mode:
        accept_error = _validate_accept_header(request)
        if accept_error is not None:
            return accept_error
        version_error = _validate_protocol_version(request)
        if version_error is not None:
            return version_error
        content_type = request.headers.get("content-type", "")
        if content_type and "application/json" not in content_type.lower():
            return _error_response(
                None,
                "Content-Type must be application/json",
                status_code=415,
                code="unsupported_media_type",
                protocol_version=_protocol_version(request),
            )

    try:
        payload = await request.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return _error_response(
            None,
            "Invalid JSON",
            protocol_version=_protocol_version(request),
        )

    if isinstance(payload, list):
        return await _handle_batch(payload, request)
    if not isinstance(payload, dict):
        return _error_response(
            None,
            "Invalid JSON-RPC request",
            status_code=400,
            code="invalid_request",
            protocol_version=_protocol_version(request),
        )

    result = await _handle_single(payload, request)
    if result is None:
        return Response(
            status_code=202,
            headers={"MCP-Protocol-Version": _protocol_version(request)},
        )
    if isinstance(result, Response):
        result.headers.setdefault("MCP-Protocol-Version", _protocol_version(request))
        return result
    return _json_response(result, headers={"MCP-Protocol-Version": _protocol_version(request)})


async def _handle_batch(payloads: list[object], request: Request) -> Response:
    if len(payloads) > MAX_BATCH_REQUESTS:
        return _error_response(
            None,
            f"Batch request too large (max {MAX_BATCH_REQUESTS})",
            status_code=400,
            code="batch_too_large",
            protocol_version=_protocol_version(request),
        )
    if not payloads:
        return _error_response(
            None,
            "Invalid JSON-RPC batch request",
            status_code=400,
            code="invalid_request",
            protocol_version=_protocol_version(request),
        )

    responses: list[dict[str, object]] = []
    for item in payloads:
        if not isinstance(item, dict):
            responses.append(
                _error_body(None, "Invalid JSON-RPC batch entry", code="invalid_request")
            )
            continue
        response = await _handle_single(item, request)
        if response is not None:
            responses.append(response)

    if not responses:
        return Response(
            status_code=202,
            headers={"MCP-Protocol-Version": _protocol_version(request)},
        )
    return _json_response(responses, headers={"MCP-Protocol-Version": _protocol_version(request)})


async def _handle_single(
    payload: dict[str, object],
    request: Request,
) -> dict[str, object] | None:
    request_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})
    params_dict = params if isinstance(params, dict) else {}

    if request_id is None:
        if isinstance(method, str) and method.startswith("notifications/"):
            return None
        return None

    if method is None and ("result" in payload or "error" in payload):
        return None

    if not isinstance(method, str):
        return _error_body(request_id, "Invalid JSON-RPC method", code="invalid_request")

    if method == "initialize":
        settings = load_settings()
        requested_version = params_dict.get("protocolVersion")
        if isinstance(requested_version, str) and requested_version in SUPPORTED_PROTOCOL_VERSIONS:
            negotiated = requested_version
        else:
            negotiated = SUPPORTED_PROTOCOL_VERSIONS[-1]
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": negotiated,
                "serverInfo": {"name": "aws-cli-mcp", "version": __version__},
                "instructions": settings.server.instructions,
                "capabilities": {"tools": {"listChanged": False}},
            },
        }

    if method == "tools/list":
        tools = [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            }
            for tool in get_tool_registry().values()
        ]
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}

    if method == "tools/call":
        name_obj = params_dict.get("name")
        if not isinstance(name_obj, str):
            return _error_body(request_id, "Invalid tool name")
        name = name_obj
        arguments_obj = params_dict.get("arguments", {})
        if not isinstance(arguments_obj, dict):
            return _error_body(request_id, "Invalid tool arguments", code="invalid_params")
        arguments = arguments_obj
        registry = get_tool_registry()
        tool = registry.get(name)
        if tool is None:
            return _error_body(request_id, f"Unknown tool: {name}")
        try:
            result = tool.handler(arguments)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, ToolResult):
                raise TypeError("Tool handler did not return ToolResult")
        except RequestContextError as exc:
            return _error_body(
                request_id,
                str(exc),
                code="internal_error",
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            logger.exception("Tool handler error: %s", name)
            return _error_body(request_id, "Internal tool error")

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": result.content,
                "structuredContent": result.structured_content,
            },
        }

    return _error_body(request_id, f"Unsupported method: {method[:256]}")


def _error_response(
    request_id: object,
    message: str,
    status_code: int = 400,
    code: str | int = -32000,
    protocol_version: str | None = None,
) -> JSONResponse:
    return JSONResponse(
        _error_body(request_id, message, code=code),
        status_code=status_code,
        headers={"MCP-Protocol-Version": protocol_version or DEFAULT_PROTOCOL_VERSION},
    )


def _error_body(
    request_id: object,
    message: str,
    code: str | int = -32000,
) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _json_response(
    payload: object,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Serialize *payload* once and return a Response.

    Avoids the previous encode→decode→encode round-trip that
    ``JSONResponse(_jsonable(data))`` performed.
    """
    body = json.dumps(payload, default=json_default, ensure_ascii=False)
    return Response(
        content=body,
        status_code=status_code,
        media_type="application/json",
        headers=headers,
    )


def _protocol_version(request: Request) -> str:
    version = request.headers.get("MCP-Protocol-Version")
    if not version:
        return DEFAULT_PROTOCOL_VERSION
    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version
    return DEFAULT_PROTOCOL_VERSION


def _validate_protocol_version(request: Request) -> JSONResponse | None:
    version = request.headers.get("MCP-Protocol-Version")
    if not version:
        return None
    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return None
    return _error_response(
        None,
        "Unsupported MCP protocol version",
        status_code=400,
        code="unsupported_protocol_version",
        protocol_version=DEFAULT_PROTOCOL_VERSION,
    )


def _validate_accept_header(request: Request) -> JSONResponse | None:
    accept = request.headers.get("accept", "")
    if not accept:
        return None  # Missing Accept header means client accepts any media type
    tokens = [part.split(";", 1)[0].strip().lower() for part in accept.split(",")]
    if "*/*" in tokens:
        return None
    if "application/json" not in tokens:
        return _error_response(
            None,
            "Accept must include application/json",
            status_code=406,
            code="not_acceptable",
            protocol_version=_protocol_version(request),
        )
    return None


def _validate_origin(request: Request, strict_mode: bool) -> JSONResponse | None:
    allowed = tuple(getattr(request.app.state, "http_allowed_origins", ()))
    allow_missing = bool(getattr(request.app.state, "http_allow_missing_origin", True))
    origin = request.headers.get("origin")
    if not origin:
        if strict_mode and allowed and not allow_missing:
            return _error_response(
                None,
                "Missing Origin header",
                status_code=403,
                code="origin_required",
                protocol_version=_protocol_version(request),
            )
        return None
    if not allowed:
        return None
    if "*" in allowed:
        return None
    if origin not in allowed:
        return _error_response(
            None,
            "Origin not allowed",
            status_code=403,
            code="origin_not_allowed",
            protocol_version=_protocol_version(request),
        )
    return None
