"""MCP runtime adapter with optional FastMCP support."""

from __future__ import annotations

import inspect
import json
import logging
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast

from pydantic import BaseModel

logger = logging.getLogger(__name__)


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, object]
    handler: Callable[[dict[str, object]], "ToolResult | Awaitable[ToolResult]"]


class ToolResult(BaseModel):
    content: list[dict[str, object]]
    structured_content: dict[str, object] | None = None


class _SimpleMCPServer:
    def __init__(self, name: str, version: str, instructions: str) -> None:
        self._name = name
        self._version = version
        self._instructions = instructions
        self._tools: dict[str, ToolSpec] = {}

    def add_tool(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def run(self) -> None:  # pragma: no cover - stdio loop
        import asyncio

        loop = asyncio.new_event_loop()
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    self._write_error(None, "Invalid JSON")
                    continue
                if not isinstance(request, dict):
                    self._write_error(None, "Invalid JSON-RPC request")
                    continue

                request_id = request.get("id")
                method = request.get("method")
                raw_params = request.get("params", {})
                params = raw_params if isinstance(raw_params, dict) else {}

                if method == "initialize":
                    init_result: dict[str, object] = {
                        "serverInfo": {"name": self._name, "version": self._version},
                        "instructions": self._instructions,
                        "capabilities": {"tools": {}},
                    }
                    self._write_result(request_id, init_result)
                elif method == "tools/list":
                    tools = [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.input_schema,
                        }
                        for tool in self._tools.values()
                    ]
                    self._write_result(request_id, {"tools": tools})
                elif method == "tools/call":
                    raw_name = params.get("name")
                    if not isinstance(raw_name, str):
                        self._write_error(request_id, "Invalid tool name")
                        continue
                    name = raw_name
                    raw_arguments = params.get("arguments", {})
                    arguments = raw_arguments if isinstance(raw_arguments, dict) else {}
                    if name not in self._tools:
                        self._write_error(request_id, f"Unknown tool: {name}")
                        continue
                    try:
                        raw_result = self._tools[name].handler(arguments)
                        if _is_awaitable(raw_result):
                            tool_result = loop.run_until_complete(
                                cast(Awaitable[ToolResult], raw_result)
                            )
                        else:
                            tool_result = cast(ToolResult, raw_result)
                        if not isinstance(tool_result, ToolResult):
                            raise TypeError("Tool handler did not return ToolResult")
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as exc:  # pragma: no cover - error path
                        logger.exception("Tool execution error: %s", exc)
                        self._write_error(request_id, "Internal tool error")
                        continue
                    payload: dict[str, object] = {
                        "content": tool_result.content,
                        "structuredContent": tool_result.structured_content,
                    }
                    self._write_result(request_id, payload)
                else:
                    method_name = method if isinstance(method, str) else repr(method)
                    self._write_error(request_id, f"Unsupported method: {method_name[:256]}")
        finally:
            loop.close()

    def _write_result(self, request_id: object, result: dict[str, object]) -> None:
        payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()

    def _write_error(self, request_id: object, message: str) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": message},
        }
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()


FastMCP: Any
FunctionTool: Any
FastToolResult: Any

try:  # optional FastMCP support
    from fastmcp import FastMCP
    from fastmcp.tools import FunctionTool
    from fastmcp.tools.tool import ToolResult as FastToolResult

    _FAST_MCP_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    FastMCP = None
    FunctionTool = None
    FastToolResult = None
    _FAST_MCP_AVAILABLE = False


class MCPServer:
    """Adapter that uses FastMCP when available or a minimal stdio server otherwise."""

    def __init__(self, name: str, version: str, instructions: str) -> None:
        self._server: Any
        self._mode: str
        if _FAST_MCP_AVAILABLE:
            self._server = FastMCP(name=name, version=version, instructions=instructions)
            self._mode = "fastmcp"
        else:
            self._server = _SimpleMCPServer(name=name, version=version, instructions=instructions)
            self._mode = "simple"

    def add_tool(self, tool: ToolSpec) -> None:
        if self._mode == "fastmcp":
            self._add_fastmcp_tool(tool)
        else:
            self._server.add_tool(tool)

    def run(self) -> None:
        self._server.run()

    def _add_fastmcp_tool(self, tool: ToolSpec) -> None:
        if FunctionTool is None or FastToolResult is None:
            raise RuntimeError("FastMCP tooling unavailable")

        # Build a closure-based handler with a synthetic signature so FastMCP
        # sees named parameters without resorting to exec()/eval().
        raw_properties = tool.input_schema.get("properties", {})
        properties = raw_properties if isinstance(raw_properties, dict) else {}
        prop_names = [name for name in properties.keys() if isinstance(name, str)]

        async def _handler(**kwargs: object) -> object:
            filtered = {k: v for k, v in kwargs.items() if v is not None}
            raw_result = tool.handler(filtered)
            if _is_awaitable(raw_result):
                result = await cast(Awaitable[ToolResult], raw_result)
            else:
                result = cast(ToolResult, raw_result)
            if not isinstance(result, ToolResult):
                raise TypeError("Tool handler did not return ToolResult")
            return FastToolResult(
                content=result.content,
                structured_content=result.structured_content,
            )

        # Attach a synthetic signature so FastMCP discovers the named parameters.
        params = [
            inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=None, annotation=object)
            for name in prop_names
        ]
        _handler.__signature__ = inspect.Signature(params)  # type: ignore[attr-defined]
        safe_name = tool.name.replace("-", "_").replace(".", "_")
        _handler.__name__ = f"_handler_{safe_name}"

        fast_tool = FunctionTool.from_function(
            _handler,
            name=tool.name,
            description=tool.description,
        )
        # best-effort override of the input schema when FastMCP exposes the field
        fields = getattr(fast_tool.__class__, "model_fields", None)
        if isinstance(fields, dict) and "input_schema" in fields:
            setattr(fast_tool, "input_schema", tool.input_schema)
        self._server.add_tool(fast_tool)


def _is_awaitable(value: object) -> bool:
    try:
        return inspect.isawaitable(value)
    except TypeError:
        return False
