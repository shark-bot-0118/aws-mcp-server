"""MCP runtime adapter with optional FastMCP support."""

from __future__ import annotations

import inspect
import json
import sys
from dataclasses import dataclass
from typing import Awaitable, Callable

from pydantic import BaseModel


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
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                self._write_error(None, "Invalid JSON")
                continue

            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            if method == "initialize":
                result = {
                    "serverInfo": {"name": self._name, "version": self._version},
                    "instructions": self._instructions,
                    "capabilities": {"tools": {}},
                }
                self._write_result(request_id, result)
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
                name = params.get("name")
                arguments = params.get("arguments", {})
                if name not in self._tools:
                    self._write_error(request_id, f"Unknown tool: {name}")
                    continue
                try:
                    result = self._tools[name].handler(arguments)
                    if _is_awaitable(result):
                        import asyncio

                        result = asyncio.run(result)
                except Exception as exc:  # pragma: no cover - error path
                    self._write_error(request_id, str(exc))
                    continue
                payload = {
                    "content": result.content,
                    "structuredContent": result.structured_content,
                }
                self._write_result(request_id, payload)
            else:
                self._write_error(request_id, f"Unsupported method: {method}")

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


try:  # optional FastMCP support
    from fastmcp import FastMCP  # type: ignore
    from fastmcp.tools import FunctionTool  # type: ignore
    from fastmcp.tools.tool import ToolResult as FastToolResult  # type: ignore

    _FAST_MCP_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    FastMCP = None
    FunctionTool = None
    FastToolResult = None
    _FAST_MCP_AVAILABLE = False


class MCPServer:
    """Adapter that uses FastMCP when available or a minimal stdio server otherwise."""

    def __init__(self, name: str, version: str, instructions: str) -> None:
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
        prop_names = list(tool.input_schema.get("properties", {}).keys())

        async def _handler(**kwargs: object) -> "FastToolResult":
            filtered = {k: v for k, v in kwargs.items() if v is not None}
            result = tool.handler(filtered)
            if _is_awaitable(result):
                result = await result
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
            fast_tool.input_schema = tool.input_schema
        self._server.add_tool(fast_tool)


def _is_awaitable(value: object) -> bool:
    try:
        import inspect

        return inspect.isawaitable(value)
    except Exception:
        return False
