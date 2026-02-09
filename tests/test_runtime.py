import asyncio
import inspect
import json
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from aws_cli_mcp.mcp_runtime import MCPServer, ToolResult, ToolSpec, _is_awaitable, _SimpleMCPServer


def test_simple_server_initialize(monkeypatch):
    stdin = StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
    )
    stdout = StringIO()

    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.run()

    out = stdout.getvalue()
    msg = json.loads(out)
    assert msg["id"] == 1
    assert msg["result"]["serverInfo"]["name"] == "test"


def test_simple_server_tools_list(monkeypatch):
    stdin = StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    )
    stdout = StringIO()

    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.add_tool(ToolSpec("t1", "desc", {}, lambda x: ToolResult(content="ok")))
    server.run()

    out = stdout.getvalue()
    msg = json.loads(out)
    assert len(msg["result"]["tools"]) == 1
    assert msg["result"]["tools"][0]["name"] == "t1"


def test_simple_server_tools_call(monkeypatch):
    stdin = StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "t1", "arguments": {}},
            }
        )
        + "\n"
    )
    stdout = StringIO()

    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.add_tool(
        ToolSpec("t1", "desc", {}, lambda x: ToolResult(content=[{"type": "text", "text": "ok"}]))
    )
    server.run()

    out = stdout.getvalue()
    msg = json.loads(out)
    assert msg["result"]["content"] == [{"type": "text", "text": "ok"}]


def test_simple_server_call_unknown(monkeypatch):
    stdin = StringIO(json.dumps({"method": "tools/call", "params": {"name": "uk"}}) + "\n")
    stdout = StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.run()

    out = stdout.getvalue()
    assert "Unknown tool" in out


def test_simple_server_call_error(monkeypatch):
    stdin = StringIO(json.dumps({"method": "tools/call", "params": {"name": "t1"}}) + "\n")
    stdout = StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    def fail(x):
        raise ValueError("Fail")

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.add_tool(ToolSpec("t1", "desc", {}, fail))
    server.run()

    out = stdout.getvalue()
    # Exception details are masked — only generic message returned to client.
    assert "Internal tool error" in out


def test_simple_server_invalid_json(monkeypatch):
    stdin = StringIO("INVALID\n")
    stdout = StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    server = _SimpleMCPServer("test", "1.0", "inst")
    server.run()

    out = stdout.getvalue()
    assert "Invalid JSON" in out


def test_mcp_server_simple_mode():
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", False):
        server = MCPServer("name", "v1", "ins")
        assert server._mode == "simple"
        server.add_tool(ToolSpec("t1", "d", {}, lambda x: 1))
        # No error


def test_mcp_server_fast_mode():
    # Mock FastMCP imports and availability
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", True):
        with patch("aws_cli_mcp.mcp_runtime.FastMCP"):
            with patch("aws_cli_mcp.mcp_runtime.FunctionTool") as MockFT:
                MockFT.from_function.return_value = MagicMock()

                server = MCPServer("name", "v1", "ins")
                assert server._mode == "fastmcp"

                # Need FunctionTool and FastToolResult available in module scope or mocked
                with patch("aws_cli_mcp.mcp_runtime.FunctionTool", MockFT):
                    with patch("aws_cli_mcp.mcp_runtime.FastToolResult"):
                        server.add_tool(ToolSpec("t1", "d", {"properties": {"a": {}}}, lambda x: 1))

                MockFT.from_function.assert_called()


def test_mcp_server_run_delegates():
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", False):
        server = MCPServer("name", "v1", "ins")
    server._server = MagicMock()
    server.run()
    server._server.run.assert_called_once_with()


def test_add_fastmcp_tool_raises_when_tooling_unavailable():
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", True):
        with patch("aws_cli_mcp.mcp_runtime.FastMCP"):
            server = MCPServer("name", "v1", "ins")

    with patch("aws_cli_mcp.mcp_runtime.FunctionTool", None):
        with patch("aws_cli_mcp.mcp_runtime.FastToolResult", None):
            with patch.object(server, "_mode", "fastmcp"):
                with pytest.raises(RuntimeError, match="FastMCP tooling unavailable"):
                    server.add_tool(
                        ToolSpec(
                            name="tool",
                            description="desc",
                            input_schema={"properties": {"a": {}}},
                            handler=lambda payload: ToolResult(
                                content=[{"type": "text", "text": str(payload)}]
                            ),
                        )
                    )


def test_add_fastmcp_tool_handler_filters_none_and_sets_input_schema():
    captured = {"handler": None}
    result_holder = {"result": None}

    class FakeFastToolResult:
        def __init__(self, content, structured_content):
            self.content = content
            self.structured_content = structured_content

    class FakeTool:
        model_fields = {"input_schema": object()}

    fake_tool = FakeTool()

    def _from_function(handler, **kwargs):
        captured["handler"] = handler
        return fake_tool

    fake_server = MagicMock()
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", True):
        with patch("aws_cli_mcp.mcp_runtime.FastMCP", return_value=fake_server):
            with patch("aws_cli_mcp.mcp_runtime.FunctionTool") as mock_function_tool:
                with patch("aws_cli_mcp.mcp_runtime.FastToolResult", FakeFastToolResult):
                    mock_function_tool.from_function.side_effect = _from_function
                    server = MCPServer("name", "v1", "ins")

                    async def _handler(payload):
                        return ToolResult(
                            content=[{"type": "text", "text": str(payload)}],
                            structured_content={"ok": True},
                        )

                    server.add_tool(
                        ToolSpec(
                            name="my.tool",
                            description="desc",
                            input_schema={"properties": {"a": {}, "b": {}}},
                            handler=_handler,
                        )
                    )

                    assert captured["handler"] is not None
                    result_holder["result"] = asyncio.run(captured["handler"](a=1, b=None))

    result = result_holder["result"]
    assert isinstance(result, FakeFastToolResult)
    assert "b" not in result.content[0]["text"]
    assert fake_tool.input_schema == {"properties": {"a": {}, "b": {}}}
    fake_server.add_tool.assert_called_once_with(fake_tool)


def test_is_awaitable_exception_path(monkeypatch):
    def _raise(_value):
        raise TypeError("boom")

    monkeypatch.setattr(inspect, "isawaitable", _raise)
    assert _is_awaitable(object()) is False


def test_add_fastmcp_tool_handler_sync_non_toolresult_raises() -> None:
    captured = {"handler": None}

    class FakeFastToolResult:
        def __init__(self, content, structured_content):
            self.content = content
            self.structured_content = structured_content

    class FakeTool:
        model_fields = {"input_schema": object()}

    def _from_function(handler, **kwargs):
        captured["handler"] = handler
        return FakeTool()

    fake_server = MagicMock()
    with patch("aws_cli_mcp.mcp_runtime._FAST_MCP_AVAILABLE", True):
        with patch("aws_cli_mcp.mcp_runtime.FastMCP", return_value=fake_server):
            with patch("aws_cli_mcp.mcp_runtime.FunctionTool") as mock_function_tool:
                with patch("aws_cli_mcp.mcp_runtime.FastToolResult", FakeFastToolResult):
                    mock_function_tool.from_function.side_effect = _from_function
                    server = MCPServer("name", "v1", "ins")
                    server.add_tool(
                        ToolSpec(
                            name="sync.tool",
                            description="desc",
                            input_schema={"properties": {"a": {}}},
                            handler=lambda payload: {"not": "tool-result"},
                        )
                    )

    assert captured["handler"] is not None
    with pytest.raises(TypeError, match="Tool handler did not return ToolResult"):
        asyncio.run(captured["handler"](a=1))
