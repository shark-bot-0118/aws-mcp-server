
import json
import sys
from io import StringIO
from unittest.mock import MagicMock, patch
from aws_cli_mcp.mcp_runtime import _SimpleMCPServer, MCPServer, ToolSpec, ToolResult

def test_simple_server_initialize(monkeypatch):
    stdin = StringIO(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
    }) + "\n")
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
    stdin = StringIO(json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }) + "\n")
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
    stdin = StringIO(json.dumps({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call", 
        "params": {"name": "t1", "arguments": {}}
    }) + "\n")
    stdout = StringIO()
    
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    
    server = _SimpleMCPServer("test", "1.0", "inst")
    server.add_tool(ToolSpec("t1", "desc", {}, lambda x: ToolResult(content="ok")))
    server.run()
    
    out = stdout.getvalue()
    msg = json.loads(out)
    assert msg["result"]["content"] == "ok"

def test_simple_server_call_unknown(monkeypatch):
    stdin = StringIO(json.dumps({ "method": "tools/call", "params": {"name": "uk"}}) + "\n")
    stdout = StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    
    server = _SimpleMCPServer("test", "1.0", "inst")
    server.run()
    
    out = stdout.getvalue()
    assert "Unknown tool" in out

def test_simple_server_call_error(monkeypatch):
    stdin = StringIO(json.dumps({ "method": "tools/call", "params": {"name": "t1"}}) + "\n")
    stdout = StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    
    def fail(x): raise ValueError("Fail")
    
    server = _SimpleMCPServer("test", "1.0", "inst")
    server.add_tool(ToolSpec("t1", "desc", {}, fail))
    server.run()
    
    out = stdout.getvalue()
    assert "Fail" in out
    
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
                         server.add_tool(
                             ToolSpec("t1", "d", {"properties": {"a": {}}}, lambda x: 1)
                         )
                 
                 MockFT.from_function.assert_called()
