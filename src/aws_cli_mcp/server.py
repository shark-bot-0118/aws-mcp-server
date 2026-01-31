"""Entrypoint for the AWS Tool-Execution MCP server."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aws_cli_mcp import __version__
from aws_cli_mcp.config import load_settings
from aws_cli_mcp.logging_utils import configure_logging
from aws_cli_mcp.mcp_runtime import MCPServer
from aws_cli_mcp.tools import register_tools


def build_server() -> MCPServer:
    """Create and configure the MCP server instance."""

    settings = load_settings()

    server = MCPServer(
        name="aws-cli-mcp",
        version=__version__,
        instructions=settings.server.instructions,
    )
    
    # Re-configure logging AFTER FastMCP init to ensure our handlers (FileHandler) persist
    configure_logging()
    
    import logging
    import sys
    logging.info(f"Initializing AWS CLI MCP Server v{__version__}")
    logging.info(f"Log file configured at: {settings.logging.file}")
    
    # Debug to stderr
    print(f"[DEBUG] Log file path: {settings.logging.file}", file=sys.stderr)
    register_tools(server)
    return server


server = build_server()


if __name__ == "__main__":  # pragma: no cover
    server.run()
