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


def _is_http_transport(mode: str) -> bool:
    return mode in {"http", "remote"}


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

    logging.info("Initializing AWS CLI MCP Server v%s", __version__)
    logging.info("Log file configured at: %s", settings.logging.file)
    register_tools(server)
    return server


def run_entrypoint() -> None:
    """Run the server based on transport settings."""
    settings = load_settings()
    if _is_http_transport(settings.server.transport_mode):
        _run_http()
        return
    server = build_server()
    server.run()


def _run_http() -> None:
    settings = load_settings()
    from aws_cli_mcp.transport.http_server import create_http_app

    try:
        import uvicorn  # type: ignore
    except Exception as exc:
        raise RuntimeError("uvicorn is required for HTTP transport mode") from exc

    app = create_http_app()
    uvicorn.run(app, host=settings.server.host, port=settings.server.port)


def _module_init() -> MCPServer | None:
    """Initialise the module-level server instance.

    Separated from bare module scope so the side-effect (loading settings,
    building a server) is explicit and testable.
    """
    _settings = load_settings()
    if _is_http_transport(_settings.server.transport_mode):
        return None
    return build_server()


server = _module_init()


if __name__ == "__main__":  # pragma: no cover
    _settings = load_settings()
    if _is_http_transport(_settings.server.transport_mode):
        _run_http()
    else:
        if server is None:
            server = build_server()
        server.run()
