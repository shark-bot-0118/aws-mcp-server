"""Entrypoint for the AWS Tool-Execution MCP server."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # pragma: no cover

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
    get_server().run()


def _run_http() -> None:
    settings = load_settings()
    configure_logging()
    from aws_cli_mcp.transport.http_server import create_http_app

    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("uvicorn is required for HTTP transport mode") from exc

    app = create_http_app()
    # This server uses MCP over HTTP and does not expose websocket endpoints.
    uvicorn.run(
        app,
        host=settings.server.host,
        port=settings.server.port,
        ws="none",
        log_config=None,
    )


_server: MCPServer | None = None
_server_lock = threading.Lock()


def get_server() -> MCPServer:
    """Lazily initialise and return the module-level server instance.

    Unlike the previous ``_module_init()`` approach this does NOT execute
    ``load_settings()`` / ``build_server()`` at import time, which improves
    testability and avoids circular-import risks.
    """
    global _server
    if _server is not None:
        return _server
    with _server_lock:
        if _server is None:
            _server = build_server()
        return _server


# Keep for backward compatibility – tests import this.
def _module_init() -> MCPServer | None:
    _settings = load_settings()
    if _is_http_transport(_settings.server.transport_mode):
        return None
    return get_server()


if __name__ == "__main__":  # pragma: no cover
    _settings = load_settings()
    if _is_http_transport(_settings.server.transport_mode):
        _run_http()
    else:
        get_server().run()
