import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aws_cli_mcp.server import _module_init, _run_http, build_server, get_server


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server.MCPServer")
@patch("aws_cli_mcp.server.register_tools")
@patch("aws_cli_mcp.server.configure_logging")
def test_build_server(mock_log, mock_register, mock_server_cls, mock_settings):
    # Setup mocks
    settings = MagicMock()
    settings.server.instructions = "Instructions"
    settings.logging.file = "test.log"
    mock_settings.return_value = settings

    mock_instance = MagicMock()
    mock_server_cls.return_value = mock_instance

    # Run
    server = build_server()

    # Verify
    mock_settings.assert_called_once()
    mock_server_cls.assert_called_once()
    assert mock_server_cls.call_args[1]["name"] == "aws-cli-mcp"
    assert mock_server_cls.call_args[1]["instructions"] == "Instructions"

    mock_log.assert_called_once()
    mock_register.assert_called_once_with(mock_instance)
    assert server == mock_instance


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server.configure_logging")
@patch("aws_cli_mcp.transport.http_server.create_http_app")
def test_run_http_configures_logging(mock_create_http_app, mock_log, mock_settings):
    settings = MagicMock()
    settings.server.host = "0.0.0.0"
    settings.server.port = 8000
    mock_settings.return_value = settings

    uvicorn_run = MagicMock()
    with patch.dict(sys.modules, {"uvicorn": SimpleNamespace(run=uvicorn_run)}):
        _run_http()

    mock_log.assert_called_once()
    mock_create_http_app.assert_called_once_with()
    uvicorn_run.assert_called_once_with(
        mock_create_http_app.return_value,
        host=settings.server.host,
        port=settings.server.port,
        ws="none",
        log_config=None,
    )


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server._run_http")
def test_run_entrypoint_http_branch(mock_run_http, mock_load_settings):
    from aws_cli_mcp.server import run_entrypoint

    settings = MagicMock()
    settings.server.transport_mode = "http"
    mock_load_settings.return_value = settings

    run_entrypoint()
    mock_run_http.assert_called_once_with()


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server.get_server")
def test_run_entrypoint_stdio_branch(mock_get_server, mock_load_settings):
    from aws_cli_mcp.server import run_entrypoint

    settings = MagicMock()
    settings.server.transport_mode = "stdio"
    mock_load_settings.return_value = settings

    server = MagicMock()
    mock_get_server.return_value = server

    run_entrypoint()
    server.run.assert_called_once_with()


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server.configure_logging")
def test_run_http_raises_without_uvicorn(mock_log, mock_load_settings):
    settings = MagicMock()
    settings.server.host = "0.0.0.0"
    settings.server.port = 8000
    mock_load_settings.return_value = settings

    original_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("no uvicorn")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(RuntimeError, match="uvicorn is required"):
            _run_http()


@patch("aws_cli_mcp.server.load_settings")
@patch("aws_cli_mcp.server.build_server")
def test_module_init_uses_build_server_in_stdio(mock_build_server, mock_load_settings):
    settings = MagicMock()
    settings.server.transport_mode = "stdio"
    mock_load_settings.return_value = settings
    sentinel = MagicMock()
    mock_build_server.return_value = sentinel
    assert _module_init() is sentinel


@patch("aws_cli_mcp.server.load_settings")
def test_module_init_returns_none_for_http(mock_load_settings):
    settings = MagicMock()
    settings.server.transport_mode = "http"
    mock_load_settings.return_value = settings
    assert _module_init() is None


@patch("aws_cli_mcp.server.build_server")
def test_get_server_lazy_initializes_once(mock_build_server):
    import aws_cli_mcp.server as server_module

    old_server = server_module._server
    server_module._server = None
    try:
        sentinel = MagicMock()
        mock_build_server.return_value = sentinel

        assert get_server() is sentinel
        assert get_server() is sentinel
        mock_build_server.assert_called_once_with()
    finally:
        server_module._server = old_server
