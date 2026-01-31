
from unittest.mock import MagicMock, patch
from aws_cli_mcp.server import build_server

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
