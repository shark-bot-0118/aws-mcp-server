"""Tests for tool registry helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aws_cli_mcp.tools import get_tool_registry, get_tool_specs, register_tools


def test_get_tool_specs_and_registry() -> None:
    specs = get_tool_specs()
    names = [tool.name for tool in specs]
    assert names == ["aws_search_operations", "aws_get_operation_schema", "aws_execute"]

    registry = get_tool_registry()
    assert set(registry.keys()) == set(names)


def test_register_tools_adds_all_specs() -> None:
    server = MagicMock()
    with patch("aws_cli_mcp.tools.logging") as mock_logging:
        logger = MagicMock()
        mock_logging.getLogger.return_value = logger
        register_tools(server)

    assert server.add_tool.call_count == 3
    assert logger.info.call_count >= 2
