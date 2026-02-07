"""Tool registration helpers.

This module registers the 3 unified AWS tools:
- aws_search_operations: Search AWS operations from Smithy models
- aws_get_operation_schema: Get JSON Schema for an operation
- aws_execute: Validate and invoke AWS operations
"""

from __future__ import annotations

from aws_cli_mcp.logging_utils import get_logger
from aws_cli_mcp.mcp_runtime import MCPServer, ToolSpec
from aws_cli_mcp.tools.aws_unified import (
    execute_tool,
    get_operation_schema_tool,
    search_operations_tool,
)

__all__ = ["get_tool_registry", "get_tool_specs", "register_tools"]


def get_tool_specs() -> list[ToolSpec]:
    return [
        search_operations_tool,
        get_operation_schema_tool,
        execute_tool,
    ]


def get_tool_registry() -> dict[str, ToolSpec]:
    return {tool.name: tool for tool in get_tool_specs()}


def register_tools(server: MCPServer) -> None:
    """Register unified AWS tools with the MCP server.

    Registers exactly 3 tools:
    - aws_search_operations
    - aws_get_operation_schema
    - aws_execute
    """
    logger = get_logger(__name__)
    logger.info("Registering unified AWS tools (3-tool architecture)")

    for tool in get_tool_specs():
        server.add_tool(tool)

    logger.info(
        "Registered 3 unified tools: aws_search_operations, aws_get_operation_schema, aws_execute"
    )
