"""Tool registration helpers.

This module registers the 3 unified AWS tools:
- aws.searchOperations: Search AWS operations from Smithy models
- aws.getOperationSchema: Get JSON Schema for an operation
- aws.execute: Validate and invoke AWS operations
"""

from __future__ import annotations

from aws_cli_mcp.logging_utils import get_logger
from aws_cli_mcp.mcp_runtime import MCPServer
from aws_cli_mcp.tools.aws_unified import (
    aws_execute_tool,
    aws_get_operation_schema_tool,
    aws_search_operations_tool,
)

__all__ = ["register_tools"]


def register_tools(server: MCPServer) -> None:
    """Register unified AWS tools with the MCP server.

    Registers exactly 3 tools:
    - aws.searchOperations
    - aws.getOperationSchema
    - aws.execute
    """
    logger = get_logger(__name__)
    logger.info("Registering unified AWS tools (3-tool architecture)")

    server.add_tool(aws_search_operations_tool)
    server.add_tool(aws_get_operation_schema_tool)
    server.add_tool(aws_execute_tool)

    logger.info("Registered 3 unified tools: aws.searchOperations, aws.getOperationSchema, aws.execute")
