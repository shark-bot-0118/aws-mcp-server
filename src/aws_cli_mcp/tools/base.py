"""Tool helpers."""

from __future__ import annotations

import json

from aws_cli_mcp.mcp_runtime import ToolResult
from aws_cli_mcp.utils.jsonschema import validate_payload
from aws_cli_mcp.utils.serialization import json_default


def validate_or_raise(schema: dict[str, object], payload: dict[str, object]) -> None:
    errors = validate_payload(schema, payload)
    if errors:
        raise ValueError("Input validation failed: " + "; ".join(errors))


def result_from_payload(payload: dict[str, object]) -> ToolResult:
    text = json.dumps(payload, ensure_ascii=True, indent=2, default=json_default)
    content = [{"type": "text", "text": text}]
    return ToolResult(content=content, structured_content=payload)
