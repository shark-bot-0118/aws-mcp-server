from __future__ import annotations

import pytest

from aws_cli_mcp.tools.base import result_from_payload, validate_or_raise


def test_validate_or_raise_raises_on_invalid_input() -> None:
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    with pytest.raises(ValueError, match="Input validation failed"):
        validate_or_raise(schema, {"name": 123})


def test_result_from_payload_builds_tool_result() -> None:
    result = result_from_payload({"ok": True})
    assert result.structured_content == {"ok": True}
    assert result.content[0]["type"] == "text"
