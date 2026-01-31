

from datetime import datetime, timezone
from decimal import Decimal
from aws_cli_mcp.utils.jsonschema import validate_payload, validate_payload_structured, format_structured_errors
from aws_cli_mcp.utils.serialization import json_default

def test_validate_payload():
    schema = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}
    
    # Valid
    assert validate_payload(schema, {"a": 1}) == []
    
    # Invalid
    errors = validate_payload(schema, {"a": "bad"})
    assert len(errors) > 0

def test_validate_payload_structured():
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "integer"},
            "b": {"enum": ["x", "y"]},
            "c": {"type": "string", "minLength": 5}
        },
        "required": ["a"]
    }
    
    # Valid
    assert validate_payload_structured(schema, {"a": 1}) == []
    
    # Invalid: missing required
    errors = validate_payload_structured(schema, {})
    assert len(errors) == 1
    assert errors[0].type == "missing_required"
    
    # Invalid: type mismatch
    errors = validate_payload_structured(schema, {"a": "bad"})
    assert len(errors) == 1
    assert errors[0].type == "invalid_type"
    
    # Invalid: enum
    errors = validate_payload_structured(schema, {"a": 1, "b": "z"})
    assert len(errors) == 1
    assert errors[0].type == "enum_violation"
    
    # Invalid: minLength
    errors = validate_payload_structured(schema, {"a": 1, "c": "abc"})
    assert len(errors) == 1
    assert errors[0].type == "min_length_violation"

def test_format_structured_errors():
    from aws_cli_mcp.utils.jsonschema import ValidationError
    errors = [
        ValidationError(type="missing_required", message="Missing 'a'", path="a", hint="Add a"),
        ValidationError(type="invalid_type", message="Wrong type", path="b", expected="int", got="str")
    ]
    
    formatted = format_structured_errors(errors)
    assert "missing" in formatted
    assert "invalid" in formatted
    assert formatted["missing"] == ["a"]
    assert formatted["invalid"][0]["path"] == "b"


def test_json_default():
    # Datetime
    dt = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert json_default(dt) == "2023-01-01T12:00:00+00:00"
    
    # Bytes
    assert json_default(b"hello") == "hello" # decoded
    
    # Decimal
    assert json_default(Decimal("10.5")) == 10.5
    assert json_default(Decimal("10")) == 10
    
    # Unknown
    class Obj: pass
    assert str(json_default(Obj())).startswith("<")

    # Streams
    class Stream:
        def read(self): return b"content"
    assert json_default(Stream()) == "content"
    
    class EmptyStream:
        def read(self): return b""
    assert json_default(EmptyStream()) == ""

    class TextStream:
        def read(self): return "text"
    assert json_default(TextStream()) == "text"

    class ErrorStream:
        def read(self): raise Exception("Network")
    assert json_default(ErrorStream()) == ""

    # Iterables
    class Gen:
        def __iter__(self): yield 1; yield 2
    assert json_default(Gen()) == [1, 2]
    
    # Verify list/dict/str not treated as generic iterable

    # Wait, json_default is for objects NOT serializable by default.
    # List is serializable, so it shouldn't reach here in normal json.dumps use.
    # But if called directly:
    # Logic: if hasattr(__iter__) and not isinstance(str, bytes, dict, list)
    # So list is skipped by that check.
    # Fallback is str(obj).
    assert json_default([1]) == "[1]" # logic: str([1]) 

