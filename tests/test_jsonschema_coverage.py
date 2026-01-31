
from aws_cli_mcp.utils.jsonschema import validate_payload_structured, format_structured_errors, ValidationError

def test_jsonschema_validators():
    schema = {
        "type": "object",
        "required": ["req"],
        "properties": {
            "req": {"type": "string"},
            "enum_field": {"enum": ["A", "B"]},
            "pattern_field": {"pattern": "^[0-9]+$"},
            "min_len": {"minLength": 3},
            "max_len": {"maxLength": 5},
            "min_val": {"minimum": 10},
            "max_val": {"maximum": 20},
            "format_field": {"format": "email"},
        },
        "additionalProperties": False
    }

    # Payload triggering multiple errors
    payload = {
        # Missing 'req'
        "enum_field": "C",
        "pattern_field": "abc",
        "min_len": "a",
        "max_len": "too_long",
        "min_val": 5,
        "max_val": 25,
        "format_field": "not-email",
        "extra": "prop"
    }
    
    errors = validate_payload_structured(schema, payload)
    formatted = format_structured_errors(errors)
    
    # Verify formatted output (missing)
    # The message for required usually contains the field name
    assert formatted["missing"] is not None
    # We can't guarantee exact message string without relying on jsonschema internals, 
    # but validate_payload_structured handles 'required' validator logic.
    
    # Check if we hit all branches in _classify_error and validation_payload_structured
    error_types = [e.type for e in errors]
    assert "enum_violation" in error_types
    assert "pattern_mismatch" in error_types
    assert "min_length_violation" in error_types
    assert "max_length_violation" in error_types
    assert "minimum_violation" in error_types
    assert "maximum_violation" in error_types
    # Format check depends on if 'format' checker is enabled/installed in jsonschema? 
    # Draft202012Validator should handle it if format checker is provided.
    
    from jsonschema import ValidationError as JSError
    # specific format error mock
    fake_error = JSError("msg", validator="format", validator_value="email", instance="bad")
    
    # Classify it
    from aws_cli_mcp.utils.jsonschema import _classify_error
    assert _classify_error(fake_error) == "format_error"
    
    assert "additional_property" in error_types

def test_jsonschema_helpers():
    # Test specific path in format_structured_errors for missing without single quotes
    
    errors = [
        ValidationError(type="missing_required", message="Some obscure message without quotes", path="path.to.field")
    ]
    formatted = format_structured_errors(errors)
    # Line 186
    assert formatted["missing"] == ["path.to.field"]
    
    # Hints logic (Line 200)
    errors = [
        ValidationError(type="t1", message="m1", hint="h1"),
        ValidationError(type="t2", message="m2", hint="h2"),
    ]
    formatted = format_structured_errors(errors)
    assert formatted["hint"] == "h1 h2"
    
    # Hint > 3 truncation
    errors = [ValidationError(type="t", message="m", hint=f"h{i}") for i in range(4)]
    formatted = format_structured_errors(errors)
    assert formatted["hint"] == "h0 h1 h2"
