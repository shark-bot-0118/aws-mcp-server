"""JSON Schema validation wrapper."""

from __future__ import annotations

from dataclasses import dataclass

from jsonschema import Draft202012Validator


@dataclass
class ValidationError:
    """Structured validation error for machine-readable error reporting.

    Attributes:
        type: Error category (missing_required, invalid_type, pattern_mismatch,
              enum_violation, additional_property, format_error, etc.)
        message: Human-readable error message.
        path: JSON path to the invalid field (e.g., "params.FunctionName").
        expected: Expected type or value.
        got: Actual type or value received.
        allowed_values: List of valid values for enum violations.
        hint: Actionable suggestion for fixing the error.
    """

    type: str
    message: str
    path: str | None = None
    expected: str | None = None
    got: str | None = None
    allowed_values: list[str] | None = None
    hint: str | None = None


def validate_payload(schema: dict[str, object], payload: dict[str, object]) -> list[str]:
    """Validate payload against schema and return error messages.

    Args:
        schema: JSON Schema to validate against.
        payload: Data to validate.

    Returns:
        List of error message strings.
    """
    validator = Draft202012Validator(schema)
    errors = [error.message for error in validator.iter_errors(payload)]
    return errors


def validate_payload_structured(
    schema: dict[str, object],
    payload: dict[str, object],
) -> list[ValidationError]:
    """Validate payload and return structured validation errors.

    Args:
        schema: JSON Schema to validate against.
        payload: Data to validate.

    Returns:
        List of ValidationError objects with detailed error information.
    """
    validator = Draft202012Validator(schema)
    errors: list[ValidationError] = []

    for error in validator.iter_errors(payload):
        path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else None
        error_type = _classify_error(error)
        allowed_values = None
        expected = None
        got = None
        hint = None

        if error.validator == "required":
            missing = error.validator_value
            if isinstance(missing, list) and len(missing) == 1:
                field_name = missing[0]
            else:
                field_name = str(missing)
            hint = f"Add the required field '{field_name}' to your request."
            expected = "field to be present"

        elif error.validator == "type":
            expected = error.validator_value
            got = type(error.instance).__name__ if error.instance is not None else "null"
            hint = f"Change the value to type '{expected}'."

        elif error.validator == "enum":
            allowed_values = list(error.validator_value) if error.validator_value else None
            got = str(error.instance) if error.instance is not None else "null"
            if allowed_values:
                hint = f"Use one of: {', '.join(str(v) for v in allowed_values)}"

        elif error.validator == "pattern":
            expected = f"pattern: {error.validator_value}"
            got = str(error.instance) if error.instance is not None else "null"
            hint = f"Value must match the pattern: {error.validator_value}"

        elif error.validator == "minLength":
            expected = f"minimum length {error.validator_value}"
            got = f"length {len(error.instance)}" if error.instance else "empty"
            hint = f"Provide a value with at least {error.validator_value} character(s)."

        elif error.validator == "maxLength":
            expected = f"maximum length {error.validator_value}"
            got = f"length {len(error.instance)}" if error.instance else "0"
            hint = f"Provide a value with at most {error.validator_value} character(s)."

        elif error.validator == "minimum":
            expected = f">= {error.validator_value}"
            got = str(error.instance)
            hint = f"Provide a value greater than or equal to {error.validator_value}."

        elif error.validator == "maximum":
            expected = f"<= {error.validator_value}"
            got = str(error.instance)
            hint = f"Provide a value less than or equal to {error.validator_value}."

        elif error.validator == "additionalProperties":
            got = str(error.instance) if error.instance else None
            hint = "Remove the unexpected property or check for typos."

        elif error.validator == "format":
            expected = f"format: {error.validator_value}"
            got = str(error.instance) if error.instance else "null"
            hint = f"Value must be a valid {error.validator_value}."

        errors.append(
            ValidationError(
                type=error_type,
                message=error.message,
                path=path,
                expected=expected,
                got=got,
                allowed_values=allowed_values,
                hint=hint,
            )
        )

    return errors


def _classify_error(error) -> str:
    """Classify a jsonschema error into a human-readable type."""
    validator_to_type = {
        "required": "missing_required",
        "type": "invalid_type",
        "enum": "enum_violation",
        "pattern": "pattern_mismatch",
        "minLength": "min_length_violation",
        "maxLength": "max_length_violation",
        "minimum": "minimum_violation",
        "maximum": "maximum_violation",
        "additionalProperties": "additional_property",
        "format": "format_error",
        "const": "const_mismatch",
        "oneOf": "one_of_violation",
        "anyOf": "any_of_violation",
        "allOf": "all_of_violation",
        "not": "not_violation",
        "if": "conditional_violation",
        "uniqueItems": "duplicate_items",
        "minItems": "min_items_violation",
        "maxItems": "max_items_violation",
    }
    return validator_to_type.get(error.validator, "validation_error")


def format_structured_errors(errors: list[ValidationError]) -> dict[str, object]:
    """Format structured errors for API response.

    Args:
        errors: List of ValidationError objects.

    Returns:
        Dictionary suitable for error response payload.
    """
    missing = []
    invalid = []
    allowed_values_map: dict[str, list[str]] = {}

    for err in errors:
        if err.type == "missing_required":
            if "'" in err.message:
                field = err.message.split("'")[1]
            else:
                field = err.path or "unknown"
            missing.append(field)
        else:
            invalid.append({
                "path": err.path,
                "type": err.type,
                "expected": err.expected,
                "got": err.got,
                "reason": err.message,
            })
            if err.allowed_values and err.path:
                allowed_values_map[err.path] = err.allowed_values

    hints = [err.hint for err in errors if err.hint]
    hint = hints[0] if len(hints) == 1 else " ".join(hints[:3]) if hints else None

    return {
        "missing": missing if missing else None,
        "invalid": invalid if invalid else None,
        "allowedValues": allowed_values_map if allowed_values_map else None,
        "hint": hint,
        "retryable": True,
    }
