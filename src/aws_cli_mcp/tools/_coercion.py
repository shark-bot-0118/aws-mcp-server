"""Payload type coercion for Smithy model types."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone

from aws_cli_mcp.smithy.parser import (
    ListShape,
    MapShape,
    OperationShape,
    SmithyModel,
    StructureShape,
    UnionShape,
)

_MAX_COERCE_DEPTH = 30


def _coerce_payload_types(
    model: SmithyModel,
    shape_id: str | None,
    payload: dict[str, object],
    path: str = "",
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> dict[str, object]:
    """Recursively coerce payload types to match Smithy model expectations.

    This function handles:
    - blob: base64 string -> bytes
    - integer/long/short/byte: string -> int
    - float/double: string -> float
    - boolean: string "true"/"false" -> bool
    - timestamp: validate ISO 8601 format
    - union: validate exactly one member is set
    - nested structures, lists, and maps
    """

    if depth >= _MAX_COERCE_DEPTH:
        return payload

    if shape_id is None:
        return payload

    shape = model.get_shape(shape_id)
    if shape is None:
        return payload

    # If this is an operation, get its input shape
    if isinstance(shape, OperationShape):
        return _coerce_payload_types(
            model, shape.input, payload, path, service, operation, depth
        )

    # Validate union types - exactly one member must be set
    if isinstance(shape, UnionShape):
        present_members = [name for name in shape.members if name in payload]
        if len(present_members) == 0:
            raise ValueError(
                f"Union type at '{path or 'root'}' requires exactly one member, but none provided. "
                f"Valid members: {list(shape.members.keys())}"
            )
        if len(present_members) > 1:
            raise ValueError(
                f"Union type at '{path or 'root'}' requires exactly one member, "
                f"but got {len(present_members)}: {present_members}"
            )

    if not isinstance(shape, (StructureShape, UnionShape)):
        return payload

    result = dict(payload)
    for field_name, member in shape.members.items():
        if field_name not in result:
            continue

        value = result[field_name]
        target_shape = model.get_shape(member.target)
        field_path = f"{path}.{field_name}" if path else field_name

        if target_shape is None:
            continue

        # Handle blob type - decode base64 string to bytes
        if target_shape.type == "blob":
            result[field_name] = _coerce_blob(value, field_path, service, operation)

        # Handle integer types
        elif target_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result[field_name] = _coerce_integer(value, field_path, target_shape.type)

        # Handle float types
        elif target_shape.type in {"float", "double", "bigDecimal"}:
            result[field_name] = _coerce_float(value, field_path)

        # Handle boolean type
        elif target_shape.type == "boolean":
            result[field_name] = _coerce_boolean(value, field_path)

        # Handle timestamp type
        elif target_shape.type == "timestamp":
            result[field_name] = _coerce_timestamp(value, field_path)

        # Handle nested structures and unions
        elif isinstance(target_shape, (StructureShape, UnionShape)) and isinstance(value, dict):
            result[field_name] = _coerce_payload_types(
                model, member.target, value, field_path, service, operation, depth + 1
            )

        # Handle lists
        elif isinstance(target_shape, ListShape) and isinstance(value, list):
            result[field_name] = _coerce_list(
                model, target_shape, value, field_path, service, operation, depth + 1
            )

        # Handle maps
        elif isinstance(target_shape, MapShape) and isinstance(value, dict):
            result[field_name] = _coerce_map(
                model, target_shape, value, field_path, service, operation, depth + 1
            )

    return result


def _coerce_blob(
    value: object,
    path: str,
    service: str = "",
    operation: str = "",
) -> bytes:
    """Convert base64 string to bytes.

    Supports:
    - bytes: pass through
    - str: base64 decode

    Args:
        value: The value to coerce
        path: Field path for error messages
        service: AWS service name (unused, kept for API compatibility)
        operation: Operation name (unused, kept for API compatibility)

    Returns:
        Bytes content
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding for blob field '{path}': {e}")

    raise ValueError(
        f"Expected base64 string or bytes for blob field '{path}', got {type(value).__name__}"
    )


def _coerce_integer(value: object, path: str, type_name: str) -> int:
    """Convert value to integer with range validation."""
    if isinstance(value, bool):
        # bool is subclass of int, but we don't want to accept it
        raise ValueError(f"Expected integer for '{path}', got boolean")

    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            # Handle numeric strings
            result = int(value)
        except ValueError:
            raise ValueError(f"Cannot convert '{value}' to integer for field '{path}'")
    elif isinstance(value, float):
        if value != int(value):
            raise ValueError(
                f"Cannot convert float {value} with decimal part to integer for field '{path}'"
            )
        result = int(value)
    else:
        raise ValueError(f"Expected integer for '{path}', got {type(value).__name__}")

    # Range validation for bounded types
    ranges = {
        "byte": (-128, 127),
        "short": (-32768, 32767),
        "integer": (-2147483648, 2147483647),
        "long": (-9223372036854775808, 9223372036854775807),
    }
    if type_name in ranges:
        min_val, max_val = ranges[type_name]
        if result < min_val or result > max_val:
            raise ValueError(
                f"Value {result} out of range for {type_name} field '{path}' "
                f"(valid: {min_val} to {max_val})"
            )

    return result


def _coerce_float(value: object, path: str) -> float:
    """Convert value to float."""
    if isinstance(value, bool):
        raise ValueError(f"Expected number for '{path}', got boolean")

    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            raise ValueError(f"Cannot convert '{value}' to number for field '{path}'")

    raise ValueError(f"Expected number for '{path}', got {type(value).__name__}")


def _coerce_boolean(value: object, path: str) -> bool:
    """Convert value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lower = value.lower()
        if lower in {"true", "yes", "1", "on"}:
            return True
        if lower in {"false", "no", "0", "off"}:
            return False
        raise ValueError(
            f"Cannot convert '{value}' to boolean for field '{path}'. "
            f"Valid string values: true/false, yes/no, 1/0, on/off"
        )
    if isinstance(value, (int, float)):
        return bool(value)

    raise ValueError(f"Expected boolean for '{path}', got {type(value).__name__}")


def _coerce_timestamp(value: object, path: str) -> str:
    """Validate and normalize timestamp value."""
    if not isinstance(value, str):
        if isinstance(value, (int, float)):
            # Unix timestamp - convert to ISO format
            try:
                dt = datetime.fromtimestamp(value, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OSError, OverflowError, ValueError) as e:
                raise ValueError(f"Invalid unix timestamp {value} for field '{path}': {e}")
        raise ValueError(
            f"Expected timestamp string or unix timestamp for '{path}', got {type(value).__name__}"
        )

    # Validate ISO 8601 format - try multiple common formats
    # Normalize the value for parsing
    normalized = value.replace("+00:00", "+0000").replace("-00:00", "+0000")

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f+0000",
        "%Y-%m-%dT%H:%M:%S+0000",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            datetime.strptime(normalized, fmt)
            return value  # Return original if valid
        except ValueError:
            continue

    # Try parsing with timezone offset pattern (e.g., +09:00, -05:00)
    tz_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2})?$"
    if re.match(tz_pattern, value):
        return value

    raise ValueError(
        f"Invalid timestamp format for field '{path}': '{value}'. "
        f"Expected ISO 8601 format (e.g., '2024-01-01T00:00:00Z' or '2024-01-01')"
    )


def _coerce_list(
    model: SmithyModel,
    list_shape: ListShape,
    value: list[object],
    path: str,
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> list[object]:
    """Coerce list items to expected types."""

    if depth >= _MAX_COERCE_DEPTH:
        return value

    item_shape = model.get_shape(list_shape.member.target)
    if item_shape is None:
        return value

    result: list[object] = []
    for i, item in enumerate(value):
        item_path = f"{path}[{i}]"

        if item_shape.type == "blob":
            result.append(_coerce_blob(item, item_path, service, operation))
        elif item_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result.append(_coerce_integer(item, item_path, item_shape.type))
        elif item_shape.type in {"float", "double", "bigDecimal"}:
            result.append(_coerce_float(item, item_path))
        elif item_shape.type == "boolean":
            result.append(_coerce_boolean(item, item_path))
        elif item_shape.type == "timestamp":
            result.append(_coerce_timestamp(item, item_path))
        elif isinstance(item_shape, (StructureShape, UnionShape)) and isinstance(item, dict):
            result.append(
                _coerce_payload_types(
                    model, list_shape.member.target, item, item_path, service, operation, depth + 1
                )
            )
        else:
            result.append(item)

    return result


def _coerce_map(
    model: SmithyModel,
    map_shape: MapShape,
    value: dict[str, object],
    path: str,
    service: str = "",
    operation: str = "",
    depth: int = 0,
) -> dict[str, object]:
    """Coerce map values to expected types."""

    if depth >= _MAX_COERCE_DEPTH:
        return value

    value_shape = model.get_shape(map_shape.value.target)
    if value_shape is None:
        return value

    result: dict[str, object] = {}
    for k, v in value.items():
        item_path = f"{path}.{k}"

        if value_shape.type == "blob":
            result[k] = _coerce_blob(v, item_path, service, operation)
        elif value_shape.type in {"integer", "long", "short", "byte", "bigInteger"}:
            result[k] = _coerce_integer(v, item_path, value_shape.type)
        elif value_shape.type in {"float", "double", "bigDecimal"}:
            result[k] = _coerce_float(v, item_path)
        elif value_shape.type == "boolean":
            result[k] = _coerce_boolean(v, item_path)
        elif value_shape.type == "timestamp":
            result[k] = _coerce_timestamp(v, item_path)
        elif isinstance(value_shape, (StructureShape, UnionShape)) and isinstance(v, dict):
            result[k] = _coerce_payload_types(
                model, map_shape.value.target, v, item_path, service, operation, depth + 1
            )
        else:
            result[k] = v

    return result
