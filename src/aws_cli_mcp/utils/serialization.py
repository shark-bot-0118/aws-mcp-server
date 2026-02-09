"""JSON serialization utilities."""

from __future__ import annotations

import base64
import datetime
import decimal

_MAX_SERIALIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def json_default(obj: object) -> object:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        # Preserve numeric type: convert to int if no decimal part, else float
        # This allows the value to be used as input to subsequent API calls
        if obj == obj.to_integral_value():
            return int(obj)
        return float(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(obj).decode("utf-8")

    # Handle Streams (StreamingBody, etc.)
    if hasattr(obj, "read") and callable(obj.read):
        try:
            content = obj.read(_MAX_SERIALIZE_BYTES)
            if not content:
                return ""
            if isinstance(content, bytes):
                try:
                    return content.decode("utf-8")
                except UnicodeDecodeError:
                    return base64.b64encode(content).decode("utf-8")
            return content
        except (OSError, UnicodeDecodeError):
            return ""

    # Handle Iterables (EventStream, etc.) - excluding str/bytes/dict/list
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes, dict, list)):
        try:
            return list(obj)
        except (TypeError, StopIteration):
            pass

    return str(obj)
