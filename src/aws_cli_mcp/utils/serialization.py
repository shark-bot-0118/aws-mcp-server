"""JSON serialization utilities."""

from __future__ import annotations

import base64
import datetime
import decimal
from itertools import islice

_MAX_SERIALIZE_BYTES = 10 * 1024 * 1024  # 10 MB
_MAX_ITERABLE_ITEMS = 10_000


def json_default(obj: object) -> object:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        # Preserve numeric type: convert to int if no decimal part, else float.
        # For very large values that would lose precision as float, use string.
        if obj == obj.to_integral_value():
            return int(obj)
        f = float(obj)
        if decimal.Decimal(str(f)) != obj:
            return str(obj)  # precision loss — use string representation
        return f
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

    # Handle Iterables (EventStream, etc.) - excluding str/bytes/dict/list.
    # Bounded via islice to prevent OOM on infinite/huge iterables.
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes, dict, list)):
        try:
            return list(islice(obj, _MAX_ITERABLE_ITEMS))
        except (TypeError, StopIteration):
            pass

    return str(obj)
