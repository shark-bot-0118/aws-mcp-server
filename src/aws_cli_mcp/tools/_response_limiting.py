"""Response payload limiting and compaction logic."""

from __future__ import annotations

import json

from aws_cli_mcp.utils.serialization import json_default

_DEFAULT_COMPACT_DROP_FIELDS = frozenset(
    {
        "ResponseMetadata",
        "Metadata",
    }
)

_SECONDARY_COMPACT_DROP_FIELDS = frozenset(
    {
        "Environment",
        "Tags",
        "Policy",
        "Policies",
        "PolicyDocument",
        "AssumeRolePolicyDocument",
        "Definition",
        "TemplateBody",
        "Metadata",
        "LoggingConfig",
        "TracingConfig",
        "VpcConfig",
        "UserData",
        "Configuration",
        "Document",
    }
)

_OPERATION_COMPACT_DROP_FIELDS: dict[tuple[str, str], frozenset[str]] = {
    (
        "lambda",
        "listfunctions",
    ): frozenset(
        {
            "Code",
            "CodeSha256",
            "Environment",
            "EnvironmentResponse",
            "FileSystemConfigs",
            "ImageConfigResponse",
            "LastUpdateStatusReason",
            "LastUpdateStatusReasonCode",
            "Layers",
            "LoggingConfig",
            "RuntimeVersionConfig",
            "SigningJobArn",
            "SigningProfileVersionArn",
            "StateReason",
            "StateReasonCode",
            "Tags",
            "TracingConfig",
            "Variables",
            "VpcConfig",
        }
    ),
}

_COMPACT_PRESETS_AUTO: tuple[dict[str, int], ...] = (
    {"max_depth": 4, "max_list_items": 40, "max_string_chars": 400},
    {"max_depth": 3, "max_list_items": 25, "max_string_chars": 250},
    {"max_depth": 2, "max_list_items": 15, "max_string_chars": 160},
    {"max_depth": 1, "max_list_items": 8, "max_string_chars": 96},
)

_COMPACT_PRESETS_COMPACT: tuple[dict[str, int], ...] = (
    {"max_depth": 3, "max_list_items": 20, "max_string_chars": 200},
    {"max_depth": 2, "max_list_items": 10, "max_string_chars": 120},
    {"max_depth": 1, "max_list_items": 6, "max_string_chars": 80},
)


def _json_size(value: object) -> int:
    return len(json.dumps(value, default=json_default, ensure_ascii=True))


def _truncate_json(payload: dict[str, object], limit: int) -> str:
    """Truncate JSON to a maximum length."""
    serialized = json.dumps(payload, default=json_default, ensure_ascii=True)
    if len(serialized) <= limit:
        return serialized
    return serialized[: limit - 3] + "..."


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _parse_response_mode(options: dict[str, object] | None) -> str:
    if not options:
        return "auto"
    raw = options.get("responseMode")
    if not isinstance(raw, str):
        return "auto"
    mode = raw.strip().lower()
    if mode in {"auto", "compact", "full"}:
        return mode
    return "auto"


def _parse_max_result_items(options: dict[str, object] | None) -> int | None:
    if not options:
        return None
    raw = options.get("maxResultItems")
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, (int, str)):
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return None
    return max(1, min(parsed, 200))


def _parse_omit_response_fields(options: dict[str, object] | None) -> set[str]:
    if not options:
        return set()
    raw = options.get("omitResponseFields")
    if not isinstance(raw, list):
        return set()
    fields: set[str] = set()
    for item in raw[:64]:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or len(normalized) > 64:
            continue
        fields.add(normalized)
    return fields


def _operation_drop_fields(
    service: str | None,
    operation: str | None,
    extra_fields: set[str],
) -> set[str]:
    fields = set(_DEFAULT_COMPACT_DROP_FIELDS)
    key = ((service or "").strip().lower(), (operation or "").strip().lower())
    fields.update(_OPERATION_COMPACT_DROP_FIELDS.get(key, frozenset()))
    fields.update(extra_fields)
    return fields


def _drop_field_levels(
    service: str | None,
    operation: str | None,
    extra_fields: set[str],
) -> tuple[set[str], ...]:
    base = _operation_drop_fields(service, operation, extra_fields)
    broadened = set(base)
    broadened.update(_SECONDARY_COMPACT_DROP_FIELDS)
    return base, broadened


def _compact_summary_value(value: object, max_string_chars: int) -> object:
    if isinstance(value, str):
        return _truncate_text(value, max_string_chars)
    if isinstance(value, list):
        return {
            "_mcp_compacted_type": "list",
            "itemCount": len(value),
        }
    if isinstance(value, dict):
        keys = list(value.keys())
        return {
            "_mcp_compacted_type": "object",
            "keyCount": len(keys),
            "keys": keys[:12],
        }
    return value


def _compact_payload(
    value: object,
    *,
    max_depth: int,
    max_list_items: int,
    max_string_chars: int,
    drop_fields: set[str],
    depth: int = 0,
) -> object:
    if isinstance(value, dict):
        compacted: dict[str, object] = {}
        omitted_fields: list[str] = []
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if key in drop_fields:
                omitted_fields.append(key)
                continue
            if depth >= max_depth:
                compacted[key] = _compact_summary_value(raw_value, max_string_chars)
                continue
            compacted[key] = _compact_payload(
                raw_value,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                drop_fields=drop_fields,
                depth=depth + 1,
            )
        if omitted_fields:
            compacted["_mcp_omitted_fields"] = sorted(set(omitted_fields))
        return compacted

    if isinstance(value, list):
        if depth >= max_depth:
            return {
                "_mcp_compacted_type": "list",
                "itemCount": len(value),
            }
        sliced = value[:max_list_items]
        compacted_list = [
            _compact_payload(
                item,
                max_depth=max_depth,
                max_list_items=max_list_items,
                max_string_chars=max_string_chars,
                drop_fields=drop_fields,
                depth=depth + 1,
            )
            for item in sliced
        ]
        if len(value) > max_list_items:
            compacted_list.append({"_mcp_truncated_items": len(value) - max_list_items})
        return compacted_list

    if isinstance(value, str):
        return _truncate_text(value, max_string_chars)

    return value


def _preview_payload(
    payload: dict[str, object],
    safe_limit: int,
    original_chars: int,
    hint: str,
) -> dict[str, object]:
    serialized = json.dumps(payload, default=json_default, ensure_ascii=True)
    return {
        "truncated": True,
        "maxCharacters": safe_limit,
        "originalCharacters": original_chars,
        "strategy": "preview",
        "preview": _truncate_text(serialized, safe_limit),
        "hint": hint,
    }


def _limit_result_payload(
    payload: dict[str, object],
    max_chars: int,
    *,
    service: str | None = None,
    operation: str | None = None,
    options: dict[str, object] | None = None,
) -> dict[str, object]:
    """Limit result payload size while preserving useful structure."""
    safe_limit = max(128, max_chars)
    original_chars = _json_size(payload)
    if original_chars <= safe_limit:
        return payload

    response_mode = _parse_response_mode(options)
    if response_mode == "full":
        return _preview_payload(
            payload,
            safe_limit,
            original_chars,
            "Use options.responseMode='compact' or reduce request scope (pagination/filter).",
        )

    extra_omit_fields = _parse_omit_response_fields(options)
    max_result_items = _parse_max_result_items(options)
    drop_levels = _drop_field_levels(service, operation, extra_omit_fields)
    presets = _COMPACT_PRESETS_COMPACT if response_mode == "compact" else _COMPACT_PRESETS_AUTO

    for drop_fields in drop_levels:
        for preset in presets:
            list_cap = preset["max_list_items"]
            if max_result_items is not None:
                list_cap = min(list_cap, max_result_items)
            compact_result = _compact_payload(
                payload,
                max_depth=preset["max_depth"],
                max_list_items=max(1, list_cap),
                max_string_chars=preset["max_string_chars"],
                drop_fields=drop_fields,
            )
            candidate = {
                "truncated": True,
                "maxCharacters": safe_limit,
                "originalCharacters": original_chars,
                "strategy": "compact",
                "responseMode": response_mode,
                "result": compact_result,
            }
            if _json_size(candidate) <= safe_limit:
                return candidate

    return _preview_payload(
        payload,
        safe_limit,
        original_chars,
        (
            "Compact output still exceeded MAX_OUTPUT_CHARACTERS; "
            "set lower maxResultItems or request a narrower operation scope."
        ),
    )
