import socket
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aws_cli_mcp.utils.http import normalize_public_base_url, validate_oidc_url
from aws_cli_mcp.utils.jsonschema import (
    format_structured_errors,
    validate_payload,
    validate_payload_structured,
)
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
            "c": {"type": "string", "minLength": 5},
        },
        "required": ["a"],
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
        ValidationError(
            type="invalid_type", message="Wrong type", path="b", expected="int", got="str"
        ),
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
    assert json_default(b"hello") == "hello"  # decoded

    # Decimal
    assert json_default(Decimal("10.5")) == 10.5
    assert json_default(Decimal("10")) == 10

    # Unknown
    class Obj:
        pass

    assert str(json_default(Obj())).startswith("<")

    # Streams
    class Stream:
        def read(self, size=-1):
            return b"content"

    assert json_default(Stream()) == "content"

    class EmptyStream:
        def read(self, size=-1):
            return b""

    assert json_default(EmptyStream()) == ""

    class TextStream:
        def read(self, size=-1):
            return "text"

    assert json_default(TextStream()) == "text"

    class ErrorStream:
        def read(self, size=-1):
            raise OSError("Network")

    assert json_default(ErrorStream()) == ""

    # Iterables
    class Gen:
        def __iter__(self):
            yield 1
            yield 2

    assert json_default(Gen()) == [1, 2]

    # Verify list/dict/str not treated as generic iterable

    # Wait, json_default is for objects NOT serializable by default.
    # List is serializable, so it shouldn't reach here in normal json.dumps use.
    # But if called directly:
    # Logic: if hasattr(__iter__) and not isinstance(str, bytes, dict, list)
    # So list is skipped by that check.
    # Fallback is str(obj).
    assert json_default([1]) == "[1]"  # logic: str([1])


def test_json_default_binary_fallback_paths():
    # bytes that cannot be UTF-8 should be base64-encoded
    assert json_default(b"\xff") == "/w=="

    class BinaryStream:
        def read(self, size=-1):
            return b"\xff"

    assert json_default(BinaryStream()) == "/w=="

    class BadIter:
        def __iter__(self):
            raise TypeError("boom")

    rendered = json_default(BadIter())
    assert "BadIter" in rendered


def test_validate_payload_structured_required_multi_and_format_branch():
    from aws_cli_mcp.utils import jsonschema as mod

    class FakeError:
        def __init__(self, validator, validator_value, instance, path, message):
            self.validator = validator
            self.validator_value = validator_value
            self.instance = instance
            self.absolute_path = path
            self.message = message

    class FakeValidator:
        def __init__(self, schema):
            self.schema = schema

        def iter_errors(self, payload):
            return [
                FakeError(
                    validator="required",
                    validator_value=["a", "b"],
                    instance={},
                    path=[],
                    message="required fields missing",
                ),
                FakeError(
                    validator="format",
                    validator_value="email",
                    instance="not-email",
                    path=["email"],
                    message="invalid email",
                ),
            ]

    with patch.object(mod, "Draft202012Validator", FakeValidator):
        errors = mod.validate_payload_structured({}, {})

    assert errors[0].hint == "Add the required field '['a', 'b']' to your request."
    assert errors[1].expected == "format: email"
    assert errors[1].hint == "Value must be a valid email."


def test_normalize_public_base_url_validation_paths() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_public_base_url(" ")
    with pytest.raises(ValueError, match="must use http or https"):
        normalize_public_base_url("ftp://example.com")
    with pytest.raises(ValueError, match="must include host"):
        normalize_public_base_url("https:///path")
    with pytest.raises(ValueError, match="must not include query or fragment"):
        normalize_public_base_url("https://example.com/path?x=1")
    with pytest.raises(ValueError, match="must not include userinfo"):
        normalize_public_base_url("https://user:pass@example.com")

    assert normalize_public_base_url("https://example.com/") == "https://example.com"


def test_normalize_public_base_url_root_path_branch() -> None:
    class FakePath:
        def rstrip(self, _chars: str) -> str:
            return "/"

    fake_parsed = SimpleNamespace(
        scheme="https",
        netloc="example.com",
        path=FakePath(),
        query="",
        fragment="",
        username=None,
        password=None,
    )
    with patch("aws_cli_mcp.utils.http.urlparse", return_value=fake_parsed):
        assert normalize_public_base_url("https://example.com") == "https://example.com"


def test_validate_oidc_url_rejects_invalid_scheme_and_hostname() -> None:
    with pytest.raises(ValueError, match="must use HTTPS"):
        validate_oidc_url("http://example.com")
    with pytest.raises(ValueError, match="has no hostname"):
        validate_oidc_url("https:///missing-host")


def test_validate_oidc_url_rejects_non_public_resolution() -> None:
    with patch(
        "aws_cli_mcp.utils.http.socket.getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("127.0.0.1", 443))],
    ):
        with pytest.raises(ValueError, match="non-public address"):
            validate_oidc_url("https://example.com/jwks")


def test_validate_oidc_url_accepts_public_resolution() -> None:
    url = "https://example.com/jwks"
    with patch(
        "aws_cli_mcp.utils.http.socket.getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("8.8.8.8", 443))],
    ):
        assert validate_oidc_url(url) == url
