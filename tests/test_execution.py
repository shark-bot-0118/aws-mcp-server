from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aws_cli_mcp.execution import aws_client
from aws_cli_mcp.execution.aws_client import (
    _CLIENT_CACHE,
    RequestContextError,
    _call_method,
    _read_streaming_fields,
    _truncate_text,
    call_aws_api_async,
    get_client,
    get_client_async,
)
from aws_cli_mcp.execution.idempotency import inject_idempotency_tokens
from aws_cli_mcp.smithy.parser import Member, OperationShape, SmithyModel, StructureShape


@pytest.fixture(autouse=True)
def _clear_client_cache() -> None:
    _CLIENT_CACHE.clear()
    yield
    _CLIENT_CACHE.clear()


def _settings(transport_mode: str = "stdio") -> SimpleNamespace:
    return SimpleNamespace(
        server=SimpleNamespace(transport_mode=transport_mode),
        aws=SimpleNamespace(default_profile="default-prof", default_region="us-east-1"),
        execution=SimpleNamespace(sdk_timeout_seconds=30),
    )


def _ctx_with_credentials() -> SimpleNamespace:
    return SimpleNamespace(
        aws_credentials=SimpleNamespace(
            access_key_id="AKIA...",
            secret_access_key="secret",
            session_token="token",
        )
    )


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_stdio_cache(mock_session_cls: MagicMock, mock_settings: MagicMock) -> None:
    mock_settings.return_value = _settings("stdio")

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    mock_session_cls.return_value = mock_session

    first = get_client("s3", None, None)
    second = get_client("s3", None, None)
    third = get_client("ec2", "us-west-2", "custom")

    assert first is second
    assert third is not None
    assert mock_session_cls.call_count == 2


@patch("aws_cli_mcp.execution.aws_client.load_settings")
def test_get_client_http_requires_request_context(mock_settings: MagicMock) -> None:
    mock_settings.return_value = _settings("http")

    with pytest.raises(RequestContextError):
        get_client("s3", None, None, ctx=None)


def test_require_aws_credentials_raises() -> None:
    with pytest.raises(RequestContextError, match="Missing request-scoped AWS credentials"):
        aws_client._require_aws_credentials(SimpleNamespace(aws_credentials=None))


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_http_uses_context_credentials(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("http")

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    mock_session_cls.return_value = mock_session

    ctx = _ctx_with_credentials()
    client = get_client("s3", "ap-northeast-1", None, ctx=ctx)

    assert client is mock_client
    mock_session_cls.assert_called_once()
    kwargs = mock_session_cls.call_args.kwargs
    assert kwargs["aws_access_key_id"] == "AKIA..."
    assert kwargs["region_name"] == "ap-northeast-1"


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_http_reuses_client_for_same_credentials(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("http")

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client
    mock_session_cls.return_value = mock_session

    ctx = _ctx_with_credentials()
    first = get_client("s3", "ap-northeast-1", None, ctx=ctx)
    second = get_client("s3", "ap-northeast-1", None, ctx=ctx)

    assert first is second
    mock_session_cls.assert_called_once()


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_http_separates_cache_by_credential_fingerprint(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("http")

    first_session = MagicMock()
    second_session = MagicMock()
    first_client = MagicMock()
    second_client = MagicMock()
    first_session.client.return_value = first_client
    second_session.client.return_value = second_client
    mock_session_cls.side_effect = [first_session, second_session]

    ctx1 = _ctx_with_credentials()
    ctx2 = SimpleNamespace(
        aws_credentials=SimpleNamespace(
            access_key_id="AKIA...",
            secret_access_key="secret",
            session_token="token-2",
        )
    )

    first = get_client("s3", "ap-northeast-1", None, ctx=ctx1)
    second = get_client("s3", "ap-northeast-1", None, ctx=ctx2)

    assert first is first_client
    assert second is second_client
    assert mock_session_cls.call_count == 2


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_stdio_prefers_context_credentials_when_present(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("stdio")

    mock_session = MagicMock()
    mock_session.client.return_value = MagicMock()
    mock_session_cls.return_value = mock_session

    get_client("lambda", None, None, ctx=_ctx_with_credentials())

    kwargs = mock_session_cls.call_args.kwargs
    assert kwargs["aws_session_token"] == "token"


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_cache_expires_after_ttl(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("stdio")

    first_session = MagicMock()
    second_session = MagicMock()
    first_client = MagicMock()
    second_client = MagicMock()
    first_session.client.return_value = first_client
    second_session.client.return_value = second_client
    mock_session_cls.side_effect = [first_session, second_session]

    with patch(
        "aws_cli_mcp.execution.aws_client.time.monotonic",
        side_effect=[0.0, float(aws_client._CLIENT_TTL_SECONDS) + 1.0],
    ):
        first = get_client("s3", None, None)
        second = get_client("s3", None, None)

    assert first is first_client
    assert second is second_client
    assert mock_session_cls.call_count == 2
    assert len(_CLIENT_CACHE) == 1


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_lru_eviction_when_cache_limit_exceeded(
    mock_session_cls: MagicMock,
    mock_settings: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_settings.return_value = _settings("stdio")
    monkeypatch.setattr(aws_client, "_CLIENT_CACHE_MAX_SIZE", 1)

    first_session = MagicMock()
    second_session = MagicMock()
    first_session.client.return_value = MagicMock()
    second_session.client.return_value = MagicMock()
    mock_session_cls.side_effect = [first_session, second_session]

    get_client("s3", None, None)
    get_client("ec2", None, None)

    assert mock_session_cls.call_count == 2
    assert len(_CLIENT_CACHE) == 1
    remaining_key = next(iter(_CLIENT_CACHE))
    assert remaining_key[1] == "ec2"


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.Config")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_service_config_includes_s3_checksum(
    mock_session_cls: MagicMock,
    mock_config_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("stdio")
    mock_session_cls.return_value = MagicMock(client=MagicMock(return_value=MagicMock()))

    get_client("s3", None, None)
    kwargs = mock_config_cls.call_args.kwargs
    assert kwargs["request_checksum_calculation"] == "when_required"
    assert kwargs["response_checksum_validation"] == "when_required"


@patch("aws_cli_mcp.execution.aws_client.load_settings")
@patch("aws_cli_mcp.execution.aws_client.Config")
@patch("aws_cli_mcp.execution.aws_client.boto3.Session")
def test_get_client_service_config_non_s3(
    mock_session_cls: MagicMock,
    mock_config_cls: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.return_value = _settings("stdio")
    mock_session_cls.return_value = MagicMock(client=MagicMock(return_value=MagicMock()))

    get_client("ec2", None, None)
    kwargs = mock_config_cls.call_args.kwargs
    assert "request_checksum_calculation" not in kwargs
    assert "response_checksum_validation" not in kwargs


class _BinaryStream:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def read(self, size: int | None = None) -> bytes:
        if size is None:
            return self._content
        return self._content[:size]


class _BrokenStream:
    def read(self, size: int | None = None) -> bytes:
        raise RuntimeError("read error")


def test_read_streaming_fields_handles_bytes_and_errors() -> None:
    response = {
        "Body": _BinaryStream(b"\xff\xfe\xfd"),  # Non UTF-8 bytes triggers base64
        "Payload": _BrokenStream(),  # Exception path
    }
    _read_streaming_fields(response, max_output_characters=4)

    assert isinstance(response["Body"], str)
    assert response["Payload"] == "<Error reading stream>"


def test_read_streaming_fields_handles_text() -> None:
    class _TextStream:
        def read(self, size: int | None = None) -> str:
            return "abcdef"

    response = {"AudioStream": _TextStream()}
    _read_streaming_fields(response, max_output_characters=3)
    assert response["AudioStream"] == "..."


def test_read_streaming_fields_non_stream_object_and_truncation() -> None:
    response = {
        "Body": "already text",
        "Payload": _BinaryStream(b"hello world"),
    }
    _read_streaming_fields(response, max_output_characters=5)
    assert response["Body"] == "already text"
    assert response["Payload"] == "hello"


def test_truncate_text_short_and_long() -> None:
    assert _truncate_text("abc", 10) == "abc"
    assert _truncate_text("abcdef", 5) == "ab..."


def test_call_method_wraps_non_dict_result() -> None:
    client = MagicMock()
    client.ping.return_value = "ok"
    result = _call_method(client, "ping", {}, max_output_characters=100)
    assert result == {"result": "ok"}


def test_call_method_reads_streaming_dict_fields() -> None:
    client = MagicMock()
    client.invoke.return_value = {"Body": _BinaryStream(b"hello")}
    result = _call_method(client, "invoke", {}, max_output_characters=100)
    assert result["Body"] == "hello"


@pytest.mark.asyncio
async def test_get_client_async_and_call_aws_api_async_use_to_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}

    async def fake_to_thread(func, *args, **kwargs):
        calls["count"] += 1
        return func(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    with patch("aws_cli_mcp.execution.aws_client.get_client", return_value="client"):
        client = await get_client_async("s3", None)
    assert client == "client"

    fake_client = MagicMock()
    fake_client.list_buckets.return_value = {"Buckets": []}
    result = await call_aws_api_async(fake_client, "list_buckets", 100)
    assert result == {"Buckets": []}
    assert calls["count"] >= 2


def test_inject_idempotency_tokens() -> None:
    model = MagicMock(spec=SmithyModel)

    op = MagicMock(spec=OperationShape)
    op.input = "input-struct"
    input_shape = MagicMock(spec=StructureShape)
    input_shape.members = {
        "Token": Member(target="str", traits={"smithy.api#idempotencyToken": {}}),
        "Data": Member(target="str", traits={}),
    }

    model.get_shape.side_effect = lambda sid: {
        "op": op,
        "input-struct": input_shape,
    }.get(sid)

    updated, injected = inject_idempotency_tokens(model, "op", {"Data": "foo"})
    assert "Token" in updated
    assert "Token" in injected

    updated2, injected2 = inject_idempotency_tokens(
        model,
        "op",
        {"Data": "foo", "Token": "existing"},
    )
    assert updated2["Token"] == "existing"
    assert injected2 == []

    # Operation without input shape
    op_no_input = MagicMock(spec=OperationShape)
    op_no_input.input = None
    model.get_shape.side_effect = lambda sid: op_no_input if sid == "op-no-input" else None
    no_input_updated, no_input_injected = inject_idempotency_tokens(model, "op-no-input", {})
    assert no_input_updated == {}
    assert no_input_injected == []


def test_inject_idempotency_tokens_non_structure_input_shape() -> None:
    model = MagicMock(spec=SmithyModel)
    op = MagicMock(spec=OperationShape)
    op.input = "input-scalar"
    model.get_shape.side_effect = lambda sid: {"op": op, "input-scalar": object()}.get(sid)

    updated, injected = inject_idempotency_tokens(model, "op", {"a": 1})
    assert updated == {"a": 1}
    assert injected == []
