from __future__ import annotations

import pytest

from aws_cli_mcp import config


def test_split_csv_preserve_case() -> None:
    values = config._split_csv_preserve_case(" A, B ,,C ")
    assert values == ["A", "B", "C"]


def test_resolve_path_absolute_inside_project() -> None:
    root = str(config._project_root().resolve())
    absolute = f"{root}/data/test_file"
    assert config._resolve_path(absolute) == absolute


def test_resolve_path_absolute_outside_project_rejected() -> None:
    with pytest.raises(ValueError, match="Path traversal detected"):
        config._resolve_path("/tmp/example")


def test_env_int_uses_default_for_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_INT_VALUE", "")
    assert config._env_int("TEST_INT_VALUE", 7) == 7


def test_env_int_invalid_value_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_INT_INVALID", "not_a_number")
    result = config._env_int("TEST_INT_INVALID", 42)
    assert result == 42


def test_env_float_uses_default_for_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_FLOAT_VALUE", "")
    assert config._env_float("TEST_FLOAT_VALUE", 1.5) == 1.5


def test_env_float_invalid_value_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_FLOAT_INVALID", "not_a_float")
    result = config._env_float("TEST_FLOAT_INVALID", 2.5)
    assert result == 2.5


def test_load_settings_raises_runtime_error_on_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    # Triggers pydantic validation error (minimum is 1).
    monkeypatch.setenv("AUTH_CREDENTIAL_CACHE_MAX_ENTRIES", "0")
    config._load_settings_cached.cache_clear()

    with pytest.raises(RuntimeError, match="Invalid configuration"):
        config.load_settings()

    config._load_settings_cached.cache_clear()


def test_public_base_url_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "load_dotenv", lambda **_: None)
    monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "HTTPS://mcp.example.com/base/")
    config._load_settings_cached.cache_clear()

    settings = config.load_settings()

    assert settings.server.public_base_url == "https://mcp.example.com/base"
    config._load_settings_cached.cache_clear()


def test_remote_multi_idp_requires_public_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "load_dotenv", lambda **_: None)
    monkeypatch.setenv("TRANSPORT_MODE", "remote")
    monkeypatch.setenv("AUTH_PROVIDER", "multi-idp")
    monkeypatch.delenv("MCP_PUBLIC_BASE_URL", raising=False)
    config._load_settings_cached.cache_clear()

    with pytest.raises(RuntimeError, match="MCP_PUBLIC_BASE_URL is required"):
        config.load_settings()

    config._load_settings_cached.cache_clear()
